//! Network bridge between cggmp21's `round-based` Stream/Sink and our gossipsub layer.
//!
//! This bridge is generic over the message type `Msg` from the cggmp21 protocol.
//! It converts between our gossipsub transport (opaque `Vec<u8>` via bincode) and
//! the typed `Incoming<Msg>` / `Outgoing<Msg>` that `round_based::MpcParty` expects.
//!
//! # Error handling
//! `round_based` requires that the stream error implements `std::error::Error`.
//! We use a simple `MpcError` newtype wrapping a String to satisfy this bound.

use futures::{Sink, Stream};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tracing::warn;

// ── Error type ─────────────────────────────────────────────────────────────

/// Thin error type that implements `std::error::Error`, required by `round_based`.
#[derive(Debug)]
pub struct MpcError(pub String);

impl fmt::Display for MpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for MpcError {}

impl From<anyhow::Error> for MpcError {
    fn from(e: anyhow::Error) -> Self {
        MpcError(e.to_string())
    }
}

// ── MpcSession ─────────────────────────────────────────────────────────────

/// A live MPC session connected to the gossipsub layer.
///
/// Create one per protocol execution (keygen session, signing session).
/// The gossipsub handler delivers incoming round messages via `deliver()`.
pub struct MpcSession {
    tx: mpsc::UnboundedSender<(u16, Vec<u8>)>,
    rx: mpsc::UnboundedReceiver<(u16, Vec<u8>)>,
    peer_index: HashMap<String, u16>,
}

impl MpcSession {
    pub fn new(peer_index: HashMap<String, u16>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        MpcSession { tx, rx, peer_index }
    }

    /// Called by the gossipsub handler when a `MpcRoundMessage` arrives.
    pub fn deliver(&self, from_peer: &str, payload: Vec<u8>) -> Result<(), MpcError> {
        let idx = self
            .peer_index
            .get(from_peer)
            .copied()
            .ok_or_else(|| MpcError(format!("Unknown MPC peer: {}", from_peer)))?;
        self.tx
            .send((idx, payload))
            .map_err(|_| MpcError("MPC session channel closed".into()))
    }

    /// Returns a clonable sender handle for use from the gossipsub handler.
    pub fn sender_handle(&self) -> MpcSessionTx {
        MpcSessionTx {
            tx: self.tx.clone(),
            peer_index: self.peer_index.clone(),
        }
    }

    /// Convert into a `(MpcIncoming<Msg>, MpcOutgoing)` pair for `round_based::MpcParty`.
    ///
    /// `send_fn(recipient: Option<u16>, bytes: Vec<u8>)`:
    ///   - `None`    → broadcast to all session peers via gossipsub
    ///   - `Some(i)` → unicast to the peer at keygen-index `i`
    pub fn into_network<Msg>(
        self,
        send_fn: impl Fn(Option<u16>, Vec<u8>) + Send + 'static,
    ) -> (MpcIncoming<Msg>, MpcOutgoing)
    where
        Msg: DeserializeOwned + Send + 'static,
    {
        let incoming = MpcIncoming {
            rx: self.rx,
            _phantom: std::marker::PhantomData,
            next_id: 0,
        };
        let outgoing = MpcOutgoing {
            send_fn: Box::new(send_fn),
        };
        (incoming, outgoing)
    }
}

/// Clonable handle to push incoming gossipsub bytes into a running `MpcSession`.
pub struct MpcSessionTx {
    tx: mpsc::UnboundedSender<(u16, Vec<u8>)>,
    peer_index: HashMap<String, u16>,
}

impl MpcSessionTx {
    pub fn deliver(&self, from_peer: &str, payload: Vec<u8>) -> Result<(), MpcError> {
        let idx = self
            .peer_index
            .get(from_peer)
            .copied()
            .ok_or_else(|| MpcError(format!("Unknown MPC peer: {}", from_peer)))?;
        self.tx
            .send((idx, payload))
            .map_err(|_| MpcError("MPC session channel closed".into()))
    }
}

// ── Stream half (incoming) ─────────────────────────────────────────────────

/// Receives raw `(sender_index, bytes)` from gossipsub and deserialises to `Incoming<Msg>`.
pub struct MpcIncoming<Msg> {
    rx: mpsc::UnboundedReceiver<(u16, Vec<u8>)>,
    _phantom: std::marker::PhantomData<Msg>,
    next_id: u64,
}

impl<Msg> Stream for MpcIncoming<Msg>
where
    Msg: DeserializeOwned,
{
    type Item = Result<Incoming<Msg>, MpcError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some((sender, bytes))) => {
                let id = self.next_id;
                self.next_id += 1;
                match bincode::deserialize::<Msg>(&bytes) {
                    Ok(msg) => Poll::Ready(Some(Ok(Incoming {
                        id,
                        sender,
                        msg_type: MessageType::Broadcast,
                        msg,
                    }))),
                    Err(e) => {
                        warn!(
                            "MPC: Failed to deserialize round msg from {}: {}",
                            sender, e
                        );
                        // skip bad message and wait for next
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── Sink half (outgoing) ───────────────────────────────────────────────────

/// Serialises `Outgoing<Msg>` to bytes and routes them via `send_fn`.
pub struct MpcOutgoing {
    send_fn: Box<dyn Fn(Option<u16>, Vec<u8>) + Send>,
}

impl<Msg> Sink<Outgoing<Msg>> for MpcOutgoing
where
    Msg: Serialize,
{
    type Error = MpcError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), MpcError>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Outgoing<Msg>) -> Result<(), MpcError> {
        let bytes = bincode::serialize(&item.msg)
            .map_err(|e| MpcError(format!("MPC serialize error: {}", e)))?;
        let recipient = match item.recipient {
            MessageDestination::AllParties => None,
            MessageDestination::OneParty(idx) => Some(idx),
        };
        (self.send_fn)(recipient, bytes);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), MpcError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), MpcError>> {
        Poll::Ready(Ok(()))
    }
}
