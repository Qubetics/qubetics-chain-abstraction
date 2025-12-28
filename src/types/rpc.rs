// src/mpc_request_response.rs

use crate::protocols::DKGStatus;
use crate::types::vrf::{VrfRoundSyncRequest, VrfRoundSyncResponse};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    request_response::{
        cbor::Behaviour as CborReqRespBehaviour, Codec as RequestResponseCodec,
        Config as RequestResponseConfig, ProtocolSupport,
    },
    StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, io, pin::Pin};
use tracing::info;

use super::{
    p2p::{PeerInfo, SerializablePeerId},
    SerializablePoint, SerializableScalar,
};

pub type MPCCodecRequest = <MPCCodec as libp2p::request_response::Codec>::Request;
pub type MPCCodecResponse = <MPCCodec as libp2p::request_response::Codec>::Response;

/// The protocol identifier; must match in `ProtocolSupport`.
#[derive(Debug, Clone)]
pub struct MPCProtocol;

impl AsRef<str> for MPCProtocol {
    fn as_ref(&self) -> &str {
        "/mpc/1.0.0"
    }
}

/// RPC request variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RPCRequest {
    ScheduleADKG {
        start_time: u64,
    },
    GetPeerList,
    Custom {
        id: String,
        data: Vec<u8>,
    },
    GetDKGStatus,
    GetPeerInfo,
    Ping,
    RequestFirstNodeStartTime,
    ShareFirstNodeStartTime {
        first_node_start_time: u64,
    },
    RequestCurrentVrfRound,
    VrfRoundSync(VrfRoundSyncRequest),
    SendAVSSShare {
        dealer_id: SerializablePeerId,
        receiver_id: SerializablePeerId,
        share: SerializableScalar,
        commitments: Vec<SerializablePoint>,
    },

    BroadcastCommitments {
        dealer_id: SerializablePeerId,
        commitments: Vec<SerializablePoint>,
    },

    SubmitComplaint {
        dealer_id: SerializablePeerId,
        from: SerializablePeerId,
        reason: String, // e.g. "invalid share"
    },

    DeclareADKGComplete {
        from: SerializablePeerId,
        share: SerializableScalar,
    },

    /// Request database snapshot from a peer
    RequestDatabaseSync {
        requester_id: SerializablePeerId,
    },

    /// Request specific batch of database entries
    RequestDatabaseBatch {
        batch_index: usize,
        batch_size: usize,
    },

    /// Unicast a single DKG share to a specific participant (P2P, not broadcast)
    SendDKGShare {
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
        round: u64,
    },

    /// Unicast a single refresh share to a specific participant (P2P, not broadcast)
    SendRefreshShare {
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
    },

    /// Unicast an ECDSA signature to the final node (P2P, not broadcast)
    SendECDSASignature {
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
    },

    /// Unicast BTC signatures to the final node (P2P, not broadcast)
    SendBtcSignatures {
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
    },

    /// Unicast transaction data to the final node (P2P, not broadcast)
    SendTransactionData {
        from_node_id: String,
        transaction_data: Vec<u8>,
        round: u64,
    },
}

/// RPC response variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RPCResponse {
    PeerList {
        peers: Vec<SerializablePeerId>,
        indices: Vec<Option<usize>>,    // index per peer, None if unknown
        addresses: Vec<Option<String>>, // multiaddr per peer, None if unknown
    },
    Custom {
        id: String,
        data: Vec<u8>,
    },
    DKGStarted {
        peer_id: SerializablePeerId,
    },
    DKGError(String),
    DKGStatus {
        status: DKGStatus,
    },
    Error(String),
    PeerInfo(PeerInfo),
    Pong,
    NoResponse,
    Ack,
    Verified,
    CurrentVrfRoundResponse {
        current_round: Option<u64>,
    },
    VrfRoundSync(VrfRoundSyncResponse),
    ShareAccepted,
    ComplaintAccepted,
    FinishedADKG {
        group_public_key: SerializablePoint,
    },
    GotAVSSShare {
        dealer_id: SerializablePeerId,
        receiver_id: SerializablePeerId,
        share: SerializableScalar,
        commitments: Vec<SerializablePoint>,
    },

    /// Response to database sync request with metadata
    DatabaseSyncMetadata {
        total_entries: usize,
        recommended_batch_size: usize,
    },

    /// Response with a batch of database entries
    DatabaseBatch {
        batch_index: usize,
        entries: Vec<DatabaseEntry>,
        is_last_batch: bool,
    },

    /// Database sync completed
    DatabaseSyncComplete,

    /// Acknowledge receipt of a DKG share via unicast
    DKGShareReceived {
        from_node_id: String,
        receiver_node_id: String,
        share_index: usize,
        success: bool,
    },

    /// Acknowledge receipt of a refresh share via unicast
    RefreshShareReceived {
        from_node_id: String,
        receiver_node_id: String,
        share_index: usize,
        success: bool,
    },

    /// Acknowledge receipt of an ECDSA signature via unicast
    ECDSASignatureReceived {
        from_node_id: String,
        receiver_node_id: String,
        round: u64,
        success: bool,
    },

    /// Acknowledge receipt of BTC signatures via unicast
    BtcSignaturesReceived {
        from_node_id: String,
        receiver_node_id: String,
        round: u64,
        success: bool,
    },
}

/// A single database entry for syncing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// CBOR + serde codec for our MPC protocol.
#[derive(Clone, Deserialize, Serialize)]
pub struct MPCCodec;

impl RequestResponseCodec for MPCCodec {
    type Protocol = MPCProtocol;
    type Request = RPCRequest;
    type Response = RPCResponse;

    // NOTE: These method signatures *must* match the trait exactly.
    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 MPCProtocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<RPCRequest>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait, // nonblocking read :contentReference[oaicite:4]{index=4}
        Self: 'async_trait,
    {
        info!("[MPC REQ-RESP] Read req");
        Box::pin(async move {
            let mut buf = Vec::new();
            io.read_to_end(&mut buf).await?; // collect the full request :contentReference[oaicite:5]{index=5}
            serde_cbor::from_slice(&buf) // decode CBOR
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 MPCProtocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<RPCResponse>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait, // nonblocking read :contentReference[oaicite:6]{index=6}
        Self: 'async_trait,
    {
        info!("[MPC REQ-RESP] Read resp");
        Box::pin(async move {
            let mut buf = Vec::new();
            io.read_to_end(&mut buf).await?;
            serde_cbor::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 MPCProtocol,
        io: &'life2 mut T,
        req: RPCRequest,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait, // nonblocking write :contentReference[oaicite:7]{index=7}
        Self: 'async_trait,
    {
        info!("[MPC REQ-RESP] Write req");
        Box::pin(async move {
            let data = serde_cbor::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            io.write_all(&data).await?; // send bytes
            io.flush().await // flush substream
        })
    }
    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 MPCProtocol,
        io: &'life2 mut T,
        res: RPCResponse,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait, // nonblocking write :contentReference[oaicite:8]{index=8}
        Self: 'async_trait,
    {
        info!("[MPC REQ-RESP] Write resp");
        Box::pin(async move {
            let data = serde_cbor::to_vec(&res)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            io.write_all(&data).await?;
            io.flush().await
        })
    }
}

/// Build a libp2p request‑response behaviour using our MPCCodec + CBOR.
/// You can then add this to your Swarm.
pub fn build_mpc_behaviour() -> CborReqRespBehaviour<MPCCodecRequest, MPCCodecResponse> {
    let mut cfg = RequestResponseConfig::default();
    // Increase timeout from default 60s to 180s for high-load scenarios
    // This prevents timeouts when nodes are processing many parallel transactions
    cfg.set_request_timeout(std::time::Duration::from_secs(180));
    let proto = StreamProtocol::new(MPCProtocol.as_ref());
    let protocols = std::iter::once((proto, ProtocolSupport::Full));
    CborReqRespBehaviour::new(protocols, cfg)
}
