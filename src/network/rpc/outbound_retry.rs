use crate::types::{SerializablePoint, SerializableScalar};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Entry in the outbound retry registry for timeout retry mechanism
#[derive(Debug, Clone)]
pub struct OutboundRetryEntry {
    pub peer: PeerId,
    pub retry_count: u8,
    pub msg: RetryableUnicast,
}

/// Retriable unicast message variants for the 6 RPC flows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryableUnicast {
    UnicastShareDKG {
        target_peer_id: String,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
        round: u64,
    },
    UnicastCritical {
        target_peer_id: String,
        topic: String,
        data: Vec<u8>,
        message_type: String,
        message_id: String,
    },
    UnicastECDSASignature {
        target_peer_id: String,
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
    },
    UnicastBtcSignatures {
        target_peer_id: String,
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
    },
    UnicastTransactionData {
        target_peer_id: String,
        from_node_id: String,
        transaction_data: Vec<u8>,
        round: u64,
    },
}

/// Maximum number of concurrent outbound requests per peer
pub const MAX_OUTBOUND_INFLIGHT_PER_PEER: u32 = 10;

/// Maximum number of retry attempts on timeout
pub const MAX_OUTBOUND_RETRIES: u8 = 5;
