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
    UnicastRefreshShare {
        target_peer_id: String,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
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

impl RetryableUnicast {
    /// Convert RetryableUnicast to ChannelMessage with retry count
    /// This centralizes the conversion logic used in retry mechanisms
    pub fn into_channel_message(self, retry_count: u8) -> crate::types::messaging::ChannelMessage {
        use crate::types::messaging::ChannelMessage;

        match self {
            RetryableUnicast::UnicastShareDKG {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                round,
            } => ChannelMessage::UnicastShareDKG {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                round,
                retry_count,
            },
            RetryableUnicast::UnicastRefreshShare {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
            } => ChannelMessage::UnicastRefreshShare {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                retry_count,
            },
            RetryableUnicast::UnicastCritical {
                target_peer_id,
                topic,
                data,
                message_type,
                message_id,
            } => ChannelMessage::UnicastCritical {
                target_peer_id,
                topic,
                data,
                message_type,
                message_id,
                retry_count,
            },
            RetryableUnicast::UnicastECDSASignature {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
            } => ChannelMessage::UnicastECDSASignature {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
                retry_count,
            },
            RetryableUnicast::UnicastBtcSignatures {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
            } => ChannelMessage::UnicastBtcSignatures {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
                retry_count,
            },
            RetryableUnicast::UnicastTransactionData {
                target_peer_id,
                from_node_id,
                transaction_data,
                round,
            } => ChannelMessage::UnicastTransactionData {
                target_peer_id,
                from_node_id,
                transaction_data,
                round,
                retry_count,
            },
        }
    }
}

/// Maximum number of concurrent outbound requests per peer
pub const MAX_OUTBOUND_INFLIGHT_PER_PEER: u32 = 5;

/// Maximum number of retry attempts on timeout
pub const MAX_OUTBOUND_RETRIES: u8 = 3;
