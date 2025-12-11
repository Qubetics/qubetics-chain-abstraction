use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDSASignature {
    /// 65-byte recoverable signature
    pub signature: Vec<u8>,
    pub signer_id: String,
    pub recovery_id: u8,
    /// Optional ETH address context
    pub user_eth_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignatureShare {
    pub share: Vec<u8>,
    pub signer_id: String,
    pub share_index: u32,
    pub threshold: u32,
    pub total_shares: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BtcIndexedSignature {
    pub input_index: usize,
    pub signature: ECDSASignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub aggregated_signature: Vec<u8>,
    pub signer_ids: Vec<String>,
    pub message_hash: Vec<u8>,
    pub threshold: u32,
    pub total_shares: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub aggregated_signature: Vec<u8>,
    pub signer_ids: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    MessageToSign {
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    },
    ECDSASignature {
        from: String,
        signature: ECDSASignature,
        round: u64,
        timestamp: u128,
        user_eth_address: Option<String>,
    },
    BtcSignaturesMessage {
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
        timestamp: u128,
        user_eth_address: Option<String>,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
    RequestSignatures {
        round: u64,
        final_node_id: String,
        message: String,
    },
    RequestBtcSignatures {
        round: u64,
        final_node_id: String,
        message: String,
    },
}
