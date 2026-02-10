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
        /// For TICS UserToVault batch: intent_hash slot. When set, store/aggregate by (round, slot_id).
        slot_id: Option<String>,
    },
    BtcSignaturesMessage {
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
        timestamp: u128,
        user_eth_address: Option<String>,
    },
    /// BTC UserToVault batch: per-slot multi-input signatures.
    /// Each slot (intent) can have multiple inputs (UTXOs).
    BtcUtvSignaturesMessage {
        from: String,
        signatures: Vec<BtcIndexedSignature>, // Multiple sigs (one per input)
        round: u64,
        slot_id: String, // intent_hash - identifies which slot in the batch
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
    /// Send transaction data to final node (for nodes that weren't selected to sign but became final node)
    TransactionDataForFinalNode {
        from: String,
        round: u64,
        tx_bytes: Vec<u8>,
        intent_hash: Option<String>,
        transaction_type: Option<String>,
        request_id: Option<String>,
    },

    // ============================================================
    // Nonce Protocol Messages (for random k with additive shares)
    // Supports batch generation: each message contains batch_size values
    // ============================================================

    /// Phase 1: Broadcast commitments H(R_i[j] || batch_id || j) for batch_size nonces
    /// Each node commits to all their R_i values before revealing
    NonceCommitment {
        from: String,
        batch_id: String,
        round: u64,
        /// Number of nonces in this batch
        batch_size: usize,
        /// SHA256(R_i[j] || batch_id || j) for each j in 0..batch_size
        commitments: Vec<[u8; 32]>,
        timestamp: u128,
    },

    /// Phase 2: After all commitments received, reveal R_i[j] = k_i[j] * G and k_i[j]
    /// Nodes verify each revealed R_i[j] matches prior commitment, then aggregate k[j] = Σk_i[j]
    NonceReveal {
        from: String,
        batch_id: String,
        round: u64,
        /// R_i[j] points in compressed SEC1 format (33 bytes each), batch_size points
        r_points: Vec<Vec<u8>>,
        /// k_i[j] scalar values (32 bytes each), batch_size scalars
        /// All nodes collect these to compute k[j] = Σk_i[j] for each j
        k_shares: Vec<[u8; 32]>,
        timestamp: u128,
    },

    /// Request to start nonce generation (broadcast by coordinator)
    RequestNonceGeneration {
        batch_id: String,
        round: u64,
        coordinator_id: String,
        batch_size: usize,
    },

    /// Signal that nonce generation completed successfully
    NonceGenerationComplete {
        from: String,
        batch_id: String,
        round: u64,
        /// Number of nonce tuples generated
        tuples_count: usize,
        success: bool,
    },
}
