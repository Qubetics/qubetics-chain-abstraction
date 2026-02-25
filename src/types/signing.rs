use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDSASignature {
    /// 65-byte recoverable signature
    pub signature: Vec<u8>,
    pub signer_id: String,
    pub recovery_id: u8,
    /// Optional ETH address context
    pub user_tics_address: Option<String>,
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
        user_tics_address: Option<String>,
        /// For TICS UserToVault batch: intent_hash slot. When set, store/aggregate by (round, slot_id).
        slot_id: Option<String>,
    },
    BtcSignaturesMessage {
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
        timestamp: u128,
        user_tics_address: Option<String>,
    },
    /// BTC UserToVault batch: per-slot multi-input signatures.
    /// Each slot (intent) can have multiple inputs (UTXOs).
    BtcUtvSignaturesMessage {
        from: String,
        signatures: Vec<BtcIndexedSignature>, // Multiple sigs (one per input)
        round: u64,
        slot_id: String, // intent_hash - identifies which slot in the batch
        timestamp: u128,
        user_tics_address: Option<String>,
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
        /// Serialized ChainTransaction for batch slot reconstruction (observer final nodes).
        /// Only set for per-slot batch flows (TICS_UTV_BATCH, BTC_UTV_BATCH).
        #[serde(default)]
        chain_tx_json: Option<String>,
        /// User ETH address associated with this slot (for batch slot reconstruction).
        #[serde(default)]
        user_tics_address: Option<String>,
        /// Full batch identifiers for withdraw/claim-reward batches.
        /// Each entry is "request_id|solver_address". Needed so observer final nodes
        /// can broadcast tx_id updates for ALL requests in the batch after broadcast.
        #[serde(default)]
        batch_identifiers: Option<Vec<String>>,
    },

    // ============================================================
    // Secure MPC Protocol Messages (cggmp21 rounds)
    // Replaces the insecure NonceCommitment/NonceReveal protocol.
    // Each cggmp21 round (keygen, aux_info_gen, signing) serializes
    // its round messages as opaque bytes and routes them here.
    // ============================================================
    /// Generic carrier for cggmp21 round-based messages (keygen, aux_info, signing).
    /// `session_id` matches the ExecutionId so nodes can demux concurrent sessions.
    MpcRoundMessage {
        from: String,
        /// Unique session identifier (keygen round-id, tx_id for signing, etc.)
        session_id: String,
        /// Phase: "keygen" | "aux_info" | "signing"
        phase: String,
        /// Serialized `round_based::Outgoing<Msg>` bytes (bincode-encoded)
        payload: Vec<u8>,
    },
}
