use crate::{
    commands::Command,
    protocols::{DKGMessage, VrfSelectedNodesBroadcast, VrfSelectionMessage},
    types::{
        intent::{DepositIntent, TransactionType},
        rpc_server::{NodeStatus, PendingClaimRewardRequest, PendingWithdrawRequest},
        secp::SerializableScalar,
        signing::SigningMessage,
        vrf::{VrfRoundSyncRequest, VrfRoundSyncResponse},
        ConsensusMessage,
    },
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Share metadata for AVSS exchanges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub index: usize,
    pub value: SerializableScalar,
}

/// Per-request metadata included in TICS withdraw-liquidity batches.
/// Carries enough information for all nodes to:
/// - Look up the full PendingWithdrawRequest in RocksDB
/// - Aggregate per-solver amounts for TICS (and optionally BTC) assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicsWithdrawBatchRequest {
    /// Unique withdraw-liquidity request identifier
    pub request_id: String,
    /// Solver EVM address associated with the request
    pub solver_address: String,
    /// Asset symbol, e.g. "TICS" or "BTC"
    pub asset: String,
    /// Amount as decimal string in smallest units for the asset chain
    pub amount: String,
    /// Asset chain identifier (TICS chain ID from MPC_TICS_CHAIN_ID env var for TICS, 0 for BTC placeholder)
    pub chain_id: u64,
    /// Optional on-chain transaction ID already associated with this request
    pub tx_id: Option<String>,
}

/// Per-request metadata for TICS claim-reward batches (mirrors TicsWithdrawBatchRequest).
/// - TICS: pending claims with tics_address; contract pays TICS; on success store tx_id and mark done.
/// - BTC: pending claims that already have tx_id; include to register on contract; on success mark done only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicsClaimRewardBatchRequest {
    pub request_id: String,
    pub solver_address: String,
    /// "TICS" or "BTC"
    pub asset: String,
    /// Amount as decimal string (for aggregation / contract)
    pub amount: String,
    /// TICS chain ID (from MPC_TICS_CHAIN_ID env var) for TICS, 0 for BTC
    pub chain_id: u64,
    /// For BTC entries: already-set tx_id to register on contract
    pub tx_id: Option<String>,
}

/// Per-request metadata for TICS platform-fee claim batches.
/// - TICS: pending claims with tics_target_address; contract calls claimPlatformFee(amount, 1, recipient).
/// - BTC: pending claims that already have tx_id; contract calls claimPlatformFee(amount, 0, recipient); marks done.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicsClaimPlatformFeeBatchRequest {
    pub request_id: String,
    /// "TICS" or "BTC"
    pub asset: String,
    /// Amount as decimal string in smallest units
    pub amount: String,
    /// 0 = BTC, 1 = TICS (for claimPlatformFee chainType param)
    pub chain_type: u8,
    /// For BTC entries: already-set tx_id to register on contract
    pub tx_id: Option<String>,
    /// Recipient address for claimPlatformFee (tics_target_address or btc_target_address from the request)
    pub target_address: String,
    /// Admin's original tics_address (used for admin share pubkey lookup during signing verification)
    pub admin_tics_address: String,
}

#[derive(Debug)]
pub enum ChannelMessage {
    Broadcast {
        topic: String,
        data: Vec<u8>,
    },
    DepositIntent {
        intent: DepositIntent,
        intent_id: String,
        /// User's TICS address - required for UserToVault deposits
        user_tics_address: String,
        transaction_type: TransactionType,
        amount: u128,
        /// Pre-computed target amount (converted from source amount via price feed).
        /// Computed at RPC level so the channel handler doesn't need to re-derive it.
        target_amount: u128,
        /// Signature over the serialized intent (required for gossip verification)
        signature: Option<String>,
    },
    /// Propagate a new pending claim-reward request to all nodes so they store it in DB.
    PendingClaimRewardRequestBroadcast {
        request: PendingClaimRewardRequest,
    },
    /// Inbound solver add-liquidity request (batched contract call, no DB state).
    /// These requests are validated via VERIFICATION_ADDRESS and then gossiped to peers.
    SolverAddLiquidity {
        /// Unique request identifier (from backend's signed payload).
        request_id: String,
        /// Arbitrary solver identifier (off-chain semantics, used by backend).
        solver_id: String,
        /// Solver EVM address that will receive liquidity.
        solver_address: String,
        /// Amount as decimal string in smallest units for the target chain.
        amount: String,
        /// Target chain ID (0 = BTC, TICS chain ID from MPC_TICS_CHAIN_ID env var = EVM / Qubetics).
        chain_id: u64,
        /// Signature created by VERIFICATION_ADDRESS over `signed_payload`.
        signature: String,
        /// Original signed payload (for peer-side verification if needed).
        signed_payload: String,
        /// Timestamp (ms since epoch) when this node accepted the request.
        timestamp_ms: i64,
        /// Status: "Pending" (initial), "Batched" (included in a batch), "Completed" (tx submitted).
        status: String,
        /// Optional transaction ID (e.g. on-chain deposit tx hash).
        tx_id: Option<String>,
    },
    TransactionFailure {
        sequencer_request_id: String,
        blockchain_tx_hash: String,
        error: String,
        original_request: Option<()>,
    },
    /// Internal signal to broadcast and locally process an intent batch
    IntentBatchBroadcast {
        /// List of intent hashes to process
        intent_hashes: Vec<String>,
        /// Batch type: "BTC" or "TICS"
        batch_type: String,
        /// Timestamp when batch was created
        timestamp: String,
        /// Round number that triggered this batch
        round: u64,
        /// Node ID of the final node broadcasting this batch
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// TICS UserToVault intent batch: final node picks pending intents with source_chain TICS
    /// (UserToVault not yet done) and broadcasts for all nodes to sign each with the respective user key.
    TicsUserToVaultIntentBatch {
        intent_hashes: Vec<String>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce assignments: intent_hash -> per-input nonce tuple IDs
        /// All nodes must use the same nonce tuple ID per input index to ensure signature aggregation
        nonce_assignments: std::collections::HashMap<String, Vec<String>>,
    },
    /// BTC UserToVault intent batch: final node picks pending intents with source_chain bitcoin
    /// (UserToVault not yet done) and broadcasts for all nodes to sign each with the respective user key.
    BtcUserToVaultIntentBatch {
        intent_hashes: Vec<String>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce assignments: intent_hash -> per-input nonce tuple IDs
        /// All nodes must use the same nonce tuple ID per input index to ensure signature aggregation
        nonce_assignments: std::collections::HashMap<String, Vec<String>>,
    },
    /// BTC Intent Manager contract update batch
    /// Used to update network-to-target tx-id on contract for BTC intents
    BtcIntentManagerTxUpdate {
        /// List of intent hashes to update on contract
        intent_hashes: Vec<String>,
        /// BTC batch transaction ID that was finalized
        btc_txid: String,
        /// Round number of the BTC batch
        btc_batch_round: u64,
        /// Round number for the contract update batch
        update_round: u64,
        /// Timestamp when batch was created
        timestamp: String,
        /// Node ID broadcasting this batch
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Solver add-liquidity batch broadcast
    /// Final node broadcasts selected requests for distributed signing
    /// All nodes already have the full records in RocksDB, so we only send IDs
    SolverAddLiquidityBatch {
        /// List of request IDs included in this batch (all nodes can look up details from RocksDB)
        request_ids: Vec<String>,
        /// Round number that selected this batch
        round: u64,
        /// Timestamp when batch was created
        timestamp: String,
        /// Node ID of the final node broadcasting this batch
        node_id: String,
        /// Nonce tuple_id for this batch's signature (all nodes must use the same nonce)
        nonce_tuple_id: Option<String>,
    },
    TransactionIdBroadcast {
        /// One or more intent hashes associated with this transaction ID.
        /// For single transactions, this will contain exactly one hash.
        /// For batch transactions, this will include all intent hashes in the batch.
        intent_hashes: Vec<String>,
        transaction_id: String,
        transaction_type: String,
        solver_address: Option<String>,
        node_id: String,
    },
    /// Separate broadcast for NetworkToTarget transactions to establish the final node ID
    FinalNodeIdBroadcast {
        intent_hashes: Vec<String>,
        final_node_id: String,
    },
    /// BTC withdraw-liquidity batch broadcast (definition only, no txid)
    /// Final node broadcasts selected BTC withdraw requests for distributed signing.
    /// All nodes already have the full records in RocksDB, so we only send IDs and solver addresses.
    BtcWithdrawBatch {
        /// Unique batch identifier (e.g. derived from round + timestamp)
        batch_id: String,
        /// List of (request_id, solver_address) included in this BTC withdraw batch
        requests: Vec<(String, String)>,
        /// Round number that triggered this batch
        round: u64,
        /// Timestamp when batch was created
        timestamp: String,
        /// Node ID of the final node broadcasting this batch
        node_id: String,
        /// Coordinated nonce tuple IDs for threshold signing (index -> input)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// BTC claim-reward batch broadcast (same flow as BtcWithdrawBatch).
    /// Final node broadcasts selected pending BTC claim-reward requests for distributed signing.
    BtcClaimRewardBatch {
        batch_id: String,
        requests: Vec<(String, String)>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Coordinated nonce tuple IDs for threshold signing (index -> input)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// TICS withdraw-liquidity batch broadcast.
    /// Final node broadcasts selected TICS (and optionally BTC) withdraw requests
    /// so all nodes can aggregate per-solver amounts and submit a single
    /// removeLiquidity contract call via MPC signing.
    TicsWithdrawBatch {
        /// Unique batch identifier (e.g. derived from round + timestamp)
        batch_id: String,
        /// Per-request metadata (TICS and optionally BTC) used for aggregation.
        requests: Vec<TicsWithdrawBatchRequest>,
        /// Round number that triggered this batch
        round: u64,
        /// Timestamp when batch was created
        timestamp: String,
        /// Node ID of the final node broadcasting this batch
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// TICS claim-reward batch broadcast (same flow as TicsWithdrawBatch).
    /// Picks TICS claim requests (pending) and BTC claim requests (pending + have tx_id) for contract.
    /// On success: store TICS tx_id on TICS requests and mark done; mark BTC requests done only.
    TicsClaimRewardBatch {
        batch_id: String,
        requests: Vec<TicsClaimRewardBatchRequest>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple_id for this batch's signature (all nodes must use the same nonce)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Peer invalidation batch broadcast (same flow as BtcWithdrawBatch / BtcClaimRewardBatch).
    /// Final node broadcasts selected disconnected solver IDs for distributed signing.
    PeerInvalidationBatch {
        solver_ids: Vec<String>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple_id for this batch's signature (all nodes must use the same nonce)
        nonce_tuple_id: Option<String>,
    },
    /// Broadcast when a peer invalidation request is safely deleted because the solver
    /// was already invalidated on the smart contract.
    PeerInvalidationDeleted {
        /// The solver ID that was deleted
        solver_id: String,
        /// The node ID that detected the on-chain invalidation
        node_id: String,
    },
    /// Unified claim-reward transaction ID broadcast for both TICS and BTC (same pattern as WithdrawTxIdBroadcast).
    /// - TICS: txid starts with "0x" (EVM); store tx_id on TICS requests and mark done; mark BTC requests in batch done only. Single: solver_address Some, requests empty. Batch: requests non-empty.
    /// - BTC: txid is BTC txid; store tx_id on each PendingClaimRewardRequest (do not mark done). Batch only: requests non-empty.
    ClaimRewardTxIdBroadcast {
        txid: String,
        network: String,
        batch_id: String,
        solver_address: Option<String>,
        requests: Vec<(String, String)>,
        node_id: String,
    },
    /// Unified withdraw-liquidity transaction ID broadcast for both BTC and TICS.
    /// Sent AFTER the underlying transaction (BTC batch or TICS removeLiquidity) has
    /// been constructed and broadcast.
    /// This message is interpreted by the handler and routed to
    /// handle_withdraw_liquidity_transaction_id_storage, which applies asset-specific
    /// semantics based on the txid/network shape.
    WithdrawTxIdBroadcast {
        /// Transaction ID that executed this withdraw-liquidity operation.
        /// - For BTC: raw bitcoin txid (non-0x).
        /// - For TICS: EVM transaction hash (0x-prefixed).
        txid: String,
        /// Network label or chain identifier (for logging/traceability).
        /// - For BTC: e.g. "bitcoin-mainnet" or "bitcoin-testnet".
        /// - For TICS: e.g. "qubetics".
        network: String,
        /// Batch identifier corresponding to the withdraw batch (BTC or TICS).
        batch_id: String,
        /// Optional solver address.
        /// - For BTC: usually None; individual requests are in `requests`.
        /// - For TICS: solver address for which removeLiquidity was executed.
        solver_address: Option<String>,
        /// Optional list of (request_id, solver_address) included in this withdraw batch.
        /// - For BTC: used to map a single btc_txid to many withdraw requests.
        /// - For TICS: typically empty; mapping is done per-solver via solver_address.
        requests: Vec<(String, String)>,
        /// Node ID broadcasting the txid
        node_id: String,
    },
    /// Propagate a new pending withdraw-liquidity request to all nodes so they store it in DB.
    /// Sent by the node that received the withdraw_liquidity RPC; peers store the same request.
    PendingWithdrawRequestBroadcast {
        request: PendingWithdrawRequest,
    },
    /// Propagate a new pending claim-platform-fee request to all nodes so they store it in DB.
    /// Sent by the node that received the claim_platform_fee admin RPC.
    PendingClaimPlatformFeeRequestBroadcast {
        request: crate::types::rpc_server::PendingClaimPlatformFeeRequest,
    },
    /// BTC claim-platform-fee batch broadcast (same flow as BtcWithdrawBatch).
    /// Final node broadcasts selected pending BTC platform fee claims for distributed signing.
    BtcClaimPlatformFeeBatch {
        batch_id: String,
        /// (request_id, btc_target_address) pairs
        requests: Vec<(String, String)>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Coordinated nonce tuple IDs for threshold signing (index -> input)
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Claim-platform-fee transaction ID broadcast (same pattern as ClaimRewardTxIdBroadcast).
    ClaimPlatformFeeTxIdBroadcast {
        txid: String,
        network: String,
        batch_id: String,
        /// (request_id, btc_target_address) pairs
        requests: Vec<(String, String)>,
        node_id: String,
    },
    TicsClaimPlatformFeeBatch {
        batch_id: String,
        requests: Vec<TicsClaimPlatformFeeBatchRequest>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple_id for this batch's signature (all nodes must use the same nonce)
        nonce_tuple_id: Option<String>,
    },
    UserRegistration {
        tics_address: String,
        node_id: String,
    },
    AdminRegistration {
        tics_address: String,
        node_id: String,
    },
    ScheduledDKGStart,
    PeerDiscoveryRetry {
        attempt: u8,
    },
    /// Deliver DKG share specifically to one peer
    UnicastShareDKG {
        target_peer_id: String,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        retry_count: u8,
    },
    /// Unicast a critical gossip message via P2P RPC
    UnicastCritical {
        target_peer_id: String,
        topic: String,
        data: Vec<u8>,
        message_type: String,
        message_id: String,
        retry_count: u8,
    },
    /// Send ECDSA signature to final node via P2P RPC unicast
    UnicastECDSASignature {
        target_peer_id: String,
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
        retry_count: u8,
    },

    /// Send BTC signatures to final node via P2P RPC unicast
    UnicastBtcSignatures {
        target_peer_id: String,
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
        retry_count: u8,
    },

    /// Send transaction data to final node via P2P RPC unicast
    UnicastTransactionData {
        target_peer_id: String,
        from_node_id: String,
        transaction_data: Vec<u8>,
        round: u64,
        retry_count: u8,
    },

    StatusRequest {
        responder: oneshot::Sender<NodeStatus>,
    },
    /// Request this node's complete multiaddr (e.g. for node-info RPC).
    NodeMultiaddrRequest {
        responder: oneshot::Sender<Option<String>>,
    },
    /// Check if a peer is active in the network (present in node_manager).
    PeerConnectionCheck {
        peer_id: String,
        responder: oneshot::Sender<bool>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipsubMessage {
    DKG(DKGMessage),
    Signing(SigningMessage),
    Command(Command),
    Consensus(ConsensusMessage),
    VrfSelection(VrfSelectionMessage),
    VrfSelectedNodes(VrfSelectedNodesBroadcast),
    VrfRoundSyncRequest(VrfRoundSyncRequest),
    VrfRoundSyncResponse(VrfRoundSyncResponse),
    PeerDiscovered {
        peer: PeerId,
        sequence: Option<u64>,
        index: Option<usize>,
    },
    DepositIntent {
        intent: DepositIntent,
        intent_id: String,
        /// User's TICS address - required for UserToVault deposits
        user_tics_address: String,
        /// Note: Gossiped DepositIntent is always processed as UserToVault
        amount: u128,
        /// Signature over the serialized intent (required for gossip-level verification)
        signature: Option<String>,
    },
    /// Propagate a new pending claim-reward request to all nodes so they store it in DB.
    PendingClaimRewardRequestBroadcast {
        request: PendingClaimRewardRequest,
    },
    WithdrawLiquidity {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        transaction_type: String,
    },
    /// Gossip for solver add-liquidity requests (no DB status, batch-only).
    SolverAddLiquidity {
        /// Unique request identifier (from backend's signed payload).
        request_id: String,
        solver_id: String,
        solver_address: String,
        amount: String,
        chain_id: u64,
        /// Raw payload string that was signed.
        signature: String,
        signed_payload: String,
        /// Timestamp (ms since epoch) when origin node accepted the request.
        timestamp_ms: i64,
        /// Status: "Pending" (initial), "Batched" (included in a batch), "Completed" (tx submitted).
        status: String,
        /// Optional transaction ID (e.g. on-chain deposit tx hash).
        #[serde(default)]
        tx_id: Option<String>,
    },
    /// Gossip for solver add-liquidity batch (final node broadcasts for signing)
    /// All nodes already have the full records in RocksDB, so we only send IDs
    SolverAddLiquidityBatch {
        request_ids: Vec<String>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple_id for this batch's signature (all nodes must use the same nonce)
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    UserRegistration {
        tics_address: String,
        timestamp: i64,
        node_id: String,
    },
    AdminRegistration {
        tics_address: String,
        timestamp: i64,
        node_id: String,
    },
    TransactionIdBroadcast {
        /// One or more intent hashes associated with this transaction ID.
        /// For single transactions, this will contain exactly one hash.
        /// For batch transactions, this will include all intent hashes in the batch.
        intent_hashes: Vec<String>,
        transaction_id: String,
        /// "user_to_network", "network_to_target", or reward types
        transaction_type: String,
        solver_address: Option<String>,
        /// Node that broadcasted the transaction
        node_id: String,
    },
    /// Separate broadcast for NetworkToTarget transactions to establish the final node ID
    FinalNodeIdBroadcast {
        intent_hashes: Vec<String>,
        final_node_id: String,
    },
    TransactionErrorBroadcast {
        /// Intent hashes that failed. Empty for reward/withdraw.
        intent_hashes: Vec<String>,
        error_message: String,
        /// "user_to_network", "network_to_target", or reward types
        transaction_type: String,
        solver_address: Option<String>,
        /// Node that encountered the error
        node_id: String,
    },
    /// BTC withdraw-liquidity batch broadcast
    BtcWithdrawBatch {
        batch_id: String,
        requests: Vec<(String, String)>,
        round: u64,
        timestamp: String,
        node_id: String,
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// BTC claim-reward batch broadcast (same flow as BtcWithdrawBatch).
    BtcClaimRewardBatch {
        batch_id: String,
        requests: Vec<(String, String)>,
        round: u64,
        timestamp: String,
        node_id: String,
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// TICS withdraw-liquidity batch broadcast.
    /// Final node broadcasts selected TICS (and optionally BTC) withdraw requests
    /// so all nodes can aggregate per-solver amounts and submit a single
    /// removeLiquidity contract call via MPC signing.
    TicsWithdrawBatch {
        batch_id: String,
        requests: Vec<TicsWithdrawBatchRequest>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// TICS claim-reward batch broadcast (same flow as TicsWithdrawBatch).
    TicsClaimRewardBatch {
        batch_id: String,
        requests: Vec<TicsClaimRewardBatchRequest>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Unified claim-reward transaction ID broadcast for both TICS and BTC (same shape as WithdrawTxIdBroadcast).
    ClaimRewardTxIdBroadcast {
        txid: String,
        network: String,
        batch_id: String,
        solver_address: Option<String>,
        requests: Vec<(String, String)>,
        node_id: String,
    },
    /// Unified withdraw-liquidity transaction ID broadcast for both BTC and TICS.
    /// Carries sufficient context (network, batch_id, solver, per-request mapping)
    /// so that the handler can:
    /// - For BTC: update tx_id for each (request_id, solver_address) pair.
    /// - For TICS: set tx_id and mark TICS withdraw requests for the solver as Completed.
    WithdrawTxIdBroadcast {
        txid: String,
        network: String,
        batch_id: String,
        solver_address: Option<String>,
        requests: Vec<(String, String)>,
        node_id: String,
    },
    /// Propagate a new pending withdraw-liquidity request to all nodes so they store it in DB.
    /// Sent by the node that received the withdraw_liquidity RPC; peers store the same request.
    PendingWithdrawRequestBroadcast {
        request: PendingWithdrawRequest,
    },
    /// Propagate a new pending claim-platform-fee request to all nodes so they store it in DB.
    /// Sent by the node that received the claim_platform_fee admin RPC.
    PendingClaimPlatformFeeRequestBroadcast {
        request: crate::types::rpc_server::PendingClaimPlatformFeeRequest,
    },
    /// BTC claim-platform-fee batch broadcast (same flow as BtcWithdrawBatch).
    BtcClaimPlatformFeeBatch {
        batch_id: String,
        /// (request_id, btc_target_address) pairs
        requests: Vec<(String, String)>,
        round: u64,
        timestamp: String,
        node_id: String,
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Claim-platform-fee transaction ID broadcast.
    ClaimPlatformFeeTxIdBroadcast {
        txid: String,
        network: String,
        batch_id: String,
        /// (request_id, btc_target_address) pairs
        requests: Vec<(String, String)>,
        node_id: String,
    },
    TicsClaimPlatformFeeBatch {
        batch_id: String,
        requests: Vec<TicsClaimPlatformFeeBatchRequest>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce tuple_id for this batch's signature (all nodes must use the same nonce)
        #[serde(default)]
        nonce_tuple_id: Option<String>,
    },
    /// Acknowledgment messages for critical message retry mechanism
    CriticalMessageAck {
        /// Type of message being acknowledged
        message_type: String,
        /// Unique identifier of the message
        message_id: String,
        /// Node that is acknowledging
        node_id: PeerId,
    },
    TransactionBroadcast {
        /// Sequencer request ID (None for non-sequencer transactions)
        sequencer_request_id: Option<String>,
        /// Blockchain transaction hash
        blockchain_tx_hash: String,
        /// Chain ID where the transaction was broadcasted
        chain_id: u64,
    },
    /// Batch of intent hashes for processing by all nodes
    /// Sent by final node after global clock trigger
    IntentBatchBroadcast {
        /// List of intent hashes to process
        intent_hashes: Vec<String>,
        /// Batch type: "BTC" or "TICS"
        batch_type: String,
        /// Timestamp when batch was created
        timestamp: String,
        /// Round number that triggered this batch
        round: u64,
        /// Node ID of the final node broadcasting this batch
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// TICS UserToVault intent batch: intents with source_chain TICS to be signed individually (one tx per intent).
    TicsUserToVaultIntentBatch {
        intent_hashes: Vec<String>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce assignments: intent_hash -> per-input nonce tuple IDs
        /// All nodes must use the same nonce tuple ID per input index to ensure signature aggregation
        #[serde(default)]
        nonce_assignments: std::collections::HashMap<String, Vec<String>>,
    },
    /// BTC UserToVault intent batch: intents with source_chain bitcoin to be signed individually (one tx per intent).
    BtcUserToVaultIntentBatch {
        intent_hashes: Vec<String>,
        round: u64,
        timestamp: String,
        node_id: String,
        /// Nonce assignments: intent_hash -> per-input nonce tuple IDs
        /// All nodes must use the same nonce tuple ID per input index to ensure signature aggregation
        #[serde(default)]
        nonce_assignments: std::collections::HashMap<String, Vec<String>>,
    },
    /// Notification that a transaction failed (signature verification, broadcasting, etc.)
    TransactionFailure {
        /// Sequencer request ID
        sequencer_request_id: String,
        /// Blockchain transaction hash (or "N/A" if failed before broadcasting)
        blockchain_tx_hash: String,
        /// Error message
        error: String,
        /// Original request for guaranteed retry (even if cache is empty)
        original_request: Option<()>,
    },
    /// BTC Intent Manager contract update batch
    /// Used to update network-to-target tx-id on contract for BTC intents
    BtcIntentManagerTxUpdate {
        /// List of intent hashes to update on contract
        intent_hashes: Vec<String>,
        /// BTC batch transaction ID that was finalized
        btc_txid: String,
        /// Round number of the BTC batch
        btc_batch_round: u64,
        /// Round number for the contract update batch
        update_round: u64,
        /// Timestamp when batch was created
        timestamp: String,
        /// Node ID broadcasting this batch
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Broadcast finalized nonce tuples to all nodes (including observers).
    /// Observer nodes store these locally so they can reserve nonce tuple IDs
    /// when acting as the final node for batch coordination.
    NonceTupleBroadcast {
        batch_id: String,
        tuples: Vec<crate::types::nonce::NonceTuple>,
        /// Node that generated/broadcasted the nonces
        node_id: String,
    },
    /// Nonce invalidation broadcast.
    /// When any node fails to find a coordinated nonce during signing (e.g. it was
    /// deleted as stale or never arrived), it broadcasts this message so ALL nodes
    /// mark that nonce as consumed.  This prevents inconsistent nonce pool state
    /// where some nodes still hold the nonce and others don't.
    NonceInvalidation {
        /// The nonce tuple IDs to invalidate
        nonce_tuple_ids: Vec<String>,
        /// Reason for invalidation (for logging)
        reason: String,
        /// Node that detected the problem
        node_id: String,
    },
    /// Peer disconnection notification
    /// Broadcast when a peer disconnects to track for batch invalidation
    PeerDisconnection {
        /// Peer ID that disconnected
        peer_id: String,
        /// Solver ID associated with the peer
        solver_id: String,
        /// Timestamp when disconnection was detected
        timestamp: i64,
        /// Node ID that detected the disconnection
        detector_node_id: String,
    },
    /// Peer invalidation batch broadcast (same flow as BtcWithdrawBatch / BtcClaimRewardBatch).
    /// Final node broadcasts selected disconnected solver IDs for distributed signing.
    PeerInvalidationBatch {
        /// List of solver IDs to invalidate
        solver_ids: Vec<String>,
        /// Round number that triggered this batch
        round: u64,
        /// Timestamp when batch was created
        timestamp: String,
        /// Node ID of the final node broadcasting this batch
        node_id: String,
        /// Nonce tuple IDs aligned to transaction inputs (index -> nonce tuple_id)
        #[serde(default)]
        nonce_tuple_ids: Option<Vec<String>>,
    },
    /// Broadcast when a peer invalidation request is safely deleted because the solver
    /// was already invalidated on the smart contract.
    PeerInvalidationDeleted {
        /// The solver ID that was deleted
        solver_id: String,
        /// The node ID that detected the on-chain invalidation
        node_id: String,
    },
    /// Periodic active peer list broadcast for peer count reconciliation.
    /// Nodes broadcast their active peer list every 3rd clock tick so peers
    /// can detect and fix missing entries (merge-up only, never removes).
    ActivePeerList {
        /// Node broadcasting its peer list
        node_id: String,
        /// List of (peer_id_string, optional_index) pairs
        peers: Vec<(String, Option<usize>)>,
        /// Timestamp of broadcast
        timestamp: i64,
    },
}
