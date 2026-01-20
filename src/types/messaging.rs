use crate::{
    commands::Command,
    protocols::{DKGMessage, VrfSelectedNodesBroadcast, VrfSelectionMessage},
    types::{
        intent::{DepositIntent, TransactionType},
        rpc::RPCRequest,
        rpc_server::NodeStatus,
        secp::{SerializablePoint, SerializableScalar},
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

#[derive(Debug)]
pub enum ChannelMessage {
    Broadcast {
        topic: String,
        data: Vec<u8>,
    },
    DepositIntent {
        intent: DepositIntent,
        intent_id: String,
        /// User's Ethereum address - required for UserToVault deposits
        user_eth_address: String,
        transaction_type: TransactionType,
        amount: u128,
    },
    ClaimReward {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        reward_btc: Option<String>,
        reward_tics: Option<String>,
        transaction_type: String,
    },
    AddLiquidity {
        solver_address: String,
        solver_id: String,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        request_id: String,
    },
    WithdrawLiquidity {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        /// "withdraw_liquidity"
        transaction_type: String,
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
    },
    TransactionIdBroadcast {
        intent_hash: Option<String>,
        transaction_id: String,
        transaction_type: String,
        solver_address: Option<String>,
        node_id: String,
    },
    UserRegistration {
        ethereum_address: String,
        node_id: String,
    },
    RefundInitiation {
        intent_hash: String,
        data: Vec<u8>,
    },
    ScheduledDKGStart,
    PeerDiscoveryRetry {
        attempt: u8,
    },
    /// Send a DKG share to a specific peer via P2P RPC unicast
    UnicastShareDKG {
        target_peer_id: String,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
        round: u64,
        retry_count: u8,
    },
    /// Send a refresh share to a specific peer via P2P RPC unicast
    UnicastRefreshShare {
        target_peer_id: String,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
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
        /// User's Ethereum address - required for UserToVault deposits
        user_eth_address: String,
        /// Note: Gossiped DepositIntent is always processed as UserToVault
        amount: u128,
    },
    ClaimReward {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        reward_btc: Option<String>,
        reward_tics: Option<String>,
        transaction_type: String,
    },
    AddLiquidity {
        solver_address: String,
        solver_id: String,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        request_id: String,
    },
    WithdrawLiquidity {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        transaction_type: String,
    },
    UserRegistration {
        ethereum_address: String,
        timestamp: i64,
        node_id: String,
    },
    TransactionIdBroadcast {
        intent_hash: Option<String>,
        transaction_id: String,
        /// "user_to_network", "network_to_target", or reward types
        transaction_type: String,
        solver_address: Option<String>,
        /// Node that broadcasted the transaction
        node_id: String,
    },
    TransactionErrorBroadcast {
        intent_hash: Option<String>,
        error_message: String,
        /// "user_to_network", "network_to_target", or reward types
        transaction_type: String,
        solver_address: Option<String>,
        /// Node that encountered the error
        node_id: String,
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
    /// Version announcement for rolling upgrades
    VersionAnnouncement {
        peer: PeerId,
        version: String,
        features: Vec<String>,
        timestamp: i64,
    },
    /// Upgrade announcement (starting, completed, failed)
    UpgradeAnnouncement {
        peer: PeerId,
        target_version: String,
        phase: String, // "starting", "completed", "failed", "rolled_back"
        timestamp: u64,
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
}
