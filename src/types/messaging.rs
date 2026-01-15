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
        /// If provided, use user's tweaked share; otherwise use network's DKG share
        user_eth_address: Option<String>,
        transaction_type: TransactionType,
        amount: u128,
    },
    IntentHash {
        intent_hash: Vec<u8>,
        signer: String,
        intent: DepositIntent,
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
        original_request: Option<crate::network::ContractTransactionRequest>,
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
    IntentHashBroadcast {
        intent_hash: String,
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
    /// Request a missing DKG share from a peer
    RequestDKGShare {
        target_peer_id: String,
        requester_id: String,
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
    // Core Protocol
    DKG(DKGMessage),
    Signing(SigningMessage),
    Command(Command),
    Consensus(ConsensusMessage),
    PeerDiscovered {
        peer: PeerId,
        sequence: Option<u64>,
        index: Option<usize>,
    },
    
    // VRF (Generic/Legacy)
    VrfSelection(VrfSelectionMessage),
    VrfSelectedNodes(VrfSelectedNodesBroadcast),
    VrfRoundSyncRequest(VrfRoundSyncRequest),
    VrfRoundSyncResponse(VrfRoundSyncResponse),

    // Consolidated / Multiplexed Topics
    SequencerConsensus(SequencerConsensusMessage),
    Liquidity(LiquidityMessage),
    Rewards(RewardMessage),
    Sync(SyncMessage),
    
    // Transactions
    TransactionIdBroadcast {
        intent_hash: Option<String>,
        transaction_id: String,
        transaction_type: String,
        solver_address: Option<String>,
        node_id: String,
    },
    TransactionBroadcast {
        sequencer_request_id: Option<String>,
        blockchain_tx_hash: String,
        chain_id: u64,
    },
    TransactionFailure {
        sequencer_request_id: String,
        blockchain_tx_hash: String,
        error: String,
        original_request: Option<crate::network::ContractTransactionRequest>,
    },
    TransactionErrorBroadcast {
        intent_hash: Option<String>,
        error_message: String,
        transaction_type: String,
        solver_address: Option<String>,
        node_id: String,
    },

    // Intents
    DepositIntent {
        intent: DepositIntent,
        intent_id: String,
        user_eth_address: Option<String>,
        transaction_type: TransactionType,
        amount: u128,
    },
    IntentHash {
        intent_hash: String,
        signer: String,
        intent: DepositIntent,
    },
    IntentHashBroadcast {
        intent_hash: String,
        node_id: String,
    },

    // System
    UserRegistration {
        ethereum_address: String,
        timestamp: i64,
        node_id: String,
    },
    CriticalMessageAck {
        message_type: String,
        message_id: String,
        node_id: PeerId,
    },
    VersionAnnouncement {
        peer: PeerId,
        version: String,
        features: Vec<String>,
        timestamp: i64,
    },
    UpgradeAnnouncement {
        peer: PeerId,
        target_version: String,
        phase: String,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SequencerConsensusMessage {
    // VRF
    VrfSelectedNodes {
        domain: SequencerDomain,
        broadcast: VrfSelectedNodesBroadcast,
    },
    VrfRoundSyncRequest {
        domain: SequencerDomain,
        req: VrfRoundSyncRequest,
    },
    VrfRoundSyncResponse {
        domain: SequencerDomain,
        resp: VrfRoundSyncResponse,
    },
    
    // Select/Consensus
    Select {
        domain: SequencerDomain,
        round: u64,
        request_id: String,
        final_node_id: PeerId,
        signature: Vec<u8>,
    },
    Ack {
        domain: SequencerDomain,
        round: u64,
        request_id: String,
        node_id: PeerId,
    },
    Missing {
        domain: SequencerDomain,
        round: u64,
        request_id: String,
        node_id: PeerId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SequencerDomain {
    Vault,
    Main,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityMessage {
    Add {
        solver_address: String,
        solver_id: String,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        request_id: String,
    },
    Withdraw {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        amount_btc: Option<String>,
        amount_tics: Option<String>,
        transaction_type: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RewardMessage {
    Claim {
        solver_address: String,
        btc_address: Option<String>,
        eth_address: Option<String>,
        reward_btc: Option<String>,
        reward_tics: Option<String>,
        transaction_type: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    // General Sequencer Sync
    Sequencer {
        transaction_id: String,
        sequence: u64,
        node_id: String,
        state: String,
    },
    // Network Transaction Sync
    NetworkSequencer {
        transaction_id: String,
        sequence: u64,
        node_id: String,
        state: String,
    },
}
