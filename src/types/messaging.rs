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
    /// Send a refresh share to a specific peer via P2P RPC unicast
    UnicastRefreshShare {
        target_peer_id: String,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
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
    MainSequencerVrfRoundSyncRequest(VrfRoundSyncRequest),
    MainSequencerVrfRoundSyncResponse(VrfRoundSyncResponse),
    VaultSequencerVrfRoundSyncRequest(VrfRoundSyncRequest),
    VaultSequencerVrfRoundSyncResponse(VrfRoundSyncResponse),
    PeerDiscovered {
        peer: PeerId,
        sequence: Option<u64>,
        index: Option<usize>,
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
        intent_hash: String,
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
        transaction_type: String,
    },
    DKGCommand(RPCRequest),
    UserRegistration {
        ethereum_address: String,
        timestamp: i64,
        node_id: String,
    },
    TransactionIdBroadcast {
        intent_hash: Option<String>,
        transaction_id: String,
        /// "user_to_network", "network_to_target", "vault_to_network", or reward types
        transaction_type: String,
        solver_address: Option<String>,
        /// Node that broadcasted the transaction
        node_id: String,
    },
    TransactionErrorBroadcast {
        intent_hash: Option<String>,
        error_message: String,
        /// "user_to_network", "network_to_target", "vault_to_network", or reward types
        transaction_type: String,
        solver_address: Option<String>,
        /// Node that encountered the error
        node_id: String,
    },
    IntentHashBroadcast {
        intent_hash: String,
        node_id: String,
    },
    SequencerSync {
        /// The transaction_id of the request being processed
        transaction_id: String,
        /// The sequence number for ordering
        sequence: u64,
        /// Node that is proposing/processing this request
        node_id: String,
        /// State: "proposed", "processing", "completed"
        state: String,
    },
    NetworkTransactionSequencerSync {
        /// The transaction_id of the request being processed
        transaction_id: String,
        /// The sequence number for ordering
        sequence: u64,
        /// Node that is proposing/processing this request
        node_id: String,
        /// State: "proposed", "processing", "completed"
        state: String,
    },
    /// Vault sequencer SELECT message (final node picks request)
    VaultSequencerSelect {
        round: u64,
        request_id: String,
        final_node_id: PeerId,
        signature: Vec<u8>,
    },
    /// Vault sequencer ACK message (node has the request)
    VaultSequencerAck {
        round: u64,
        request_id: String,
        node_id: PeerId,
    },
    /// Vault sequencer MISSING message (node doesn't have the request)
    VaultSequencerMissing {
        round: u64,
        request_id: String,
        node_id: PeerId,
    },
    /// VRF selected nodes broadcast for vault sequencer (independent rounds)
    VaultSequencerVrfSelectedNodes(VrfSelectedNodesBroadcast),
    /// Main sequencer SELECT message (final node picks request)
    MainSequencerSelect {
        round: u64,
        request_id: String,
        final_node_id: PeerId,
        signature: Vec<u8>,
    },
    /// Main sequencer ACK message (node has the request)
    MainSequencerAck {
        round: u64,
        request_id: String,
        node_id: PeerId,
    },
    /// Main sequencer MISSING message (node doesn't have the request)
    MainSequencerMissing {
        round: u64,
        request_id: String,
        node_id: PeerId,
    },
    /// VRF selected nodes broadcast for main sequencer (independent rounds)
    MainSequencerVrfSelectedNodes(VrfSelectedNodesBroadcast),
}
