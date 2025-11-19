use crate::{
    commands::Command,
    threshold_dkg::DKGMessage,
    types::{
        intent::{DepositIntent, TransactionType},
        rpc::RPCRequest,
        secp::SerializableScalar,
        signing::SigningMessage,
        ConsensusMessage,
    },
    vrf::{VrfSelectedNodesBroadcast, VrfSelectionMessage},
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Share metadata for AVSS exchanges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub index: usize,
    pub value: SerializableScalar,
}

#[derive(Debug, Clone)]
pub enum ChannelMessage {
    Broadcast {
        topic: String,
        data: Vec<u8>,
    },
    Unicast {
        peer_id: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipsubMessage {
    DKG(DKGMessage),
    Signing(SigningMessage),
    Command(Command),
    Consensus(ConsensusMessage),
    VrfSelection(VrfSelectionMessage),
    VrfSelectedNodes(VrfSelectedNodesBroadcast),
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
}
