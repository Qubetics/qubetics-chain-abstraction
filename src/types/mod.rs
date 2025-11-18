use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    UserToVault,
    NetworkToTarget,
    VaultToNetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionNetwork {
    TICS, // EVM/TICS transactions
    BTC,  // Bitcoin transactions
}

mod secp;
pub use secp::{SerializablePoint, SerializableScalar};

pub mod dkg;
pub mod p2p;
pub mod rpc;
pub mod rpc_server;
pub use rpc_server::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerInfo {
    pub addresses: Vec<Multiaddr>,
    pub connected: bool,
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
        user_eth_address: Option<String>, // If provided, use user's tweaked share; otherwise use network's DKG share
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
pub struct KeyShare {
    pub index: usize,
    pub value: SerializableScalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipsubMessage {
    DKG(crate::adkg_secp256k1::DKGMessage),
    Signing(crate::signing::SigningMessage),
    Command(crate::commands::Command),
    Consensus(crate::consensus::ConsensusMessage),
    VrfSelection(crate::vrf::VrfSelectionMessage),
    VrfSelectedNodes(crate::vrf::VrfSelectedNodesBroadcast),
    PeerDiscovered {
        peer: PeerId,
        sequence: Option<u64>,
        index: Option<usize>,
    },
    DepositIntent {
        intent: DepositIntent,
        intent_id: String,
        user_eth_address: Option<String>, // If provided, use user's tweaked share; otherwise use network's DKG share
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
    DKGCommand(crate::types::rpc::RPCRequest),
    UserRegistration {
        ethereum_address: String,
        timestamp: i64,
        node_id: String,
    },
    TransactionIdBroadcast {
        intent_hash: Option<String>,
        transaction_id: String,
        transaction_type: String, // "user_to_network", "network_to_target", "vault_to_network", or reward types
        solver_address: Option<String>,
        node_id: String, // Node that broadcasted the transaction
    },
    TransactionErrorBroadcast {
        intent_hash: Option<String>,
        error_message: String,
        transaction_type: String, // "user_to_network", "network_to_target", "vault_to_network", or reward types
        solver_address: Option<String>,
        node_id: String, // Node that encountered the error
    },
    IntentHashBroadcast {
        intent_hash: String,
        node_id: String,
    },
}
