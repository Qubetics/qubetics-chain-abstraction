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
    TICS,  // EVM/TICS transactions
    BTC,   // Bitcoin transactions
}

mod secp;
pub use secp::{SerializablePoint, SerializableScalar};

pub mod dkg;
pub mod p2p;
pub mod rpc;

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
    LocalTransaction {
        transaction: crate::rpc_server::DummyTransaction,
    },
    DepositIntent {
        intent: crate::rpc_server::DepositIntent,
        intent_id: String,
        user_eth_address: Option<String>, // If provided, use user's tweaked share; otherwise use network's DKG share
        transaction_type: TransactionType,
        amount: u128,
    },
    IntentHash {
        intent_hash: Vec<u8>,
        signer: String,
        intent: crate::rpc_server::DepositIntent,
    },
    TransactionIdBroadcast {
        intent_hash: String,
        transaction_id: String,
        transaction_type: String,
        node_id: String,
    },
    SolverReward {
        solver_address: String,
        reward: u128,
    },
    UserRegistration {
        ethereum_address: String,
        node_id: String,
    },
    IntentHashBroadcast {
        intent_hash: String,
        node_id: String,
    },
    ScheduledDKGStart,
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
    },
    Transaction(crate::rpc_server::DummyTransaction),
    DepositIntent {
        intent: crate::rpc_server::DepositIntent,
        intent_id: String,
        user_eth_address: Option<String>, // If provided, use user's tweaked share; otherwise use network's DKG share
        transaction_type: TransactionType,
        amount: u128,
    },
    IntentHash {
        intent_hash: String,
        signer: String,
        intent: crate::rpc_server::DepositIntent,
    },
    SolverReward {
        solver_address: String,
        reward: u128,
    },
    DKGCommand(crate::types::rpc::RPCRequest),
    UserRegistration {
        ethereum_address: String,
        timestamp: i64,
        node_id: String,
    },
    TransactionIdBroadcast {
        intent_hash: String,
        transaction_id: String,
        transaction_type: String, // "user_to_network", "network_to_target", or "vault_to_network"
        node_id: String,          // Node that broadcasted the transaction
    },
    TransactionErrorBroadcast {
        intent_hash: String,
        error_message: String,
        transaction_type: String, // "user_to_network", "network_to_target", or "vault_to_network"
        node_id: String,          // Node that encountered the error
    },
    IntentHashBroadcast {
        intent_hash: String,
        node_id: String,
    },
}
