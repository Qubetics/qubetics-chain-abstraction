use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

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
    },
    UserRegistration {
        ethereum_address: String,
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
    },
    DKGCommand(crate::types::rpc::RPCRequest),
    UserRegistration {
        ethereum_address: String,
        timestamp: i64,
        node_id: String,
    },
    IntentBroadcast {
        intent: crate::rpc_server::DepositIntent,
        signature: String,
        intent_hash: String,
    },
}
