use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

mod bls;
pub use bls::{SerializableG1Affine, SerializableScalar};

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
    ScheduledDKGStart
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub index: usize,
    pub value: SerializableScalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipsubMessage {
    DKG(crate::dkg::DKGMessage),
    Signing(crate::signing::SigningMessage),
    Command(crate::commands::Command),
    Consensus(crate::consensus::ConsensusMessage),
    VrfSelection(crate::vrf::VrfSelectionMessage),
    PeerDiscovered { peer: PeerId, sequence: Option<u64> },
    Transaction(crate::rpc_server::DummyTransaction),
    DKGCommand(crate::types::rpc::RPCRequest),
}
