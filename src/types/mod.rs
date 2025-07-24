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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DepositIntent {
    pub source_address: String,
    pub target_address: String,
    pub source_chain: String,
    pub target_chain: String,
    pub amount: u128,
    pub source_token: String,
    pub target_token: String,
    pub path: Vec<u8>,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHashBroadcast {
    pub intent_hash: String,
    pub transaction_hash: String,
    pub chain_type: String, // "eth" or "btc"
    pub round: u64,
    pub node_id: String,
}

#[derive(Debug)]
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
    LocalIntent {
        intent: DepositIntent,
    },
    LocalTransactionHash {
        tx_hash_broadcast: TransactionHashBroadcast,
    },
    QueryTransactionHash {
        intent_hash: String,
        response_tx: tokio::sync::oneshot::Sender<Option<String>>,
    },
    ScheduledDKGStart,
}

impl Clone for ChannelMessage {
    fn clone(&self) -> Self {
        match self {
            ChannelMessage::Broadcast { topic, data } => ChannelMessage::Broadcast {
                topic: topic.clone(),
                data: data.clone(),
            },
            ChannelMessage::Unicast { peer_id, data } => ChannelMessage::Unicast {
                peer_id: peer_id.clone(),
                data: data.clone(),
            },
            ChannelMessage::LocalTransaction { transaction } => ChannelMessage::LocalTransaction {
                transaction: transaction.clone(),
            },
            ChannelMessage::LocalIntent { intent } => ChannelMessage::LocalIntent {
                intent: intent.clone(),
            },
            ChannelMessage::LocalTransactionHash { tx_hash_broadcast } => ChannelMessage::LocalTransactionHash {
                tx_hash_broadcast: tx_hash_broadcast.clone(),
            },
            ChannelMessage::QueryTransactionHash { .. } => {
                panic!("QueryTransactionHash cannot be cloned due to oneshot::Sender")
            },
            ChannelMessage::ScheduledDKGStart => ChannelMessage::ScheduledDKGStart,
        }
    }
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
    VrfSelectedNodes(crate::vrf::VrfSelectedNodesBroadcast),
    PeerDiscovered { peer: PeerId, sequence: Option<u64> },
    Transaction(crate::rpc_server::DummyTransaction),
    Intent(DepositIntent),
    TransactionHash(TransactionHashBroadcast),
    DKGCommand(crate::types::rpc::RPCRequest),
}
