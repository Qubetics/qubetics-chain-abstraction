use anyhow::Result;
use libp2p::{
    gossipsub::{self, TopicHash},
    kad::{self, store::MemoryStore, Event as KademliaEvent},
    request_response::{
        cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent,
    },
    swarm::NetworkBehaviour,
    PeerId,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::adkg_secp256k1::DKGNode;
use crate::commands::CommandProcessor;
use crate::consensus::ConsensusNode;
use crate::database::Database;
use crate::node_selection::NodeMembership;
use crate::signing::{DatabaseSigningNode, SigningNode};
use crate::types::rpc::{MPCCodecRequest, MPCCodecResponse, RPCRequest, RPCResponse};
use crate::types::ChannelMessage;
use crate::user_intent_manager::UserIntentManager;

/// Network behavior combining Gossipsub, Request-Response, and Kademlia
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkEvent")]
pub struct MPCBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub request_response: CborReqRespBehaviour<MPCCodecRequest, MPCCodecResponse>,
    pub kademlia: kad::Behaviour<MemoryStore>,
}

/// Network events from different protocol layers
#[derive(Debug)]
pub enum NetworkEvent {
    Gossipsub(gossipsub::Event),
    RequestResponse(ReqRespEvent<RPCRequest, RPCResponse>),
    Kademlia(KademliaEvent),
}

impl From<gossipsub::Event> for NetworkEvent {
    fn from(event: gossipsub::Event) -> Self {
        NetworkEvent::Gossipsub(event)
    }
}

impl From<KademliaEvent> for NetworkEvent {
    fn from(event: KademliaEvent) -> Self {
        NetworkEvent::Kademlia(event)
    }
}

impl From<ReqRespEvent<RPCRequest, RPCResponse>> for NetworkEvent {
    fn from(event: ReqRespEvent<RPCRequest, RPCResponse>) -> Self {
        NetworkEvent::RequestResponse(event)
    }
}

/// Database sync state for tracking synchronization progress
#[derive(Debug, Clone)]
pub struct DatabaseSyncState {
    pub in_progress: bool,
    pub source_peer: Option<PeerId>,
    pub total_entries: usize,
    pub batch_size: usize,
    pub current_batch: usize,
    pub total_batches: usize,
    pub entries_synced: usize,
}

impl DatabaseSyncState {
    pub fn new() -> Self {
        Self {
            in_progress: false,
            source_peer: None,
            total_entries: 0,
            batch_size: 0,
            current_batch: 0,
            total_batches: 0,
            entries_synced: 0,
        }
    }

    pub fn start_sync(&mut self, peer: PeerId, total_entries: usize, batch_size: usize) {
        self.in_progress = true;
        self.source_peer = Some(peer);
        self.total_entries = total_entries;
        self.batch_size = batch_size;
        self.current_batch = 0;
        self.total_batches = (total_entries + batch_size - 1) / batch_size;
        self.entries_synced = 0;
    }

    pub fn complete_batch(&mut self, entries_count: usize) {
        self.current_batch += 1;
        self.entries_synced += entries_count;
    }

    pub fn finish_sync(&mut self) {
        self.in_progress = false;
        self.source_peer = None;
    }

    pub fn progress_percentage(&self) -> f32 {
        if self.total_entries == 0 {
            return 100.0;
        }
        (self.entries_synced as f32 / self.total_entries as f32) * 100.0
    }
}

/// Main network layer struct managing P2P networking and MPC operations
pub struct NetworkLayer {
    pub(crate) local_key: libp2p::identity::Keypair,
    pub(crate) local_peer_id: PeerId,
    pub(crate) message_tx: mpsc::Sender<ChannelMessage>,
    pub(crate) message_rx: mpsc::Receiver<ChannelMessage>,
    pub(crate) topics: HashSet<TopicHash>,
    pub(crate) dkg_node: Option<DKGNode>,
    pub(crate) signing_node: Option<SigningNode>,
    pub(crate) db_signing_node: Option<Arc<Mutex<DatabaseSigningNode>>>,
    pub(crate) consensus_node: Option<ConsensusNode>,
    pub(crate) command_processor: Option<CommandProcessor>,
    pub(crate) user_intent_manager: Option<UserIntentManager>,
    pub(crate) node_manager: Box<dyn NodeMembership>,
    pub(crate) scheduled_dkg_task: Option<JoinHandle<()>>,
    pub(crate) vrf_round_requested: bool,
    pub(crate) peer_indices: HashMap<PeerId, usize>,
    pub(crate) db: Database,
    pub(crate) db_sync_state: DatabaseSyncState,
    pub(crate) needs_database_sync: bool,
    pub(crate) pending_peer_discovery_retry: bool,
    pub(crate) processed_disconnects: HashMap<PeerId, Instant>,
}

impl NetworkLayer {
    pub const MAX_PEER_DISCOVERY_RETRIES: u8 = 10;
}

