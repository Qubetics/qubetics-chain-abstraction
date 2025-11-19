use anyhow::Result;
use libp2p::{
    gossipsub::{self, TopicHash},
    kad::{self, store::MemoryStore, Event as KademliaEvent},
    request_response::{cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent},
    swarm::NetworkBehaviour,
    PeerId,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::commands::CommandProcessor;
use crate::consensus::ConsensusNode;
use crate::database::Database;
use crate::node_selection::NodeMembership;
use crate::signing::{DatabaseSigningNode, SigningNode};
use crate::threshold_dkg::DKGNode;
use crate::types::dkg::{MSG_TOPIC_DKG, MSG_TOPIC_PEER_DISCOVERY};
use crate::types::rpc::{MPCCodecRequest, MPCCodecResponse, RPCRequest, RPCResponse};
use crate::types::ChannelMessage;
use crate::user_intent_manager::UserIntentManager;

/// Network behavior combining Gossipsub, Request-Response, and Kademlia for MPC nodes
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkEvent")]
pub struct MpcNetworkBehaviour {
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

/// Typed view of the gossipsub topics this MPC node participates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GossipTopic {
    Dkg,
    PeerDiscovery,
    Signing,
    Consensus,
    Commands,
    VrfSelection,
    Transactions,
    DepositIntents,
    IntentHashes,
    DkgCommands,
    SignaturesToFinalNode,
    UserRegistrations,
    SolverRewards,
    ClaimRewards,
    TransactionIdSync,
    ConsensusResult,
    TransactionErrorSync,
    LegacyDkg,
}

impl GossipTopic {
    pub const MPC_TOPICS: &'static [GossipTopic] = &[
        GossipTopic::Dkg,
        GossipTopic::PeerDiscovery,
        GossipTopic::Signing,
        GossipTopic::Consensus,
        GossipTopic::Commands,
        GossipTopic::VrfSelection,
        GossipTopic::Transactions,
        GossipTopic::DepositIntents,
        GossipTopic::IntentHashes,
        GossipTopic::DkgCommands,
        GossipTopic::SignaturesToFinalNode,
        GossipTopic::UserRegistrations,
        GossipTopic::SolverRewards,
        GossipTopic::ClaimRewards,
        GossipTopic::TransactionIdSync,
        GossipTopic::ConsensusResult,
        GossipTopic::TransactionErrorSync,
        GossipTopic::LegacyDkg,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            GossipTopic::Dkg => MSG_TOPIC_DKG,
            GossipTopic::PeerDiscovery => MSG_TOPIC_PEER_DISCOVERY,
            GossipTopic::Signing => "signing",
            GossipTopic::Consensus => "consensus",
            GossipTopic::Commands => "commands",
            GossipTopic::VrfSelection => "vrf-selection",
            GossipTopic::Transactions => "transactions",
            GossipTopic::DepositIntents => "deposit-intents",
            GossipTopic::IntentHashes => "intent-hashes",
            GossipTopic::DkgCommands => "dkg-commands",
            GossipTopic::SignaturesToFinalNode => "signatures-to-final-node",
            GossipTopic::UserRegistrations => "user-registrations",
            GossipTopic::SolverRewards => "solver-rewards",
            GossipTopic::ClaimRewards => "claim-rewards",
            GossipTopic::TransactionIdSync => "transaction-id-sync",
            GossipTopic::ConsensusResult => "consensus-result",
            GossipTopic::TransactionErrorSync => "transaction-error-sync",
            GossipTopic::LegacyDkg => "dkg",
        }
    }
}

pub const MPC_TOPICS: &[GossipTopic] = GossipTopic::MPC_TOPICS;

/// Peer discovery subsystem state for MPC networking
#[derive(Debug, Default)]
pub struct PeerDiscoveryState {
    pub peer_indices: HashMap<PeerId, usize>,
    pub pending_peer_discovery_retry: bool,
    pub processed_disconnects: HashMap<PeerId, Instant>,
}

impl PeerDiscoveryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_retry_pending(&mut self) {
        self.pending_peer_discovery_retry = true;
    }

    pub fn clear_retry(&mut self) {
        self.pending_peer_discovery_retry = false;
    }
}

/// Main network layer struct managing P2P networking and MPC operations
pub struct MpcNetworkLayer {
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
    pub(crate) peer_discovery: PeerDiscoveryState,
    pub(crate) db: Database,
    pub(crate) db_sync_state: DatabaseSyncState,
    pub(crate) needs_database_sync: bool,
}

impl MpcNetworkLayer {
    pub const MAX_PEER_DISCOVERY_RETRIES: u8 = 10;
}
