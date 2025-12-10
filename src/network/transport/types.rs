use libp2p::{
    gossipsub::{self, TopicHash},
    kad::{self, store::MemoryStore, Event as KademliaEvent},
    request_response::{cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent},
    swarm::NetworkBehaviour,
    Multiaddr, PeerId,
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::commands::CommandProcessor;
use crate::consensus::ConsensusNode;
use crate::database::Database;
use crate::network::discovery::types::{DatabaseSyncState, PeerDiscoveryState};
use crate::network::sequencer::{ContractTransactionSequencer, NetworkTransactionSequencer};
use crate::node_selection::NodeMembership;
use crate::protocols::DKGNode;
use crate::signing::{DatabaseSigningNode, SigningNode};
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

pub const TOPIC_SIGNING: &str = "signing";
pub const TOPIC_CONSENSUS: &str = "consensus";
pub const TOPIC_COMMANDS: &str = "commands";
pub const TOPIC_VRF_SELECTION: &str = "vrf-selection";
pub const TOPIC_TRANSACTIONS: &str = "transactions";
pub const TOPIC_DEPOSIT_INTENTS: &str = "deposit-intents";
pub const TOPIC_INTENT_HASHES: &str = "intent-hashes";
pub const TOPIC_DKG_COMMANDS: &str = "dkg-commands";
pub const TOPIC_SIGNATURES_TO_FINAL_NODE: &str = "signatures-to-final-node";
pub const TOPIC_USER_REGISTRATIONS: &str = "user-registrations";
pub const TOPIC_SOLVER_REWARDS: &str = "solver-rewards";
pub const TOPIC_CLAIM_REWARDS: &str = "claim-rewards";
pub const TOPIC_ADD_LIQUIDITY: &str = "add-liquidity";
pub const TOPIC_WITHDRAW_LIQUIDITY: &str = "withdraw-liquidity";
pub const TOPIC_TRANSACTION_ID_SYNC: &str = "transaction-id-sync";
pub const TOPIC_CONSENSUS_RESULT: &str = "consensus-result";
pub const TOPIC_TRANSACTION_ERROR_SYNC: &str = "transaction-error-sync";
pub const TOPIC_LEGACY_DKG: &str = "dkg";
pub const TOPIC_SEQUENCER_SYNC: &str = "sequencer-sync";
pub const TOPIC_NETWORK_TRANSACTION_SEQUENCER_SYNC: &str = "network-transaction-sequencer-sync";

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
    AddLiquidity,
    WithdrawLiquidity,
    TransactionIdSync,
    ConsensusResult,
    TransactionErrorSync,
    LegacyDkg,
    SequencerSync,
    NetworkTransactionSequencerSync,
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
        GossipTopic::AddLiquidity,
        GossipTopic::WithdrawLiquidity,
        GossipTopic::TransactionIdSync,
        GossipTopic::ConsensusResult,
        GossipTopic::TransactionErrorSync,
        GossipTopic::LegacyDkg,
        GossipTopic::SequencerSync,
        GossipTopic::NetworkTransactionSequencerSync,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            GossipTopic::Dkg => MSG_TOPIC_DKG,
            GossipTopic::PeerDiscovery => MSG_TOPIC_PEER_DISCOVERY,
            GossipTopic::Signing => TOPIC_SIGNING,
            GossipTopic::Consensus => TOPIC_CONSENSUS,
            GossipTopic::Commands => TOPIC_COMMANDS,
            GossipTopic::VrfSelection => TOPIC_VRF_SELECTION,
            GossipTopic::Transactions => TOPIC_TRANSACTIONS,
            GossipTopic::DepositIntents => TOPIC_DEPOSIT_INTENTS,
            GossipTopic::IntentHashes => TOPIC_INTENT_HASHES,
            GossipTopic::DkgCommands => TOPIC_DKG_COMMANDS,
            GossipTopic::SignaturesToFinalNode => TOPIC_SIGNATURES_TO_FINAL_NODE,
            GossipTopic::UserRegistrations => TOPIC_USER_REGISTRATIONS,
            GossipTopic::SolverRewards => TOPIC_SOLVER_REWARDS,
            GossipTopic::ClaimRewards => TOPIC_CLAIM_REWARDS,
            GossipTopic::AddLiquidity => TOPIC_ADD_LIQUIDITY,
            GossipTopic::WithdrawLiquidity => TOPIC_WITHDRAW_LIQUIDITY,
            GossipTopic::TransactionIdSync => TOPIC_TRANSACTION_ID_SYNC,
            GossipTopic::ConsensusResult => TOPIC_CONSENSUS_RESULT,
            GossipTopic::TransactionErrorSync => TOPIC_TRANSACTION_ERROR_SYNC,
            GossipTopic::LegacyDkg => TOPIC_LEGACY_DKG,
            GossipTopic::SequencerSync => TOPIC_SEQUENCER_SYNC,
            GossipTopic::NetworkTransactionSequencerSync => TOPIC_NETWORK_TRANSACTION_SEQUENCER_SYNC,
        }
    }
}

pub const MPC_TOPICS: &[GossipTopic] = GossipTopic::MPC_TOPICS;

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
    pub(crate) bootstrap_addresses: Vec<Multiaddr>,
    pub(crate) bootstrap_peer_ids: Vec<PeerId>,
    pub(crate) discovery_seeds: Vec<Multiaddr>,
    pub(crate) contract_sequencer: Option<ContractTransactionSequencer>,
    /// Mutex to ensure only one contract transaction is processed at a time
    /// This prevents parallel processing even if multiple requests are queued
    pub(crate) contract_processing_lock: Arc<Mutex<()>>,
    pub(crate) network_transaction_sequencer: Option<NetworkTransactionSequencer>,
    /// Mutex to ensure only one network transaction is processed at a time
    pub(crate) network_transaction_processing_lock: Arc<Mutex<()>>,
}

impl MpcNetworkLayer {
    pub const MAX_PEER_DISCOVERY_RETRIES: u8 = 10;
}
