use anyhow::Result;
use futures::StreamExt;
use std::sync::Arc;
use ethers::{
    abi::Token,
    providers::{Http, Provider},
    types::{Address, U256},
};
use std::str::FromStr;
use crate::prepare_unsigned_eip1559_tx;
use libp2p::{
    core::ConnectedPoint, gossipsub::{self, Message, TopicHash}, identity::Keypair, kad::{self, store::MemoryStore, BucketInserts, Event as KademliaEvent}, multiaddr::Protocol, noise, request_response::{
        cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent, Message as ReqRespMessage,
    }, swarm::{ConnectionError, NetworkBehaviour, SwarmEvent}, tcp, yamux, Multiaddr, PeerId
};
use sha2::Digest as Sha2Digest;

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher}, time::{SystemTime, UNIX_EPOCH},
};
use std::{
    collections::{ HashSet},
    env,
    fmt::Debug,
    time::Duration,
};
use tokio::io;
use tokio::task::JoinHandle;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use ff::PrimeField;

use crate::{chain::EthereumTransaction, commands::CommandProcessor, rpc_server::DummyTransaction, utils::transaction::get_default_gas_price_for_chain};
use crate::consensus::ConsensusNode;
use crate::adkg_secp256k1::DKGNode;
use crate::node_management::NodeMembership;
use crate::signing::{SigningNode, DatabaseSigningNode};
use crate::user_registry::{DatabaseUserRegistry, TransactionStatus};
use crate::{
    adkg_secp256k1::DKGStatus,
    types::{
        dkg::{MSG_TOPIC_DKG, MSG_TOPIC_PEER_DISCOVERY},
        p2p::SerializablePeerId,
        rpc::{
            build_mpc_behaviour, MPCCodecRequest, MPCCodecResponse, MPCProtocol, RPCRequest,
            RPCResponse,
        },
        ChannelMessage, GossipsubMessage, PeerInfo,
    },
};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkEvent")]
pub struct MPCBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    // mdns: mdns::tokio::Behaviour,
    pub request_response: CborReqRespBehaviour<MPCCodecRequest, MPCCodecResponse>,
    pub kademlia: kad::Behaviour<MemoryStore>,
}

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

pub struct NetworkLayer {
    local_key: Keypair,
    local_peer_id: PeerId,
    message_tx: mpsc::Sender<ChannelMessage>,
    message_rx: mpsc::Receiver<ChannelMessage>,
    topics: HashSet<TopicHash>,
    dkg_node: Option<DKGNode>,
    signing_node: Option<SigningNode>,
    db_signing_node: Option<Arc<Mutex<DatabaseSigningNode>>>,
    consensus_node: Option<ConsensusNode>,
    command_processor: Option<CommandProcessor>,
    user_registry: Option<DatabaseUserRegistry>,
    node_manager: Box<dyn NodeMembership>,
    scheduled_dkg_task: Option<JoinHandle<()>>,
    vrf_round_requested: bool, // Flag to prevent duplicate VRF round requests
}

impl NetworkLayer {
    pub async fn new(node_manager: Box<dyn NodeMembership>) -> Result<Self> {
        // Load or create persistent keypair
        let (local_key, local_peer_id) = Self::load_or_create_keypair().await?;
        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            local_key,
            local_peer_id,
            message_tx: tx,
            message_rx: rx,
            topics: HashSet::new(),
            dkg_node: None,
            signing_node: None,
            db_signing_node: None,
            consensus_node: None,
            command_processor: None,
            user_registry: None,
            node_manager,
            scheduled_dkg_task: None,
            vrf_round_requested: false,
        })
    }

    pub fn set_dkg_node(&mut self, dkg_node: DKGNode) {
        self.dkg_node = Some(dkg_node);
    }

    pub fn set_signing_node(&mut self, signing_node: SigningNode) {
        self.signing_node = Some(signing_node);
    }

    pub fn set_db_signing_node(&mut self, db_signing_node: Arc<Mutex<DatabaseSigningNode>>) {
        self.db_signing_node = Some(db_signing_node);
    }

    pub fn set_consensus_node(&mut self, node: ConsensusNode) {
        self.consensus_node = Some(node);
    }

    pub fn set_command_processor(&mut self, processor: CommandProcessor) {
        self.command_processor = Some(processor);
    }

    pub fn set_user_registry(&mut self, registry: Arc<DatabaseUserRegistry>) {
        info!("🔗 [NETWORK] Received database user registry - Arc pointer: {:p}", Arc::as_ptr(&registry));
        info!("🔗 [NETWORK] About to clone DatabaseUserRegistry from Arc");
        self.user_registry = Some((*registry).clone());
        info!("🔗 [NETWORK] DatabaseUserRegistry clone stored in network layer");

        // Also set the user registry on the signing node for transaction ID storage
        if let Some(signing_node) = &mut self.signing_node {
            signing_node.set_user_registry(registry.clone());
            info!("📋 [NETWORK] Set user registry on signing node for transaction ID storage");
        } else {
            info!("⚠️ [NETWORK] Signing node not available when setting user registry");
        }
    }

    pub fn set_database(&mut self, database: Arc<crate::database::Database>) {
        info!("🗄️ [NETWORK] Setting database on signing node for solver amount storage");

        // Set the database on the signing node for solver amount storage
        if let Some(signing_node) = &mut self.signing_node {
            signing_node.set_database(database);
            info!("🗄️ [NETWORK] Set database on signing node for solver amount storage");
        } else {
            info!("⚠️ [NETWORK] Signing node not available when setting database");
        }
    }

    pub fn get_dkg_node(&mut self) -> Option<&mut DKGNode> {
        self.dkg_node.as_mut()
    }

    pub fn get_signing_node(&mut self) -> Option<&mut SigningNode> {
        self.signing_node.as_mut()
    }

    pub fn get_user_registry(&mut self) -> Option<&mut DatabaseUserRegistry> {
        self.user_registry.as_mut()
    }

    pub fn get_msg_tx(&self) -> mpsc::Sender<ChannelMessage> {
        self.message_tx.clone()
    }

    pub fn get_msg_rx(&mut self) -> &mut mpsc::Receiver<ChannelMessage> {
        &mut self.message_rx
    }

    pub fn get_local_peer_id<'a>(&'a self) -> &'a PeerId {
        &self.local_peer_id
    }

    /// Load existing keypair from database or create a new one
    async fn load_or_create_keypair() -> Result<(Keypair, PeerId)> {
        use crate::database::{Database, DatabaseConfig, keys};

        // Create database connection
        let db_config = DatabaseConfig::default();
        let database = Database::new(db_config)?;

        // Try to load existing keypair
        if let Some(keypair_bytes) = database.get_keypair(keys::PEER_KEYPAIR)? {
            match Keypair::from_protobuf_encoding(&keypair_bytes) {
                Ok(keypair) => {
                    let peer_id = PeerId::from(keypair.public());
                    info!("🔄 Loaded existing keypair - Peer ID: {}", peer_id);
                    return Ok((keypair, peer_id));
                }
                Err(e) => {
                    warn!("⚠️ Failed to decode existing keypair: {}. Generating new one.", e);
                }
            }
        } else {
            info!("🆕 No existing keypair found. Generating new one.");
        }

        // Generate new keypair
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        // Save keypair to database
        let keypair_bytes = keypair.to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("Failed to encode keypair: {}", e))?;
        database.put_keypair(keys::PEER_KEYPAIR, &keypair_bytes)?;

        info!("✅ Generated and saved new keypair - Peer ID: {}", peer_id);
        Ok((keypair, peer_id))
    }

    /// Broadcast a user registration to all other nodes in the P2P network
    pub async fn broadcast_user_registration(&self, ethereum_address: &str, node_id: &str) -> Result<()> {
        let registration_msg = GossipsubMessage::UserRegistration {
            ethereum_address: ethereum_address.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            node_id: node_id.to_string(),
        };

        let msg_bytes = serde_json::to_vec(&registration_msg)
            .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

        // Send via the message channel to be broadcast by the swarm
        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "user-registrations".to_string(),
                data: msg_bytes,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send user registration broadcast: {}", e))?;

        info!("📡 Broadcasted user registration for {} from node {} to P2P network", ethereum_address, node_id);
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(self.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(5))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .flood_publish(true)
                    .fanout_ttl(Duration::from_secs(60))
                    .prune_peers(10)
                    .prune_backoff(Duration::from_secs(1))
                    .build()
                    .map_err(io::Error::other)
                    .map_err(io::Error::other)?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // Initialize Kademlia
                let store = MemoryStore::new(key.public().to_peer_id());
                let mut kademlia_config = kad::Config::default();
                kademlia_config.set_kbucket_inserts(BucketInserts::OnConnected);
                kademlia_config.set_query_timeout(Duration::from_secs(60));
                kademlia_config
                    .set_replication_factor(std::num::NonZeroUsize::new(3).expect("3 is non-zero"));

                let mut kademlia =
                    kad::Behaviour::with_config(key.public().to_peer_id(), store, kademlia_config);

                let bootstrap_nodes: Vec<&'static str> = vec![];

                for addr in bootstrap_nodes {
                    if let Ok(addr) = addr.parse::<Multiaddr>() {
                        if let Some(peer_id) = addr.iter().find_map(|proto| {
                            if let libp2p::multiaddr::Protocol::P2p(multihash) = proto {
                                PeerId::from_multihash(multihash.clone().into()).ok()
                            } else {
                                None
                            }
                        }) {
                            kademlia.add_address(&peer_id, addr);
                        }
                    }
                }

                let request_response = build_mpc_behaviour();

                Ok(MPCBehaviour {
                    gossipsub,
                    // mdns,
                    request_response,
                    kademlia,
                })
            })?
            .build();

        // Check if this is an existing node with DKG data - if so, subscribe to topics immediately
        self.subscribe_to_default_topics(&mut swarm)?;
        
        info!("Starting Kademlia bootstrap...");

        // Node manager will determine if this is the first node

        self.node_manager
            .add_node(self.local_peer_id.clone())
            .map_err(|e| anyhow::anyhow!(e))?;

        // Bootstrap with the configured nodes
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("Failed to start bootstrap: {:?}", e);
        }

        // Start a task to check if this is the first node after bootstrap attempts
        let tx_clone = self.message_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
        let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(300));
        let mut discovery_timer = tokio::time::interval(Duration::from_secs(300));
        let mut dkg_status_timer = tokio::time::interval(Duration::from_secs(300));
        let mut peerlist_logger = tokio::time::interval(Duration::from_secs(300));


        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;


        let args: Vec<String> = env::args().collect();
        if args.len() >= 2 {
            // Parse all addresses from command line arguments
            let addresses: Vec<Multiaddr> = args[1..]
                .iter()
                .filter_map(|arg| {
                    match arg.parse::<Multiaddr>() {
                        Ok(addr) => {
                            info!("Parsed address: {}", addr);
                            Some(addr)
                        }
                        Err(e) => {
                            error!("Failed to parse address '{}': {}", arg, e);
                            None
                        }
                    }
                })
                .collect();

            if addresses.is_empty() {
                warn!("No valid addresses provided to dial");
            } else {
                info!("Dialing {} addresses:", addresses.len());
                for (i, addr) in addresses.iter().enumerate() {
                    info!("  {}. {}", i + 1, addr);
                    if let Err(e) = swarm.dial(addr.clone()) {
                        error!("Failed to dial address {}: {}", addr, e);
                    } else {
                        info!("Successfully initiated dial to: {}", addr);
                    }
                }
            }
        }
        info!("Local Peer ID: {}", self.local_peer_id);

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    info!("[SWARM] some");
                    // 🛡️ Error recovery for swarm events - prevent node crashes
                    if let Err(e) = self.handle_swarm_event(event, &mut swarm).await {
                        error!("❌ [NETWORK] Swarm event handling failed: {}", e);
                        error!("🛡️ [NETWORK] Node continues operating despite swarm event failure");
                        error!("🔍 [NETWORK] Error details: {:?}", e);
                        // Continue processing other events
                    }
                }
                // only hit when there is anything on the mpsc channel
                msg = self.message_rx.recv() => {
                    if let Some(msg) = msg {
                        // 🛡️ Error recovery for channel messages - prevent node crashes
                        if let Err(e) = self.handle_channel_message(msg, &mut swarm).await {
                            error!("❌ [NETWORK] Channel message handling failed: {}", e);
                            error!("🛡️ [NETWORK] Node continues operating despite message handling failure");
                            error!("🔍 [NETWORK] Error details: {:?}", e);
                            // Continue processing other messages
                        }
                    }
                }

                _ = peerlist_logger.tick() => {
                    let peers = self.node_manager.get_active_nodes();
                    info!(
                        "🕒 PeerList snapshot ({} peers): {:?}",
                        peers.len(),
                        peers
                    );
                }
                 _ = bootstrap_timer.tick() => {
                    // Periodic bootstrap to discover new peers
                    info!("Performing periodic bootstrap...");
                    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                        warn!("Periodic bootstrap failed: {:?}", e);
                    }
                }

                _ = discovery_timer.tick() => {
                    // Periodic peer discovery
                    info!("🔄 Performing periodic peer discovery...");

                    // Debug: Show current state before discovery
                    let current_total = self.node_manager.get_total_nodes();
                    let active_nodes = self.node_manager.get_active_nodes();
                    info!("📊 Current node manager state - Total: {}, Active nodes: {:?}", current_total, active_nodes);

                    // Log gossipsub state
                    let gossipsub_peers = swarm.behaviour_mut().gossipsub.all_peers().count();
                    info!("📡 Gossipsub connected peers: {}", gossipsub_peers);

                    // Log Kademlia state
                    let kbucket_count: usize = swarm
                        .behaviour_mut()
                        .kademlia
                        .kbuckets()
                        .map(|bucket| bucket.num_entries())
                        .sum();
                    info!("🌐 Kademlia routing table entries: {}", kbucket_count);

                    swarm.behaviour_mut().kademlia.get_closest_peers(self.local_peer_id);

                    // Also search for random peers to populate routing table
                    let random_peer = PeerId::random();
                    swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                }

                _ = dkg_status_timer.tick() => {
                    // Periodic DKG status check
                    if let Some(dkg_node) = &self.dkg_node {
                        let status = dkg_node.get_status();
                        info!("📊 DKG Status Check - Current status: {:?}", status);

                        if let DKGStatus::Completed = status {
                            // DKG is completed, log final results
                            if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                                info!("🎯 DKG COMPLETED - Final secret share: {:?}", secret_share);
                            }
                            if let Some(public_key) = dkg_node.get_final_public_key().await {
                                info!("🔑 DKG COMPLETED - Final public key: {:?}", public_key);
                            }
                        } else if let DKGStatus::Started = status {
                            // DKG is in progress, check progress
                            info!("⏳ DKG in progress...");
                        }
                    }
                }
            };
        }
    }

    fn subscribe_to_default_topics(
        &mut self,
        swarm: &mut libp2p::Swarm<MPCBehaviour>,
    ) -> Result<()> {
        let topics = vec![
            MSG_TOPIC_DKG,
            MSG_TOPIC_PEER_DISCOVERY,
            "signing",
            "consensus",
            "commands",
            "vrf-selection",
            "transactions",
            "deposit-intents",
            "intent-hashes",
            "dkg-commands",
            "signatures-to-final-node",
            "user-registrations",
            "solver-rewards",
            "transaction-id-sync",
            "consensus-result",
            "transaction-error-sync",
        ];
        for topic in topics {
            let topic_hash = gossipsub::IdentTopic::new(topic);
            info!("🔔 Attempting to subscribe to topic: {}", topic);
            info!("🔔 Topic hash: {:?}", topic_hash.hash());

            let res = swarm.behaviour_mut().gossipsub.subscribe(&topic_hash);
            match res {
                Ok(_) => {
                    info!("✅ Successfully subscribed to topic: {}", topic);
                }
                Err(err) => {
                    warn!(
                        "❌ Failed to subscribe to topic: {} with error {:?}",
                        topic, err
                    );
                }
            }
            self.topics.insert(topic_hash.hash());
        }

        // Log current gossipsub state
        let peer_count = swarm.behaviour_mut().gossipsub.all_peers().count();
        info!("📊 Current gossipsub peer count: {}", peer_count);

        Ok(())
    }

    fn is_bootstrap_node(&self, peer_id: &PeerId) -> bool {
        let bootstrap_peer_ids: Vec<&'static str> = vec![
        ];

        let peer_id_str = peer_id.to_string();
        bootstrap_peer_ids
            .iter()
            .any(|&bootstrap_id| peer_id_str.contains(bootstrap_id))
    }

    fn schedule_dkg_at(&mut self, start_time_unix: u64) {
        if let Some(prev) = self.scheduled_dkg_task.take() {
            info!("⏰ Cancelling previous scheduled DKG task");
            prev.abort();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let delay = start_time_unix.saturating_sub(now);

        // clone only the sender
        let tx = self.message_tx.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(delay)).await;
            // send the one "start now" message back into your main loop
            let _ = tx.send(ChannelMessage::ScheduledDKGStart).await;
        });

        self.scheduled_dkg_task = Some(handle);
        info!("✅ Scheduled DKG to start at {}", start_time_unix);
    }

    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<NetworkEvent>,
        swarm: &mut libp2p::Swarm<MPCBehaviour>,
    ) -> Result<()> {
        info!("[SWARM EVENT] {:?}", event);
        match event {
            // if the event is of type RequestResponse
            // and depending upon the nature like:
            // if the branch is Response, the peer can send the type Request to other peers
            // else type Response will be sent to other peers
            // someone will initiate the process by sending a NetworkEvent::RequestResponse with msg type ReqRespMessage::Request
            // to other peer(s)
            // the other peer(s) will recieve the it as ReqRespMessage::Request under the event NetworkEvent::RequestResponse
            // the reciever of the init will be one or many depending on how it was send
            // if sent by calling on peer_id, the reciever will be one; if called on swarm, it'll be a broadcast

            // Handle connection establishment - this is crucial for Kademlia routing updates
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                info!("🔗 Connection established with peer: {:?}", peer_id);
                // Get the remote address and add it to Kademlia
                let remote_addr = endpoint.get_remote_address();
                info!("📍 Remote address: {:?}", remote_addr);

                // Determine whether they dialed us (we're the listener) or we dialed them
                let is_listener = matches!(endpoint, ConnectedPoint::Listener { .. });
                let is_dialer   = matches!(endpoint, ConnectedPoint::Dialer   { .. });

                // Check if we already know this peer
                let already_known = self.node_manager.get_active_nodes().contains(&peer_id);

                // Add the peer's address to Kademlia - this should trigger RoutingUpdated
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, remote_addr.clone());

                // Add peer to gossipsub as explicit peer for better message delivery
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                info!("➕ Added peer {} to gossipsub explicit peers", peer_id);

                if is_listener && !already_known {
                    info!("📡 New peer {} connected; announcing to mesh", peer_id);
                    let msg = GossipsubMessage::PeerDiscovered {
                        peer: peer_id.clone(),
                        sequence: Some(1),
                    };
                    let payload = serde_json::to_vec(&msg)
                        .expect("serialize PeerDiscovered");
                    match self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await {
                        Ok(_) => {
                            info!(
                                "✅ Successfully broadcasted peer discovery for: {:?}",
                                peer_id.clone()
                            );
                        }
                        Err(e) => {
                            warn!("❌ Failed to broadcast peer discovery: {:?}", e);
                            // Retry once after a short delay
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            if let Err(retry_e) =
                                self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await
                            {
                                warn!(
                                    "❌ Retry failed to broadcast peer discovery: {:?}",
                                    retry_e
                                );
                            }
                        }
                    }

                    // Check if peer already exists in node manager
                    let current_nodes = self.node_manager.get_active_nodes();
                    if current_nodes.contains(&peer_id) {
                        info!("ℹ️ Peer {} already exists in node manager, skipping", peer_id);
                    } else {
                        self.node_manager
                                .add_node(peer_id)
                                .map_err(|e| anyhow::anyhow!(e))?;

                        // Update signing node threshold after adding peer
                        if let Some(signing_node) = &mut self.signing_node {
                            let new_threshold = self.node_manager.get_threshold();
                            signing_node.set_threshold(new_threshold);
                            info!("🔄 [THRESHOLD] Updated signing node threshold to {} after Kademlia peer addition", new_threshold);
                        }
                    }


                    let total = self.node_manager.get_total_nodes();
                    let threshold = self.node_manager.get_threshold();

                    if total >= threshold + 1 {
                        info!(
                            "🎯 Sufficient nodes connected ({} >= {} + 1), triggering DKG!",
                            total, threshold
                        );

                        let now_secs = SystemTime::now()
                            .duration_since(UNIX_EPOCH).unwrap()
                            .as_secs();
                        let start_time = now_secs + 10;
                        info!("🕒 Scheduling DKG start at unix time {}", start_time);

                        for peer in self.node_manager.get_active_nodes() {
                            if peer != *self.get_local_peer_id() {
                                swarm.behaviour_mut()
                                    .request_response
                                    .send_request(
                                        &peer,
                                        RPCRequest::ScheduleADKG { start_time },
                                    );
                            }
                        }
                        info!("📅 Scheduled DKG start for all peers at {}", start_time);
                        self.schedule_dkg_at(start_time);
                    } else {
                        info!(
                            "⏳ Waiting for more nodes: {}/{} (need {} + 1)",
                            total,
                            threshold + 1,
                            threshold
                        );
                    }
                }

                if is_dialer {
                    info!("🚀 Sending GetPeerList RPC to {}", peer_id);
                    swarm.behaviour_mut()
                        .request_response
                        .send_request(&peer_id, RPCRequest::GetPeerList);
                }

                // Debug: Log current Kademlia routing table size
                let kbucket_count: usize = swarm
                    .behaviour_mut()
                    .kademlia
                    .kbuckets()
                    .map(|bucket| bucket.num_entries())
                    .sum();
                info!(
                    "📋 Kademlia routing table now has {} entries",
                    kbucket_count
                );

                // Log current gossipsub peer count
                let gossipsub_peer_count = swarm.behaviour_mut().gossipsub.all_peers().count();
                info!(
                    "📊 Gossipsub peer count after adding {}: {}",
                    peer_id, gossipsub_peer_count
                );

                // Try to discover more peers through this connection
                swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
            }

            SwarmEvent::Behaviour(NetworkEvent::RequestResponse(ReqRespEvent::Message {
                peer,
                message,
                ..
            })) => {
                // peer.r
                info!("RPC request: peer: {} response: {:?}", peer, message);
                match message {
                    // this peer will recieve a request from other peer(s) (incl testing agent(s))
                    ReqRespMessage::Request {
                        request, channel, ..
                    } => {
                        let response = match request {
                            RPCRequest::GetPeerList => {
                                // Log that we received the full‐list request
                                info!("🔄 GetPeerList RPC received from {}", peer);

                                // Gather everyone we know
                                let peers: Vec<SerializablePeerId> = self
                                    .node_manager
                                    .get_active_nodes()
                                    .into_iter()
                                    .map(SerializablePeerId)
                                    .collect();

                                // Log how many peers we're returning (and list them if you like)
                                info!(
                                    "📋 Sending PeerList response to {}: {} entries: {:?}",
                                    peer,
                                    peers.len(),
                                    peers
                                );

                                RPCResponse::PeerList { peers }
                            }
                            RPCRequest::Ping => RPCResponse::Pong,
                            RPCRequest::GetPeerInfo => {
                                // Provide your implementation to get peer info
                                RPCResponse::PeerInfo(PeerInfo {
                                    addresses: vec![],
                                    connected: true,
                                })
                            }
                            RPCRequest::Custom { id, data } => {
                                // Handle custom request
                                RPCResponse::Custom { id, data }
                            },
                            RPCRequest::StartADKG// {n, threshold }
                            => {
                                // handle dkg start
                                match self.dkg_node.as_mut() {
                                    Some(dkg) => {
                                        info!("🚀 Received DKG start request from peer {}", peer);

                                        // Update DKG parameters with current network state
                                        let total = self.node_manager.get_total_nodes();
                                        let threshold = self.node_manager.get_threshold();
                                        dkg.update_node_params(total, threshold);
                                        dkg.reset().await;
                                        if let Some(signing_node) = &mut self.signing_node {
                                            signing_node.set_threshold(self.node_manager.get_total_nodes() - 1);
                                        }
                                        self.node_manager
                                            .set_threshold(total - 1);
                                        info!("🔄 DKG parameters updated: total_nodes={}, threshold={}", total, threshold);

                                        match dkg.start_dkg(self.node_manager.clone()).await {
                                            Ok(_) => {
                                                info!("✅ Successfully started DKG in response to peer request");
                                                RPCResponse::DKGStarted {peer_id: SerializablePeerId(peer)}
                                            }
                                            Err(e) => {
                                                warn!("❌ Failed to start DKG: {:?}", e);
                                                RPCResponse::DKGError(format!("Failed to start DKG: {:?}", e))
                                            }
                                        }
                                    }
                                    None => {
                                        warn!("❌ DKG node not initialized");
                                        RPCResponse::DKGError("DKG is not initialized.".to_string())
                                    }
                                }
                            },
                            // This peer node will recieve a request from some external agent that will
                            // connect with this peer to request it to initiate dkg
                            RPCRequest::GetDKGStatus => { // peer.r.dkg.ptp
                                let status = self
                                    .dkg_node
                                    .as_ref()
                                    .map(|dkg| dkg.get_status())
                                    .unwrap_or(DKGStatus::New);

                                RPCResponse::DKGStatus { status } // send back to the agent at peer.send.ptp
                            },
                            RPCRequest::SendAVSSShare { share, commitments, receiver_id, .. } => {
                                if self.dkg_node.is_none() {
                                    RPCResponse::Error("DKG not initialized".to_string())
                                } else {
                                    // Extract share index from receiver_id
                                    let share_index = if let Ok(index) = receiver_id.0.to_string().parse::<usize>() {
                                        index
                                    } else {
                                        // Fallback to hash-based index
                                        use std::collections::hash_map::DefaultHasher;
                                        use std::hash::{Hash, Hasher};
                                        let mut hasher = DefaultHasher::new();
                                        receiver_id.0.to_string().hash(&mut hasher);
                                        let hash = hasher.finish();
                                        ((hash % 100) + 1) as usize // Use a reasonable default range
                                    };

                                    if self.dkg_node.as_ref().unwrap().verify_share(&share, share_index, &commitments) {
                                        RPCResponse::ShareAccepted
                                    } else {
                                        RPCResponse::Error("Invalid share".into())
                                    }
                                }
                            },
                            RPCRequest::ScheduleADKG { start_time } => {
                                info!("🕒 Got DKGStartAt({})", start_time);
                                self.schedule_dkg_at(start_time);
                                RPCResponse::Ack
                            }
                            RPCRequest::RequestCurrentVrfRound => {
                                info!("🔄 Received request for current VRF round from peer {}", peer);
                                let mut current_round = None;

                                // Check signing_node first
                                if let Some(signing_node) = &self.signing_node {
                                    if let Some(vrf_service) = &signing_node.vrf_service {
                                        current_round = Some(vrf_service.get_current_round().await);
                                    }
                                }

                                // If no round from signing_node, check db_signing_node
                                if current_round.is_none() {
                                    if let Some(db_signing_node) = &self.db_signing_node {
                                        let node = db_signing_node.lock().await;
                                        if let Some(vrf_service) = &node.vrf_service {
                                            current_round = Some(vrf_service.get_current_round().await);
                                        }
                                    }
                                }

                                RPCResponse::CurrentVrfRoundResponse {
                                    current_round,
                                }
                            }
                            _ => RPCResponse::Ack
                        };
                        // here the following line will send to the other connected peers (incl any testing agent(s))
                        let res = swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, response); // peer.send.ptp
                        if res.is_err() {
                            warn!("❌ Failed to send response to peer {}: {:?}", peer, res.err());
                        } else {
                            info!("📤 Sent RPC response to {}: {:?}", peer, res);
                        }
                    }
                    // here peer(s) will recieve the msg sent by other peer by peer.send.ptp
                    ReqRespMessage::Response {
                        request_id: _,
                        response,
                    } => {
                        info!("📥 Got RPC response {:?} from {}", response, peer);
                        // peer.r
                        match response {
                            RPCResponse::PeerList { peers } => {
                                info!("🔄 Merging peer‐set from {}: {:?}", peer, peers);
                                for SerializablePeerId(p) in peers {
                                    if !self.node_manager.get_active_nodes().contains(&p) {
                                        self.node_manager.add_node(p.clone())
                                            .map_err(|e| anyhow::anyhow!(e))?;

                                        // Update signing node threshold after adding peer
                                        if let Some(signing_node) = &mut self.signing_node {
                                            let new_threshold = self.node_manager.get_threshold();
                                            signing_node.set_threshold(new_threshold);
                                            info!("🔄 [THRESHOLD] Updated signing node threshold to {} after peer list merge", new_threshold);
                                        }
                                    }
                                }
                            },

                            RPCResponse::GotAVSSShare {
                                dealer_id: _,
                                receiver_id: _,
                                share: _group_key,
                                commitments: _,
                            } => {
                            }

                            RPCResponse::DKGStarted { peer_id } => {
                                info!("DKG has started by: {:?}", peer_id);
                            }

                            RPCResponse::Error(err) => {
                                warn!("Received error from peer {}: {}", peer, err);
                            }

                            RPCResponse::ShareAccepted => {
                            }


                            RPCResponse::CurrentVrfRoundResponse { current_round } => {
                                if let Some(network_round) = current_round {
                                    info!("🔄 Received current VRF round response: {} from peer {}", network_round, peer);

                                    // Simple VRF round sync for both signing nodes
                                    if let Some(signing_node) = &mut self.signing_node {
                                        signing_node.sync_vrf_round_with_network(network_round).await;
                                    }
                                    if let Some(db_signing_node) = &mut self.db_signing_node {
                                        let mut node = db_signing_node.lock().await;
                                        node.sync_vrf_round_with_network(network_round).await;
                                    }

                                    info!("✅ [NETWORK] VRF round synced to network round: {}", network_round);
                                    // VRF sync successful, don't need to request again
                                } else {
                                    info!("ℹ️ Peer {} doesn't have current VRF round yet", peer);
                                }
                            }

                            other => {
                                info!("ℹ️  RPCResponse::{:?} from {} (no action)", other, peer);
                            }
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(NetworkEvent::RequestResponse(
                ReqRespEvent::OutboundFailure { peer, error, .. },
            )) => {
                info!("Outbound failure to peer {}: {:?}", peer, error);
            }
            SwarmEvent::Behaviour(NetworkEvent::RequestResponse(
                ReqRespEvent::InboundFailure { peer, error, .. },
            )) => {
                info!("Inbound failure to peer {}: {:?}", peer, error);
            }
            SwarmEvent::Behaviour(NetworkEvent::RequestResponse(ReqRespEvent::ResponseSent {
                peer,
                ..
            })) => {
                info!("Response sent to peer {}", peer);
            }

            SwarmEvent::Behaviour(NetworkEvent::Kademlia(event)) => {
                match event {
                    KademliaEvent::RoutingUpdated {
                        peer,
                        is_new_peer,
                        addresses,
                        bucket_range,
                        old_peer,
                    } => {
                        info!("-----------routing updated----------: Peer{:?}, is_new_peer{:?}, addresses{:?}, bucket_range{:?}, old_peer{:?}\n", peer, is_new_peer, addresses, bucket_range, old_peer);
                        // let before = self.node_manager.get_total_nodes();
                        // info!("[RoutingUpdated] New peer added : {:?}", peer);
                        if is_new_peer {
                            // Check if this is a bootstrap node
                            if self.is_bootstrap_node(&peer) {
                                info!("⚠️  This is a bootstrap node, skipping: {:?}", peer);
                                return Ok(());
                            }

                            info!("\x1b[32m✅ This is a real MPC node: {:?}\x1b[0m", peer);

                            let total = self.node_manager.get_total_nodes();
                            let threshold = self.node_manager.get_threshold();

                            // Debug: Show all active nodes
                            let active_nodes = self.node_manager.get_active_nodes();
                            info!(
                                "\x1b[36m🔗 Active nodes in manager: {:?}\x1b[0m",
                                active_nodes
                            );
                            info!(
                                "\x1b[33m📊 node length: {:?}\x1b[0m",
                                self.node_manager.get_total_nodes()
                            );

                            info!(
                                "\x1b[35m🎯 Updated node count: {}, threshold: {}\x1b[0m",
                                total, threshold
                            );
                        }
                    }
                    KademliaEvent::InboundRequest { request } => {
                        info!("-----------InboundRequest----------: {:?}", request);
                    }
                    KademliaEvent::OutboundQueryProgressed {
                        id,
                        result,
                        stats,
                        step,
                    } => {
                        info!(
                            "-----------OutboundQueryProgressed----------: {:?}, {:?}, {:?}, {:?}",
                            id, result, stats, step
                        );
                    }
                    KademliaEvent::UnroutablePeer { peer } => {
                        info!("-----------UnroutablePeer----------: {:?}", peer);
                    }
                    KademliaEvent::RoutablePeer { peer, address } => {
                        info!(
                            "-----------RoutablePeer----------: {:?}, {:?}",
                            peer, address
                        );
                    }
                    KademliaEvent::PendingRoutablePeer { peer, address } => {
                        info!(
                            "-----------PendingRoutablePeer----------: {:?}, {:?}",
                            peer, address
                        );
                    }
                    KademliaEvent::ModeChanged { new_mode } => {
                        info!("-----------ModeChanged----------: {:?}", new_mode);
                    }
                }
            }

            // if the msg sent by a peer has event type of Gossipsub, this branch will be hit on the
            // reciever(s)
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Message {
                // dkg.r.2.0
                message_id,
                propagation_source,
                message,
            })) => {
                info!(
                    "📨 Received gossipsub message - Topic: {}, From: {}, Message ID: {:?}",
                    message.topic, propagation_source, message_id
                );

                // Log message size and topic hash
                info!("📦 Message size: {} bytes", message.data.len());
                info!("🏷️ Topic hash: {:?}", message.topic);

                self.handle_gossipsub_message(&message).await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                info!("📡 Peer {} subscribed to topic: {}", peer_id, topic);

                // If this is the peer discovery topic, we can now safely broadcast our presence
                if topic.as_str() == MSG_TOPIC_PEER_DISCOVERY {
                    info!(
                        "🎯 Peer discovery topic subscription confirmed by: {}",
                        peer_id
                    );

                    // Small delay to ensure subscription is fully processed
                    // tokio::time::sleep(Duration::from_millis(50)).await;

                    // Broadcast our presence to this newly subscribed peer
                    let msg = GossipsubMessage::PeerDiscovered {
                        peer: self.local_peer_id.clone(),
                        sequence: Some(1), // Add sequence number
                    };
                    if let Ok(payload) = serde_json::to_vec(&msg) {
                        if let Err(e) = self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await {
                            warn!(
                                "Failed to broadcast presence to newly subscribed peer: {:?}",
                                e
                            );
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            })) => {
                warn!("📡 Peer {} unsubscribed from topic: {}", peer_id, topic);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                let full = address
                    .clone()
                    .with(Protocol::P2p(self.local_peer_id.clone().into()));
                info!("📡 multiaddress   : {}", full);

                info!(
                    "Listening for RPC connections on {}{}",
                    address,
                    MPCProtocol.as_ref()
                );
            }
            SwarmEvent::ConnectionClosed {
                peer_id: _,
                connection_id: _,
                endpoint: _,
                num_established: _,
                cause,
            } => {
                if let Some(ca) = cause {
                    match ca {
                        ConnectionError::IO(e) => {
                            info!(
                                "[ERROR] Kind: {} RAW: {:?} ref: {:?} Full: {}",
                                e.kind(),
                                e.raw_os_error(),
                                e.get_ref().as_slice(),
                                e
                            );
                        }
                        _ => {}
                    }
                }
            }

            _ => {
                info!("[EVENT] other");
            }
        }
        Ok(())
    }

    async fn handle_gossipsub_message(&mut self, message: &Message) -> Result<()> {
        info!(
            "i am at handle_gossipsub_message ---------- {:?}",
            message.topic
        );

        // Better error handling for message deserialization
        let msg = match serde_json::from_slice::<GossipsubMessage>(&message.data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to deserialize gossipsub message: {:?}", e);
                warn!("Message data: {:?}", String::from_utf8_lossy(&message.data));
                return Ok(()); // Continue processing other messages
            }
        };

        info!("[GMSG] {:?}", msg);
        match msg {
            // this must be used by broadcast in dkg (sending end)
            // so, here it must match on the recieving end
            GossipsubMessage::DKG(dkg_msg) => {
                // dkg.r.2.1
                // here we unwrapped the outer gossipmsg wrap from
                // the msg bytes (check broadcast_shares() in dkg module)
                if let Some(dkg_node) = &mut self.dkg_node {
                    // now we can unwrap the internal dkg wrap to get the DKG related things
                    dkg_node.handle_message(dkg_msg,self.node_manager.clone()).await?;
                }
            }
            GossipsubMessage::Signing(signing_msg) => {
                info!("📥 [NETWORK] Received signing message on topic: {}", message.topic);
                info!("📋 [NETWORK] Signing message type: {:?}", signing_msg);

                if let Some(signing_node) = &mut self.signing_node {
                    // 🛡️ Error recovery for signing message processing - prevent node crashes
                    let signing_result = if message.topic.to_string() == "signatures-to-final-node" {
                        info!("🎯 [NETWORK] Processing signature for final node topic");
                        match signing_msg {
                            crate::signing::SigningMessage::ECDSASignature { from, signature, round, timestamp:_timestamp, user_eth_address } => {
                                info!("📤 [NETWORK] Routing ECDSA signature to final node handler from: {} for round: {} (user_eth_address: {:?})", from, round, user_eth_address);
                                signing_node.handle_signature_to_final_node(from, signature, round).await
                            }
                            crate::signing::SigningMessage::BtcSignaturesMessage { from, signatures, round, timestamp: _timestamp, user_eth_address } => {
                                info!("📤 [NETWORK] Routing BTC signatures to final node handler from: {} for round: {} (user_eth_address: {:?})", from, round, user_eth_address);
                                // You may want to implement a similar handler for BTC signatures in signing_node
                                // For now, just call the generic handler
                                signing_node.handle_btc_signatures_to_final_node(from, signatures, round).await
                            }
                            _ => {
                                info!("📤 [NETWORK] Routing other signing message to normal handler");
                                // Handle other signing messages normally
                                signing_node.handle_message(signing_msg).await
                            }
                        }
                    } else {
                        info!("📤 [NETWORK] Processing normal signing message on topic: {}", message.topic);
                        // Handle normal signing messages
                        match &signing_msg {
                            crate::signing::SigningMessage::ECDSASignature { from, signature, round, timestamp:_timestamp, user_eth_address } => {
                                let tx_type = if user_eth_address.is_some() { "user-to-network" } else { "network-to-target" };
                                info!("📥 [NETWORK] Received {} ECDSA signature from {} for round {} on topic {} (user_eth_address: {:?})", tx_type, from, round, message.topic, user_eth_address);
                                info!("🔍 [NETWORK] Signature details - signer_id: {}",
                                      signature.signer_id);
                            }
                            _ => {
                                info!("📥 [NETWORK] Received other signing message type");
                            }
                        }
                        signing_node.handle_message(signing_msg).await
                    };

                    // Handle signing errors gracefully
                    if let Err(e) = signing_result {
                        error!("❌ [NETWORK] Signing message processing failed: {}", e);
                        error!("🛡️ [NETWORK] Node continues operating despite signing failure");
                        error!("🔍 [NETWORK] Error details: {:?}", e);
                        // Don't propagate the error - continue processing other messages
                    }
                } else {
                    warn!("❌ [NETWORK] Signing node not available to handle signing message");
                }
            }
            GossipsubMessage::Command(cmd) => {
                if let Some(cmd_processor) = &mut self.command_processor {
                    cmd_processor.handle_message(cmd).await?;
                }
            }
            GossipsubMessage::Consensus(consensus_msg) => {
                info!("📥 [CONSENSUS] Received consensus message: {:?}", consensus_msg);

                // Handle consensus message in signing node
                if let Some(signing_node) = &mut self.signing_node {
                    signing_node.handle_consensus_message(consensus_msg.clone()).await?;
                }

                // Also handle in standalone consensus node if available
                if let Some(consensus_node) = &mut self.consensus_node {
                    consensus_node.handle_message(consensus_msg).await?;
                }
            }
            GossipsubMessage::VrfSelection(vrf_msg) => {
                // Handle VRF selection messages
                if let Some(_vrf_manager) =
                    self.node_manager
                        .as_any()
                        .downcast_ref::<crate::node_management::VrfNodeManager>()
                {
                    // We need to handle this differently since we can't mutate through a trait object
                    // For now, we'll log the message
                    info!("Received VRF selection message: {:?}", vrf_msg);
                } else {
                    info!(
                        "Received VRF selection message but node manager is not VRF-based: {:?}",
                        vrf_msg
                    );
                }
            }
            GossipsubMessage::VrfSelectedNodes(broadcast_msg) => {
                info!("📥 [VRF] Received VRF selected nodes broadcast: {:?}", broadcast_msg);

                // Store the received VRF selection in the signing node's VRF selector
                if let Some(signing_node) = &mut self.signing_node {
                    let selector_node_id = broadcast_msg.selector_node_id.clone();
                    let round = broadcast_msg.round;
                    signing_node.handle_vrf_selected_nodes_broadcast(self.node_manager.get_total_nodes(), broadcast_msg);
                    info!(
                        "💾 [VRF] Stored VRF selected nodes from node {} for round {}",
                        selector_node_id.0, round
                    );
                }
            }
            GossipsubMessage::Transaction(transaction) => {
                info!("📝 Received transaction via gossipsub: {:?}", transaction);
                // Here you can add transaction processing logic
                // For example, validate the transaction, add to mempool, etc.
                if let Some(signing_node) = &mut self.signing_node {
                    // Set available nodes from node manager before signing
                    let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);

                    // Generate BLS key pair if not already done
                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                            info!("🔐 [NETWORK] Got secret share from DKG");
                            signing_node.set_private_key_from_scalar(secret_share);

                            // ✅ Also set the DKG group public key
                            if let Some(group_key) = dkg_node.get_final_public_key().await {
                                signing_node.set_group_public_key(group_key);
                                info!("🔑 [NETWORK] Set DKG group public key for signing node");
                            }
                        } else {
                            info!("⏳ [NETWORK] DKG not completed yet, no secret share available");
                            return Ok(());
                        }
                    } else {
                        info!("❌ [NETWORK] DKG node not available");
                        return Ok(());
                    }
                    info!("transaction: {:?}", transaction);
                    info!("transaction.nonce: {:?}", transaction.nonce);
                    // Convert transaction to bytes for signing using RLP encoding
                    let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&transaction);
                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                    signing_node.sign_message(tx_bytes, &transaction, None, None, None, None).await?;
                }
            }
            GossipsubMessage::DKGCommand(dkg_cmd) => {
                info!("🚀 Received DKG command via gossipsub: {:?}", dkg_cmd);
                match dkg_cmd {
                    RPCRequest::StartADKG => {
                        if let Some(dkg_node) = &mut self.dkg_node {
                            info!("🚀 Starting DKG in response to gossipsub command");
                            if let Err(e) = dkg_node.start_dkg(self.node_manager.clone()).await {
                                warn!("❌ Failed to start DKG from gossipsub command: {:?}", e);
                            }
                        } else {
                            warn!("❌ DKG node not initialized for gossipsub command");
                        }
                    }
                    _ => {
                        info!("📋 Received other DKG command: {:?}", dkg_cmd);
                    }
                }
            }
            GossipsubMessage::UserRegistration { ethereum_address, timestamp, node_id } => {
                info!("👤 Received user registration via gossipsub: {} from node {} at {}", ethereum_address, node_id, timestamp);

                // Process user registration locally (same pattern as deposit intent)
                if let Some(user_registry) = &mut self.user_registry {
                    // Get DKG secret share if available
                    let dkg_secret_share = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_secret_share().await
                    } else {
                        None
                    };

                    // Register the user locally
                    match user_registry.register_user(&ethereum_address, dkg_secret_share.as_ref(), &node_id).await {
                        Ok(registration) => {
                            info!("✅ [GOSSIPSUB] Successfully registered user {} locally", ethereum_address);

                            // Log tweaked secret share status
                            if registration.tweaked_secret_share.is_some() {
                                info!("🔑 [GOSSIPSUB] Computed and stored tweaked secret share for user: {}", ethereum_address);
                            } else {
                                info!("⚠️ [GOSSIPSUB] No tweaked secret share computed (DKG secret share not available) for user: {}", ethereum_address);
                            }

                            // Deterministically compute HMAC tweak and update commitments locally (primary path)
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(tweak_scalar) = k256::Scalar::from_repr_vartime(registration.hmac_constant.into()) {
                                        match dkg_node.derive_user_specific_group_key_from_commitments(tweak_scalar).await {
                                            Ok(group_key) => {
                                                if let Err(e) = user_registry.set_user_group_key(&ethereum_address, group_key).await {
                                                    warn!("❌ [GOSSIPSUB] Failed to store user group key for {}: {}", ethereum_address, e);
                                                } else {
                                                    info!("🔑 [GOSSIPSUB] Stored user-specific group key and derived addresses for {}", ethereum_address);
                                                    // Log the derived addresses
                                                    if let Some(user) = user_registry.get_user_by_address(&ethereum_address).await {
                                if user.derived_eth_address.is_some() {
                                    info!("📬 [GOSSIPSUB] Derived ETH address stored for {}", ethereum_address);
                                }
                                if user.derived_btc_address.is_some() {
                                    info!("📬 [GOSSIPSUB] Derived BTC address stored for {}", ethereum_address);
                                }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!("❌ [GOSSIPSUB] Failed to derive user-specific group key for {}: {}", ethereum_address, e);
                                            }
                                        }
                                    }
                                } else {
                                    warn!("❌ [GOSSIPSUB] Invalid HMAC tweak scalar for {}", ethereum_address);
                                }
                        }
                        Err(e) => {
                            warn!("❌ [GOSSIPSUB] Failed to register user {} locally: {}", ethereum_address, e);
                        }
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] User registry not available to handle user registration");
                }
            }
            GossipsubMessage::TransactionIdBroadcast { intent_hash, transaction_id, transaction_type, node_id } => {
                info!("📡 [NETWORK] Received transaction ID broadcast from node {}", node_id);
                info!("🔗 [NETWORK] Intent hash: {}", intent_hash);
                info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);

                // Store the transaction ID in our local user registry
                if let Some(user_registry) = &self.user_registry {
                    let storage_result = match transaction_type.as_str() {
                        "user_to_vault" => {
                            // Also update solver amounts for user_to_vault using signing node, if available
                            if let Some(signing_node) = &self.signing_node {
                                if let Err(e) = signing_node.update_solver_amounts_for_user_to_vault(&intent_hash).await {
                                    warn!("⚠️ [SIGNING] Failed to update solver amounts for UserToVault transaction: {}", e);
                                } else {
                                    // Calculate rewards after successfully updating solver amounts
                                    if let Err(e) = signing_node.calculate_reward_per_solver(&intent_hash).await {
                                        warn!("⚠️ [SIGNING] Failed to calculate rewards for UserToVault transaction: {}", e);
                                    } else {
                                        info!("✅ [SIGNING] Successfully calculated rewards for UserToVault transaction: {}", intent_hash);
                                    }
                                }
                            }
                            user_registry
                                .store_user_to_vault_tx_id(
                                    &intent_hash,
                                    &transaction_id,
                                    Some(&node_id),
                                )
                                .await
                        },
                        "network_to_target" => {
                            user_registry
                                .store_network_to_target_tx_id(
                                    &intent_hash,
                                    &transaction_id,
                                    Some(&node_id),
                                ).await
                        },
                        "vault_to_network" => {
                            user_registry
                                .store_vault_to_network_tx_id(
                                    &intent_hash,
                                    &transaction_id,
                                    Some(&node_id),
                                )
                                .await
                        },
                        _ => {
                            warn!("❌ [NETWORK] Unknown transaction type: {}", transaction_type);
                            return Ok(());
                        }
                    };

                    match storage_result {
                        Ok(()) => {
                            if let Err(e) = user_registry
                                .store_transaction_status(&transaction_id, TransactionStatus::Pending)
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to store transaction status for broadcast tx {}: {}",
                                    transaction_id, e
                                );
                            }
                            info!(
                                "✅ [NETWORK] Successfully synchronized transaction ID {} for intent {} (type: {})",
                                transaction_id, intent_hash, transaction_type
                            );

                            // Execute contract call when transaction ID is received
                            if let Some(user_registry) = &self.user_registry {
                                if let Some(intent) = user_registry.get_intent(&intent_hash).await {
                                    // Convert transaction type string to enum
                                    let tx_type_enum = match transaction_type.as_str() {
                                        "user_to_vault" => crate::types::TransactionType::UserToVault,
                                        "network_to_target" => crate::types::TransactionType::NetworkToTarget,
                                        "vault_to_network" => crate::types::TransactionType::VaultToNetwork,
                                        _ => {
                                            warn!("❌ [CONTRACT] Unknown transaction type for contract call: {}", transaction_type);
                                            return Ok(());
                                        }
                                    };

                                    // Get vault group key
                                    let vault_group_key = if let Some(dkg_node) = &self.dkg_node {
                                        dkg_node.get_vault_group_key().await
                                    } else {
                                        None
                                    };

                                    if let Some(vault_group_key) = vault_group_key {
                                        // Use transaction_id as tx_hash for contract call
                                        // let tx_hash_bytes = transaction_id.clone();
                                        // Execute contract call
                                        if let Err(e) = self.execute_contract_call_for_transaction(
                                            &intent,
                                            &intent_hash,
                                            tx_type_enum,
                                            &transaction_id,
                                            Some(vault_group_key),
                                            intent.amount,
                                        ).await {
                                            warn!("❌ [CONTRACT] Failed to execute contract call for transaction ID {}: {}", transaction_id, e);
                                        } else {
                                            info!("✅ [CONTRACT] Successfully executed contract call for transaction ID {}", transaction_id);
                                        }
                                    } else {
                                        warn!("❌ [CONTRACT] No vault group key available for contract call execution");
                                    }
                                } else {
                                    warn!("❌ [CONTRACT] Could not retrieve intent {} for contract call execution", intent_hash);
                                }
                            }
                        },
                        Err(e) => {
                            error!("❌ [NETWORK] Failed to store synchronized transaction ID: {}", e);
                        }
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction ID");
                }
            }
            GossipsubMessage::TransactionErrorBroadcast { intent_hash, error_message, transaction_type, node_id } => {
                info!("📡 [NETWORK] Received transaction error broadcast from node {}", node_id);
                info!("🔗 [NETWORK] Intent hash: {}", intent_hash);
                info!("💥 [NETWORK] Error message: {}", error_message);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);

                // Store the error message in our local user registry
                if let Some(user_registry) = &self.user_registry {
                    match user_registry
                        .store_transaction_error(
                            &intent_hash,
                            &error_message,
                            Some(&node_id),
                        )
                        .await
                    {
                        Ok(()) => {
                            info!("✅ [NETWORK] Successfully synchronized transaction error for intent {}: {}", intent_hash, error_message);
                        },
                        Err(e) => {
                            error!("❌ [NETWORK] Failed to store synchronized transaction error: {}", e);
                        }
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction error");
                }
            }
            GossipsubMessage::IntentHashBroadcast { intent_hash, node_id } => {
                info!(
                    "📨 [GOSSIPSUB] Received intent hash broadcast {} from node {}",
                    intent_hash, node_id
                );
            }
            GossipsubMessage::SolverReward { solver_address, reward } => {
                info!("💰 [REWARD] Received solver reward for {}: {}", solver_address, reward);
                // Create dummy transaction paying the solver
                // Fetch chain_id on the basis of tics (assuming tics is the chain name or identifier)
                let chain_to_use = "qubetics"; // Replace this with the actual tics variable if available
                let chain_id = crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                    .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", chain_to_use))?;

                // You may need to determine from_address based on your logic, e.g. from DKG node/group key
                let from_address = if let Some(dkg_node) = &self.dkg_node {
                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                        crate::utils::get_eth_address_from_group_key(group_key)
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                // Use fetch_ethereum_nonce from transaction utils
                let nonce = crate::utils::transaction::fetch_ethereum_nonce(&from_address, chain_id).await?;

                let ethereum_tx = EthereumTransaction {
                    to: solver_address.clone(),
                    value: format!("0x{:x}", reward),
                    gas_limit: 300000,
                    gas_price: get_default_gas_price_for_chain(chain_to_use),
                    nonce,
                    data: None,
                    chain_id,
                };

                if let Some(dkg_node) = &self.dkg_node {
                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                        let from_addr = crate::utils::get_eth_address_from_group_key(group_key);
                        info!(
                            "🧾 [NETWORK] Created solver reward tx from {} to {} amount {}",
                            from_addr, solver_address, reward
                        );
                    }
                }

                // Create DummyTransaction from EthereumTransaction
                let dummy_tx = crate::rpc_server::DummyTransaction {
                    to: ethereum_tx.to.clone(),
                    value: ethereum_tx.value.clone(),
                    nonce: ethereum_tx.nonce,
                    gas_limit: ethereum_tx.gas_limit,
                    gas_price: ethereum_tx.gas_price.clone(),
                    chain_id: ethereum_tx.chain_id,
                };
                let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&dummy_tx);

                // Sign the solver reward transaction
                if let Some(signing_node) = &mut self.signing_node {
                    // Set available nodes from node manager before signing
                    let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);

                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                            info!("🔐 [REWARD] Got secret share from DKG: {:?}", secret_share);
                            signing_node.set_private_key_from_scalar(secret_share);
                            info!("🔐 [REWARD] Starting solver reward signing process: 0x{}", hex::encode(tx_bytes.clone()));
                            signing_node.sign_message(tx_bytes, &dummy_tx, Some(secret_share), None, None, None).await?;
                            info!("✅ [REWARD] Solver reward signing completed");
                        } else {
                            info!("⏳ [REWARD] DKG not completed yet, no secret share available");
                            return Ok(());
                        }
                    } else {
                        info!("❌ [REWARD] DKG node not available");
                        return Ok(());
                    }

                } else {
                    warn!("❌ [REWARD] Signing node not available for solver reward");
                }
            }
            GossipsubMessage::IntentHash { intent_hash, signer, intent } => {
                info!("📝 [GOSSIPSUB] Received intent hash {} from {}", intent_hash, signer);

                if let Some(user_registry) = &self.user_registry {
                    match hex::decode(&intent_hash) {
                        Ok(bytes) => {
                            if let Err(e) = user_registry.store_intent_hash(bytes, &signer, &intent).await {
                                warn!("❌ [GOSSIPSUB] Failed to store intent hash: {}", e);
                            } else {
                                info!("✅ [GOSSIPSUB] Stored intent hash from {}", signer);
                            }
                        }
                        Err(e) => {
                            warn!("❌ [GOSSIPSUB] Invalid intent hash {}: {}", intent_hash, e);
                        }
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] No user registry available to store intent hash");
                }
            }
            GossipsubMessage::DepositIntent { intent, intent_id, user_eth_address, transaction_type, amount } => {
                info!("📝 [GOSSIPSUB] Processing deposit intent received via gossipsub: {:?} (ID: {})", intent, intent_id);

                // Calculate intent hash for transaction ID storage
                let intent_hash = crate::utils::calculate_intent_hash(&intent);
                info!("🔐 [GOSSIPSUB] Calculated intent hash: {}", intent_hash);

                // Determine chain type based on transaction type:
                // - UserToVault: use source_chain (user is depositing FROM this chain)
                // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
                // - VaultToNetwork: use source_chain (vault is sending back to network on source chain)
                let chain_to_use = match transaction_type {
                    crate::types::TransactionType::UserToVault => &intent.source_chain.to_lowercase(),
                    crate::types::TransactionType::NetworkToTarget => &intent.target_chain.to_lowercase(),
                    crate::types::TransactionType::VaultToNetwork => &intent.source_chain.to_lowercase(),
                };
                info!("🔗 [GOSSIPSUB] Processing deposit intent for chain: {} (transaction_type: {:?})",
                      chain_to_use, transaction_type);

                // Get the appropriate signing key based on transaction type
                let signing_key: Option<k256::Scalar> = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        // For user deposits, use user's tweaked secret share
                        self.get_signing_key_for_user(user_eth_address.as_ref()).await
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        // For network withdrawals, use network's DKG secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        // For vault-to-network, use vault's tweaked secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_vault_tweaked_secret_share().await
                        } else {
                            None
                        }
                    }
                };

                if let Some(signing_node) = &mut self.signing_node {
                    // Set appropriate chain handler based on the determined chain
                    if crate::utils::transaction::is_evm_chain(chain_to_use) {
                        if let Some(chain_id) = crate::utils::transaction::get_chain_id_from_name(chain_to_use) {
                            let chain_handler = crate::chain::ChainHandlerFactory::create_ethereum_handler(chain_id);
                            signing_node.set_chain_handler(chain_handler.into());
                            info!("🔗 [GOSSIPSUB] Set Ethereum chain handler for chain: {} (ID: {})", chain_to_use, chain_id);
                        }
                    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                        let mut chain_handler = crate::chain::ChainHandlerFactory::create_bitcoin_handler("testnet".to_string());

                        // Set appropriate group public key in Bitcoin chain handler based on transaction type
                        match transaction_type {
                            crate::types::TransactionType::UserToVault => {
                                // For user deposits, use user's specific group key
                                if let Some(eth_addr) = &user_eth_address {
                                    if let Some(user_registry) = &self.user_registry {
                                        if let Some(user) = user_registry.get_user_by_address(eth_addr).await {
                                            if let Some(user_group_key) = &user.user_group_key {
                                                let affine_point = user_group_key.0; // user_group_key is SerializablePoint(AffinePoint)
                                                let encoded_point = k256::EncodedPoint::from(affine_point);
                                                let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                                if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain::BitcoinChainHandler>() {
                                                    btc_handler.set_group_public_key(compressed_bytes);
                                                    info!("🔑 [GOSSIPSUB] Set user-specific group public key in Bitcoin chain handler for user: {}", eth_addr);
                                                }
                                            } else {
                                                warn!("❌ [GOSSIPSUB] User {} has no group key for Bitcoin transaction", eth_addr);
                                            }
                                        } else {
                                            warn!("❌ [GOSSIPSUB] User {} not found for Bitcoin transaction", eth_addr);
                                        }
                                    } else {
                                        warn!("❌ [GOSSIPSUB] User registry not available for Bitcoin transaction");
                                    }
                                } else {
                                    warn!("❌ [GOSSIPSUB] UserToVault transaction requires user_eth_address");
                                }
                            }
                            crate::types::TransactionType::NetworkToTarget => {
                                // For network withdrawals, use network's DKG group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                                        let affine_point = group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain::BitcoinChainHandler>() {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [GOSSIPSUB] Set network DKG group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                            crate::types::TransactionType::VaultToNetwork => {
                                // For vault-to-network, use vault's group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(vault_group_key) = dkg_node.get_vault_group_key().await {
                                        let affine_point = vault_group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain::BitcoinChainHandler>() {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [GOSSIPSUB] Set vault group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                        }

                        signing_node.set_chain_handler(chain_handler.into());
                        info!("🔗 [GOSSIPSUB] Set Bitcoin chain handler");
                    } else {
                        warn!("❌ [GOSSIPSUB] Unsupported chain: {}, using default Ethereum handler", chain_to_use);
                    }

                    // Get derived addresses based on transaction type
                    let (derived_eth_addr, derived_btc_addr) = match transaction_type {
                        crate::types::TransactionType::UserToVault => {
                            // For user deposits, use user's derived addresses
                            if let Some(eth_addr) = &user_eth_address {
                                if let Some(user_registry) = &self.user_registry {
                                    if let Some(user) = user_registry.get_user_by_address(eth_addr).await {
                                        (user.derived_eth_address.clone(), user.derived_btc_address.clone())
                                    } else {
                                        warn!("❌ [GOSSIPSUB] User {} not found in registry", eth_addr);
                                        (None, None)
                                    }
                                } else {
                                    warn!("❌ [GOSSIPSUB] User registry not available");
                                    (None, None)
                                }
                            } else {
                                warn!("❌ [GOSSIPSUB] UserToVault transaction requires user_eth_address");
                                (None, None)
                            }
                        }
                        crate::types::TransactionType::NetworkToTarget | crate::types::TransactionType::VaultToNetwork => {
                            // For network withdrawals and vault-to-network, no derived addresses needed
                            (None, None)
                        }
                    };

                    let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_public_key().await
                    } else {
                        None
                    };

                    // Get vault group key for vault operations
                    let vault_group_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_vault_group_key().await
                    } else {
                        None
                    };

                    // Get vault addresses from database
                    let (vault_eth_addr, vault_btc_addr) = if let Some(registry) = &self.user_registry {
                        let database = registry.get_database();
                        let vault_eth = database.get_string(&crate::database::keys::DKG_VAULT_ETH_ADDRESS).ok().flatten();
                        let vault_btc = database.get_string(&crate::database::keys::DKG_VAULT_BTC_ADDRESS).ok().flatten();
                        (vault_eth, vault_btc)
                    } else {
                        return Err(anyhow::anyhow!("User registry not available"));
                    };

                    let chain_transaction_result = crate::utils::transaction::create_chain_transaction_from_deposit_intent(&intent, group_public_key, derived_eth_addr.as_ref(), derived_btc_addr.as_ref(), transaction_type.clone(), vault_eth_addr.as_ref(), vault_btc_addr.as_ref(), amount).await;

                    match chain_transaction_result {
                        Ok(chain_transaction) => {
                            info!("📝 [GOSSIPSUB] Created {} transaction from deposit intent", signing_node.get_chain_type());

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if let Some(key) = signing_key {
                                info!("🔐 [GOSSIPSUB] Got signing key for deposit intent");
                                signing_node.set_private_key_from_scalar(key);

                                // Set the appropriate group public key based on transaction type
                                match transaction_type {
                                    crate::types::TransactionType::UserToVault => {
                                        // For user deposits, use user-specific group key
                                        if let Some(eth_address) = &user_eth_address {
                                            if let Some(user_registry) = &self.user_registry {
                                                if let Some(user) = user_registry.get_user_by_address(eth_address).await {
                                                    if let Some(user_group_key) = &user.user_group_key {
                                                        signing_node.set_group_public_key(user_group_key.0.into()); // Convert AffinePoint to ProjectivePoint
                                                        info!("🔑 [GOSSIPSUB] Set user-specific group public key for: {}", eth_address);
                                                    } else {
                                                        warn!("❌ [GOSSIPSUB] User {} has no group key available", eth_address);
                                                        return Ok(());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::NetworkToTarget => {
                                        // For network withdrawals, use the original DKG group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(group_key) = dkg_node.get_final_public_key().await {
                                                signing_node.set_group_public_key(group_key);
                                                info!("🔑 [GOSSIPSUB] Set network DKG group public key");
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::VaultToNetwork => {
                                        // For vault-to-network, use the vault group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(vault_group_key) = dkg_node.get_vault_group_key().await {
                                                signing_node.set_vault_group_key(vault_group_key);
                                                info!("🔑 [GOSSIPSUB] Set vault group public key");
                                            }
                                        }
                                    }
                                }
                            } else {
                                info!("❌ [GOSSIPSUB] Could not get signing key for deposit intent");
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = signing_node.get_chain_handler().create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!("🔐 [GOSSIPSUB] Starting {} signing process for deposit intent: 0x{}",
                                  signing_node.get_chain_type(), hex::encode(tx_bytes.clone()));

                            // Handle Bitcoin and EVM differently - DummyTransaction is only for EVM!
                            match chain_transaction {
                                crate::chain::ChainTransaction::Bitcoin(ref btc_tx) => {
                                    // For Bitcoin, use direct signing with tx_bytes and original transaction
                                    signing_node.sign_bitcoin_transaction(tx_bytes.clone(), Some(btc_tx.clone()), user_eth_address.clone(), Some(intent_hash.clone()), Some(transaction_type.clone()), signing_key).await?;
                                }
                                crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                                    // For EVM chains, use your proven DummyTransaction logic
                                    let dummy_tx = crate::rpc_server::DummyTransaction {
                                        to: eth_tx.to.clone(),
                                        value: eth_tx.value.clone(),
                                        nonce: eth_tx.nonce,
                                        gas_limit: eth_tx.gas_limit,
                                        gas_price: eth_tx.gas_price.clone(),
                                        chain_id: eth_tx.chain_id,
                                    };

                                    let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&dummy_tx);
                                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                                    let user_tweaked_share = match transaction_type {
                                        crate::types::TransactionType::UserToVault => {
                                            // For user deposits, use user's tweaked secret share
                                            if let Some(eth_addr) = &user_eth_address {
                                                if let Some(user_registry) = &self.user_registry {
                                                    if let Some(user) = user_registry.get_user_by_address(eth_addr).await {
                                                        user.tweaked_secret_share.map(|s| s.0)
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::NetworkToTarget => {
                                            // For network withdrawals, use network's DKG secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_final_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::VaultToNetwork => {
                                            // For vault-to-network, use vault's tweaked secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_vault_tweaked_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                    };

                                    signing_node.sign_message(tx_bytes.clone(), &dummy_tx, user_tweaked_share, user_eth_address.clone(), Some(intent_hash.clone()), Some(transaction_type.clone())).await?;

                                    // // Only execute contract transaction for UserToVault transaction type
                                    // if matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                                    //     info!("📝 [GOSSIPSUB] UserToVault transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);


                                    //             match contract_transaction {
                                    //                 crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::rpc_server::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // } else if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget){
                                    //     info!("📝 [GOSSIPSUB] networkToTarget transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);


                                    //             match contract_transaction {
                                    //                 crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::rpc_server::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // }
                                }
                            }
                            info!("✅ [GOSSIPSUB] {} deposit intent signing completed", signing_node.get_chain_type());
                        }
                        Err(e) => {
                            warn!("❌ [GOSSIPSUB] Failed to create chain transaction: {}", e);
                            return Ok(());
                        }
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] Signing node not available for deposit intent processing");
                }
            }

            GossipsubMessage::PeerDiscovered { peer, sequence } => {
                info!(
                    "🎯 Peer discovered via gossipsub: {:?} (seq: {:?})",
                    peer, sequence
                );

                // Check if we already have this peer to avoid duplicates
                let current_nodes = self.node_manager.get_active_nodes();
                if current_nodes.contains(&peer) {
                    info!("ℹ️ Peer {} already exists in node manager, skipping", peer);
                    return Ok(());
                }

                match self.node_manager.add_node(peer) {
                    Ok(_) => {
                        info!("✅ Successfully added peer {} to node manager", peer);

                        // Log updated node count
                        let total = self.node_manager.get_total_nodes();
                        let threshold = self.node_manager.get_threshold();
                        info!("📊 Updated node count: {}, threshold: {}", total, threshold);
                        // Update signing node threshold to match current network state
                        if let Some(signing_node) = &mut self.signing_node {
                            let new_threshold = self.node_manager.get_threshold();
                            signing_node.set_threshold(new_threshold);
                            info!("🔄 [THRESHOLD] Updated signing node threshold to {} (total nodes: {})", new_threshold, total);
                        }
                    }
                    Err(e) => {
                        warn!("❌ Failed to add peer {} to node manager: {:?}", peer, e);
                    }
                }
            }
        }
        Ok(())
    }

    // ChannelMessage is related to the MPSC channel only
    async fn handle_channel_message(
        &mut self,
        message: ChannelMessage,
        swarm: &mut libp2p::Swarm<MPCBehaviour>,
    ) -> Result<()> {
        info!("[handle_channel_message()] {:?}", message);
        match message {
            // this is used in the dkg code
            ChannelMessage::Broadcast { topic, data } => {
                // dkg.s.1
                info!("📢 [BROADCAST] Attempting to broadcast to topic: {}", topic);
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());
                info!("🏷️ [BROADCAST] Topic hash: {:?}", topic_hash.hash());

                // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                // if peer(s) have already subscribed to this topic, they will recieve this
                // msg (check subscribe_to_default_topics())
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();
                info!(
                    "📊 [BROADCAST] Available peers for topic {}: {}",
                    topic, peer_count
                );

                if peer_count > 0 {
                    info!("👥 [BROADCAST] Connected peers:");
                    for (peer_id, _peer_info) in swarm_mut.gossipsub.all_peers() {
                        info!("   - Peer: {:?}", peer_id);
                    }

                    match swarm_mut.gossipsub.publish(topic_hash, data) {
                        Ok(_) => {
                            info!(
                                "✅ [BROADCAST] Successfully published message to topic: {}",
                                topic
                            );
                        }
                        Err(e) => {
                            warn!(
                                "❌ [BROADCAST] Failed to publish message to topic {}: {:?}",
                                topic, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [BROADCAST] No peers available for broadcasting to topic: {}",
                        topic
                    );
                }
            }
            // Handle local transaction processing (for the node that receives the HTTP request)
            ChannelMessage::LocalTransaction { transaction } => {
                info!("🔐 [LOCAL] Processing transaction locally: {:?}", transaction);

                if let Some(signing_node) = &mut self.signing_node {
                    // Set available nodes from node manager before signing
                    let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);

                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                            info!("🔐 [NETWORK] Got secret share from DKG: {:?}", secret_share);
                            signing_node.set_private_key_from_scalar(secret_share);

                            // ✅ Also set the DKG group public key
                            if let Some(group_key) = dkg_node.get_final_public_key().await {
                                signing_node.set_group_public_key(group_key);
                                info!("🔑 [NETWORK] Set DKG group public key for local transaction");
                            }
                        } else {
                            info!("⏳ [NETWORK] DKG not completed yet, no secret share available");
                            return Ok(());
                        }
                    } else {
                        info!("❌ [NETWORK] DKG node not available");
                        return Ok(());
                    }

                    // Convert transaction to bytes for signing using RLP encoding
                    let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&transaction);
                    info!("🔐 [LOCAL] Starting local signing process {:?}", hex::encode(tx_bytes.clone()));
                    signing_node.sign_message(tx_bytes, &transaction, None, None, None, None).await?;
                    info!("✅ [LOCAL] Local transaction signing completed");
                } else {
                    warn!("❌ [LOCAL] Signing node not available for local processing");
                }
            }
            // this is not used anywhere yet
            ChannelMessage::Unicast { peer_id, data } => {
                // Implement direct message sending using request-response protocol
                let peer_id = PeerId::from_bytes(&hex::decode(peer_id)?)
                    .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
                let request = RPCRequest::Custom {
                    id: "custom".to_string(),
                    data,
                };
                // this will send the channel msg as
                // NetworkEvent::RequestResponse under ReqRespMessage::Request type
                // to just single peer
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);
            }
            ChannelMessage::IntentHash { intent_hash, signer, intent } => {
                info!("📝 [NETWORK] Storing intent hash from signer {}", signer);

                if let Some(user_registry) = &self.user_registry {
                    if let Err(e) = user_registry.store_intent_hash(intent_hash.clone(), &signer, &intent).await {
                        warn!("❌ [NETWORK] Failed to store intent hash: {}", e);
                    } else {
                        info!("✅ [NETWORK] Intent hash stored locally");
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store intent hash");
                }

                let intent_hash_hex = hex::encode(&intent_hash);
                let gossip_msg = GossipsubMessage::IntentHash {
                    intent_hash: intent_hash_hex.clone(),
                    signer: signer.clone(),
                    intent: intent.clone(),
                };
                let msg_bytes = serde_json::to_vec(&gossip_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize intent hash message: {}", e))?;
                let topic = gossipsub::IdentTopic::new("intent-hashes");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted intent hash {}", intent_hash_hex);
            }
            ChannelMessage::DepositIntent { intent, intent_id, user_eth_address, transaction_type, amount } => {
                info!("📝 [NETWORK] Processing deposit intent locally: {:?}", intent);

                // Only broadcast to other nodes via gossipsub when using network share (no user_eth_address)
                info!("🌐 [NETWORK] Using network share - broadcasting to P2P network");
                let deposit_intent_msg = GossipsubMessage::DepositIntent {
                    intent: intent.clone(),
                    intent_id: intent_id.clone(),
                    user_eth_address: user_eth_address.clone(),
                    transaction_type: transaction_type.clone(),
                    amount: amount.clone(),
                };
                let msg_bytes = serde_json::to_vec(&deposit_intent_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize deposit intent: {}", e))?;


                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("deposit-intents");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted deposit intent to P2P network");

                // Calculate intent hash for transaction ID storage
                let intent_hash = crate::utils::calculate_intent_hash(&intent);
                info!("🔐 [LOCAL] Calculated intent hash: {}", intent_hash);

                // Prepare unsigned transaction for on-chain deposit intent recording
                // self.prepare_deposit_intent_tx(&intent, &intent_hash).await;

                // Determine chain type based on transaction type:
                // - UserToVault: use source_chain (user is depositing FROM this chain)
                // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
                // - VaultToNetwork: use source_chain (vault is sending back to network on source chain)
                let chain_to_use = match transaction_type {
                    crate::types::TransactionType::UserToVault => &intent.source_chain.to_lowercase(),
                    crate::types::TransactionType::NetworkToTarget => &intent.target_chain.to_lowercase(),
                    crate::types::TransactionType::VaultToNetwork => &intent.source_chain.to_lowercase(),
                };
                info!("🔗 [LOCAL] Processing deposit intent for chain: {} (transaction_type: {:?})",
                      chain_to_use, transaction_type);

                // Get the appropriate signing key based on transaction type
                let signing_key: Option<k256::Scalar> = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        // For user deposits, use user's tweaked secret share
                        self.get_signing_key_for_user(user_eth_address.as_ref()).await
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        // For network withdrawals, use network's DKG secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        // For vault-to-network, use vault's tweaked secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_vault_tweaked_secret_share().await
                        } else {
                            None
                        }
                    }
                };

                // Process locally first (this node will sign it)
                if let Some(signing_node) = &mut self.signing_node {
                    // Set appropriate chain handler based on the determined chain
                    if crate::utils::transaction::is_evm_chain(chain_to_use) {
                        if let Some(chain_id) = crate::utils::transaction::get_chain_id_from_name(chain_to_use) {
                            let chain_handler = crate::chain::ChainHandlerFactory::create_ethereum_handler(chain_id);
                            signing_node.set_chain_handler(chain_handler.into());
                            info!("🔗 [LOCAL] Set Ethereum chain handler for chain: {} (ID: {})", chain_to_use, chain_id);
                        }
                    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                        let mut chain_handler = crate::chain::ChainHandlerFactory::create_bitcoin_handler("testnet".to_string());

                        // Set appropriate group public key in Bitcoin chain handler based on transaction type
                        match transaction_type {
                            crate::types::TransactionType::UserToVault => {
                                // For user deposits, use user's specific group key
                                if let Some(eth_addr) = &user_eth_address {
                                    if let Some(user_registry) = &self.user_registry {
                                        if let Some(user) = user_registry.get_user_by_address(eth_addr).await {
                                            if let Some(user_group_key) = &user.user_group_key {
                                                let affine_point = user_group_key.0; // user_group_key is SerializablePoint(AffinePoint)
                                                let encoded_point = k256::EncodedPoint::from(affine_point);
                                                let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                                if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain::BitcoinChainHandler>() {
                                                    btc_handler.set_group_public_key(compressed_bytes);
                                                    info!("🔑 [LOCAL] Set user-specific group public key in Bitcoin chain handler for user: {}", eth_addr);
                                                }
                                            } else {
                                                warn!("❌ [LOCAL] User {} has no group key for Bitcoin transaction", eth_addr);
                                            }
                                        } else {
                                            warn!("❌ [LOCAL] User {} not found for Bitcoin transaction", eth_addr);
                                        }
                                    } else {
                                        warn!("❌ [LOCAL] User registry not available for Bitcoin transaction");
                                    }
                                } else {
                                    warn!("❌ [LOCAL] UserToVault transaction requires user_eth_address");
                                }
                            }
                            crate::types::TransactionType::NetworkToTarget => {
                                // For network withdrawals, use network's DKG group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                                        let affine_point = group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain::BitcoinChainHandler>() {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [LOCAL] Set network DKG group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                            crate::types::TransactionType::VaultToNetwork => {
                                // For vault-to-network, use vault's group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(vault_group_key) = dkg_node.get_vault_group_key().await {
                                        let affine_point = vault_group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain::BitcoinChainHandler>() {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [LOCAL] Set vault group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                        }

                        signing_node.set_chain_handler(chain_handler.into());
                        info!("🔗 [LOCAL] Set Bitcoin chain handler");
                    } else {
                        warn!("❌ [LOCAL] Unsupported chain: {}, using default Ethereum handler", chain_to_use);
                    }

                    // Get derived addresses based on transaction type
                    let (derived_eth_addr, derived_btc_addr) = match transaction_type {
                        crate::types::TransactionType::UserToVault => {
                            // For user deposits, use user's derived addresses
                            if let Some(eth_addr) = &user_eth_address {
                                if let Some(user_registry) = &self.user_registry {
                                    if let Some(user) = user_registry.get_user_by_address(eth_addr).await {
                                        (user.derived_eth_address.clone(), user.derived_btc_address.clone())
                                    } else {
                                        warn!("❌ [LOCAL] User {} not found in registry", eth_addr);
                                        (None, None)
                                    }
                                } else {
                                    warn!("❌ [LOCAL] User registry not available");
                                    (None, None)
                                }
                            } else {
                                warn!("❌ [LOCAL] UserToVault transaction requires user_eth_address");
                                (None, None)
                            }
                        }
                        crate::types::TransactionType::NetworkToTarget | crate::types::TransactionType::VaultToNetwork => {
                            // For network withdrawals and vault-to-network, no derived addresses needed
                            (None, None)
                        }
                    };

                    let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_public_key().await
                    } else {
                        None
                    };

                    let vault_group_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_vault_group_key().await
                    } else {
                        None
                    };

                    // Get vault addresses from database
                    let (vault_eth_addr, vault_btc_addr) = if let Some(registry) = &self.user_registry {
                        let database = registry.get_database();
                        let vault_eth = database.get_string(&crate::database::keys::DKG_VAULT_ETH_ADDRESS).ok().flatten();
                        let vault_btc = database.get_string(&crate::database::keys::DKG_VAULT_BTC_ADDRESS).ok().flatten();
                        (vault_eth, vault_btc)
                    } else {
                        return Err(anyhow::anyhow!("User registry not available"));
                    };

                    let chain_transaction_result = crate::utils::transaction::create_chain_transaction_from_deposit_intent(&intent, group_public_key, derived_eth_addr.as_ref(), derived_btc_addr.as_ref(), transaction_type.clone(), vault_eth_addr.as_ref(), vault_btc_addr.as_ref(), amount).await;

                    match chain_transaction_result {
                        Ok(chain_transaction) => {
                            info!("📝 [LOCAL] Created {} transaction from deposit intent", signing_node.get_chain_type());

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if let Some(key) = signing_key {
                                info!("🔐 [LOCAL] Got signing key for deposit intent");
                                signing_node.set_private_key_from_scalar(key);

                                // Set the appropriate group public key based on transaction type
                                match transaction_type {
                                    crate::types::TransactionType::UserToVault => {
                                        // For user deposits, use user-specific group key
                                        if let Some(eth_address) = &user_eth_address {
                                            if let Some(user_registry) = &self.user_registry {
                                                if let Some(user) = user_registry.get_user_by_address(eth_address).await {
                                                    if let Some(user_group_key) = &user.user_group_key {
                                                        signing_node.set_group_public_key(user_group_key.0.into()); // Convert AffinePoint to ProjectivePoint
                                                        info!("🔑 [LOCAL] Set user-specific group public key for: {}", eth_address);
                                                    } else {
                                                        warn!("❌ [LOCAL] User {} has no group key available", eth_address);
                                                        return Ok(());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::NetworkToTarget => {
                                        // For network withdrawals, use the original DKG group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(group_key) = dkg_node.get_final_public_key().await {
                                                signing_node.set_group_public_key(group_key);
                                                info!("🔑 [LOCAL] Set network DKG group public key");
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::VaultToNetwork => {
                                        // For vault-to-network, use the vault group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(vault_group_key) = dkg_node.get_vault_group_key().await {
                                                signing_node.set_vault_group_key(vault_group_key);
                                                info!("🔑 [LOCAL] Set vault group public key");
                                            }
                                        }
                                    }
                                }
                            } else {
                                info!("❌ [LOCAL] Could not get signing key for deposit intent");
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = signing_node.get_chain_handler().create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!("🔐 [LOCAL] Starting {} signing process for deposit intent: 0x{}",
                                  signing_node.get_chain_type(), hex::encode(tx_bytes.clone()));

                            // Handle Bitcoin and EVM differently - DummyTransaction is only for EVM!
                            match chain_transaction {
                                crate::chain::ChainTransaction::Bitcoin(ref btc_tx) => {
                                    // For Bitcoin, use direct signing with tx_bytes and original transaction
                                    signing_node.sign_bitcoin_transaction( tx_bytes.clone(), Some(btc_tx.clone()), user_eth_address.clone(), Some(intent_hash.clone()), Some(transaction_type.clone()), signing_key ).await?;
                                }
                                crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                                    // For EVM chains, use your proven DummyTransaction logic
                                    let dummy_tx = crate::rpc_server::DummyTransaction {
                                        to: eth_tx.to.clone(),
                                        value: eth_tx.value.clone(),
                                        nonce: eth_tx.nonce,
                                        gas_limit: eth_tx.gas_limit,
                                        gas_price: eth_tx.gas_price.clone(),
                                        chain_id: eth_tx.chain_id,
                                    };
                                    let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&dummy_tx);
                                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                                    // Get signing key based on transaction type
                                    let user_tweaked_share = match transaction_type {
                                        crate::types::TransactionType::UserToVault => {
                                            // For user deposits, use user's tweaked secret share
                                            if let Some(eth_addr) = &user_eth_address {
                                                if let Some(user_registry) = &self.user_registry {
                                                    if let Some(user) = user_registry.get_user_by_address(eth_addr).await {
                                                        user.tweaked_secret_share.map(|s| s.0)
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::NetworkToTarget => {
                                            // For network withdrawals, use network's DKG secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_final_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::VaultToNetwork => {
                                            // For vault-to-network, use vault's tweaked secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_vault_tweaked_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                    };

                                    signing_node.sign_message(tx_bytes.clone(), &dummy_tx, user_tweaked_share, user_eth_address.clone(), Some(intent_hash.clone()), Some(transaction_type.clone())).await?;

                                    // // Only execute contract transaction for UserToVault transaction type
                                    // if matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                                    //     info!("📝 [LOCAL] UserToVault transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [LOCAL] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);


                                    //             match contract_transaction {
                                    //                 crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::rpc_server::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [LOCAL] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [LOCAL] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // } else if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget){
                                    //     info!("📝 [GOSSIPSUB] networkToTarget transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);


                                    //             match contract_transaction {
                                    //                 crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::rpc_server::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }

                                    // }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("❌ [LOCAL] Failed to create chain transaction from deposit intent: {}", e);
                        }
                    }
                } else {
                    warn!("❌ [LOCAL] Signing node not available for deposit intent");
                }
            }

            ChannelMessage::TransactionIdBroadcast { intent_hash, transaction_id, transaction_type, node_id } => {
                info!("📡 [NETWORK] Received transaction ID broadcast from node {}", node_id);
                info!("🔗 [NETWORK] Intent hash: {}", intent_hash);
                info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);

                // Store the transaction ID in our local user registry
                if let Some(user_registry) = &self.user_registry {
                    let storage_result = match transaction_type.as_str() {
                        "user_to_vault" => {
                            // Also update solver amounts for user_to_vault using signing node, if available
                            if let Some(signing_node) = &self.signing_node {
                                if let Err(e) = signing_node.update_solver_amounts_for_user_to_vault(&intent_hash).await {
                                    warn!("⚠️ [SIGNING] Failed to update solver amounts for UserToVault transaction: {}", e);
                                } else {
                                    // Calculate rewards after successfully updating solver amounts
                                    if let Err(e) = signing_node.calculate_reward_per_solver(&intent_hash).await {
                                        warn!("⚠️ [SIGNING] Failed to calculate rewards for UserToVault transaction: {}", e);
                                    } else {
                                        info!("✅ [SIGNING] Successfully calculated rewards for UserToVault transaction: {}", intent_hash);
                                    }
                                }
                            }
                            user_registry.store_user_to_vault_tx_id(&intent_hash, &transaction_id, Some(&node_id)).await
                        },
                        "network_to_target" => {
                            user_registry.store_network_to_target_tx_id(&intent_hash, &transaction_id, Some(&node_id)).await
                        },
                        "vault_to_network" => {
                            user_registry.store_vault_to_network_tx_id(&intent_hash, &transaction_id, Some(&node_id)).await
                        },
                        _ => {
                            warn!("❌ [NETWORK] Unknown transaction type: {}", transaction_type);
                            return Ok(());
                        }
                    };

                    match storage_result {
                        Ok(()) => {
                            if let Err(e) = user_registry
                                .store_transaction_status(&transaction_id, TransactionStatus::Pending)
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to store transaction status for broadcast tx {}: {}",
                                    transaction_id, e
                                );
                            }
                            info!(
                                "✅ [NETWORK] Successfully synchronized transaction ID {} for intent {} (type: {})",
                                transaction_id, intent_hash, transaction_type
                            );

                            // Execute contract call when transaction ID is received
                            if let Some(user_registry) = &self.user_registry {
                                if let Some(intent) = user_registry.get_intent(&intent_hash).await {
                                    // Convert transaction type string to enum
                                    let tx_type_enum = match transaction_type.as_str() {
                                        "user_to_vault" => crate::types::TransactionType::UserToVault,
                                        "network_to_target" => crate::types::TransactionType::NetworkToTarget,
                                        "vault_to_network" => crate::types::TransactionType::VaultToNetwork,
                                        _ => {
                                            warn!("❌ [CONTRACT] Unknown transaction type for contract call: {}", transaction_type);
                                            return Ok(());
                                        }
                                    };

                                    // Get vault group key
                                    let vault_group_key = if let Some(dkg_node) = &self.dkg_node {
                                        dkg_node.get_vault_group_key().await
                                    } else {
                                        None
                                    };

                                    if let Some(vault_group_key) = vault_group_key {

                                        // Execute contract call
                                        if let Err(e) = self.execute_contract_call_for_transaction(
                                            &intent,
                                            &intent_hash,
                                            tx_type_enum,
                                            &transaction_id,
                                            Some(vault_group_key),
                                            intent.amount,
                                        ).await {
                                            warn!("❌ [CONTRACT] Failed to execute contract call for transaction ID {}: {}", transaction_id, e);
                                        } else {
                                            info!("✅ [CONTRACT] Successfully executed contract call for transaction ID {}", transaction_id);
                                        }
                                    } else {
                                        warn!("❌ [CONTRACT] No vault group key available for contract call execution");
                                    }
                                } else {
                                    warn!("❌ [CONTRACT] Could not retrieve intent {} for contract call execution", intent_hash);
                                }
                            }
                        },
                        Err(e) => {
                            error!("❌ [NETWORK] Failed to store synchronized transaction ID: {}", e);
                        }
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction ID");
                }
            }

            ChannelMessage::SolverReward { solver_address, reward } => {
                info!("💰 [NETWORK] Broadcasting solver reward: {} -> {}", solver_address, reward);
                let reward_msg = GossipsubMessage::SolverReward {
                    solver_address: solver_address.clone(),
                    reward,
                };
                let msg_bytes = serde_json::to_vec(&reward_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize solver reward: {}", e))?;

                let topic = gossipsub::IdentTopic::new("solver-rewards");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted solver reward to P2P network");
                // Fetch chain_id on the basis of tics (assuming tics is the chain name or identifier)
                let chain_to_use = "qubetics"; // Replace this with the actual tics variable if available
                let chain_id = crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                    .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", chain_to_use))?;

                // You may need to determine from_address based on your logic, e.g. from DKG node/group key
                let from_address = if let Some(dkg_node) = &self.dkg_node {
                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                        crate::utils::get_eth_address_from_group_key(group_key)
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                // Use fetch_ethereum_nonce from transaction utils
                let nonce = crate::utils::transaction::fetch_ethereum_nonce(&from_address, chain_id).await?;

                let ethereum_tx = EthereumTransaction {
                    to: solver_address.clone(),
                    value: format!("0x{:x}", reward),
                    gas_limit: 300000,
                    gas_price: get_default_gas_price_for_chain(chain_to_use),
                    nonce,
                    data: None,
                    chain_id,
                };

                if let Some(dkg_node) = &self.dkg_node {
                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                        let from_addr = crate::utils::get_eth_address_from_group_key(group_key);
                        info!(
                            "🧾 [NETWORK] Created solver reward tx from {} to {} amount {}",
                            from_addr, solver_address, reward
                        );
                    }
                }

                // Create DummyTransaction from EthereumTransaction
                let dummy_tx = crate::rpc_server::DummyTransaction {
                    to: ethereum_tx.to.clone(),
                    value: ethereum_tx.value.clone(),
                    nonce: ethereum_tx.nonce,
                    gas_limit: ethereum_tx.gas_limit,
                    gas_price: ethereum_tx.gas_price.clone(),
                    chain_id: ethereum_tx.chain_id,
                };
                let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&dummy_tx);

                // Sign the solver reward transaction
                if let Some(signing_node) = &mut self.signing_node {
                    // Set available nodes from node manager before signing
                    let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);

                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                            info!("🔐 [REWARD] Got secret share from DKG: {:?}", secret_share);
                            signing_node.set_private_key_from_scalar(secret_share);
                            info!("🔐 [REWARD] Starting solver reward signing process: 0x{}", hex::encode(tx_bytes.clone()));
                            signing_node.sign_message(tx_bytes, &dummy_tx, Some(secret_share), None, None, None).await?;
                            info!("✅ [REWARD] Solver reward signing completed");
                        } else {
                            info!("⏳ [REWARD] DKG not completed yet, no secret share available");
                            return Ok(());
                        }
                    } else {
                        info!("❌ [REWARD] DKG node not available");
                        return Ok(());
                    }

                } else {
                    warn!("❌ [REWARD] Signing node not available for solver reward");
                }
            }
            ChannelMessage::IntentHashBroadcast { intent_hash, node_id } => {
                info!(
                    "📡 [NETWORK] Broadcasting intent hash {} from node {}",
                    intent_hash, node_id
                );
                let broadcast_msg = GossipsubMessage::IntentHashBroadcast {
                    intent_hash: intent_hash.clone(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&broadcast_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize intent hash broadcast: {}", e))?;
                let topic = gossipsub::IdentTopic::new("intent-hashes");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted intent hash to P2P network");
            }
            ChannelMessage::UserRegistration { ethereum_address, node_id } => {
                info!("👤 [NETWORK] Broadcasting user registration: {} from node {}", ethereum_address, node_id);

                // Directly update commitments locally using the stored HMAC constant
                if let (Some(user_registry), Some(dkg_node)) = (&self.user_registry, &self.dkg_node) {
                    if let Some(reg) = user_registry.get_user_by_address(&ethereum_address).await {
                        if let Some(tweak_scalar) = k256::Scalar::from_repr_vartime(reg.hmac_constant.into()) {                                // Derive and store user-specific group key from updated commitments
                                match dkg_node.derive_user_specific_group_key_from_commitments(tweak_scalar).await {
                                    Ok(group_key) => {
                                        if let Err(e) = user_registry.set_user_group_key(&ethereum_address, group_key).await {
                                            warn!("❌ [NETWORK] Failed to store user group key for {}: {}", ethereum_address, e);
                                        } else {
                                            info!("🔑 [NETWORK] Stored user-specific group key and derived addresses for {}", ethereum_address);
                                            // Log the derived addresses
                                            if let Some(user) = user_registry.get_user_by_address(&ethereum_address).await {
                                                if let Some(eth_addr) = &user.derived_eth_address {
                                                    info!("📬 [NETWORK] Derived ETH address for {}: {}", ethereum_address, eth_addr);
                                                }
                                                if let Some(btc_addr) = &user.derived_btc_address {
                                                    info!("📬 [NETWORK] Derived BTC address for {}: {}", ethereum_address, btc_addr);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("❌ [NETWORK] Failed to derive user-specific group key for {}: {}", ethereum_address, e);
                                    }
                                }
                            }
                        } else {
                            warn!("❌ [NETWORK] Invalid HMAC tweak scalar for {}", ethereum_address);
                        }
                } else {
                    warn!("❌ [NETWORK] Missing user_registry or dkg_node; cannot update commitments locally for {}", ethereum_address);
                }

                // Create and broadcast user registration message via gossipsub (same pattern as deposit intent)
                let user_reg_msg = GossipsubMessage::UserRegistration {
                    ethereum_address: ethereum_address.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&user_reg_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("user-registrations");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted user registration to P2P network");
            }
            ChannelMessage::ScheduledDKGStart => {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();
                if let Some(dkg) = &mut self.dkg_node {
                    dkg.update_node_params(total, threshold);
                    dkg.reset().await;
                    if let Some(signing_node) = &mut self.signing_node {
                        signing_node.set_threshold(total/2 + 1);
                    }
                    self.node_manager
                        .set_threshold(total/2 + 1);
                    info!("🔄 DKG parameters updated: total_nodes={}, threshold={}", total, threshold);
                    if let Err(e) = dkg.start_dkg(self.node_manager.clone()).await {
                        warn!("❌ Scheduled DKG start failed: {:?}", e);
                    }
                } else {
                    warn!("❌ DKG node not initialized at scheduled start!");
                }
            }
        }
        Ok(())
    }

    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;
        Ok(())
    }

    pub async fn send_direct_message(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::Unicast {
                peer_id: peer_id.to_string(),
                data: data.to_vec(),
            })
            .await?;
        Ok(())
    }

    /// Get the appropriate signing key based on the user eth address
    async fn get_signing_key_for_user(&self, user_eth_address: Option<&String>) -> Option<k256::Scalar> {
        if let Some(eth_address) = user_eth_address {
            // Use user-specific tweaked share
            info!("🔑 [NETWORK] Using user-specific tweaked share for signing - User: {}", eth_address);

            if let Some(user_registry) = &self.user_registry {
                match user_registry.get_user_by_address(eth_address).await {
                    Some(user) => {
                        if let Some(tweaked_share) = &user.tweaked_secret_share {
                            info!("✅ [NETWORK] Found user's tweaked share for: {}", eth_address);
                            Some(tweaked_share.0) // Convert SerializableScalar to Scalar
                        } else {
                            warn!("❌ [NETWORK] User {} has no tweaked share available", eth_address);
                            None
                        }
                    }
                    None => {
                        warn!("❌ [NETWORK] User {} not found in registry", eth_address);
                        None
                    }
                }
            } else {
                warn!("❌ [NETWORK] User registry not available");
                None
            }
        } else {
            // Use network's original DKG share
            info!("🔑 [NETWORK] Using network's original DKG share for signing");

            if let Some(dkg_node) = &self.dkg_node {
                if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                    info!("✅ [NETWORK] Found network's DKG share");
                    Some(secret_share)
                } else {
                    warn!("❌ [NETWORK] DKG not completed yet, no secret share available");
                    None
                }
            } else {
                warn!("❌ [NETWORK] DKG node not available");
                None
            }
        }
    }

    /// Execute contract call for a given transaction type and intent
    async fn execute_contract_call_for_transaction(
        &mut self,
        intent: &crate::rpc_server::DepositIntent,
        intent_hash: &str,
        transaction_type: crate::types::TransactionType,
        tx_hash: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
        amount: u128,
    ) -> Result<()> {
        if let Some(signing_node) = &mut self.signing_node {
            info!("📝 [CONTRACT] Executing contract call for transaction type: {:?}", transaction_type);

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(
                vault_group_key,
                amount,
                intent,
                intent_hash,
                tx_hash,
                transaction_type.clone()
            ).await;

            match contract_call_result {
                Ok(contract_transaction) => {
                    info!("📝 [CONTRACT] Created contract call transaction");
                    let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);

                    match contract_transaction {
                        crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                            let contract_tx = crate::rpc_server::ContractTransaction {
                                to: eth_tx.to.clone(),
                                value: eth_tx.value.clone(),
                                nonce: eth_tx.nonce,
                                gas_limit: eth_tx.gas_limit,
                                gas_price: eth_tx.gas_price.clone(),
                                chain_id: eth_tx.chain_id,
                                data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                            };
                            let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                            debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                            let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                dkg_node.get_vault_tweaked_secret_share().await
                            } else {
                                None
                            };
                            signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                        }
                        _ => {
                            info!("📝 [CONTRACT] Contract call transaction is not Ethereum type, skipping");
                        }
                    }
                }
                Err(e) => {
                    warn!("❌ [CONTRACT] Failed to create contract call transaction: {}", e);
                }
            }
        } else {
            warn!("❌ [CONTRACT] Signing node not available for contract call execution");
        }

        Ok(())
    }
}