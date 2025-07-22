use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    core::ConnectedPoint, gossipsub::{self, Message, TopicHash}, identity::Keypair, kad::{self, store::MemoryStore, BucketInserts, Event as KademliaEvent}, multiaddr::Protocol, noise, request_response::{
        cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent, Message as ReqRespMessage,
    }, swarm::{ConnectionError, NetworkBehaviour, SwarmEvent}, tcp, yamux, Multiaddr, PeerId
};

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
use tokio::sync::{mpsc};
use tracing::{info, warn};

use crate::{commands::CommandProcessor, node_management};
use crate::consensus::ConsensusNode;
use crate::dkg::DKGNode;
use crate::node_management::NodeMembership;
use crate::signing::SigningNode;
use crate::{
    dkg::DKGStatus,
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
    consensus_node: Option<ConsensusNode>,
    command_processor: Option<CommandProcessor>,
    node_manager: Box<dyn NodeMembership>,
    scheduled_dkg_task: Option<JoinHandle<()>>,
}

impl NetworkLayer {
    pub async fn new(node_manager: Box<dyn NodeMembership>) -> Result<Self> {
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            local_key,
            local_peer_id,
            message_tx: tx,
            message_rx: rx,
            topics: HashSet::new(),
            dkg_node: None,
            signing_node: None,
            consensus_node: None,
            command_processor: None,
            node_manager,
            scheduled_dkg_task: None,
        })
    }

    pub fn set_dkg_node(&mut self, dkg_node: DKGNode) {
        self.dkg_node = Some(dkg_node);
    }

    pub fn set_signing_node(&mut self, signing_node: SigningNode) {
        self.signing_node = Some(signing_node);
    }

    pub fn set_consensus_node(&mut self, node: ConsensusNode) {
        self.consensus_node = Some(node);
    }

    pub fn set_command_processor(&mut self, processor: CommandProcessor) {
        self.command_processor = Some(processor);
    }

    pub fn get_dkg_node(&mut self) -> Option<&mut DKGNode> {
        self.dkg_node.as_mut()
    }

    pub fn get_signing_node(&mut self) -> Option<&mut SigningNode> {
        self.signing_node.as_mut()
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
        self.subscribe_to_default_topics(&mut swarm)?;
        println!("Starting Kademlia bootstrap...");
        self.node_manager
            .add_node(self.local_peer_id.clone())
            .map_err(|e| anyhow::anyhow!(e))?;

        // Bootstrap with the configured nodes
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("Failed to start bootstrap: {:?}", e);
        }
        let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(300));
        let mut discovery_timer = tokio::time::interval(Duration::from_secs(300));
        let mut dkg_status_timer = tokio::time::interval(Duration::from_secs(300));
        let mut peerlist_logger = tokio::time::interval(Duration::from_secs(10));


        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;


        let args: Vec<String> = env::args().collect();
        if args.len() >= 2 {
            let server_addr: Multiaddr = args[1].parse()?;
            println!("Dialing address: {}", server_addr);
            swarm.dial(server_addr.clone())?;
        }

        println!("Local Peer ID: {}", self.local_peer_id);

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    info!("[SWARM] some");
                    self.handle_swarm_event(event, &mut swarm).await?;
                }
                // only hit when there is anything on the mpsc channel
                msg = self.message_rx.recv() => {
                    if let Some(msg) = msg {
                        // lets handle the channel msg on the basis of its type
                        self.handle_channel_message(msg, &mut swarm).await?;
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
                    println!("Performing periodic bootstrap...");
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
            "dkg-commands",
            "signatures-to-final-node",
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
            // send the one “start now” message back into your main loop
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

                // Determine whether they dialed us (we’re the listener) or we dialed them
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

                    self.node_manager
                            .add_node(peer_id)
                            .map_err(|e| anyhow::anyhow!(e))?;

                    
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

                                // Log how many peers we’re returning (and list them if you like)
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
                    // Handle all signing messages normally
                    info!("📤 [NETWORK] Processing signing message on topic: {}", message.topic);
                    signing_node.handle_message(signing_msg).await?;
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
                    signing_node.handle_vrf_selected_nodes_broadcast(broadcast_msg);
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
                            info!("🔐 [NETWORK] Got secret share from DKG: {:?}", secret_share);
                            signing_node.set_private_key_from_bls_scalar(secret_share);
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
                    println!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                    signing_node.sign_message(tx_bytes, &transaction).await?;
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
                            signing_node.set_private_key_from_bls_scalar(secret_share);
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
                    signing_node.sign_message(tx_bytes, &transaction).await?;
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
            ChannelMessage::ScheduledDKGStart => {
                info!("🚀 Starting DKG at the exact agreed instant {}!", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();
                if let Some(dkg) = &mut self.dkg_node {
                    dkg.update_node_params(total, threshold);
                    dkg.reset().await;
                    if let Some(signing_node) = &mut self.signing_node {
                        signing_node.set_threshold(self.node_manager.get_total_nodes() - 1);
                    }
                    self.node_manager
                        .set_threshold(total - 1);
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
}
