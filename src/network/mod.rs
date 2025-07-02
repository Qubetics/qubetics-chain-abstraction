use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, Message, TopicHash},
    identity::Keypair,
    kad::{self, store::MemoryStore, BucketInserts, Event as KademliaEvent},
    mdns::{self},
    multiaddr::Protocol,
    noise,
    request_response::{
        cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent, Message as ReqRespMessage,
    },
    swarm::{ConnectionError, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};
use std::{
    collections::{HashMap, HashSet},
    env,
    fmt::Debug,
    time::Duration,
};
use tokio::io;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::commands::CommandProcessor;
use crate::consensus::ConsensusNode;
use crate::dkg::DKGNode;
use crate::node_management::NodeMembership;
use crate::signing::SigningNode;
use crate::{
    dkg::DKGStatus,
    protos::intent::intent_service_server::IntentServiceServer,
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

// impl From<mdns::Event> for NetworkEvent {
//     fn from(event: mdns::Event) -> Self {
//         NetworkEvent::Mdns(event)
//     }
// }

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
                    // Add timestamp to prevent duplicate message ID issues
                    // std::time::SystemTime::now()
                    //     .duration_since(std::time::UNIX_EPOCH)
                    //     .unwrap_or_default()
                    //     .as_nanos()
                    //     .hash(&mut s);
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

        // Bootstrap with the configured nodes
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("Failed to start bootstrap: {:?}", e);
        }
        let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        let mut discovery_timer = tokio::time::interval(Duration::from_secs(120)); // 2 minutes (reduced from 60 seconds)

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

        let args: Vec<String> = env::args().collect();
        if args.len() >= 2 {
            let server_addr: Multiaddr = args[1].parse()?;
            println!("Dialing address: {}", server_addr);
            swarm.dial(server_addr.clone())?;
        }

        println!("Local Peer ID: {}", self.local_peer_id);
        self.node_manager
            .add_node(self.local_peer_id.clone())
            .map_err(|e| anyhow::anyhow!(e))?;

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

                    // Periodic broadcast of our local peer to ensure all peers know about us
                    // Only broadcast if we have peers but haven't seen recent activity
                    if current_total > 1 && gossipsub_peers > 0 {
                        // Add a sequence number to make each message unique
                        static mut SEQUENCE: u64 = 0;
                        let seq = unsafe {
                            SEQUENCE += 1;
                            SEQUENCE
                        };

                        let msg = GossipsubMessage::PeerDiscovered {
                            peer: self.local_peer_id.clone(),
                            sequence: Some(seq), // Add sequence number
                        };
                        // info!("🔄 Periodic broadcast of local peer: {:?} (seq: {})", self.local_peer_id, seq);
                        // if let Ok(payload) = serde_json::to_vec(&msg) {
                        //     if let Err(e) = self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await {
                        //         warn!("❌ Failed periodic peer broadcast: {:?}", e);
                        //     }
                        // }
                    } else {
                        info!("⏸️ Skipping periodic broadcast - peers: {}, gossipsub peers: {}", current_total, gossipsub_peers);
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
            // "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            // "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
            // "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            // "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        ];

        let peer_id_str = peer_id.to_string();
        bootstrap_peer_ids
            .iter()
            .any(|&bootstrap_id| peer_id_str.contains(bootstrap_id))
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

                // Debug: Check if this is a bootstrap node
                let bootstrap_peer_ids: Vec<&'static str> = vec![
                    // "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                    // "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
                    // "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                    // "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
                ];

                let peer_id_str = peer_id.to_string();
                let is_bootstrap = bootstrap_peer_ids
                    .iter()
                    .any(|&bootstrap_id| peer_id_str.contains(bootstrap_id));

                if is_bootstrap {
                    info!("🔗 Connected to bootstrap node: {:?}", peer_id);
                } else {
                    info!("🔗 Connected to MPC node: {:?}", peer_id);

                    // For MPC nodes, let's manually trigger some discovery
                    info!("🔍 Triggering peer discovery for MPC node: {:?}", peer_id);
                }

                // Get the remote address and add it to Kademlia
                let remote_addr = endpoint.get_remote_address();
                info!("📍 Remote address: {:?}", remote_addr);

                // Add the peer's address to Kademlia - this should trigger RoutingUpdated
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, remote_addr.clone());

                // Add peer to gossipsub as explicit peer for better message delivery
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                info!("➕ Added peer {} to gossipsub explicit peers", peer_id);

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
                                        info!("------------Starting DKG------------");
                                        dkg.start_dkg().await?;
                                        RPCResponse::DKGStarted {peer_id: SerializablePeerId(peer)}
                                    }
                                    None => RPCResponse::DKGError("dkg is not initialized.".to_string()),
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
                            RPCRequest::SendAVSSShare { share, commitments, .. } => {
                                if self.dkg_node.is_none() {
                                    RPCResponse::Error("DKG not initialized".to_string())
                                } else if self.dkg_node.as_ref().unwrap().verify_share(&share, &commitments) {
                                    RPCResponse::ShareAccepted
                                } else {
                                    RPCResponse::Error("Invalid share".into())
                                }
                            },
                            _ => RPCResponse::Ack
                        };
                        // here the following line will send to the other connected peers (incl any testing agent(s))
                        let _ = swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, response); // peer.send.ptp
                    }
                    // here peer(s) will recieve the msg sent by other peer by peer.send.ptp
                    ReqRespMessage::Response {
                        request_id,
                        response,
                    } => {
                        // peer.r
                        match response {
                            RPCResponse::GotAVSSShare {
                                dealer_id,
                                receiver_id,
                                share,
                                commitments,
                            } => {
                                // Handle AVSS share response here (maybe store in state?)
                                // e.g., self.dkg_node.as_mut()?.handle_received_share(party_id, share, commitments);
                            }

                            RPCResponse::DKGStarted { peer_id } => {
                                // dkg started by sending peer
                                info!("DKG has started by: {:?}", peer_id);
                            }

                            RPCResponse::Error(err) => {
                                // error received because of previous sent request
                                warn!("Received error from peer {}: {}", peer, err);
                            }

                            RPCResponse::ShareAccepted => {
                                // share accepted by the peer whom this node sent it to
                            }

                            _ => {
                                // Optionally handle other responses like DKGStatus, ShareAccepted, etc.
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
                        info!("-----------routing updated----------: Peer{:?}, is_new_peer{:?}, addresses{:?}, bucket_range{:?}, old_peer{:?}", peer, is_new_peer, addresses, bucket_range, old_peer);
                        self.node_manager
                            .add_node(peer)
                            .map_err(|e| anyhow::anyhow!(e))?;

                        if is_new_peer {
                            info!("New peer added: {:?}", peer);
                            let msg = GossipsubMessage::PeerDiscovered {
                                peer: peer.clone(),
                                sequence: Some(1), // Add sequence number
                            };
                            info!("Broadcasting PeerDiscovered message: {:?}", msg);
                            let payload = serde_json::to_vec(&msg)
                                .map_err(|e| anyhow::anyhow!("serialize PeerDiscovered: {}", e))?;

                            // Check if we have connected peers before broadcasting
                            let connected_peers =
                                swarm.behaviour_mut().gossipsub.all_peers().count();
                            info!("Connected peers before broadcast: {}", connected_peers);

                            if connected_peers > 0 {
                                // Add a small delay to ensure topic subscription is complete
                                tokio::time::sleep(Duration::from_millis(100)).await;

                                match self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await {
                                    Ok(_) => {
                                        info!(
                                            "✅ Successfully broadcasted peer discovery for: {:?}",
                                            peer
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
                            } else {
                                warn!("⚠️ No connected peers available for broadcasting peer discovery");
                            }

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

                            if total >= threshold + 1 {
                                if let Some(dkg_node) = &mut self.dkg_node {
                                    dkg_node.update_node_params(total, threshold);
                                    dkg_node.start_dkg().await?;

                                    for peer in self.node_manager.get_active_nodes() {
                                        let _ = swarm
                                            .behaviour_mut()
                                            .request_response
                                            .send_request(&peer, RPCRequest::StartADKG);
                                    }
                                }
                            }
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
                    tokio::time::sleep(Duration::from_millis(50)).await;

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
                peer_id,
                connection_id,
                endpoint,
                num_established,
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
                    dkg_node.handle_message(dkg_msg).await?;
                }
            }
            GossipsubMessage::Signing(signing_msg) => {
                if let Some(signing_node) = &mut self.signing_node {
                    signing_node.handle_message(signing_msg).await?;
                }
            }
            GossipsubMessage::Command(cmd) => {
                if let Some(cmd_processor) = &mut self.command_processor {
                    cmd_processor.handle_message(cmd).await?;
                }
            }
            GossipsubMessage::Consensus(consensus_msg) => {
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
    // the channel is setup between
    // 1. dkg thread (writing end) and tokio async task executor (reading end)
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
