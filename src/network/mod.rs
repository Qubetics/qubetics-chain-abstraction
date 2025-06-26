use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, Message, TopicHash},
    identity::Keypair,
    kad::{store::MemoryStore, BucketInserts, Event as KademliaEvent},
    mdns::{self},
    noise,
    request_response::{
        cbor::Behaviour as CborReqRespBehaviour, Event as ReqRespEvent, Message as ReqRespMessage,
    },
    swarm::{ConnectionError, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
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
        dkg::MSG_TOPIC_DKG,
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
    // Mdns(mdns::Event),
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
    peers: RwLock<HashMap<PeerId, PeerInfo>>,
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
            peers: RwLock::new(HashMap::new()),
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
                    gossipsub::MessageId::from(s.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(30))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(io::Error::other)
                    .map_err(io::Error::other)?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // let mdns_config = mdns::Config {
                //     query_interval: Duration::from_secs(10),
                //     ttl: Duration::from_secs(10),
                //     ..Default::default()
                // };

                // let mdns =
                //     mdns::tokio::Behaviour::new(mdns_config, key.public().to_peer_id())?;

                // Initialize Kademlia
                let store = MemoryStore::new(key.public().to_peer_id());
                let mut kademlia_config = kad::Config::default();
                kademlia_config.set_kbucket_inserts(BucketInserts::OnConnected);
                kademlia_config.set_query_timeout(Duration::from_secs(60));
                kademlia_config
                    .set_replication_factor(std::num::NonZeroUsize::new(3).expect("3 is non-zero"));

                let mut kademlia =
                    kad::Behaviour::with_config(key.public().to_peer_id(), store, kademlia_config);

                    // Add bootstrap nodes
            let bootstrap_nodes = vec![
                "/dnsaddr/bootstrap-0.mainnet.libp2p.io/tcp/443/wss/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                "/dnsaddr/bootstrap-1.mainnet.libp2p.io/tcp/443/wss/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
                "/dnsaddr/bootstrap-2.mainnet.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                "/dnsaddr/bootstrap-3.mainnet.libp2p.io/tcp/443/wss/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
            ];

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

        println!("Starting Kademlia bootstrap...");

        // Bootstrap with the configured nodes
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("Failed to start bootstrap: {:?}", e);
        }
        let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        let mut discovery_timer = tokio::time::interval(Duration::from_secs(60)); // 1 minute

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

        let args: Vec<String> = env::args().collect();
        if args.len() >= 2 {
            // eprintln!("Usage: {} <multiaddr>", args[0]);
            // std::process::exit(1);
            let server_addr: Multiaddr = args[1].parse()?;
            println!("Dialing address: {}", server_addr);
            swarm.dial(server_addr.clone())?;
        }

        println!("Local Peer ID: {}", self.local_peer_id);

        self.subscribe_to_default_topics(&mut swarm)?;

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
                    info!("Performing peer discovery...");

                    // Debug: Show current state before discovery
                    let current_total = self.node_manager.get_total_nodes();
                    let active_nodes = self.node_manager.get_active_nodes();
                    info!("Current node manager state - Total: {}, Active nodes: {:?}", current_total, active_nodes);

                    swarm.behaviour_mut().kademlia.get_closest_peers(self.local_peer_id);

                    // Also search for random peers to populate routing table
                    let random_peer = PeerId::random();
                    swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
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
            "signing",
            "consensus",
            "commands",
            "vrf-selection",
        ];
        for topic in topics {
            let topic_hash = gossipsub::IdentTopic::new(topic);
            info!("topic hash for {} is {}", topic, topic_hash);
            swarm.behaviour_mut().gossipsub.subscribe(&topic_hash)?;
            self.topics.insert(topic_hash.hash());
        }
        Ok(())
    }

    fn is_bootstrap_node(&self, peer_id: &PeerId) -> bool {
        let bootstrap_peer_ids = vec![
            "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
            "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
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
                info!(
                    "\x1b[37m🔗 Connection established with peer: {:?}\x1b[0m",
                    peer_id
                );

                // Debug: Check if this is a bootstrap node
                let bootstrap_peer_ids = vec![
                    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
                    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
                ];

                let peer_id_str = peer_id.to_string();
                let is_bootstrap = bootstrap_peer_ids
                    .iter()
                    .any(|&bootstrap_id| peer_id_str.contains(bootstrap_id));

                if is_bootstrap {
                    info!(
                        "\x1b[33m🔗 Connected to bootstrap node: {:?}\x1b[0m",
                        peer_id
                    );
                } else {
                    info!("\x1b[32m🔗 Connected to MPC node: {:?}\x1b[0m", peer_id);

                    // For MPC nodes, let's manually trigger some discovery
                    info!(
                        "\x1b[36m🔍 Triggering peer discovery for MPC node: {:?}\x1b[0m",
                        peer_id
                    );
                }

                // Get the remote address and add it to Kademlia
                let remote_addr = endpoint.get_remote_address();
                info!("\x1b[90m📍 Remote address: {:?}\x1b[0m", remote_addr);

                // Add the peer's address to Kademlia - this should trigger RoutingUpdated
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, remote_addr.clone());

                // Debug: Log current Kademlia routing table size
                let kbucket_count: usize = swarm
                    .behaviour_mut()
                    .kademlia
                    .kbuckets()
                    .map(|bucket| bucket.num_entries())
                    .sum();
                info!(
                    "\x1b[35m📋 Kademlia routing table now has {} entries\x1b[0m",
                    kbucket_count
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
                            RPCRequest::SendAVSSShare { dealer_id: _, share: _, commitments: _, .. } => {
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
                        request_id: _,
                        response,
                    } => {
                        // peer.r
                        match response {
                            RPCResponse::GotAVSSShare {
                                dealer_id: _,
                                receiver_id: _,
                                share: _,
                                commitments: _,
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
            // SwarmEvent::Behaviour(NetworkEvent::Mdns(mdns::Event::Discovered(peers))) => {
            //     for (peer_id, addr) in peers {
            //         info!("Discovered peer: {peer_id} at {addr}");
            //         self.peers.write().await.insert(peer_id, PeerInfo {
            //             addresses: vec![addr],
            //             connected: true,
            //         });
            //         self.node_manager.add_node(peer_id).map_err(|e| anyhow::anyhow!(e))?;
            //         info!("Added node: {peer_id}");
            //         // Restart DKG when new node joins
            //         if let Some(dkg_node) = &mut self.dkg_node {
            //             dkg_node.start_dkg().await?;
            //         }
            //     }
            //     println!("[NEW] Peers: {}", self.peers.read().await.values().filter(|peer| peer.connected).collect::<Vec<_>>().len());
            // }

            // SwarmEvent::Behaviour(NetworkEvent::Mdns(mdns::Event::Expired(peers))) => {
            //     info!("[EXP]");
            //     for (peer_id, _) in peers {
            //         if let Some(peer) = self.peers.write().await.get_mut(&peer_id) {
            //             peer.connected = false;
            //         }
            //         self.node_manager.remove_node(peer_id).map_err(|e| anyhow::anyhow!(e))?;
            //     }
            //     println!("[EXP] Peers: {}", self.peers.read().await.values().filter(|peer| peer.connected).collect::<Vec<_>>().len());
            //     // Restart DKG when a node leaves or expired from the network
            //     if let Some(dkg_node) = &mut self.dkg_node {
            //         dkg_node.start_dkg().await?;
            //     }
            // }
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

                        if is_new_peer {
                            info!("New peer added: {:?}", peer);

                            // Check if this is a bootstrap node
                            if self.is_bootstrap_node(&peer) {
                                info!("⚠️  This is a bootstrap node, skipping: {:?}", peer);
                                return Ok(());
                            }

                            info!("\x1b[32m✅ This is a real MPC node: {:?}\x1b[0m", peer);

                            self.node_manager
                                .add_node(peer)
                                .map_err(|e| anyhow::anyhow!(e))?;

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

                            // Start DKG when 2nd node and onwards join the network
                            if total > 1 {
                                if let Some(dkg_node) = &mut self.dkg_node {
                                    dkg_node.update_node_params(total, threshold); // Update total_nodes in the DKGNode
                                    dkg_node.start_dkg().await?;
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
                    "Received message with id: {} from: {}",
                    message_id, propagation_source
                );
                self.handle_gossipsub_message(&message).await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                info!("Subscribed to topic: {}", topic);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
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
        info!("i am at handle_gossipsub_message ---------- {:?}", message);
        let res = serde_json::from_slice::<GossipsubMessage>(&message.data);
        if let Err(e) = &res {
            info!("now I know the error ----- {:?}", e);
        }
        let msg = res.unwrap();
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
                info!("[handle_channel_message()] [BCAST] topic: {}", topic);
                let topic_hash = gossipsub::IdentTopic::new(topic);
                // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                // if peer(s) have already subscribed to this topic, they will recieve this
                // msg (check subscribe_to_default_topics())
                let swarm_mut = swarm.behaviour_mut();
                info!(
                    "[handle_channel_message()] [BCAST] prs count: {}",
                    swarm_mut.gossipsub.all_peers().count()
                );
                if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                    info!("error: {:?}", e);
                };
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
