/// Swarm event handlers
/// Handles ConnectionEstablished, ConnectionClosed, Kademlia events, etc.
use anyhow::Result;
use libp2p::swarm::{ConnectionError, SwarmEvent};
use libp2p::{
    gossipsub, kad::Event as KademliaEvent, multiaddr::Protocol,
    request_response::Message as ReqRespMessage, PeerId,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

use crate::database::{key_utils::peer_addr_key, keys};
use crate::protocols::DKGMessage;
use crate::types::dkg::MSG_TOPIC_PEER_DISCOVERY;
use crate::types::p2p::SerializablePeerId;
use crate::types::rpc::{MPCProtocol, RPCRequest};
use crate::types::vrf::VrfRoundSyncRequest;
use crate::types::{ChannelMessage, GossipsubMessage};

use super::types::{MpcNetworkBehaviour, MpcNetworkLayer, NetworkEvent, VrfDomain};

impl MpcNetworkLayer {
    /// Main swarm event handler - delegates to specific handlers
    pub(crate) async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<NetworkEvent>,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        info!("[SWARM EVENT] {:?}", event);
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.handle_connection_established(swarm, peer_id, endpoint)
                    .await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::RequestResponse(req_resp_event)) => {
                self.handle_request_response_event(swarm, req_resp_event)
                    .await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::Kademlia(kad_event)) => {
                self.handle_kademlia_event(kad_event).await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Message {
                message_id,
                propagation_source,
                message,
            })) => {
                info!(
                    "📨 Received gossipsub message - Topic: {}, From: {}, Message ID: {:?}",
                    message.topic, propagation_source, message_id
                );
                info!("📦 Message size: {} bytes", message.data.len());
                info!("🏷️ Topic hash: {:?}", message.topic);

                self.handle_gossipsub_message(&message).await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                self.handle_peer_subscribed(peer_id, topic).await?;
            }
            SwarmEvent::Behaviour(NetworkEvent::Gossipsub(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            })) => {
                warn!("📡 Peer {} unsubscribed from topic: {}", peer_id, topic);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                self.handle_new_listen_addr(address);
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id: _,
                endpoint: _,
                num_established,
                cause,
            } => {
                self.handle_connection_closed(peer_id, num_established, cause)
                    .await;
            }
            _ => {
                info!("[EVENT] other");
            }
        }
        Ok(())
    }

    /// Handle connection established event
    async fn handle_connection_established(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        endpoint: libp2p::core::ConnectedPoint,
    ) -> Result<()> {
        use libp2p::core::ConnectedPoint;

        info!("🔗 Connection established with peer: {:?}", peer_id);
        let remote_addr = endpoint.get_remote_address();
        info!("📍 Remote address: {:?}", remote_addr);

        // Track connected peer
        self.connected_peers_cache.insert(peer_id);

        // Only persist the dialed address when we are the dialer; listener side remote_addr is ephemeral (caller source port).
        let is_dialer = matches!(endpoint, ConnectedPoint::Dialer { .. });
        if is_dialer {
            info!(
                "🔗 [CONNECTION_ESTABLISHED] Storing peer address {} => {} in peer_multiaddresses",
                peer_id, remote_addr
            );
            self.peer_discovery
                .peer_multiaddresses
                .insert(peer_id, remote_addr.clone());
            let addr_key = peer_addr_key(&peer_id.to_string());
            if let Err(e) = self.db.put_string(&addr_key, &remote_addr.to_string()) {
                warn!(
                    "⚠️ Failed to persist peer address {} => {}: {}",
                    peer_id, remote_addr, e
                );
            }
        } else {
            info!(
                "ℹ️ Listener-side connection from {} at {}; not persisting (likely ephemeral)",
                peer_id, remote_addr
            );
        }

        // Always request PeerInfo to learn the peer's listen addresses
        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, RPCRequest::GetPeerInfo);

        // Determine whether they dialed us or we dialed them
        let is_listener = matches!(endpoint, ConnectedPoint::Listener { .. });

        // Check if we already know this peer
        let already_known = self.node_manager.get_active_nodes().contains(&peer_id);

        // Add the peer's address to Kademlia
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, remote_addr.clone());

        // Add peer to gossipsub as explicit peer
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
        info!("➕ Added peer {} to gossipsub explicit peers", peer_id);

        // Retry database sync if needed
        if self.needs_database_sync && !self.db_sync_state.in_progress {
            info!(
                "🔄 [DB_SYNC] Connection established, retrying database sync with peer: {}",
                peer_id
            );
            self.needs_database_sync = false;

            if let Err(e) = self.sync_database_from_peer(swarm, peer_id).await {
                warn!("❌ [DB_SYNC] Failed to start database sync: {:?}", e);
                self.needs_database_sync = true;
            } else {
                info!("✅ [DB_SYNC] Database sync retry initiated successfully");
            }
        }

        if is_listener && !already_known {
            self.handle_new_peer_connection(swarm, peer_id).await?;

            let total = self.node_manager.get_total_nodes();

            // Check if initial DKG has been completed
            let initial_dkg_complete = if let Some(dkg) = &self.dkg_node {
                dkg.is_initial_dkg_complete().await
            } else {
                false
            };

            if initial_dkg_complete {
                info!("🔒 [DKG] Initial DKG already completed with 4 nodes");
                info!("🆕 [NEW_NODE] Total nodes: {}, new node resharing will be triggered via PeerDiscovery gossipsub handler", total);
            } else if total == 4 {
                // First time we have 4 nodes, start initial DKG
                info!("🎯 Initial 4 nodes connected, triggering first DKG!");

                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let start_time = now_secs + 10;
                info!(
                    "🕒 Scheduling initial DKG start at unix time {}",
                    start_time
                );

                for peer in self.node_manager.get_active_nodes() {
                    if peer != *self.get_local_peer_id() {
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, RPCRequest::ScheduleADKG { start_time });
                    }
                }
                info!(
                    "📅 Scheduled initial DKG start for all peers at {}",
                    start_time
                );
                self.schedule_dkg_at(start_time);
            } else if total < 4 {
                info!("⏳ Waiting for initial 4 nodes: {}/4", total);
            }
        }

        if is_dialer {
            info!("🚀 Sending GetPeerList RPC to {}", peer_id);
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, RPCRequest::GetPeerList);

            // Also request VRF round sync when connecting
            if !self.vrf_round_requested && !self.needs_database_sync {
                info!(
                    "🔄 [VRF_SYNC] Requesting current VRF round from peer {} on connection",
                    peer_id
                );
                swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    RPCRequest::VrfRoundSync(VrfRoundSyncRequest {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round: self
                            .get_local_vrf_round_for_domain(VrfDomain::Signing)
                            .await,
                    }),
                );
                self.vrf_round_requested = true;
                info!("✅ [VRF_SYNC] VRF round request sent to peer {}", peer_id);
            }
        }

        // Debug: Log Kademlia and gossipsub stats
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

        let gossipsub_peer_count = swarm.behaviour_mut().gossipsub.all_peers().count();
        info!(
            "📊 Gossipsub peer count after adding {}: {}",
            peer_id, gossipsub_peer_count
        );

        // Try to discover more peers through this connection
        swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);

        Ok(())
    }

    /// Handle request-response events
    async fn handle_request_response_event(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        event: libp2p::request_response::Event<
            crate::types::rpc::RPCRequest,
            crate::types::rpc::RPCResponse,
        >,
    ) -> Result<()> {
        use libp2p::request_response::Event as ReqRespEvent;

        match event {
            ReqRespEvent::Message { peer, message, .. } => {
                info!("RPC request: peer: {} response: {:?}", peer, message);
                match message {
                    ReqRespMessage::Request {
                        request, channel, ..
                    } => {
                        let response = self.handle_rpc_request(peer, request, swarm).await;
                        let res = swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, response);
                        if res.is_err() {
                            warn!(
                                "❌ Failed to send response to peer {}: {:?}",
                                peer,
                                res.err()
                            );
                        } else {
                            info!("📤 Sent RPC response to {}: {:?}", peer, res);
                        }
                    }
                    ReqRespMessage::Response {
                        request_id: _,
                        response,
                    } => {
                        self.handle_rpc_response(swarm, peer, response).await?;
                    }
                }
            }
            ReqRespEvent::OutboundFailure { peer, error, .. } => {
                info!("Outbound failure to peer {}: {:?}", peer, error);
            }
            ReqRespEvent::InboundFailure { peer, error, .. } => {
                info!("Inbound failure to peer {}: {:?}", peer, error);
            }
            ReqRespEvent::ResponseSent { peer, .. } => {
                info!("Response sent to peer {}", peer);
            }
        }
        Ok(())
    }

    /// Handle Kademlia events
    async fn handle_kademlia_event(&mut self, event: KademliaEvent) -> Result<()> {
        match event {
            KademliaEvent::RoutingUpdated {
                peer,
                is_new_peer,
                addresses,
                bucket_range,
                old_peer,
            } => {
                info!(
                    "-----------routing updated----------: Peer{:?}, is_new_peer{:?}, addresses{:?}, bucket_range{:?}, old_peer{:?}\n",
                    peer, is_new_peer, addresses, bucket_range, old_peer
                );

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
        Ok(())
    }

    /// Handle peer subscribed to topic event
    async fn handle_peer_subscribed(
        &mut self,
        peer_id: PeerId,
        topic: libp2p::gossipsub::TopicHash,
    ) -> Result<()> {
        info!("📡 Peer {} subscribed to topic: {}", peer_id, topic);

        // If this is the peer discovery topic, we can now safely broadcast our presence
        if topic.as_str() == MSG_TOPIC_PEER_DISCOVERY {
            info!(
                "🎯 Peer discovery topic subscription confirmed by: {}",
                peer_id
            );

            let active_nodes = self.node_manager.get_active_nodes();
            let other_peers_in_manager: Vec<_> = active_nodes
                .iter()
                .filter(|&pid| pid != self.get_local_peer_id())
                .collect();

            // Also check database for other peers
            let mut other_peers_in_db = 0;
            if let Ok(keys) = self.db.get_keys_with_prefix_async(keys::PEER_INDEX).await {
                for k in keys {
                    if let Some(peer_str) = k.strip_prefix(keys::PEER_INDEX) {
                        if let Ok(pid) = peer_str.parse::<PeerId>() {
                            if pid != *self.get_local_peer_id() {
                                other_peers_in_db += 1;
                            }
                        }
                    }
                }
            }

            let has_other_peers = !other_peers_in_manager.is_empty() || other_peers_in_db > 0;
            if !has_other_peers {
                info!(
                    "ℹ️ No other peers found yet; delaying peer discovery broadcast until another peer is available"
                );
                self.schedule_peer_discovery_retry(1);
                return Ok(());
            } else {
                info!(
                    "✅ Found {} other peers in node manager, {} in database",
                    other_peers_in_manager.len(),
                    other_peers_in_db
                );
                self.peer_discovery.pending_peer_discovery_retry = false;
            }

            // Update peer_indices mapping for all active peers before logging
            info!("🔢 Active nodes: {:?}", active_nodes);
            for pid in &active_nodes {
                if !self.peer_discovery.peer_indices.contains_key(pid) {
                    if let Some(db_idx) = self.get_index_from_db_async(pid).await {
                        info!("🔢 Loaded index {} for peer {} from database", db_idx, pid);
                        self.peer_discovery.peer_indices.insert(*pid, db_idx);
                    }
                }
            }

            let existing_peer_count = self.peer_discovery.peer_indices.len();
            info!("📊 Existing peers count: {}", existing_peer_count);
            if existing_peer_count > 0 {
                let existing_peers: Vec<(String, usize)> = self
                    .peer_discovery
                    .peer_indices
                    .iter()
                    .map(|(pid, idx)| (pid.to_string(), *idx))
                    .collect();
                info!("📋 Existing peers with indices: {:?}", existing_peers);
            }

            if has_other_peers {
                self.broadcast_local_presence().await?;
            }
        }

        Ok(())
    }

    /// Handle new listen address
    fn handle_new_listen_addr(&self, address: libp2p::Multiaddr) {
        info!("Listening on {}", address);
        let full = address.clone().with(Protocol::P2p(self.local_peer_id));
        info!("📡 multiaddress   : {}", full);
        info!(
            "Listening for RPC connections on {}{}",
            address,
            MPCProtocol.as_ref()
        );
    }

    /// Handle connection closed event
    async fn handle_connection_closed(
        &mut self,
        peer_id: PeerId,
        num_established: u32,
        cause: Option<ConnectionError>,
    ) {
        self.connected_peers_cache.remove(&peer_id);
        if let Some(ca) = cause {
            if let ConnectionError::IO(e) = ca {
                info!(
                    "[ERROR] Kind: {} RAW: {:?} ref: {:?} Full: {}",
                    e.kind(),
                    e.raw_os_error(),
                    e.get_ref().as_slice(),
                    e
                );
            }
        }

        // STEP 1: Detect when a node fully disconnects (no remaining connections)
        if num_established == 0 {
            info!(
                "🔌 [DISCONNECT] Node {} has fully disconnected (0 connections remaining)",
                peer_id
            );

            // Check if this was an active node in our network
            let was_active = self.node_manager.get_active_nodes().contains(&peer_id);

            if was_active {
                warn!(
                    "⚠️ [DISCONNECT] Active node {} disconnected - broadcasting to all nodes",
                    peer_id
                );

                // STEP 1: Broadcast disconnect notification to ALL nodes via gossipsub
                let disconnect_msg = DKGMessage::NodeDisconnected {
                    disconnected_node_id: peer_id.to_string(),
                    broadcaster_node_id: self.local_peer_id.to_string(),
                };

                let gossip_wrap = GossipsubMessage::DKG(disconnect_msg);
                if let Ok(msg_bytes) = serde_json::to_vec(&gossip_wrap) {
                    if let Err(e) = self
                        .message_tx
                        .send(ChannelMessage::Broadcast {
                            topic: "dkg".to_string(),
                            data: msg_bytes,
                        })
                        .await
                    {
                        error!(
                            "❌ [DISCONNECT] Failed to send disconnect notification to channel: {}",
                            e
                        );
                    } else {
                        info!(
                            "📢 [DISCONNECT] Broadcasted disconnect notification for node {} to all nodes",
                            peer_id
                        );
                    }
                }

                // STEP 2: Process disconnect locally
                self.handle_node_disconnect_internal(peer_id).await;
            } else {
                info!(
                    "ℹ️ [DISCONNECT] Disconnected peer {} was not an active node",
                    peer_id
                );
            }
        }
    }
}
