/// Swarm event handlers
/// Handles ConnectionEstablished, ConnectionClosed, Kademlia events, etc.
use anyhow::Result;
use libp2p::swarm::{ConnectionError, SwarmEvent};
use libp2p::{
    gossipsub, kad::Event as KademliaEvent,
    request_response::Message as ReqRespMessage, PeerId,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

use crate::database::{key_utils::peer_addr_key, keys};
use crate::protocols::DKGMessage;
use crate::types::dkg::MSG_TOPIC_PEER_DISCOVERY;
use crate::types::p2p::SerializablePeerId;
use crate::types::rpc::RPCRequest;
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
                message_id: _,
                propagation_source: _,
                message,
            })) => {
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
            _ => {}
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

        let remote_addr = endpoint.get_remote_address();

        // Track connected peer
        self.connected_peers_cache.insert(peer_id);

        // Only persist the dialed address when we are the dialer; listener side remote_addr is ephemeral (caller source port).
        let is_dialer = matches!(endpoint, ConnectedPoint::Dialer { .. });
        if is_dialer {
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

        // Retry database sync if needed
        if self.needs_database_sync && !self.db_sync_state.in_progress {
            self.needs_database_sync = false;

            if let Err(e) = self.sync_database_from_peer(swarm, peer_id).await {
                warn!("❌ [DB_SYNC] Failed to start database sync: {:?}", e);
                self.needs_database_sync = true;
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

            // Check if we have existing DKG shares (additional safety check)
            let has_dkg_shares = if let Some(dkg) = &self.dkg_node {
                dkg.get_final_secret_share().await.is_some()
            } else {
                false
            };

            if initial_dkg_complete || has_dkg_shares {
                if has_dkg_shares {
                    info!("🔒 [DKG] Existing DKG shares detected - preserving state");
                }
                info!("🔒 [DKG] Initial DKG already completed, skipping re-initialization");
                info!("🆕 [NEW_NODE] Total nodes: {}, new node resharing will be triggered via PeerDiscovery gossipsub handler", total);
            } else if total == 3 {
                // Check if DKG is already in progress
                let is_dkg_running = if let Some(dkg) = &self.dkg_node {
                    let status = dkg.get_status();
                     !matches!(status, crate::protocols::DKGStatus::New)
                } else {
                    false
                };

                if is_dkg_running {
                     info!("⏳ [DKG] 3 nodes connected, but DKG is already running (Status != New). Skipping re-init.");
                } else {
                    // First time we have 3 nodes AND no existing DKG, start initial DKG
                    info!("🎯 Initial 3 nodes connected, triggering first DKG!");


                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let start_time = now_secs + 10;

                for peer in self.node_manager.get_active_nodes() {
                    if peer != *self.get_local_peer_id() {
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, RPCRequest::ScheduleADKG { start_time });
                    }
                }
                self.schedule_dkg_at(start_time);
            }
        }
    }

        if is_dialer {
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, RPCRequest::GetPeerList);

            // Also request VRF round sync when connecting
            if !self.vrf_round_requested && !self.needs_database_sync {
                swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    RPCRequest::VrfRoundSync(VrfRoundSyncRequest {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round: self
                            .get_local_vrf_round_for_domain(VrfDomain::Signing, None)
                            .await,
                        context: String::new(),
                    }),
                );
                self.vrf_round_requested = true;
            }
        }

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
                        }
                    }
                    ReqRespMessage::Response {
                        request_id,
                        response,
                    } => {
                        // Check if the response is an application-level error (e.g., "DKG not initialized")
                        // If so, we treat it as a failure and retry, instead of considering it a success.
                        let is_error_response = matches!(response, crate::types::rpc::RPCResponse::Error(_));

                        if is_error_response {
                            // It's an error, check if we should retry
                            if let Some(mut pending) = self.pending_share_requests.remove(&request_id) {
                                warn!("⚠️ [RETRY] Received application error for share request {:?}: {:?}", request_id, response);

                                const MAX_RETRIES: u8 = 10;
                                if pending.retry_count < MAX_RETRIES {
                                    pending.retry_count += 1;
                                    let delay_ms = 500 * (1 << pending.retry_count.min(6));
                                    
                                    info!(
                                        "🔄 [RETRY] Rescheduling error-response share request to {} (attempt {}/{}) in {}ms", 
                                        peer, pending.retry_count, MAX_RETRIES, delay_ms
                                    );

                                    // Reschedule via channel to avoid blocking and handle re-sending
                                    let tx = self.message_tx.clone();
                                    let request = pending.request.clone();
                                    let peer_str = peer.to_string();
                                    let retry_count = pending.retry_count;

                                    tokio::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                                        
                                        let msg = match request {
                                            RPCRequest::SendDKGShare { from_node_id, share_index, share_value, commitments, round } => {
                                                Some(ChannelMessage::UnicastShareDKG {
                                                    target_peer_id: peer_str,
                                                    from_node_id,
                                                    share_index,
                                                    share_value,
                                                    commitments,
                                                    round,
                                                    retry_count,
                                                })
                                            },
                                            RPCRequest::SendRefreshShare { from_node_id, share_index, share_value, commitments } => {
                                                Some(ChannelMessage::UnicastRefreshShare {
                                                    target_peer_id: peer_str,
                                                    from_node_id,
                                                    share_index,
                                                    share_value,
                                                    commitments,
                                                    retry_count,
                                                })
                                            },
                                            _ => None,
                                        };

                                        if let Some(channel_msg) = msg {
                                            if let Err(e) = tx.send(channel_msg).await {
                                                warn!("❌ [RETRY] Failed to enqueue retry message: {}", e);
                                            }
                                        }
                                    });
                                } else {
                                    error!("❌ [RETRY] Max retries reached for share request to {}", peer);
                                }
                            } else {
                                // Not a tracked request, just handle normally (log error)
                                self.handle_rpc_response(swarm, peer, response).await?;
                            }
                        } else {
                            // Success! Remove from pending tracking
                            self.pending_share_requests.remove(&request_id);
                            self.handle_rpc_response(swarm, peer, response).await?;
                        }
                    }
                }
            }
            ReqRespEvent::OutboundFailure { peer, request_id, error, .. } => {
                // Log detailed error information
                warn!(
                    "❌ [REQ-RESP] Outbound failure to peer {} (req: {:?}): {:?}",
                    peer, request_id, error
                );
                
                // Check if peer is actually connected (may show true even if request-response fails)
                let is_connected = swarm.is_connected(&peer);
                warn!(
                    "🔍 [REQ-RESP] Peer {} connection status: {} (connection exists but request-response failed)",
                    peer, is_connected
                );
                
                // Log error type for debugging
                let error_str = format!("{:?}", error);
                if error_str.contains("Timeout") {
                    warn!(
                        "⏱️ [REQ-RESP] Request timeout to {} - peer may be overloaded or unresponsive",
                        peer
                    );
                } else if error_str.contains("ConnectionClosed") || error_str.contains("Connection") {
                    warn!(
                        "🔌 [REQ-RESP] Connection issue to {} - peer may have disconnected or connection is stale",
                        peer
                    );
                } else if error_str.contains("Dial") {
                    warn!(
                        "📞 [REQ-RESP] Dial failure to {} - connection may not be established",
                        peer
                    );
                } else if error_str.contains("Unsupported") || error_str.contains("Protocol") {
                    warn!(
                        "🚫 [REQ-RESP] Protocol issue to {} - protocol mismatch or unsupported",
                        peer
                    );
                }
                
                // Check if this was a pending share request
                if let Some(mut pending) = self.pending_share_requests.remove(&request_id) {
                    const MAX_RETRIES: u8 = 10;
                    if pending.retry_count < MAX_RETRIES {
                        pending.retry_count += 1;
                        let delay_ms = 500 * (1 << pending.retry_count.min(6));
                        
                        info!(
                            "🔄 [RETRY] Rescheduling failed share request to {} (attempt {}/{}) in {}ms", 
                            peer, pending.retry_count, MAX_RETRIES, delay_ms
                        );

                        // Reschedule via channel to avoid blocking and handle re-sending
                        let tx = self.message_tx.clone();
                        let request = pending.request.clone();
                        let peer_str = peer.to_string();
                        let retry_count = pending.retry_count;

                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            
                            let msg = match request {
                                RPCRequest::SendDKGShare { from_node_id, share_index, share_value, commitments, round } => {
                                    Some(ChannelMessage::UnicastShareDKG {
                                        target_peer_id: peer_str,
                                        from_node_id,
                                        share_index,
                                        share_value,
                                        commitments,
                                        round,
                                        retry_count,
                                    })
                                },
                                RPCRequest::SendRefreshShare { from_node_id, share_index, share_value, commitments } => {
                                    Some(ChannelMessage::UnicastRefreshShare {
                                        target_peer_id: peer_str,
                                        from_node_id,
                                        share_index,
                                        share_value,
                                        commitments,
                                        retry_count,
                                    })
                                },
                                _ => None,
                            };

                            if let Some(channel_msg) = msg {
                                if let Err(e) = tx.send(channel_msg).await {
                                    warn!("❌ [RETRY] Failed to enqueue retry message: {}", e);
                                }
                            }
                        });
                    } else {
                        error!("❌ [RETRY] Max retries reached for share request to {}", peer);
                    }
                }
            }
            ReqRespEvent::InboundFailure { peer, error, .. } => {
                warn!("Inbound failure to peer {}: {:?}", peer, error);
            }
            ReqRespEvent::ResponseSent { .. } => {}
        }
        Ok(())
    }

    /// Handle Kademlia events
    async fn handle_kademlia_event(&mut self, event: KademliaEvent) -> Result<()> {
        match event {
            KademliaEvent::RoutingUpdated {
                peer,
                is_new_peer,
                addresses: _,
                bucket_range: _,
                old_peer: _,
            } => {
                if is_new_peer {
                    // Check if this is a bootstrap node
                    if self.is_bootstrap_node(&peer) {
                        return Ok(());
                    }
                }
            }
            KademliaEvent::InboundRequest { .. } => {}
            KademliaEvent::OutboundQueryProgressed { .. } => {}
            KademliaEvent::UnroutablePeer { .. } => {}
            KademliaEvent::RoutablePeer { .. } => {}
            KademliaEvent::PendingRoutablePeer { .. } => {}
            KademliaEvent::ModeChanged { .. } => {}
        }
        Ok(())
    }

    /// Handle peer subscribed to topic event
    async fn handle_peer_subscribed(
        &mut self,
        peer_id: PeerId,
        topic: libp2p::gossipsub::TopicHash,
    ) -> Result<()> {
        // If this is the peer discovery topic, we can now safely broadcast our presence
        if topic.as_str() == MSG_TOPIC_PEER_DISCOVERY {

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
                self.schedule_peer_discovery_retry(1);
                return Ok(());
            } else {
                self.peer_discovery.pending_peer_discovery_retry = false;
            }

            // Update peer_indices mapping for all active peers
            for pid in &active_nodes {
                if !self.peer_discovery.peer_indices.contains_key(pid) {
                    if let Some(db_idx) = self.get_index_from_db_async(pid).await {
                        self.peer_discovery.peer_indices.insert(*pid, db_idx);
                    }
                }
            }

            if has_other_peers {
                self.broadcast_local_presence().await?;
            }
        }

        Ok(())
    }

    /// Handle new listen address - log P2P server details
    fn handle_new_listen_addr(&self, address: libp2p::Multiaddr) {
        // Extract port and protocol information from multiaddr
        let mut tcp_port: Option<u16> = None;
        let mut udp_port: Option<u16> = None;
        let mut protocol = "unknown";
        
        // Parse multiaddr to extract port information
        let addr_str = address.to_string();
        
        // Check for TCP port
        if let Some(tcp_part) = addr_str.split("/tcp/").nth(1) {
            if let Some(port_str) = tcp_part.split('/').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    tcp_port = Some(port);
                    protocol = "TCP";
                }
            }
        }
        
        // Check for UDP/QUIC port
        if let Some(udp_part) = addr_str.split("/udp/").nth(1) {
            if let Some(port_str) = udp_part.split('/').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    udp_port = Some(port);
                    if addr_str.contains("quic-v1") {
                        protocol = "QUIC";
                    } else {
                        protocol = "UDP";
                    }
                }
            }
        }
        
        // Log P2P server information
        if let Some(port) = tcp_port {
            info!(
                "🌐 [P2P] P2P server listening on TCP port {} - Multiaddr: {}/p2p/{}",
                port, address, self.local_peer_id
            );
            info!(
                "🔗 [P2P] Connect to this node using: {}/p2p/{}",
                address, self.local_peer_id
            );
        } else if let Some(port) = udp_port {
            info!(
                "🌐 [P2P] P2P server listening on {} port {} - Multiaddr: {}/p2p/{}",
                protocol, port, address, self.local_peer_id
            );
            info!(
                "🔗 [P2P] Connect to this node using: {}/p2p/{}",
                address, self.local_peer_id
            );
        } else {
            info!(
                "🌐 [P2P] P2P server listening on address: {}/p2p/{}",
                address, self.local_peer_id
            );
        }
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
                    }
                }

                // STEP 2: Process disconnect locally
                self.handle_node_disconnect_internal(peer_id).await;
            }
        }
    }
}
