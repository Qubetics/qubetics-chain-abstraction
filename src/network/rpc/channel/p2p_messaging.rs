use anyhow::{Result, anyhow};
use tracing::{debug, error, info, warn};
use crate::network::transport::types::{MpcNetworkLayer, MpcNetworkBehaviour};
use crate::types::*;
use libp2p::gossipsub;
use libp2p::{Multiaddr, PeerId};
use crate::types::rpc::RPCRequest;

impl MpcNetworkLayer {
    pub(crate) async fn handle_ch_broadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::Broadcast { topic, data } => {
                    // dkg.s.1
                    let topic_hash = gossipsub::IdentTopic::new(topic.clone());
    
                    // Production: Check channel capacity and log warnings for monitoring
                    let _channel_capacity_warning_threshold = 0.8; // Warn at 80% full
                    // Note: We can't directly check channel capacity, but we can monitor via try_send failures
                    
                    // Check if this is a critical message that needs retry tracking
                    // Only register if retry manager is available and message deserializes correctly
                    // Skip registration if message is already being tracked (e.g., from a retry)
                    if let Some(retry_mgr) = &self.retry_manager {
                        match serde_json::from_slice::<crate::types::GossipsubMessage>(&data) {
                            Ok(gossip_msg) => {
                                if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_msg) {
                                    // Generate message ID to check if already tracked
                                    if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_msg) {
                                        // Check if already being tracked (this is a retry, skip registration)
                                        if retry_mgr.is_message_tracked(&message_id).await {
                                            debug!("🔄 [RETRY] Message {:?} already tracked, skipping registration (this is a retry)", message_id);
                                        } else {
                                            // Get expected nodes (all active nodes except ourselves)
                                            let expected_nodes: std::collections::HashSet<PeerId> = self
                                                .node_manager
                                                .get_active_nodes()
                                                .into_iter()
                                                .filter(|&pid| pid != self.local_peer_id)
                                                .collect();
    
                                            if !expected_nodes.is_empty() {
                                                // Check if already tracked (retry case)
                                                if retry_mgr.is_message_tracked(&message_id).await {
                                                    debug!("🔄 [RETRY] Message {:?} already tracked, skipping registration (this is a retry)", message_id);
                                                } else {
                                                    // Log expected nodes for debugging
                                                    let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
                                                    debug!(
                                                        "📋 [RETRY] Registering message {:?} - expecting ACKs from {} nodes: {:?}",
                                                        message_id, expected_nodes.len(), expected_list
                                                    );
                                                    
                                                    // Register with retry manager (first time only)
                                                    if let Err(e) = retry_mgr.register_message(
                                                        message_id.clone(),
                                                        topic.clone(),
                                                        data.clone(),
                                                        expected_nodes.clone(),
                                                    ).await {
                                                        debug!("❌ [RETRY] Failed to register critical message for retry: {}", e);
                                                    }
                                                }
                                            } else {
                                                debug!("⚠️ [RETRY] No expected nodes - skipping retry registration for {:?}", message_id);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Message deserialization failed - this is expected for some message types
                                // Only log at debug level to avoid noise
                                debug!("[BROADCAST] Message deserialization failed (may not be a GossipsubMessage): {}", e);
                            }
                        }
                    }
    
                    // Check if this is a retry by checking if message is already tracked
                    let is_retry = if let Some(retry_mgr) = &self.retry_manager {
                        match serde_json::from_slice::<crate::types::GossipsubMessage>(&data) {
                            Ok(gossip_msg) => {
                                if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_msg) {
                                    if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_msg) {
                                        retry_mgr.is_message_tracked(&message_id).await
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            }
                            Err(_) => false,
                        }
                    } else {
                        false
                    };
    
                    // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                    // if peer(s) have already subscribed to this topic, they will recieve this
                    // msg (check subscribe_to_default_topics())
                    let swarm_mut = swarm.behaviour_mut();
                    let peer_count = swarm_mut.gossipsub.all_peers().count();
    
                    if peer_count > 0 {
                        let publish_result = swarm_mut.gossipsub.publish(topic_hash, data);
                        match publish_result {
                            Ok(_) => {}
                            Err(e) => {
                                if is_retry {
                                    debug!(
                                        "❌ [RETRY] CRITICAL: Failed to publish retry message to topic {}: {:?}",
                                        topic, e
                                    );
                                    // For retries, this is critical - log as debug (retry path)
                                } else {
                                    warn!(
                                        "❌ [BROADCAST] Failed to publish message to topic {}: {:?}",
                                        topic, e
                                    );
                                    // Initial publish failure - retry mechanism will handle it if message was registered
                                }
                            }
                        }
                    } else {
                        if is_retry {
                            debug!(
                                "❌ [RETRY] No peers available for retry broadcast to topic: {}",
                                topic
                            );
                        } else {
                            warn!(
                                "⚠️ [BROADCAST] No peers available for broadcasting to topic: {}",
                                topic
                            );
                        }
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_unicastsharedkg(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::UnicastShareDKG {
                    target_peer_id,
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                    round,
                    retry_count,
                } => {
                    const MAX_RETRIES: u8 = 10;
    
    
                    // Parse the target peer ID
                    let peer_id = match target_peer_id.parse::<PeerId>() {
                        Ok(pid) => pid,
                        Err(e) => {
                            warn!(
                                "❌ [DKG-SECURE] Invalid peer ID '{}': {}",
                                target_peer_id, e
                            );
                            return Err(anyhow!("Invalid peer ID: {}", e));
                        }
                    };
    
                    // Attempt to dial if not connected and we have a listen address
                    let mut is_connected = swarm.is_connected(&peer_id);
                    let connected_peers = swarm.connected_peers().collect::<Vec<_>>();
                    debug!("🔐 [DKG-SECURE] Connected peers: {:?}", connected_peers);
    
                    info!(
                        "🔐 [DKG-SECURE]  Peer discovery {} address: {:?}",
                        target_peer_id,
                        self.peer_discovery.peer_multiaddresses.get(&peer_id)
                    );
    
                    if !is_connected {
                        if let Some(addr) = self
                            .peer_discovery
                            .peer_multiaddresses
                            .get(&peer_id)
                            .cloned()
                        {
                            info!(
                                "📞 [DKG-SECURE] Not connected to {}, dialing before send: {}",
                                target_peer_id, addr
                            );
                            let address: Multiaddr = if addr
                                .to_string()
                                .contains(&format!("/p2p/{}", target_peer_id))
                            {
                                addr.clone()
                            } else {
                                format!("{}/p2p/{}", addr, target_peer_id)
                                    .parse()
                                    .expect("valid multiaddr")
                            };
                            if let Err(e) = swarm.dial(address.clone()) {
                                warn!("⚠️ [DKG-SECURE] Dial to {} failed: {}", target_peer_id, e);
                            } else {
                                // allow a brief window for connection to establish
                                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                                is_connected = swarm.is_connected(&peer_id);
                                info!(
                                    "🔐 [DKG-SECURE] Dial to connect to {} successful {}",
                                    target_peer_id, is_connected
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [DKG-SECURE] No known address to dial peer {}; will rely on retries",
                                target_peer_id
                            );
                        }
                    }
    
                    if !is_connected && retry_count < MAX_RETRIES {
                        // Not connected - schedule retry with exponential backoff
                        let delay_ms = 1000 * (1 << retry_count.min(5)); // 1s, 2s, 4s, 8s, 16s, 32s max
                        debug!(
                            "🔄 [DKG-SECURE] Peer send {} not connected - scheduling retry {} in {}ms",
                            target_peer_id,
                            retry_count + 1,
                            delay_ms
                        );
    
                        let tx = self.message_tx.clone();
                        let retry_msg = ChannelMessage::UnicastShareDKG {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            share_index,
                            share_value,
                            commitments,
                            round,
                            retry_count: retry_count + 1,
                        };
    
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                            if let Err(e) = tx.send(retry_msg).await {
                                tracing::warn!(
                                    "❌ [DKG-SECURE] Failed to schedule retry for share {}: {}",
                                    share_index,
                                    e
                                );
                            }
                        });
    
                        return Ok(());
                    }
    
                    if !is_connected {
                        warn!(
                            "❌ [DKG-SECURE] Peer {} still not connected after {} retries - giving up",
                            target_peer_id, MAX_RETRIES
                        );
                    }
    
                    // PACING: Check per-peer in-flight count before sending
                    {
                        use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                        let mut inflight = self.outbound_inflight.lock().await;
                        let count = inflight.get(&peer_id).copied().unwrap_or(0);
                        
                        if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                            // At capacity - re-queue with delay
                            debug!(
                                "⏸️ [DKG-SECURE] Peer {} at capacity ({}/{}), re-queuing share {}",
                                target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, share_index
                            );
                            let tx = self.message_tx.clone();
                            let msg = ChannelMessage::UnicastShareDKG {
                                target_peer_id: target_peer_id.clone(),
                                from_node_id: from_node_id.clone(),
                                share_index,
                                share_value: share_value.clone(),
                                commitments: commitments.clone(),
                                round,
                                retry_count,
                            };
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                                let _ = tx.send(msg).await;
                            });
                            return Ok(());
                        }
                        
                        // Increment in-flight count
                        *inflight.entry(peer_id).or_insert(0) += 1;
                    }
    
                    // Clone values for retry registry before creating RPC request
                    let from_node_id_clone = from_node_id.clone();
                    let share_value_clone = share_value.clone();
                    let commitments_clone = commitments.clone();
    
                    // Create the RPC request
                    let request = RPCRequest::SendDKGShare {
                        from_node_id,
                        share_index,
                        share_value,
                        commitments,
                        round,
                    };
    
                    // Send via request-response protocol (unicast, not broadcast)
                    let request_id = swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, request);
    
                    // RETRY: Insert into outbound_retry registry
                    {
                        use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                        let retry_msg = RetryableUnicast::UnicastShareDKG {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id: from_node_id_clone,
                            share_index,
                            share_value: share_value_clone,
                            commitments: commitments_clone,
                            round,
                        };
                        let entry = OutboundRetryEntry {
                            peer: peer_id,
                            retry_count,
                            msg: retry_msg,
                        };
                        self.outbound_retry.lock().await.insert(request_id, entry);
                    }
    
                    info!(
                        "✅ [DKG-SECURE] Share index {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                        share_index, target_peer_id, request_id, is_connected
                    );
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_unicastcritical(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::UnicastCritical {
                    target_peer_id,
                    topic,
                    data,
                    message_type,
                    message_id,
                    retry_count,
                } => {
                    const MAX_RETRIES: u8 = 1;
                    const RETRY_DELAY_MS: u64 = 200;
    
                    // info!(
                    //     "📨 [CRITICAL-UNICAST] Sending critical message {}:{} to peer {} (attempt {})",
                    //     message_type,
                    //     message_id,
                    //     target_peer_id,
                    //     retry_count + 1
                    // );
    
                    let peer_id = match target_peer_id.parse::<PeerId>() {
                        Ok(pid) => pid,
                        Err(e) => {
                            warn!(
                                "❌ [CRITICAL-UNICAST] Invalid peer ID '{}': {}",
                                target_peer_id, e
                            );
                            return Err(anyhow!("Invalid peer ID: {}", e));
                        }
                    };
    
                    let mut is_connected = swarm.is_connected(&peer_id);
                    // info!(
                    //     "📨 [CRITICAL-UNICAST] Target Peer {} connected: {}",
                    //     target_peer_id, is_connected
                    // );
    
                    if !is_connected {
                        if let Some(addr) = self
                            .peer_discovery
                            .peer_multiaddresses
                            .get(&peer_id)
                            .cloned()
                        {
                            info!(
                                "📞 [CRITICAL-UNICAST] Not connected to {}, dialing before send: {}",
                                target_peer_id, addr
                            );
                            let address: Multiaddr = if addr
                                .to_string()
                                .contains(&format!("/p2p/{}", target_peer_id))
                            {
                                addr.clone()
                            } else {
                                format!("{}/p2p/{}", addr, target_peer_id)
                                    .parse()
                                    .expect("valid multiaddr")
                            };
                            if let Err(e) = swarm.dial(address.clone()) {
                                warn!(
                                    "⚠️ [CRITICAL-UNICAST] Dial to {} failed: {}",
                                    target_peer_id, e
                                );
                            } else {
                                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                                is_connected = swarm.is_connected(&peer_id);
                                // info!(
                                //     "📨 [CRITICAL-UNICAST] Dial to {} successful: {}",
                                //     target_peer_id, is_connected
                                // );
                            }
                        } else {
                            warn!(
                                "⚠️ [CRITICAL-UNICAST] No known address to dial peer {}; will rely on retry manager",
                                target_peer_id
                            );
                        }
                    }
    
                    if !is_connected && retry_count < MAX_RETRIES {
                        info!(
                            "🔄 [CRITICAL-UNICAST] Peer {} not connected - scheduling quick retry {} in {}ms",
                            target_peer_id,
                            retry_count + 1,
                            RETRY_DELAY_MS
                        );
    
                        let tx = self.message_tx.clone();
                        let retry_msg = ChannelMessage::UnicastCritical {
                            target_peer_id: target_peer_id.clone(),
                            topic: topic.clone(),
                            data: data.clone(),
                            message_type: message_type.clone(),
                            message_id: message_id.clone(),
                            retry_count: retry_count + 1,
                        };
    
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                            if let Err(e) = tx.send(retry_msg).await {
                                tracing::warn!(
                                    "❌ [CRITICAL-UNICAST] Failed to schedule retry for {}:{}: {}",
                                    message_type,
                                    message_id,
                                    e
                                );
                            }
                        });
    
                        return Ok(());
                    }
    
                    if !is_connected {
                        warn!(
                            "❌ [CRITICAL-UNICAST] Peer {} still not connected after quick retry - giving up",
                            target_peer_id
                        );
                        return Ok(());
                    }
    
                    // PACING: Check per-peer in-flight count before sending
                    {
                        use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                        let mut inflight = self.outbound_inflight.lock().await;
                        let count = inflight.get(&peer_id).copied().unwrap_or(0);
                        
                        if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                            // At capacity - re-queue with delay
                            // info!(
                            //     "⏸️ [CRITICAL-UNICAST] Peer {} at capacity ({}/{}), re-queuing message",
                            //     target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER
                            // );
                            let tx = self.message_tx.clone();
                            let msg = ChannelMessage::UnicastCritical {
                                target_peer_id: target_peer_id.clone(),
                                topic,
                                data,
                                message_type,
                                message_id,
                                retry_count,
                            };
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                                let _ = tx.send(msg).await;
                            });
                            return Ok(());
                        }
                        
                        // Increment in-flight count
                        *inflight.entry(peer_id).or_insert(0) += 1;
                    }
    
                    let request = RPCRequest::DeliverCriticalGossip {
                        topic: topic.clone(),
                        data: data.clone(),
                        message_type: message_type.clone(),
                        message_id: message_id.clone(),
                    };
    
                    let request_id = swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, request);
    
                    // RETRY: Insert into outbound_retry registry
                    {
                        use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                        let retry_msg = RetryableUnicast::UnicastCritical {
                            target_peer_id: target_peer_id.clone(),
                            topic,
                            data,
                            message_type,
                            message_id,
                        };
                        let entry = OutboundRetryEntry {
                            peer: peer_id,
                            retry_count,
                            msg: retry_msg,
                        };
                        self.outbound_retry.lock().await.insert(request_id, entry);
                    }
    
                    info!(
                        "✅ [CRITICAL-UNICAST] Critical message sent to {} (request_id: {:?}, connected: {})",
                        target_peer_id, request_id, is_connected
                    );
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_unicastecdsasignature(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::UnicastECDSASignature {
                    target_peer_id,
                    from_node_id,
                    signature_data,
                    round,
                    retry_count,
                } => {
                    const MAX_RETRIES: u8 = 10;
    
                    debug!(
                        "🔐 [SIGNING-SECURE] Sending ECDSA signature for round {} via UNICAST to peer {} (attempt {})",
                        round,
                        target_peer_id,
                        retry_count + 1
                    );
    
                    let peer_id = match target_peer_id.parse::<PeerId>() {
                        Ok(pid) => pid,
                        Err(e) => {
                            warn!(
                                "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                                target_peer_id, e
                            );
                            return Err(anyhow!("Invalid peer ID: {}", e));
                        }
                    };
    
                    let mut is_connected = swarm.is_connected(&peer_id);
                    debug!(
                        "🔐 [SIGNING-SECURE] Target Peer {} connected: {}",
                        target_peer_id, is_connected
                    );
    
                    if !is_connected {
                        if let Some(addr) = self
                            .peer_discovery
                            .peer_multiaddresses
                            .get(&peer_id)
                            .cloned()
                        {
                            debug!(
                                "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                                target_peer_id, addr
                            );
                            let address: Multiaddr = if addr
                                .to_string()
                                .contains(&format!("/p2p/{}", target_peer_id))
                            {
                                addr.clone()
                            } else {
                                format!("{}/p2p/{}", addr, target_peer_id)
                                    .parse()
                                    .expect("valid multiaddr")
                            };
                            if let Err(e) = swarm.dial(address.clone()) {
                                warn!(
                                    "⚠️ [SIGNING-SECURE] Dial to {} failed: {}",
                                    target_peer_id, e
                                );
                            } else {
                                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                                is_connected = swarm.is_connected(&peer_id);
                                debug!(
                                    "🔐 [SIGNING-SECURE] Dial to connect to {} successful {}",
                                    target_peer_id, is_connected
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING-SECURE] No known address to dial peer {}; will rely on retries",
                                target_peer_id
                            );
                        }
                    }
    
                    if !is_connected && retry_count < MAX_RETRIES {
                        let delay_ms = 1000 * (1 << retry_count.min(5));
                        debug!(
                            "🔄 [SIGNING-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                            target_peer_id,
                            retry_count + 1,
                            delay_ms
                        );
    
                        let tx = self.message_tx.clone();
                        let retry_msg = ChannelMessage::UnicastECDSASignature {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            signature_data,
                            round,
                            retry_count: retry_count + 1,
                        };
    
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                            if let Err(e) = tx.send(retry_msg).await {
                                tracing::warn!(
                                    "❌ [SIGNING-SECURE] Failed to schedule retry for round {} signature: {}",
                                    round,
                                    e
                                );
                            }
                        });
    
                        return Ok(());
                    }
    
                    if !is_connected {
                        warn!(
                            "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                            target_peer_id, MAX_RETRIES
                        );
                    }
    
                    // PACING: Check per-peer in-flight count before sending
                    {
                        use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                        let mut inflight = self.outbound_inflight.lock().await;
                        let count = inflight.get(&peer_id).copied().unwrap_or(0);
                        
                        if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                            // At capacity - re-queue with delay
                            debug!(
                                "⏸️ [SIGNING-SECURE] Peer {} at capacity ({}/{}), re-queuing ECDSA signature for round {}",
                                target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, round
                            );
                            let tx = self.message_tx.clone();
                            let msg = ChannelMessage::UnicastECDSASignature {
                                target_peer_id: target_peer_id.clone(),
                                from_node_id,
                                signature_data,
                                round,
                                retry_count,
                            };
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                                let _ = tx.send(msg).await;
                            });
                            return Ok(());
                        }
                        
                        // Increment in-flight count
                        *inflight.entry(peer_id).or_insert(0) += 1;
                    }
    
                    let request = RPCRequest::SendECDSASignature {
                        from_node_id: from_node_id.clone(),
                        signature_data: signature_data.clone(),
                        round,
                    };
    
                    let request_id = swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, request);
    
                    // RETRY: Insert into outbound_retry registry
                    {
                        use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                        let retry_msg = RetryableUnicast::UnicastECDSASignature {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            signature_data,
                            round,
                        };
                        let entry = OutboundRetryEntry {
                            peer: peer_id,
                            retry_count,
                            msg: retry_msg,
                        };
                        self.outbound_retry.lock().await.insert(request_id, entry);
                    }
    
                    debug!(
                        "✅ [SIGNING-SECURE] ECDSA signature for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                        round, target_peer_id, request_id, is_connected
                    );
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_unicastbtcsignatures(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::UnicastBtcSignatures {
                    target_peer_id,
                    from_node_id,
                    signature_data,
                    round,
                    retry_count,
                } => {
                    const MAX_RETRIES: u8 = 10;
    
                    debug!(
                        "🔐 [SIGNING-SECURE] Sending BTC signatures for round {} via UNICAST to peer {} (attempt {})",
                        round,
                        target_peer_id,
                        retry_count + 1
                    );
    
                    let peer_id = match target_peer_id.parse::<PeerId>() {
                        Ok(pid) => pid,
                        Err(e) => {
                            warn!(
                                "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                                target_peer_id, e
                            );
                            return Err(anyhow!("Invalid peer ID: {}", e));
                        }
                    };
    
                    let mut is_connected = swarm.is_connected(&peer_id);
                    debug!(
                        "🔐 [SIGNING-SECURE] Target Peer {} connected: {}",
                        target_peer_id, is_connected
                    );
    
                    if !is_connected {
                        if let Some(addr) = self
                            .peer_discovery
                            .peer_multiaddresses
                            .get(&peer_id)
                            .cloned()
                        {
                            debug!(
                                "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                                target_peer_id, addr
                            );
                            let address: Multiaddr = if addr
                                .to_string()
                                .contains(&format!("/p2p/{}", target_peer_id))
                            {
                                addr.clone()
                            } else {
                                format!("{}/p2p/{}", addr, target_peer_id)
                                    .parse()
                                    .expect("valid multiaddr")
                            };
                            if let Err(e) = swarm.dial(address.clone()) {
                                warn!(
                                    "⚠️ [SIGNING-SECURE] Dial to {} failed: {}",
                                    target_peer_id, e
                                );
                            } else {
                                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                                is_connected = swarm.is_connected(&peer_id);
                                debug!(
                                    "🔐 [SIGNING-SECURE] Dial to connect to {} successful {}",
                                    target_peer_id, is_connected
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING-SECURE] No known address to dial peer {}; will rely on retries",
                                target_peer_id
                            );
                        }
                    }
    
                    if !is_connected && retry_count < MAX_RETRIES {
                        let delay_ms = 1000 * (1 << retry_count.min(5));
                        debug!(
                            "🔄 [SIGNING-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                            target_peer_id,
                            retry_count + 1,
                            delay_ms
                        );
    
                        let tx = self.message_tx.clone();
                        let retry_msg = ChannelMessage::UnicastBtcSignatures {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            signature_data,
                            round,
                            retry_count: retry_count + 1,
                        };
    
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                            if let Err(e) = tx.send(retry_msg).await {
                                tracing::warn!(
                                    "❌ [SIGNING-SECURE] Failed to schedule retry for round {} BTC signatures: {}",
                                    round,
                                    e
                                );
                            }
                        });
    
                        return Ok(());
                    }
    
                    if !is_connected {
                        warn!(
                            "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                            target_peer_id, MAX_RETRIES
                        );
                    }
    
                    // PACING: Check per-peer in-flight count before sending
                    {
                        use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                        let mut inflight = self.outbound_inflight.lock().await;
                        let count = inflight.get(&peer_id).copied().unwrap_or(0);
                        
                        if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                            // At capacity - re-queue with delay
                            debug!(
                                "⏸️ [SIGNING-SECURE] Peer {} at capacity ({}/{}), re-queuing BTC signatures for round {}",
                                target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, round
                            );
                            let tx = self.message_tx.clone();
                            let msg = ChannelMessage::UnicastBtcSignatures {
                                target_peer_id: target_peer_id.clone(),
                                from_node_id,
                                signature_data,
                                round,
                                retry_count,
                            };
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                                let _ = tx.send(msg).await;
                            });
                            return Ok(());
                        }
                        
                        // Increment in-flight count
                        *inflight.entry(peer_id).or_insert(0) += 1;
                    }
    
                    let request = RPCRequest::SendBtcSignatures {
                        from_node_id: from_node_id.clone(),
                        signature_data: signature_data.clone(),
                        round,
                    };
    
                    let request_id = swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, request);
    
                    // RETRY: Insert into outbound_retry registry
                    {
                        use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                        let retry_msg = RetryableUnicast::UnicastBtcSignatures {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            signature_data,
                            round,
                        };
                        let entry = OutboundRetryEntry {
                            peer: peer_id,
                            retry_count,
                            msg: retry_msg,
                        };
                        self.outbound_retry.lock().await.insert(request_id, entry);
                    }
    
                    debug!(
                        "✅ [SIGNING-SECURE] BTC signatures for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                        round, target_peer_id, request_id, is_connected
                    );
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_unicasttransactiondata(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::UnicastTransactionData {
                    target_peer_id,
                    from_node_id,
                    transaction_data,
                    round,
                    retry_count,
                } => {
                    const MAX_RETRIES: u8 = 10;
    
                    debug!(
                        "📦 [SIGNING-SECURE] Sending transaction data for round {} via UNICAST to peer {} (attempt {})",
                        round,
                        target_peer_id,
                        retry_count + 1
                    );
    
                    let peer_id = match target_peer_id.parse::<PeerId>() {
                        Ok(pid) => pid,
                        Err(e) => {
                            warn!(
                                "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                                target_peer_id, e
                            );
                            return Err(anyhow!("Invalid peer ID: {}", e));
                        }
                    };
    
                    let mut is_connected = swarm.is_connected(&peer_id);
                    debug!(
                        "📦 [SIGNING-SECURE] Target Peer {} connected: {}",
                        target_peer_id, is_connected
                    );
    
                    if !is_connected {
                        if let Some(addr) = self
                            .peer_discovery
                            .peer_multiaddresses
                            .get(&peer_id)
                            .cloned()
                        {
                            debug!(
                                "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                                target_peer_id, addr
                            );
                            let address: Multiaddr = if addr
                                .to_string()
                                .contains(&format!("/p2p/{}", target_peer_id))
                            {
                                addr.clone()
                            } else {
                                format!("{}/p2p/{}", addr, target_peer_id)
                                    .parse()
                                    .expect("valid multiaddr")
                            };
                            if let Err(e) = swarm.dial(address.clone()) {
                                warn!(
                                    "❌ [SIGNING-SECURE] Failed to dial {}: {}",
                                    target_peer_id, e
                                );
                            } else {
                                debug!("✅ [SIGNING-SECURE] Dialing {}", target_peer_id);
                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            }
                            is_connected = swarm.is_connected(&peer_id);
                        } else {
                            warn!(
                                "❌ [SIGNING-SECURE] No known address for peer {}",
                                target_peer_id
                            );
                        }
                    }
    
                    if !is_connected && retry_count < MAX_RETRIES {
                        let tx = self.message_tx.clone();
                        let delay_ms = 2000 + (retry_count as u64 * 1000);
                        debug!(
                            "⏰ [SIGNING-SECURE] Peer {} not connected, will retry transaction data for round {} in {}ms (attempt {}/{})",
                            target_peer_id,
                            round,
                            delay_ms,
                            retry_count + 1,
                            MAX_RETRIES
                        );
    
                        let retry_msg = ChannelMessage::UnicastTransactionData {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            transaction_data,
                            round,
                            retry_count: retry_count + 1,
                        };
    
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                            if let Err(e) = tx.send(retry_msg).await {
                                tracing::warn!(
                                    "❌ [SIGNING-SECURE] Failed to schedule retry for round {} transaction data: {}",
                                    round,
                                    e
                                );
                            }
                        });
    
                        return Ok(());
                    }
    
                    if !is_connected {
                        warn!(
                            "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                            target_peer_id, MAX_RETRIES
                        );
                    }
    
                    // PACING: Check per-peer in-flight count before sending
                    {
                        use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                        let mut inflight = self.outbound_inflight.lock().await;
                        let count = inflight.get(&peer_id).copied().unwrap_or(0);
                        
                        if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                            // At capacity - re-queue with delay
                            debug!(
                                "⏸️ [SIGNING-SECURE] Peer {} at capacity ({}/{}), re-queuing transaction data for round {}",
                                target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, round
                            );
                            let tx = self.message_tx.clone();
                            let msg = ChannelMessage::UnicastTransactionData {
                                target_peer_id: target_peer_id.clone(),
                                from_node_id,
                                transaction_data,
                                round,
                                retry_count,
                            };
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                                let _ = tx.send(msg).await;
                            });
                            return Ok(());
                        }
                        
                        // Increment in-flight count
                        *inflight.entry(peer_id).or_insert(0) += 1;
                    }
    
                    let request = RPCRequest::SendTransactionData {
                        from_node_id: from_node_id.clone(),
                        transaction_data: transaction_data.clone(),
                        round,
                    };
    
                    let request_id = swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, request);
    
                    // RETRY: Insert into outbound_retry registry
                    {
                        use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                        let retry_msg = RetryableUnicast::UnicastTransactionData {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            transaction_data,
                            round,
                        };
                        let entry = OutboundRetryEntry {
                            peer: peer_id,
                            retry_count,
                            msg: retry_msg,
                        };
                        self.outbound_retry.lock().await.insert(request_id, entry);
                    }
    
                    debug!(
                        "✅ [SIGNING-SECURE] Transaction data for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                        round, target_peer_id, request_id, is_connected
                    );
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_transactionfailure(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::TransactionFailure {
                    sequencer_request_id,
                    blockchain_tx_hash,
                    error,
                    original_request,
                } => {
                    info!(
                        "📝 [NETWORK] Processing transaction failure locally: request_id={}, error={}",
                        sequencer_request_id, error
                    );
    
                    // Check if error message indicates transaction is already in mempool
                    // If so, skip failure handling - transaction will succeed later
                    if error.contains("tx already in mempool") {
                        info!(
                            "✅ [TX_FAILURE] Transaction {} is already in mempool (error: {}). Will succeed later. Skipping failure handling.",
                            sequencer_request_id, error
                        );
                        // Don't re-insert or broadcast failure - transaction is pending and will succeed
                        return Ok(());
                    }
    
                    // Contract sequencer removed - transaction failures are logged but not retried via sequencer
                    warn!(
                        "⚠️ [TX_FAILURE] [LOCAL] Contract transaction {} failed: {}. Sequencer removed, no automatic retry.",
                        sequencer_request_id, error
                    );
    
                    // Then broadcast to other nodes via gossipsub
                    let failure_msg = GossipsubMessage::TransactionFailure {
                        sequencer_request_id: sequencer_request_id.clone(),
                        blockchain_tx_hash: blockchain_tx_hash.clone(),
                        error: error.clone(),
                        original_request,
                    };
                    let msg_bytes = serde_json::to_vec(&failure_msg)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize transaction failure: {}", e))?;
                    
                    let topic = gossipsub::IdentTopic::new("transaction-failure");
                    swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                    info!("📡 [NETWORK] Broadcasted transaction failure to P2P network");
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_transactionidbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::TransactionIdBroadcast {
                    intent_hashes,
                    transaction_id,
                    transaction_type,
                    solver_address,
                    node_id,
                } => {
                    info!(
                        "📡 [NETWORK] Received transaction ID broadcast from node {}",
                        node_id
                    );
                    info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                    info!("🔄 [NETWORK] Transaction type: {}", transaction_type);
                    if !intent_hashes.is_empty() {
                        info!("🔗 [NETWORK] Intent hashes: {:?}", intent_hashes);
                    } else if let Some(solver) = &solver_address {
                        info!("🧩 [NETWORK] Solver address: {}", solver);
                    } else {
                        info!("ℹ️ [NETWORK] No intent hashes or solver address supplied with transaction ID broadcast");
                    }
    
                    // Process locally first (like add_liquidity / peerinv:) so this node updates DB too
                    {
                        use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
                        let topic_hash = IdentTopic::new("transaction-sync");
                        let gossip_message = crate::types::GossipsubMessage::TransactionIdBroadcast {
                            intent_hashes: intent_hashes.clone(),
                            transaction_id: transaction_id.clone(),
                            transaction_type: transaction_type.clone(),
                            solver_address: solver_address.clone(),
                            node_id: node_id.clone(),
                        };
                        let data = serde_json::to_vec(&gossip_message).unwrap_or_default();
                        let local_msg = GossipMessage {
                            source: Some(self.local_peer_id),
                            data,
                            sequence_number: None,
                            topic: topic_hash.hash(),
                        };
                        if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                            warn!("❌ [NETWORK] Failed to process TransactionIdBroadcast locally: {}", e);
                        }
                    }
    
                    // Gossip the transaction ID broadcast to other peers immediately so everyone can contribute their share in parallel
                    let gossip_message = GossipsubMessage::TransactionIdBroadcast {
                        intent_hashes: intent_hashes.clone(),
                        transaction_id: transaction_id.clone(),
                        transaction_type: transaction_type.clone(),
                        solver_address: solver_address.clone(),
                        node_id: node_id.clone(),
                    };
    
                    let msg_bytes = match serde_json::to_vec(&gossip_message) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!("❌ [NETWORK] Failed to serialize transaction ID broadcast for gossiping: {}", e);
                            return Ok(());
                        }
                    };
    
                    let topic_str = "transaction-sync";
                    let topic = gossipsub::IdentTopic::new(topic_str);
    
                    // CRITICAL FIX: Register TransactionIdBroadcast for retry tracking
                    // This ensures all nodes receive transaction IDs even if initial broadcast fails
                    if let Some(retry_mgr) = &self.retry_manager {
                        if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_message) {
                            if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_message) {
                                // Check if already being tracked (this is a retry, skip registration)
                                if !retry_mgr.is_message_tracked(&message_id).await {
                                    // Get expected nodes (all active nodes except ourselves)
                                    let expected_nodes: std::collections::HashSet<PeerId> = self
                                        .node_manager
                                        .get_active_nodes()
                                        .into_iter()
                                        .filter(|&pid| pid != self.local_peer_id)
                                        .collect();
    
                                    if !expected_nodes.is_empty() {
                                        let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
                                        debug!(
                                            "📋 [RETRY] Registering TransactionIdBroadcast {:?} - expecting ACKs from {} nodes: {:?}",
                                            message_id, expected_nodes.len(), expected_list
                                        );
                                        
                                        // Register with retry manager (first time only)
                                        if let Err(e) = retry_mgr.register_message(
                                            message_id.clone(),
                                            topic_str.to_string(),
                                            msg_bytes.clone(),
                                            expected_nodes.clone(),
                                        ).await {
                                            debug!("❌ [RETRY] Failed to register TransactionIdBroadcast for retry: {}", e);
                                        } else {
                                            debug!("✅ [RETRY] Successfully registered TransactionIdBroadcast {:?} for retry tracking", message_id);
                                        }
                                    } else {
                                        debug!("⚠️ [RETRY] No expected nodes - skipping retry registration for TransactionIdBroadcast {:?}", message_id);
                                    }
                                } else {
                                    debug!("🔄 [RETRY] TransactionIdBroadcast {:?} already tracked, skipping registration (this is a retry)", message_id);
                                }
                            }
                        }
                    }
    
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), msg_bytes)
                    {
                        error!(
                            "❌ [NETWORK] Failed to gossip transaction ID broadcast to other peers: {}",
                            e
                        );
                    } else {
                        if !intent_hashes.is_empty() {
                            info!(
                                "📡 [NETWORK] Gossiped transaction ID {} for intents {:?} (type: {}) to other peers",
                                transaction_id, intent_hashes, transaction_type
                            );
                        } else if let Some(solver) = &solver_address {
                            info!(
                                "📡 [NETWORK] Gossiped reward transaction ID {} for solver {} (type: {}) to other peers",
                                transaction_id, solver, transaction_type
                            );
                        } else {
                            info!(
                                "📡 [NETWORK] Gossiped transaction ID {} (type: {}) to other peers",
                                transaction_id, transaction_type
                            );
                        }
                    }
    
                    // Define add_liquidity record structure and DB prefix
                    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
                    struct PendingAddLiquidityRecord {
                        request_id: String,
                        solver_id: String,
                        solver_address: String,
                        amount: String,
                        chain_id: u64,
                        signature: String,
                        signed_payload: String,
                        timestamp_ms: i64,
                        status: String,
                        #[serde(default)]
                        tx_id: Option<String>,
                    }
                    const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";
    
                    // Now process locally using shared handler
                    if !intent_hashes.is_empty() {
                        // Parse node_id to get PeerId for security check
                        let sender_peer_id = node_id
                            .parse::<libp2p::PeerId>()
                            .unwrap_or_else(|_| libp2p::PeerId::random());
    
                        for intent_hash in intent_hashes.iter() {
                            // Peer invalidation: already handled via gossipsub local processing (peerinv: prefix clears PENDING_DISCONNECTION)
                            if intent_hash.starts_with("peerinv:") {
                                info!(
                                    "ℹ️ [PEER_INVALIDATION] Skipping duplicate local processing for {} (already handled via gossipsub path)",
                                    intent_hash
                                );
                                continue;
                            }
                            // Check if this is an add_liquidity request_id (starts with "addliq:")
                            if intent_hash.starts_with("addliq:") {
                                // This is an add_liquidity request, mark as Completed
                                let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, intent_hash);
                                if let Ok(Some(mut record)) =
                                    self.db
                                        .get_string_async::<PendingAddLiquidityRecord>(&key)
                                        .await
                                {
                                    record.status = "Completed".to_string();
                                    let _ = self.db.put_string_async(&key, &record).await;
                                    info!("✅ [ADD_LIQUIDITY] Marked request {} as Completed (tx: {})", intent_hash, transaction_id);
                                }
                            } else {
                                // Regular intent, use existing handler
                                if let Err(e) = self
                                    .handle_transaction_id_storage(
                                        intent_hash,
                                        &transaction_id,
                                        &transaction_type,
                                        &node_id,
                                        &sender_peer_id,
                                    )
                                    .await
                                {
                                    error!(
                                        "❌ [NETWORK] Failed to handle transaction ID storage for intent {}: {}",
                                        intent_hash, e
                                    );
                                }
                            }
                        }
                    } else {
                        warn!("⚠️ [NETWORK] Transaction ID broadcast missing both intent hashes and solver address");
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_finalnodeidbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::FinalNodeIdBroadcast {
                    intent_hashes,
                    final_node_id,
                } => {
                    info!(
                        "📡 [NETWORK] Broadcasting final node ID {} for intents {:?}",
                        final_node_id, intent_hashes
                    );
    
                    // Process locally first
                    {
                        use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
                        let topic_hash = IdentTopic::new("transaction-sync");
                        let gossip_message = crate::types::GossipsubMessage::FinalNodeIdBroadcast {
                            intent_hashes: intent_hashes.clone(),
                            final_node_id: final_node_id.clone(),
                        };
                        let data = serde_json::to_vec(&gossip_message).unwrap_or_default();
                        let local_msg = GossipMessage {
                            source: Some(self.local_peer_id),
                            data,
                            sequence_number: None,
                            topic: topic_hash.hash(),
                        };
                        if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                            warn!("❌ [NETWORK] Failed to process FinalNodeIdBroadcast locally: {}", e);
                        }
                    }
    
                    // Gossip the final node ID broadcast
                    let gossip_message = GossipsubMessage::FinalNodeIdBroadcast {
                        intent_hashes: intent_hashes.clone(),
                        final_node_id: final_node_id.clone(),
                    };
    
                    let msg_bytes = match serde_json::to_vec(&gossip_message) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!("❌ [NETWORK] Failed to serialize final node ID broadcast: {}", e);
                            return Ok(());
                        }
                    };
    
                    let topic_str = "transaction-sync";
                    let topic = gossipsub::IdentTopic::new(topic_str);
    
                    // Register for retry tracking
                    if let Some(retry_mgr) = &self.retry_manager {
                        if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_message) {
                            if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_message) {
                                if !retry_mgr.is_message_tracked(&message_id).await {
                                    let expected_nodes: std::collections::HashSet<PeerId> = self
                                        .node_manager
                                        .get_active_nodes()
                                        .into_iter()
                                        .filter(|&pid| pid != self.local_peer_id)
                                        .collect();
    
                                    if !expected_nodes.is_empty() {
                                        if let Err(e) = retry_mgr.register_message(
                                            message_id.clone(),
                                            topic_str.to_string(),
                                            msg_bytes.clone(),
                                            expected_nodes.clone(),
                                        ).await {
                                            debug!("❌ [RETRY] Failed to register FinalNodeIdBroadcast: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
    
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), msg_bytes) {
                        error!(
                            "❌ [NETWORK] Failed to gossip final node ID broadcast: {}",
                            e
                        );
                    } else {
                        info!(
                            "📡 [NETWORK] Gossiped final node ID {} for intents {:?}",
                            final_node_id, intent_hashes
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_scheduleddkgstart(
        &mut self,
        msg_enum: ChannelMessage,
        _swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::ScheduledDKGStart => {
                    let total = self.node_manager.get_total_nodes();
                    let threshold = self.node_manager.get_threshold();
    
                    if let Some(dkg) = &mut self.dkg_node {
                        // This should only be called for initial DKG with 3 nodes
                        let initial_dkg_complete = dkg.is_initial_dkg_complete().await;
    
                        if initial_dkg_complete {
                            warn!("⚠️ [DKG] ScheduledDKGStart called but initial DKG already complete. This should not happen.");
                            return Ok(());
                        }
    
                        // Start the initial DKG with 3 nodes
                        info!("🚀 [DKG] Starting initial DKG with {} nodes", total);
    
                        if total != 3 {
                            warn!(
                                "⚠️ [DKG] Expected 4 nodes for initial DKG, but have {}",
                                total
                            );
                        }
    
                        if let Err(e) = dkg.update_node_params(total, threshold) {
                            warn!("❌ [DKG] Invalid params for scheduled start: {}", e);
                            return Ok(());
                        }
                        if let Err(e) = dkg.reset().await {
                            warn!("❌ [DKG] Failed to reset before scheduled start: {}", e);
                            return Ok(());
                        }
                        if let Some(arc) = &self.signing_node {
                        let mut signing_node = arc.lock().await;
                            // Align signing threshold with the node manager's configured threshold
                            signing_node.set_threshold(threshold);
                        }
                        info!(
                            "🔄 DKG parameters updated: total_nodes={}, threshold={}",
                            total, threshold
                        );
                        if let Err(e) = dkg.start_dkg(self.node_manager.clone()).await {
                            warn!("❌ Scheduled DKG start failed: {:?}", e);
                        }
                    } else {
                        warn!("❌ DKG node not initialized at scheduled start!");
                    }
            }
            _ => {},
        }
        Ok(())
    }

}
