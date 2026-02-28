use anyhow::Result;
use libp2p::gossipsub::Message;
use tracing::{debug, error, info, warn};
use crate::network::transport::types::{MpcNetworkLayer, VrfDomain, TOPIC_CONSENSUS};
use crate::types::*;
use crate::types::p2p::SerializablePeerId;
use crate::types::vrf::VrfRoundSyncResponse;

impl MpcNetworkLayer {
    pub(crate) async fn handle_signing(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::Signing(signing_msg) => {
                    if let Some(arc) = &self.signing_node {
                        let mut signing_node = arc.lock().await;
                        // 🛡️ Error recovery for signing message processing - prevent node crashes
                        // Handle signing messages
                        match &signing_msg {
                            SigningMessage::ECDSASignature {
                                from,
                                signature,
                                round,
                                timestamp: _timestamp,
                                user_tics_address,
                                slot_id: _,
                            } => {
                                let tx_type = if user_tics_address.is_some() {
                                    "user-to-network"
                                } else {
                                    "network-to-target"
                                };
                                debug!("📥 [NETWORK] Received {} ECDSA signature from {} for round {} on topic {} (user_tics_address: {:?})", tx_type, from, round, message.topic, user_tics_address);
                                info!(
                                    "🔍 [NETWORK] Signature details - signer_id: {}",
                                    signature.signer_id
                                );
                            }
                            SigningMessage::BtcUtvSignaturesMessage {
                                from,
                                signatures,
                                round,
                                slot_id,
                                timestamp: _timestamp,
                                user_tics_address: _,
                            } => {
                                info!(
                                    "📥 [NETWORK] Received BTC UTV batch signatures from {} for slot {} round {} ({} inputs)",
                                    from, slot_id, round, signatures.len()
                                );
                            }
                            // Nonce protocol messages for random k generation
                            SigningMessage::NonceCommitment { .. } => {}
                            SigningMessage::NonceReveal { .. } => {}
                            SigningMessage::RequestNonceGeneration { .. } => {}
                            SigningMessage::NonceGenerationComplete { .. } => {}
                            _ => {}
                        }
                        let signing_result = signing_node.handle_message(signing_msg).await;
    
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_consensus(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::Consensus(consensus_msg) => {
                    // Handle consensus message in signing node
                    if let Some(arc) = &self.signing_node {
                        let mut signing_node = arc.lock().await;
                        signing_node
                            .handle_consensus_message(consensus_msg.clone())
                            .await?;
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_vrfselection(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::VrfSelection(_vrf_msg) => {
                    // Handle selection messages
                    if let Some(_vrf_manager) = self
                        .node_manager
                        .as_any()
                        .downcast_ref::<crate::node_selection::VrfNodeManager>()
                    {
                        // We need to handle this differently since we can't mutate through a trait object
                        // For now, we'll log the message
                    } else {
                        debug!("Received selection message but node manager is not selection-based (ignored)");
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_vrfselectednodes(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::VrfSelectedNodes(broadcast_msg) => {
                    let selector_node_id = broadcast_msg.selector_node_id.0;
                    let round = broadcast_msg.round;
                    let sender_peer_id = match message.source {
                        Some(pid) => pid,
                        None => {
                            warn!("🚫 [SECURITY] Rejecting VrfSelectedNodes broadcast: message has no source");
                            return Ok(());
                        }
                    };
                    debug!(
                        "���� [SELECTION] Received selected nodes broadcast: round={}, from={}, received_by={}",
                        round, selector_node_id, self.local_peer_id
                    );
    
                    // No ACK or retry for VrfSelectedNodes - used only for round sync / consensus trigger (final node is HRW)
    
                    // Store the received selection in the signing node's selector
                    if let Some(arc) = &self.signing_node {
                        let mut signing_node = arc.lock().await;
                        let selector_node_id = broadcast_msg.selector_node_id.clone();
                        let round = broadcast_msg.round;
                        signing_node.handle_vrf_selected_nodes_broadcast(
                            self.node_manager.get_total_nodes(),
                            broadcast_msg,
                            sender_peer_id,
                        );
                        info!(
                            "💾 [SELECTION] Stored selected nodes from node {} for round {}",
                            selector_node_id.0, round
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_vrfroundsyncrequest(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::VrfRoundSyncRequest(sync_request) => {
                    let peer = sync_request.from.0;
                    let reference_round = self
                        .get_local_vrf_round_for_domain(VrfDomain::Signing, Some(&sync_request.context))
                        .await;
    
                    if self
                        .store_peer_round_if_valid(
                            VrfDomain::Signing,
                            &sync_request.context,
                            peer,
                            reference_round,
                            sync_request.current_round,
                        )
                        .await
                    {
                        info!(
                            "💾 [SYNC] Stored round {:?} for peer {} from gossipsub request",
                            sync_request.current_round, peer
                        );
                    }
    
                    let response_round = self
                        .get_local_vrf_round_for_domain(VrfDomain::Signing, Some(&sync_request.context))
                        .await;
                    let response = GossipsubMessage::VrfRoundSyncResponse(VrfRoundSyncResponse {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round: response_round,
                        context: sync_request.context.clone(),
                    });
    
                    match serde_json::to_vec(&response) {
                        Ok(data) => {
                            if let Err(e) = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: TOPIC_CONSENSUS.to_string(),
                                    data,
                                })
                                .await
                            {
                                warn!(
                                    "⚠️ [SYNC] Failed to send round sync response to {}: {}",
                                    peer, e
                                );
                            }
                        }
                        Err(e) => warn!("⚠️ [SYNC] Failed to serialize round sync response: {}", e),
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_vrfroundsyncresponse(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::VrfRoundSyncResponse(sync_response) => {
                    let peer = sync_response.from.0;
                    let reference_round = self
                        .get_local_vrf_round_for_domain(
                            VrfDomain::Signing,
                            Some(&sync_response.context),
                        )
                        .await;
    
                    if self
                        .store_peer_round_if_valid(
                            VrfDomain::Signing,
                            &sync_response.context,
                            peer,
                            reference_round,
                            sync_response.current_round,
                        )
                        .await
                    {
                        info!(
                            "💾 [SYNC] Stored round {:?} for peer {} from gossipsub response",
                            sync_response.current_round, peer
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_noncetuplebroadcast(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::NonceTupleBroadcast {
                    batch_id,
                    tuples,
                    node_id,
                } => {
                    // Store broadcasted nonce tuples locally.
                    // Observer nodes need these so they can reserve nonce IDs when
                    // acting as the final node for batch coordination.
                    // DKG nodes already stored them during generation, so duplicates
                    // are harmlessly overwritten.
                    info!(
                        "📥 [NONCE] Received {} nonce tuples from node {} (batch {})",
                        tuples.len(),
                        node_id,
                        batch_id
                    );
    
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        if let Some(nm) = node.nonce_manager() {
                            let nm_guard = nm.lock().await;
                            let total = tuples.len();
                            let mut stored = 0usize;
                            for tuple in tuples {
                                if let Err(e) = nm_guard.store_received_nonce_tuple(tuple).await {
                                    warn!(
                                        "⚠️ [NONCE] Failed to store nonce tuple from batch {}: {}",
                                        batch_id, e
                                    );
                                } else {
                                    stored += 1;
                                }
                            }
                            info!(
                                "✅ [NONCE] Stored {}/{} nonce tuples from batch {}",
                                stored, total, batch_id
                            );
                        }
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_nonceinvalidation(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::NonceInvalidation {
                    nonce_tuple_ids,
                    reason,
                    node_id,
                } => {
                    // A peer failed to find one or more coordinated nonces during signing.
                    // Mark them as consumed locally so we don't try to use them either.
                    warn!(
                        "🚫 [NONCE] Received invalidation from node {} for {} nonce(s): {:?} (reason: {})",
                        node_id,
                        nonce_tuple_ids.len(),
                        nonce_tuple_ids,
                        reason
                    );
    
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.invalidate_nonces_local(&nonce_tuple_ids, &reason)
                            .await;
                    }
            }
            _ => {},
        }
        Ok(())
    }

}
