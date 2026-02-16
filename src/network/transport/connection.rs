use anyhow::{anyhow, Result};
use libp2p::PeerId;
use std::time::Duration;
use tracing::{info, warn};

use crate::database::keys;
use crate::types::dkg::MSG_TOPIC_PEER_DISCOVERY;
use crate::types::GossipsubMessage;

use super::types::{MpcNetworkBehaviour, MpcNetworkLayer};

impl MpcNetworkLayer {
    /// Handle node disconnection internally (called both locally and from broadcast)
    pub(crate) async fn handle_node_disconnect_internal(&mut self, peer_id: PeerId) {
        info!("🔧 [DISCONNECT] Processing disconnect for node {}", peer_id);

        // DEDUPLICATION: Check if we've already processed this disconnect recently
        let now = std::time::Instant::now();
        let dedup_window = std::time::Duration::from_secs(10); // 10-second deduplication window

        if let Some(last_processed) = self.peer_discovery.processed_disconnects.get(&peer_id) {
            if now.duration_since(*last_processed) < dedup_window {
                info!("⏭️ [DISCONNECT] Already processed disconnect for {} recently (within {} seconds), skipping",
                      peer_id, dedup_window.as_secs());
                return;
            }
        }

        // Mark this disconnect as processed
        self.peer_discovery
            .processed_disconnects
            .insert(peer_id, now);
        info!(
            "✅ [DISCONNECT] Marked disconnect for {} as processed at {:?}",
            peer_id, now
        );

        // Clean up old entries (older than dedup_window) to prevent memory growth
        self.peer_discovery
            .processed_disconnects
            .retain(|_, &mut timestamp| now.duration_since(timestamp) < dedup_window);

        // Log active nodes BEFORE removal
        let active_nodes_before = self.node_manager.get_active_nodes();
        info!(
            "📋 [DISCONNECT] Active nodes BEFORE removal: {:?} (count: {})",
            active_nodes_before,
            active_nodes_before.len()
        );

        // Remove node from node manager
        if let Err(e) = self.node_manager.remove_node(peer_id) {
            warn!(
                "⚠️ [DISCONNECT] Failed to remove node {} from node manager: {}",
                peer_id, e
            );
            return;
        }

        // Log active nodes AFTER removal to verify
        let active_nodes_after = self.node_manager.get_active_nodes();
        info!(
            "✅ [DISCONNECT] Successfully removed node {} from node_manager",
            peer_id
        );
        info!(
            "📋 [DISCONNECT] Active nodes AFTER removal: {:?} (count: {})",
            active_nodes_after,
            active_nodes_after.len()
        );

        // Double-check the node is really gone
        if active_nodes_after.contains(&peer_id) {
            tracing::error!(
                "❌ [DISCONNECT] BUG: Node {} still in active nodes after removal!",
                peer_id
            );
        } else {
            info!(
                "✅ [DISCONNECT] Verified: Node {} is NOT in active nodes list",
                peer_id
            );
        }

        // Also remove from peer_indices HashMap
        if let Some(removed_index) = self.peer_discovery.peer_indices.remove(&peer_id) {
            info!(
                "✅ [DISCONNECT] Removed peer {} (index {}) from peer_indices HashMap",
                peer_id, removed_index
            );
        }

        // Remove from database as well (peer index and commitments so share_pubkey recompute doesn't fail)
        let peer_index_key = format!("{}{}", keys::PEER_INDEX, peer_id);
        if let Err(e) = self.db.delete_string(&peer_index_key) {
            warn!(
                "⚠️ [DISCONNECT] Failed to remove peer {} from database: {}",
                peer_id, e
            );
        } else {
            info!("✅ [DISCONNECT] Removed peer {} from database", peer_id);
        }

        // Remove disconnected peer's commitments so compute_and_store_all_share_pubkeys doesn't look up their (deleted) index
        let commitment_key = format!("{}{}", keys::DKG_COMMITMENT, peer_id);
        if let Err(e) = self.db.delete_string(&commitment_key) {
            warn!(
                "⚠️ [DISCONNECT] Failed to remove commitments for peer {}: {}",
                peer_id, e
            );
        } else {
            info!("✅ [DISCONNECT] Removed commitments for peer {} from database", peer_id);
        }

        // Update network parameters
        let new_total = self.node_manager.get_total_nodes();
        let new_threshold = self.node_manager.get_threshold();

        info!(
            "📊 [DISCONNECT] Updated network: total_nodes={}, threshold={}",
            new_total, new_threshold
        );

        // Contract sequencer removed

        // Update DKG and signing node parameters
        if let Some(dkg_node) = &mut self.dkg_node {
            if let Err(e) = dkg_node.update_node_params(new_total, new_threshold) {
                warn!("⚠️ [DISCONNECT] Failed to update DKG params: {}", e);
            }
        }

        // Only update signing threshold if initial DKG is not yet complete
        // After DKG, threshold is fixed based on initial DKG participants
        let initial_dkg_complete = if let Some(dkg_node) = &self.dkg_node {
            dkg_node.is_initial_dkg_complete().await
        } else {
            false
        };
        if !initial_dkg_complete {
            // If we already know the DKG signer count, use it for threshold
            // instead of total_nodes — prevents observer threshold inflation
            let effective_threshold = if let Some(dkg_node) = &self.dkg_node {
                if let Some(dkg_count) = dkg_node.get_dkg_signer_count() {
                    let t = dkg_count / 2 + 1;
                    info!("🔄 [THRESHOLD] Using DKG-based threshold {} (from {} DKG signers)", t, dkg_count);
                    t
                } else {
                    new_threshold
                }
            } else {
                new_threshold
            };
            if let Some(arc) = &self.signing_node {
                let mut signing_node = arc.lock().await;
                signing_node.set_threshold(effective_threshold);
            }
        } else {
            info!("ℹ️ [THRESHOLD] Keeping signing threshold unchanged after disconnect - fixed by initial DKG");
        }

    }

    /// Handle new peer connection and announce to network
    pub(crate) async fn handle_new_peer_connection(
        &mut self,
        _swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
    ) -> Result<()> {
        info!("📡 New peer {} connected; announcing to mesh", peer_id);

        // Assign and persist index based on DB state
        let tentative_index = self.assign_and_persist_index(&peer_id);
        info!("assigned_index : {:?}", tentative_index);

        let msg = GossipsubMessage::PeerDiscovered {
            peer: peer_id,
            sequence: Some(1),
            index: Some(tentative_index),
        };

        let payload = match serde_json::to_vec(&msg) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    "❌ Failed to serialize peer discovery announcement for {}: {}",
                    peer_id, err
                );
                return Err(anyhow!(err));
            }
        };

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
                if let Err(retry_e) = self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await {
                    warn!("❌ Retry failed to broadcast peer discovery: {:?}", retry_e);
                }
            }
        }

        // Check if peer already exists in node manager
        let current_nodes = self.node_manager.get_active_nodes();
        if current_nodes.contains(&peer_id) {
            info!(
                "ℹ️ Peer {} already exists in node manager, skipping",
                peer_id
            );
        } else {
            self.node_manager
                .add_node(peer_id)
                .map_err(|e| anyhow::anyhow!(e))?;

            // Do NOT update signing threshold after initial DKG is complete
            // Threshold is fixed based on initial DKG participants only
            let initial_dkg_complete = if let Some(dkg_node) = &self.dkg_node {
                dkg_node.is_initial_dkg_complete().await
            } else {
                false
            };
            if let Some(arc) = &self.signing_node {
                let mut signing_node = arc.lock().await;

                let new_node_count = self.node_manager.get_active_nodes().len();

                if !initial_dkg_complete {
                    // Before DKG completion: only update total_nodes counter.
                    // Do NOT trigger nonce generation or stale deletion yet —
                    // dkg_signer_count is still unknown and nonces created now
                    // would have inconsistent contributor counts across nodes.
                    signing_node.update_nonce_manager_total_nodes(new_node_count).await;
                    info!("⏳ [NONCE] Updated total_nodes={} (nonce generation deferred until DKG complete)", new_node_count);

                    // If DKG signer count is already known (observer received it from PeerList),
                    // use it for threshold instead of total_nodes to prevent inflation
                    let effective_threshold = if let Some(dkg_node) = &self.dkg_node {
                        if let Some(dkg_count) = dkg_node.get_dkg_signer_count() {
                            let t = dkg_count / 2 + 1;
                            info!("🔄 [THRESHOLD] Using DKG-based threshold {} (from {} DKG signers)", t, dkg_count);
                            t
                        } else {
                            self.node_manager.get_threshold()
                        }
                    } else {
                        self.node_manager.get_threshold()
                    };
                    signing_node.set_threshold(effective_threshold);
                    info!("🔄 [THRESHOLD] Updated signing node threshold to {} after peer addition", effective_threshold);
                } else {
                    // After DKG completion: safe to delete stale nonces and regenerate.
                    // handle_nonce_manager_node_joined does three things:
                    // 1. Updates total_nodes so nonce generation waits for all nodes
                    // 2. Deletes stale nonces (created with fewer nodes than current count)
                    // 3. Triggers immediate nonce regeneration with all nodes
                    signing_node.handle_nonce_manager_node_joined(new_node_count).await;
                    info!("🔢 [NONCE] Refreshed NonceManager after peer addition (total_nodes={})", new_node_count);
                    info!("ℹ️ [THRESHOLD] Keeping signing threshold unchanged - new node joined after initial DKG (observer only)");
                }
            }
        }

        Ok(())
    }
}
