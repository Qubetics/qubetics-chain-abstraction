use anyhow::{anyhow, Result};
use libp2p::PeerId;
use std::time::Duration;
use tracing::{info, warn};

use crate::database::keys;
use crate::protocols::DKGStatus;
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

        // Remove from database as well
        let peer_index_key = format!("{}{}", keys::PEER_INDEX, peer_id);
        if let Err(e) = self.db.delete_string(&peer_index_key) {
            warn!(
                "⚠️ [DISCONNECT] Failed to remove peer {} from database: {}",
                peer_id, e
            );
        } else {
            info!("✅ [DISCONNECT] Removed peer {} from database", peer_id);
        }

        // Update network parameters
        let new_total = self.node_manager.get_total_nodes();
        let new_threshold = self.node_manager.get_threshold();

        info!(
            "📊 [DISCONNECT] Updated network: total_nodes={}, threshold={}",
            new_total, new_threshold
        );

        // Update DKG and signing node parameters
        if let Some(dkg_node) = &mut self.dkg_node {
            if let Err(e) = dkg_node.update_node_params(new_total, new_threshold) {
                warn!("⚠️ [DISCONNECT] Failed to update DKG params: {}", e);
            }
        }

        if let Some(signing_node) = &mut self.signing_node {
            signing_node.set_threshold(new_threshold);
        }

        // Execute proactive resharing
        info!(
            "🔄 [DISCONNECT] Triggering proactive resharing with {} remaining nodes",
            new_total
        );

        if let Some(dkg_node) = &mut self.dkg_node {
            let dkg_status = dkg_node.get_status();
            if matches!(dkg_status, DKGStatus::Completed) {
                // Add delay to ensure all nodes have processed the broadcast
                info!("⏰ [DISCONNECT] Waiting 3 seconds for all nodes to sync...");
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                info!("✅ [DISCONNECT] Sync period complete, starting resharing");

                if let Err(e) = dkg_node
                    .execute_polynomial_refresh(self.node_manager.clone())
                    .await
                {
                    tracing::error!("❌ [DISCONNECT] Failed to execute resharing: {}", e);
                } else {
                    info!("✅ [DISCONNECT] Resharing completed successfully");
                }
            } else {
                warn!("⚠️ [DISCONNECT] DKG not completed yet, skipping resharing");
            }
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

            // Update signing node threshold after adding peer
            if let Some(signing_node) = &mut self.signing_node {
                let new_threshold = self.node_manager.get_threshold();
                signing_node.set_threshold(new_threshold);
                info!("🔄 [THRESHOLD] Updated signing node threshold to {} after Kademlia peer addition", new_threshold);
            }
        }

        Ok(())
    }
}
