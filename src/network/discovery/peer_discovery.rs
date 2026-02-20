use anyhow::Result;
use libp2p::PeerId;
use std::time::Duration;
use tracing::{info, warn};

use crate::database::{key_utils, keys};
use crate::types::dkg::MSG_TOPIC_PEER_DISCOVERY;
use crate::types::{ChannelMessage, GossipsubMessage};

use crate::network::transport::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Get maximum peer index from database
    pub(crate) fn get_max_peer_index_from_db(&self) -> usize {
        if let Ok(keys) = self
            .db
            .get_keys_with_prefix(crate::database::keys::PEER_INDEX)
        {
            let mut max_idx = 0usize;
            for k in keys {
                if let Ok(Some(idx)) = self.db.get_string::<usize>(&k) {
                    if idx > max_idx {
                        max_idx = idx;
                    }
                }
            }
            max_idx
        } else {
            0
        }
    }

    /// Get peer index from database
    pub(crate) fn get_index_from_db(&self, pid: &PeerId) -> Option<usize> {
        let key = crate::database::key_utils::peer_index_key(&pid.to_string());
        self.db.get_string::<usize>(&key).ok().flatten()
    }

    /// Async-safe helper for loading peer indices without blocking the Tokio runtime.
    pub(crate) async fn get_index_from_db_async(&self, pid: &PeerId) -> Option<usize> {
        let key = crate::database::key_utils::peer_index_key(&pid.to_string());
        self.db.get_string_async::<usize>(&key).await.ok().flatten()
    }

    /// Assign and persist peer index
    pub(crate) fn assign_and_persist_index(&mut self, pid: &PeerId) -> usize {
        if let Some(idx) = self.get_index_from_db(pid) {
            // Restore in-memory mapping (may have been removed on disconnect)
            self.peer_discovery.peer_indices.insert(*pid, idx);
            return idx;
        }
        // Determine next index strictly from DB state
        let next = self.get_max_peer_index_from_db().saturating_add(1);
        let key = crate::database::key_utils::peer_index_key(&pid.to_string());
        if let Err(e) = self.db.put_string(&key, &next) {
            warn!("Failed to persist peer index: {:?}", e);
        }
        self.peer_discovery.peer_indices.insert(*pid, next);
        next
    }

    /// Ensure local peer has an assigned index
    pub(crate) fn ensure_local_index(&mut self) -> usize {
        if let Some(idx) = self.get_index_from_db(&self.local_peer_id) {
            self.peer_discovery
                .peer_indices
                .insert(self.local_peer_id, idx);
            return idx;
        }
        // If no peers indexed yet, start at 1; otherwise next max+1
        let current_max = self.get_max_peer_index_from_db();
        let idx = if current_max == 0 { 1 } else { current_max + 1 };
        let key = crate::database::key_utils::peer_index_key(&self.local_peer_id.to_string());
        if let Err(e) = self.db.put_string(&key, &idx) {
            warn!("Failed to persist local index: {:?}", e);
        }
        self.peer_discovery
            .peer_indices
            .insert(self.local_peer_id, idx);
        idx
    }

    /// Check if there are additional peers beyond local peer
    pub(crate) fn has_additional_peers(&self) -> bool {
        let local = self.get_local_peer_id();
        if self
            .node_manager
            .get_active_nodes()
            .iter()
            .any(|pid| pid != local)
        {
            return true;
        }

        if let Ok(keys) = self.db.get_keys_with_prefix(keys::PEER_INDEX) {
            for k in keys {
                if let Some(peer_str) = k.strip_prefix(keys::PEER_INDEX) {
                    if let Ok(pid) = peer_str.parse::<PeerId>() {
                        if &pid != local {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Schedule a peer discovery retry attempt
    pub(crate) fn schedule_peer_discovery_retry(&mut self, attempt: u8) {
        if attempt > Self::MAX_PEER_DISCOVERY_RETRIES {
            warn!(
                "⚠️ Maximum peer discovery retry attempts ({}) reached; giving up for now",
                Self::MAX_PEER_DISCOVERY_RETRIES
            );
            self.peer_discovery.pending_peer_discovery_retry = false;
            return;
        }

        if self.peer_discovery.pending_peer_discovery_retry {
            info!(
                "⏳ Peer discovery retry already scheduled (attempt {})",
                attempt
            );
            return;
        }

        self.peer_discovery.pending_peer_discovery_retry = true;
        info!(
            "⏱️ Scheduling peer discovery retry attempt {} in 1 second",
            attempt
        );
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(e) = tx
                .send(ChannelMessage::PeerDiscoveryRetry { attempt })
                .await
            {
                warn!(
                    "Failed to enqueue peer discovery retry (attempt {}): {:?}",
                    attempt, e
                );
            }
        });
    }

    /// Broadcast local node presence to the network
    pub(crate) async fn broadcast_local_presence(&mut self) -> Result<()> {
        let my_index = self
            .peer_discovery
            .peer_indices
            .get(&self.local_peer_id)
            .cloned()
            .unwrap_or_else(|| self.node_manager.get_total_nodes());

        if let Some(idx) = self
            .peer_discovery
            .peer_indices
            .get(&self.local_peer_id)
            .cloned()
        {
            let key = key_utils::peer_index_key(&self.local_peer_id.to_string());
            if let Err(e) = self.db.put_string_async(&key, &idx).await {
                warn!("Failed to persist my index: {:?}", e);
            }
        }

        let msg = GossipsubMessage::PeerDiscovered {
            peer: self.local_peer_id,
            sequence: Some(1),
            index: Some(my_index),
        };

        match serde_json::to_vec(&msg) {
            Ok(payload) => {
                if let Err(e) = self.broadcast(MSG_TOPIC_PEER_DISCOVERY, &payload).await {
                    warn!(
                        "Failed to broadcast presence during peer discovery retry handling: {:?}",
                        e
                    );
                }
            }
            Err(e) => {
                warn!("Failed to serialize peer discovery message: {:?}", e);
            }
        }

        Ok(())
    }

    /// Check if a peer is a bootstrap node
    pub(crate) fn is_bootstrap_node(&self, peer_id: &PeerId) -> bool {
        self.bootstrap_peer_ids
            .iter()
            .any(|bootstrap_id| bootstrap_id == peer_id)
    }
}
