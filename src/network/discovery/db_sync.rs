use anyhow::Result;
use libp2p::PeerId;
use tracing::{info, warn};

use crate::types::p2p::SerializablePeerId;
use crate::types::rpc::RPCRequest;
use crate::types::vrf::VrfRoundSyncRequest;

use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer, VrfDomain};

impl MpcNetworkLayer {
    /// Sync database from an existing peer when joining the network
    /// This method should be called by new nodes after connecting to the network
    pub async fn sync_database_from_peer(
        &self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
    ) -> Result<()> {
        info!("📦 [DB_SYNC] Starting database sync from peer {}", peer_id);

        // Step 1: Request database metadata
        let request = RPCRequest::RequestDatabaseSync {
            requester_id: SerializablePeerId(self.local_peer_id),
        };

        let request_id = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request);

        info!(
            "📦 [DB_SYNC] Sent sync metadata request (ID: {:?})",
            request_id
        );

        // Note: The actual response handling happens in the swarm event loop
        // We need to handle DatabaseSyncMetadata and DatabaseBatch responses there
        Ok(())
    }

    /// Handle database sync metadata response and start batch requests
    pub async fn handle_database_sync_metadata(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        total_entries: usize,
        batch_size: usize,
    ) -> Result<()> {
        if total_entries == 0 {
            info!("📦 [DB_SYNC] Peer has no data to sync");
            return Ok(());
        }

        // Initialize sync state
        self.db_sync_state
            .start_sync(peer_id, total_entries, batch_size);

        let total_batches = total_entries.div_ceil(batch_size);
        info!(
            "📦 [DB_SYNC] Starting batch sync: {} entries in {} batches from peer {}",
            total_entries, total_batches, peer_id
        );
        info!("📊 [DB_SYNC] Progress: 0/{} entries (0.00%)", total_entries);

        // Request first batch - subsequent batches will be requested after receiving responses
        let request = RPCRequest::RequestDatabaseBatch {
            batch_index: 0,
            batch_size,
        };

        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request);

        info!("📦 [DB_SYNC] Requested batch 0/{}", total_batches - 1);
        Ok(())
    }

    /// Handle a batch of database entries
    pub async fn handle_database_batch(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        batch_index: usize,
        entries: Vec<crate::types::rpc::DatabaseEntry>,
        is_last_batch: bool,
        batch_size: usize,
    ) -> Result<()> {
        let entries_count = entries.len();

        info!(
            "📦 [DB_SYNC] Received batch {} with {} entries (last: {})",
            batch_index, entries_count, is_last_batch
        );

        // Convert entries to tuple format
        let db_entries: Vec<(Vec<u8>, Vec<u8>)> =
            entries.into_iter().map(|e| (e.key, e.value)).collect();

        // Import batch into database
        self.db.import_batch_async(db_entries).await?;

        // Update sync state
        self.db_sync_state.complete_batch(entries_count);

        let progress = self.db_sync_state.progress_percentage();
        info!(
            "✅ [DB_SYNC] Successfully imported batch {} - Progress: {}/{} entries ({:.2}%)",
            batch_index,
            self.db_sync_state.entries_synced,
            self.db_sync_state.total_entries,
            progress
        );

        // Request next batch if not last
        if !is_last_batch {
            let request = RPCRequest::RequestDatabaseBatch {
                batch_index: batch_index + 1,
                batch_size,
            };

            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);

            info!(
                "📦 [DB_SYNC] Requested batch {}/{} from peer {}",
                batch_index + 1,
                self.db_sync_state.total_batches - 1,
                peer_id
            );
        } else {
            // Finish sync
            self.db_sync_state.finish_sync();
            info!("🎉 [DB_SYNC] Database synchronization completed!");
            info!(
                "📊 [DB_SYNC] Total synced: {} entries from peer {}",
                self.db_sync_state.entries_synced, peer_id
            );

            // Request round sync after database sync completes
            if !self.vrf_round_requested {
                info!(
                    "🔄 [SYNC] Requesting current round from peer {}",
                    peer_id
                );
                let current_round = self
                    .get_local_vrf_round_for_domain(VrfDomain::Signing, None)
                    .await;
                swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    RPCRequest::VrfRoundSync(VrfRoundSyncRequest {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round,
                        context: String::new(),
                    }),
                );
                self.vrf_round_requested = true;
                info!("✅ [SYNC] Round request sent to peer {}", peer_id);
            }
        }

        Ok(())
    }

    /// Start state sync from a peer (users without shares, intents, pending tx, rounds).
    pub async fn sync_state_sync_from_peer(
        &self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
    ) -> Result<()> {
        info!("📦 [STATE_SYNC] Starting state sync from peer {}", peer_id);

        let request = RPCRequest::RequestStateSync {
            requester_id: SerializablePeerId(self.local_peer_id),
        };

        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request);

        info!("📦 [STATE_SYNC] Sent state sync metadata request");
        Ok(())
    }

    /// Handle state sync metadata and request first batch for first non-empty prefix.
    pub async fn handle_state_sync_metadata(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        prefix_counts: Vec<(String, usize)>,
        withdraw_rounds: Vec<u64>,
        claim_reward_rounds: Vec<u64>,
        peer_invalidation_pending: Vec<(String, Vec<String>)>,
    ) -> Result<()> {
        let batch_size = 100;
        let non_empty: Vec<(String, usize)> = prefix_counts
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .collect();

        if non_empty.is_empty()
            && withdraw_rounds.is_empty()
            && claim_reward_rounds.is_empty()
            && peer_invalidation_pending.is_empty()
        {
            info!("📦 [STATE_SYNC] Peer has no state to sync");
            return Ok(());
        }

        self.state_sync_state.start_sync(
            peer_id,
            non_empty.clone(),
            batch_size,
            withdraw_rounds,
            claim_reward_rounds,
            peer_invalidation_pending,
        );

        info!(
            "📦 [STATE_SYNC] Starting sync: {} prefix(s) from peer {}",
            non_empty.len(),
            peer_id
        );

        if let Some((prefix, _)) = self.state_sync_state.current_prefix() {
            let request = RPCRequest::RequestStateSyncBatch {
                prefix: prefix.clone(),
                batch_index: 0,
                batch_size,
            };
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);
            info!("📦 [STATE_SYNC] Requested batch 0 for prefix {}", prefix);
        } else {
            self.apply_synced_pending_rounds().await;
            self.state_sync_state.finish_sync();
            info!("🎉 [STATE_SYNC] No prefixes to sync; applied pending rounds only");
        }

        Ok(())
    }

    /// Handle a state sync batch: import, then request next batch or next prefix or finish.
    pub async fn handle_state_sync_batch(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        prefix: String,
        batch_index: usize,
        entries: Vec<crate::types::rpc::DatabaseEntry>,
        is_last_batch: bool,
    ) -> Result<()> {
        let count = entries.len();
        let db_entries: Vec<(Vec<u8>, Vec<u8>)> =
            entries.into_iter().map(|e| (e.key, e.value)).collect();

        if !db_entries.is_empty() {
            self.db.import_batch_async(db_entries).await?;
        }

        self.state_sync_state.complete_batch(count);

        info!(
            "✅ [STATE_SYNC] Imported batch {} for prefix {} ({} entries)",
            batch_index, prefix, count
        );

        if !is_last_batch {
            let request = RPCRequest::RequestStateSyncBatch {
                prefix: prefix.clone(),
                batch_index: batch_index + 1,
                batch_size: self.state_sync_state.batch_size,
            };
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);
            return Ok(());
        }

        self.state_sync_state.next_prefix();

        if let Some((next_prefix, _)) = self.state_sync_state.current_prefix() {
            let request = RPCRequest::RequestStateSyncBatch {
                prefix: next_prefix.clone(),
                batch_index: 0,
                batch_size: self.state_sync_state.batch_size,
            };
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);
            info!("📦 [STATE_SYNC] Requested batch 0 for next prefix {}", next_prefix);
            return Ok(());
        }

        self.apply_synced_pending_rounds().await;
        self.state_sync_state.finish_sync();
        info!(
            "🎉 [STATE_SYNC] State sync completed! Total entries synced: {}",
            self.state_sync_state.entries_synced
        );

        if !self.vrf_round_requested {
            let current_round = self
                .get_local_vrf_round_for_domain(VrfDomain::Signing, None)
                .await;
            swarm.behaviour_mut().request_response.send_request(
                &peer_id,
                RPCRequest::VrfRoundSync(VrfRoundSyncRequest {
                    from: SerializablePeerId(self.local_peer_id),
                    current_round,
                    context: String::new(),
                }),
            );
            self.vrf_round_requested = true;
        }

        Ok(())
    }

    /// Apply synced withdraw_rounds, claim_reward_rounds, and peer_invalidation_pending.
    async fn apply_synced_pending_rounds(&mut self) {
        let (wr, cr) = (
            self.state_sync_state.withdraw_rounds.clone(),
            self.state_sync_state.claim_reward_rounds.clone(),
        );
        let peer_inv = self.state_sync_state.peer_invalidation_pending.clone();

        if let Some(arc) = &self.signing_node {
            let node = arc.lock().await;
            node.apply_synced_pending_rounds(&wr, &cr).await;
            info!(
                "✅ [STATE_SYNC] Applied {} withdraw_rounds and {} claim_reward_rounds to PendingStore",
                wr.len(),
                cr.len()
            );
        } else if !wr.is_empty() || !cr.is_empty() {
            warn!("⚠️ [STATE_SYNC] No signing_node; skipped applying pending rounds");
        }

        if !peer_inv.is_empty() {
            let mut pending = self.peer_invalidation_pending.lock().await;
            for (round, solver_ids) in peer_inv {
                pending.insert(round, solver_ids);
            }
            info!(
                "✅ [STATE_SYNC] Applied {} peer_invalidation_pending entries",
                self.state_sync_state.peer_invalidation_pending.len()
            );
        }
    }
}
