use anyhow::Result;
use libp2p::PeerId;
use tracing::{error, info, warn};

use crate::database::primitives::keys;
use crate::types::p2p::SerializablePeerId;
use crate::types::rpc::RPCRequest;
use crate::types::user_intent::{AdminRegistration, UserRegistration};
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

    /// Handle a batch of database entries (DB_SYNC path — only USER_REGISTRATION entries).
    /// Applies the same merge logic as STATE_SYNC: never overwrite existing users
    /// that already have a valid tweaked_secret_share.
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

        // DB_SYNC exports USER_REGISTRATION entries which may contain the exporting
        // node's tweaked_secret_share (unlike STATE_SYNC which strips it).
        // We must merge carefully: never overwrite a local user that already has a valid share.
        let mut import_entries = Vec::new();
        let mut skipped = 0usize;
        for entry in entries {
            let key_str = String::from_utf8_lossy(&entry.key).to_string();
            match self.db.get_string::<UserRegistration>(&key_str) {
                Ok(Some(existing_user)) if existing_user.tweaked_secret_share.is_some() => {
                    // Local user has valid tweaked share — SKIP to preserve it
                    info!(
                        "🛡️ [DB_SYNC] Preserving existing user {} (has valid tweaked_secret_share)",
                        key_str
                    );
                    skipped += 1;
                }
                _ => {
                    // Strip tweaked_secret_share from incoming entry (it belongs to the exporting node)
                    match bincode::deserialize::<UserRegistration>(&entry.value) {
                        Ok(mut incoming_user) => {
                            incoming_user.tweaked_secret_share = None;
                            if let Ok(stripped_bytes) = bincode::serialize(&incoming_user) {
                                import_entries.push((entry.key, stripped_bytes));
                            } else {
                                import_entries.push((entry.key, entry.value));
                            }
                        }
                        Err(_) => {
                            import_entries.push((entry.key, entry.value));
                        }
                    }
                }
            }
        }

        if skipped > 0 {
            info!(
                "🛡️ [DB_SYNC] Preserved {} existing user(s) with valid tweaked shares",
                skipped
            );
        }

        if !import_entries.is_empty() {
            self.db.import_batch_async(import_entries).await?;
        }

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

            // Compute tweaked shares for newly imported users (those with None).
            if let Some(ref uim) = self.user_intent_manager {
                match uim.refresh_missing_user_tweaked_shares().await {
                    Ok(count) => {
                        if count > 0 {
                            info!("✅ [DB_SYNC] Computed tweaked shares for {} new user(s)", count);
                        }
                    }
                    Err(e) => warn!("⚠️ [DB_SYNC] Failed to compute tweaked shares: {}", e),
                }
                // Compute tweaked shares for newly imported admins (those with None).
                match uim.refresh_missing_admin_tweaked_shares().await {
                    Ok(count) => {
                        if count > 0 {
                            info!("✅ [DB_SYNC] Computed tweaked shares for {} new admin(s)", count);
                        }
                    }
                    Err(e) => warn!("⚠️ [DB_SYNC] Failed to compute admin tweaked shares: {}", e),
                }
            }

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

        // Purge stale pending entries before importing fresh state from peer.
        // Only transient/pending prefixes are purged — static data (users, intents, DKG) is additive.
        let pending_prefixes = [
            keys::PENDING_TRANSACTION,
            keys::PENDING_DISCONNECTION,
            keys::DISCONNECTION_STAGING,
            keys::PENDING_WITHDRAW_LIQUIDITY,
            keys::PENDING_CLAIM_REWARD,
            keys::SOLVER_ADD_LIQUIDITY,
        ];
        for prefix in &pending_prefixes {
            match self.db.delete_keys_with_prefix_async(prefix).await {
                Ok(count) if count > 0 => {
                    info!("🗑️ [STATE_SYNC] Purged {} stale entries for prefix {}", count, prefix);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("⚠️ [STATE_SYNC] Failed to purge prefix {}: {}", prefix, e);
                }
            }
        }

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
    /// For USER_REGISTRATION entries: only import users that don't already exist locally
    /// (preserves existing tweaked_secret_share from original DKG signing).
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

        if prefix == keys::USER_REGISTRATION {
            // For user entries: merge — only import NEW users, never overwrite existing ones.
            // Existing users already have the correct tweaked_secret_share computed from
            // the original DKG; overwriting would destroy it (peer strips tweaked_secret_share).
            let mut new_entries = Vec::new();
            let mut skipped = 0usize;
            for entry in entries {
                let key_str = String::from_utf8_lossy(&entry.key).to_string();
                // Check if this user already exists locally with a valid tweaked share
                match self.db.get_string::<UserRegistration>(&key_str) {
                    Ok(Some(existing_user)) if existing_user.tweaked_secret_share.is_some() => {
                        // Local user has valid tweaked share — SKIP import to preserve it
                        info!(
                            "🛡️ [STATE_SYNC] Preserving existing user {} (has valid tweaked_secret_share)",
                            key_str
                        );
                        skipped += 1;

                        // Merge intent_hashes from the peer: add new intents AND update
                        // statuses of existing ones so restarted nodes converge to the
                        // network's current state. Solved is terminal — never overwrite it.
                        match bincode::deserialize::<UserRegistration>(&entry.value) {
                            Ok(incoming_user) => {
                                let mut merged_user = existing_user;
                                let mut intents_added = 0usize;
                                let mut intents_updated = 0usize;
                                for (hash, peer_status) in incoming_user.intent_hashes {
                                    use crate::types::user_intent::IntentStatus;
                                    match merged_user.intent_hashes.get(&hash) {
                                        None => {
                                            // New intent not yet known locally — add it
                                            merged_user.intent_hashes.insert(hash, peer_status);
                                            intents_added += 1;
                                        }
                                        Some(IntentStatus::Solved) => {
                                            // Solved is terminal — never overwrite
                                        }
                                        Some(local_status) if *local_status != peer_status => {
                                            // Peer has a different (fresher) status — converge to it
                                            merged_user.intent_hashes.insert(hash, peer_status);
                                            intents_updated += 1;
                                        }
                                        _ => {} // Same status — nothing to do
                                    }
                                }
                                if intents_added > 0 || intents_updated > 0 {
                                    info!(
                                        "📋 [STATE_SYNC] Merged intent(s) for existing user {}: {} added, {} status-updated",
                                        key_str, intents_added, intents_updated
                                    );
                                    if let Ok(merged_bytes) = bincode::serialize(&merged_user) {
                                        new_entries.push((entry.key, merged_bytes));
                                        skipped -= 1; // This user will be written (merged, not skipped)
                                    }
                                }
                            }
                            Err(e) => {
                                error!("❌ [STATE_SYNC] Failed to deserialize incoming user {}: {}", key_str, e);
                            }
                        }
                    }
                    _ => {
                        // User doesn't exist locally or has no tweaked share — import from peer
                        info!("📥 [STATE_SYNC] Importing user {} (new or missing tweaked share)", key_str);
                        new_entries.push((entry.key, entry.value));
                    }
                }
            }

            if skipped > 0 {
                info!(
                    "🛡️ [STATE_SYNC] Preserved {} existing user(s) with valid tweaked shares",
                    skipped
                );
            }

            if !new_entries.is_empty() {
                self.db.import_batch_async(new_entries).await?;
            }
        } else if prefix == keys::ADMIN_REGISTRATION {
            // For admin entries: merge — only import NEW admins, never overwrite existing ones.
            // Existing admins already have the correct tweaked_secret_share computed from
            // the original DKG; overwriting would destroy it (peer strips tweaked_secret_share).
            let mut new_entries = Vec::new();
            let mut skipped = 0usize;
            for entry in entries {
                let key_str = String::from_utf8_lossy(&entry.key).to_string();
                match self.db.get_string::<AdminRegistration>(&key_str) {
                    Ok(Some(existing_admin)) if existing_admin.tweaked_secret_share.is_some() => {
                        info!(
                            "🛡️ [STATE_SYNC] Preserving existing admin {} (has valid tweaked_secret_share)",
                            key_str
                        );
                        skipped += 1;
                    }
                    _ => {
                        info!("📥 [STATE_SYNC] Importing admin {} (new or missing tweaked share)", key_str);
                        new_entries.push((entry.key, entry.value));
                    }
                }
            }

            if skipped > 0 {
                info!(
                    "🛡️ [STATE_SYNC] Preserved {} existing admin(s) with valid tweaked shares",
                    skipped
                );
            }

            if !new_entries.is_empty() {
                self.db.import_batch_async(new_entries).await?;
            }
        } else {
            // Non-user/admin entries: import as-is (blind overwrite is fine)
            let db_entries: Vec<(Vec<u8>, Vec<u8>)> =
                entries.into_iter().map(|e| (e.key, e.value)).collect();
            if !db_entries.is_empty() {
                self.db.import_batch_async(db_entries).await?;
            }
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

        // Compute tweaked_secret_share ONLY for newly imported users (those with None).
        // Existing users already have valid tweaked shares preserved during merge above.
        if let Some(ref uim) = self.user_intent_manager {
            match uim.refresh_missing_user_tweaked_shares().await {
                Ok(count) => {
                    if count > 0 {
                        info!("✅ [STATE_SYNC] Computed tweaked shares for {} new user(s) after sync", count);
                    } else {
                        info!("✅ [STATE_SYNC] No new users need tweaked share computation");
                    }
                }
                Err(e) => warn!("⚠️ [STATE_SYNC] Failed to compute tweaked shares for new users: {}", e),
            }
            // Compute tweaked shares for newly imported admins (those with None).
            match uim.refresh_missing_admin_tweaked_shares().await {
                Ok(count) => {
                    if count > 0 {
                        info!("✅ [STATE_SYNC] Computed tweaked shares for {} new admin(s) after sync", count);
                    } else {
                        info!("✅ [STATE_SYNC] No new admins need tweaked share computation");
                    }
                }
                Err(e) => warn!("⚠️ [STATE_SYNC] Failed to compute tweaked shares for new admins: {}", e),
            }
        }

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

    /// Clear stale in-memory pending state and apply fresh state from peer.
    async fn apply_synced_pending_rounds(&mut self) {
        let (wr, cr) = (
            self.state_sync_state.withdraw_rounds.clone(),
            self.state_sync_state.claim_reward_rounds.clone(),
        );
        let peer_inv = self.state_sync_state.peer_invalidation_pending.clone();

        if let Some(arc) = &self.signing_node {
            let node = arc.lock().await;
            // Clear stale rounds first, then apply fresh state from peer
            node.clear_and_apply_synced_pending_rounds(&wr, &cr).await;
            info!(
                "✅ [STATE_SYNC] Cleared and applied {} withdraw_rounds and {} claim_reward_rounds to PendingStore",
                wr.len(),
                cr.len()
            );
        } else if !wr.is_empty() || !cr.is_empty() {
            warn!("⚠️ [STATE_SYNC] No signing_node; skipped applying pending rounds");
        }

        // Clear stale peer_invalidation_pending, then apply fresh state from peer
        {
            let mut pending = self.peer_invalidation_pending.lock().await;
            pending.clear();
            for (round, solver_ids) in peer_inv {
                pending.insert(round, solver_ids);
            }
        }
        info!(
            "✅ [STATE_SYNC] Cleared and applied {} peer_invalidation_pending entries",
            self.state_sync_state.peer_invalidation_pending.len()
        );
    }
}
