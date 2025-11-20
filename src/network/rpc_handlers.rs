/// RPC Request/Response handlers
/// This module contains all the RPC request and response handling logic
use anyhow::Result;
use libp2p::PeerId;
use tracing::{error, info, warn};

use crate::database::key_utils;
use crate::threshold_dkg::DKGStatus;
use crate::types::p2p::SerializablePeerId;
use crate::types::rpc::{RPCRequest, RPCResponse};
use crate::types::PeerInfo;

use super::types::{MpcNetworkBehaviour, MpcNetworkLayer};

impl MpcNetworkLayer {
    /// Handle RPC requests from peers
    pub(crate) async fn handle_rpc_request(
        &mut self,
        peer: PeerId,
        request: RPCRequest,
    ) -> RPCResponse {
        match request {
            RPCRequest::GetPeerList => self.handle_get_peer_list_request(peer).await,
            RPCRequest::Ping => RPCResponse::Pong,
            RPCRequest::GetPeerInfo => RPCResponse::PeerInfo(PeerInfo {
                addresses: vec![],
                connected: true,
            }),
            RPCRequest::Custom { id, data } => RPCResponse::Custom { id, data },
            RPCRequest::StartADKG => self.handle_start_adkg_request(peer).await,
            RPCRequest::GetDKGStatus => self.handle_get_dkg_status_request().await,
            RPCRequest::SendAVSSShare {
                share,
                commitments,
                receiver_id,
                ..
            } => {
                self.handle_send_avss_share_request(share, commitments, receiver_id)
                    .await
            }
            RPCRequest::ScheduleADKG { start_time } => {
                info!("🕒 Got DKGStartAt({})", start_time);
                self.schedule_dkg_at(start_time);
                RPCResponse::Ack
            }
            RPCRequest::RequestCurrentVrfRound => self.handle_request_current_vrf_round(peer).await,
            RPCRequest::RequestDatabaseSync { requester_id } => {
                self.handle_request_database_sync(peer, requester_id).await
            }
            RPCRequest::RequestDatabaseBatch {
                batch_index,
                batch_size,
            } => {
                self.handle_request_database_batch(peer, batch_index, batch_size)
                    .await
            }
            _ => RPCResponse::Ack,
        }
    }

    /// Handle GetPeerList RPC request
    async fn handle_get_peer_list_request(&mut self, peer: PeerId) -> RPCResponse {
        info!("🔄 GetPeerList RPC received from {}", peer);

        // Gather everyone we know
        let peers: Vec<SerializablePeerId> = self
            .node_manager
            .get_active_nodes()
            .into_iter()
            .map(SerializablePeerId)
            .collect();

        // 🔧 FIX: Update peer_indices mapping for all peers before sending
        // This ensures peer_indices stays in sync with the database
        for SerializablePeerId(pid) in &peers {
            if !self.peer_discovery.peer_indices.contains_key(pid) {
                // Load from database if not in peer_indices
                if let Some(db_idx) = self.get_index_from_db_async(pid).await {
                    info!(
                        "🔢 [PEER_LIST_SEND] Loaded index {} for peer {} from database",
                        db_idx, pid
                    );
                    self.peer_discovery.peer_indices.insert(pid.clone(), db_idx);
                }
            }
        }

        // Map indices in the same order, also load from DB if not in-memory
        let mut indices: Vec<Option<usize>> = Vec::with_capacity(peers.len());
        for SerializablePeerId(pid) in &peers {
            if let Some(idx) = self.peer_discovery.peer_indices.get(pid).cloned() {
                indices.push(Some(idx));
            } else {
                let key = key_utils::peer_index_key(&pid.to_string());
                match self.db.get_string_async::<usize>(&key).await {
                    Ok(Some(idx)) => {
                        // Update peer_indices with index from database
                        info!(
                            "🔢 [PEER_LIST_SEND] Loading index {} for peer {} from database",
                            idx, pid
                        );
                        self.peer_discovery.peer_indices.insert(pid.clone(), idx);
                        indices.push(Some(idx));
                    }
                    Ok(None) => indices.push(None),
                    Err(e) => {
                        warn!(
                            "❌ [PEER_LIST_SEND] Failed to load index for {}: {}",
                            pid, e
                        );
                        indices.push(None);
                    }
                }
            }
        }

        // Log how many peers we're returning
        info!(
            "📋 Sending PeerList response to {}: {} entries: {:?} {:?}",
            peer,
            peers.len(),
            peers,
            indices
        );

        RPCResponse::PeerList { peers, indices }
    }

    /// Handle StartADKG RPC request
    async fn handle_start_adkg_request(&mut self, peer: PeerId) -> RPCResponse {
        match self.dkg_node.as_mut() {
            Some(dkg) => {
                info!("🚀 Received DKG start request from peer {}", peer);

                // Update DKG parameters with current network state
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();
                dkg.update_node_params(total, threshold);
                dkg.reset().await;
                if let Some(signing_node) = &mut self.signing_node {
                    signing_node.set_threshold(self.node_manager.get_total_nodes() - 1);
                }
                self.node_manager.set_threshold(total - 1);
                info!(
                    "🔄 DKG parameters updated: total_nodes={}, threshold={}",
                    total, threshold
                );

                match dkg.start_dkg(self.node_manager.clone()).await {
                    Ok(_) => {
                        info!("✅ Successfully started DKG in response to peer request");
                        RPCResponse::DKGStarted {
                            peer_id: SerializablePeerId(peer),
                        }
                    }
                    Err(e) => {
                        warn!("❌ Failed to start DKG: {:?}", e);
                        RPCResponse::DKGError(format!("Failed to start DKG: {:?}", e))
                    }
                }
            }
            None => {
                warn!("❌ DKG node not initialized");
                RPCResponse::DKGError("DKG is not initialized.".to_string())
            }
        }
    }

    /// Handle GetDKGStatus RPC request
    async fn handle_get_dkg_status_request(&self) -> RPCResponse {
        let status = self
            .dkg_node
            .as_ref()
            .map(|dkg| dkg.get_status())
            .unwrap_or(DKGStatus::New);

        RPCResponse::DKGStatus { status }
    }

    /// Handle SendAVSSShare RPC request
    async fn handle_send_avss_share_request(
        &self,
        share: crate::types::secp::SerializableScalar,
        commitments: Vec<crate::types::secp::SerializablePoint>,
        receiver_id: SerializablePeerId,
    ) -> RPCResponse {
        if self.dkg_node.is_none() {
            return RPCResponse::Error("DKG not initialized".to_string());
        }

        // Extract share index from receiver_id
        let share_index = if let Ok(index) = receiver_id.0.to_string().parse::<usize>() {
            index
        } else {
            // Fallback to hash-based index
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            receiver_id.0.to_string().hash(&mut hasher);
            let hash = hasher.finish();
            ((hash % 100) + 1) as usize // Use a reasonable default range
        };

        if self
            .dkg_node
            .as_ref()
            .unwrap()
            .verify_share(&share, share_index, &commitments)
        {
            RPCResponse::ShareAccepted
        } else {
            RPCResponse::Error("Invalid share".into())
        }
    }

    /// Handle RequestCurrentVrfRound RPC request
    async fn handle_request_current_vrf_round(&self, peer: PeerId) -> RPCResponse {
        info!(
            "🔄 Received request for current VRF round from peer {}",
            peer
        );
        let mut current_round = None;

        // Check signing_node first
        if let Some(signing_node) = &self.signing_node {
            if let Some(vrf_service) = &signing_node.vrf_service {
                current_round = Some(vrf_service.get_current_round().await);
            }
        }

        // If no round from signing_node, check db_signing_node
        if current_round.is_none() {
            if let Some(db_signing_node) = &self.db_signing_node {
                let node = db_signing_node.lock().await;
                if let Some(vrf_service) = &node.vrf_service {
                    current_round = Some(vrf_service.get_current_round().await);
                }
            }
        }

        RPCResponse::CurrentVrfRoundResponse { current_round }
    }

    /// Handle RequestDatabaseSync RPC request
    async fn handle_request_database_sync(
        &self,
        _peer: PeerId,
        requester_id: SerializablePeerId,
    ) -> RPCResponse {
        info!(
            "📦 [DB_SYNC] Received database sync request from peer: {:?}",
            requester_id
        );

        match self
            .db
            .count_entries_with_prefix_async(crate::database::keys::USER_REGISTRATION)
            .await
        {
            Ok(total_entries) => {
                let recommended_batch_size = 100; // Entries per batch
                info!(
                    "📦 [DB_SYNC] Database has {} user entries, recommending batch size of {}",
                    total_entries, recommended_batch_size
                );
                RPCResponse::DatabaseSyncMetadata {
                    total_entries,
                    recommended_batch_size,
                }
            }
            Err(e) => {
                error!("❌ [DB_SYNC] Failed to count user database entries: {}", e);
                RPCResponse::Error(format!("Failed to count user database entries: {}", e))
            }
        }
    }

    /// Handle RequestDatabaseBatch RPC request
    async fn handle_request_database_batch(
        &self,
        peer: PeerId,
        batch_index: usize,
        batch_size: usize,
    ) -> RPCResponse {
        info!(
            "📦 [DB_SYNC] Received database batch request: batch {} with size {} from peer {}",
            batch_index, batch_size, peer
        );

        match self
            .db
            .export_batch_with_prefix_async(
                crate::database::keys::USER_REGISTRATION,
                batch_index * batch_size,
                batch_size,
            )
            .await
        {
            Ok((entries, is_last_batch)) => {
                let db_entries: Vec<crate::types::rpc::DatabaseEntry> = entries
                    .into_iter()
                    .map(|(key, value)| crate::types::rpc::DatabaseEntry { key, value })
                    .collect();

                info!(
                    "📦 [DB_SYNC] Sending batch {} with {} user entries (last batch: {})",
                    batch_index,
                    db_entries.len(),
                    is_last_batch
                );

                RPCResponse::DatabaseBatch {
                    batch_index,
                    entries: db_entries,
                    is_last_batch,
                }
            }
            Err(e) => {
                error!("❌ [DB_SYNC] Failed to export batch: {}", e);
                RPCResponse::Error(format!("Failed to export batch: {}", e))
            }
        }
    }

    /// Handle RPC responses from peers
    pub(crate) async fn handle_rpc_response(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer: PeerId,
        response: RPCResponse,
    ) -> Result<()> {
        info!("📥 Got RPC response {:?} from {}", response, peer);

        match response {
            RPCResponse::PeerList { peers, indices } => {
                self.handle_peer_list_response(swarm, peers, indices)
                    .await?;
            }
            RPCResponse::GotAVSSShare { .. } => {}
            RPCResponse::DKGStarted { peer_id } => {
                info!("DKG has started by: {:?}", peer_id);
            }
            RPCResponse::Error(err) => {
                warn!("Received error from peer {}: {}", peer, err);
            }
            RPCResponse::ShareAccepted => {}
            RPCResponse::CurrentVrfRoundResponse { current_round } => {
                self.handle_current_vrf_round_response(current_round).await;
            }
            RPCResponse::DatabaseSyncMetadata {
                total_entries,
                recommended_batch_size,
            } => {
                info!(
                    "📦 [DB_SYNC] Received sync metadata: {} entries, batch size {}",
                    total_entries, recommended_batch_size
                );

                if let Err(e) = self
                    .handle_database_sync_metadata(
                        swarm,
                        peer,
                        total_entries,
                        recommended_batch_size,
                    )
                    .await
                {
                    error!("❌ [DB_SYNC] Failed to handle sync metadata: {}", e);
                }
            }
            RPCResponse::DatabaseBatch {
                batch_index,
                entries,
                is_last_batch,
            } => {
                info!(
                    "📦 [DB_SYNC] Received batch {} with {} entries",
                    batch_index,
                    entries.len()
                );

                // Use the recommended batch size from metadata (default 100)
                let batch_size = 100;

                if let Err(e) = self
                    .handle_database_batch(
                        swarm,
                        peer,
                        batch_index,
                        entries,
                        is_last_batch,
                        batch_size,
                    )
                    .await
                {
                    error!("❌ [DB_SYNC] Failed to handle batch: {}", e);
                }
            }
            other => {
                info!("ℹ️  RPCResponse::{:?} from {} (no action)", other, peer);
            }
        }

        Ok(())
    }

    /// Handle PeerList RPC response
    async fn handle_peer_list_response(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peers: Vec<SerializablePeerId>,
        indices: Vec<Option<usize>>,
    ) -> Result<()> {
        info!("🔄 Merging peer‐set: {:?}", peers);
        info!("🔄 Received indices: {:?}", indices);

        let mut batch_updates: Vec<(String, usize)> = Vec::new();

        for (i, SerializablePeerId(p)) in peers.into_iter().enumerate() {
            // Add peer to node_manager if not already present
            if !self.node_manager.get_active_nodes().contains(&p) {
                self.node_manager
                    .add_node(p.clone())
                    .map_err(|e| anyhow::anyhow!(e))?;

                // Update signing node threshold after adding peer
                if let Some(signing_node) = &mut self.signing_node {
                    let new_threshold = self.node_manager.get_threshold();
                    signing_node.set_threshold(new_threshold);
                    info!(
                        "🔄 [THRESHOLD] Updated signing node threshold to {} after peer list merge",
                        new_threshold
                    );
                }
            }

            // 🔧 FIX: Update peer_indices mapping for ALL peers in the peer list
            // Priority: 1) Index from peer list, 2) Existing in peer_indices, 3) Load from database
            let index_to_use = if let Some(idx) = indices.get(i).cloned().flatten() {
                // Index provided in peer list - use it and persist to database
                info!(
                    "🔢 [PEER_LIST] Using index {} for peer {} from peer list",
                    idx, p
                );
                Some(idx)
            } else if let Some(existing_idx) = self.peer_discovery.peer_indices.get(&p).cloned() {
                // Already in peer_indices - keep it
                info!(
                    "🔢 [PEER_LIST] Using existing index {} for peer {} from peer_indices",
                    existing_idx, p
                );
                Some(existing_idx)
            } else if let Some(db_idx) = self.get_index_from_db_async(&p).await {
                // Load from database if available
                info!(
                    "🔢 [PEER_LIST] Loaded index {} for peer {} from database",
                    db_idx, p
                );
                Some(db_idx)
            } else {
                // No index available
                warn!("⚠️  [PEER_LIST] No index found for peer {} (not in peer list, peer_indices, or database)", p);
                None
            };

            // Update peer_indices and persist to database if we have an index
            if let Some(idx) = index_to_use {
                self.peer_discovery.peer_indices.insert(p.clone(), idx);
                let key = key_utils::peer_index_key(&p.to_string());
                batch_updates.push((key, idx));
            }
        }

        if !batch_updates.is_empty() {
            if let Err(e) = self
                .db
                .batch_write_async(move |batch| {
                    for (key, idx) in batch_updates {
                        batch.put_string(&key, &idx)?;
                    }
                    Ok(())
                })
                .await
            {
                warn!(
                    "❌ [PEER_LIST] Failed to persist peer indices batch: {:?}",
                    e
                );
            }
        }

        info!(
            "📊 [PEER_LIST] Updated peer_indices mapping: {} entries",
            self.peer_discovery.peer_indices.len()
        );

        // After learning about all peers, check if this is a new node joining existing network
        self.handle_new_node_joining_check(swarm).await?;

        Ok(())
    }

    /// Check if this is a new node joining an existing network
    async fn handle_new_node_joining_check(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        let (should_sync, sync_peer_opt, new_node_index_opt, needs_retry) = if let Some(dkg_node) =
            &mut self.dkg_node
        {
            let total = self.node_manager.get_total_nodes();
            let threshold = self.node_manager.get_threshold();

            // Update DKG node parameters with current network size
            dkg_node.update_node_params(total, threshold);
            info!(
                "🔄 [NEW_NODE] Updated DKG params: total_nodes={}, threshold={}",
                total, threshold
            );

            let has_dkg_data = dkg_node.get_final_secret_share().await.is_some();
            info!("🔍 [NEW_NODE] Has DKG data: {}", has_dkg_data);

            // If this node has no DKG data and network has > 4 nodes, it's a new node joining
            if !has_dkg_data && total > 4 {
                info!("🆕 [NEW_NODE] Learned about {} total nodes, triggering database sync and share request", total);

                let connected_peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                info!(
                    "🔗 [NEW_NODE] Currently connected to {} peers: {:?}",
                    connected_peers.len(),
                    connected_peers
                );

                // Find first connected peer for sync (excluding ourselves)
                let sync_peer = connected_peers
                    .iter()
                    .find(|pid| **pid != self.local_peer_id)
                    .cloned();

                let should_proceed = if let Some(ref peer) = sync_peer {
                    info!("✅ [NEW_NODE] Selected connected peer for sync: {}", peer);
                    true
                } else {
                    warn!("⚠️ [NEW_NODE] No connected peers available for database sync!");
                    warn!(
                        "⚠️ [NEW_NODE] Will retry database sync when a connection is established"
                    );
                    false
                };

                // CRITICAL: Check if this is a REJOINING node or a truly NEW node
                let new_node_index = if let Some(existing_index) =
                    self.get_index_from_db_async(&self.local_peer_id).await
                {
                    info!(
                        "🔄 [REJOIN] Node rejoining with existing index: {}",
                        existing_index
                    );
                    existing_index
                } else {
                    // This is a truly NEW node - assign max_index + 1
                    let all_assigned_indices: Vec<usize> =
                        self.peer_discovery.peer_indices.values().cloned().collect();
                    let max_index = all_assigned_indices.iter().max().cloned().unwrap_or(0);
                    let final_index = max_index + 1;
                    info!("🆕 [NEW_NODE] Assigned permanent index: {} (max_existing={}, total_nodes={})", 
                              final_index, max_index, total);
                    final_index
                };

                (
                    should_proceed,
                    sync_peer,
                    Some(new_node_index),
                    !should_proceed,
                )
            } else {
                (false, None, None, false)
            }
        } else {
            (false, None, None, false)
        };

        if needs_retry {
            self.needs_database_sync = true;
        }

        // Now handle sync and DKG request outside of the dkg_node borrow
        if should_sync {
            // First, sync database from an existing peer
            if let Some(sync_peer) = sync_peer_opt {
                info!(
                    "📦 [NEW_NODE] Initiating database sync from peer: {}",
                    sync_peer
                );

                if let Err(e) = self.sync_database_from_peer(swarm, sync_peer).await {
                    warn!("❌ [NEW_NODE] Failed to start database sync: {:?}", e);
                } else {
                    info!("✅ [NEW_NODE] Database sync initiated");
                }
            }

            // Request DKG shares
            if let (Some(dkg_node), Some(new_node_index)) = (&mut self.dkg_node, new_node_index_opt)
            {
                if let Err(e) = dkg_node.request_shares_as_new_node(new_node_index).await {
                    warn!("❌ [NEW_NODE] Failed to request shares: {:?}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle CurrentVrfRoundResponse
    async fn handle_current_vrf_round_response(&mut self, current_round: Option<u64>) {
        if let Some(network_round) = current_round {
            info!("🔄 Received current VRF round response: {}", network_round);

            // Simple VRF round sync for both signing nodes
            if let Some(signing_node) = &mut self.signing_node {
                signing_node
                    .sync_vrf_round_with_network(network_round)
                    .await;
            }
            if let Some(db_signing_node) = &mut self.db_signing_node {
                let mut node = db_signing_node.lock().await;
                node.sync_vrf_round_with_network(network_round).await;
            }

            info!(
                "✅ [NETWORK] VRF round synced to network round: {}",
                network_round
            );
        } else {
            info!("ℹ️ Peer doesn't have current VRF round yet");
        }
    }
}
