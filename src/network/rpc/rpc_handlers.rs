/// RPC Request/Response handlers
/// This module contains all the RPC request and response handling logic
use anyhow::Result;
use libp2p::PeerId;
use tracing::{error, info, warn};

use crate::database::key_utils::{self, peer_addr_key};
use crate::types::p2p::SerializablePeerId;
use crate::types::{PeerInfo, SerializablePoint, SerializableScalar};

use crate::database::VrfStorage;
use crate::protocols::DKGStatus;
use crate::types::rpc::{RPCRequest, RPCResponse};
use crate::types::vrf::{VrfRoundSyncRequest, VrfRoundSyncResponse};

use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer};

const MAX_VRF_ROUND_SKEW: u64 = 10;

impl MpcNetworkLayer {
    /// Handle RPC requests from peers
    pub(crate) async fn handle_rpc_request(
        &mut self,
        peer: PeerId,
        request: RPCRequest,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> RPCResponse {
        match request {
            RPCRequest::GetPeerList => self.handle_get_peer_list_request(peer, swarm).await,
            RPCRequest::Ping => RPCResponse::Pong,
            RPCRequest::GetPeerInfo => {
                let self_peer = self.get_local_peer_id();
                let listen_addrs: Vec<_> = swarm
                    .listeners()
                    .cloned()
                    .map(|a| format!("{}/p2p/{}", a, self_peer))
                    .filter_map(|s| s.parse().ok())
                    .collect();

                RPCResponse::PeerInfo(PeerInfo {
                    addresses: listen_addrs,
                    connected: true,
                })
            }
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
            RPCRequest::VrfRoundSync(sync_request) => {
                self.handle_vrf_round_sync_request(peer, sync_request).await
            }
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
            // SECURE DKG SHARE - receive unicast share via P2P RPC
            RPCRequest::SendDKGShare {
                from_node_id,
                share_index,
                share_value,
                commitments,
                round,
            } => {
                info!(
                    "🔐 [DKG-SECURE] Received UNICAST share index: {}, share value: {:?}, commitments: {:?}, from: {}, round: {}",
                    share_index, share_value, commitments, from_node_id, round
                );
                self.handle_incoming_dkg_share(
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                    round,
                )
                .await
            }
            // SECURE REFRESH SHARE - receive unicast refresh share via P2P RPC
            RPCRequest::SendRefreshShare {
                from_node_id,
                share_index,
                share_value,
                commitments,
            } => {
                info!(
                    "🔐 [REFRESH-SECURE] Received UNICAST refresh share index: {}, from: {}",
                    share_index, from_node_id
                );
                self.handle_incoming_refresh_share(
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                )
                .await
            }
            _ => RPCResponse::Ack,
        }
    }

    pub(crate) async fn get_local_vrf_round(&self) -> Option<u64> {
        // Check signing_node first
        if let Some(signing_node) = &self.signing_node {
            if let Some(vrf_service) = signing_node.vrf_service() {
                return Some(vrf_service.get_current_round().await);
            }
        }

        // If no round from signing_node, check db_signing_node
        if let Some(db_signing_node) = &self.db_signing_node {
            let node = db_signing_node.lock().await;
            if let Some(vrf_service) = &node.vrf_service {
                return Some(vrf_service.get_current_round().await);
            }
        }

        None
    }

    fn is_vrf_round_within_range(reference_round: Option<u64>, candidate_round: u64) -> bool {
        reference_round
            .map(|reference| {
                candidate_round >= reference.saturating_sub(MAX_VRF_ROUND_SKEW)
                    && candidate_round <= reference.saturating_add(MAX_VRF_ROUND_SKEW)
            })
            .unwrap_or(true)
    }

    pub(crate) fn store_peer_round_if_valid(
        &mut self,
        peer: PeerId,
        reference_round: Option<u64>,
        reported_round: Option<u64>,
    ) -> bool {
        let Some(round) = reported_round else {
            warn!(
                "⚠️ [VRF_SYNC] Received VRF round sync without round value from {}",
                peer
            );
            return false;
        };

        if Self::is_vrf_round_within_range(reference_round, round) {
            // Store in memory (for backward compatibility)
            self.peer_rounds.insert(peer, round);
            
            // Persist to database as single source of truth
            let vrf_storage = VrfStorage::new(self.db.clone());
            if let Err(e) = vrf_storage.set_peer_round(&peer.to_string(), round) {
                warn!(
                    "⚠️ [VRF_SYNC] Failed to persist peer round {} for {} to DB: {}",
                    round, peer, e
                );
            } else {
                info!("💾 [VRF_SYNC] Stored VRF round {} for peer {} (DB)", round, peer);
            }
            true
        } else {
            warn!(
                "⚠️ [VRF_SYNC] Ignoring VRF round {} from {} (reference: {:?}, skew limit: {})",
                round, peer, reference_round, MAX_VRF_ROUND_SKEW
            );
            false
        }
    }

    /// Handle GetPeerList RPC request
    async fn handle_get_peer_list_request(
        &mut self,
        peer: PeerId,
        swarm: &libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> RPCResponse {
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
                    self.peer_discovery.peer_indices.insert(*pid, db_idx);
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
                        self.peer_discovery.peer_indices.insert(*pid, idx);
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

        // Build listen addresses (string) aligned with peers.
        let mut addresses: Vec<Option<String>> = Vec::with_capacity(peers.len());
        let self_peer = self.get_local_peer_id();
        let self_listen: Vec<String> = swarm
            .listeners()
            .cloned()
            .map(|a| format!("{}/p2p/{}", a, self_peer))
            .collect();

        for SerializablePeerId(pid) in &peers {
            // If we have a stored listen addr for this peer, use it (DB or in-memory)
            if let Some(addr) = self.peer_discovery.peer_multiaddresses.get(pid) {
                addresses.push(Some(format!("{}/p2p/{}", addr, pid)));
                continue;
            }
            let key = peer_addr_key(&pid.to_string());
            if let Ok(Some(addr_str)) = self.db.get_string::<String>(&key) {
                // Ensure /p2p/<peer> suffix
                let normalized = if addr_str.contains(&format!("/p2p/{}", pid)) {
                    addr_str
                } else {
                    format!("{}/p2p/{}", addr_str, pid)
                };
                addresses.push(Some(normalized));
                continue;
            }

            // If this is us, include our listen addr(s)
            if *pid == *self_peer && !self_listen.is_empty() {
                addresses.push(Some(self_listen[0].clone()));
                continue;
            }

            // Otherwise unknown
            addresses.push(None);
        }

        // Log how many peers we're returning
        info!(
            "📋 Sending PeerList response to {}: {} entries (addresses count: {})",
            peer,
            peers.len(),
            addresses.iter().filter(|a| a.is_some()).count()
        );

        RPCResponse::PeerList {
            peers,
            indices,
            addresses,
        }
    }

    /// Handle StartADKG RPC request
    async fn handle_start_adkg_request(&mut self, peer: PeerId) -> RPCResponse {
        match self.dkg_node.as_mut() {
            Some(dkg) => {
                info!("🚀 Received DKG start request from peer {}", peer);

                // Update DKG parameters with current network state
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();
                if let Err(e) = dkg.update_node_params(total, threshold) {
                    warn!("❌ Invalid DKG params: {}", e);
                    return RPCResponse::DKGError(format!("Invalid DKG params: {e}"));
                }
                if let Err(e) = dkg.reset().await {
                    warn!("❌ Failed to reset DKG state: {}", e);
                    return RPCResponse::DKGError(format!("Failed to reset DKG: {e}"));
                }
                if let Some(signing_node) = &mut self.signing_node {
                    // Keep signing threshold consistent with the node manager's threshold
                    let new_threshold = self.node_manager.get_threshold();
                    signing_node.set_threshold(new_threshold);
                    info!(
                        "🔄 [THRESHOLD] Updated signing node threshold to {} (total nodes: {})",
                        new_threshold, total
                    );
                }
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
                        RPCResponse::DKGError(format!("Failed to start DKG: {e:?}"))
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

    /// Handle incoming DKG share from unicast P2P RPC
    async fn handle_incoming_dkg_share(
        &mut self,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
        _round: u64,
    ) -> RPCResponse {
        info!(
            "🔐 [DKG-SECURE] Processing unicast share index: {}, share value: {:?}, commitments: {:?}, from: {}",
            share_index, share_value, commitments, from_node_id
        );

        let dkg_node = match &mut self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [DKG-SECURE] DKG node not initialized");
                return RPCResponse::Error("DKG not initialized".to_string());
            }
        };

        let receiver_node_id = dkg_node.get_id().to_string();

        
        // Use the public method to process the share
        match dkg_node.process_incoming_share(
            from_node_id.clone(),
            share_index,
            share_value,
            commitments,
            self.node_manager.clone(),
        ).await {
            Ok(true) => {
                info!(
                    "✅ [DKG-SECURE] Share index {} from {} processed incoming share successfully ",
                    share_index, from_node_id
                );
                RPCResponse::DKGShareReceived {
                    from_node_id,
                    receiver_node_id,
                    share_index,
                    success: true,
                }
            }
            Ok(false) => {
                warn!(
                    "❌ [DKG-SECURE] Share index {} from {} was rejected",
                    share_index, from_node_id
                );
                RPCResponse::DKGShareReceived {
                    from_node_id,
                    receiver_node_id,
                    share_index,
                    success: false,
                }
            }
            Err(e) => {
                warn!(
                    "❌ [DKG-SECURE] Error processing share index {} from {}: {}",
                    share_index, from_node_id, e
                );
                RPCResponse::Error(format!("Failed to process share: {}", e))
            }
        }
    }

    /// Handle incoming refresh share from unicast P2P RPC
    async fn handle_incoming_refresh_share(
        &mut self,
        from_node_id: String,
        share_index: usize,
        share_value: SerializableScalar,
        commitments: Vec<SerializablePoint>,
    ) -> RPCResponse {
        info!(
            "🔐 [REFRESH-SECURE] Processing unicast refresh share index: {}, from: {}",
            share_index, from_node_id
        );

        let dkg_node = match &mut self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [REFRESH-SECURE] DKG node not initialized");
                return RPCResponse::Error("DKG not initialized".to_string());
            }
        };

        let receiver_node_id = dkg_node.get_id().to_string();

        // Use the public method to process the refresh share
        match dkg_node.handle_unicast_refresh_share(
            from_node_id.clone(),
            share_index,
            share_value,
            commitments,
            self.node_manager.clone(),
        ).await {
            Ok(true) => {
                info!(
                    "✅ [REFRESH-SECURE] Refresh share index {} from {} processed successfully",
                    share_index, from_node_id
                );
                RPCResponse::RefreshShareReceived {
                    from_node_id,
                    receiver_node_id,
                    share_index,
                    success: true,
                }
            }
            Ok(false) => {
                warn!(
                    "❌ [REFRESH-SECURE] Refresh share index {} from {} was rejected",
                    share_index, from_node_id
                );
                RPCResponse::RefreshShareReceived {
                    from_node_id,
                    receiver_node_id,
                    share_index,
                    success: false,
                }
            }
            Err(e) => {
                warn!(
                    "❌ [REFRESH-SECURE] Error processing refresh share index {} from {}: {}",
                    share_index, from_node_id, e
                );
                RPCResponse::Error(format!("Failed to process refresh share: {}", e))
            }
        }
    }

    /// Handle RequestCurrentVrfRound RPC request
    async fn handle_request_current_vrf_round(&self, peer: PeerId) -> RPCResponse {
        info!(
            "🔄 Received request for current VRF round from peer {}",
            peer
        );
        let current_round = self.get_local_vrf_round().await;

        RPCResponse::CurrentVrfRoundResponse { current_round }
    }

    async fn handle_vrf_round_sync_request(
        &mut self,
        peer: PeerId,
        request: VrfRoundSyncRequest,
    ) -> RPCResponse {
        if request.from.0 != peer {
            warn!(
                "⚠️ [VRF_SYNC] Peer mismatch in VRF round sync request: declared={}, actual={}",
                request.from.0, peer
            );
        }

        let local_round = self.get_local_vrf_round().await;
        self.store_peer_round_if_valid(peer, local_round, request.current_round);

        RPCResponse::VrfRoundSync(VrfRoundSyncResponse {
            from: SerializablePeerId(self.local_peer_id),
            current_round: local_round,
        })
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
                RPCResponse::Error(format!("Failed to count user database entries: {e}"))
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
                RPCResponse::Error(format!("Failed to export batch: {e}"))
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
            RPCResponse::PeerList {
                peers,
                indices,
                addresses,
            } => {
                self.handle_peer_list_response(swarm, peers, indices, addresses)
                    .await?;
            }
            RPCResponse::PeerInfo(peer_info) => {
                let addr_count = peer_info.addresses.len();
                for addr in peer_info.addresses {
                    // Extract PeerId from the /p2p/ component of the multiaddr string
                    let maybe_peer = addr
                        .to_string()
                        .rsplit_once("/p2p/")
                        .and_then(|(_, pid_str)| pid_str.parse::<PeerId>().ok());

                    if let Some(peer_id) = maybe_peer {
                        self.peer_discovery
                            .peer_multiaddresses
                            .insert(peer_id, addr.clone());
                        let key = peer_addr_key(&peer_id.to_string());
                        if let Err(e) = self.db.put_string(&key, &addr.to_string()) {
                            warn!("⚠️ [PEER_INFO] Failed to persist addr for {}: {}", peer_id, e);
                        }
                    }
                }
                info!(
                    "🌐 [PEER_INFO] Stored {} addresses from peer {}",
                    addr_count, peer
                );
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
                let reference_round = self.get_local_vrf_round().await;
                self.store_peer_round_if_valid(peer, reference_round, current_round);
                self.handle_current_vrf_round_response(current_round).await;
            }
            RPCResponse::VrfRoundSync(sync_response) => {
                self.handle_vrf_round_sync_response(peer, sync_response)
                    .await;
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
        addresses: Vec<Option<String>>,
    ) -> Result<()> {
        info!("🔄 Merging peer‐set: {:?}", peers);
        info!("🔄 Received indices: {:?}", indices);
        info!(
            "🔄 Received addresses (count with some): {}",
            addresses.iter().filter(|a| a.is_some()).count()
        );

        let mut batch_updates: Vec<(String, usize)> = Vec::new();

        for (i, SerializablePeerId(p)) in peers.into_iter().enumerate() {
            // Add peer to node_manager if not already present
            if !self.node_manager.get_active_nodes().contains(&p) {
                self.node_manager
                    .add_node(p)
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
                self.peer_discovery.peer_indices.insert(p, idx);
                let key = key_utils::peer_index_key(&p.to_string());
                batch_updates.push((key, idx));
            }

            // Insert advertised address into map/db and dial if needed
            if let Some(addr_str) = addresses.get(i).cloned().flatten() {
                // Ensure /p2p/<peer> suffix
                let suffix = format!("/p2p/{}", p);
                let addr_with_p2p = if addr_str.contains(&suffix) {
                    addr_str.clone()
                } else {
                    format!("{}/p2p/{}", addr_str, p)
                };

                if let Ok(addr) = addr_with_p2p.parse::<libp2p::Multiaddr>() {
                    info!("🔐 [PEER_LIST] Inserting advertised address into map/db for peer {}: {}", p, addr);
                    self.peer_discovery.peer_multiaddresses.insert(p, addr.clone());
                    let key = peer_addr_key(&p.to_string());
                    if let Err(e) = self.db.put_string(&key, &addr.to_string()) {
                        warn!("⚠️ [PEER_LIST] Failed to persist addr for {}: {}", p, e);
                    }
                    if p != *self.get_local_peer_id() && !swarm.is_connected(&p) {
                        info!("📞 [PEER_LIST] Dialing peer {} at {}", p, addr);
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("⚠️ [PEER_LIST] Dial to {} failed: {}", p, e);
                        }
                    }
                } else {
                    warn!("⚠️ [PEER_LIST] Invalid multiaddr for {}: {}", p, addr_str);
                }
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
            dkg_node.update_node_params(total, threshold)?;
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

    async fn handle_vrf_round_sync_response(
        &mut self,
        peer: PeerId,
        response: VrfRoundSyncResponse,
    ) {
        if response.from.0 != peer {
            warn!(
                "⚠️ [VRF_SYNC] Peer mismatch in VRF round sync response: declared={}, actual={}",
                response.from.0, peer
            );
        }

        let reference_round = self.get_local_vrf_round().await;
        if self.store_peer_round_if_valid(peer, reference_round, response.current_round) {
            info!("✅ [VRF_SYNC] Applied VRF round sync from peer {}", peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MpcNetworkLayer;
    use crate::database::{Database, DatabaseConfig};
    use crate::node_selection::{BasicNodeManager, DefaultThresholdCalculator};
    use libp2p::PeerId;
    use tempfile::tempdir;

    async fn build_network_layer() -> MpcNetworkLayer {
        let temp_dir = tempdir().expect("tempdir to create");
        let db_root = temp_dir.into_path();
        let db_path = db_root.join("db");
        let db = Database::new(DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            create_if_missing: true,
            max_open_files: 32,
        })
        .expect("db to start");

        let manager = Box::new(BasicNodeManager::new(Box::new(DefaultThresholdCalculator)));

        MpcNetworkLayer::new(manager, db)
            .await
            .expect("network layer to initialize")
    }

    #[tokio::test]
    async fn stores_peer_rounds_within_allowed_skew() {
        let mut layer = build_network_layer().await;
        let peer = PeerId::random();

        let stored = layer.store_peer_round_if_valid(peer, Some(5), Some(6));

        assert!(stored, "valid rounds should be stored");
        assert_eq!(layer.peer_rounds.get(&peer), Some(&6));
    }

    #[tokio::test]
    async fn ignores_peer_rounds_outside_allowed_skew() {
        let mut layer = build_network_layer().await;
        let peer = PeerId::random();

        let stored = layer.store_peer_round_if_valid(
            peer,
            Some(1),
            Some(1 + super::MAX_VRF_ROUND_SKEW + 10),
        );

        assert!(layer.peer_rounds.get(&peer).is_none());
        assert!(!stored, "out-of-range rounds should be rejected");
    }
}
