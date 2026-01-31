/// RPC Request/Response handlers
/// This module contains all the RPC request and response handling logic
use anyhow::Result;
use libp2p::gossipsub::{IdentTopic, Message};
use libp2p::PeerId;
use tracing::{error, warn};

use crate::database::key_utils::{self, peer_addr_key};
use crate::types::p2p::SerializablePeerId;
use crate::types::signing::SigningMessage;
use crate::types::{GossipsubMessage, PeerInfo, SerializablePoint, SerializableScalar};

use crate::database::VrfStorage;
use crate::protocols::DKGStatus;
use crate::types::rpc::{RPCRequest, RPCResponse};
use crate::types::vrf::{VrfRoundSyncRequest, VrfRoundSyncResponse};

use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer, VrfDomain};

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
                self.handle_incoming_refresh_share(
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                )
                .await
            }
            RPCRequest::SendECDSASignature {
                from_node_id,
                signature_data,
                round,
            } => {
                self.handle_incoming_ecdsa_signature(from_node_id, signature_data, round)
                    .await
            }
            RPCRequest::SendBtcSignatures {
                from_node_id,
                signature_data,
                round,
            } => {
                self.handle_incoming_btc_signatures(from_node_id, signature_data, round)
                    .await
            }
            RPCRequest::SendTransactionData {
                from_node_id,
                transaction_data,
                round,
            } => {
                self.handle_incoming_transaction_data(from_node_id, transaction_data, round)
                    .await
            }
            RPCRequest::DeliverCriticalGossip {
                topic,
                data,
                message_type,
                message_id,
            } => {
                let message = Message {
                    source: Some(peer),
                    data,
                    sequence_number: None,
                    topic: IdentTopic::new(topic).hash(),
                };

                match self.handle_gossipsub_message(&message).await {
                    Ok(()) => RPCResponse::CriticalDeliveryAck {
                        message_type,
                        message_id,
                    },
                    Err(e) => {
                        warn!(
                            "❌ [CRITICAL-UNICAST] Failed to handle delivered message: {}",
                            e
                        );
                        RPCResponse::Error(format!(
                            "Failed to handle critical message: {e}"
                        ))
                    }
                }
            }
            _ => RPCResponse::Ack,
        }
    }

    fn resolve_context(&self, domain: VrfDomain, context: Option<&str>) -> String {
        let provided = context.unwrap_or_default();
        if !provided.is_empty() {
            return provided.to_string();
        }

        match domain {
            VrfDomain::Signing => self
                .signing_node
                .as_ref()
                .and_then(|node| node.vrf_service())
                .map(|svc| svc.context().to_string())
                .or_else(|| {
                    if let Some(db_signing_node) = &self.db_signing_node {
                        if let Ok(guard) = db_signing_node.try_lock() {
                            if let Some(vrf_service) = &guard.vrf_service {
                                return Some(vrf_service.context().to_string());
                            }
                        }
                    }
                    None
                })
                .unwrap_or_default(),
        }
    }

    pub(crate) async fn get_local_vrf_round_for_domain(
        &self,
        domain: VrfDomain,
        context: Option<&str>,
    ) -> Option<u64> {
        let context = self.resolve_context(domain, context);
        match domain {
            VrfDomain::Signing => {
                if let Some(signing_node) = &self.signing_node {
                    if let Some(vrf_service) = signing_node.vrf_service() {
                        if vrf_service.context() == context {
                            return Some(vrf_service.get_current_round().await);
                        }
                    }
                }

                if let Some(db_signing_node) = &self.db_signing_node {
                    let node = db_signing_node.lock().await;
                    if let Some(vrf_service) = &node.vrf_service {
                        if vrf_service.context() == context {
                            return Some(vrf_service.get_current_round().await);
                        }
                    }
                }
            }
        }

        None
    }

    #[allow(dead_code)]
    pub(crate) async fn get_local_vrf_round(&self) -> Option<u64> {
        self.get_local_vrf_round_for_domain(VrfDomain::Signing, None)
            .await
    }

    fn get_vrf_storage_for_domain(&self, domain: VrfDomain, context: &str) -> Option<VrfStorage> {
        let context = self.resolve_context(domain, Some(context));

        match domain {
            VrfDomain::Signing => {
                // Prefer in-memory signing node VRF service if context matches
                if let Some(signing_node) = &self.signing_node {
                    if let Some(vrf_service) = signing_node.vrf_service() {
                        if vrf_service.context() == context {
                            return vrf_service.storage();
                        }
                    }
                }

                // Fall back to db_signing_node VRF service
                if let Some(db_signing_node) = &self.db_signing_node {
                    if let Ok(node) = db_signing_node.try_lock() {
                        if let Some(vrf_service) = &node.vrf_service {
                            if vrf_service.context() == context {
                                return vrf_service.storage();
                            }
                        }
                    }
                }

                None
            }
        }
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
        domain: VrfDomain,
        context: &str,
        peer: PeerId,
        reference_round: Option<u64>,
        reported_round: Option<u64>,
    ) -> bool {
        let normalized_context = self.resolve_context(domain, Some(context));
        let Some(round) = reported_round else {
            warn!(
                "⚠️ [VRF_SYNC] Received VRF round sync without round value from {}",
                peer
            );
            return false;
        };

        if Self::is_vrf_round_within_range(reference_round, round) {
            // Store in memory (for backward compatibility)
            let entry = self
                .peer_rounds
                .entry(domain)
                .or_default()
                .entry(normalized_context.clone())
                .or_default();
            entry.insert(peer, round);

            // Persist to database as single source of truth
            if let Some(vrf_storage) = self.get_vrf_storage_for_domain(domain, &normalized_context)
            {
                if let Err(e) = vrf_storage.set_peer_round_for_context(
                    &normalized_context,
                    &peer.to_string(),
                    round,
                ) {
                    warn!(
                        "⚠️ [VRF_SYNC] Failed to persist peer round {} for {} to DB: {}",
                        round, peer, e
                    );
                }
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
        _peer: PeerId,
        swarm: &libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> RPCResponse {

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

        RPCResponse::PeerList {
            peers,
            indices,
            addresses,
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

        let dkg_node = self.dkg_node.as_ref().unwrap();

        // SECURITY FIX: Get our own actual index from storage instead of using hash-based fallback
        // The hash-based fallback would almost never match the actual index used during share generation,
        // causing valid shares to be rejected. Shares are generated with indices 1..=total_nodes based on
        // the dealer's view of node indices (stored in database), so we must use the same source.
        // When we receive SendAVSSShare, we are the receiver, so we use our own node ID to get our index.
        let our_node_id = dkg_node.get_id();
        let share_index = match dkg_node.get_peer_index_for(our_node_id) {
            Ok(Some(idx)) => idx,
            Ok(None) => {
                warn!(
                    "❌ [DKG] No stored peer index found for our node {}; cannot verify share (receiver_id: {})",
                    our_node_id, receiver_id.0
                );
                return RPCResponse::Error(format!(
                    "Cannot determine share index for our node {}: no peer index in storage",
                    our_node_id
                ));
            }
            Err(e) => {
                warn!(
                    "❌ [DKG] Failed to get peer index for our node {}: {} (receiver_id: {})",
                    our_node_id, e, receiver_id.0
                );
                return RPCResponse::Error(format!(
                    "Failed to get peer index for our node {}: {}",
                    our_node_id, e
                ));
            }
        };

        if dkg_node.verify_share(&share, share_index, &commitments) {
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
        let dkg_node = match &mut self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [DKG-SECURE] DKG node not initialized");
                return RPCResponse::Error("DKG not initialized".to_string());
            }
        };

        let receiver_node_id = dkg_node.get_id().to_string();

        // Use the public method to process the share
        match dkg_node
            .process_incoming_share(
                from_node_id.clone(),
                share_index,
                share_value,
                commitments,
                self.node_manager.clone(),
            )
            .await
        {
            Ok(true) => {
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
        let dkg_node = match &mut self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [REFRESH-SECURE] DKG node not initialized");
                return RPCResponse::Error("DKG not initialized".to_string());
            }
        };

        let receiver_node_id = dkg_node.get_id().to_string();

        // Use the public method to process the refresh share
        match dkg_node
            .handle_unicast_refresh_share(
                from_node_id.clone(),
                share_index,
                share_value,
                commitments,
                self.node_manager.clone(),
            )
            .await
        {
            Ok(true) => {
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

    /// Handle incoming ECDSA signature from unicast P2P RPC
    async fn handle_incoming_ecdsa_signature(
        &mut self,
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
    ) -> RPCResponse {
        let signing_message = match serde_json::from_slice::<GossipsubMessage>(&signature_data) {
            Ok(GossipsubMessage::Signing(msg)) => msg,
            Ok(other) => {
                warn!(
                    "❌ [SIGNING-SECURE] Unexpected gossipsub message type for ECDSA signature: {:?}",
                    other
                );
                return RPCResponse::ECDSASignatureReceived {
                    from_node_id,
                    receiver_node_id: self.get_local_peer_id().to_string(),
                    round,
                    success: false,
                };
            }
            Err(e) => {
                warn!(
                    "❌ [SIGNING-SECURE] Failed to deserialize ECDSA signature payload: {}",
                    e
                );
                return RPCResponse::ECDSASignatureReceived {
                    from_node_id,
                    receiver_node_id: self.get_local_peer_id().to_string(),
                    round,
                    success: false,
                };
            }
        };

        let (from, signature, msg_round) = match signing_message {
            SigningMessage::ECDSASignature {
                from,
                signature,
                round,
                ..
            } => (from, signature, round),
            _ => {
                warn!(
                    "❌ [SIGNING-SECURE] Received signing message that is not an ECDSA signature"
                );
                return RPCResponse::ECDSASignatureReceived {
                    from_node_id,
                    receiver_node_id: self.get_local_peer_id().to_string(),
                    round,
                    success: false,
                };
            }
        };

        if msg_round != round {
            warn!(
                "⚠️ [SIGNING-SECURE] Round mismatch for ECDSA signature: request round {}, message round {}",
                round, msg_round
            );
        }

        let mut receiver_node_id = self.get_local_peer_id().to_string();
        let result = if let Some(signing_node) = &mut self.signing_node {
            receiver_node_id = signing_node.get_node_id().to_string();
            signing_node
                .handle_signature_to_final_node(from.clone(), signature.clone(), round)
                .await
        } else {
            warn!("❌ [SIGNING-SECURE] Signing node not initialized to process ECDSA signature");
            return RPCResponse::ECDSASignatureReceived {
                from_node_id,
                receiver_node_id,
                round,
                success: false,
            };
        };

        match result {
            Ok(_) => {
                RPCResponse::ECDSASignatureReceived {
                    from_node_id,
                    receiver_node_id,
                    round,
                    success: true,
                }
            }
            Err(e) => {
                warn!(
                    "❌ [SIGNING-SECURE] Failed to process ECDSA signature for round {}: {}",
                    round, e
                );
                RPCResponse::ECDSASignatureReceived {
                    from_node_id,
                    receiver_node_id,
                    round,
                    success: false,
                }
            }
        }
    }

    /// Handle incoming BTC signatures from unicast P2P RPC
    async fn handle_incoming_btc_signatures(
        &mut self,
        from_node_id: String,
        signature_data: Vec<u8>,
        round: u64,
    ) -> RPCResponse {
        let signing_message = match serde_json::from_slice::<GossipsubMessage>(&signature_data) {
            Ok(GossipsubMessage::Signing(msg)) => msg,
            Ok(other) => {
                warn!(
                    "❌ [SIGNING-SECURE] Unexpected gossipsub message type for BTC signatures: {:?}",
                    other
                );
                return RPCResponse::BtcSignaturesReceived {
                    from_node_id,
                    receiver_node_id: self.get_local_peer_id().to_string(),
                    round,
                    success: false,
                };
            }
            Err(e) => {
                warn!(
                    "❌ [SIGNING-SECURE] Failed to deserialize BTC signatures payload: {}",
                    e
                );
                return RPCResponse::BtcSignaturesReceived {
                    from_node_id,
                    receiver_node_id: self.get_local_peer_id().to_string(),
                    round,
                    success: false,
                };
            }
        };

        let (from, signatures, msg_round) = match signing_message {
            SigningMessage::BtcSignaturesMessage {
                from,
                signatures,
                round,
                ..
            } => (from, signatures, round),
            _ => {
                warn!(
                    "❌ [SIGNING-SECURE] Received signing message that is not a BTC signatures payload"
                );
                return RPCResponse::BtcSignaturesReceived {
                    from_node_id,
                    receiver_node_id: self.get_local_peer_id().to_string(),
                    round,
                    success: false,
                };
            }
        };

        if msg_round != round {
            warn!(
                "⚠️ [SIGNING-SECURE] Round mismatch for BTC signatures: request round {}, message round {}",
                round, msg_round
            );
        }

        let mut receiver_node_id = self.get_local_peer_id().to_string();
        let result = if let Some(signing_node) = &mut self.signing_node {
            receiver_node_id = signing_node.get_node_id().to_string();
            signing_node
                .handle_btc_signatures_to_final_node(from.clone(), signatures.clone(), round)
                .await
        } else {
            warn!("❌ [SIGNING-SECURE] Signing node not initialized to process BTC signatures");
            return RPCResponse::BtcSignaturesReceived {
                from_node_id,
                receiver_node_id,
                round,
                success: false,
            };
        };

        match result {
            Ok(_) => {
                RPCResponse::BtcSignaturesReceived {
                    from_node_id,
                    receiver_node_id,
                    round,
                    success: true,
                }
            }
            Err(e) => {
                warn!(
                    "❌ [SIGNING-SECURE] Failed to process BTC signatures for round {}: {}",
                    round, e
                );
                RPCResponse::BtcSignaturesReceived {
                    from_node_id,
                    receiver_node_id,
                    round,
                    success: false,
                }
            }
        }
    }

    /// Handle incoming transaction data from signing nodes to final node
    async fn handle_incoming_transaction_data(
        &mut self,
        _from_node_id: String,
        transaction_data: Vec<u8>,
        round: u64,
    ) -> RPCResponse {
        let signing_message = match serde_json::from_slice::<GossipsubMessage>(&transaction_data) {
            Ok(GossipsubMessage::Signing(msg)) => msg,
            Ok(other) => {
                warn!(
                    "❌ [SIGNING-SECURE] Unexpected gossipsub message type for transaction data: {:?}",
                    other
                );
                return RPCResponse::Ack;
            }
            Err(e) => {
                warn!(
                    "❌ [SIGNING-SECURE] Failed to deserialize transaction data payload: {}",
                    e
                );
                return RPCResponse::Ack;
            }
        };

        let (from, tx_bytes, intent_hash, transaction_type, request_id, msg_round) =
            match signing_message {
                SigningMessage::TransactionDataForFinalNode {
                    from,
                    round,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                } => (
                    from,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                    round,
                ),
                _ => {
                    warn!(
                    "❌ [SIGNING-SECURE] Received signing message that is not a transaction data payload"
                );
                    return RPCResponse::Ack;
                }
            };

        if msg_round != round {
            warn!(
                "⚠️ [SIGNING-SECURE] Round mismatch for transaction data: request round {}, message round {}",
                round, msg_round
            );
        }

        let result = if let Some(signing_node) = &mut self.signing_node {
            signing_node
                .handle_transaction_data_for_final_node(
                    from.clone(),
                    round,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                )
                .await
        } else {
            warn!("❌ [SIGNING-SECURE] Signing node not initialized to process transaction data");
            return RPCResponse::Ack;
        };

        match result {
            Ok(_) => RPCResponse::Ack,
            Err(e) => {
                warn!(
                    "❌ [SIGNING-SECURE] Failed to process transaction data for round {}: {}",
                    round, e
                );
                RPCResponse::Ack
            }
        }
    }

    /// Handle RequestCurrentVrfRound RPC request
    async fn handle_request_current_vrf_round(&self, _peer: PeerId) -> RPCResponse {
        let current_round = self
            .get_local_vrf_round_for_domain(VrfDomain::Signing, None)
            .await;

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

        let local_round = self
            .get_local_vrf_round_for_domain(VrfDomain::Signing, Some(&request.context))
            .await;
        self.store_peer_round_if_valid(
            VrfDomain::Signing,
            &request.context,
            peer,
            local_round,
            request.current_round,
        );

        RPCResponse::VrfRoundSync(VrfRoundSyncResponse {
            from: SerializablePeerId(self.local_peer_id),
            current_round: local_round,
            context: request.context,
        })
    }

    /// Handle RequestDatabaseSync RPC request
    async fn handle_request_database_sync(
        &self,
        _peer: PeerId,
        _requester_id: SerializablePeerId,
    ) -> RPCResponse {
        match self
            .db
            .count_entries_with_prefix_async(crate::database::keys::USER_REGISTRATION)
            .await
        {
            Ok(total_entries) => {
                let recommended_batch_size = 100; // Entries per batch
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
        _peer: PeerId,
        batch_index: usize,
        batch_size: usize,
    ) -> RPCResponse {
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
                let _addr_count = peer_info.addresses.len();
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
                            warn!(
                                "⚠️ [PEER_INFO] Failed to persist addr for {}: {}",
                                peer_id, e
                            );
                        }
                    }
                }
            }
            RPCResponse::GotAVSSShare { .. } => {}
            RPCResponse::DKGStarted { peer_id: _ } => {}
            RPCResponse::Error(err) => {
                warn!("Received error from peer {}: {}", peer, err);
            }
            RPCResponse::ShareAccepted => {}
            RPCResponse::CurrentVrfRoundResponse { current_round } => {
                let reference_round = self
                    .get_local_vrf_round_for_domain(VrfDomain::Signing, None)
                    .await;
                self.store_peer_round_if_valid(
                    VrfDomain::Signing,
                    "",
                    peer,
                    reference_round,
                    current_round,
                );
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
            RPCResponse::ECDSASignatureReceived { .. } => {}
            RPCResponse::BtcSignaturesReceived { .. } => {}
            RPCResponse::CriticalDeliveryAck {
                message_type,
                message_id,
            } => {
                let msg_type = match message_type.as_str() {
                    "TransactionIdBroadcast" => {
                        crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast
                    }
                    "VrfSelectedNodes" => {
                        crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes
                    }
                    _ => {
                        warn!(
                            "⚠️ [CRITICAL-UNICAST] Unknown message type in ACK: {}",
                            message_type
                        );
                        return Ok(());
                    }
                };

                let message_id_obj = crate::network::rpc::retry_manager::MessageId {
                    message_type: msg_type.clone(),
                    unique_id: message_id.clone(),
                };

                if let Some(retry_mgr) = &self.retry_manager {
                    match retry_mgr
                        .record_acknowledgment(&message_id_obj, peer)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {}
                        Err(e) => {
                            error!(
                                "❌ [CRITICAL-UNICAST] Failed to record acknowledgment: {}",
                                e
                            );
                        }
                    }
                }
            }
            other => {
                // Unhandled response type
                let _ = other;
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
        let mut batch_updates: Vec<(String, usize)> = Vec::new();

        // 1️⃣ First, merge all peers (no threshold updates yet)
        let mut new_peers_added = false;
        for (i, SerializablePeerId(p)) in peers.into_iter().enumerate() {
            // Add peer to node_manager if not already present
            if !self.node_manager.get_active_nodes().contains(&p) {
                self.node_manager
                    .add_node(p)
                    .map_err(|e| anyhow::anyhow!(e))?;
                new_peers_added = true; // Mark if any new peer was added
            }

            // 🔧 FIX: Update peer_indices mapping for ALL peers in the peer list
            // Priority: 1) Index from peer list, 2) Existing in peer_indices, 3) Load from database
            let index_to_use = if let Some(idx) = indices.get(i).cloned().flatten() {
                // Index provided in peer list - use it and persist to database
                Some(idx)
            } else if let Some(existing_idx) = self.peer_discovery.peer_indices.get(&p).cloned() {
                // Already in peer_indices - keep it
                Some(existing_idx)
            } else if let Some(db_idx) = self.get_index_from_db_async(&p).await {
                // Load from database if available
                Some(db_idx)
            } else {
                // No index available
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
                    self.peer_discovery
                        .peer_multiaddresses
                        .insert(p, addr.clone());
                    let key = peer_addr_key(&p.to_string());
                    if let Err(e) = self.db.put_string(&key, &addr.to_string()) {
                        warn!("⚠️ [PEER_LIST] Failed to persist addr for {}: {}", p, e);
                    }
                    if p != *self.get_local_peer_id() && !swarm.is_connected(&p) {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("⚠️ [PEER_LIST] Dial to {} failed: {}", p, e);
                        }
                    }
                } else {
                    warn!("⚠️ [PEER_LIST] Invalid multiaddr for {}: {}", p, addr_str);
                }
            }
        }

        // 2️⃣ Update threshold **only if new peers were added**
        if new_peers_added {
            let new_threshold = self.node_manager.get_threshold(); // Compute once
            if let Some(signing_node) = &mut self.signing_node {
                signing_node.set_threshold(new_threshold);
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

        // CRITICAL: Only use the peer_list_processed flag if DKG is NOT completed
        // This prevents duplicate processing ONLY during initial joining
        // After DKG completes, we can process PeerList responses again if needed
        let dkg_completed = self
            .dkg_node
            .as_ref()
            .map(|dkg| matches!(dkg.get_status(), DKGStatus::Completed))
            .unwrap_or(false);

        if !dkg_completed {
            // New node joining - check if we've already processed a PeerList
            if self.peer_discovery.peer_list_processed {
                return Ok(());
            }

            // Mark as processed for this joining session
            self.peer_discovery.peer_list_processed = true;
        }

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

            let has_dkg_data = dkg_node.get_final_secret_share().await.is_some();

            // Check if peer list includes nodes with assigned indices (indicates established network)
            let _peers_have_indices = !self.peer_discovery.peer_indices.is_empty();
            let _max_peer_index = self
                .peer_discovery
                .peer_indices
                .values()
                .max()
                .cloned()
                .unwrap_or(0);

            // Count connected peers (not including self)
            let _connected_peer_count = swarm.connected_peers().count();


            // NEW NODE DETECTION (more robust):
            // A node is a "new node joining established network" if:
            // 1. It has NO DKG data (no secret share)
            // 2. AND the network has 4+ total nodes (meaning 3 existing + this new one)
            //
            // IMPORTANT: We use `total >= 4` (not connected_peer_count) because:
            // - When we receive PeerList, we've already added those peers to node_manager
            // - But we might not be CONNECTED to all of them yet (dialing happens after)
            // - Initial 3-node DKG happens at EXACTLY total==3 (handled in swarm_events.rs)
            // - So if total >= 4 and we have no DKG data, we're definitely a new node joining
            let is_new_node_joining = !has_dkg_data && total >= 4;

            if is_new_node_joining {

                let connected_peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();

                // Find first connected peer for sync (excluding ourselves)
                let sync_peer = connected_peers
                    .iter()
                    .find(|pid| **pid != self.local_peer_id)
                    .cloned();

                let should_proceed = sync_peer.is_some();

                // CRITICAL: Check if this is a REJOINING node or a truly NEW node
                let new_node_index = if let Some(existing_index) =
                    self.get_index_from_db_async(&self.local_peer_id).await
                {
                    existing_index
                } else {
                    // This is a truly NEW node - assign max_index + 1
                    let all_assigned_indices: Vec<usize> =
                        self.peer_discovery.peer_indices.values().cloned().collect();
                    let max_index = all_assigned_indices.iter().max().cloned().unwrap_or(0);
                    max_index + 1
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
                if let Err(e) = self.sync_database_from_peer(swarm, sync_peer).await {
                    warn!("❌ [NEW_NODE] Failed to start database sync: {:?}", e);
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

        let reference_round = self
            .get_local_vrf_round_for_domain(VrfDomain::Signing, Some(&response.context))
            .await;
        if self.store_peer_round_if_valid(
            VrfDomain::Signing,
            &response.context,
            peer,
            reference_round,
            response.current_round,
        ) {
            // VRF round sync applied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MpcNetworkLayer;
    use crate::database::{Database, DatabaseConfig};
    use crate::network::transport::types::VrfDomain;
    use crate::node_selection::{BasicNodeManager, DefaultThresholdCalculator};
    use libp2p::PeerId;
    use tempfile::tempdir;

    async fn build_network_layer() -> MpcNetworkLayer {
        let temp_dir = tempdir().expect("tempdir to create");
        let db_path = temp_dir.path().join("db");
        let db = Database::new(DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            create_if_missing: true,
            max_open_files: 32,
            encryption_key: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
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

        let stored =
            layer.store_peer_round_if_valid(VrfDomain::Signing, "", peer, Some(5), Some(6));

        assert!(stored, "valid rounds should be stored");
        assert_eq!(
            layer
                .peer_rounds
                .get(&VrfDomain::Signing)
                .and_then(|ctx| ctx.get(""))
                .and_then(|rounds| rounds.get(&peer)),
            Some(&6)
        );
    }

    #[tokio::test]
    async fn ignores_peer_rounds_outside_allowed_skew() {
        let mut layer = build_network_layer().await;
        let peer = PeerId::random();

        let stored = layer.store_peer_round_if_valid(
            VrfDomain::Signing,
            "",
            peer,
            Some(1),
            Some(1 + super::MAX_VRF_ROUND_SKEW + 10),
        );

        assert!(layer
            .peer_rounds
            .get(&VrfDomain::Signing)
            .and_then(|ctx| ctx.get(""))
            .and_then(|rounds| rounds.get(&peer))
            .is_none());
        assert!(!stored, "out-of-range rounds should be rejected");
    }
}
