/// RPC Request/Response handlers
/// This module contains all the RPC request and response handling logic
use anyhow::Result;
use libp2p::gossipsub::{IdentTopic, Message};
use libp2p::PeerId;
use std::collections::HashSet;
use tracing::{error, info, warn};

use crate::database::key_utils::{self, peer_addr_key};
use crate::database::keys;
use crate::types::p2p::SerializablePeerId;
use crate::types::UserRegistration;
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
            RPCRequest::RequestStateSync { requester_id } => {
                self.handle_request_state_sync(peer, requester_id).await
            }
            RPCRequest::RequestStateSyncBatch {
                prefix,
                batch_index,
                batch_size,
            } => {
                self.handle_request_state_sync_batch(peer, prefix, batch_index, batch_size)
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
                        RPCResponse::Error(format!("Failed to handle critical message: {e}"))
                    }
                }
            }
            RPCRequest::RequestNoncePoolSync => {
                // Serve available (unconsumed) nonce tuples to a requesting observer node.
                if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    if let Some(nm) = node.nonce_manager() {
                        let nm_guard = nm.lock().await;
                        match nm_guard.get_available_tuples_for_sync().await {
                            Ok(tuples) => {
                                info!(
                                    "📤 [NONCE_SYNC] Serving {} nonce tuples to requesting peer",
                                    tuples.len()
                                );
                                RPCResponse::NoncePoolSync { tuples }
                            }
                            Err(e) => {
                                warn!("⚠️ [NONCE_SYNC] Failed to get nonce tuples: {}", e);
                                RPCResponse::NoncePoolSync { tuples: vec![] }
                            }
                        }
                    } else {
                        RPCResponse::NoncePoolSync { tuples: vec![] }
                    }
                } else {
                    RPCResponse::NoncePoolSync { tuples: vec![] }
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
                .and_then(|arc| arc.try_lock().ok())
                .and_then(|guard| guard.vrf_service().map(|svc| svc.context().to_string()))
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
                if let Some(arc) = &self.signing_node {
                    let signing_node = arc.lock().await;
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

    async fn get_vrf_storage_for_domain(
        &self,
        domain: VrfDomain,
        context: &str,
    ) -> Option<VrfStorage> {
        let context = self.resolve_context(domain, Some(context));

        match domain {
            VrfDomain::Signing => {
                // Prefer in-memory signing node round service if context matches
                if let Some(arc) = &self.signing_node {
                    let signing_node = arc.lock().await;
                    if let Some(vrf_service) = signing_node.vrf_service() {
                        if vrf_service.context() == context {
                            return vrf_service.storage();
                        }
                    }
                }

                // Fall back to db_signing_node round service
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
                // A node at round 0 has just started and has no established state.
                // Accept any peer round so it can catch up to the network's current round
                // via sync_rounds → update_round_from_peer_rounds (takes max).
                if reference == 0 {
                    return true;
                }
                // Only reject rounds that are too far BEHIND our reference.
                // Rounds ahead are always accepted — peers legitimately advance
                // while this node is offline or slow, and rejecting them causes
                // a permanent desync where a rejoining node can never catch up
                // (the gap never closes because both sides tick at the same rate).
                candidate_round >= reference.saturating_sub(MAX_VRF_ROUND_SKEW)
            })
            .unwrap_or(true)
    }

    pub(crate) async fn store_peer_round_if_valid(
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
                "⚠️ [SYNC] Received round sync without round value from {}",
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
            if let Some(vrf_storage) = self
                .get_vrf_storage_for_domain(domain, &normalized_context)
                .await
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
                "⚠️ [SYNC] Ignoring round {} from {} (reference: {:?}, skew limit: {})",
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

        // Include DKG signer count so observer nodes can filter HRW candidates
        let dkg_signer_count = if let Some(dkg_node) = &self.dkg_node {
            dkg_node.get_dkg_signer_count()
        } else {
            None
        };

        // Include vault group key so observer nodes can derive liquidity operator addresses
        let vault_group_key = if let Some(dkg_node) = &self.dkg_node {
            dkg_node.get_vault_group_key().await.map(|pk| {
                let affine: k256::AffinePoint = pk.into();
                crate::types::SerializablePoint(affine)
            })
        } else {
            None
        };

        // Include final public key (network group key) so observer nodes can derive network ETH/BTC addresses
        let final_public_key = if let Some(dkg_node) = &self.dkg_node {
            dkg_node.get_final_public_key().await.map(|pk| {
                let affine: k256::AffinePoint = pk.into();
                crate::types::SerializablePoint(affine)
            })
        } else {
            None
        };

        RPCResponse::PeerList {
            peers,
            indices,
            addresses,
            dkg_signer_count,
            vault_group_key,
            final_public_key,
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
            Ok(true) => RPCResponse::DKGShareReceived {
                from_node_id,
                receiver_node_id,
                share_index,
                success: true,
            },
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

        let (from, signature, msg_round, slot_id) = match signing_message {
            SigningMessage::ECDSASignature {
                from,
                signature,
                round,
                slot_id,
                ..
            } => (from, signature, round, slot_id),
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
        let result = if let Some(arc) = &self.signing_node {
            let mut signing_node = arc.lock().await;
            receiver_node_id = signing_node.get_node_id().to_string();
            signing_node
                .handle_signature_to_final_node(from.clone(), signature.clone(), round, slot_id)
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
            Ok(_) => RPCResponse::ECDSASignatureReceived {
                from_node_id,
                receiver_node_id,
                round,
                success: true,
            },
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
        let result = if let Some(arc) = &self.signing_node {
            let mut signing_node = arc.lock().await;
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
            Ok(_) => RPCResponse::BtcSignaturesReceived {
                from_node_id,
                receiver_node_id,
                round,
                success: true,
            },
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

        let (from, tx_bytes, intent_hash, transaction_type, request_id, msg_round, chain_tx_json, user_tics_address, batch_identifiers) =
            match signing_message {
                SigningMessage::TransactionDataForFinalNode {
                    from,
                    round,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                    chain_tx_json,
                    user_tics_address,
                    batch_identifiers,
                } => (
                    from,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                    round,
                    chain_tx_json,
                    user_tics_address,
                    batch_identifiers,
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

        let result = if let Some(arc) = &self.signing_node {
            let mut signing_node = arc.lock().await;
            signing_node
                .handle_transaction_data_for_final_node(
                    from.clone(),
                    round,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                    chain_tx_json,
                    user_tics_address,
                    batch_identifiers,
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
                "⚠️ [SYNC] Peer mismatch in round sync request: declared={}, actual={}",
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
        )
        .await;

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

    /// Safe prefixes for state sync (no DKG secrets, no user tweaked_secret_share, no node keypair).
    /// Covers: users, intents, pending/consensus/signing refs, peer invalidation, solver amounts,
    /// contract-call state (add_liquidity, withdraw_liquidity, claim_reward), peer addresses (PEER_ADDR),
    /// and node public keys for verification. Peer indices (PEER_INDEX) are not synced here—they are
    /// set on connection via GetPeerList response (handle_peer_list_response). In-memory withdraw/claim
    /// rounds and peer_invalidation_pending are sent in StateSyncMetadata and applied on the joiner.
    fn state_sync_prefixes() -> &'static [&'static str] {
        &[
            keys::USER_REGISTRATION,
            keys::INTENT_REGISTRY,
            keys::INTENT_TRANSACTION_IDS,
            keys::USER_INTENT_HASH,
            keys::INTENT_HASH_TO_USER,
            keys::INTENT_TARGET_AMOUNT,
            keys::PENDING_TRANSACTION,
            keys::TRANSACTION_STATUS,
            keys::CONSENSUS_ROUND,
            keys::CONSENSUS_RESULT,
            keys::SELECTED_NODES,
            keys::FINAL_NODE_ROUND,
            keys::PENDING_DISCONNECTION,
            keys::DISCONNECTION_STAGING,
            keys::SOLVER_AMOUNTS,
            keys::SOLVER_ADD_LIQUIDITY,
            keys::PENDING_WITHDRAW_LIQUIDITY,
            keys::PENDING_CLAIM_REWARD,
            keys::PEER_ADDR,
            keys::PUBLIC_KEY,
        ]
    }

    /// Handle RequestStateSync: return metadata (per-prefix counts + withdraw/claim_reward rounds).
    async fn handle_request_state_sync(
        &self,
        _peer: PeerId,
        _requester_id: SerializablePeerId,
    ) -> RPCResponse {
        let mut prefix_counts = Vec::with_capacity(Self::state_sync_prefixes().len());
        for prefix in Self::state_sync_prefixes() {
            match self.db.count_entries_with_prefix_async(prefix).await {
                Ok(count) => prefix_counts.push(((*prefix).to_string(), count)),
                Err(e) => {
                    error!("❌ [STATE_SYNC] Failed to count prefix {}: {}", prefix, e);
                    return RPCResponse::Error(format!("Failed to count prefix {prefix}: {e}"));
                }
            }
        }

        let (withdraw_rounds, claim_reward_rounds) = if let Some(arc) = &self.signing_node {
            let node = arc.lock().await;
            node.get_pending_rounds_for_sync().await
        } else {
            (Vec::new(), Vec::new())
        };

        let peer_invalidation_pending = self
            .peer_invalidation_pending
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();

        info!(
            "📦 [STATE_SYNC] Serving metadata: {} prefix(s), {} withdraw_rounds, {} claim_reward_rounds, {} peer_invalidation_pending",
            prefix_counts.len(),
            withdraw_rounds.len(),
            claim_reward_rounds.len(),
            peer_invalidation_pending.len()
        );

        RPCResponse::StateSyncMetadata {
            prefix_counts,
            withdraw_rounds,
            claim_reward_rounds,
            peer_invalidation_pending,
        }
    }

    /// Handle RequestStateSyncBatch: export a batch for one prefix; strip user tweaked_secret_share for USER_REGISTRATION.
    async fn handle_request_state_sync_batch(
        &self,
        _peer: PeerId,
        prefix: String,
        batch_index: usize,
        batch_size: usize,
    ) -> RPCResponse {
        let start = batch_index * batch_size;

        if prefix == keys::USER_REGISTRATION {
            // Export user batch with tweaked_secret_share stripped (no private data).
            match self
                .db
                .export_batch_with_prefix_async(keys::USER_REGISTRATION, start, batch_size)
                .await
            {
                Ok((entries, is_last_batch)) => {
                    let mut out = Vec::with_capacity(entries.len());
                    for (key, value) in entries {
                        match bincode::deserialize::<UserRegistration>(&value) {
                            Ok(mut user) => {
                                user.tweaked_secret_share = None;
                                match bincode::serialize(&user) {
                                    Ok(value_clean) => {
                                        out.push(crate::types::rpc::DatabaseEntry {
                                            key,
                                            value: value_clean,
                                        });
                                    }
                                    Err(e) => {
                                        error!("❌ [STATE_SYNC] Failed to serialize user: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("❌ [STATE_SYNC] Failed to deserialize user: {}", e);
                            }
                        }
                    }
                    RPCResponse::StateSyncBatch {
                        prefix,
                        batch_index,
                        entries: out,
                        is_last_batch,
                    }
                }
                Err(e) => {
                    error!("❌ [STATE_SYNC] Failed to export user batch: {}", e);
                    RPCResponse::Error(format!("Failed to export user batch: {e}"))
                }
            }
        } else if Self::state_sync_prefixes().iter().any(|p| *p == prefix.as_str()) {
            match self
                .db
                .export_batch_with_prefix_async(&prefix, start, batch_size)
                .await
            {
                Ok((entries, is_last_batch)) => {
                    let db_entries: Vec<crate::types::rpc::DatabaseEntry> = entries
                        .into_iter()
                        .map(|(key, value)| crate::types::rpc::DatabaseEntry { key, value })
                        .collect();
                    RPCResponse::StateSyncBatch {
                        prefix,
                        batch_index,
                        entries: db_entries,
                        is_last_batch,
                    }
                }
                Err(e) => {
                    error!("❌ [STATE_SYNC] Failed to export batch for {}: {}", prefix, e);
                    RPCResponse::Error(format!("Failed to export batch: {e}"))
                }
            }
        } else {
            RPCResponse::Error(format!("Unknown state sync prefix: {}", prefix))
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
                dkg_signer_count,
                vault_group_key,
                final_public_key,
            } => {
                // Store DKG signer count if provided (needed for HRW filtering on observer nodes)
                if let Some(count) = dkg_signer_count {
                    if let Some(dkg_node) = &self.dkg_node {
                        if dkg_node.get_dkg_signer_count().is_none() {
                            if let Err(e) = dkg_node.set_dkg_signer_count(count) {
                                warn!("⚠️ [PEER_LIST] Failed to store DKG signer count: {}", e);
                            } else {
                                info!("🔢 [PEER_LIST] Stored DKG signer count from peer: {}", count);
                            }
                        }
                        // Mark initial DKG as complete for this observer node so that
                        // future peer additions don't keep bumping the threshold
                        if !dkg_node.is_initial_dkg_complete().await {
                            if let Err(e) = dkg_node.mark_initial_dkg_complete().await {
                                warn!("⚠️ [PEER_LIST] Failed to set initial_dkg_complete: {}", e);
                            } else {
                                info!("✅ [PEER_LIST] Marked initial DKG as complete (dkg_signer_count={})", count);
                            }
                        }
                        // Fix signing threshold: observer nodes must use DKG signer threshold
                        // (dkg_signer_count / 2 + 1), NOT total_nodes / 2 + 1
                        let dkg_threshold = count / 2 + 1;
                        if let Some(arc) = &self.signing_node {
                            let mut signing_node = arc.lock().await;
                            signing_node.set_threshold(dkg_threshold);
                            info!("🔄 [THRESHOLD] Signing threshold set to {} (based on {} DKG signers)", dkg_threshold, count);
                        }
                    }
                    // Also update the NonceManager's dkg_signer_count so observer nodes
                    // use the correct stale-nonce filter (num_contributors >= dkg_signer_count).
                    if let Some(arc) = &self.signing_node {
                        let signing_node = arc.lock().await;
                        if let Some(nm) = signing_node.nonce_manager() {
                            let nm_guard = nm.lock().await;
                            nm_guard.update_dkg_signer_count(count);
                        }
                    }

                    // Request nonce pool sync from this peer if we're an observer node
                    // (no DKG share = observer that missed NonceTupleBroadcast during startup).
                    let needs_nonce_sync = if let Some(arc) = &self.signing_node {
                        let sn = arc.lock().await;
                        !sn.has_dkg_share().await
                    } else {
                        false
                    };
                    if needs_nonce_sync {
                        info!(
                            "🔄 [NONCE_SYNC] Requesting nonce pool sync from peer {}",
                            peer
                        );
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, RPCRequest::RequestNoncePoolSync);
                    }
                }

                // Store vault group key and derived liquidity operator addresses
                // (needed by observer nodes that joined after DKG for TICS UTV batch signing)
                if let Some(vgk) = vault_group_key {
                    let vault_pk = k256::ProjectivePoint::from(vgk.0);
                    if let Some(dkg_node) = &self.dkg_node {
                        // Only store if not already present (avoid overwriting DKG-derived data)
                        if dkg_node.get_vault_group_key().await.is_none() {
                            if let Err(e) = dkg_node.set_vault_group_key(vault_pk).await {
                                warn!("⚠️ [PEER_LIST] Failed to store vault group key: {}", e);
                            } else {
                                info!("🏦 [PEER_LIST] Stored vault group key from peer");
                            }

                            // Derive and store liquidity operator ETH/BTC addresses
                            let vault_eth = crate::utils::get_eth_address_from_group_key(vault_pk);
                            let vault_btc = crate::utils::get_btc_address_from_group_key(vault_pk);
                            if let Err(e) = dkg_node.set_liquidity_operator_addresses(&vault_eth, &vault_btc).await {
                                warn!("⚠️ [PEER_LIST] Failed to store liquidity operator addresses: {}", e);
                            } else {
                                info!("🏦 [PEER_LIST] Stored liquidity operator addresses (ETH: {}, BTC: {})", vault_eth, vault_btc);
                            }
                        }
                    }
                }

                // Store final public key (network group key) for deriving network ETH/BTC addresses
                // (needed by observer nodes for batch processing — BTC/ETH UTV, withdraw, claim-reward)
                if let Some(fpk) = final_public_key {
                    let network_pk = k256::ProjectivePoint::from(fpk.0);
                    if let Some(dkg_node) = &self.dkg_node {
                        if dkg_node.get_final_public_key().await.is_none() {
                            if let Err(e) = dkg_node.set_final_public_key(network_pk).await {
                                warn!("⚠️ [PEER_LIST] Failed to store final public key: {}", e);
                            } else {
                                let net_eth = crate::utils::get_eth_address_from_group_key(network_pk);
                                let net_btc = crate::utils::get_btc_address_from_group_key(network_pk);
                                info!("🔑 [PEER_LIST] Stored network group key from peer (ETH: {}, BTC: {})", net_eth, net_btc);
                            }
                        }
                    }
                }

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
                )
                .await;
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
            RPCResponse::StateSyncMetadata {
                prefix_counts,
                withdraw_rounds,
                claim_reward_rounds,
                peer_invalidation_pending,
            } => {
                if let Err(e) = self
                    .handle_state_sync_metadata(
                        swarm,
                        peer,
                        prefix_counts,
                        withdraw_rounds,
                        claim_reward_rounds,
                        peer_invalidation_pending,
                    )
                    .await
                {
                    error!("❌ [STATE_SYNC] Failed to handle metadata: {}", e);
                }
            }
            RPCResponse::StateSyncBatch {
                prefix,
                batch_index,
                entries,
                is_last_batch,
            } => {
                if let Err(e) = self
                    .handle_state_sync_batch(
                        swarm,
                        peer,
                        prefix,
                        batch_index,
                        entries,
                        is_last_batch,
                    )
                    .await
                {
                    error!("❌ [STATE_SYNC] Failed to handle batch: {}", e);
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
                    match retry_mgr.record_acknowledgment(&message_id_obj, peer).await {
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
            RPCResponse::NoncePoolSync { tuples } => {
                // Store received nonce tuples from a peer (observer or DKG node nonce pool sync).
                let count = tuples.len();
                if count > 0 {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        if let Some(nm) = node.nonce_manager() {
                            let nm_guard = nm.lock().await;
                            let mut stored = 0usize;
                            for tuple in tuples {
                                if let Err(e) = nm_guard.store_received_nonce_tuple(tuple).await {
                                    warn!("⚠️ [NONCE_SYNC] Failed to store synced nonce: {}", e);
                                } else {
                                    stored += 1;
                                }
                            }
                            info!(
                                "✅ [NONCE_SYNC] Stored {}/{} nonce tuples from peer {}",
                                stored, count, peer
                            );

                            // After sync, trigger pregenerate to fill any remaining gap.
                            // startup_pregenerate() checks if the pool already meets min_pool_size
                            // and skips if sufficient, so this is safe to call unconditionally.
                            if let Err(e) = nm_guard.startup_pregenerate().await {
                                warn!("⚠️ [NONCE_SYNC] Failed to trigger startup_pregenerate after sync: {}", e);
                            }
                        }
                    }
                } else {
                    info!("ℹ️ [NONCE_SYNC] Peer {} returned empty nonce pool", peer);
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

        // 2️⃣ Update threshold **only if new peers were added** and initial DKG is not yet complete
        // After initial DKG, threshold is fixed based on initial DKG participants only
        if new_peers_added {
          let initial_dkg_complete = if let Some(dkg_node) = &self.dkg_node {
                dkg_node.is_initial_dkg_complete().await
            } else {
                false
            };
            if !initial_dkg_complete {
                let new_threshold = self.node_manager.get_threshold();
                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    signing_node.set_threshold(new_threshold);
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

        // CRITICAL: Only use the peer_list_processed flag if DKG is NOT completed
        // This prevents duplicate processing ONLY during initial joining
        // After DKG completes, we can process PeerList responses again if needed
        let _dkg_completed = self
            .dkg_node
            .as_ref()
            .map(|dkg| matches!(dkg.get_status(), DKGStatus::Completed))
            .unwrap_or(false);

        // if !dkg_completed {
        // New node joining - check if we've already processed a PeerList
        if self.peer_discovery.peer_list_processed {
            return Ok(());
        }

        // Mark as processed for this joining session
        self.peer_discovery.peer_list_processed = true;
        // }

        // After learning about all peers, check if this is a new node joining existing network
        self.handle_new_node_joining_check(swarm).await?;

        Ok(())
    }

    /// Check if this is a new node joining an existing network
    async fn handle_new_node_joining_check(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        // Defense-in-depth: dialer-side self-check for pending invalidation.
        // Normally the listener disconnects blocked peers before they reach here,
        // but if we somehow got a PeerList response while our own invalidation is
        // pending, abort early — do not restore DKG state or sync nonces.
        {
            let self_solver_id = self.local_peer_id.to_string();
            let pending_key = format!(
                "{}{}",
                crate::database::keys::PENDING_DISCONNECTION,
                self_solver_id
            );
            if let Ok(Some(_)) = self.db.get_string::<String>(&pending_key) {
                warn!(
                    "🚫 [SELF_CHECK] This node has a pending invalidation — skipping node joining check until invalidation completes"
                );
                return Ok(());
            }
        }

        let total = self.node_manager.get_total_nodes();
        let threshold = self.node_manager.get_threshold();
        let new_node_index = self.resolve_new_node_index().await;

        let (should_sync, sync_peer_opt, _new_node_index_opt, needs_retry) = if let Some(dkg_node) =
            &mut self.dkg_node
        {
            dkg_node.update_node_params(total, threshold)?;
            let has_dkg_data = dkg_node.get_final_secret_share().await.is_some();

            if has_dkg_data {
                // Main DKG node restarting - preserve DKG shares and restore completed state
                info!(
                    "🔄 [RECONNECT] Main DKG node restarting with existing shares, total={} - restoring completed state",
                    total
                );
                match dkg_node.restore_completed_state().await {
                    Ok(()) => {
                        info!("✅ [RECONNECT] DKG state restored successfully - node can resume signing");

                        // Flush stale nonce pool: while this node was offline, other nodes
                        // may have consumed or invalidated nonces via NonceInvalidation
                        // messages. We have no way to know which nonces are still valid,
                        // so flush everything and request a fresh pool from a peer.
                        if let Some(arc) = &self.signing_node {
                            let node = arc.lock().await;
                            match node.flush_nonce_pool().await {
                                Ok(flushed) => {
                                    info!(
                                        "🗑️ [RECONNECT] Flushed {} stale nonces from pool",
                                        flushed
                                    );
                                }
                                Err(e) => {
                                    warn!("⚠️ [RECONNECT] Failed to flush nonce pool: {}", e);
                                }
                            }
                        }

                        // Still sync user database to catch registrations we missed while offline
                        let sync_peer = swarm
                            .connected_peers()
                            .find(|pid| **pid != self.local_peer_id)
                            .cloned();

                        // Request nonce pool sync from a peer to replace flushed nonces
                        if let Some(ref peer) = sync_peer {
                            info!(
                                "🔄 [NONCE_SYNC] DKG node requesting nonce pool sync from peer {} after restart",
                                peer
                            );
                            swarm
                                .behaviour_mut()
                                .request_response
                                .send_request(peer, RPCRequest::RequestNoncePoolSync);
                        }

                        (
                            sync_peer.is_some(),
                            sync_peer,
                            None,
                            false,
                        )
                    }
                    Err(e) => {
                        warn!("⚠️ [RECONNECT] Failed to restore DKG state (corrupt data?): {:?}", e);
                        (false, None, None, false)
                    }
                }
            } else if !has_dkg_data && total >= 4 {
                let sync_peer = swarm
                    .connected_peers()
                    .find(|pid| **pid != self.local_peer_id)
                    .cloned();
                let should_proceed = sync_peer.is_some();
                info!(
                    "🔢 [NEW_NODE] New node index: {} (from PeerList, DB, or first free slot)",
                    new_node_index
                );
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

        if should_sync {
            if let Some(sync_peer) = sync_peer_opt {
                if let Err(e) = self.sync_database_from_peer(swarm, sync_peer).await {
                    warn!("❌ [NEW_NODE] Failed to start database sync: {:?}", e);
                }
            }
        }

        Ok(())
    }

    /// Resolve this node's index when joining: use PeerList assignment, else DB, else first free slot.
    async fn resolve_new_node_index(&self) -> usize {
        let assigned = self
            .peer_discovery
            .peer_indices
            .get(&self.local_peer_id)
            .cloned();
        if let Some(idx) = assigned {
            return idx;
        }
        if let Some(idx) = self.get_index_from_db_async(&self.local_peer_id).await {
            return idx;
        }
        let other: HashSet<usize> = self
            .peer_discovery
            .peer_indices
            .iter()
            .filter(|(pid, _)| **pid != self.local_peer_id)
            .map(|(_, i)| *i)
            .collect();
        (1..).find(|k| !other.contains(k)).unwrap_or(1)
    }

    /// Handle CurrentVrfRoundResponse
    async fn handle_current_vrf_round_response(&mut self, current_round: Option<u64>) {
        if let Some(network_round) = current_round {
            // Simple round sync for both signing nodes
            if let Some(arc) = &self.signing_node {
                let mut signing_node = arc.lock().await;
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
                "⚠️ [SYNC] Peer mismatch in round sync response: declared={}, actual={}",
                response.from.0, peer
            );
        }

        let reference_round = self
            .get_local_vrf_round_for_domain(VrfDomain::Signing, Some(&response.context))
            .await;
        if self
            .store_peer_round_if_valid(
                VrfDomain::Signing,
                &response.context,
                peer,
                reference_round,
                response.current_round,
            )
            .await
        {
            // Round sync applied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // is_vrf_round_within_range – verifies the asymmetric skew fix
    // -----------------------------------------------------------------------

    #[test]
    fn none_reference_accepts_any_candidate() {
        // When a node has no established round, accept everything.
        assert!(MpcNetworkLayer::is_vrf_round_within_range(None, 0));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(None, 100));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(None, u64::MAX));
    }

    #[test]
    fn zero_reference_accepts_any_candidate() {
        // A node at round 0 just started — accept all peer rounds.
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(0), 0));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(0), 1));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(0), 500));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(0), u64::MAX));
    }

    #[test]
    fn candidate_within_skew_behind_is_accepted() {
        // Candidate is 1..MAX_VRF_ROUND_SKEW rounds behind reference → ok.
        let reference = 100;
        for behind in 0..=MAX_VRF_ROUND_SKEW {
            assert!(
                MpcNetworkLayer::is_vrf_round_within_range(Some(reference), reference - behind),
                "candidate {} should be accepted (reference {})",
                reference - behind,
                reference
            );
        }
    }

    #[test]
    fn candidate_too_far_behind_is_rejected() {
        // Candidate is more than MAX_VRF_ROUND_SKEW rounds behind → reject.
        let reference = 100;
        let too_far = reference - MAX_VRF_ROUND_SKEW - 1;
        assert!(
            !MpcNetworkLayer::is_vrf_round_within_range(Some(reference), too_far),
            "candidate {} should be rejected (reference {})",
            too_far,
            reference
        );
        assert!(!MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 0));
    }

    #[test]
    fn candidate_ahead_is_always_accepted() {
        // This is the key fix: rounds AHEAD must always be accepted so that
        // a rejoining node can catch up to peers that advanced while it was offline.
        let reference = 100;
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 101));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 110));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 200));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 1000));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), u64::MAX));
    }

    #[test]
    fn candidate_far_ahead_after_restart_scenario() {
        // Simulates the exact bug scenario: node restarts with stale round 310,
        // peers are at 375+. Previously rejected (gap > 10), now accepted.
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(310), 375));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(310), 500));
    }

    #[test]
    fn candidate_equal_to_reference_is_accepted() {
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(50), 50));
    }

    #[test]
    fn saturating_sub_prevents_underflow() {
        // reference=5, skew=10 → saturating_sub gives 0, so any candidate >= 0 accepted.
        let reference = 5u64;
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 0));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 1));
        assert!(MpcNetworkLayer::is_vrf_round_within_range(Some(reference), 5));
    }
}
