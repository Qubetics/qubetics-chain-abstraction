/// Gossipsub message handler
/// Handles all gossipsub message types: DKG, Signing, Command, Consensus, selection/round sync, etc.
///
/// NOTE: This module contains the gossipsub message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~2038-3559 of the original file
use anyhow::Result;
use ff::PrimeField;
use libp2p::{gossipsub::Message, PeerId};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::{
    database::key_utils,
    rpc_server::utils::{
        convert_src_smallest_to_dst_smallest, fetch_crypto_prices, fetch_network_balance,
    },
    signing::TicsSigner,
    types::{
        p2p::SerializablePeerId, signing::SigningMessage, vrf::VrfRoundSyncResponse,
        ChannelMessage, GossipsubMessage, IntentStatus,
    },
    utils::transaction::DUST_LIMIT_SATS,
};

use crate::network::transport::types::{MpcNetworkLayer, VrfDomain, TOPIC_CONSENSUS};

/// RocksDB record for pending solver_add_liquidity requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingAddLiquidityRecord {
    request_id: String,
    solver_id: String,
    solver_address: String,
    amount: String,
    chain_id: u64,
    signature: String,
    signed_payload: String,
    timestamp_ms: i64,
    /// Status: "Pending" (initial), "Batched" (included in a batch), "Completed" (tx submitted).
    status: String,
    /// Optional on-chain deposit tx hash associated with this liquidity add.
    #[serde(default)]
    tx_id: Option<String>,
}

const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";

/// Minimum TICS unclaimed to include in a claim batch (1 TICS = 10^18 wei).
const MIN_CLAIM_TICS_WEI: u64 = 1_000_000_000_000_000_000;

impl MpcNetworkLayer {
    /// Main gossipsub message handler - delegates to specific message type handlers
    pub(crate) async fn handle_gossipsub_message(&mut self, message: &Message) -> Result<()> {
        // Extract sender peer ID from message for security checks
        // Note: message.source is Option<PeerId> - we'll handle it in each match arm that needs it

        // Better error handling for message deserialization
        let msg = match serde_json::from_slice::<GossipsubMessage>(&message.data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to deserialize gossipsub message: {:?}", e);
                return Ok(()); // Continue processing other messages
            }
        };
        match msg {
            // this must be used by broadcast in dkg (sending end)
            // so, here it must match on the recieving end
            GossipsubMessage::DKG(dkg_msg) => {
                // Check if this is a NodeDisconnected message - handle it specially
                if let crate::protocols::DKGMessage::NodeDisconnected {
                    ref disconnected_node_id,
                    ref broadcaster_node_id,
                } = dkg_msg
                {
                    info!(
                        "📢 [DISCONNECT] Received disconnect broadcast: {} disconnected (from {})",
                        disconnected_node_id, broadcaster_node_id
                    );

                    // Parse the disconnected node ID
                    if let Ok(peer_id) = disconnected_node_id.parse::<PeerId>() {
                        // A node must never remove itself from its own active list.
                        // During reconnection, connection flapping + REJOIN_BLOCKED can
                        // cause a fresh disconnect broadcast about us while we are still alive.
                        if peer_id == self.local_peer_id {
                            warn!(
                                "📢 [DISCONNECT] Ignoring disconnect broadcast about ourselves ({}) from {} — we are still alive",
                                peer_id, broadcaster_node_id
                            );
                            return Ok(());
                        }

                        // Check if we haven't already processed this disconnect
                        if self.node_manager.get_active_nodes().contains(&peer_id) {
                            debug!("📢 [DISCONNECT] Processing disconnect for node {}", peer_id);
                            self.handle_node_disconnect_internal(peer_id).await;
                        } else {
                            debug!("📢 [DISCONNECT] Node {} already removed, skipping", peer_id);
                        }
                    }
                } else {
                    // dkg.r.2.1
                    // here we unwrapped the outer gossipmsg wrap from
                    // the msg bytes (check broadcast_shares() in dkg module)
                    if let Some(dkg_node) = &mut self.dkg_node {
                        let was_complete = dkg_node.is_initial_dkg_complete().await;

                        // now we can unwrap the internal dkg wrap to get the DKG related things
                        dkg_node
                            .handle_message(dkg_msg, self.node_manager.clone())
                            .await?;

                        // If DKG just completed, update NonceManager's dkg_signer_count
                        // so the stale-nonce filter works correctly from the start.
                        if !was_complete && dkg_node.is_initial_dkg_complete().await {
                            if let Some(count) = dkg_node.get_dkg_signer_count() {
                                if let Some(arc) = &self.signing_node {
                                    let signing_node = arc.lock().await;
                                    if let Some(nm) = signing_node.nonce_manager() {
                                        let nm_guard = nm.lock().await;
                                        nm_guard.update_dkg_signer_count(count);
                                        // This node completed DKG — it holds a secret share and
                                        // can participate in the commit-reveal nonce protocol.
                                        nm_guard.set_is_dkg_signer(true);
                                        info!("🔢 [DKG] Updated NonceManager dkg_signer_count={} and is_dkg_signer=true after DKG completion", count);
                                    }
                                }
                            }
                        }
                    }
                }
            }
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
            GossipsubMessage::Command(cmd) => {
                if let Some(cmd_processor) = self.command_processor.as_ref() {
                    cmd_processor.handle_message(cmd).await?;
                }
            }
            GossipsubMessage::Consensus(consensus_msg) => {
                // Handle consensus message in signing node
                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    signing_node
                        .handle_consensus_message(consensus_msg.clone())
                        .await?;
                }
            }
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
            GossipsubMessage::UserRegistration {
                tics_address,
                timestamp,
                node_id,
            } => {
                info!(
                    "👤 Received user registration via gossipsub: {} from node {} at {}",
                    tics_address, node_id, timestamp
                );

                // Process user registration locally (same pattern as deposit intent)
                if let Some(user_intent_manager) = &mut self.user_intent_manager {
                    // Get DKG secret share if available
                    let dkg_secret_share = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_secret_share().await
                    } else {
                        None
                    };

                    // Register the user locally
                    match user_intent_manager
                        .register_user(&tics_address, dkg_secret_share.as_ref(), &node_id)
                        .await
                    {
                        Ok(registration) => {
                            info!(
                                "✅ [GOSSIPSUB] Successfully registered user {} locally",
                                tics_address
                            );

                            // Log tweaked secret share status
                            if registration.tweaked_secret_share.is_some() {
                                debug!("🔑 [GOSSIPSUB] Computed and stored tweaked secret share for user: {}", tics_address);
                            } else {
                                info!("⚠️ [GOSSIPSUB] No tweaked secret share computed (DKG secret share not available) for user: {}", tics_address);
                            }

                            // Deterministically compute HMAC tweak and update commitments locally (primary path)
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(tweak_scalar) = k256::Scalar::from_repr_vartime(
                                    registration.hmac_constant.into(),
                                ) {
                                    match dkg_node
                                        .derive_user_specific_group_key_from_commitments(
                                            tweak_scalar,
                                        )
                                        .await
                                    {
                                        Ok(group_key) => {
                                            if let Err(e) = user_intent_manager
                                                .set_user_group_key(&tics_address, group_key)
                                                .await
                                            {
                                                warn!("❌ [GOSSIPSUB] Failed to store user group key for {}: {}", tics_address, e);
                                            } else {
                                                // Log the derived addresses
                                                if let Some(user) = user_intent_manager
                                                    .get_user_by_address(&tics_address)
                                                    .await
                                                {
                                                    if user.derived_eth_address.is_some() {
                                                        debug!("📬 [GOSSIPSUB] Derived TICS address stored for {}", tics_address);
                                                    }
                                                    if user.derived_btc_address.is_some() {
                                                        debug!("📬 [GOSSIPSUB] Derived BTC address stored for {}", tics_address);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("❌ [GOSSIPSUB] Failed to derive user-specific group key for {}: {}", tics_address, e);
                                        }
                                    }
                                }
                            } else {
                                warn!(
                                    "❌ [GOSSIPSUB] Invalid HMAC tweak scalar for {}",
                                    tics_address
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to register user {} locally: {}",
                                tics_address, e
                            );
                        }
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] User registry not available to handle user registration");
                }
            }
            GossipsubMessage::AdminRegistration {
                tics_address,
                timestamp,
                node_id,
            } => {
                info!(
                    "👤 Received admin registration via gossipsub: {} from node {} at {}",
                    tics_address, node_id, timestamp
                );

                if let Some(user_intent_manager) = &mut self.user_intent_manager {
                    let dkg_secret_share = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_secret_share().await
                    } else {
                        None
                    };

                    match user_intent_manager
                        .register_admin(&tics_address, dkg_secret_share.as_ref(), &node_id)
                        .await
                    {
                        Ok(registration) => {
                            info!(
                                "✅ [GOSSIPSUB] Successfully registered admin {} locally",
                                tics_address
                            );

                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(tweak_scalar) = k256::Scalar::from_repr_vartime(
                                    registration.hmac_constant.into(),
                                ) {
                                    match dkg_node
                                        .derive_user_specific_group_key_from_commitments(
                                            tweak_scalar,
                                        )
                                        .await
                                    {
                                        Ok(group_key) => {
                                            if let Err(e) = user_intent_manager
                                                .set_admin_group_key(&tics_address, group_key)
                                                .await
                                            {
                                                warn!("❌ [GOSSIPSUB] Failed to store admin group key for {}: {}", tics_address, e);
                                            } else {
                                                debug!("🔑 [GOSSIPSUB] Stored admin-specific group key and derived addresses for {}", tics_address);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("❌ [GOSSIPSUB] Failed to derive admin-specific group key for {}: {}", tics_address, e);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to register admin {} locally: {}",
                                tics_address, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "❌ [GOSSIPSUB] User registry not available to handle admin registration"
                    );
                }
            }
            GossipsubMessage::TransactionIdBroadcast {
                intent_hashes,
                transaction_id,
                transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction ID broadcast from node {}",
                    node_id
                );

                // Authenticate against the real libp2p sender, not the self-reported payload field.
                let sender_peer_id = match message.source {
                    Some(pid) => pid,
                    None => {
                        warn!(
                            "🚫 [SECURITY] Rejecting TransactionIdBroadcast: message has no source peer ID"
                        );
                        return Ok(());
                    }
                };

                let is_trusted_node = self
                    .node_manager
                    .get_active_nodes()
                    .contains(&sender_peer_id);
                if !is_trusted_node {
                    warn!(
                        "🚫 [SECURITY] Rejecting TransactionIdBroadcast: actual sender {} is not a trusted/active node",
                        sender_peer_id
                    );
                    return Ok(());
                }

                // Warn if payload node_id differs from the authenticated source (spoofing attempt).
                if let Ok(claimed_pid) = node_id.parse::<libp2p::PeerId>() {
                    if claimed_pid != sender_peer_id {
                        warn!(
                            "⚠️ [SECURITY] TransactionIdBroadcast payload node_id {} differs from actual sender {} — using actual sender",
                            node_id, sender_peer_id
                        );
                    }
                }

                info!(
                    "✅ [SECURITY] TransactionIdBroadcast authenticated from trusted node {}",
                    sender_peer_id
                );
                if !intent_hashes.is_empty() {
                    info!("🔗 [NETWORK] Intent hashes: {:?}", intent_hashes);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hashes or solver address supplied with transaction ID broadcast");
                }

                // Send acknowledgment for critical message
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
                    &GossipsubMessage::TransactionIdBroadcast {
                        intent_hashes: intent_hashes.clone(),
                        transaction_id: transaction_id.clone(),
                        transaction_type: transaction_type.clone(),
                        solver_address: solver_address.clone(),
                        node_id: node_id.clone(),
                    },
                )
                .await;

                // Process using shared handler
                if !intent_hashes.is_empty() {
                    for intent_hash in intent_hashes.iter() {
                        // Prefix "peerinv:round" (like add_liquidity "addliq:"): clear PENDING_DISCONNECTION for this batch
                        if intent_hash.starts_with("peerinv:") {
                            if let Some(round_str) = intent_hash.strip_prefix("peerinv:") {
                                if let Ok(_round_u64) = round_str.parse::<u64>() {
                                    // Get solver IDs from in-memory map (populated when PeerInvalidationBatch was received)
                                    let solver_ids_from_map = {
                                        let mut pending =
                                            self.peer_invalidation_pending.lock().await;
                                        pending.remove(round_str)
                                    };

                                    // Use in-memory map if available; otherwise fall back to scanning
                                    // all PENDING_DISCONNECTION keys from DB (covers restarts / timing gaps)
                                    let solver_ids_to_clear: Vec<String> = if let Some(ids) =
                                        solver_ids_from_map
                                    {
                                        ids
                                    } else {
                                        let prefix = crate::database::keys::PENDING_DISCONNECTION;
                                        let mut fallback_ids = Vec::new();
                                        if let Ok(all_keys) =
                                            self.db.get_keys_with_prefix_async(prefix).await
                                        {
                                            for key in &all_keys {
                                                // Key format: "pending_disconnection:{solver_id}"
                                                if let Some(solver_id) = key.strip_prefix(prefix) {
                                                    fallback_ids.push(solver_id.to_string());
                                                }
                                            }
                                        }
                                        if !fallback_ids.is_empty() {
                                            info!(
                                                "🔄 [PEER_INVALIDATION] In-memory map empty for round {}; found {} solver(s) from DB fallback scan",
                                                round_str, fallback_ids.len()
                                            );
                                        }
                                        fallback_ids
                                    };

                                    // Delete the PENDING_DISCONNECTION entry for each solver
                                    // so the solver is no longer blocked from rejoining and won't be picked up again
                                    if !solver_ids_to_clear.is_empty() {
                                        for solver_id in &solver_ids_to_clear {
                                            let pending_key = format!(
                                                "{}{}",
                                                crate::database::keys::PENDING_DISCONNECTION,
                                                solver_id
                                            );
                                            let _ = self.db.delete_string(&pending_key);
                                        }
                                        info!(
                                            "🧹 [PEER_INVALIDATION] Cleared PENDING_DISCONNECTION for {} solver(s) after tx confirmed (peerinv:{}), peers can now rejoin",
                                            solver_ids_to_clear.len(),
                                            round_str
                                        );
                                    }
                                }
                            }
                            continue;
                        }
                        // Check if this is an add_liquidity request_id (starts with "addliq:")
                        if intent_hash.starts_with("addliq:") {
                            // This is an add_liquidity request, mark as Completed
                            let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, intent_hash);
                            if let Ok(Some(mut record)) = self
                                .db
                                .get_string_async::<PendingAddLiquidityRecord>(&key)
                                .await
                            {
                                record.status = "Completed".to_string();
                                let _ = self.db.put_string_async(&key, &record).await;
                                info!(
                                    "✅ [ADD_LIQUIDITY] Marked request {} as Completed (tx: {})",
                                    intent_hash, transaction_id
                                );
                            }
                        } else {
                            // Regular intent, use existing handler
                            if let Err(e) = self
                                .handle_transaction_id_storage(
                                    intent_hash,
                                    &transaction_id,
                                    &transaction_type,
                                    &node_id,
                                    &sender_peer_id,
                                )
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to handle transaction ID storage for intent {}: {}",
                                    intent_hash, e
                                );
                            }
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [NETWORK] Transaction ID broadcast missing both intent hashes and solver address"
                    );
                }
            }
            GossipsubMessage::FinalNodeIdBroadcast {
                intent_hashes,
                final_node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received final node ID broadcast from node {}",
                    final_node_id
                );

                // Authenticate against the real libp2p sender, not the self-reported payload field.
                let actual_source = match message.source {
                    Some(pid) => pid,
                    None => {
                        warn!(
                            "🚫 [SECURITY] Rejecting FinalNodeIdBroadcast: message has no source peer ID"
                        );
                        return Ok(());
                    }
                };

                let is_trusted_node = self
                    .node_manager
                    .get_active_nodes()
                    .contains(&actual_source);
                if !is_trusted_node {
                    warn!(
                        "🚫 [SECURITY] Rejecting FinalNodeIdBroadcast: actual sender {} is not a trusted/active node",
                        actual_source
                    );
                    return Ok(());
                }

                // Warn if payload final_node_id differs from the authenticated source.
                if let Ok(claimed_pid) = final_node_id.parse::<libp2p::PeerId>() {
                    if claimed_pid != actual_source {
                        warn!(
                            "⚠️ [SECURITY] FinalNodeIdBroadcast payload final_node_id {} differs from actual sender {} — ignoring payload claim",
                            final_node_id, actual_source
                        );
                    }
                }

                info!(
                    "✅ [SECURITY] FinalNodeIdBroadcast authenticated from trusted node {}",
                    actual_source
                );
                if !intent_hashes.is_empty() {
                    info!("🔗 [NETWORK] Intent hashes: {:?}", intent_hashes);
                } else {
                    info!("ℹ️ [NETWORK] No intent hashes supplied with final node ID broadcast");
                }

                // Send acknowledgment for critical message
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::FinalNodeIdBroadcast,
                    &GossipsubMessage::FinalNodeIdBroadcast {
                        intent_hashes: intent_hashes.clone(),
                        final_node_id: final_node_id.clone(),
                    },
                )
                .await;

                // Process storage using user intent manager
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    for intent_hash in intent_hashes {
                        info!(
                            "💾 [NETWORK] Storing final_solver {} for intent {}",
                            final_node_id, intent_hash
                        );
                        if let Err(e) = user_intent_manager
                            .store_final_solver(&intent_hash, &final_node_id)
                            .await
                        {
                            error!(
                                "❌ [NETWORK] Failed to store final solver for intent {}: {}",
                                intent_hash, e
                            );
                        }
                    }
                } else {
                    warn!("⚠️ [NETWORK] User intent manager not available, could not store final node ID");
                }
            }
            GossipsubMessage::TransactionErrorBroadcast {
                intent_hashes,
                error_message,
                transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction error broadcast from node {} (type: {})",
                    node_id, transaction_type
                );
                if !intent_hashes.is_empty() {
                    info!("🔗 [NETWORK] Identifiers: {} item(s)", intent_hashes.len());
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hashes or solver address supplied with transaction error broadcast");
                }

                // Handle add_liquidity failures - no status update needed
                // Since we only have "Pending" and "Completed", failed requests are already "Pending"
                // They will automatically retry in the next TICS cycle
                if !intent_hashes.is_empty() {
                    for h in &intent_hashes {
                        if h.starts_with("addliq:") {
                            warn!(
                                "⚠️ [ADD_LIQUIDITY] Request {} failed (error: {}), will retry in next cycle (status remains 'Pending')",
                                h, error_message
                            );
                        }
                    }
                }

                // --- Revert string-status pending requests (withdraw, claim_reward, claim_platform_fee) ---
                // Identifiers are encoded as "request_id|solver_address" in the intent_hashes field.
                let tx_type = transaction_type.as_str();
                if tx_type == "withdraw_liquidity"
                    || tx_type == "claim_reward"
                    || tx_type == "claim_platform_fee"
                {
                    use crate::types::rpc_server::{
                        PendingClaimPlatformFeeRequest, PendingClaimRewardRequest,
                        PendingWithdrawRequest,
                    };
                    let db_prefix = match tx_type {
                        "withdraw_liquidity" => "pending_withdraw_liquidity:",
                        "claim_reward" => "pending_claim_reward:",
                        "claim_platform_fee" => "pending_claim_platform_fee:",
                        _ => unreachable!(),
                    };

                    // If we have specific identifiers, revert only those. Otherwise
                    // revert all Batched (no tx_id) records for the solver.
                    if !intent_hashes.is_empty() {
                        for ident in &intent_hashes {
                            if ident.starts_with("addliq:") || ident.starts_with("peerinv:") {
                                continue;
                            }
                            // Try to extract request_id from "request_id|solver" format
                            let req_id = if let Some((id, _)) = ident.split_once('|') {
                                id
                            } else {
                                ident.as_str()
                            };

                            // Scan DB for matching request and revert if Batched (never Completed/Failed)
                            match tx_type {
                                "withdraw_liquidity" => {
                                    let entries: Vec<(String, PendingWithdrawRequest)> = self
                                        .db
                                        .get_values_with_prefix(db_prefix)
                                        .unwrap_or_default();
                                    for (key, req) in entries {
                                        if req.request_id == req_id
                                            && req.status == "Batched"
                                            && req.tx_id.is_none()
                                        {
                                            let mut reverted = req.clone();
                                            reverted.status = "Pending".to_string();
                                            if let Err(e) = self.db.put_string(&key, &reverted) {
                                                warn!("⚠️ [NETWORK] Failed to revert withdraw {} to Pending: {}", req_id, e);
                                            } else {
                                                info!("🔄 [NETWORK] Reverted withdraw {} to Pending (synced from node {})", req_id, node_id);
                                            }
                                        }
                                    }
                                }
                                "claim_reward" => {
                                    let entries: Vec<(String, PendingClaimRewardRequest)> = self
                                        .db
                                        .get_values_with_prefix(db_prefix)
                                        .unwrap_or_default();
                                    for (key, req) in entries {
                                        if req.request_id == req_id
                                            && req.status == "Batched"
                                            && req.tx_id.is_none()
                                        {
                                            let mut reverted = req.clone();
                                            reverted.status = "Pending".to_string();
                                            if let Err(e) = self.db.put_string(&key, &reverted) {
                                                warn!("⚠️ [NETWORK] Failed to revert claim_reward {} to Pending: {}", req_id, e);
                                            } else {
                                                info!("🔄 [NETWORK] Reverted claim_reward {} to Pending (synced from node {})", req_id, node_id);
                                            }
                                        }
                                    }
                                }
                                "claim_platform_fee" => {
                                    let entries: Vec<(String, PendingClaimPlatformFeeRequest)> =
                                        self.db
                                            .get_values_with_prefix(db_prefix)
                                            .unwrap_or_default();
                                    for (key, req) in entries {
                                        if req.request_id == req_id
                                            && req.status == "Batched"
                                            && req.tx_id.is_none()
                                        {
                                            let mut reverted = req.clone();
                                            reverted.status = "Pending".to_string();
                                            if let Err(e) = self.db.put_string(&key, &reverted) {
                                                warn!("⚠️ [NETWORK] Failed to revert claim_platform_fee {} to Pending: {}", req_id, e);
                                            } else {
                                                info!("🔄 [NETWORK] Reverted claim_platform_fee {} to Pending (synced from node {})", req_id, node_id);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    } else if let Some(solver) = &solver_address {
                        // No specific identifiers — revert ALL Batched records for this solver
                        match tx_type {
                            "withdraw_liquidity" => {
                                let entries: Vec<(String, PendingWithdrawRequest)> = self
                                    .db
                                    .get_values_with_prefix(db_prefix)
                                    .unwrap_or_default();
                                for (key, req) in entries {
                                    if req.solver_address.to_lowercase() == solver.to_lowercase()
                                        && req.status == "Batched"
                                        && req.tx_id.is_none()
                                    {
                                        let mut reverted = req.clone();
                                        reverted.status = "Pending".to_string();
                                        if let Err(e) = self.db.put_string(&key, &reverted) {
                                            warn!("⚠️ [NETWORK] Failed to revert withdraw {} to Pending: {}", req.request_id, e);
                                        } else {
                                            info!("🔄 [NETWORK] Reverted withdraw {} to Pending for solver {} (synced from node {})", req.request_id, solver, node_id);
                                        }
                                    }
                                }
                            }
                            "claim_reward" => {
                                let entries: Vec<(String, PendingClaimRewardRequest)> = self
                                    .db
                                    .get_values_with_prefix(db_prefix)
                                    .unwrap_or_default();
                                for (key, req) in entries {
                                    if req.solver_address.to_lowercase() == solver.to_lowercase()
                                        && req.status == "Batched"
                                        && req.tx_id.is_none()
                                    {
                                        let mut reverted = req.clone();
                                        reverted.status = "Pending".to_string();
                                        if let Err(e) = self.db.put_string(&key, &reverted) {
                                            warn!("⚠️ [NETWORK] Failed to revert claim_reward {} to Pending: {}", req.request_id, e);
                                        } else {
                                            info!("🔄 [NETWORK] Reverted claim_reward {} to Pending for solver {} (synced from node {})", req.request_id, solver, node_id);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // --- Revert IntentStatus-based intents (user_to_vault, network_to_target, etc.) ---
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if !intent_hashes.is_empty() {
                        for h in &intent_hashes {
                            // Skip non-intent identifiers
                            if h.starts_with("addliq:")
                                || h.starts_with("peerinv:")
                                || h.contains('|')
                            {
                                continue;
                            }

                            if let Err(e) = user_intent_manager
                                .store_transaction_error(h, &error_message, Some(&node_id))
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to store synchronized transaction error for {}: {}",
                                    h, e
                                );
                            }

                            // Revert intent from Batched back to Pending so all nodes
                            // stay in sync and the intent can be re-batched next cycle.
                            // NEVER revert from Solved — that is a terminal state.
                            if let Some(user) = user_intent_manager.get_user_by_intent_hash(h).await
                            {
                                let current_status = user_intent_manager
                                    .get_intent_status(&user.tics_address, h)
                                    .await;
                                if matches!(current_status, Some(IntentStatus::Solved)) {
                                    debug!(
                                        "⏭️ [NETWORK] Skipping revert for intent {} — already Solved",
                                        h
                                    );
                                    continue;
                                }
                                let new_status = if transaction_type == "intent_rejected" {
                                    IntentStatus::Rejected
                                } else {
                                    IntentStatus::Pending
                                };

                                if let Err(e) = user_intent_manager
                                    .update_intent_status(&user.tics_address, h, new_status.clone())
                                    .await
                                {
                                    warn!(
                                        "⚠️ [NETWORK] Failed to transition intent {} to {:?}: {}",
                                        h, new_status, e
                                    );
                                } else {
                                    info!(
                                        "🔄 [NETWORK] Transitioned intent {} to {:?} for user {} (synced from node {})",
                                        h, new_status, user.tics_address, node_id
                                    );
                                }
                            }
                        }
                    } else if solver_address.is_none() {
                        warn!("⚠️ [NETWORK] Transaction error broadcast missing both intent hashes and solver address");
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction error");
                }
            }
            GossipsubMessage::PeerInvalidationDeleted { solver_id, node_id } => {
                info!(
                    "🧹 [PEER_INVALIDATION] Received PeerInvalidationDeleted from node {}: cleaning up solver {}",
                    node_id, solver_id
                );
                let staging_key = format!("pending_disconnection:{}", solver_id);
                if let Err(e) = self.db.delete_string(&staging_key) {
                    warn!(
                        "⚠️ [PEER_INVALIDATION] Failed to delete {} upon receiving PeerInvalidationDeleted: {}",
                        staging_key, e
                    );
                } else {
                    info!(
                        "✅ [PEER_INVALIDATION] Successfully removed {} after receiving PeerInvalidationDeleted",
                        staging_key
                    );
                }
            }
            GossipsubMessage::DepositIntent {
                intent,
                intent_id: _intent_id,
                user_tics_address,
                amount: _,
                signature,
            } => {
                // user_tics_address is now mandatory (not Option)
                let user_eth_addr = user_tics_address;

                // Calculate intent hash from the intent (valid intent = same hash as RPC originator)
                let intent_hash = match crate::utils::calculate_intent_hash(&intent) {
                    Ok(hash) => hash,
                    Err(e) => {
                        warn!(
                            "❌ [GOSSIPSUB] Failed to calculate intent hash (invalid intent): {}",
                            e
                        );
                        return Ok(());
                    }
                };
                info!("🔐 [GOSSIPSUB] Calculated intent hash: {}", intent_hash);

                // Validate intent: source/target chain must match token and address type (TICS vs BTC)
                if let Err(e) =
                    crate::utils::intent_validation::validate_intent_chains_tokens_addresses(
                        &intent,
                    )
                {
                    warn!(
                        "⚠️ [GOSSIPSUB] Rejecting DepositIntent - chain/token/address validation failed: {} (intent hash: {})",
                        e, intent_hash
                    );
                    return Ok(());
                }

                // CRITICAL: Reject duplicate intent hash immediately - do no further processing (no signature verify, no user lookup).
                let user_intent_manager = match &self.user_intent_manager {
                    Some(uim) => uim,
                    None => {
                        warn!("❌ [GOSSIPSUB] User intent manager not available - cannot validate deposit intent");
                        return Ok(());
                    }
                };
                if user_intent_manager.get_intent(&intent_hash).await.is_some() {
                    warn!(
                        "⚠️ [GOSSIPSUB] Rejecting DepositIntent - intent hash {} already exists (duplicate); no processing",
                        intent_hash
                    );
                    return Ok(());
                }

                // CRITICAL (protocol): Signature is mandatory at gossip level; verify recovered signer matches claimed user.
                let signature = match signature.as_ref() {
                    Some(s) => s.as_str(),
                    None => {
                        warn!(
                            "⚠️ [GOSSIPSUB] Rejecting DepositIntent - signature required for gossip verification (intent hash: {})",
                            intent_hash
                        );
                        return Ok(());
                    }
                };
                // Deposit intent is the message: same serialization the client signed.
                let intent_bytes: Vec<u8> = match serde_json::to_string(&intent) {
                    Ok(s) => s.into_bytes(),
                    Err(e) => {
                        warn!("❌ [GOSSIPSUB] Failed to serialize intent for signature verification: {}", e);
                        return Ok(());
                    }
                };
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                let (compact, v) = match normalize_eth_signature(signature) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            "⚠️ [GOSSIPSUB] Invalid signature format for DepositIntent {}: {}",
                            intent_hash, e
                        );
                        return Ok(());
                    }
                };
                let recovered_signer = match recover_eth_address_secp(
                    &intent_bytes,
                    &compact,
                    v,
                    true,
                ) {
                    Ok(addr) => addr,
                    Err(e1) => match recover_eth_address_secp(&intent_bytes, &compact, v, false) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            warn!(
                                "⚠️ [GOSSIPSUB] Failed to recover signer for DepositIntent {}: personal_sign={}, raw={}",
                                intent_hash, e1, e2
                            );
                            return Ok(());
                        }
                    },
                };
                if recovered_signer.to_lowercase() != user_eth_addr.to_lowercase() {
                    warn!(
                        "⚠️ [GOSSIPSUB] Rejecting DepositIntent - signature signer {} does not match claimed user {}",
                        recovered_signer, user_eth_addr
                    );
                    return Ok(());
                }

                // CRITICAL (protocol): Only accept deposit intents for registered users.
                if user_intent_manager
                    .get_user_by_address(&user_eth_addr)
                    .await
                    .is_none()
                {
                    warn!(
                        "⚠️ [GOSSIPSUB] Rejecting DepositIntent - user {} is not registered (valid intent requires registered user)",
                        user_eth_addr
                    );
                    return Ok(());
                }

                // CRITICAL: Check if user has sufficient balance on source chain before accepting intent
                info!(
                    "💰 [GOSSIPSUB] Checking source address balance for intent: {} (amount: {})",
                    intent_hash, intent.amount
                );

                let source_amount = match intent.amount.trim().parse::<u128>() {
                    Ok(a) if a > 0 => a,
                    Ok(_) => {
                        warn!(
                            "⚠️ [GOSSIPSUB] Rejecting DepositIntent {} - amount is zero",
                            intent_hash
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!(
                            "❌ [GOSSIPSUB] Invalid amount format in intent {}: {}",
                            intent_hash, e
                        );
                        return Ok(());
                    }
                };

                // Determine blockchain for balance check
                let source_blockchain = if intent.source_chain.eq_ignore_ascii_case("btc")
                    || intent.source_chain.eq_ignore_ascii_case("bitcoin")
                {
                    "btc"
                } else {
                    "eth"
                };

                // Calculate required balance: amount + dynamic buffer + estimated tx fee
                let fee_bps = crate::contract::fetch_dynamic_fee_bps().await;
                let dynamic_fee_buffer = (source_amount * fee_bps) / 10000;
                let estimated_tx_fee: u128 = if source_blockchain == "btc" {
                    let fee_rate = std::env::var("BTC_FEE_RATE_SAT_VB")
                        .ok()
                        .and_then(|v| v.parse::<u128>().ok())
                        .unwrap_or(2);
                    208 * fee_rate
                } else {
                    300_000_000_000_000u128 // gas_limit=300k * gas_price=1 Gwei
                };
                let required_balance = source_amount + dynamic_fee_buffer + estimated_tx_fee;

                // Fetch user's source address balance
                match fetch_network_balance(&intent.source_address, source_blockchain).await {
                    Ok(user_balance) => {
                        if user_balance < required_balance {
                            warn!(
                                "⚠️ [GOSSIPSUB] Insufficient source balance for intent {}: user has {}, needs {} (amount {} + 5% {} + fee {})",
                                intent_hash, user_balance, required_balance,
                                source_amount, dynamic_fee_buffer, estimated_tx_fee
                            );
                            return Ok(());
                        } else {
                            info!(
                                "✅ [GOSSIPSUB] Source address has sufficient balance: {} >= {}",
                                user_balance, required_balance
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ [GOSSIPSUB] Failed to fetch source address balance for {}: {}",
                            intent_hash, e
                        );
                        return Ok(());
                    }
                }

                // BTC source dust check: reject if BTC source amount is below dust limit
                let src_is_btc = intent.source_chain.eq_ignore_ascii_case("btc")
                    || intent.source_chain.eq_ignore_ascii_case("bitcoin");
                if src_is_btc && source_amount < (DUST_LIMIT_SATS as u128) {
                    warn!(
                        "⚠️ [GOSSIPSUB] BTC-source intent {} below dust limit: {} satoshis (min {})",
                        intent_hash, source_amount, DUST_LIMIT_SATS
                    );
                    return Ok(());
                }

                // BTC source: verify user has enough *confirmed* UTXOs (total balance may include unconfirmed)
                if src_is_btc {
                    let is_testnet = crate::types::network::network_type().is_testnet();
                    match crate::utils::transaction::fetch_bitcoin_utxos(
                        &intent.source_address,
                        is_testnet,
                    )
                    .await
                    {
                        Ok(utxos) => {
                            let confirmed_balance: u128 = utxos
                                .iter()
                                .filter(|u| u.status.confirmed)
                                .map(|u| u.value as u128)
                                .sum();
                            if confirmed_balance < required_balance {
                                warn!(
                                    "⚠️ [GOSSIPSUB] Insufficient confirmed UTXOs for intent {}: confirmed {} sats, needs {}",
                                    intent_hash, confirmed_balance, required_balance
                                );
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [GOSSIPSUB] Failed to fetch UTXOs for BTC source address {}: {}",
                                intent.source_address, e
                            );
                            return Ok(());
                        }
                    }
                }

                // Each node: fetch prices, compute target amount; store only when network has sufficient funds
                const MIN_BTC_INTENT_SATS: u128 = 550;
                let parsed_amount = match intent.amount.parse::<u128>() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(
                            "❌ [GOSSIPSUB] Invalid intent amount for {}: {}",
                            intent_hash, e
                        );
                        return Ok(());
                    }
                };
                // Same-chain (TICS->TICS or BTC->BTC): use original RPC amount as target and store it by intent hash
                let is_same_chain = {
                    let src_tics = intent.source_chain.eq_ignore_ascii_case("tics")
                        || intent.source_chain.eq_ignore_ascii_case("qubetics");
                    let dst_tics = intent.target_chain.eq_ignore_ascii_case("tics")
                        || intent.target_chain.eq_ignore_ascii_case("qubetics");
                    let src_btc = intent.source_chain.eq_ignore_ascii_case("btc")
                        || intent.source_chain.eq_ignore_ascii_case("bitcoin");
                    let dst_btc = intent.target_chain.eq_ignore_ascii_case("btc")
                        || intent.target_chain.eq_ignore_ascii_case("bitcoin");
                    (src_tics && dst_tics) || (src_btc && dst_btc)
                };
                let target_amount = if is_same_chain {
                    parsed_amount
                } else {
                    let prices = match fetch_crypto_prices(Some(intent.timestamp)).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to fetch prices for target amount: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
                    match convert_src_smallest_to_dst_smallest(
                        parsed_amount,
                        &intent.source_chain,
                        &intent.target_chain,
                        &prices,
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to convert target amount for {}: {:?}",
                                intent_hash, e
                            );
                            return Ok(());
                        }
                    }
                };

                let is_tics_to_btc = (intent.source_chain.eq_ignore_ascii_case("tics")
                    || intent.source_chain.eq_ignore_ascii_case("qubetics"))
                    && (intent.target_chain.eq_ignore_ascii_case("btc")
                        || intent.target_chain.eq_ignore_ascii_case("bitcoin"));
                if is_tics_to_btc && target_amount < MIN_BTC_INTENT_SATS {
                    warn!(
                        "⚠️ [GOSSIPSUB] TICS->BTC intent {} below minimum: {} satoshis (min {})",
                        intent_hash, target_amount, MIN_BTC_INTENT_SATS
                    );
                    return Ok(());
                }

                // TICS target detection for treasury vault checks.
                let dst_is_tics = intent.target_chain.eq_ignore_ascii_case("tics")
                    || intent.target_chain.eq_ignore_ascii_case("qubetics")
                    || intent.target_chain.eq_ignore_ascii_case("evm");

                // Check network balance for target chain:
                // - *->TICS: Treasury Vault contract balance (TICS payouts come from vault).
                // - *->BTC: DKG BTC address balance.
                let network_address = if dst_is_tics {
                    crate::env_defaults::treasury_vault_contract_address()
                } else if let Some(dkg_node) = &self.dkg_node {
                    match dkg_node.get_final_public_key().await {
                        Some(final_public) => {
                            if intent.target_chain.eq_ignore_ascii_case("btc")
                                || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                            {
                                match crate::utils::get_btc_address_from_group_key(final_public) {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        warn!("⚠️ [GOSSIP] Failed to derive network BTC address: {}", e);
                                        String::new()
                                    }
                                }
                            } else {
                                crate::utils::get_eth_address_from_group_key(final_public)
                            }
                        }
                        None => String::new(),
                    }
                } else {
                    String::new()
                };

                let has_sufficient_funds = if !network_address.is_empty() {
                    let blockchain = if intent.target_chain.eq_ignore_ascii_case("btc")
                        || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                    {
                        "btc"
                    } else {
                        "eth"
                    };
                    match fetch_network_balance(&network_address, blockchain).await {
                        Ok(network_balance) => {
                            if network_balance < target_amount {
                                warn!(
                                    "⚠️ [GOSSIPSUB] Insufficient network balance for intent {}: have {}, need {}",
                                    intent_hash, network_balance, target_amount
                                );
                                false
                            } else {
                                true
                            }
                        }
                        Err(e) => {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to fetch network balance for {}: {}",
                                intent_hash, e
                            );
                            false
                        }
                    }
                } else {
                    false
                };

                // If funds are not sufficient, reject the intent completely (do not store).
                if !has_sufficient_funds {
                    return Ok(());
                }

                // At this point the intent is accepted. Enforce invariant:
                // if the intent is stored, its target_amount must also be stored.
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_intent_target_amount(&intent_hash, target_amount)
                        .await
                    {
                        warn!(
                            "❌ [GOSSIPSUB] Failed to store target amount for {}: {}. Rejecting intent.",
                            intent_hash, e
                        );
                        return Ok(());
                    }

                    // Only after successfully storing target_amount do we persist the intent itself.
                    if let Ok(intent_hash_bytes) = hex::decode(&intent_hash) {
                        if let Err(e) = user_intent_manager
                            .store_intent_hash(intent_hash_bytes, &user_eth_addr, &intent)
                            .await
                        {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to store intent hash {}: {}",
                                intent_hash, e
                            );
                            return Ok(());
                        }
                    } else {
                        warn!("❌ [GOSSIPSUB] Invalid intent hash format: {}", intent_hash);
                        return Ok(());
                    }

                    info!(
                        "💾 [GOSSIPSUB] Stored target amount {} and intent {} (network has sufficient funds)",
                        target_amount, intent_hash
                    );
                }

                // At this stage, the intent has been fully validated, stored, and its target
                // amount persisted. To align with withdraw/claim flows, we *do not* immediately
                // create or sign a UserToVault transaction here. Instead, the intent remains
                // in Pending status and will be picked up by the dedicated processing flow.
                info!(
                    "⏸️ [GOSSIPSUB] Deposit intent {} marked as Pending; skipping immediate UserToVault processing",
                    intent_hash
                );

                return Ok(());
            }
            GossipsubMessage::SolverAddLiquidity {
                request_id,
                solver_id,
                solver_address,
                amount,
                chain_id,
                signature,
                signed_payload,
                timestamp_ms,
                status,
                tx_id,
            } => {
                info!(
                    "💧 [ADD_LIQUIDITY] Received solver_add_liquidity gossip: request_id={}, solver_id={}, solver_address={}, amount={}, chain_id={}",
                    request_id, solver_id, solver_address, amount, chain_id
                );

                // Validate chainId before persisting (must match RPC rules: 0 = BTC, TICS chain ID = EVM).
                let tics_chain_id = crate::env_defaults::mpc_tics_chain_id();
                if chain_id != 0 && chain_id != tics_chain_id {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Unsupported chain_id {} for request_id={}, dropping (allowed: 0=BTC, {}=EVM)",
                        chain_id, request_id, tics_chain_id
                    );
                    return Ok(());
                }

                // Re-verify signature using VERIFICATION_ADDRESS before accepting into local queue.
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                let verification_address = crate::env_defaults::verification_address();
                if verification_address.is_empty() {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] VERIFICATION_ADDRESS not configured; dropping request"
                    );
                    return Ok(());
                }

                // Validate request_id is non-empty
                if request_id.trim().is_empty() {
                    warn!("⚠️ [ADD_LIQUIDITY] Empty request_id in gossip, dropping",);
                    return Ok(());
                }

                // Expect the signed_payload to be the raw message bytes that were signed.
                let msg_bytes = signed_payload.as_bytes();
                if msg_bytes.is_empty() {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Empty signed_payload for request_id={}, dropping",
                        request_id
                    );
                    return Ok(());
                }

                match amount.trim().parse::<u128>() {
                    Ok(a) if a > 0 => {} // valid
                    Ok(_) => {
                        warn!(
                            "⚠️ [ADD_LIQUIDITY] Zero amount for request_id={}, dropping",
                            request_id
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("⚠️ [ADD_LIQUIDITY] Invalid amount '{}' for request_id={}: {}, dropping", amount, request_id, e);
                        return Ok(());
                    }
                }

                // Validate solver_id is non-empty
                if solver_id.trim().is_empty() {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Empty solver_id for request_id={}, dropping",
                        request_id
                    );
                    return Ok(());
                }

                // Validate solver_address is a valid Ethereum address format (0x + 40 hex chars)
                if !solver_address.starts_with("0x")
                    || solver_address.len() != 42
                    || !solver_address[2..].chars().all(|c| c.is_ascii_hexdigit())
                {
                    warn!("⚠️ [ADD_LIQUIDITY] Invalid solver_address '{}' for request_id={}, dropping", solver_address, request_id);
                    return Ok(());
                }

                // Verify solver is onboarded (registered) on-chain
                match crate::contract::validate_solver_onboarded(&solver_id, "ADD_LIQUIDITY_GOSSIP")
                    .await
                {
                    Ok(true) => {} // solver is onboarded
                    Ok(false) => {
                        warn!("🚫 [ADD_LIQUIDITY] Solver '{}' is not onboarded on-chain for request_id={}, dropping", solver_id, request_id);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("🚫 [ADD_LIQUIDITY] Failed to verify solver '{}' on-chain for request_id={}: {}, dropping", solver_id, request_id, e);
                        return Ok(());
                    }
                }

                // Fully re-verify signature: recovered signer must match VERIFICATION_ADDRESS.
                let (compact, v) = match normalize_eth_signature(&signature) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            "⚠️ [ADD_LIQUIDITY] Invalid signature format in gossip for request_id={}: {}",
                            request_id, e
                        );
                        return Ok(());
                    }
                };

                let recovered_address = match recover_eth_address_secp(msg_bytes, &compact, v, true)
                {
                    Ok(addr) => addr,
                    Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            warn!(
                                    "⚠️ [ADD_LIQUIDITY] Failed to recover signer for request_id={}: personal_sign={}, raw={}",
                                    request_id, e1, e2
                                );
                            return Ok(());
                        }
                    },
                };

                if recovered_address.to_lowercase() != verification_address.to_lowercase() {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Gossip verification failed for request_id={}: recovered={}, expected={}",
                        request_id, recovered_address, verification_address
                    );
                    return Ok(());
                }

                // Persist to RocksDB as a pending add-liquidity record.
                // Use the status from the message (should be "Pending" for new requests).
                let record = PendingAddLiquidityRecord {
                    request_id: request_id.clone(),
                    solver_id: solver_id.clone(),
                    solver_address: solver_address.clone(),
                    amount: amount.clone(),
                    chain_id,
                    signature: signature.clone(),
                    signed_payload: signed_payload.clone(),
                    timestamp_ms,
                    status: status.clone(),
                    tx_id: tx_id.clone(),
                };

                // Use request_id as the unique key identifier
                let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, request_id);

                if let Err(e) = self.db.put_string_async(&key, &record).await {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Failed to persist pending record for request_id={} to RocksDB: {}",
                        request_id, e
                    );
                    return Ok(());
                }

                info!(
                    "✅ [ADD_LIQUIDITY] Accepted solver_add_liquidity request into pending queue (request_id={}, status={}, ts={})",
                    request_id, status, timestamp_ms
                );
            }
            GossipsubMessage::PeerDiscovered {
                peer,
                sequence,
                index,
            } => {
                info!(
                    "🎯 Peer discovered via gossipsub: {:?} (seq: {:?}, idx: {:?})",
                    peer, sequence, index
                );

                // ===== SOLVER VALIDATION =====
                // Validate that the discovered peer is an active solver before processing,
                // but skip validation for invulnerable nodes (initial DKG signers).
                let solver_id = peer.to_string();

                // Before DKG has completed (no invulnerables stored yet), treat all peers as
                // invulnerable so initial bootstrap nodes can be discovered and connected.
                let is_invulnerable = match self
                    .db
                    .get_string_async::<Vec<String>>(crate::database::keys::DKG_INVULNERABLES)
                    .await
                {
                    Ok(Some(invulnerables)) if !invulnerables.is_empty() => {
                        invulnerables.contains(&solver_id)
                    }
                    // No invulnerables stored yet or read error — assume bootstrap phase and
                    // treat this peer as invulnerable to allow initial nodes to join.
                    _ => true,
                };

                if !is_invulnerable {
                    match crate::contract::validate_solver_active_strict(
                        &solver_id,
                        "PEER_DISCOVERY_VALIDATION",
                    )
                    .await
                    {
                        Ok(_) => {
                            // Solver is active, proceed with peer discovery
                        }
                        Err(e) => {
                            warn!(
                                "🚫 [PEER_DISCOVERY_VALIDATION] Rejecting peer discovery for {}: {}",
                                peer, e
                            );
                            return Ok(());
                        }
                    }
                }
                // ===== END SOLVER VALIDATION =====

                // Check if we already have this peer to avoid duplicates
                let current_nodes = self.node_manager.get_active_nodes();
                if current_nodes.contains(&peer) {
                    return Ok(());
                }

                // If index provided, store and persist it
                if let Some(idx) = index {
                    self.peer_discovery.peer_indices.insert(peer, idx);
                    let key = key_utils::peer_index_key(&peer.to_string());
                    if let Err(e) = self.db.put_string_async(&key, &idx).await {
                        warn!("Failed to persist peer index: {:?}", e);
                    }
                }

                match self.node_manager.add_node(peer) {
                    Ok(_) => {
                        debug!("✅ Successfully added peer {} to node manager", peer);

                        // Log updated node count
                        let total = self.node_manager.get_total_nodes();
                        let threshold = self.node_manager.get_threshold();
                        info!("📊 Updated node count: {}, threshold: {}", total, threshold);

                        // Contract sequencer removed

                        // Do NOT update signing threshold when new nodes join after initial DKG
                        // Threshold is fixed based on the initial DKG participants only
                        // New nodes are passive observers and cannot sign
                        if let Some(dkg_node_ref) = &self.dkg_node {
                            let initial_dkg_complete = dkg_node_ref.is_initial_dkg_complete().await;
                            if !initial_dkg_complete {
                                // Check if we already know the DKG signer count (received from PeerList).
                                // If so, use it to compute threshold instead of total_nodes — this
                                // prevents observer nodes from inflating threshold beyond what
                                // the actual DKG signers can satisfy.
                                if let Some(dkg_count) = dkg_node_ref.get_dkg_signer_count() {
                                    let dkg_threshold = dkg_count / 2 + 1;
                                    if let Some(arc) = &self.signing_node {
                                        let mut signing_node = arc.lock().await;
                                        signing_node.set_threshold(dkg_threshold);
                                        info!("🔄 [THRESHOLD] Set signing threshold to {} (based on {} DKG signers, not total {})", dkg_threshold, dkg_count, total);
                                    }
                                    // Also mark initial DKG complete so future peers don't re-bump
                                    if let Err(e) = dkg_node_ref.mark_initial_dkg_complete().await {
                                        warn!(
                                            "⚠️ [THRESHOLD] Failed to set initial_dkg_complete: {}",
                                            e
                                        );
                                    }
                                } else {
                                    // During initial DKG setup (no signer count yet), update threshold as nodes join
                                    if let Some(arc) = &self.signing_node {
                                        let mut signing_node = arc.lock().await;
                                        let new_threshold = self.node_manager.get_threshold();
                                        signing_node.set_threshold(new_threshold);
                                        info!("🔄 [THRESHOLD] Updated signing node threshold to {} (total nodes: {})", new_threshold, total);
                                    }
                                }
                            } else {
                                info!("ℹ️ [THRESHOLD] Keeping signing threshold unchanged - new node joined after initial DKG (observer only)");
                            }
                        }

                        // New nodes join as passive observers - no share distribution or refresh
                        if let Some(dkg_node) = &mut self.dkg_node {
                            let initial_dkg_complete = dkg_node.is_initial_dkg_complete().await;
                            if initial_dkg_complete {
                                info!("ℹ️ [EXISTING_NODE] New peer {} joined network as observer (no share distribution)", peer);
                            } else {
                                info!("ℹ️ [NEW_NODE] Initial DKG not yet completed (waiting for 3 nodes)");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("❌ Failed to add peer {} to node manager: {:?}", peer, e);
                    }
                }
            }
            GossipsubMessage::CriticalMessageAck {
                message_type,
                message_id,
                node_id,
            } => {
                debug!(
                    "[RETRY] Received ACK from {} for message type: {}, id: {}",
                    node_id, message_type, message_id
                );

                // Parse message type and create message ID
                let msg_type = match message_type.as_str() {
                    "TransactionIdBroadcast" => crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
                    _ => {
                        debug!("[RETRY] Unknown message type in ACK: {}", message_type);
                        return Ok(());
                    }
                };

                let message_id_obj = crate::network::rpc::retry_manager::MessageId {
                    message_type: msg_type.clone(),
                    unique_id: message_id.clone(),
                };

                // Record acknowledgment
                if let Some(retry_mgr) = &self.retry_manager {
                    match retry_mgr
                        .record_acknowledgment(&message_id_obj, node_id.clone())
                        .await
                    {
                        Ok(all_acked) => {
                            if all_acked {
                                debug!("[RETRY] All nodes acknowledged message {}", message_id);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[RETRY] Failed to record ACK from {} for {}: {}",
                                node_id, message_id, e
                            );
                        }
                    }
                }
            }
            GossipsubMessage::TransactionBroadcast {
                sequencer_request_id: _,
                blockchain_tx_hash,
                chain_id,
            } => {
                info!(
                    "📡 [TX_BROADCAST] Transaction broadcasted: chain_id={}, tx_hash={}",
                    chain_id, blockchain_tx_hash
                );
                // Peer invalidation tx confirmation is handled via PeerInvalidationTxConfirmedBroadcast (like WithdrawTxIdBroadcast), not here
            }
            GossipsubMessage::IntentBatchBroadcast {
                intent_hashes,
                batch_type,
                timestamp,
                round,
                node_id,
                nonce_tuple_ids,
            } => {
                info!(
                    "📦 [INTENT_BATCH] Received intent batch broadcast from node {} (round {})",
                    node_id, round
                );
                info!(
                    "📦 [INTENT_BATCH] Batch type: {}, timestamp: {}, {} intent hashes",
                    batch_type,
                    timestamp,
                    intent_hashes.len()
                );

                // Remove coordinator-assigned nonce from local available pool so no
                // other coordinator picks the same nonce for a different operation.
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, batch_type.clone());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type {}, skipping duplicate",
                        round, batch_type
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                // SHARED: Fetch intent details from database (same for BTC and TICS)
                // Each receiving node independently validates every intent before signing.
                let mut intent_data = Vec::new();

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    let mut batch_intents = Vec::new();

                    for intent_hash in &intent_hashes {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                            // 1. Chain/token/address consistency
                            if let Err(e) = crate::utils::intent_validation::validate_intent_chains_tokens_addresses(&intent) {
                                warn!(
                                    "⚠️ [BATCH] Intent {} failed chain/token/address validation: {}, skipping",
                                    intent_hash, e
                                );
                                continue;
                            }
                            // 2. Amount > 0
                            let _parsed_amount: u128 = match intent.amount.trim().parse() {
                                Ok(a) if a > 0 => a,
                                Ok(_) => {
                                    warn!(
                                        "⚠️ [BATCH] Intent {} has zero amount, skipping",
                                        intent_hash
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    warn!("⚠️ [BATCH] Intent {} has invalid amount '{}': {}, skipping", intent_hash, intent.amount, e);
                                    continue;
                                }
                            };
                            // 3. Intent status must not be Solved or Rejected
                            if let Some(user) = user_intent_manager
                                .get_user_by_intent_hash(intent_hash)
                                .await
                            {
                                if let Some(status) = user_intent_manager
                                    .get_intent_status(&user.tics_address, intent_hash)
                                    .await
                                {
                                    if status == IntentStatus::Solved
                                        || status == IntentStatus::Rejected
                                    {
                                        warn!(
                                            "⚠️ [BATCH] Intent {} status is {:?}, skipping",
                                            intent_hash, status
                                        );
                                        continue;
                                    }
                                }
                            }

                            batch_intents.push((intent_hash.clone(), intent.clone()));
                            if let Some(tx_ids) = user_intent_manager
                                .get_intent_transaction_ids(intent_hash)
                                .await
                            {
                                if tx_ids.user_to_network_tx_id.is_some() {
                                    intent_data.push((intent_hash.clone(), intent, tx_ids));
                                } else {
                                    warn!(
                                        "⚠️  [BATCH] Intent {} missing UserToVault transaction",
                                        intent_hash
                                    );
                                }
                            }
                        } else {
                            warn!("⚠️ [BATCH] Intent {} not found in database", intent_hash);
                        }
                    }

                    if batch_intents.is_empty() {
                        warn!("⚠️ [BATCH] No valid intents found for batch processing");
                        return Ok(());
                    }

                    info!(
                        "✅ [BATCH] Fetched {} intents for {} batch processing",
                        batch_intents.len(),
                        batch_type
                    );

                    // Check if this node has a DKG share (needed for signing, not for TX building)
                    let is_dkg_participant = if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.has_dkg_share().await
                    } else {
                        false
                    };

                    // NOTE: Fallback price fetches now use intent.timestamp (per-intent)
                    // instead of the batch creation timestamp, ensuring consistency with
                    // the price snapshot used at intent submission time.

                    // DIFFERENT: Process based on batch type
                    if batch_type == "BTC" {
                        if !is_dkg_participant {
                            // Non-participating nodes skip BTC batch creation/signing; TX data arrives via per-slot messages.
                            return Ok(());
                        }
                        // BITCOIN BATCH TRANSACTION FLOW
                        info!(
                            "₿ [BATCH] Processing Bitcoin batch transaction for {} intents",
                            intent_data.len()
                        );

                        // Step 1: Build BatchOutput list from intents
                        use crate::signing::chains::bitcoin_batch::BatchOutput;
                        let mut batch_outputs = Vec::new();

                        for (intent_hash, intent, _tx_ids) in &intent_data {
                            // Use stored target_amount (in satoshis for BTC target).
                            // This was computed at RPC/gossip validation time and stored via
                            // store_intent_target_amount(). Prefer this over re-computing from
                            // current prices to honour the amount promised to the user.
                            let amount_sats: u64 = if let Some(stored) = user_intent_manager
                                .get_intent_target_amount(intent_hash)
                                .await
                            {
                                info!(
                                    "💱 [BATCH] Intent {} using stored target_amount = {} sats",
                                    intent_hash, stored
                                );
                                stored as u64
                            } else {
                                // Fallback: re-compute using the intent's original timestamp
                                // so the price snapshot matches what was used at submission time.
                                warn!(
                                    "⚠️ [BATCH] No stored target_amount for intent {}; falling back to price conversion with intent timestamp",
                                    intent_hash
                                );
                                let source_amount: u128 = match intent.amount.parse() {
                                    Ok(amt) => amt,
                                    Err(e) => {
                                        warn!(
                                            "⚠️ [BATCH] Failed to parse amount for intent {}: {}",
                                            intent_hash, e
                                        );
                                        continue;
                                    }
                                };
                                let fallback_prices =
                                    match crate::rpc_server::utils::fetch_crypto_prices(Some(
                                        intent.timestamp,
                                    ))
                                    .await
                                    {
                                        Ok(p) => p,
                                        Err(e) => {
                                            error!(
                                            "❌ [BATCH] Failed to fetch prices for intent {} (timestamp {}); skipping: {}",
                                            intent_hash, intent.timestamp, e
                                        );
                                            continue;
                                        }
                                    };
                                match crate::rpc_server::utils::convert_src_smallest_to_dst_smallest(
                                    source_amount,
                                    &intent.source_chain,
                                    &intent.target_chain,
                                    &fallback_prices,
                                ) {
                                    Ok(amt) => amt as u64,
                                    Err(e) => {
                                        error!("❌ [BATCH] Currency conversion failed for intent {}: {:?}", intent_hash, e);
                                        continue;
                                    }
                                }
                            };

                            // Validate dust threshold
                            if amount_sats < 546 {
                                warn!("⚠️ [BATCH] Intent {} amount {} sats is below dust threshold, skipping",
                                    intent_hash, amount_sats);
                                continue;
                            }

                            batch_outputs.push(BatchOutput {
                                address: intent.target_address.clone(),
                                amount: amount_sats,
                            });

                            info!(
                                "💰 [BATCH] Added output: {} sats to {}",
                                amount_sats, intent.target_address
                            );
                        }

                        if batch_outputs.is_empty() {
                            warn!("⚠️ [BATCH] No valid outputs after filtering");
                            return Ok(());
                        }

                        // Step 2: Get network's DKG Bitcoin address (where network BTC is stored)
                        // Use the network group key address, NOT the vault address
                        let dkg_node = match &self.dkg_node {
                            Some(node) => node,
                            None => {
                                error!("❌ [BATCH] DKG node not available");
                                return Ok(());
                            }
                        };

                        let group_key = match dkg_node.get_final_public_key().await {
                            Some(key) => key,
                            None => {
                                error!("❌ [BATCH] Network group key not available");
                                return Ok(());
                            }
                        };

                        let network_btc_address = match crate::utils::get_btc_address_from_group_key(group_key) {
                            Ok(addr) => addr,
                            Err(e) => {
                                error!("❌ [BATCH] Failed to derive network BTC address: {}", e);
                                return Ok(());
                            }
                        };

                        info!(
                            "🏦 [BATCH] Using network BTC address: {}",
                            network_btc_address
                        );

                        // Step 3: Fetch network BTC UTXOs
                        let is_testnet = crate::types::network::network_type().is_testnet();
                        let utxos = match crate::utils::transaction::fetch_bitcoin_utxos(
                            &network_btc_address,
                            is_testnet,
                        )
                        .await
                        {
                            Ok(utxos) => utxos,
                            Err(e) => {
                                error!(
                                    "❌ [BATCH] Failed to fetch UTXOs for liquidity operator: {}",
                                    e
                                );
                                return Ok(());
                            }
                        };

                        info!(
                            "📦 [BATCH] Fetched {} UTXOs from network vault",
                            utxos.len()
                        );

                        // Step 4: Convert BitcoinUtxo → BatchUtxo
                        use crate::signing::chains::bitcoin_batch::BatchUtxo;
                        let mut batch_utxos = Vec::new();

                        // We need to get the script_pubkey for the network address
                        let network_script_pubkey =
                            match crate::utils::transaction::create_bitcoin_script_pubkey(
                                &network_btc_address,
                            ) {
                                Ok(spk) => spk,
                                Err(e) => {
                                    error!("❌ [BATCH] Failed to create script pubkey for network address: {}", e);
                                    return Ok(());
                                }
                            };

                        for utxo in utxos {
                            if !utxo.status.confirmed {
                                continue; // Skip unconfirmed
                            }

                            batch_utxos.push(BatchUtxo {
                                txid: utxo.txid,
                                vout: utxo.vout,
                                value: utxo.value,
                                script_pubkey: network_script_pubkey.clone(),
                            });
                        }

                        info!(
                            "✅ [BATCH] Prepared {} confirmed UTXOs for selection",
                            batch_utxos.len()
                        );

                        // Step 5: Select UTXOs for batch transaction
                        use crate::signing::chains::bitcoin_batch::{
                            select_utxos_for_batch, BatchPolicy,
                        };

                        let policy = BatchPolicy {
                            fee_rate: std::env::var("BTC_FEE_RATE_SAT_VB")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(1),
                            dust_threshold: 546,
                            change_address: network_btc_address.clone(),
                        };

                        let selected =
                            match select_utxos_for_batch(&batch_utxos, &batch_outputs, &policy) {
                                Ok(sel) => sel,
                                Err(e) => {
                                    error!("❌ [BATCH] UTXO selection failed: {}", e);
                                    return Ok(());
                                }
                            };

                        info!(
                            "💰 [BATCH] Selected {} UTXOs: total={} sats, fee={} sats, change={} sats",
                            selected.utxos.len(),
                            selected.total_input_value,
                            selected.fee,
                            selected.change
                        );

                        // Step 6: Build unsigned transaction
                        use crate::signing::chains::bitcoin_batch::build_batch_unsigned_tx;

                        let unsigned_tx =
                            match build_batch_unsigned_tx(&selected, &batch_outputs, &policy) {
                                Ok(tx) => tx,
                                Err(e) => {
                                    error!(
                                        "❌ [BATCH] Failed to build unsigned transaction: {}",
                                        e
                                    );
                                    return Ok(());
                                }
                            };

                        info!(
                            "🔨 [BATCH] Built unsigned transaction: {} inputs, {} outputs",
                            unsigned_tx.input.len(),
                            unsigned_tx.output.len()
                        );

                        // Step 7: Convert bitcoin::Transaction to our BitcoinTransaction type
                        let mut our_inputs = Vec::new();
                        for (i, tx_in) in unsigned_tx.input.iter().enumerate() {
                            our_inputs.push(crate::types::BitcoinInput {
                                txid: tx_in.previous_output.txid.to_string(),
                                vout: tx_in.previous_output.vout,
                                script_sig: vec![], // Empty for unsigned
                                sequence: tx_in.sequence.0,
                                witness_utxo: Some(crate::types::BitcoinWitnessUtxo {
                                    value: selected.utxos[i].value,
                                    script_pubkey: selected.utxos[i].script_pubkey.clone(),
                                }),
                            });
                        }

                        let mut our_outputs = Vec::new();
                        for tx_out in &unsigned_tx.output {
                            our_outputs.push(crate::types::BitcoinOutput {
                                value: tx_out.value.to_sat(),
                                script_pubkey: tx_out.script_pubkey.as_bytes().to_vec(),
                            });
                        }

                        let our_btc_tx = crate::types::BitcoinTransaction {
                            version: unsigned_tx.version.0 as u32,
                            inputs: our_inputs,
                            outputs: our_outputs,
                            lock_time: unsigned_tx.lock_time.to_consensus_u32(),
                            witness: None, // P2PKH doesn't use witness
                        };

                        info!("🔄 [BATCH] Converted to internal BitcoinTransaction type");

                        // Step 8: Trigger signing using existing flow
                        if let Some(arc) = &self.signing_node {
                            let mut signing_node = arc.lock().await;
                            let mut chain_handler_box = crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                                crate::types::network::network_type().bitcoin_network_label().to_string()
                            );

                            // Set network's DKG group key
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(group_key) = dkg_node.get_final_public_key().await {
                                    let affine_point = group_key.to_affine();
                                    let encoded_point = k256::EncodedPoint::from(affine_point);
                                    let compressed_bytes =
                                        encoded_point.compress().to_bytes().to_vec();

                                    if let Some(btc_handler) = chain_handler_box.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>()
                                    {
                                        btc_handler.set_group_public_key(compressed_bytes);
                                        debug!("🔑 [BATCH] Set network DKG group public key");
                                    }
                                }
                            }

                            // Convert Box<dyn ChainHandler> to Arc<dyn ChainHandler>
                            let chain_handler: std::sync::Arc<
                                dyn crate::chain_abstraction::ChainHandler,
                            > = std::sync::Arc::from(chain_handler_box);
                            let tx_bytes = chain_handler.create_transaction_bytes(
                                &crate::chain_abstraction::ChainTransaction::Bitcoin(
                                    our_btc_tx.clone(),
                                ),
                            )?;

                            // Get DKG secret share for signing
                            let signing_key = if let Some(dkg_node) = &self.dkg_node {
                                dkg_node.get_final_secret_share().await
                            } else {
                                None
                            };

                            info!("🔐 [BATCH] Starting Bitcoin batch signing process...");

                            // Collect intent hashes from batch for signing
                            let intent_hashes_in_batch: Vec<String> = intent_data
                                .iter()
                                .map(|(hash, _, _)| hash.clone())
                                .collect();

                            info!(
                                "💾 [BATCH] Processing {} intent hashes in batch",
                                intent_hashes_in_batch.len()
                            );

                            use crate::signing::chains::BitcoinSigner;
                            let mut btc_signer = BitcoinSigner::new(&mut signing_node);
                            let computed_input_count = our_btc_tx.inputs.len();
                            let nonce_count =
                                nonce_tuple_ids.as_ref().map(|ids| ids.len()).unwrap_or(0);

                            if nonce_count != computed_input_count {
                                warn!(
                                    "⚠️ [BTC_BATCH] Nonce count ({}) does not match computed input count ({}) before signing",
                                    nonce_count, computed_input_count
                                );
                            } else {
                                info!(
                                    "ℹ️ [BTC_BATCH] Nonce count matches computed input count: {}",
                                    computed_input_count
                                );
                            }

                            if let Err(e) = btc_signer
                                .sign_transaction(
                                    tx_bytes,
                                    &chain_handler,
                                    Some(our_btc_tx),
                                    None,
                                    intent_hashes_in_batch.clone(),
                                    Some(crate::types::TransactionType::NetworkToTarget),
                                    signing_key,
                                    None,
                                    signing_key,
                                    nonce_tuple_ids.clone(),
                                    round,
                                )
                                .await
                            {
                                warn!("❌ [BTC_BATCH] BTC NetworkToTarget batch signing failed for round {}: {}", round, e);

                                // Revert intents locally (never revert Solved)
                                if let Some(uim) = &self.user_intent_manager {
                                    for h in &intent_hashes_in_batch {
                                        if let Some(user) = uim.get_user_by_intent_hash(h).await {
                                            let current =
                                                uim.get_intent_status(&user.tics_address, h).await;
                                            if matches!(current, Some(IntentStatus::Solved)) {
                                                continue;
                                            }
                                            let _ = uim
                                                .update_intent_status(
                                                    &user.tics_address,
                                                    h,
                                                    IntentStatus::Pending,
                                                )
                                                .await;
                                            info!(
                                                "🔄 [BTC_BATCH] Reverted intent {} to Pending",
                                                h
                                            );
                                        }
                                    }
                                }

                                // Broadcast error so other nodes also revert
                                let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                                    intent_hashes: intent_hashes_in_batch,
                                    error_message: format!(
                                        "BTC NetworkToTarget batch signing failed for round {}: {}",
                                        round, e
                                    ),
                                    transaction_type: "network_to_target".to_string(),
                                    solver_address: None,
                                    node_id: self.local_peer_id.to_string(),
                                };
                                if let Ok(data) = serde_json::to_vec(&error_msg) {
                                    let _ = self
                                        .message_tx
                                        .send(ChannelMessage::Broadcast {
                                            topic: "transaction-sync".to_string(),
                                            data,
                                        })
                                        .await;
                                }
                            } else {
                                debug!("✅ [BATCH] Bitcoin batch transaction signed successfully");
                            }
                        } else {
                            error!("❌ [BATCH] Signing node not available");
                        }
                    } else if batch_type == "TICS" {
                        info!(
                            "💎 [TICS_BATCH] Creating TICS batch transaction with {} intents",
                            batch_intents.len()
                        );

                        // Prepare BatchIntentInput array for processBatchIntents contract call
                        let mut batch_intent_inputs = Vec::new();

                        for (intent_hash, intent) in &batch_intents {
                            let source_amount = match intent.amount.parse::<u128>() {
                                Ok(amt) => amt,
                                Err(e) => {
                                    warn!(
                                        "⚠️ [TICS_BATCH] Invalid amount for intent {}: {}",
                                        intent_hash, e
                                    );
                                    continue;
                                }
                            };
                            // Use stored target_amount (pre-computed at intent submission).
                            // For same-chain (TICS→TICS) target_amount == source_amount.
                            // For cross-chain (BTC→TICS) target_amount is in wei, NOT satoshis.
                            // Do NOT fall back to source_amount — units may differ across chains.
                            let target_amount = match user_intent_manager
                                .get_intent_target_amount(intent_hash)
                                .await
                            {
                                Some(amt) => amt,
                                None => {
                                    // Fallback: re-compute using the intent's original timestamp
                                    // so the price snapshot matches what was used at submission time.
                                    warn!(
                                        "⚠️ [TICS_BATCH] No stored target_amount for intent {}; computing fallback with intent timestamp",
                                        intent_hash
                                    );
                                    if intent.source_chain.to_lowercase()
                                        == intent.target_chain.to_lowercase()
                                    {
                                        source_amount
                                    } else {
                                        match crate::rpc_server::utils::fetch_crypto_prices(Some(intent.timestamp)).await {
                                            Ok(prices) => {
                                                match crate::rpc_server::utils::convert_src_smallest_to_dst_smallest(
                                                    source_amount,
                                                    &intent.source_chain,
                                                    &intent.target_chain,
                                                    &prices,
                                                ) {
                                                    Ok(amt) => amt,
                                                    Err(e) => {
                                                        error!("❌ [TICS_BATCH] Fallback conversion failed for intent {}: {:?}", intent_hash, e);
                                                        continue;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("❌ [TICS_BATCH] Failed to fetch prices for intent {} (timestamp {}); skipping: {}", intent_hash, intent.timestamp, e);
                                                continue;
                                            }
                                        }
                                    }
                                }
                            };

                            // Get UserToVault transaction hash for this intent, if available
                            let tx_ids = user_intent_manager
                                .get_intent_transaction_ids(intent_hash)
                                .await;

                            // Get UserToVault transaction hash
                            let user_tx_hash = tx_ids
                                .as_ref()
                                .and_then(|ids| ids.user_to_network_tx_id.clone())
                                .unwrap_or_else(|| {
                                    warn!(
                                        "⚠️ [TICS_BATCH] Intent {} missing UserToVault tx hash",
                                        intent_hash
                                    );
                                    "N/A".to_string()
                                });

                            // Create BatchIntentInput for this intent
                            let batch_input = crate::types::BatchIntentInput {
                                source_address: intent.source_address.clone(),
                                target_address: intent.target_address.clone(),
                                source_chain: intent.source_chain.clone(),
                                target_chain: intent.target_chain.clone(),
                                source_amount,
                                target_amount,
                                source_token: intent.source_token.clone(),
                                target_token: intent.target_token.clone(),
                                intent_id: intent_hash.clone(),
                                withdraw_tx_hash: user_tx_hash.clone(), // For NetworkToTarget, withdrawTxHash = intent_hash
                                deposit_tx_hash: None, // depositTxHash = user's deposit tx
                            };

                            batch_intent_inputs.push(batch_input);
                        }

                        info!(
                            "📤 [TICS_BATCH] Prepared {} BatchIntentInput entries",
                            batch_intent_inputs.len()
                        );

                        // Create processBatchIntents calldata using timestamp from the batch broadcast
                        // so all nodes build the same calldata and tx digest.
                        if let Some(calldata) =
                            crate::utils::transaction::encode_process_batch_intents_calldata(
                                &batch_intent_inputs,
                                crate::types::BatchType::TICS,
                                &timestamp,
                            )
                        {
                            info!(
                                "✅ [TICS_BATCH] Created processBatchIntents calldata ({} bytes)",
                                calldata.len()
                            );

                            // Create and submit an MPC-signed contract call transaction for processBatchIntents.
                            // This mirrors the BTC batch wiring: we push the batch TX into the existing MPC signing flow
                            // and store the full list of intent hashes for the round.
                            // Use MAIN DKG group key (not vault key) for processBatchIntents.
                            let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                                dkg_node.get_final_public_key().await
                            } else {
                                None
                            };

                            let Some(group_public_key) = group_public_key else {
                                warn!("❌ [TICS_BATCH] Main DKG group key not available; cannot create contract call");
                                return Ok(());
                            };

                            // Contract address for IntentManager (processBatchIntents)
                            let contract_address_env =
                                crate::env_defaults::intent_manager_contract_address();
                            if contract_address_env == "0x0000000000000000000000000000000000000000"
                            {
                                warn!("❌ [TICS_BATCH] INTENT_MANAGER_CONTRACT_ADDRESS not configured");
                                return Ok(());
                            }

                            // Use the MAIN group-derived EVM address as sender
                            let from_address =
                                crate::utils::get_eth_address_from_group_key(group_public_key);
                            let chain_id =
                                crate::utils::transaction::get_chain_id_from_name("qubetics")
                                    .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());

                            // Estimate gas; abort if it would revert
                            let calldata_hex = format!("0x{}", hex::encode(&calldata));
                            let estimated_gas =
                                crate::utils::transaction::estimate_gas_for_deposit_intent(
                                    &from_address,
                                    &contract_address_env,
                                    &calldata_hex,
                                    chain_id,
                                )
                                .await
                                .map_err(|e| {
                                    anyhow::anyhow!("TICS batch gas estimation failed: {}", e)
                                })?;
                            let gas_limit = estimated_gas + (estimated_gas / 10);

                            let nonce = crate::utils::transaction::fetch_tics_nonce(
                                &from_address,
                                chain_id,
                            )
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("Failed to fetch nonce for {}: {}", from_address, e)
                            })?;

                            let gas_price = crate::utils::transaction::get_gas_price_for_chain("qubetics", chain_id)
                                .await
                                .unwrap_or_else(|e| {
                                    warn!("⚠️ [TICS_BATCH] Failed to get dynamic gas price: {}, using fallback", e);
                                    crate::utils::transaction::get_default_gas_price_for_chain("qubetics")
                                });

                            let contract_tx = crate::types::ContractTransaction {
                                to: contract_address_env.clone(),
                                value: "0x0".to_string(),
                                nonce,
                                gas_limit,
                                gas_price,
                                chain_id,
                                data: calldata_hex,
                            };

                            // Start MPC signing (both DKG and observer nodes call sign_contract_message;
                            // observer nodes build + store the TX and advance round but skip actual ECDSA signing)
                            if let Some(arc) = &self.signing_node {
                                let mut signing_node = arc.lock().await;
                                let available_nodes: Vec<PeerId> =
                                    self.node_manager.get_active_nodes().into_iter().collect();
                                signing_node.set_available_nodes(available_nodes);

                                // Ensure MAIN group key is available on signing node
                                signing_node.set_group_public_key(group_public_key);

                                // Use MAIN final secret share for signing (network group key path)
                                // Observer nodes pass None — sign_contract_message handles this gracefully
                                let secret_share = if let Some(dkg_node) = &self.dkg_node {
                                    dkg_node.get_final_secret_share().await
                                } else {
                                    None
                                };

                                let contract_tx_bytes =
                                    crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                let contract_chain_handler =
                                    signing_node.get_contract_chain_handler().clone();
                                let mut eth_signer = TicsSigner::new(&mut signing_node);
                                let nonce_tuple_id = nonce_tuple_ids
                                    .as_ref()
                                    .and_then(|ids| ids.first().cloned());

                                if let Err(e) = eth_signer
                                    .sign_contract_message(
                                        contract_tx_bytes,
                                        &contract_chain_handler,
                                        &contract_tx,
                                        None,
                                        None, // user_tics_address (not applicable)
                                        intent_hashes.clone(),
                                        // Use the main DKG share as an explicit signing key override.
                                        secret_share,
                                        None,
                                        None,
                                        None, // tics_withdraw_identifiers (not applicable)
                                        None, // tics_claim_reward_identifiers (not applicable)
                                        None, // tics_claim_platform_fee_identifiers (not applicable)
                                        nonce_tuple_id.clone(), // COORDINATED nonce from coordinator
                                        round,
                                    )
                                    .await
                                {
                                    warn!("❌ [TICS_BATCH] TICS NetworkToTarget batch signing failed for round {}: {}", round, e);

                                    // Revert intents locally (never revert Solved)
                                    if let Some(uim) = &self.user_intent_manager {
                                        for h in &intent_hashes {
                                            if let Some(user) = uim.get_user_by_intent_hash(h).await
                                            {
                                                let current = uim
                                                    .get_intent_status(&user.tics_address, h)
                                                    .await;
                                                if matches!(current, Some(IntentStatus::Solved)) {
                                                    continue;
                                                }
                                                let _ = uim
                                                    .update_intent_status(
                                                        &user.tics_address,
                                                        h,
                                                        IntentStatus::Pending,
                                                    )
                                                    .await;
                                                info!(
                                                    "🔄 [TICS_BATCH] Reverted intent {} to Pending",
                                                    h
                                                );
                                            }
                                        }
                                    }

                                    // Broadcast error so other nodes also revert
                                    let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                                        intent_hashes: intent_hashes.clone(),
                                        error_message: format!("TICS NetworkToTarget batch signing failed for round {}: {}", round, e),
                                        transaction_type: "network_to_target".to_string(),
                                        solver_address: None,
                                        node_id: self.local_peer_id.to_string(),
                                    };
                                    if let Ok(data) = serde_json::to_vec(&error_msg) {
                                        let _ = self
                                            .message_tx
                                            .send(ChannelMessage::Broadcast {
                                                topic: "transaction-sync".to_string(),
                                                data,
                                            })
                                            .await;
                                    }
                                } else {
                                    info!(
                                        "✅ [TICS_BATCH] Submitted processBatchIntents contract transaction into MPC signing flow ({} intents, nonce: {:?})",
                                        intent_hashes.len(),
                                        nonce_tuple_id
                                    );
                                    info!(
                                        "ℹ️  [TICS_BATCH] Signatures will be sent to final node: {}",
                                        node_id
                                    );
                                }
                            } else {
                                warn!(
                                    "❌ [TICS_BATCH] Signing node not available; cannot start MPC signing for batch contract call"
                                );
                            }
                        } else {
                            warn!("❌ [TICS_BATCH] Failed to encode processBatchIntents calldata");
                        }
                    } else {
                        warn!("⚠️ [INTENT_BATCH] Unknown batch type: {}", batch_type);
                    }
                } else {
                    warn!("❌ [BATCH] User intent manager not available");
                }
            }
            GossipsubMessage::TicsUserToVaultIntentBatch {
                intent_hashes,
                round,
                timestamp: _,
                node_id,
                nonce_assignments,
            } => {
                info!(
                    "📦 [TICS_UTV_BATCH] Received TICS UserToVault intent batch from node {} (round {}, {} intents)",
                    node_id, round, intent_hashes.len()
                );

                // Keep sliding window in sync on all nodes so when any node becomes final it excludes last N batches
                if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.record_tics_user_to_vault_batch(&intent_hashes);
                    // Remove coordinator-assigned nonces from local available pool
                    if !nonce_assignments.is_empty() {
                        let nonce_ids: Vec<String> = nonce_assignments
                            .values()
                            .flat_map(|ids| ids.iter().cloned())
                            .collect();
                        node.remove_nonces_from_available_pool(&nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "TICS_UTV".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!("⏭️ [BATCH] Already processed batch for round {} type TICS_UTV, skipping duplicate", round);
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    // Mark all intents in this batch as Batched on this node so they are not re-picked for future batches
                    for intent_hash in intent_hashes.iter() {
                        if let Some(user) = user_intent_manager
                            .get_user_by_intent_hash(intent_hash)
                            .await
                        {
                            if let Err(e) = user_intent_manager
                                .update_intent_status(
                                    &user.tics_address,
                                    intent_hash,
                                    IntentStatus::Batched,
                                )
                                .await
                            {
                                warn!(
                                    "⚠️ [TICS_UTV_BATCH] Failed to mark intent {} as Batched on receive: {}",
                                    intent_hash, e
                                );
                            }
                        }
                    }

                    // All nodes (DKG + observer) proceed with batch processing.
                    // sign_tics_user_to_vault_batch_with_nonces() handles observer path
                    // internally (stores batch data, skips signing).

                    let mut batch_intents = Vec::new();
                    for intent_hash in intent_hashes.iter() {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                            // 1. Check intent has not already been processed
                            let tx_ids = user_intent_manager
                                .get_intent_transaction_ids(intent_hash)
                                .await;
                            let no_user_tx = tx_ids
                                .as_ref()
                                .map(|ids| ids.user_to_network_tx_id.is_none())
                                .unwrap_or(true);
                            if !no_user_tx {
                                warn!(
                                    "⚠️ [TICS_UTV_BATCH] Intent {} already has UserToVault tx, skipping",
                                    intent_hash
                                );
                                continue;
                            }
                            // 2. Source chain must be TICS
                            let source_ok = intent.source_chain.eq_ignore_ascii_case("tics")
                                || intent.source_chain.eq_ignore_ascii_case("qubetics");
                            if !source_ok {
                                warn!(
                                    "⚠️ [TICS_UTV_BATCH] Intent {} source_chain is not TICS, skipping",
                                    intent_hash
                                );
                                continue;
                            }
                            // 3. Chain/token/address consistency
                            if let Err(e) = crate::utils::intent_validation::validate_intent_chains_tokens_addresses(&intent) {
                                warn!(
                                    "⚠️ [TICS_UTV_BATCH] Intent {} failed validation: {}, skipping",
                                    intent_hash, e
                                );
                                continue;
                            }
                            // 4. Amount must be > 0
                            let _parsed_amount: u128 = match intent.amount.trim().parse() {
                                Ok(a) if a > 0 => a,
                                Ok(_) => {
                                    warn!(
                                        "⚠️ [TICS_UTV_BATCH] Intent {} has zero amount, skipping",
                                        intent_hash
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    warn!("⚠️ [TICS_UTV_BATCH] Intent {} has invalid amount '{}': {}, skipping", intent_hash, intent.amount, e);
                                    continue;
                                }
                            };
                            // 5. Intent status must be Pending or Batched
                            if let Some(user) = user_intent_manager
                                .get_user_by_intent_hash(intent_hash)
                                .await
                            {
                                if let Some(status) = user_intent_manager
                                    .get_intent_status(&user.tics_address, intent_hash)
                                    .await
                                {
                                    if status != IntentStatus::Pending
                                        && status != IntentStatus::Batched
                                    {
                                        warn!(
                                            "⚠️ [TICS_UTV_BATCH] Intent {} status is {:?} (expected Pending/Batched), skipping",
                                            intent_hash, status
                                        );
                                        continue;
                                    }
                                }

                                let source_amount = match intent.amount.trim().parse::<u128>() {
                                    Ok(a) if a > 0 => a,
                                    _ => {
                                        warn!(
                                            "⚠️ [TICS_UTV_BATCH] Invalid amount for intent {}",
                                            intent_hash
                                        );
                                        continue;
                                    }
                                };
                                let fee_bps = crate::contract::fetch_dynamic_fee_bps().await;
                                let dynamic_fee_buffer = (source_amount * fee_bps) / 10000;
                                let estimated_tx_fee: u128 = 300_000_000_000_000;
                                let required_balance =
                                    source_amount + dynamic_fee_buffer + estimated_tx_fee;

                                match crate::rpc_server::utils::fetch_network_balance(
                                    &intent.source_address,
                                    "eth",
                                )
                                .await
                                {
                                    Ok(user_balance) => {
                                        if user_balance < required_balance {
                                            tracing::warn!(
                                                "⚠️ [TICS_UTV_BATCH] Insufficient balance for intent in batch {}: has {}, needs {}. Rejecting locally.",
                                                intent_hash, user_balance, required_balance
                                            );
                                            if let Err(e) = user_intent_manager
                                                .update_intent_status(
                                                    &user.tics_address,
                                                    intent_hash,
                                                    crate::types::IntentStatus::Rejected,
                                                )
                                                .await
                                            {
                                                tracing::error!("Failed to update intent status to Rejected for {}: {}", intent_hash, e);
                                            }
                                            continue;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("⚠️ [TICS_UTV_BATCH] Failed to fetch balance for intent {}: {}", intent_hash, e);
                                        continue;
                                    }
                                }

                                batch_intents.push((
                                    intent_hash.clone(),
                                    intent,
                                    user.tics_address,
                                ));
                            } else {
                                warn!(
                                    "⚠️ [TICS_UTV_BATCH] Intent {} has no registered user, skipping",
                                    intent_hash
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [TICS_UTV_BATCH] Intent {} not found in database",
                                intent_hash
                            );
                        }
                    }

                    if batch_intents.is_empty() {
                        warn!("⚠️ [TICS_UTV_BATCH] No valid TICS UserToVault intents to process");
                        return Ok(());
                    }

                    info!(
                        "✅ [TICS_UTV_BATCH] Fetched {} intents for TICS UserToVault batch (round {})",
                        batch_intents.len(),
                        round
                    );

                    // One round; batch stored and signed per-slot; final node aggregates each slot and broadcasts one-by-one.
                    // UserToVault on TICS: from user derived_eth -> to treasury vault (env); liquidity_operator_eth is fallback. No group key or BTC addr needed.
                    let liquidity_operator_eth_addr = user_intent_manager
                        .get_database()
                        .get_string(crate::database::keys::DKG_LIQUIDITY_OPERATOR_ETH_ADDRESS)
                        .ok()
                        .flatten();

                    let mut batch: Vec<(
                        String,
                        String,
                        crate::chain_abstraction::ChainTransaction,
                        Vec<u8>,
                        Option<k256::Scalar>,
                    )> = Vec::new();
                    for (intent_hash, intent, user_eth_addr) in &batch_intents {
                        // For TICS UserToVault, amount must be in source-chain units (wei for EVM).
                        // intent.amount is always in source-chain smallest units.
                        // Do NOT use get_intent_target_amount — that is in target-chain units
                        // (e.g. satoshis for TICS->BTC), which is wrong for a source-chain tx.
                        let source_amount: u128 = match intent.amount.trim().parse() {
                            Ok(a) if a > 0 => a,
                            _ => {
                                warn!("⚠️ [TICS_UTV_BATCH] Intent {} has invalid/zero amount '{}', skipping", intent_hash, intent.amount);
                                continue;
                            }
                        };
                        let fee_bps = crate::contract::fetch_dynamic_fee_bps().await;
                        let amount = source_amount + (source_amount * fee_bps / 10000);

                        let user =
                            match user_intent_manager.get_user_by_address(user_eth_addr).await {
                                Some(u) => u,
                                None => {
                                    warn!(
                                        "⚠️ [TICS_UTV_BATCH] User {} not found for intent {}",
                                        user_eth_addr, intent_hash
                                    );
                                    continue;
                                }
                            };
                        let derived_eth_addr = user.derived_eth_address.clone();
                        let derived_btc_addr = user.derived_btc_address.clone();

                        let chain_tx_result =
                            crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                                intent,
                                None, // UserToVault on EVM does not use group key
                                derived_eth_addr.as_ref(),
                                derived_btc_addr.as_ref(),
                                crate::types::TransactionType::UserToVault,
                                liquidity_operator_eth_addr.as_ref(),
                                None, // EVM only
                                amount,
                            )
                            .await;

                        let chain_transaction = match chain_tx_result {
                            Ok(tx) => tx,
                            Err(e) => {
                                warn!(
                                    "❌ [TICS_UTV_BATCH] Failed to create chain tx for intent {}: {}",
                                    intent_hash, e
                                );
                                continue;
                            }
                        };

                        let tx_bytes = match &chain_transaction {
                            crate::chain_abstraction::ChainTransaction::Tics(eth_tx) => {
                                crate::utils::transaction::create_transaction_for_signing(eth_tx)
                            }
                            _ => {
                                warn!(
                                    "❌ [TICS_UTV_BATCH] Intent {} is not EVM (expected TICS)",
                                    intent_hash
                                );
                                continue;
                            }
                        };

                        let signing_key = self.get_signing_key_for_user(Some(user_eth_addr)).await;
                        batch.push((
                            intent_hash.clone(),
                            user_eth_addr.clone(),
                            chain_transaction,
                            tx_bytes,
                            signing_key,
                        ));
                    }

                    if batch.is_empty() {
                        warn!(
                            "⚠️ [TICS_UTV_BATCH] No valid batch entries (missing users/keys/txs)"
                        );
                        return Ok(());
                    }

                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();

                    if let Some(arc) = &self.signing_node {
                        let mut signing_node = arc.lock().await;
                        signing_node.set_available_nodes(available_nodes);

                        use crate::signing::chains::TicsSigner;
                        let mut eth_signer = TicsSigner::new(&mut signing_node);
                        let n_slots = batch.len();
                        // Use coordinated nonces if available
                        if let Err(e) = eth_signer
                            .sign_tics_user_to_vault_batch_with_nonces(
                                round,
                                batch,
                                nonce_assignments.clone(),
                            )
                            .await
                        {
                            warn!(
                                "❌ [TICS_UTV_BATCH] Batch signing failed for round {}: {}",
                                round, e
                            );
                            // Revert intent status back to Pending so they can be
                            // re-picked in the next epoch cycle.
                            // NEVER revert from Solved — that is a terminal state.
                            let failed_hashes: Vec<String> =
                                batch_intents.iter().map(|(h, _, _)| h.clone()).collect();
                            for (intent_hash, _intent, user_eth_addr) in &batch_intents {
                                let current = user_intent_manager
                                    .get_intent_status(user_eth_addr, intent_hash)
                                    .await;
                                if matches!(current, Some(IntentStatus::Solved)) {
                                    continue;
                                }
                                if let Err(revert_err) = user_intent_manager
                                    .update_intent_status(
                                        user_eth_addr,
                                        intent_hash,
                                        IntentStatus::Pending,
                                    )
                                    .await
                                {
                                    warn!(
                                        "⚠️ [TICS_UTV_BATCH] Failed to revert intent {} to Pending: {}",
                                        intent_hash, revert_err
                                    );
                                }
                            }

                            // Broadcast error to all nodes so they also revert
                            // intent status from Batched to Pending.
                            let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                                intent_hashes: failed_hashes,
                                error_message: format!(
                                    "TICS UTV batch signing failed for round {}: {}",
                                    round, e
                                ),
                                transaction_type: "user_to_network".to_string(),
                                solver_address: None,
                                node_id: self.local_peer_id.to_string(),
                            };
                            if let Ok(data) = serde_json::to_vec(&error_msg) {
                                let _ = self
                                    .message_tx
                                    .send(ChannelMessage::Broadcast {
                                        topic: "transaction-sync".to_string(),
                                        data,
                                    })
                                    .await;
                                info!("📡 [TICS_UTV_BATCH] Broadcasted batch failure for round {} to sync intent status across nodes", round);
                            }
                        } else {
                            info!(
                                "✅ [TICS_UTV_BATCH] Initiated batch signing for round {} ({} slots, coordinated: {})",
                                round, n_slots, !nonce_assignments.is_empty()
                            );
                        }
                    } else {
                        warn!("❌ [TICS_UTV_BATCH] Signing node not available");
                    }
                } else {
                    warn!("❌ [TICS_UTV_BATCH] User intent manager not available");
                }
            }
            GossipsubMessage::BtcUserToVaultIntentBatch {
                intent_hashes,
                round,
                timestamp: _,
                node_id,
                nonce_assignments,
            } => {
                info!(
                    "📦 [BTC_UTV_BATCH] Received BTC UserToVault intent batch from node {} (round {}, {} intents)",
                    node_id, round, intent_hashes.len()
                );

                // Keep sliding window in sync on all nodes so when any node becomes final it excludes last N batches
                if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.record_btc_user_to_vault_batch(&intent_hashes);
                    // Remove coordinator-assigned nonces from local available pool
                    if !nonce_assignments.is_empty() {
                        let nonce_ids: Vec<String> = nonce_assignments
                            .values()
                            .flat_map(|ids| ids.iter().cloned())
                            .collect();
                        node.remove_nonces_from_available_pool(&nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "BTC_UTV".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!("⏭️ [BATCH] Already processed batch for round {} type BTC_UTV, skipping duplicate", round);
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    // Mark all intents in this batch as Batched on this node so they are not re-picked for future batches
                    for intent_hash in intent_hashes.iter() {
                        if let Some(user) = user_intent_manager
                            .get_user_by_intent_hash(intent_hash)
                            .await
                        {
                            if let Err(e) = user_intent_manager
                                .update_intent_status(
                                    &user.tics_address,
                                    intent_hash,
                                    IntentStatus::Batched,
                                )
                                .await
                            {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Failed to mark intent {} as Batched on receive: {}",
                                    intent_hash, e
                                );
                            }
                        }
                    }

                    // All nodes (DKG + observer) proceed with batch processing.
                    // sign_btc_user_to_vault_batch() handles observer path
                    // internally (stores batch data, skips signing).

                    let mut batch_intents = Vec::new();
                    for intent_hash in intent_hashes.iter() {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                            // 1. Check intent has not already been processed
                            let tx_ids = user_intent_manager
                                .get_intent_transaction_ids(intent_hash)
                                .await;
                            let no_user_tx = tx_ids
                                .as_ref()
                                .map(|ids| ids.user_to_network_tx_id.is_none())
                                .unwrap_or(true);
                            if !no_user_tx {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Intent {} already has UserToVault tx, skipping",
                                    intent_hash
                                );
                                continue;
                            }
                            // 2. Source chain must be Bitcoin
                            let source_ok = intent.source_chain.eq_ignore_ascii_case("bitcoin")
                                || intent.source_chain.eq_ignore_ascii_case("btc");
                            if !source_ok {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Intent {} source_chain is not Bitcoin, skipping",
                                    intent_hash
                                );
                                continue;
                            }
                            // 3. Chain/token/address consistency
                            if let Err(e) = crate::utils::intent_validation::validate_intent_chains_tokens_addresses(&intent) {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Intent {} failed validation: {}, skipping",
                                    intent_hash, e
                                );
                                continue;
                            }
                            // 4. Amount must be > 0 and above dust for BTC source
                            let parsed_amount: u128 = match intent.amount.trim().parse() {
                                Ok(a) if a > 0 => a,
                                other => {
                                    if let Err(e) = other {
                                        warn!("⚠️ [BTC_UTV_BATCH] Intent {} has invalid amount '{}': {}, marking as Rejected", intent_hash, intent.amount, e);
                                    } else {
                                        warn!("⚠️ [BTC_UTV_BATCH] Intent {} has zero amount, marking as Rejected", intent_hash);
                                    }
                                    if let Some(user) = user_intent_manager
                                        .get_user_by_intent_hash(intent_hash)
                                        .await
                                    {
                                        let _ = user_intent_manager
                                            .update_intent_status(
                                                &user.tics_address,
                                                intent_hash,
                                                IntentStatus::Rejected,
                                            )
                                            .await;
                                    }
                                    continue;
                                }
                            };
                            if (parsed_amount as u64) < DUST_LIMIT_SATS {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Intent {} amount {} sats below dust limit {}, marking as Rejected",
                                    intent_hash, parsed_amount, DUST_LIMIT_SATS
                                );
                                // Mark as Rejected so this intent is never re-picked for future batches
                                if let Some(user) = user_intent_manager
                                    .get_user_by_intent_hash(intent_hash)
                                    .await
                                {
                                    let _ = user_intent_manager
                                        .update_intent_status(
                                            &user.tics_address,
                                            intent_hash,
                                            IntentStatus::Rejected,
                                        )
                                        .await;
                                }
                                continue;
                            }
                            // 5. Intent status must be Pending or Batched
                            if let Some(user) = user_intent_manager
                                .get_user_by_intent_hash(intent_hash)
                                .await
                            {
                                if let Some(status) = user_intent_manager
                                    .get_intent_status(&user.tics_address, intent_hash)
                                    .await
                                {
                                    if status != IntentStatus::Pending
                                        && status != IntentStatus::Batched
                                    {
                                        warn!(
                                            "⚠️ [BTC_UTV_BATCH] Intent {} status is {:?} (expected Pending/Batched), skipping",
                                            intent_hash, status
                                        );
                                        continue;
                                    }
                                }

                                let fee_bps = crate::contract::fetch_dynamic_fee_bps().await;
                                let dynamic_fee_buffer = (parsed_amount * fee_bps) / 10000;
                                let fee_rate = std::env::var("BTC_FEE_RATE_SAT_VB")
                                    .ok()
                                    .and_then(|v| v.parse::<u128>().ok())
                                    .unwrap_or(2);
                                let estimated_tx_fee: u128 = 208 * fee_rate;
                                let required_balance =
                                    parsed_amount + dynamic_fee_buffer + estimated_tx_fee;

                                match crate::utils::transaction::fetch_bitcoin_utxos(
                                    &intent.source_address,
                                    false,
                                )
                                .await
                                {
                                    Ok(utxos) => {
                                        let confirmed_balance: u128 = utxos
                                            .iter()
                                            .filter(|u| u.status.confirmed)
                                            .map(|u| u.value as u128)
                                            .sum();
                                        if confirmed_balance < required_balance {
                                            tracing::warn!(
                                                "⚠️ [BTC_UTV_BATCH] Insufficient confirmed UTXOs for intent in batch {}: has {}, needs {}. Rejecting locally.",
                                                intent_hash, confirmed_balance, required_balance
                                            );
                                            if let Err(e) = user_intent_manager
                                                .update_intent_status(
                                                    &user.tics_address,
                                                    intent_hash,
                                                    crate::types::IntentStatus::Rejected,
                                                )
                                                .await
                                            {
                                                tracing::error!("Failed to update intent status to Rejected for {}: {}", intent_hash, e);
                                            }
                                            continue;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("⚠️ [BTC_UTV_BATCH] Failed to fetch utxos for intent {}: {}", intent_hash, e);
                                        continue;
                                    }
                                }

                                batch_intents.push((
                                    intent_hash.clone(),
                                    intent,
                                    user.tics_address,
                                ));
                            } else {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Intent {} has no registered user, skipping",
                                    intent_hash
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [BTC_UTV_BATCH] Intent {} not found in database",
                                intent_hash
                            );
                        }
                    }

                    if batch_intents.is_empty() {
                        warn!("⚠️ [BTC_UTV_BATCH] No valid BTC UserToVault intents to process");
                        return Ok(());
                    }

                    info!(
                        "✅ [BTC_UTV_BATCH] Fetched {} intents for BTC UserToVault batch (round {})",
                        batch_intents.len(),
                        round
                    );

                    // UserToVault on Bitcoin: from user derived_btc -> to network BTC address (where network BTC is held)
                    let network_btc_addr = match &self.dkg_node {
                        Some(dkg_node) => match dkg_node.get_final_public_key().await {
                            Some(group_key) => {
                                match crate::utils::get_btc_address_from_group_key(group_key) {
                                    Ok(addr) => Some(addr),
                                    Err(e) => {
                                        error!("❌ [BTC_UTV_BATCH] Failed to derive network BTC address: {}", e);
                                        return Ok(());
                                    }
                                }
                            }
                            None => {
                                warn!("❌ [BTC_UTV_BATCH] Network group key not available; cannot derive network BTC address");
                                return Ok(());
                            }
                        },
                        None => {
                            warn!("❌ [BTC_UTV_BATCH] DKG node not available");
                            return Ok(());
                        }
                    };

                    let mut batch: Vec<(
                        String,
                        String,
                        crate::chain_abstraction::ChainTransaction,
                        Vec<u8>,
                        Option<k256::Scalar>,
                    )> = Vec::new();
                    for (intent_hash, intent, user_eth_addr) in &batch_intents {
                        // For Bitcoin UserToVault, amount must be in satoshis (source chain).
                        // intent.amount is in source-chain smallest units = satoshis for Bitcoin.
                        // Do NOT use get_intent_target_amount — that is in target-chain units (e.g. wei for BTC->TICS).
                        let amount_sats: u128 = match intent.amount.trim().parse() {
                            Ok(a) if a > 0 => a,
                            _ => {
                                warn!("⚠️ [BTC_UTV_BATCH] Intent {} has invalid/zero amount '{}', skipping", intent_hash, intent.amount);
                                continue;
                            }
                        };
                        let fee_bps = crate::contract::fetch_dynamic_fee_bps().await;
                        let amount = amount_sats + (amount_sats * fee_bps / 10000); // Dynamic buffer for fees

                        let user =
                            match user_intent_manager.get_user_by_address(user_eth_addr).await {
                                Some(u) => u,
                                None => {
                                    warn!(
                                        "⚠️ [BTC_UTV_BATCH] User {} not found for intent {}",
                                        user_eth_addr, intent_hash
                                    );
                                    continue;
                                }
                            };
                        let derived_eth_addr = user.derived_eth_address.clone();
                        let derived_btc_addr = user.derived_btc_address.clone();

                        let chain_tx_result =
                            crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                                intent,
                                None,
                                derived_eth_addr.as_ref(),
                                derived_btc_addr.as_ref(),
                                crate::types::TransactionType::UserToVault,
                                None, // ETH addr not used for Bitcoin chain
                                network_btc_addr.as_ref(),
                                amount,
                            )
                            .await;

                        let chain_transaction = match chain_tx_result {
                            Ok(tx) => tx,
                            Err(e) => {
                                warn!(
                                    "❌ [BTC_UTV_BATCH] Failed to create chain tx for intent {}: {}",
                                    intent_hash, e
                                );
                                // Revert intent status back to Pending so it can be retried
                                // in a future batch (e.g. once UTXOs are confirmed).
                                if let Err(revert_err) = user_intent_manager
                                    .update_intent_status(
                                        &user.tics_address,
                                        intent_hash,
                                        IntentStatus::Pending,
                                    )
                                    .await
                                {
                                    warn!(
                                        "⚠️ [BTC_UTV_BATCH] Failed to revert intent {} to Pending: {}",
                                        intent_hash, revert_err
                                    );
                                }
                                continue;
                            }
                        };

                        let tx_bytes: Vec<u8> = match &chain_transaction {
                            crate::chain_abstraction::ChainTransaction::Bitcoin(_) => {
                                vec![] // Digest is computed from chain_tx (sighash) in get_message_and_type
                            }
                            _ => {
                                warn!("❌ [BTC_UTV_BATCH] Intent {} is not Bitcoin (expected Bitcoin)", intent_hash);
                                continue;
                            }
                        };

                        let signing_key = self.get_signing_key_for_user(Some(user_eth_addr)).await;
                        batch.push((
                            intent_hash.clone(),
                            user_eth_addr.clone(),
                            chain_transaction,
                            tx_bytes,
                            signing_key,
                        ));
                    }

                    if batch.is_empty() {
                        warn!("⚠️ [BTC_UTV_BATCH] No valid batch entries (missing users/keys/txs)");
                        return Ok(());
                    }

                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();

                    if let Some(arc) = &self.signing_node {
                        let mut signing_node = arc.lock().await;
                        signing_node.set_available_nodes(available_nodes);

                        use crate::signing::chains::BitcoinSigner;
                        let mut btc_signer = BitcoinSigner::new(&mut signing_node);
                        let n_slots = batch.len();
                        if let Err(e) = btc_signer
                            .sign_btc_user_to_vault_batch(round, batch, &nonce_assignments)
                            .await
                        {
                            warn!(
                                "❌ [BTC_UTV_BATCH] Batch signing failed for round {}: {}",
                                round, e
                            );
                            // Revert intent status back to Pending so they can be
                            // re-picked in the next epoch cycle.
                            // NEVER revert from Solved — that is a terminal state.
                            let failed_hashes: Vec<String> =
                                batch_intents.iter().map(|(h, _, _)| h.clone()).collect();
                            for (intent_hash, _intent, user_eth_addr) in &batch_intents {
                                let current = user_intent_manager
                                    .get_intent_status(user_eth_addr, intent_hash)
                                    .await;
                                if matches!(current, Some(IntentStatus::Solved)) {
                                    continue;
                                }
                                if let Err(revert_err) = user_intent_manager
                                    .update_intent_status(
                                        user_eth_addr,
                                        intent_hash,
                                        IntentStatus::Pending,
                                    )
                                    .await
                                {
                                    warn!(
                                        "⚠️ [BTC_UTV_BATCH] Failed to revert intent {} to Pending: {}",
                                        intent_hash, revert_err
                                    );
                                }
                            }

                            // Broadcast error to all nodes so they also revert
                            // intent status from Batched to Pending.
                            let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                                intent_hashes: failed_hashes,
                                error_message: format!(
                                    "BTC UTV batch signing failed for round {}: {}",
                                    round, e
                                ),
                                transaction_type: "user_to_network".to_string(),
                                solver_address: None,
                                node_id: self.local_peer_id.to_string(),
                            };
                            if let Ok(data) = serde_json::to_vec(&error_msg) {
                                let _ = self
                                    .message_tx
                                    .send(ChannelMessage::Broadcast {
                                        topic: "transaction-sync".to_string(),
                                        data,
                                    })
                                    .await;
                                info!("📡 [BTC_UTV_BATCH] Broadcasted batch failure for round {} to sync intent status across nodes", round);
                            }
                        } else {
                            info!(
                                "✅ [BTC_UTV_BATCH] Initiated batch signing for round {} ({} slots)",
                                round, n_slots
                            );
                        }
                    } else {
                        warn!("❌ [BTC_UTV_BATCH] Signing node not available");
                    }
                } else {
                    warn!("❌ [BTC_UTV_BATCH] User intent manager not available");
                }
            }
            GossipsubMessage::BtcWithdrawBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                use crate::signing::chains::bitcoin_batch::{
                    build_batch_unsigned_tx, select_utxos_for_batch,
                };
                use crate::signing::chains::bitcoin_batch::{BatchOutput, BatchPolicy, BatchUtxo};
                use crate::types::rpc_server::PendingWithdrawRequest;

                info!(
                    "📦 [BTC_WITHDRAW] Received BTC withdraw batch {} from node {} (round {}, timestamp {})",
                    batch_id, node_id, round, timestamp
                );

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // All nodes (DKG + observer) proceed with batch processing.
                // sign_bitcoin_transaction() handles observer path internally
                // (builds TX, skips signing, stores for aggregation).

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "BTC_WITHDRAW".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type BTC_WITHDRAW, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                // Load all pending withdraw records so we can look up each request
                let db = &self.db;
                let all_withdraws: Vec<(String, PendingWithdrawRequest)> =
                    match db.get_values_with_prefix("pending_withdraw_liquidity:") {
                        Ok(entries) => entries,
                        Err(e) => {
                            warn!(
                                "⚠️ [BTC_WITHDRAW] Failed to load pending withdraw requests: {}",
                                e
                            );
                            return Ok(());
                        }
                    };

                // Build a lookup map keyed by (request_id, solver_address_lower)
                let mut withdraw_map: std::collections::HashMap<
                    (String, String),
                    PendingWithdrawRequest,
                > = std::collections::HashMap::new();
                for (_key, req) in all_withdraws {
                    let key = (req.request_id.clone(), req.solver_address.to_lowercase());
                    withdraw_map.insert(key, req);
                }

                // Build BatchOutput list from BTC withdraw requests
                let mut batch_outputs: Vec<BatchOutput> = Vec::new();
                let mut used_requests: Vec<(String, String)> = Vec::new();

                for (request_id, solver_address) in &requests {
                    let key = (request_id.clone(), solver_address.to_lowercase());
                    if let Some(req) = withdraw_map.get(&key) {
                        // Only process BTC withdraws that are in Pending or Batched state and have no tx_id
                        if req.asset.to_uppercase() != "BTC"
                            || (req.status != "Pending" && req.status != "Batched")
                            || req.tx_id.is_some()
                        {
                            continue;
                        }

                        let btc_addr = match &req.btc_address {
                            Some(addr) if !addr.trim().is_empty() => addr.clone(),
                            _ => {
                                warn!(
                                    "⚠️ [BTC_WITHDRAW] Missing BTC address for withdraw request {} (solver={})",
                                    request_id, solver_address
                                );
                                continue;
                            }
                        };

                        let amount_sats: u64 = match req.amount.parse() {
                            Ok(amt) => amt,
                            Err(e) => {
                                warn!(
                                    "⚠️ [BTC_WITHDRAW] Invalid amount for withdraw request {}: {}",
                                    request_id, e
                                );
                                continue;
                            }
                        };

                        if amount_sats < 546 {
                            warn!(
                                "⚠️ [BTC_WITHDRAW] Withdraw request {} amount {} sats is below dust threshold, skipping",
                                request_id, amount_sats
                            );
                            continue;
                        }

                        batch_outputs.push(BatchOutput {
                            address: btc_addr.clone(),
                            amount: amount_sats,
                        });
                        used_requests.push((request_id.clone(), solver_address.clone()));

                        info!(
                            "💰 [BTC_WITHDRAW] Added output: {} sats to {} (request_id={}, solver={})",
                            amount_sats, btc_addr, request_id, solver_address
                        );
                    } else {
                        warn!(
                            "⚠️ [BTC_WITHDRAW] Withdraw request {} for solver {} not found in DB",
                            request_id, solver_address
                        );
                    }
                }

                if batch_outputs.is_empty() {
                    warn!("⚠️ [BTC_WITHDRAW] No valid BTC withdraw outputs after filtering");
                    return Ok(());
                }

                // Step 2: Get network's DKG Bitcoin address (where network BTC is stored)
                let dkg_node = match &self.dkg_node {
                    Some(node) => node,
                    None => {
                        error!("❌ [BTC_WITHDRAW] DKG node not available");
                        return Ok(());
                    }
                };

                let group_key = match dkg_node.get_final_public_key().await {
                    Some(key) => key,
                    None => {
                        error!("❌ [BTC_WITHDRAW] Network group key not available");
                        return Ok(());
                    }
                };

                let network_btc_address = match crate::utils::get_btc_address_from_group_key(group_key) {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("❌ [BTC_WITHDRAW] Failed to derive network BTC address: {}", e);
                        return Ok(());
                    }
                };

                info!(
                    "🏦 [BTC_WITHDRAW] Using network BTC address for withdraw batch: {}",
                    network_btc_address
                );

                // Step 3: Fetch network BTC UTXOs
                let is_testnet = crate::types::network::network_type().is_testnet();
                let utxos = match crate::utils::transaction::fetch_bitcoin_utxos(
                    &network_btc_address,
                    is_testnet,
                )
                .await
                {
                    Ok(utxos) => utxos,
                    Err(e) => {
                        error!(
                            "❌ [BTC_WITHDRAW] Failed to fetch UTXOs for liquidity operator: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                info!(
                    "📦 [BTC_WITHDRAW] Fetched {} UTXOs from liquidity operator for withdraw batch",
                    utxos.len()
                );

                // Step 4: Convert BitcoinUtxo → BatchUtxo
                let mut batch_utxos: Vec<BatchUtxo> = Vec::new();

                let network_script_pubkey =
                    match crate::utils::transaction::create_bitcoin_script_pubkey(
                        &network_btc_address,
                    ) {
                        Ok(spk) => spk,
                        Err(e) => {
                            error!(
                                "❌ [BTC_WITHDRAW] Failed to create script pubkey for network address: {}",
                                e
                            );
                            return Ok(());
                        }
                    };

                for utxo in utxos {
                    if !utxo.status.confirmed {
                        continue;
                    }

                    batch_utxos.push(BatchUtxo {
                        txid: utxo.txid,
                        vout: utxo.vout,
                        value: utxo.value,
                        script_pubkey: network_script_pubkey.clone(),
                    });
                }

                info!(
                    "✅ [BTC_WITHDRAW] Prepared {} confirmed UTXOs for withdraw batch selection",
                    batch_utxos.len()
                );

                // Step 5: Select UTXOs for batch transaction
                let policy = BatchPolicy {
                    fee_rate: std::env::var("BTC_FEE_RATE_SAT_VB")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(1),
                    dust_threshold: 546,
                    change_address: network_btc_address.clone(),
                };

                let selected = match select_utxos_for_batch(&batch_utxos, &batch_outputs, &policy) {
                    Ok(sel) => sel,
                    Err(e) => {
                        error!("❌ [BTC_WITHDRAW] UTXO selection failed: {}", e);
                        return Ok(());
                    }
                };

                info!(
                    "💰 [BTC_WITHDRAW] Selected {} UTXOs: total={} sats, fee={} sats, change={} sats",
                    selected.utxos.len(),
                    selected.total_input_value,
                    selected.fee,
                    selected.change
                );

                // Deduct fee_per_output from each output and filter dust
                let fee_per_solver = selected.fee_per_output;

                let mut valid_outputs = Vec::new();
                let mut valid_requests = Vec::new();

                for (idx, output) in batch_outputs.into_iter().enumerate() {
                    let req_tuple = used_requests[idx].clone();

                    if output.amount > fee_per_solver + policy.dust_threshold {
                        valid_outputs.push(BatchOutput {
                            address: output.address,
                            amount: output.amount - fee_per_solver,
                        });
                        valid_requests.push(req_tuple);
                    } else {
                        warn!(
                            "⚠️ [BTC_WITHDRAW] Dropping request {} because amount {} cannot cover fee {} + dust {}",
                            req_tuple.0, output.amount, fee_per_solver, policy.dust_threshold
                        );
                    }
                }

                if valid_outputs.is_empty() {
                    warn!("⚠️ [BTC_WITHDRAW] All outputs were dropped due to insufficient amounts to cover fees");
                    return Ok(());
                }

                // Update the batch vectors used downstream
                batch_outputs = valid_outputs;
                used_requests = valid_requests;

                // Step 6: Build unsigned transaction
                let unsigned_tx = match build_batch_unsigned_tx(&selected, &batch_outputs, &policy)
                {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!(
                            "❌ [BTC_WITHDRAW] Failed to build unsigned withdraw transaction: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                info!(
                    "🔨 [BTC_WITHDRAW] Built unsigned withdraw transaction: {} inputs, {} outputs",
                    unsigned_tx.input.len(),
                    unsigned_tx.output.len()
                );

                // Step 7: Convert to internal BitcoinTransaction type
                let mut our_inputs = Vec::new();
                for (i, tx_in) in unsigned_tx.input.iter().enumerate() {
                    our_inputs.push(crate::types::BitcoinInput {
                        txid: tx_in.previous_output.txid.to_string(),
                        vout: tx_in.previous_output.vout,
                        script_sig: vec![],
                        sequence: tx_in.sequence.0,
                        witness_utxo: Some(crate::types::BitcoinWitnessUtxo {
                            value: selected.utxos[i].value,
                            script_pubkey: selected.utxos[i].script_pubkey.clone(),
                        }),
                    });
                }

                let mut our_outputs = Vec::new();
                for tx_out in &unsigned_tx.output {
                    our_outputs.push(crate::types::BitcoinOutput {
                        value: tx_out.value.to_sat(),
                        script_pubkey: tx_out.script_pubkey.as_bytes().to_vec(),
                    });
                }

                let our_btc_tx = crate::types::BitcoinTransaction {
                    version: unsigned_tx.version.0 as u32,
                    inputs: our_inputs,
                    outputs: our_outputs,
                    lock_time: unsigned_tx.lock_time.to_consensus_u32(),
                    witness: None,
                };

                let mismatch = nonce_tuple_ids
                    .as_ref()
                    .map_or(true, |ids| ids.len() != our_btc_tx.inputs.len());
                if mismatch {
                    let nonce_count = nonce_tuple_ids.as_ref().map_or(0, |ids| ids.len());
                    let input_count = our_btc_tx.inputs.len();
                    error!(
                        "❌ [BTC_WITHDRAW] Nonce/input count mismatch for batch {}: nonce_ids={}, inputs={}. Rejecting and rolling back batch",
                        batch_id,
                        nonce_count,
                        input_count
                    );

                    self.processed_batch_rounds
                        .remove(&(round, "BTC_WITHDRAW".to_string()));

                    let entries: Vec<(String, PendingWithdrawRequest)> = self
                        .db
                        .get_values_with_prefix("pending_withdraw_liquidity:")
                        .unwrap_or_default();
                    for (key, req) in entries {
                        let req_solver_lower = req.solver_address.to_lowercase();
                        if req.status == "Batched"
                            && req.tx_id.is_none()
                            && used_requests.iter().any(|(rid, solver)| {
                                *rid == req.request_id && solver.to_lowercase() == req_solver_lower
                            })
                        {
                            let mut reverted = req.clone();
                            reverted.status = "Pending".to_string();
                            let _ = self.db.put_string(&key, &reverted);
                            info!(
                                "🔄 [BTC_WITHDRAW] Reverted withdraw {} to Pending after nonce/input mismatch",
                                req.request_id
                            );
                        }
                    }
                    return Ok(());
                }

                info!("🔄 [BTC_WITHDRAW] Converted to internal BitcoinTransaction type");

                // Step 8: Trigger signing using existing BTC batch signing flow
                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let mut chain_handler_box =
                        crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                            crate::types::network::network_type()
                                .bitcoin_network_label()
                                .to_string(),
                        );

                    // Set network's DKG group key
                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(group_key) = dkg_node.get_final_public_key().await {
                            let affine_point = group_key.to_affine();
                            let encoded_point = k256::EncodedPoint::from(affine_point);
                            let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                            if let Some(btc_handler) = chain_handler_box
                                .as_any_mut()
                                .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                            ) {
                                btc_handler.set_group_public_key(compressed_bytes);
                                debug!("🔑 [BTC_WITHDRAW] Set network DKG group public key");
                            }
                        }
                    }

                    let chain_handler: std::sync::Arc<dyn crate::chain_abstraction::ChainHandler> =
                        std::sync::Arc::from(chain_handler_box);

                    let tx_bytes = chain_handler.create_transaction_bytes(
                        &crate::chain_abstraction::ChainTransaction::Bitcoin(our_btc_tx.clone()),
                    )?;

                    let signing_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_secret_share().await
                    } else {
                        None
                    };

                    info!("🔐 [BTC_WITHDRAW] Starting Bitcoin withdraw batch signing process...");

                    // Encode batch metadata as "request_id|solver_address" per entry so the
                    // signing layer can stash it in `withdraw_pending_transactions_btc`.
                    let withdraw_identifiers: Vec<String> = used_requests
                        .iter()
                        .map(|(req_id, solver_addr)| {
                            format!("{}|{}", req_id, solver_addr.to_lowercase())
                        })
                        .collect();

                    use crate::signing::chains::BitcoinSigner;
                    let mut btc_signer = BitcoinSigner::new(&mut signing_node);
                    if let Err(e) = btc_signer
                        .sign_transaction(
                            tx_bytes,
                            &chain_handler,
                            Some(our_btc_tx),
                            None, // No user eth address
                            withdraw_identifiers.clone(),
                            Some(crate::types::TransactionType::WithdrawLiquidity),
                            signing_key,
                            None, // No per-withdraw solver address; encoded in identifiers
                            signing_key,
                            nonce_tuple_ids.clone(),
                            round,
                        )
                        .await
                    {
                        warn!(
                            "❌ [BTC_WITHDRAW] Batch signing failed for round {}: {}",
                            round, e
                        );

                        // Revert local Batched requests to Pending (never Completed)
                        {
                            use crate::types::rpc_server::PendingWithdrawRequest;
                            let entries: Vec<(String, PendingWithdrawRequest)> = self
                                .db
                                .get_values_with_prefix("pending_withdraw_liquidity:")
                                .unwrap_or_default();
                            for (key, req) in entries {
                                if req.status == "Batched"
                                    && req.tx_id.is_none()
                                    && used_requests.iter().any(|(rid, _)| *rid == req.request_id)
                                {
                                    let mut reverted = req.clone();
                                    reverted.status = "Pending".to_string();
                                    let _ = self.db.put_string(&key, &reverted);
                                    info!(
                                        "🔄 [BTC_WITHDRAW] Reverted withdraw {} to Pending",
                                        req.request_id
                                    );
                                }
                            }
                        }

                        // Broadcast error so other nodes also revert
                        let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: withdraw_identifiers,
                            error_message: format!(
                                "BTC withdraw batch signing failed for round {}: {}",
                                round, e
                            ),
                            transaction_type: "withdraw_liquidity".to_string(),
                            solver_address: None,
                            node_id: self.local_peer_id.to_string(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: "transaction-sync".to_string(),
                                    data,
                                })
                                .await;
                            info!("📡 [BTC_WITHDRAW] Broadcasted batch failure for round {} to sync status across nodes", round);
                        }
                    } else {
                        debug!("✅ [BTC_WITHDRAW] Bitcoin withdraw batch transaction signing initiated");
                    }
                } else {
                    error!("❌ [BTC_WITHDRAW] Signing node not available");
                }
            }
            GossipsubMessage::BtcClaimRewardBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                use crate::contract::{ContractClient, ContractConfig, SolverManagerContract};
                use crate::signing::chains::bitcoin_batch::{
                    build_batch_unsigned_tx, select_utxos_for_batch,
                };
                use crate::signing::chains::bitcoin_batch::{BatchOutput, BatchPolicy, BatchUtxo};
                use crate::types::rpc_server::PendingClaimRewardRequest;
                use ethers::types::Address;

                info!(
                    "📦 [BTC_CLAIM_REWARD] Received BTC claim-reward batch {} from node {} (timestamp {})",
                    batch_id, node_id, timestamp
                );

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // All nodes (DKG + observer) proceed with batch processing.
                // sign_bitcoin_transaction() handles observer path internally
                // (builds TX, skips signing, stores for aggregation).

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "BTC_CLAIM_REWARD".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type BTC_CLAIM_REWARD, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                let db = &self.db;
                let all_claims: Vec<(String, PendingClaimRewardRequest)> = match db
                    .get_values_with_prefix("pending_claim_reward:")
                {
                    Ok(entries) => entries,
                    Err(e) => {
                        warn!(
                                "⚠️ [BTC_CLAIM_REWARD] Failed to load pending claim reward requests: {}",
                                e
                            );
                        return Ok(());
                    }
                };

                let mut claim_map: std::collections::HashMap<
                    (String, String),
                    PendingClaimRewardRequest,
                > = std::collections::HashMap::new();
                for (_key, req) in all_claims {
                    let key = (req.request_id.clone(), req.solver_address.to_lowercase());
                    claim_map.insert(key, req);
                }

                let mut batch_outputs: Vec<BatchOutput> = Vec::new();
                let mut used_requests: Vec<(String, String)> = Vec::new();

                for (request_id, solver_address) in &requests {
                    let key = (request_id.clone(), solver_address.to_lowercase());
                    let req = match claim_map.get(&key) {
                        Some(r) => r,
                        None => {
                            warn!(
                                "⚠️ [BTC_CLAIM_REWARD] Claim request {} for solver {} not found in DB",
                                request_id, solver_address
                            );
                            continue;
                        }
                    };
                    if (req.status != "Pending" && req.status != "Batched") || req.tx_id.is_some() {
                        continue;
                    }
                    let btc_addr = match &req.btc_address {
                        Some(addr) if !addr.trim().is_empty() => addr.clone(),
                        _ => {
                            warn!(
                                "⚠️ [BTC_CLAIM_REWARD] Missing BTC address for claim request {} (solver={})",
                                request_id, solver_address
                            );
                            continue;
                        }
                    };

                    let solver_addr = solver_address
                        .parse::<Address>()
                        .map_err(|_| anyhow::anyhow!("invalid solver address {}", solver_address));
                    let solver_addr = match solver_addr {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    let rpc_url = crate::env_defaults::solver_contract_rpc_url();
                    let contract_address_env = crate::env_defaults::solver_contract_address();
                    let chain_id = crate::env_defaults::solver_contract_chain_id()
                        .parse::<u64>()
                        .ok()
                        .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());
                    if contract_address_env == "0x0000000000000000000000000000000000000000" {
                        warn!("⚠️ [BTC_CLAIM_REWARD] Solver contract not configured; skipping unclaimed fetch");
                        continue;
                    }
                    let contract_address = match contract_address_env.parse::<Address>() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let config = ContractConfig {
                        rpc_url: rpc_url.clone(),
                        contract_address,
                        chain_id,
                    };
                    let client = match ContractClient::new(config.clone()) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let contract = match SolverManagerContract::new(&config, client.provider()) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let solver_id = match contract.get_solver_id(solver_addr).await {
                        Ok(id) if !id.trim().is_empty() => id,
                        _ => continue,
                    };
                    let rewards = match contract
                        .get_solvers_unclaimed_rewards(vec![solver_id.clone()])
                        .await
                    {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let btc_unclaimed = rewards
                        .first()
                        .map(|r| r.1)
                        .unwrap_or(ethers::types::U256::zero());
                    let amount_sats: u64 = btc_unclaimed.as_u64();
                    if amount_sats <= DUST_LIMIT_SATS {
                        continue;
                    }
                    batch_outputs.push(BatchOutput {
                        address: btc_addr.clone(),
                        amount: amount_sats,
                    });
                    used_requests.push((request_id.clone(), solver_address.clone()));
                }

                if batch_outputs.is_empty() {
                    warn!("⚠️ [BTC_CLAIM_REWARD] No valid claim-reward outputs after filtering");
                    return Ok(());
                }

                let dkg_node = match &self.dkg_node {
                    Some(node) => node,
                    None => {
                        error!("❌ [BTC_CLAIM_REWARD] DKG node not available");
                        return Ok(());
                    }
                };
                let group_key = match dkg_node.get_final_public_key().await {
                    Some(key) => key,
                    None => {
                        error!("❌ [BTC_CLAIM_REWARD] Network group key not available");
                        return Ok(());
                    }
                };
                let network_btc_address = match crate::utils::get_btc_address_from_group_key(group_key) {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_REWARD] Failed to derive network BTC address: {}", e);
                        return Ok(());
                    }
                };

                let is_testnet = crate::types::network::network_type().is_testnet();
                let utxos = match crate::utils::transaction::fetch_bitcoin_utxos(
                    &network_btc_address,
                    is_testnet,
                )
                .await
                {
                    Ok(utxos) => utxos,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_REWARD] Failed to fetch UTXOs: {}", e);
                        return Ok(());
                    }
                };

                let mut batch_utxos: Vec<BatchUtxo> = Vec::new();
                let network_script_pubkey =
                    match crate::utils::transaction::create_bitcoin_script_pubkey(
                        &network_btc_address,
                    ) {
                        Ok(spk) => spk,
                        Err(e) => {
                            error!(
                                "❌ [BTC_CLAIM_REWARD] Failed to create script pubkey: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
                for utxo in utxos {
                    if !utxo.status.confirmed {
                        continue;
                    }
                    batch_utxos.push(BatchUtxo {
                        txid: utxo.txid,
                        vout: utxo.vout,
                        value: utxo.value,
                        script_pubkey: network_script_pubkey.clone(),
                    });
                }

                let policy = BatchPolicy {
                    fee_rate: std::env::var("BTC_FEE_RATE_SAT_VB")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(1),
                    dust_threshold: 546,
                    change_address: network_btc_address.clone(),
                };

                let selected = match select_utxos_for_batch(&batch_utxos, &batch_outputs, &policy) {
                    Ok(sel) => sel,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_REWARD] UTXO selection failed: {}", e);
                        return Ok(());
                    }
                };

                info!(
                    "💰 [BTC_CLAIM_REWARD] Selected {} UTXOs: total={} sats, fee={} sats, change={} sats",
                    selected.utxos.len(),
                    selected.total_input_value,
                    selected.fee,
                    selected.change
                );

                let fee_per_solver = selected.fee_per_output;

                let mut valid_outputs = Vec::new();
                let mut valid_requests = Vec::new();

                for (idx, output) in batch_outputs.into_iter().enumerate() {
                    let req_tuple = used_requests[idx].clone();

                    if output.amount > fee_per_solver + policy.dust_threshold {
                        valid_outputs.push(BatchOutput {
                            address: output.address,
                            amount: output.amount - fee_per_solver,
                        });
                        valid_requests.push(req_tuple);
                    } else {
                        warn!(
                            "⚠️ [BTC_CLAIM_REWARD] Dropping request {} because amount {} cannot cover fee {} + dust {}",
                            req_tuple.0, output.amount, fee_per_solver, policy.dust_threshold
                        );
                    }
                }

                if valid_outputs.is_empty() {
                    warn!("⚠️ [BTC_CLAIM_REWARD] All outputs were dropped due to insufficient amounts to cover fees");
                    return Ok(());
                }

                batch_outputs = valid_outputs;
                used_requests = valid_requests;

                let unsigned_tx = match build_batch_unsigned_tx(&selected, &batch_outputs, &policy)
                {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_REWARD] Failed to build unsigned tx: {}", e);
                        return Ok(());
                    }
                };

                let mut our_inputs = Vec::new();
                for (i, tx_in) in unsigned_tx.input.iter().enumerate() {
                    our_inputs.push(crate::types::BitcoinInput {
                        txid: tx_in.previous_output.txid.to_string(),
                        vout: tx_in.previous_output.vout,
                        script_sig: vec![],
                        sequence: tx_in.sequence.0,
                        witness_utxo: Some(crate::types::BitcoinWitnessUtxo {
                            value: selected.utxos[i].value,
                            script_pubkey: selected.utxos[i].script_pubkey.clone(),
                        }),
                    });
                }
                let mut our_outputs = Vec::new();
                for tx_out in &unsigned_tx.output {
                    our_outputs.push(crate::types::BitcoinOutput {
                        value: tx_out.value.to_sat(),
                        script_pubkey: tx_out.script_pubkey.as_bytes().to_vec(),
                    });
                }
                let our_btc_tx = crate::types::BitcoinTransaction {
                    version: unsigned_tx.version.0 as u32,
                    inputs: our_inputs,
                    outputs: our_outputs,
                    lock_time: unsigned_tx.lock_time.to_consensus_u32(),
                    witness: None,
                };

                if nonce_tuple_ids
                    .as_ref()
                    .map_or(true, |ids| ids.len() != our_btc_tx.inputs.len())
                {
                    error!(
                        "❌ [BTC_CLAIM_REWARD] Nonce/input count mismatch. metadata={{batch_id: {}, round: {}, timestamp: {}, coordinator_node_id: {}, request_count: {}}}, counts={{nonce_tuple_ids: {}, tx_inputs: {}}}. Rejecting and rolling back batch",
                        batch_id,
                        round,
                        timestamp,
                        node_id,
                        requests.len(),
                        nonce_tuple_ids.as_ref().map(|ids| ids.len()).unwrap_or(0),
                        our_btc_tx.inputs.len()
                    );

                    self.processed_batch_rounds
                        .remove(&(round, "BTC_CLAIM_REWARD".to_string()));

                    let entries: Vec<(String, PendingClaimRewardRequest)> = self
                        .db
                        .get_values_with_prefix("pending_claim_reward:")
                        .unwrap_or_default();
                    for (key, req) in entries {
                        if req.status == "Batched"
                            && req
                                .tx_id
                                .as_ref()
                                .map(|tx_id| tx_id.trim().is_empty())
                                .unwrap_or(true)
                            && used_requests.iter().any(|(rid, solver)| {
                                *rid == req.request_id
                                    && solver.eq_ignore_ascii_case(&req.solver_address)
                            })
                        {
                            let mut reverted = req.clone();
                            reverted.status = "Pending".to_string();
                            let _ = self.db.put_string(&key, &reverted);
                            info!(
                                "🔄 [BTC_CLAIM_REWARD] Reverted claim {} to Pending after nonce/input mismatch",
                                req.request_id
                            );
                        }
                    }
                    return Ok(());
                }

                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let mut chain_handler_box =
                        crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                            crate::types::network::network_type()
                                .bitcoin_network_label()
                                .to_string(),
                        );
                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(group_key) = dkg_node.get_final_public_key().await {
                            let affine_point = group_key.to_affine();
                            let encoded_point = k256::EncodedPoint::from(affine_point);
                            let compressed_bytes = encoded_point.compress().to_bytes().to_vec();
                            if let Some(btc_handler) = chain_handler_box
                                .as_any_mut()
                                .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                            ) {
                                btc_handler.set_group_public_key(compressed_bytes);
                            }
                        }
                    }
                    let chain_handler: std::sync::Arc<dyn crate::chain_abstraction::ChainHandler> =
                        std::sync::Arc::from(chain_handler_box);
                    let tx_bytes = chain_handler.create_transaction_bytes(
                        &crate::chain_abstraction::ChainTransaction::Bitcoin(our_btc_tx.clone()),
                    )?;
                    let signing_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_secret_share().await
                    } else {
                        None
                    };
                    let claim_reward_identifiers: Vec<String> = used_requests
                        .iter()
                        .map(|(req_id, solver_addr)| {
                            format!("{}|{}", req_id, solver_addr.to_lowercase())
                        })
                        .collect();
                    use crate::signing::chains::BitcoinSigner;
                    let mut btc_signer = BitcoinSigner::new(&mut signing_node);
                    if let Err(e) = btc_signer
                        .sign_transaction(
                            tx_bytes,
                            &chain_handler,
                            Some(our_btc_tx),
                            None,
                            claim_reward_identifiers.clone(),
                            Some(crate::types::TransactionType::ClaimReward),
                            signing_key,
                            None,
                            signing_key,
                            nonce_tuple_ids.clone(),
                            round,
                        )
                        .await
                    {
                        warn!(
                            "❌ [BTC_CLAIM_REWARD] Batch signing failed for round {}: {}",
                            round, e
                        );

                        // Revert local Batched requests to Pending (never Completed)
                        {
                            use crate::types::rpc_server::PendingClaimRewardRequest;
                            let entries: Vec<(String, PendingClaimRewardRequest)> = self
                                .db
                                .get_values_with_prefix("pending_claim_reward:")
                                .unwrap_or_default();
                            for (key, req) in entries {
                                if req.status == "Batched"
                                    && req.tx_id.is_none()
                                    && used_requests.iter().any(|(rid, _)| *rid == req.request_id)
                                {
                                    let mut reverted = req.clone();
                                    reverted.status = "Pending".to_string();
                                    let _ = self.db.put_string(&key, &reverted);
                                    info!(
                                        "🔄 [BTC_CLAIM_REWARD] Reverted claim_reward {} to Pending",
                                        req.request_id
                                    );
                                }
                            }
                        }

                        // Broadcast error so other nodes also revert
                        let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: claim_reward_identifiers,
                            error_message: format!(
                                "BTC claim-reward batch signing failed for round {}: {}",
                                round, e
                            ),
                            transaction_type: "claim_reward".to_string(),
                            solver_address: None,
                            node_id: self.local_peer_id.to_string(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: "transaction-sync".to_string(),
                                    data,
                                })
                                .await;
                            info!("📡 [BTC_CLAIM_REWARD] Broadcasted batch failure for round {} to sync status across nodes", round);
                        }
                    } else {
                        debug!(
                            "✅ [BTC_CLAIM_REWARD] Bitcoin claim-reward batch signing initiated"
                        );
                    }
                } else {
                    error!("❌ [BTC_CLAIM_REWARD] Signing node not available");
                }
            }
            GossipsubMessage::TicsWithdrawBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                use crate::types::rpc_server::PendingWithdrawRequest;
                use crate::utils::transaction::RemoveLiquidityBatchRequest;
                use ethers::types::U256;

                info!(
                    "📦 [TICS_WITHDRAW] Received TICS withdraw batch {} from node {} (round {}, timestamp {})",
                    batch_id, node_id, round, timestamp
                );

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "TICS_WITHDRAW".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type TICS_WITHDRAW, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                if requests.is_empty() {
                    info!("ℹ️  [TICS_WITHDRAW] Empty TicsWithdrawBatch received, nothing to do");
                    return Ok(());
                }

                // Load all pending withdraw records so we can look up each request
                let db = &self.db;
                let all_withdraws: Vec<(String, PendingWithdrawRequest)> =
                    match db.get_values_with_prefix("pending_withdraw_liquidity:") {
                        Ok(entries) => entries,
                        Err(e) => {
                            warn!(
                                "⚠️ [TICS_WITHDRAW] Failed to load pending withdraw requests: {}",
                                e
                            );
                            return Ok(());
                        }
                    };

                // Build a lookup map keyed by (request_id, solver_address_lower)
                let mut withdraw_map: std::collections::HashMap<
                    (String, String),
                    PendingWithdrawRequest,
                > = std::collections::HashMap::new();
                for (_key, req) in all_withdraws {
                    let key = (req.request_id.clone(), req.solver_address.to_lowercase());
                    withdraw_map.insert(key, req);
                }

                // Accept both Pending and Batched (epoch 3 marks as Batched before sending)
                let is_pending_or_batched = |s: &str| s == "Pending" || s == "Batched";

                // 1) Aggregate TICS withdraw amount per solver (all solvers in the batch)
                let mut per_solver_tics: std::collections::HashMap<String, U256> =
                    std::collections::HashMap::new();

                // 2) Collect BTC requests that have tx_id (for contract registration)
                let mut btc_entries: Vec<(String, String, U256)> = Vec::new(); // (solver_address_lower, tx_id, amount)
                                                                               // 3) Collect "request_id|solver_address" for all requests included in this batch (for tx-id broadcast)
                let mut used_identifiers: Vec<String> = Vec::new();

                for entry in &requests {
                    let key = (
                        entry.request_id.clone(),
                        entry.solver_address.to_lowercase(),
                    );
                    let req = match withdraw_map.get(&key) {
                        Some(r) => r,
                        None => {
                            warn!(
                                "⚠️ [TICS_WITHDRAW] Withdraw request {} for solver {} not found in DB",
                                entry.request_id, entry.solver_address
                            );
                            continue;
                        }
                    };

                    if !is_pending_or_batched(&req.status) {
                        continue;
                    }

                    let amount_u256 = match U256::from_dec_str(&req.amount) {
                        Ok(a) => a,
                        Err(e) => {
                            warn!(
                                "⚠️ [TICS_WITHDRAW] Invalid amount for request {}: {}",
                                req.request_id, e
                            );
                            continue;
                        }
                    };

                    if req.asset.to_uppercase() == "TICS" {
                        if amount_u256.is_zero() {
                            continue;
                        }
                        used_identifiers
                            .push(format!("{}|{}", entry.request_id, entry.solver_address));
                        let solver_key = req.solver_address.to_lowercase();
                        let agg = per_solver_tics
                            .entry(solver_key.clone())
                            .or_insert(U256::zero());
                        *agg += amount_u256;
                        info!(
                            "💧 [TICS_WITHDRAW] Aggregated TICS {} for solver {} from request {}",
                            amount_u256, solver_key, req.request_id
                        );
                    } else if req.asset.to_uppercase() == "BTC" {
                        // Include BTC requests that already have tx_id (funds sent; register on contract)
                        let tx_id = match &req.tx_id {
                            Some(id) if !id.is_empty() => id.clone(),
                            _ => continue,
                        };
                        used_identifiers
                            .push(format!("{}|{}", entry.request_id, entry.solver_address));
                        btc_entries.push((req.solver_address.to_lowercase(), tx_id, amount_u256));
                        info!(
                            "💧 [TICS_WITHDRAW] Including BTC request {} for solver {} (tx_id={}, amount={})",
                            req.request_id, req.solver_address, req.tx_id.as_deref().unwrap_or(""), amount_u256
                        );
                    }
                }

                // Build single removeLiquidity batch: TICS entries (aggregated per solver) + BTC entries (one per request with tx_id)
                let mut batch_requests: Vec<RemoveLiquidityBatchRequest> = Vec::new();

                for (solver_address_lower, total_amount) in &per_solver_tics {
                    if total_amount.is_zero() {
                        continue;
                    }
                    let solver_id =
                        match self.fetch_solver_id_for_address(solver_address_lower).await {
                            Ok(id) => id,
                            Err(e) => {
                                warn!(
                                "⚠️ [TICS_WITHDRAW] Unable to fetch solver ID for {}: {}; skipping",
                                solver_address_lower, e
                            );
                                continue;
                            }
                        };
                    batch_requests.push((
                        solver_id,
                        *total_amount,
                        1u8, // chainType TICS
                        batch_id.clone(),
                    ));
                }

                for (solver_address_lower, tx_id, amount) in &btc_entries {
                    let solver_id = match self
                        .fetch_solver_id_for_address(solver_address_lower)
                        .await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            warn!(
                                "⚠️ [TICS_WITHDRAW] Unable to fetch solver ID for {} (BTC): {}; skipping",
                                solver_address_lower, e
                            );
                            continue;
                        }
                    };
                    batch_requests.push((
                        solver_id,
                        *amount,
                        0u8, // chainType BTC
                        tx_id.clone(),
                    ));
                }

                if batch_requests.is_empty() {
                    warn!(
                        "⚠️ [TICS_WITHDRAW] No valid TICS or BTC withdraw entries to process for batch {}",
                        batch_id
                    );
                    return Ok(());
                }

                info!(
                    "📦 [TICS_WITHDRAW] Built removeLiquidity batch: {} entries (TICS solvers={}, BTC entries={})",
                    batch_requests.len(),
                    per_solver_tics.len(),
                    btc_entries.len()
                );

                // Get DKG node and vault group key for liquidity operator address
                let dkg_node = if let Some(node) = &self.dkg_node {
                    node
                } else {
                    warn!(
                        "❌ [TICS_WITHDRAW] Cannot process TICS withdraw batch - DKG node unavailable"
                    );
                    return Ok(());
                };

                let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
                    key
                } else {
                    warn!(
                        "❌ [TICS_WITHDRAW] Liquidity operator group key unavailable; cannot derive address"
                    );
                    return Ok(());
                };

                let liquidity_operator_address =
                    crate::utils::get_eth_address_from_group_key(group_public_key);

                let contract_address = crate::env_defaults::solver_contract_address();
                if contract_address == "0x0000000000000000000000000000000000000000" {
                    warn!(
                        "⏭️ [TICS_WITHDRAW] Skipping TICS withdraw batch {} - solver contract address not configured",
                        batch_id
                    );
                    return Ok(());
                }

                let tics_cid = crate::env_defaults::mpc_tics_chain_id();
                let contract_chain_id = crate::env_defaults::solver_contract_chain_id()
                    .parse::<u64>()
                    .unwrap_or(tics_cid);
                let contract_chain_name = if contract_chain_id == tics_cid {
                    "qubetics"
                } else {
                    "tics"
                };

                // One removeLiquidity tx for the entire batch (all TICS + all BTC with tx_id)
                let eth_tx =
                    crate::utils::transaction::create_solver_remove_liquidity_batch_transaction(
                        &liquidity_operator_address,
                        &batch_requests,
                        &batch_id,
                        &contract_address,
                        contract_chain_id,
                        contract_chain_name,
                    )
                    .await?;

                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);
                    signing_node.set_chain_handler(
                        crate::chain_abstraction::ChainHandlerFactory::create_tics_handler(
                            eth_tx.chain_id,
                        )
                        .into(),
                    );

                    // Build contract TX (needed by both DKG and observer nodes)
                    let contract_tx = crate::types::intent::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        nonce: eth_tx.nonce,
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        chain_id: eth_tx.chain_id,
                        data: eth_tx
                            .data
                            .as_ref()
                            .map(|d| format!("0x{}", hex::encode(d)))
                            .unwrap_or_else(|| "0x".to_string()),
                    };

                    // Both DKG and observer nodes call sign_contract_message;
                    // observer nodes build + store the TX and advance round but skip ECDSA signing
                    let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;
                    signing_node.set_vault_group_key(group_public_key);

                    let contract_tx_bytes =
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        );
                    let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
                    let mut eth_signer = crate::signing::TicsSigner::new(&mut signing_node);

                    let nonce_tuple_id = nonce_tuple_ids
                        .as_ref()
                        .and_then(|ids| ids.first().cloned());

                    if let Err(e) = eth_signer
                        .sign_contract_message(
                            contract_tx_bytes,
                            &contract_chain_handler,
                            &contract_tx,
                            vault_tweaked_share.clone(),
                            None,
                            vec![],
                            vault_tweaked_share,
                            None,
                            None,
                            Some(used_identifiers.clone()),
                            None,
                            None,
                            nonce_tuple_id.clone(),
                            round,
                        )
                        .await
                    {
                        warn!(
                            "❌ [TICS_WITHDRAW] Batch signing failed for round {}: {}",
                            round, e
                        );

                        // Revert local Batched requests to Pending (never Completed)
                        {
                            use crate::types::rpc_server::PendingWithdrawRequest;
                            let entries: Vec<(String, PendingWithdrawRequest)> = self
                                .db
                                .get_values_with_prefix("pending_withdraw_liquidity:")
                                .unwrap_or_default();
                            for (key, req) in entries {
                                if req.status == "Batched"
                                    && req.tx_id.is_none()
                                    && used_identifiers.iter().any(|id| {
                                        id.split_once('|')
                                            .map_or(false, |(rid, _)| rid == req.request_id)
                                    })
                                {
                                    let mut reverted = req.clone();
                                    reverted.status = "Pending".to_string();
                                    let _ = self.db.put_string(&key, &reverted);
                                    info!(
                                        "🔄 [TICS_WITHDRAW] Reverted withdraw {} to Pending",
                                        req.request_id
                                    );
                                }
                            }
                        }

                        // Broadcast error so other nodes also revert
                        let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: used_identifiers,
                            error_message: format!(
                                "TICS withdraw batch signing failed for round {}: {}",
                                round, e
                            ),
                            transaction_type: "withdraw_liquidity".to_string(),
                            solver_address: None,
                            node_id: self.local_peer_id.to_string(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: "transaction-sync".to_string(),
                                    data,
                                })
                                .await;
                            info!("📡 [TICS_WITHDRAW] Broadcasted batch failure for round {} to sync status across nodes", round);
                        }
                    } else {
                        info!(
                            "✅ [TICS_WITHDRAW] Submitted single removeLiquidity batch transaction ({} entries) into MPC signing flow",
                            batch_requests.len()
                        );
                    }
                } else {
                    warn!("❌ [TICS_WITHDRAW] Signing node unavailable for TICS withdraw batch");
                }
            }
            GossipsubMessage::TicsClaimRewardBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                use crate::contract::{ContractClient, ContractConfig, SolverManagerContract};
                use crate::types::rpc_server::PendingClaimRewardRequest;
                use crate::utils::transaction::{
                    create_solver_claim_rewards_batch_transaction, RewardClaimBatchEntry,
                };
                use ethers::types::{Address, U256};

                info!(
                    "📦 [TICS_CLAIM_REWARD] Received TICS claim-reward batch {} from node {} (timestamp {})",
                    batch_id, node_id, timestamp
                );

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "TICS_CLAIM_REWARD".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type TICS_CLAIM_REWARD, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                if requests.is_empty() {
                    info!("ℹ️  [TICS_CLAIM_REWARD] Empty TicsClaimRewardBatch received, nothing to do");
                    return Ok(());
                }

                let db = &self.db;
                let all_claims: Vec<(String, PendingClaimRewardRequest)> = match db
                    .get_values_with_prefix("pending_claim_reward:")
                {
                    Ok(entries) => entries,
                    Err(e) => {
                        warn!(
                                "⚠️ [TICS_CLAIM_REWARD] Failed to load pending claim reward requests: {}",
                                e
                            );
                        return Ok(());
                    }
                };

                let mut claim_map: std::collections::HashMap<
                    (String, String),
                    PendingClaimRewardRequest,
                > = std::collections::HashMap::new();
                for (_key, req) in all_claims {
                    let key = (req.request_id.clone(), req.solver_address.to_lowercase());
                    claim_map.insert(key, req);
                }

                let is_pending_or_batched = |s: &str| s == "Pending" || s == "Batched";

                // Aggregate TICS unclaimed per solver (solver_address -> amount)
                let mut per_solver_tics: std::collections::HashMap<String, U256> =
                    std::collections::HashMap::new();
                // All request identifiers for tx-id broadcast (request_id|solver_address)
                let mut used_identifiers: Vec<String> = Vec::new();

                // Collect unique TICS solver addresses and their request identifiers
                let mut tics_solver_addresses: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for entry in &requests {
                    let key = (
                        entry.request_id.clone(),
                        entry.solver_address.to_lowercase(),
                    );
                    let req = match claim_map.get(&key) {
                        Some(r) => r,
                        None => {
                            warn!(
                                "⚠️ [TICS_CLAIM_REWARD] Claim request {} for solver {} not found in DB",
                                entry.request_id, entry.solver_address
                            );
                            continue;
                        }
                    };
                    if !is_pending_or_batched(&req.status) {
                        continue;
                    }
                    used_identifiers.push(format!("{}|{}", entry.request_id, entry.solver_address));

                    let has_eth = req
                        .tics_address
                        .as_ref()
                        .map_or(false, |a| !a.trim().is_empty());
                    if has_eth {
                        tics_solver_addresses.insert(entry.solver_address.to_lowercase());
                    }
                }

                if tics_solver_addresses.is_empty() {
                    warn!(
                        "⚠️ [TICS_CLAIM_REWARD] No TICS claim requests to process for batch {}",
                        batch_id
                    );
                    return Ok(());
                }

                // Fetch unclaimed TICS per solver via contract
                let rpc_url = crate::env_defaults::solver_contract_rpc_url();
                let contract_address_env = crate::env_defaults::solver_contract_address();
                let chain_id = crate::env_defaults::solver_contract_chain_id()
                    .parse::<u64>()
                    .ok()
                    .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());
                if contract_address_env == "0x0000000000000000000000000000000000000000" {
                    warn!("⚠️ [TICS_CLAIM_REWARD] Solver contract not configured; skipping");
                    return Ok(());
                }
                let contract_address = match contract_address_env.parse::<Address>() {
                    Ok(a) => a,
                    Err(_) => {
                        warn!("⚠️ [TICS_CLAIM_REWARD] Invalid solver contract address");
                        return Ok(());
                    }
                };
                let config = ContractConfig {
                    rpc_url: rpc_url.clone(),
                    contract_address,
                    chain_id,
                };
                let client = match ContractClient::new(config.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("⚠️ [TICS_CLAIM_REWARD] Contract client failed: {}", e);
                        return Ok(());
                    }
                };
                let contract = match SolverManagerContract::new(&config, client.provider()) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            "⚠️ [TICS_CLAIM_REWARD] SolverManagerContract::new failed: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                for solver_address_lower in &tics_solver_addresses {
                    let solver_id = match self
                        .fetch_solver_id_for_address(solver_address_lower)
                        .await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            warn!(
                                "⚠️ [TICS_CLAIM_REWARD] Unable to fetch solver ID for {}: {}; skipping",
                                solver_address_lower, e
                            );
                            continue;
                        }
                    };
                    let rewards = match contract
                        .get_solvers_unclaimed_rewards(vec![solver_id.clone()])
                        .await
                    {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let tics_unclaimed = rewards.first().map(|r| r.2).unwrap_or(U256::zero());
                    if tics_unclaimed <= U256::from(MIN_CLAIM_TICS_WEI) {
                        continue;
                    }
                    per_solver_tics.insert(solver_address_lower.clone(), tics_unclaimed);
                }

                if per_solver_tics.is_empty() {
                    warn!(
                        "⚠️ [TICS_CLAIM_REWARD] No non-zero TICS unclaimed amounts for batch {}",
                        batch_id
                    );
                    return Ok(());
                }

                let claims: Vec<RewardClaimBatchEntry> = per_solver_tics
                    .iter()
                    .filter(|(_, amt)| !amt.is_zero())
                    .map(|(addr, amt)| (addr.clone(), *amt))
                    .collect();

                let dkg_node = if let Some(node) = &self.dkg_node {
                    node
                } else {
                    warn!(
                        "❌ [TICS_CLAIM_REWARD] Cannot process TICS claim-reward batch - DKG node unavailable"
                    );
                    return Ok(());
                };

                let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
                    key
                } else {
                    warn!("❌ [TICS_CLAIM_REWARD] Liquidity operator group key unavailable");
                    return Ok(());
                };

                let liquidity_operator_address =
                    crate::utils::get_eth_address_from_group_key(group_public_key);

                let contract_address_str = crate::env_defaults::solver_contract_address();
                let tics_cid = crate::env_defaults::mpc_tics_chain_id();
                let contract_chain_id = crate::env_defaults::solver_contract_chain_id()
                    .parse::<u64>()
                    .unwrap_or(tics_cid);
                let contract_chain_name = if contract_chain_id == tics_cid {
                    "qubetics"
                } else {
                    "tics"
                };

                let chain_tx = match create_solver_claim_rewards_batch_transaction(
                    &liquidity_operator_address,
                    &claims,
                    1u8, // chainType TICS
                    &contract_address_str,
                    contract_chain_id,
                    contract_chain_name,
                )
                .await
                {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!(
                            "⚠️ [TICS_CLAIM_REWARD] Failed to create claimRewardsBatch tx: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let crate::chain_abstraction::ChainTransaction::Tics(eth_tx) = &chain_tx else {
                    warn!("❌ [TICS_CLAIM_REWARD] Expected TICS transaction");
                    return Ok(());
                };

                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);
                    signing_node.set_chain_handler(
                        crate::chain_abstraction::ChainHandlerFactory::create_tics_handler(
                            eth_tx.chain_id,
                        )
                        .into(),
                    );

                    // Both DKG and observer nodes call sign_contract_message;
                    // observer nodes build + store the TX and advance round but skip ECDSA signing
                    let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;
                    signing_node.set_vault_group_key(group_public_key);

                    let contract_tx = crate::types::intent::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        nonce: eth_tx.nonce,
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        chain_id: eth_tx.chain_id,
                        data: eth_tx
                            .data
                            .as_ref()
                            .map(|d| format!("0x{}", hex::encode(d)))
                            .unwrap_or_else(|| "0x".to_string()),
                    };

                    let contract_tx_bytes =
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        );
                    let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
                    let mut eth_signer = crate::signing::TicsSigner::new(&mut signing_node);

                    let nonce_tuple_id = nonce_tuple_ids
                        .as_ref()
                        .and_then(|ids| ids.first().cloned());

                    if let Err(e) = eth_signer
                        .sign_contract_message(
                            contract_tx_bytes,
                            &contract_chain_handler,
                            &contract_tx,
                            vault_tweaked_share.clone(),
                            None,
                            vec![],
                            vault_tweaked_share,
                            None,
                            None,
                            None,
                            Some(used_identifiers.clone()),
                            None,
                            nonce_tuple_id.clone(),
                            round,
                        )
                        .await
                    {
                        warn!(
                            "❌ [TICS_CLAIM_REWARD] Batch signing failed for round {}: {}",
                            round, e
                        );

                        // Revert local Batched requests to Pending (never Completed)
                        {
                            use crate::types::rpc_server::PendingClaimRewardRequest;
                            let entries: Vec<(String, PendingClaimRewardRequest)> = self
                                .db
                                .get_values_with_prefix("pending_claim_reward:")
                                .unwrap_or_default();
                            for (key, req) in entries {
                                if req.status == "Batched"
                                    && req.tx_id.is_none()
                                    && used_identifiers.iter().any(|id| {
                                        id.split_once('|')
                                            .map_or(false, |(rid, _)| rid == req.request_id)
                                    })
                                {
                                    let mut reverted = req.clone();
                                    reverted.status = "Pending".to_string();
                                    let _ = self.db.put_string(&key, &reverted);
                                    info!("🔄 [TICS_CLAIM_REWARD] Reverted claim_reward {} to Pending", req.request_id);
                                }
                            }
                        }

                        // Broadcast error so other nodes also revert
                        let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: used_identifiers,
                            error_message: format!(
                                "TICS claim-reward batch signing failed for round {}: {}",
                                round, e
                            ),
                            transaction_type: "claim_reward".to_string(),
                            solver_address: None,
                            node_id: self.local_peer_id.to_string(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: "transaction-sync".to_string(),
                                    data,
                                })
                                .await;
                            info!("📡 [TICS_CLAIM_REWARD] Broadcasted batch failure for round {} to sync status across nodes", round);
                        }
                    } else {
                        info!(
                            "✅ [TICS_CLAIM_REWARD] Submitted claimRewardsBatch (TICS) into MPC signing flow ({} claims)",
                            claims.len()
                        );
                    }
                } else {
                    warn!("❌ [TICS_CLAIM_REWARD] Signing node unavailable");
                }
            }
            GossipsubMessage::WithdrawTxIdBroadcast {
                txid,
                network,
                batch_id,
                solver_address,
                requests,
                node_id,
            } => {
                info!(
                    "📡 [WITHDRAW_TXID] Received withdraw-liquidity txid broadcast from node {}: txid={}, batch_id={}, network={}, solver={:?}, requests={}",
                    node_id,
                    txid,
                    batch_id,
                    network,
                    solver_address,
                    requests.len()
                );

                let is_tics = txid.starts_with("0x");

                if is_tics {
                    // TICS withdraw-liquidity:
                    // - txid is an EVM hash (0x...)
                    // - When requests is non-empty: update all (request_id, solver) via batch handler (multiple solvers/requests).
                    // - When requests is empty: single-solver legacy, solver_address must be present, call single-request handler with None.
                    if !requests.is_empty() {
                        if let Err(e) = self
                            .handle_withdraw_liquidity_transaction_id_storage_batch(
                                &txid,
                                "withdraw_liquidity",
                                &requests,
                            )
                            .await
                        {
                            warn!(
                                "⚠️ [TICS_WITHDRAW] Batch storage failed for txid {} ({} requests): {}",
                                txid, requests.len(), e
                            );
                        }
                    } else if let Some(solver) = solver_address.as_ref() {
                        if let Err(e) = self
                            .handle_withdraw_liquidity_transaction_id_storage(
                                solver,
                                &txid,
                                "withdraw_liquidity",
                                None,
                            )
                            .await
                        {
                            warn!(
                                "⚠️ [TICS_WITHDRAW] Failed to apply txid {} for solver {}: {}",
                                txid, solver, e
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [TICS_WITHDRAW] Missing solver_address and empty requests for TICS withdraw txid broadcast: txid={}, batch_id={}",
                            txid, batch_id
                        );
                    }
                } else {
                    // BTC withdraw-liquidity:
                    // - txid is a BTC transaction ID (non-0x)
                    // - When requests is non-empty: update all (request_id, solver) via batch handler (multiple solvers/requests).
                    if requests.is_empty() {
                        warn!(
                            "⚠️ [BTC_WITHDRAW] WithdrawTxIdBroadcast has no requests for BTC txid {} (batch_id={})",
                            txid, batch_id
                        );
                    } else if let Err(e) = self
                        .handle_withdraw_liquidity_transaction_id_storage_batch(
                            &txid,
                            "withdraw_liquidity",
                            &requests,
                        )
                        .await
                    {
                        warn!(
                            "⚠️ [BTC_WITHDRAW] Batch storage failed for txid {} ({} requests): {}",
                            txid,
                            requests.len(),
                            e
                        );
                    }
                }
            }
            GossipsubMessage::ClaimRewardTxIdBroadcast {
                txid,
                network,
                batch_id,
                solver_address,
                requests,
                node_id,
            } => {
                info!(
                    "📡 [CLAIM_REWARD_TXID] Received claim-reward txid broadcast from node {}: txid={}, network={}, batch_id={}, solver={:?}, requests={}",
                    node_id, txid, network, batch_id, solver_address, requests.len()
                );
                // Unified handler: TICS vs BTC determined by txid (0x = TICS, else BTC), same as withdraw.
                if !requests.is_empty() {
                    if let Err(e) = self
                        .handle_claim_reward_transaction_id_storage_batch(&txid, &requests)
                        .await
                    {
                        warn!(
                            "⚠️ [CLAIM_REWARD_TXID] Batch storage failed for txid {} ({} requests): {}",
                            txid, requests.len(), e
                        );
                    }
                } else if let Some(solver) = solver_address.as_ref() {
                    if let Err(e) = self
                        .handle_claim_reward_transaction_id_storage(solver, &txid, None)
                        .await
                    {
                        warn!(
                            "⚠️ [CLAIM_REWARD_TXID] Single storage failed for txid {} (solver {}): {}",
                            txid, solver, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [CLAIM_REWARD_TXID] Claim-reward txid broadcast has empty requests and no solver_address: txid={}, batch_id={}",
                        txid, batch_id
                    );
                }
            }
            GossipsubMessage::BtcIntentManagerTxUpdate {
                intent_hashes,
                btc_txid,
                btc_batch_round,
                update_round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                info!(
                    "🔄 [BTC_INTENT_MANAGER] Received BTC intent manager update batch from node {} (round {})",
                    node_id, update_round
                );
                info!(
                    "🔄 [BTC_INTENT_MANAGER] {} intents, BTC batch round: {}, BTC txid: {}, nonce: {:?}",
                    intent_hashes.len(),
                    btc_batch_round,
                    btc_txid,
                    nonce_tuple_ids
                );

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (update_round, "BTC_INTENT_MANAGER_UPDATE".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type BTC_INTENT_MANAGER_UPDATE, skipping duplicate",
                        update_round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                // Process the batch - create contract call
                // handle_btc_intent_manager_update_batch is a method on MpcNetworkLayer (in channel_handler.rs)
                // Since both are impl MpcNetworkLayer, we can call it directly
                let intent_hashes_clone = intent_hashes.clone();
                if let Err(e) = self
                    .handle_btc_intent_manager_update_batch(
                        intent_hashes,
                        btc_txid,
                        btc_batch_round,
                        update_round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids
                            .as_ref()
                            .and_then(|ids| ids.first().cloned()),
                    )
                    .await
                {
                    error!(
                        "❌ [BTC_INTENT_MANAGER] Failed to handle contract update batch: {}",
                        e
                    );

                    // Revert intents locally (never revert Solved)
                    if let Some(uim) = &self.user_intent_manager {
                        for h in &intent_hashes_clone {
                            if let Some(user) = uim.get_user_by_intent_hash(h).await {
                                let current = uim.get_intent_status(&user.tics_address, h).await;
                                if matches!(current, Some(IntentStatus::Solved)) {
                                    continue;
                                }
                                let _ = uim
                                    .update_intent_status(
                                        &user.tics_address,
                                        h,
                                        IntentStatus::Pending,
                                    )
                                    .await;
                                info!("🔄 [BTC_INTENT_MANAGER] Reverted intent {} to Pending", h);
                            }
                        }
                    }

                    // Broadcast error so other nodes also revert
                    let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                        intent_hashes: intent_hashes_clone,
                        error_message: format!(
                            "BTC IntentManager contract update batch failed for round {}: {}",
                            update_round, e
                        ),
                        transaction_type: "network_to_target".to_string(),
                        solver_address: None,
                        node_id: self.local_peer_id.to_string(),
                    };
                    if let Ok(data) = serde_json::to_vec(&error_msg) {
                        let _ = self
                            .message_tx
                            .send(ChannelMessage::Broadcast {
                                topic: "transaction-sync".to_string(),
                                data,
                            })
                            .await;
                    }
                }
            }
            GossipsubMessage::PeerDisconnection {
                peer_id,
                solver_id,
                timestamp,
                detector_node_id,
            } => {
                info!(
                    "📡 [PEER_DISCONNECT] Received disconnection broadcast for solver {} from detector {}",
                    solver_id, detector_node_id
                );

                // Validate solver_id is non-empty and well-formed
                if solver_id.trim().is_empty() {
                    warn!("⚠️ [PEER_DISCONNECT] Ignoring disconnection with empty solver_id");
                    return Ok(());
                }

                // Ignore disconnect broadcasts about ourselves — we are still alive
                if solver_id == self.local_peer_id.to_string() {
                    warn!(
                        "📡 [PEER_DISCONNECT] Ignoring disconnection broadcast about ourselves ({}) — we are still alive",
                        solver_id
                    );
                    return Ok(());
                }

                // Validate timestamp is sane (not too far in past/future)
                let now = chrono::Utc::now().timestamp();
                let max_age_secs = 3600; // 1 hour in the past
                let max_future_secs = 300; // 5 minutes in the future

                if timestamp < now - max_age_secs {
                    warn!(
                        "⚠️ [PEER_DISCONNECT] Ignoring stale disconnection (timestamp too old: {} vs now: {})",
                        timestamp, now
                    );
                    return Ok(());
                }

                if timestamp > now + max_future_secs {
                    warn!(
                        "⚠️ [PEER_DISCONNECT] Ignoring disconnection with future timestamp: {} vs now: {}",
                        timestamp, now
                    );
                    return Ok(());
                }

                // Guard: invulnerable nodes (initial DKG signers) are never staged for invalidation
                if let Ok(Some(invulnerables)) = self
                    .db
                    .get_string::<Vec<String>>(crate::database::keys::DKG_INVULNERABLES)
                {
                    if invulnerables.contains(&solver_id) {
                        info!(
                            "🛡️ [PEER_DISCONNECT] Solver {} is an invulnerable (DKG signer) — skipping disconnection staging",
                            solver_id
                        );
                        return Ok(());
                    }
                }

                // Write to the staging map — NOT the invalidation queue.
                // At epoch-2 surviving staging entries are promoted to PENDING_DISCONNECTION.
                // The on-chain validation check is deferred to epoch-2 (before promotion).
                // If the peer reconnects before epoch-2 the staging entry is cleared on connect
                // and no invalidation is ever queued for this peer.
                let staging_key = format!(
                    "{}{}",
                    crate::database::keys::DISCONNECTION_STAGING,
                    solver_id
                );
                if let Ok(Some(_)) = self.db.get_string::<String>(&staging_key) {
                    info!(
                        "ℹ️ [PEER_DISCONNECT] Staging entry already exists for solver {}, skipping duplicate",
                        solver_id
                    );
                    return Ok(());
                }

                // Store in staging for batch promotion at epoch-2
                let disconnection_record = serde_json::json!({
                    "peer_id": peer_id,
                    "solver_id": solver_id,
                    "timestamp": timestamp,
                    "detector_node_id": detector_node_id,
                });

                if let Ok(record_str) = serde_json::to_string(&disconnection_record) {
                    if let Err(e) = self.db.put_string(&staging_key, &record_str) {
                        error!("❌ [PEER_DISCONNECT] Failed to store staging record: {}", e);
                    } else {
                        info!(
                            "💾 [PEER_DISCONNECT] Stored disconnection staging record for solver: {} (promoted to invalidation at epoch-2 if peer does not rejoin)",
                            solver_id
                        );
                    }
                }
            }
            GossipsubMessage::PeerInvalidationBatch {
                solver_ids,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                info!(
                    "📦 [PEER_INVALIDATION] Received peer invalidation batch from node {} (round {}, timestamp {}, {} solver IDs, nonce: {:?})",
                    node_id, round, timestamp, solver_ids.len(), nonce_tuple_ids
                );

                if solver_ids.is_empty() {
                    warn!("⚠️ [PEER_INVALIDATION] Empty solver_ids list in batch");
                    return Ok(());
                }

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "PEER_INVALIDATION".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type PEER_INVALIDATION, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                // Check on-chain validity for each solver individually before proceeding.
                // If already invalidated, drop it and broadcast a deletion so other nodes wipe it.
                let mut valid_solver_ids = Vec::new();

                let contract_config_opt = crate::contract::get_solver_contract_config()?;
                let contract_config = match contract_config_opt {
                    Some(config) => config,
                    None => {
                        warn!("⚠️ [PEER_INVALIDATION] Solver contract config not available");
                        return Ok(());
                    }
                };

                if let Ok(client) = crate::contract::ContractClient::new(contract_config.clone()) {
                    if let Ok(contract) = crate::contract::SolverManagerContract::new(
                        &contract_config,
                        client.provider(),
                    ) {
                        for sid in &solver_ids {
                            match contract.is_solver_id_validated(sid).await {
                                Ok(true) => {
                                    valid_solver_ids.push(sid.clone());
                                }
                                Ok(false) => {
                                    info!(
                                        "ℹ️ [PEER_INVALIDATION] Solver {} already invalidated on-chain, wiping local record and broadcasting deletion",
                                        sid
                                    );
                                    let pending_key = format!("pending_disconnection:{}", sid);
                                    let _ = self.db.delete_string(&pending_key);

                                    // Broadcast deletion so other peers wipe it
                                    let del_msg =
                                        crate::types::ChannelMessage::PeerInvalidationDeleted {
                                            solver_id: sid.clone(),
                                            node_id: self.local_peer_id.to_string(),
                                        };
                                    let _ = self.message_tx.send(del_msg).await;
                                }
                                Err(e) => {
                                    warn!(
                                        "⚠️ [PEER_INVALIDATION] Failed to check on-chain validation for {}: {} — keeping in batch",
                                        sid, e
                                    );
                                    valid_solver_ids.push(sid.clone());
                                }
                            }
                        }
                    } else {
                        valid_solver_ids = solver_ids.clone();
                    }
                } else {
                    valid_solver_ids = solver_ids.clone();
                }

                if valid_solver_ids.is_empty() {
                    info!("✅ [PEER_INVALIDATION] All solvers in batch are already invalidated on-chain, nothing to do");
                    return Ok(());
                }

                // Store round -> solver_ids so we can broadcast PeerInvalidationTxConfirmed after tx receipt
                {
                    let mut pending = self.peer_invalidation_pending.lock().await;
                    pending.insert(round.to_string(), valid_solver_ids.clone());
                }

                let solver_contract_address = format!("{:?}", contract_config.contract_address);
                let chain_id = contract_config.chain_id;

                // Get DKG node for vault key access
                let dkg_node = if let Some(dkg) = &self.dkg_node {
                    dkg
                } else {
                    warn!("❌ [PEER_INVALIDATION] Cannot process batch - DKG node unavailable");
                    return Ok(());
                };

                let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
                    key
                } else {
                    warn!(
                        "❌ [PEER_INVALIDATION] Liquidity operator group key unavailable; cannot derive liquidity operator address"
                    );
                    return Ok(());
                };

                let liquidity_operator_address =
                    crate::utils::get_eth_address_from_group_key(group_public_key);

                info!(
                    "🔑 [PEER_INVALIDATION] Using liquidity operator address: {}",
                    liquidity_operator_address
                );

                // Build the invalidateSolverIds transaction (all nodes build the same tx)
                let chain_tx = crate::utils::transaction::create_invalidate_solver_ids_transaction(
                    &liquidity_operator_address,
                    &valid_solver_ids,
                    &solver_contract_address,
                    chain_id,
                )
                .await?;

                // Expect a TICS transaction
                let eth_tx = match chain_tx {
                    crate::chain_abstraction::ChainTransaction::Tics(tx) => tx,
                    _ => {
                        warn!(
                            "❌ [PEER_INVALIDATION] Invalidation transaction is not a TICS transaction"
                        );
                        return Ok(());
                    }
                };

                info!(
                    "✅ [PEER_INVALIDATION] Built invalidateSolverIds TICS transaction: nonce={}, gas_limit={}",
                    eth_tx.nonce, eth_tx.gas_limit
                );

                // Start MPC signing using vault (liquidity operator) DKG key
                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let available_nodes: Vec<libp2p::PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);
                    signing_node.set_chain_handler(
                        crate::chain_abstraction::ChainHandlerFactory::create_tics_handler(
                            eth_tx.chain_id,
                        )
                        .into(),
                    );

                    let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

                    if let Some(ref _secret_share) = vault_tweaked_share {
                        // Use liquidity operator (vault) key
                        signing_node.set_vault_group_key(group_public_key);

                        let contract_tx = crate::types::intent::ContractTransaction {
                            to: eth_tx.to.clone(),
                            value: eth_tx.value.clone(),
                            nonce: eth_tx.nonce,
                            gas_limit: eth_tx.gas_limit,
                            gas_price: eth_tx.gas_price.clone(),
                            chain_id: eth_tx.chain_id,
                            data: eth_tx
                                .data
                                .as_ref()
                                .map(|d| format!("0x{}", hex::encode(d)))
                                .unwrap_or_else(|| "0x".to_string()),
                        };

                        let contract_tx_bytes =
                            crate::utils::transaction::create_transaction_for_signing_contract(
                                &contract_tx,
                            );
                        let contract_chain_handler =
                            signing_node.get_contract_chain_handler().clone();
                        let mut eth_signer = crate::signing::TicsSigner::new(&mut signing_node);

                        // Prefix approach (like add_liquidity "addliq:"): intent_hashes = ["peerinv:round"] so TransactionIdBroadcast handler clears PENDING_DISCONNECTION
                        let peerinv_intent = format!("peerinv:{}", round);
                        eth_signer
                            .sign_contract_message(
                                contract_tx_bytes,
                                &contract_chain_handler,
                                &contract_tx,
                                vault_tweaked_share.clone(),
                                None,
                                vec![peerinv_intent],
                                vault_tweaked_share,
                                None,
                                None,
                                None,
                                None,
                                None, // tics_claim_platform_fee_identifiers (not applicable)
                                nonce_tuple_ids
                                    .as_ref()
                                    .and_then(|ids| ids.first().cloned()),
                                round,
                            )
                            .await?;

                        info!(
                            "✅ [PEER_INVALIDATION] Submitted invalidateSolverIds transaction into MPC signing flow ({} solver IDs); PENDING_DISCONNECTION will be cleared after tx receipt",
                            solver_ids.len()
                        );
                    } else {
                        warn!(
                            "⚠️ [PEER_INVALIDATION] Skipping batch - missing liquidity operator secret share"
                        );
                    }
                } else {
                    warn!(
                        "❌ [PEER_INVALIDATION] Signing node not available; cannot start MPC signing for invalidation"
                    );
                }
            }
            GossipsubMessage::SolverAddLiquidityBatch {
                request_ids,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                info!(
                    "💧 [ADD_LIQUIDITY_BATCH] Received solver_add_liquidity batch from node {} (round {})",
                    node_id, round
                );
                info!(
                    "💧 [ADD_LIQUIDITY_BATCH] {} requests to process (will look up from RocksDB), timestamp: {}, nonce: {:?}",
                    request_ids.len(), timestamp, nonce_tuple_ids
                );

                let nonce_tuple_id = nonce_tuple_ids
                    .as_ref()
                    .and_then(|ids| ids.first().cloned());

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_id) = nonce_tuple_id {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(std::slice::from_ref(nonce_id))
                            .await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "SOLVER_ADD_LIQUIDITY".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type SOLVER_ADD_LIQUIDITY, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                // All nodes (DKG + observer) process the batch.
                // Observer nodes will go through sign_contract_message() which handles
                // the observer path internally (builds TX, skips signing, stores for aggregation).
                if let Err(e) = self
                    .handle_solver_add_liquidity_batch(
                        request_ids,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_id,
                    )
                    .await
                {
                    error!(
                        "❌ [ADD_LIQUIDITY_BATCH] Failed to handle solver add_liquidity batch: {}",
                        e
                    );
                    // Don't mark as Pending - local processing errors indicate permanent issues
                    // Only blockchain transaction failures (TransactionErrorBroadcast) trigger retry
                }
            }
            GossipsubMessage::WithdrawLiquidity { .. } => {
                // Legacy variant; withdraw requests are now propagated via PendingWithdrawRequestBroadcast.
                debug!("[WITHDRAW_LIQUIDITY] Ignoring legacy WithdrawLiquidity gossip message");
            }
            GossipsubMessage::PendingWithdrawRequestBroadcast { request } => {
                use crate::types::rpc_server::PendingWithdrawRequest;

                info!(
                    "💧 [WITHDRAW_LIQUIDITY] Received pending withdraw request from gossip: request_id={}, solver={}, asset={}",
                    request.request_id, request.solver_address, request.asset
                );

                // --- Input validation ---
                if request.request_id.trim().is_empty() {
                    warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw: empty request_id");
                    return Ok(());
                }

                // Validate asset
                if request.asset != "TICS" && request.asset != "BTC" {
                    warn!(
                        "🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: invalid asset '{}'",
                        request.request_id, request.asset
                    );
                    return Ok(());
                }

                // Validate amount
                match request.amount.trim().parse::<u128>() {
                    Ok(a) if a > 0 => {}
                    _ => {
                        warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: invalid or zero amount '{}'", request.request_id, request.amount);
                        return Ok(());
                    }
                }

                // Validate solver_address is a valid TICS/Ethereum address
                if !crate::utils::is_valid_tics_address(request.solver_address.trim()) {
                    warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: invalid solver_address '{}'", request.request_id, request.solver_address);
                    return Ok(());
                }

                // Validate target address matches asset
                match request.asset.as_str() {
                    "TICS" => match &request.tics_address {
                        Some(addr) if !addr.trim().is_empty() => {
                            if !crate::utils::is_valid_tics_address(addr.trim()) {
                                warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: invalid tics_address '{}'", request.request_id, addr);
                                return Ok(());
                            }
                        }
                        _ => {
                            warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: TICS withdrawal missing tics_address", request.request_id);
                            return Ok(());
                        }
                    },
                    "BTC" => match &request.btc_address {
                        Some(addr) if crate::utils::is_valid_bitcoin_address(addr) => {}
                        Some(addr) => {
                            warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: invalid btc_address '{}'", request.request_id, addr);
                            return Ok(());
                        }
                        _ => {
                            warn!("🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: BTC withdrawal missing btc_address", request.request_id);
                            return Ok(());
                        }
                    },
                    _ => {}
                }

                // ── Gossip-level signature verification ───────────────────────────────────
                // Re-run the same check the RPC handler did. Every receiving node must
                // independently confirm that the withdraw request was signed by the claimed
                // solver before it is written to RocksDB and potentially included in a
                // threshold-signed batch.  A rogue peer cannot bypass this by constructing
                // a forged PendingWithdrawRequestBroadcast gossip message.
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                if request.signature.trim().is_empty() {
                    warn!(
                        "🚫 [WITHDRAW_LIQUIDITY] Rejecting gossip withdraw {}: missing signature",
                        request.request_id
                    );
                    return Ok(());
                }
                let (compact, v) = match normalize_eth_signature(&request.signature) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            "🚫 [WITHDRAW_LIQUIDITY] Invalid signature format for gossip withdraw {}: {}",
                            request.request_id, e
                        );
                        return Ok(());
                    }
                };
                let msg_bytes = request.message.as_bytes();
                let recovered = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
                    Ok(addr) => addr,
                    Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            warn!(
                                "🚫 [WITHDRAW_LIQUIDITY] Failed to recover signer for gossip withdraw {}: personal_sign={}, raw={}",
                                request.request_id, e1, e2
                            );
                            return Ok(());
                        }
                    },
                };
                if recovered.to_lowercase() != request.solver_address.to_lowercase() {
                    warn!(
                        "🚫 [WITHDRAW_LIQUIDITY] Signature mismatch for gossip withdraw {}: recovered={}, claimed_solver={}",
                        request.request_id, recovered, request.solver_address
                    );
                    return Ok(());
                }
                // ── End signature verification ────────────────────────────────────────────

                // Persist only if this solver has no existing Pending/Batched request for the same asset (one in-flight per solver per asset).
                let solver_lower = request.solver_address.to_lowercase();
                let prefix = format!("pending_withdraw_liquidity:{}:", solver_lower);
                let existing: Vec<(String, PendingWithdrawRequest)> = match self
                    .db
                    .get_values_with_prefix(&prefix)
                {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(
                                "⚠️ [WITHDRAW_LIQUIDITY] Failed to check existing withdraws for solver {}: {}",
                                request.solver_address, e
                            );
                        return Ok(());
                    }
                };
                let has_pending_or_batched = existing.iter().any(|(_, r)| {
                    r.asset == request.asset && (r.status == "Pending" || r.status == "Batched")
                });
                if has_pending_or_batched {
                    info!(
                        "🚫 [WITHDRAW_LIQUIDITY] Ignoring duplicate {} withdraw request {} for solver {}: already has Pending/Batched",
                        request.asset, request.request_id, request.solver_address
                    );
                    return Ok(());
                }

                let key = format!(
                    "pending_withdraw_liquidity:{}:{}",
                    solver_lower, request.request_id
                );

                // Use put_string_if_absent_async so that a duplicate gossip delivery of the
                // same request_id is a no-op rather than overwriting an already-stored record
                // (e.g. one that may have progressed to Batched on this node).
                match self.db.put_string_if_absent_async(&key, &request, &key).await {
                    Ok(true) => {
                        info!(
                            "✅ [WITHDRAW_LIQUIDITY] Stored PendingWithdrawRequest from gossip (request_id={}, solver={})",
                            request.request_id, request.solver_address
                        );
                    }
                    Ok(false) => {
                        info!(
                            "ℹ️ [WITHDRAW_LIQUIDITY] Duplicate gossip withdraw {}: already stored, skipping overwrite",
                            request.request_id
                        );
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ [WITHDRAW_LIQUIDITY] Failed to persist PendingWithdrawRequest request_id={} from gossip: {}",
                            request.request_id, e
                        );
                    }
                }
            }
            GossipsubMessage::PendingClaimPlatformFeeRequestBroadcast { request } => {
                use crate::types::rpc_server::PendingClaimPlatformFeeRequest;

                info!(
                    "💰 [PLATFORM_FEE] Received pending claim-platform-fee request from gossip: request_id={}, asset={}, amount={}",
                    request.request_id, request.asset, request.amount
                );

                // --- Input validation ---
                if request.request_id.trim().is_empty() {
                    warn!("🚫 [PLATFORM_FEE] Rejecting gossip claim: empty request_id");
                    return Ok(());
                }
                if request.asset != "TICS" && request.asset != "BTC" {
                    warn!(
                        "🚫 [PLATFORM_FEE] Rejecting gossip claim {}: invalid asset '{}'",
                        request.request_id, request.asset
                    );
                    return Ok(());
                }
                let claimed_amount = match request.amount.trim().parse::<u128>() {
                    Ok(a) if a > 0 => a,
                    _ => {
                        warn!("🚫 [PLATFORM_FEE] Rejecting gossip claim {}: invalid or zero amount '{}'", request.request_id, request.amount);
                        return Ok(());
                    }
                };
                // Validate exactly one target address is set, matches asset, and has valid format
                match request.asset.as_str() {
                    "TICS" => match &request.tics_target_address {
                        Some(addr) if !addr.trim().is_empty() => {
                            if !crate::utils::is_valid_tics_address(addr.trim()) {
                                warn!("🚫 [PLATFORM_FEE] Rejecting gossip claim {}: invalid tics_target_address '{}'", request.request_id, addr);
                                return Ok(());
                            }
                        }
                        _ => {
                            warn!("🚫 [PLATFORM_FEE] Rejecting gossip claim {}: TICS claim missing tics_target_address", request.request_id);
                            return Ok(());
                        }
                    },
                    "BTC" => match &request.btc_target_address {
                        Some(addr) if crate::utils::is_valid_bitcoin_address(addr) => {}
                        Some(addr) => {
                            warn!(
                                "🚫 [PLATFORM_FEE] Rejecting gossip claim {}: invalid btc_target_address format '{}'",
                                request.request_id, addr
                            );
                            return Ok(());
                        }
                        _ => {
                            warn!(
                                "🚫 [PLATFORM_FEE] Rejecting gossip claim {}: BTC claim missing btc_target_address",
                                request.request_id
                            );
                            return Ok(());
                        }
                    },
                    _ => {} // already rejected above
                }

                // ── Gossip-level signature verification ───────────────────────────────────
                // Every receiving node re-verifies that the request was signed by
                // ADMIN_PUBLIC_ADDRESS before storing it.  This mirrors the RPC-level check
                // in handle_claim_platform_fee and prevents a rogue peer from injecting a
                // forged PendingClaimPlatformFeeRequestBroadcast.
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                let admin_public_address = crate::env_defaults::admin_public_address();
                if admin_public_address.trim().is_empty() {
                    warn!("🚫 [PLATFORM_FEE] ADMIN_PUBLIC_ADDRESS not configured; dropping gossip claim {}", request.request_id);
                    return Ok(());
                }
                if request.signature.trim().is_empty() {
                    warn!("🚫 [PLATFORM_FEE] Missing signature for gossip claim {}", request.request_id);
                    return Ok(());
                }
                let (compact, v) = match normalize_eth_signature(&request.signature) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("🚫 [PLATFORM_FEE] Invalid signature format for gossip claim {}: {}", request.request_id, e);
                        return Ok(());
                    }
                };
                let msg_bytes = request.message.as_bytes();
                let recovered = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
                    Ok(addr) => addr,
                    Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            warn!(
                                "🚫 [PLATFORM_FEE] Failed to recover signer for gossip claim {}: personal_sign={}, raw={}",
                                request.request_id, e1, e2
                            );
                            return Ok(());
                        }
                    },
                };
                if recovered.to_lowercase() != admin_public_address.trim().to_lowercase() {
                    warn!(
                        "🚫 [PLATFORM_FEE] Signature mismatch for gossip claim {}: recovered={}, expected ADMIN_PUBLIC_ADDRESS={}",
                        request.request_id, recovered, admin_public_address
                    );
                    return Ok(());
                }
                // ── End signature verification ────────────────────────────────────────────

                let key = format!("pending_claim_platform_fee:{}", request.request_id);

                // Deduplicate: skip if a record with this request_id already exists.
                let existing: Option<PendingClaimPlatformFeeRequest> = match self
                    .db
                    .get_string(&key)
                {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                                "⚠️ [PLATFORM_FEE] Failed to check existing record for request_id={}: {}",
                                request.request_id, e
                            );
                        return Ok(());
                    }
                };

                if existing.is_some() {
                    info!(
                        "🚫 [PLATFORM_FEE] Ignoring duplicate platform fee request {} — already stored",
                        request.request_id
                    );
                    return Ok(());
                }

                // --- One-claim-per-chain enforcement ---
                {
                    let prefix = crate::database::primitives::keys::PENDING_CLAIM_PLATFORM_FEE;
                    let entries: Vec<(String, PendingClaimPlatformFeeRequest)> =
                        self.db.get_values_with_prefix(prefix).unwrap_or_default();
                    let has_active = entries.iter().any(|(_, r)| {
                        r.asset == request.asset && (r.status == "Pending" || r.status == "Batched")
                    });
                    if has_active {
                        info!(
                            "🚫 [PLATFORM_FEE] Rejecting gossip claim {} — active {} claim already exists",
                            request.request_id, request.asset
                        );
                        return Ok(());
                    }
                }

                // --- BTC dust check ---
                if request.asset == "BTC" {
                    if claimed_amount < (DUST_LIMIT_SATS as u128) {
                        warn!(
                            "🚫 [PLATFORM_FEE] Gossip claim {} rejected: BTC amount {} sats below dust limit {}",
                            request.request_id, claimed_amount, DUST_LIMIT_SATS
                        );
                        return Ok(());
                    }
                }

                // --- On-chain amount validation ---
                {
                    use crate::contract::{ContractClient, ContractConfig, SolverManagerContract};
                    use ethers::types::Address;

                    let tics_cid = crate::env_defaults::mpc_tics_chain_id();
                    let on_chain_id: u64 = match request.asset.as_str() {
                        "BTC" => 0,
                        "TICS" => tics_cid,
                        _ => {
                            warn!(
                                "⚠️ [PLATFORM_FEE] Unknown asset '{}' in gossip claim — skipping on-chain check",
                                request.asset
                            );
                            0
                        }
                    };

                    let rpc_url = crate::env_defaults::tics_chain_rpc_url();
                    let chain_id: u64 = crate::env_defaults::tics_chain_id();
                    let contract_address_env =
                        std::env::var("SOLVER_MANAGER_CONTRACT_ADDRESS").unwrap_or_default();
                    if let Ok(contract_address) = contract_address_env.parse::<Address>() {
                        let config = ContractConfig {
                            rpc_url: rpc_url.clone(),
                            contract_address,
                            chain_id,
                        };
                        if let Ok(client) = ContractClient::new(config.clone()) {
                            if let Ok(contract) =
                                SolverManagerContract::new(&config, client.provider())
                            {
                                match contract
                                    .get_platform_unclaimed_fee(ethers::types::U256::from(
                                        on_chain_id,
                                    ))
                                    .await
                                {
                                    Ok(unclaimed) => {
                                        let requested =
                                            ethers::types::U256::from_dec_str(&request.amount)
                                                .unwrap_or_default();
                                        if requested > unclaimed {
                                            warn!(
                                                "❌ [PLATFORM_FEE] Gossip claim {} rejected: requested {} > on-chain unclaimed {}",
                                                request.request_id, requested, unclaimed
                                            );
                                            return Ok(());
                                        }
                                        info!(
                                            "✅ [PLATFORM_FEE] Gossip on-chain validation passed for {}: requested={}, unclaimed={}",
                                            request.request_id, requested, unclaimed
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            "🚫 [PLATFORM_FEE] getPlatformUnclaimedFee failed during gossip validation: {} — rejecting claim",
                                            e
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }

                // --- Network balance check ---
                // TICS claims: check treasury vault balance
                // BTC claims: check DKG-derived BTC address balance
                {
                    let requested_u128 = claimed_amount;
                    let (network_address, blockchain, liquidity_source) = if request.asset == "TICS"
                    {
                        let vault = crate::env_defaults::treasury_vault_contract_address();
                        (vault, "eth", "treasury vault")
                    } else {
                        // BTC: derive address from DKG group key
                        if let Some(dkg_node) = &self.dkg_node {
                            match dkg_node.get_final_public_key().await {
                                Some(final_public) => {
                                    match crate::utils::get_btc_address_from_group_key(final_public) {
                                        Ok(btc_addr) => (btc_addr, "btc", "network BTC address"),
                                        Err(e) => {
                                            warn!("⚠️ [PLATFORM_FEE] Failed to derive network BTC address: {}", e);
                                            return Ok(());
                                        }
                                    }
                                }
                                None => {
                                    warn!(
                                        "⚠️ [PLATFORM_FEE] DKG key not available — cannot verify BTC balance for gossip claim {}",
                                        request.request_id
                                    );
                                    return Ok(());
                                }
                            }
                        } else {
                            warn!(
                                "⚠️ [PLATFORM_FEE] DKG node not available — cannot verify BTC balance for gossip claim {}",
                                request.request_id
                            );
                            return Ok(());
                        }
                    };

                    match fetch_network_balance(&network_address, blockchain).await {
                        Ok(balance) => {
                            if balance < requested_u128 {
                                warn!(
                                    "❌ [PLATFORM_FEE] Gossip claim {} rejected: {} balance {} < requested {}",
                                    request.request_id, liquidity_source, balance, requested_u128
                                );
                                return Ok(());
                            }
                            info!(
                                "✅ [PLATFORM_FEE] Gossip {} balance check passed for {}: {} >= {}",
                                liquidity_source, request.request_id, balance, requested_u128
                            );
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [PLATFORM_FEE] Failed to fetch {} balance for gossip claim {}: {}",
                                liquidity_source, request.request_id, e
                            );
                            return Ok(());
                        }
                    }
                }

                if let Err(e) = self.db.put_string_async(&key, &request).await {
                    warn!(
                        "⚠️ [PLATFORM_FEE] Failed to persist PendingClaimPlatformFeeRequest request_id={}: {}",
                        request.request_id, e
                    );
                } else {
                    info!(
                        "✅ [PLATFORM_FEE] Stored PendingClaimPlatformFeeRequest from gossip (request_id={}, asset={}, amount={})",
                        request.request_id, request.asset, request.amount
                    );
                }
            }
            GossipsubMessage::PendingClaimRewardRequestBroadcast { request } => {
                use crate::types::rpc_server::PendingClaimRewardRequest;

                info!(
                    "🎁 [CLAIM_REWARD] Received pending claim reward request from gossip: request_id={}, solver={}",
                    request.request_id, request.solver_address
                );

                // --- Input validation ---
                if request.request_id.trim().is_empty() {
                    warn!("🚫 [CLAIM_REWARD] Rejecting gossip claim: empty request_id");
                    return Ok(());
                }

                // Validate solver_address is a valid TICS/Ethereum address
                if !crate::utils::is_valid_tics_address(request.solver_address.trim()) {
                    warn!(
                        "🚫 [CLAIM_REWARD] Rejecting gossip claim {}: invalid solver_address '{}'",
                        request.request_id, request.solver_address
                    );
                    return Ok(());
                }

                // Validate at least one target address is provided
                let has_tics = request
                    .tics_address
                    .as_ref()
                    .map_or(false, |a| !a.trim().is_empty());
                let has_btc = request
                    .btc_address
                    .as_ref()
                    .map_or(false, |a| !a.trim().is_empty());
                if !has_tics && !has_btc {
                    warn!(
                        "🚫 [CLAIM_REWARD] Rejecting gossip claim {}: no target address provided",
                        request.request_id
                    );
                    return Ok(());
                }

                // Validate TICS address format if provided (strict: checksum via is_valid_tics_address)
                if let Some(ref addr) = request.tics_address {
                    let a = addr.trim();
                    if !a.is_empty() && !crate::utils::is_valid_tics_address(a) {
                        warn!("🚫 [CLAIM_REWARD] Rejecting gossip claim {}: invalid tics_address '{}'", request.request_id, addr);
                        return Ok(());
                    }
                }

                // Validate BTC address format if provided
                if let Some(ref addr) = request.btc_address {
                    if !crate::utils::is_valid_bitcoin_address(addr) {
                        warn!(
                            "🚫 [CLAIM_REWARD] Rejecting gossip claim {}: invalid btc_address format '{}'",
                            request.request_id, addr
                        );
                        return Ok(());
                    }
                }

                // ── Gossip-level signature verification ───────────────────────────────────
                // PendingClaimRewardRequest already carries `signature` (set by the RPC
                // handler).  Every receiving node must independently recover the signer and
                // confirm it matches the claimed `solver_address` before committing to
                // RocksDB.  This mirrors the verification done in handle_claim_reward.
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                if request.signature.trim().is_empty() {
                    warn!(
                        "🚫 [CLAIM_REWARD] Missing signature for gossip claim {}, dropping",
                        request.request_id
                    );
                    return Ok(());
                }
                let (compact, v) = match normalize_eth_signature(&request.signature) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            "🚫 [CLAIM_REWARD] Invalid signature format for gossip claim {}: {}",
                            request.request_id, e
                        );
                        return Ok(());
                    }
                };
                let msg_bytes = request.message.as_bytes();
                let recovered = match recover_eth_address_secp(msg_bytes, &compact, v, true) {
                    Ok(addr) => addr,
                    Err(e1) => match recover_eth_address_secp(msg_bytes, &compact, v, false) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            warn!(
                                "🚫 [CLAIM_REWARD] Failed to recover signer for gossip claim {}: personal_sign={}, raw={}",
                                request.request_id, e1, e2
                            );
                            return Ok(());
                        }
                    },
                };
                if recovered.to_lowercase() != request.solver_address.to_lowercase() {
                    warn!(
                        "🚫 [CLAIM_REWARD] Signature mismatch for gossip claim {}: recovered={}, claimed_solver={}",
                        request.request_id, recovered, request.solver_address
                    );
                    return Ok(());
                }
                // ── End signature verification ────────────────────────────────────────────

                let solver_lower = request.solver_address.to_lowercase();
                let prefix = format!("pending_claim_reward:{}:", solver_lower);
                let existing: Vec<(String, PendingClaimRewardRequest)> = match self
                    .db
                    .get_values_with_prefix(&prefix)
                {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(
                                "⚠️ [CLAIM_REWARD] Failed to check existing claim rewards for solver {}: {}",
                                request.solver_address, e
                            );
                        return Ok(());
                    }
                };
                let has_pending_or_batched = existing
                    .iter()
                    .any(|(_, r)| r.status == "Pending" || r.status == "Batched");
                if has_pending_or_batched {
                    info!(
                        "🚫 [CLAIM_REWARD] Ignoring duplicate claim reward request {} for solver {}: already has Pending/Batched",
                        request.request_id, request.solver_address
                    );
                    return Ok(());
                }

                let key = format!(
                    "pending_claim_reward:{}:{}",
                    solver_lower, request.request_id
                );

                // Use put_string_if_absent_async so that a duplicate gossip delivery of the
                // same request_id is a no-op rather than overwriting an already-stored record.
                match self.db.put_string_if_absent_async(&key, &request, &key).await {
                    Ok(true) => {
                        info!(
                            "✅ [CLAIM_REWARD] Stored PendingClaimRewardRequest from gossip (request_id={}, solver={})",
                            request.request_id, request.solver_address
                        );
                    }
                    Ok(false) => {
                        info!(
                            "ℹ️ [CLAIM_REWARD] Duplicate gossip claim reward {}: already stored, skipping overwrite",
                            request.request_id
                        );
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ [CLAIM_REWARD] Failed to persist PendingClaimRewardRequest request_id={} from gossip: {}",
                            request.request_id, e
                        );
                    }
                }
            }
            GossipsubMessage::TransactionFailure {
                sequencer_request_id,
                blockchain_tx_hash,
                error,
                original_request: _original_request,
            } => {
                warn!(
                    "❌ [TX_FAILURE] Transaction failed: request_id={}, tx_hash={}, error={}",
                    sequencer_request_id, blockchain_tx_hash, error
                );

                // Check if error message indicates transaction is already in mempool
                // If so, skip failure handling - transaction will succeed later
                if error.contains("tx already in mempool") {
                    info!(
                        "✅ [TX_FAILURE] Transaction {} is already in mempool (error: {}). Will succeed later. Skipping failure handling.",
                        sequencer_request_id, error
                    );
                    // Don't re-insert - transaction is pending and will succeed
                    return Ok(());
                }

                // Contract sequencer removed - transaction failures are logged but not retried via sequencer
                warn!(
                    "⚠️ [TX_FAILURE] Contract transaction {} failed: {}. Sequencer removed, no automatic retry.",
                    sequencer_request_id, error
                );

                // Note: For add_liquidity, failed transactions won't reach here since gas estimation
                // failures are caught earlier and marked as "Failed" in RocksDB
            }
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
            GossipsubMessage::ActivePeerList {
                node_id,
                peers,
                timestamp,
            } => {
                // Periodic peer list reconciliation — merge-up only (never remove).
                // If a peer in the received list is missing from our node_manager but
                // we have an active connection to it, re-add it. If we are missing from
                // the sender's list, re-announce ourselves.
                let now = chrono::Utc::now().timestamp();
                let max_age_secs = 300; // 5 minutes

                if timestamp < now - max_age_secs || timestamp > now + max_age_secs {
                    warn!(
                        "⚠️ [PEER_SYNC] Ignoring stale/future ActivePeerList from {} (ts={}, now={})",
                        node_id, timestamp, now
                    );
                    return Ok(());
                }

                info!(
                    "📋 [PEER_SYNC] Received ActivePeerList from {} with {} peers",
                    node_id,
                    peers.len()
                );

                let current_nodes = self.node_manager.get_active_nodes();
                let mut added_count = 0u32;

                for (peer_str, idx) in &peers {
                    if let Ok(peer_id) = peer_str.parse::<PeerId>() {
                        // Skip ourselves
                        if peer_id == self.local_peer_id {
                            continue;
                        }
                        // If peer is NOT in our node_manager but IS actively connected
                        if !current_nodes.contains(&peer_id)
                            && self.connected_peers_cache.contains(&peer_id)
                        {
                            // Store index if provided
                            if let Some(i) = idx {
                                self.peer_discovery.peer_indices.insert(peer_id, *i);
                                let key = crate::database::key_utils::peer_index_key(
                                    &peer_id.to_string(),
                                );
                                if let Err(e) = self.db.put_string(&key, i) {
                                    warn!("⚠️ [PEER_SYNC] Failed to persist peer index: {:?}", e);
                                }
                            }

                            match self.node_manager.add_node(peer_id) {
                                Ok(_) => {
                                    added_count += 1;
                                    info!(
                                        "✅ [PEER_SYNC] Re-added missing peer {} (idx: {:?}) from {}'s ActivePeerList",
                                        peer_id, idx, node_id
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "⚠️ [PEER_SYNC] Failed to re-add peer {}: {:?}",
                                        peer_id, e
                                    );
                                }
                            }
                        }
                    }
                }

                if added_count > 0 {
                    let total = self.node_manager.get_total_nodes();
                    info!(
                        "📊 [PEER_SYNC] Added {} missing peer(s) from {}'s list. Total nodes now: {}",
                        added_count, node_id, total
                    );
                }

                // Check if WE are missing from the sender's list — if so, re-announce
                let our_id_str = self.local_peer_id.to_string();
                let we_are_in_list = peers.iter().any(|(p, _)| *p == our_id_str);
                if !we_are_in_list {
                    info!(
                        "📢 [PEER_SYNC] We ({}) are missing from {}'s peer list — re-announcing",
                        our_id_str, node_id
                    );
                    let our_index = self
                        .peer_discovery
                        .peer_indices
                        .get(&self.local_peer_id)
                        .copied();
                    let announce_msg = GossipsubMessage::PeerDiscovered {
                        peer: self.local_peer_id,
                        sequence: None,
                        index: our_index,
                    };
                    if let Ok(msg_bytes) = serde_json::to_vec(&announce_msg) {
                        if let Err(e) = self
                            .message_tx
                            .send(crate::types::messaging::ChannelMessage::Broadcast {
                                topic: "peer-discovery".to_string(),
                                data: msg_bytes,
                            })
                            .await
                        {
                            warn!("⚠️ [PEER_SYNC] Failed to re-announce ourselves: {}", e);
                        }
                    }
                }
            }
            GossipsubMessage::BtcClaimPlatformFeeBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_ids,
            } => {
                use crate::signing::chains::bitcoin_batch::{
                    build_batch_unsigned_tx, select_utxos_for_batch,
                };
                use crate::signing::chains::bitcoin_batch::{BatchOutput, BatchPolicy, BatchUtxo};
                use crate::types::rpc_server::PendingClaimPlatformFeeRequest;

                info!(
                    "📦 [BTC_CLAIM_PLATFORM_FEE] Received BTC claim-platform-fee batch {} from node {} (round {}, timestamp {})",
                    batch_id, node_id, round, timestamp
                );

                // Remove coordinator-assigned nonces from local available pool
                if let Some(ref nonce_ids) = nonce_tuple_ids {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(nonce_ids).await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "BTC_CLAIM_PLATFORM_FEE".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type BTC_CLAIM_PLATFORM_FEE, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                // Load all pending platform-fee claim records
                let db = &self.db;
                let all_claims: Vec<(String, PendingClaimPlatformFeeRequest)> = match db
                    .get_values_with_prefix(
                        crate::database::primitives::keys::PENDING_CLAIM_PLATFORM_FEE,
                    ) {
                    Ok(entries) => entries,
                    Err(e) => {
                        warn!(
                                "⚠️ [BTC_CLAIM_PLATFORM_FEE] Failed to load pending platform fee claims: {}",
                                e
                            );
                        return Ok(());
                    }
                };

                // Build lookup by request_id
                let mut claim_map: std::collections::HashMap<
                    String,
                    PendingClaimPlatformFeeRequest,
                > = std::collections::HashMap::new();
                for (_key, req) in all_claims {
                    claim_map.insert(req.request_id.clone(), req);
                }

                // Build BatchOutput list from platform-fee requests
                let mut batch_outputs: Vec<BatchOutput> = Vec::new();
                let mut used_requests: Vec<(String, String)> = Vec::new();

                for (request_id, btc_target_address) in &requests {
                    if let Some(req) = claim_map.get(request_id) {
                        if req.asset != "BTC"
                            || (req.status != "Pending" && req.status != "Batched")
                            || req.tx_id.is_some()
                        {
                            continue;
                        }

                        let amount_sats: u64 = match req.amount.parse() {
                            Ok(amt) => amt,
                            Err(e) => {
                                warn!(
                                    "⚠️ [BTC_CLAIM_PLATFORM_FEE] Invalid amount for request {}: {}",
                                    request_id, e
                                );
                                continue;
                            }
                        };

                        if amount_sats < 546 {
                            warn!(
                                "⚠️ [BTC_CLAIM_PLATFORM_FEE] Request {} amount {} sats below dust threshold, skipping",
                                request_id, amount_sats
                            );
                            continue;
                        }

                        batch_outputs.push(BatchOutput {
                            address: btc_target_address.clone(),
                            amount: amount_sats,
                        });
                        used_requests.push((request_id.clone(), btc_target_address.clone()));

                        info!(
                            "💰 [BTC_CLAIM_PLATFORM_FEE] Added output: {} sats to {} (request_id={})",
                            amount_sats, btc_target_address, request_id
                        );
                    } else {
                        warn!(
                            "⚠️ [BTC_CLAIM_PLATFORM_FEE] Request {} not found in DB",
                            request_id
                        );
                    }
                }

                if batch_outputs.is_empty() {
                    warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] No valid outputs after filtering");
                    return Ok(());
                }

                // Get network's DKG Bitcoin address
                let dkg_node = match &self.dkg_node {
                    Some(node) => node,
                    None => {
                        error!("❌ [BTC_CLAIM_PLATFORM_FEE] DKG node not available");
                        return Ok(());
                    }
                };

                let group_key = match dkg_node.get_final_public_key().await {
                    Some(key) => key,
                    None => {
                        error!("❌ [BTC_CLAIM_PLATFORM_FEE] Network group key not available");
                        return Ok(());
                    }
                };

                let network_btc_address = match crate::utils::get_btc_address_from_group_key(group_key) {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_PLATFORM_FEE] Failed to derive network BTC address: {}", e);
                        return Ok(());
                    }
                };

                info!(
                    "🏦 [BTC_CLAIM_PLATFORM_FEE] Using network BTC address: {}",
                    network_btc_address
                );

                // Fetch network BTC UTXOs
                let is_testnet = crate::types::network::network_type().is_testnet();
                let utxos = match crate::utils::transaction::fetch_bitcoin_utxos(
                    &network_btc_address,
                    is_testnet,
                )
                .await
                {
                    Ok(utxos) => utxos,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_PLATFORM_FEE] Failed to fetch UTXOs: {}", e);
                        return Ok(());
                    }
                };

                info!("📦 [BTC_CLAIM_PLATFORM_FEE] Fetched {} UTXOs", utxos.len());

                // Convert BitcoinUtxo → BatchUtxo
                let network_script_pubkey =
                    match crate::utils::transaction::create_bitcoin_script_pubkey(
                        &network_btc_address,
                    ) {
                        Ok(spk) => spk,
                        Err(e) => {
                            error!(
                                "❌ [BTC_CLAIM_PLATFORM_FEE] Failed to create script pubkey: {}",
                                e
                            );
                            return Ok(());
                        }
                    };

                let mut batch_utxos: Vec<BatchUtxo> = Vec::new();
                for utxo in utxos {
                    if !utxo.status.confirmed {
                        continue;
                    }
                    batch_utxos.push(BatchUtxo {
                        txid: utxo.txid,
                        vout: utxo.vout,
                        value: utxo.value,
                        script_pubkey: network_script_pubkey.clone(),
                    });
                }

                // Select UTXOs for batch transaction
                let policy = BatchPolicy {
                    fee_rate: std::env::var("BTC_FEE_RATE_SAT_VB")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(1),
                    dust_threshold: 546,
                    change_address: network_btc_address.clone(),
                };

                let selected = match select_utxos_for_batch(&batch_utxos, &batch_outputs, &policy) {
                    Ok(sel) => sel,
                    Err(e) => {
                        error!("❌ [BTC_CLAIM_PLATFORM_FEE] UTXO selection failed: {}", e);
                        return Ok(());
                    }
                };

                info!(
                    "💰 [BTC_CLAIM_PLATFORM_FEE] Selected {} UTXOs: total={} sats, fee={} sats, change={} sats",
                    selected.utxos.len(),
                    selected.total_input_value,
                    selected.fee,
                    selected.change
                );

                // Build unsigned transaction
                let unsigned_tx = match build_batch_unsigned_tx(&selected, &batch_outputs, &policy)
                {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!(
                            "❌ [BTC_CLAIM_PLATFORM_FEE] Failed to build unsigned transaction: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                info!(
                    "🔨 [BTC_CLAIM_PLATFORM_FEE] Built unsigned tx: {} inputs, {} outputs",
                    unsigned_tx.input.len(),
                    unsigned_tx.output.len()
                );

                // Convert to internal BitcoinTransaction type
                let mut our_inputs = Vec::new();
                for (i, tx_in) in unsigned_tx.input.iter().enumerate() {
                    our_inputs.push(crate::types::BitcoinInput {
                        txid: tx_in.previous_output.txid.to_string(),
                        vout: tx_in.previous_output.vout,
                        script_sig: vec![],
                        sequence: tx_in.sequence.0,
                        witness_utxo: Some(crate::types::BitcoinWitnessUtxo {
                            value: selected.utxos[i].value,
                            script_pubkey: selected.utxos[i].script_pubkey.clone(),
                        }),
                    });
                }

                let mut our_outputs = Vec::new();
                for tx_out in &unsigned_tx.output {
                    our_outputs.push(crate::types::BitcoinOutput {
                        value: tx_out.value.to_sat(),
                        script_pubkey: tx_out.script_pubkey.as_bytes().to_vec(),
                    });
                }

                let our_btc_tx = crate::types::BitcoinTransaction {
                    version: unsigned_tx.version.0 as u32,
                    inputs: our_inputs,
                    outputs: our_outputs,
                    lock_time: unsigned_tx.lock_time.to_consensus_u32(),
                    witness: None,
                };

                if nonce_tuple_ids
                    .as_ref()
                    .map_or(true, |ids| ids.len() != our_btc_tx.inputs.len())
                {
                    error!(
                        "❌ [BTC_CLAIM_PLATFORM_FEE] Nonce/input count mismatch for batch {}: nonce_ids={}, inputs={}. Rejecting and rolling back batch",
                        batch_id,
                        nonce_tuple_ids.as_ref().map(|ids| ids.len()).unwrap_or(0),
                        our_btc_tx.inputs.len()
                    );

                    self.processed_batch_rounds
                        .remove(&(round, "BTC_CLAIM_PLATFORM_FEE".to_string()));

                    let entries: Vec<(String, PendingClaimPlatformFeeRequest)> = self
                        .db
                        .get_values_with_prefix("pending_claim_platform_fee:")
                        .unwrap_or_default();
                    for (key, req) in entries {
                        if req.status == "Batched"
                            && req.tx_id.is_none()
                            && used_requests.iter().any(|(rid, _)| *rid == req.request_id)
                        {
                            let mut reverted = req.clone();
                            reverted.status = "Pending".to_string();
                            let _ = self.db.put_string(&key, &reverted);
                            info!(
                                "🔄 [BTC_CLAIM_PLATFORM_FEE] Reverted claim {} to Pending after nonce/input mismatch",
                                req.request_id
                            );
                        }
                    }
                    return Ok(());
                }

                // Trigger signing
                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let mut chain_handler_box =
                        crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                            crate::types::network::network_type()
                                .bitcoin_network_label()
                                .to_string(),
                        );

                    // Set network's DKG group key
                    if let Some(dkg_node) = &self.dkg_node {
                        if let Some(group_key) = dkg_node.get_final_public_key().await {
                            let affine_point = group_key.to_affine();
                            let encoded_point = k256::EncodedPoint::from(affine_point);
                            let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                            if let Some(btc_handler) = chain_handler_box
                                .as_any_mut()
                                .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                            ) {
                                btc_handler.set_group_public_key(compressed_bytes);
                                debug!(
                                    "🔑 [BTC_CLAIM_PLATFORM_FEE] Set network DKG group public key"
                                );
                            }
                        }
                    }

                    let chain_handler: std::sync::Arc<dyn crate::chain_abstraction::ChainHandler> =
                        std::sync::Arc::from(chain_handler_box);

                    let tx_bytes = chain_handler.create_transaction_bytes(
                        &crate::chain_abstraction::ChainTransaction::Bitcoin(our_btc_tx.clone()),
                    )?;

                    let signing_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_secret_share().await
                    } else {
                        None
                    };

                    info!("🔐 [BTC_CLAIM_PLATFORM_FEE] Starting Bitcoin claim-platform-fee signing process...");

                    // Encode batch metadata as "request_id|admin"
                    let claim_identifiers: Vec<String> = used_requests
                        .iter()
                        .map(|(req_id, _)| format!("{}|admin", req_id))
                        .collect();

                    use crate::signing::chains::BitcoinSigner;
                    let mut btc_signer = BitcoinSigner::new(&mut signing_node);
                    if let Err(e) = btc_signer
                        .sign_transaction(
                            tx_bytes,
                            &chain_handler,
                            Some(our_btc_tx),
                            None,
                            claim_identifiers.clone(),
                            Some(crate::types::TransactionType::ClaimPlatformFee),
                            signing_key,
                            None,
                            signing_key,
                            nonce_tuple_ids.clone(),
                            round,
                        )
                        .await
                    {
                        warn!(
                            "❌ [BTC_CLAIM_PLATFORM_FEE] Batch signing failed for round {}: {}",
                            round, e
                        );

                        // Revert local Batched requests to Pending (never Completed)
                        {
                            use crate::types::rpc_server::PendingClaimPlatformFeeRequest;
                            let entries: Vec<(String, PendingClaimPlatformFeeRequest)> = self
                                .db
                                .get_values_with_prefix("pending_claim_platform_fee:")
                                .unwrap_or_default();
                            for (key, req) in entries {
                                if req.status == "Batched"
                                    && req.tx_id.is_none()
                                    && used_requests.iter().any(|(rid, _)| *rid == req.request_id)
                                {
                                    let mut reverted = req.clone();
                                    reverted.status = "Pending".to_string();
                                    let _ = self.db.put_string(&key, &reverted);
                                    info!("🔄 [BTC_CLAIM_PLATFORM_FEE] Reverted claim_platform_fee {} to Pending", req.request_id);
                                }
                            }
                        }

                        // Broadcast error so other nodes also revert
                        let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: claim_identifiers,
                            error_message: format!(
                                "BTC claim-platform-fee batch signing failed for round {}: {}",
                                round, e
                            ),
                            transaction_type: "claim_platform_fee".to_string(),
                            solver_address: None,
                            node_id: self.local_peer_id.to_string(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: "transaction-sync".to_string(),
                                    data,
                                })
                                .await;
                            info!("📡 [BTC_CLAIM_PLATFORM_FEE] Broadcasted batch failure for round {} to sync status across nodes", round);
                        }
                    } else {
                        debug!("✅ [BTC_CLAIM_PLATFORM_FEE] Bitcoin claim-platform-fee transaction signing initiated");
                    }
                } else {
                    error!("❌ [BTC_CLAIM_PLATFORM_FEE] Signing node not available");
                }
            }
            GossipsubMessage::TicsClaimPlatformFeeBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use crate::types::rpc_server::PendingClaimPlatformFeeRequest;
                use crate::utils::transaction::create_claim_platform_fee_transaction;
                use ethers::types::U256;

                info!(
                    "📦 [TICS_CLAIM_PLATFORM_FEE] Received TICS claim-platform-fee batch {} from node {} (timestamp {})",
                    batch_id, node_id, timestamp
                );

                // Remove coordinator-assigned nonce from local available pool
                if let Some(ref nonce_id) = nonce_tuple_id {
                    if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.remove_nonces_from_available_pool(&[nonce_id.clone()])
                            .await;
                    }
                }

                // Deduplicate: skip if we already processed a batch for this round+type
                let batch_key = (round, "TICS_CLAIM_PLATFORM_FEE".to_string());
                if self.processed_batch_rounds.contains(&batch_key) {
                    info!(
                        "⏭️ [BATCH] Already processed batch for round {} type TICS_CLAIM_PLATFORM_FEE, skipping duplicate",
                        round
                    );
                    return Ok(());
                }
                self.processed_batch_rounds.insert(batch_key);

                if requests.is_empty() {
                    info!("ℹ️  [TICS_CLAIM_PLATFORM_FEE] Empty batch received, nothing to do");
                    return Ok(());
                }

                // We process one claim at a time (from the settlement function)
                let entry = &requests[0];
                let db = &self.db;

                // Load the claim from DB and validate
                let db_key = format!("pending_claim_platform_fee:{}", entry.request_id);
                let claim: PendingClaimPlatformFeeRequest = match db.get_string(&db_key) {
                    Ok(Some(req)) => req,
                    Ok(None) => {
                        warn!(
                            "⚠️ [TICS_CLAIM_PLATFORM_FEE] Claim {} not found in DB",
                            entry.request_id
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ [TICS_CLAIM_PLATFORM_FEE] Failed to load claim {}: {}",
                            entry.request_id, e
                        );
                        return Ok(());
                    }
                };

                let is_pending_or_batched = |s: &str| s == "Pending" || s == "Batched";
                if !is_pending_or_batched(&claim.status) {
                    warn!(
                        "⚠️ [TICS_CLAIM_PLATFORM_FEE] Claim {} has status {} (expected Pending/Batched); skipping",
                        entry.request_id, claim.status
                    );
                    return Ok(());
                }

                // Build identifier for tx-id broadcast
                let used_identifiers: Vec<String> = vec![format!("{}|admin", entry.request_id)];

                // Look up admin registration to get derived_eth_address + tweaked_secret_share + group_key
                let user_intent_manager = match &self.user_intent_manager {
                    Some(uim) => uim.clone(),
                    None => {
                        warn!("❌ [TICS_CLAIM_PLATFORM_FEE] UserIntentManager not available");
                        return Ok(());
                    }
                };

                let admin_reg = match user_intent_manager
                    .get_admin_by_address(&entry.admin_tics_address)
                    .await
                {
                    Some(reg) => reg,
                    None => {
                        warn!(
                            "⚠️ [TICS_CLAIM_PLATFORM_FEE] Admin not found for address {}",
                            entry.admin_tics_address
                        );
                        return Ok(());
                    }
                };

                let admin_derived_eth = match &admin_reg.derived_eth_address {
                    Some(addr) => addr.clone(),
                    None => {
                        warn!("⚠️ [TICS_CLAIM_PLATFORM_FEE] Admin has no derived_eth_address");
                        return Ok(());
                    }
                };

                let admin_tweaked_share = admin_reg.tweaked_secret_share.as_ref().map(|s| s.0);
                if admin_tweaked_share.is_none() {
                    info!("ℹ️ [TICS_CLAIM_PLATFORM_FEE] Admin has no tweaked_secret_share (observer/syncing node) — will store pending tx but skip signing");
                }

                let admin_group_key = match &admin_reg.user_group_key {
                    Some(k) => k.0.into(), // SerializablePoint → AffinePoint → ProjectivePoint
                    None => {
                        warn!("⚠️ [TICS_CLAIM_PLATFORM_FEE] Admin has no user_group_key");
                        return Ok(());
                    }
                };

                // Parse amount
                let amount = match U256::from_dec_str(&entry.amount) {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(
                            "⚠️ [TICS_CLAIM_PLATFORM_FEE] Invalid amount '{}': {}",
                            entry.amount, e
                        );
                        return Ok(());
                    }
                };

                // Build contract transaction: claimPlatformFee(amount, chainType, recipient)
                let contract_address_str = crate::env_defaults::solver_contract_address();
                let tics_cid = crate::env_defaults::mpc_tics_chain_id();
                let contract_chain_id = crate::env_defaults::solver_contract_chain_id()
                    .parse::<u64>()
                    .unwrap_or(tics_cid);
                let contract_chain_name = if contract_chain_id == tics_cid {
                    "qubetics"
                } else {
                    "tics"
                };

                let chain_tx = match create_claim_platform_fee_transaction(
                    &admin_derived_eth,
                    amount,
                    entry.chain_type,
                    &entry.target_address,
                    &contract_address_str,
                    contract_chain_id,
                    contract_chain_name,
                )
                .await
                {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!(
                            "⚠️ [TICS_CLAIM_PLATFORM_FEE] Failed to create claimPlatformFee tx: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let crate::chain_abstraction::ChainTransaction::Tics(eth_tx) = &chain_tx else {
                    warn!("❌ [TICS_CLAIM_PLATFORM_FEE] Expected TICS transaction");
                    return Ok(());
                };

                // Set up signing with admin key
                let _dkg_node = if let Some(node) = &self.dkg_node {
                    node
                } else {
                    warn!("❌ [TICS_CLAIM_PLATFORM_FEE] DKG node unavailable");
                    return Ok(());
                };

                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);
                    signing_node.set_chain_handler(
                        crate::chain_abstraction::ChainHandlerFactory::create_tics_handler(
                            eth_tx.chain_id,
                        )
                        .into(),
                    );

                    // Use admin's group key (not vault key)
                    signing_node.set_vault_group_key(admin_group_key);

                    let contract_tx = crate::types::intent::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        nonce: eth_tx.nonce,
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        chain_id: eth_tx.chain_id,
                        data: eth_tx
                            .data
                            .as_ref()
                            .map(|d| format!("0x{}", hex::encode(d)))
                            .unwrap_or_else(|| "0x".to_string()),
                    };

                    let contract_tx_bytes =
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        );
                    let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
                    let mut eth_signer = crate::signing::TicsSigner::new(&mut signing_node);

                    // Sign with admin's tweaked share (passed as user_tweaked_share + signing_key_override)
                    // user_tics_address = admin's tics_address (for share pubkey lookup during verification)
                    if let Err(e) = eth_signer
                        .sign_contract_message(
                            contract_tx_bytes,
                            &contract_chain_handler,
                            &contract_tx,
                            admin_tweaked_share, // user_tweaked_share: admin's share
                            Some(entry.admin_tics_address.clone()), // user_tics_address: for pubkey lookup
                            vec![],                                 // intent_hashes
                            admin_tweaked_share, // signing_key_override: same admin share
                            None,                // request_id
                            None,                // original_request
                            None,                // tics_withdraw_identifiers
                            None,                // tics_claim_reward_identifiers
                            Some(used_identifiers.clone()), // tics_claim_platform_fee_identifiers
                            nonce_tuple_id.clone(), // coordinated nonce
                            round,
                        )
                        .await
                    {
                        warn!(
                            "❌ [TICS_CLAIM_PLATFORM_FEE] Batch signing failed for round {}: {}",
                            round, e
                        );

                        // Revert local Batched requests to Pending (never Completed)
                        {
                            use crate::types::rpc_server::PendingClaimPlatformFeeRequest;
                            let entries: Vec<(String, PendingClaimPlatformFeeRequest)> = self
                                .db
                                .get_values_with_prefix("pending_claim_platform_fee:")
                                .unwrap_or_default();
                            for (key, req) in entries {
                                if req.request_id == entry.request_id
                                    && req.status == "Batched"
                                    && req.tx_id.is_none()
                                {
                                    let mut reverted = req.clone();
                                    reverted.status = "Pending".to_string();
                                    let _ = self.db.put_string(&key, &reverted);
                                    info!("🔄 [TICS_CLAIM_PLATFORM_FEE] Reverted claim_platform_fee {} to Pending", req.request_id);
                                }
                            }
                        }

                        // Broadcast error so other nodes also revert
                        let error_msg = GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: used_identifiers,
                            error_message: format!(
                                "TICS claim-platform-fee batch signing failed for round {}: {}",
                                round, e
                            ),
                            transaction_type: "claim_platform_fee".to_string(),
                            solver_address: None,
                            node_id: self.local_peer_id.to_string(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self
                                .message_tx
                                .send(ChannelMessage::Broadcast {
                                    topic: "transaction-sync".to_string(),
                                    data,
                                })
                                .await;
                            info!("📡 [TICS_CLAIM_PLATFORM_FEE] Broadcasted batch failure for round {} to sync status across nodes", round);
                        }
                        return Ok(());
                    }
                }

                info!(
                    "✅ [TICS_CLAIM_PLATFORM_FEE] Signing initiated for batch {} (claim {})",
                    batch_id, entry.request_id
                );
            }
            GossipsubMessage::ClaimPlatformFeeTxIdBroadcast {
                txid,
                network,
                batch_id,
                requests,
                node_id,
            } => {
                info!(
                    "📡 [CLAIM_PLATFORM_FEE_TXID] Received txid broadcast from node {}: txid={}, network={}, batch_id={}, requests={}",
                    node_id, txid, network, batch_id, requests.len()
                );
                if !requests.is_empty() {
                    if let Err(e) = self
                        .handle_claim_platform_fee_transaction_id_storage_batch(&txid, &requests)
                        .await
                    {
                        warn!(
                            "⚠️ [CLAIM_PLATFORM_FEE_TXID] Batch storage failed for txid {} ({} requests): {}",
                            txid, requests.len(), e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [CLAIM_PLATFORM_FEE_TXID] Empty requests in txid broadcast: txid={}, batch_id={}",
                        txid, batch_id
                    );
                }
            }
        }
        Ok(())
    }

    /// Send acknowledgment for a critical message
    async fn send_critical_message_ack(
        &self,
        msg_type: crate::network::rpc::retry_manager::CriticalMessageType,
        msg: &GossipsubMessage,
    ) {
        // Generate message ID - if this fails, we can't send an ACK
        debug!(
            "🔍 [RETRY] Starting ACK generation for message type: {:?}",
            msg_type
        );

        // Production: Add timeout to message ID generation to prevent hanging
        let gen_timeout = Duration::from_secs(2);
        let message_id = match tokio::time::timeout(gen_timeout, async {
            crate::network::rpc::retry_manager::RetryManager::generate_message_id(
                msg_type.clone(),
                msg,
            )
        })
        .await
        {
            Ok(Ok(id)) => {
                debug!("🔑 [RETRY] Generated message ID for ACK: {:?}", id);
                id
            }
            Ok(Err(e)) => {
                debug!(
                    "❌ [RETRY] CRITICAL: Failed to generate message ID for ACK: {}",
                    e
                );
                debug!(
                    "❌ [RETRY] Cannot send ACK without message ID - this will cause retry failures!"
                );
                return;
            }
            Err(_) => {
                debug!(
                    "❌ [RETRY] CRITICAL: Timeout generating message ID (>{}s)",
                    gen_timeout.as_secs()
                );
                debug!("❌ [RETRY] Cannot send ACK - this will cause retry failures!");
                return;
            }
        };

        let unique_id = message_id.unique_id.clone();
        let ack_msg = GossipsubMessage::CriticalMessageAck {
            message_type: format!("{:?}", msg_type),
            message_id: unique_id.clone(),
            node_id: self.local_peer_id,
        };

        debug!(
            "📝 [RETRY] Created ACK message: type={:?}, id={}, from={}",
            msg_type, unique_id, self.local_peer_id
        );

        let topic = match msg_type {
            crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast => {
                crate::network::transport::types::TOPIC_TRANSACTION_SYNC
            }
            crate::network::rpc::retry_manager::CriticalMessageType::FinalNodeIdBroadcast => {
                crate::network::transport::types::TOPIC_TRANSACTION_SYNC
            }
        };

        // Serialize ACK message
        let data = match serde_json::to_vec(&ack_msg) {
            Ok(d) => d,
            Err(e) => {
                debug!("❌ [RETRY] Failed to serialize ACK message: {}", e);
                return;
            }
        };

        // Send ACK via broadcast channel using try_send to avoid blocking
        // If channel is full, ACK delivery is deferred - sender will retry anyway
        debug!(
            "📡 [RETRY] Sending ACK to topic {} for message {:?}",
            topic, message_id
        );

        match self.message_tx.try_send(ChannelMessage::Broadcast {
            topic: topic.to_string(),
            data,
        }) {
            Ok(_) => {
                debug!(
                    "✅ [RETRY] ACK sent to channel for {:?} (will be broadcast to topic {})",
                    message_id, topic
                );
                // Record successful send for monitoring
                self.channel_health.record_send_success();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full but not closed - sender will retry this message
                // So the ACK will be sent again when we receive the retry
                // Record for monitoring
                self.channel_health.record_send_full();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                debug!("❌ [RETRY] CRITICAL: Channel closed - cannot send ACK!");
                debug!(
                    "❌ [RETRY] ACK for {:?} was NOT sent - system shutting down",
                    message_id
                );
                self.channel_health.record_send_closed();
            }
        }

        // Perform periodic health check
        self.channel_health.health_check();
    }
}
