/// Gossipsub message handler
/// Handles all gossipsub message types: DKG, Signing, Command, Consensus, VRF, etc.
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
    signing::EthereumSigner,
    types::{
        p2p::SerializablePeerId, signing::SigningMessage, vrf::VrfRoundSyncResponse,
        ChannelMessage, GossipsubMessage, IntentStatus,
    },
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
}

const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";

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
                        // Check if we haven't already processed this disconnect
                        if self.node_manager.get_active_nodes().contains(&peer_id) {
                            info!("📢 [DISCONNECT] Processing disconnect for node {}", peer_id);
                            self.handle_node_disconnect_internal(peer_id).await;
                        } else {
                            info!("📢 [DISCONNECT] Node {} already removed, skipping", peer_id);
                        }
                    }
                } else {
                    // dkg.r.2.1
                    // here we unwrapped the outer gossipmsg wrap from
                    // the msg bytes (check broadcast_shares() in dkg module)
                    if let Some(dkg_node) = &mut self.dkg_node {
                        // now we can unwrap the internal dkg wrap to get the DKG related things
                        dkg_node
                            .handle_message(dkg_msg, self.node_manager.clone())
                            .await?;
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
                            user_eth_address,
                            slot_id: _,
                        } => {
                            let tx_type = if user_eth_address.is_some() {
                                "user-to-network"
                            } else {
                                "network-to-target"
                            };
                            info!("📥 [NETWORK] Received {} ECDSA signature from {} for round {} on topic {} (user_eth_address: {:?})", tx_type, from, round, message.topic, user_eth_address);
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
                            user_eth_address: _,
                        } => {
                            info!(
                                "📥 [NETWORK] Received BTC UTV batch signatures from {} for slot {} round {} ({} inputs)",
                                from, slot_id, round, signatures.len()
                            );
                        }
                        // Nonce protocol messages for random k generation
                        SigningMessage::NonceCommitment { from, batch_id, round, .. } => {
                            info!(
                                "📥 [NONCE] Received commitment from {} for batch {} round {}",
                                from, batch_id, round
                            );
                        }
                        SigningMessage::NonceReveal { from, batch_id, round, .. } => {
                            info!(
                                "📥 [NONCE] Received reveal from {} for batch {} round {}",
                                from, batch_id, round
                            );
                        }
                        SigningMessage::RequestNonceGeneration { coordinator_id, batch_id, batch_size, .. } => {
                            info!(
                                "📥 [NONCE] Received generation request from {} for batch {} (size: {})",
                                coordinator_id, batch_id, batch_size
                            );
                        }
                        SigningMessage::NonceGenerationComplete { from, batch_id, tuples_count, success, .. } => {
                            info!(
                                "📥 [NONCE] Generation complete from {} for batch {} ({} tuples, success: {})",
                                from, batch_id, tuples_count, success
                            );
                        }
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
            GossipsubMessage::VrfSelection(vrf_msg) => {
                // Handle VRF selection messages
                if let Some(_vrf_manager) = self
                    .node_manager
                    .as_any()
                    .downcast_ref::<crate::node_selection::VrfNodeManager>()
                {
                    // We need to handle this differently since we can't mutate through a trait object
                    // For now, we'll log the message
                } else {
                    info!(
                        "Received VRF selection message but node manager is not VRF-based: {:?}",
                        vrf_msg
                    );
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
                    "📥 [VRF] Received VRF selected nodes broadcast: round={}, from={}, received_by={}",
                    round, selector_node_id, self.local_peer_id
                );

                // No ACK or retry for VrfSelectedNodes - used only for round sync / consensus trigger (final node is HRW)

                // Store the received VRF selection in the signing node's VRF selector
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
                        "💾 [VRF] Stored VRF selected nodes from node {} for round {}",
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
                        "💾 [VRF_SYNC] Stored round {:?} for peer {} from gossipsub request",
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
                                "⚠️ [VRF_SYNC] Failed to send round sync response to {}: {}",
                                peer, e
                            );
                        }
                    }
                    Err(e) => warn!(
                        "⚠️ [VRF_SYNC] Failed to serialize VRF round sync response: {}",
                        e
                    ),
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
                        "💾 [VRF_SYNC] Stored round {:?} for peer {} from gossipsub response",
                        sync_response.current_round, peer
                    );
                }
            }
            GossipsubMessage::UserRegistration {
                ethereum_address,
                timestamp,
                node_id,
            } => {
                info!(
                    "👤 Received user registration via gossipsub: {} from node {} at {}",
                    ethereum_address, node_id, timestamp
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
                        .register_user(&ethereum_address, dkg_secret_share.as_ref(), &node_id)
                        .await
                    {
                        Ok(registration) => {
                            info!(
                                "✅ [GOSSIPSUB] Successfully registered user {} locally",
                                ethereum_address
                            );

                            // Log tweaked secret share status
                            if registration.tweaked_secret_share.is_some() {
                                info!("🔑 [GOSSIPSUB] Computed and stored tweaked secret share for user: {}", ethereum_address);
                            } else {
                                info!("⚠️ [GOSSIPSUB] No tweaked secret share computed (DKG secret share not available) for user: {}", ethereum_address);
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
                                                .set_user_group_key(&ethereum_address, group_key)
                                                .await
                                            {
                                                warn!("❌ [GOSSIPSUB] Failed to store user group key for {}: {}", ethereum_address, e);
                                            } else {
                                                // Log the derived addresses
                                                if let Some(user) = user_intent_manager
                                                    .get_user_by_address(&ethereum_address)
                                                    .await
                                                {
                                                    if user.derived_eth_address.is_some() {
                                                        info!("📬 [GOSSIPSUB] Derived ETH address stored for {}", ethereum_address);
                                                    }
                                                    if user.derived_btc_address.is_some() {
                                                        info!("📬 [GOSSIPSUB] Derived BTC address stored for {}", ethereum_address);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("❌ [GOSSIPSUB] Failed to derive user-specific group key for {}: {}", ethereum_address, e);
                                        }
                                    }
                                }
                            } else {
                                warn!(
                                    "❌ [GOSSIPSUB] Invalid HMAC tweak scalar for {}",
                                    ethereum_address
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to register user {} locally: {}",
                                ethereum_address, e
                            );
                        }
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] User registry not available to handle user registration");
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

                // SECURITY FIX 1: Authenticate sender - verify node_id is a trusted/active node
                let sender_peer_id = match node_id.parse::<libp2p::PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "🚫 [SECURITY] Rejecting TransactionIdBroadcast: invalid node_id format '{}': {}",
                            node_id, e
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
                        "🚫 [SECURITY] Rejecting TransactionIdBroadcast: sender {} is not a trusted/active node",
                        node_id
                    );
                    return Ok(());
                }

                info!(
                    "✅ [SECURITY] TransactionIdBroadcast authenticated from trusted node {}",
                    node_id
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
            GossipsubMessage::TransactionErrorBroadcast {
                intent_hashes,
                error_message,
                transaction_type: _transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction error broadcast from node {}",
                    node_id
                );
                if !intent_hashes.is_empty() {
                    info!(
                        "🔗 [NETWORK] Intent hashes: {} intent(s)",
                        intent_hashes.len()
                    );
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
                        // Check if this is an add_liquidity request_id (starts with "addliq:")
                        if h.starts_with("addliq:") {
                            warn!(
                                "⚠️ [ADD_LIQUIDITY] Request {} failed (error: {}), will retry in next cycle (status remains 'Pending')",
                                h, error_message
                            );
                        }
                    }
                }

                // Store the error in our local user registry (one store per intent)
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if !intent_hashes.is_empty() {
                        for h in &intent_hashes {
                            // Skip add_liquidity request_ids (already handled above)
                            if h.starts_with("addliq:") {
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
                        }
                    } else if solver_address.is_some() {
                        // Reward/withdraw transaction error - just log for now
                    } else {
                        warn!("⚠️ [NETWORK] Transaction error broadcast missing both intent hashes and solver address");
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction error");
                }
            }
            GossipsubMessage::DepositIntent {
                intent,
                intent_id: _intent_id,
                user_eth_address,
                amount: _,
                signature,
            } => {
                // user_eth_address is now mandatory (not Option)
                let user_eth_addr = user_eth_address;

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

                let source_amount = match intent.amount.parse::<u128>() {
                    Ok(amt) => amt,
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

                // Fetch user's source address balance
                match fetch_network_balance(&intent.source_address, source_blockchain).await {
                    Ok(user_balance) => {
                        if user_balance < source_amount {
                            warn!(
                                "⚠️ [GOSSIPSUB] Insufficient source balance for intent {}: user has {}, needs {}",
                                intent_hash, user_balance, source_amount
                            );
                            return Ok(());
                        } else {
                            info!(
                                "✅ [GOSSIPSUB] Source address has sufficient balance: {} >= {}",
                                user_balance, source_amount
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

                // Store the intent in database (duplicate already rejected above)
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
                    intent.amount.parse::<u128>().unwrap()
                } else {
                    let prices = match fetch_crypto_prices().await {
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

                // Check network balance for target chain; store target amount only when sufficient
                let network_address = if let Some(dkg_node) = &self.dkg_node {
                    match dkg_node.get_final_public_key().await {
                        Some(final_public) => {
                            if intent.target_chain.eq_ignore_ascii_case("btc")
                                || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                            {
                                crate::utils::get_btc_address_from_group_key(final_public)
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

                if has_sufficient_funds {
                    if let Some(user_intent_manager) = &self.user_intent_manager {
                        if let Err(e) = user_intent_manager
                            .store_intent_target_amount(&intent_hash, target_amount)
                            .await
                        {
                            warn!(
                                "❌ [GOSSIPSUB] Failed to store target amount for {}: {}",
                                intent_hash, e
                            );
                        } else {
                            info!(
                                "💾 [GOSSIPSUB] Stored target amount {} for intent {} (network has sufficient funds)",
                                target_amount, intent_hash
                            );
                        }
                    }
                } else {
                    return Ok(());
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
            } => {
                info!(
                    "💧 [ADD_LIQUIDITY] Received solver_add_liquidity gossip: request_id={}, solver_id={}, solver_address={}, amount={}, chain_id={}",
                    request_id, solver_id, solver_address, amount, chain_id
                );

                // Validate chainId before persisting (must match RPC rules: 0 = BTC, 9029 = EVM).
                if chain_id != 0 && chain_id != 9029 {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Unsupported chain_id {} for request_id={}, dropping (allowed: 0=BTC, 9029=EVM)",
                        chain_id, request_id
                    );
                    return Ok(());
                }

                // Re-verify signature using VERIFICATION_ADDRESS before accepting into local queue.
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                let verification_address =
                    std::env::var("VERIFICATION_ADDRESS").unwrap_or_else(|_| "".to_string());
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

                if amount.trim().is_empty() || amount == "0" {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Zero or empty amount for request_id={}, dropping",
                        request_id
                    );
                    return Ok(());
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
                        info!("✅ Successfully added peer {} to node manager", peer);

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
                                // During initial DKG setup, update threshold as nodes join
                                if let Some(arc) = &self.signing_node {
                                    let mut signing_node = arc.lock().await;
                                    let new_threshold = self.node_manager.get_threshold();
                                    signing_node.set_threshold(new_threshold);
                                    info!("🔄 [THRESHOLD] Updated signing node threshold to {} (total nodes: {})", new_threshold, total);
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
            GossipsubMessage::VersionAnnouncement {
                peer,
                version,
                features,
                timestamp,
            } => {
                info!(
                    "📍 [VERSION] Peer {} announced version {} with features: {:?} (timestamp: {})",
                    peer, version, features, timestamp
                );
                // Version tracking will be handled when network upgrade module is integrated
            }
            GossipsubMessage::UpgradeAnnouncement {
                peer,
                target_version,
                phase,
                timestamp,
            } => {
                info!(
                    "🔄 [UPGRADE] Peer {} upgrade announcement: {} to version {} (timestamp: {})",
                    peer, phase, target_version, timestamp
                );
            } // Upgrade coordination will be handled when orchestrator is integrated
            GossipsubMessage::TransactionBroadcast {
                sequencer_request_id,
                blockchain_tx_hash,
                chain_id,
            } => {
                info!(
                    "📡 [TX_BROADCAST] Transaction broadcasted: chain_id={}, tx_hash={}",
                    chain_id, blockchain_tx_hash
                );
                if let Some(request_id) = sequencer_request_id {
                    info!("📝 [TX_BROADCAST] Request ID: {}", request_id);
                }
                // Note: add_liquidity status tracking happens via TransactionIdBroadcast, not here
            }
            GossipsubMessage::IntentBatchBroadcast {
                intent_hashes,
                batch_type,
                timestamp,
                round,
                node_id,
                nonce_tuple_id,
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

                // SHARED: Fetch intent details from database (same for BTC and TICS)
                let mut intent_data = Vec::new();

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    let mut batch_intents = Vec::new();

                    for intent_hash in &intent_hashes {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
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

                    // Observer nodes (no DKG share) should not build chain TXs or sign.
                    let is_dkg_participant = if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.has_dkg_share().await
                    } else {
                        false
                    };
                    if !is_dkg_participant {
                        info!(
                            "ℹ️ [INTENT_BATCH] Observer node skipping chain TX creation and signing for round {} (no DKG share)",
                            round
                        );
                        return Ok(());
                    }

                    // DIFFERENT: Process based on batch type
                    if batch_type == "BTC" {
                        // BITCOIN BATCH TRANSACTION FLOW
                        info!(
                            "₿ [BATCH] Processing Bitcoin batch transaction for {} intents",
                            intent_data.len()
                        );

                        // Step 0.5: Fetch crypto prices for TICS → BTC conversion
                        let prices = match crate::rpc_server::utils::fetch_crypto_prices().await {
                            Ok(p) => p,
                            Err(e) => {
                                error!(
                                    "❌ [BATCH] Failed to fetch crypto prices for conversion: {}",
                                    e
                                );
                                return Ok(());
                            }
                        };

                        info!("💱 [BATCH] Fetched crypto prices for conversion");

                        // Step 1: Build BatchOutput list from intents
                        use crate::signing::chains::bitcoin_batch::BatchOutput;
                        let mut batch_outputs = Vec::new();

                        for (intent_hash, intent, _tx_ids) in &intent_data {
                            // Parse TICS amount (in smallest units, 18 decimals)
                            let amount_tics_smallest: u128 = match intent.amount.parse() {
                                Ok(amt) => amt,
                                Err(e) => {
                                    warn!(
                                        "⚠️ [BATCH] Failed to parse amount for intent {}: {}",
                                        intent_hash, e
                                    );
                                    continue;
                                }
                            };

                            // Convert TICS → BTC satoshis using price conversion
                            let amount_sats =
                                match crate::rpc_server::utils::convert_src_smallest_to_dst_smallest(
                                    amount_tics_smallest,
                                    &intent.source_chain,
                                    &intent.target_chain,
                                    &prices,
                                ) {
                                    Ok(amt) => amt as u64,
                                    Err(e) => {
                                        error!("❌ [BATCH] Currency conversion failed for intent {}: {:?}", intent_hash, e);
                                        continue;
                                    }
                                };

                            info!("💱 [BATCH] Converted {} TICS ({} smallest units) → {} BTC satoshis", 
                                intent.amount, amount_tics_smallest, amount_sats);

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

                        let network_btc_address =
                            crate::utils::get_btc_address_from_group_key(group_key);

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
                                        info!("🔑 [BATCH] Set network DKG group public key");
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
                            btc_signer
                                .sign_transaction(
                                    tx_bytes,
                                    &chain_handler,
                                    Some(our_btc_tx),
                                    None, // No user eth address for network transaction
                                    intent_hashes_in_batch,
                                    Some(crate::types::TransactionType::NetworkToTarget),
                                    signing_key,
                                    None, // No solver
                                    signing_key,
                                    nonce_tuple_id.clone(), // coordinated nonce
                                )
                                .await?;

                            info!("✅ [BATCH] Bitcoin batch transaction signed successfully");
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
                            let target_amount = user_intent_manager
                                .get_intent_target_amount(intent_hash)
                                .await
                                .unwrap_or(source_amount);

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
                                std::env::var("INTENT_MANAGER_CONTRACT_ADDRESS").unwrap_or_else(
                                    |_| "0x0000000000000000000000000000000000000000".to_string(),
                                );
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
                                    .unwrap_or(9029);

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

                            let nonce = crate::utils::transaction::fetch_ethereum_nonce(
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

                            // Start MPC signing
                            if let Some(arc) = &self.signing_node {
                                let mut signing_node = arc.lock().await;
                                let available_nodes: Vec<PeerId> =
                                    self.node_manager.get_active_nodes().into_iter().collect();
                                signing_node.set_available_nodes(available_nodes);

                                // Ensure MAIN group key is available on signing node
                                signing_node.set_group_public_key(group_public_key);

                                // Use MAIN final secret share for signing (network group key path)
                                let secret_share = if let Some(dkg_node) = &self.dkg_node {
                                    dkg_node.get_final_secret_share().await
                                } else {
                                    None
                                };
                                if secret_share.is_none() {
                                    warn!("❌ [TICS_BATCH] Main DKG secret share not available; cannot sign contract tx");
                                    return Ok(());
                                }

                                let contract_tx_bytes =
                                    crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                let contract_chain_handler =
                                    signing_node.get_contract_chain_handler().clone();
                                let mut eth_signer = EthereumSigner::new(&mut signing_node);
                                eth_signer
                                    .sign_contract_message(
                                        contract_tx_bytes,
                                        &contract_chain_handler,
                                        &contract_tx,
                                        None,
                                        None, // user_eth_address (not applicable)
                                        intent_hashes.clone(),
                                        // Use the main DKG share as an explicit signing key override.
                                        secret_share,
                                        None,
                                        None,
                                        None, // tics_withdraw_identifiers (not applicable)
                                        None, // tics_claim_reward_identifiers (not applicable)
                                        nonce_tuple_id.clone(), // COORDINATED nonce from coordinator
                                    )
                                    .await?;

                                info!(
                                    "✅ [TICS_BATCH] Submitted processBatchIntents contract transaction into MPC signing flow ({} intents, nonce: {:?})",
                                    intent_hashes.len(),
                                    nonce_tuple_id
                                );
                                info!(
                                    "ℹ️  [TICS_BATCH] Signatures will be sent to final node: {}",
                                    node_id
                                );
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
                }

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    // Mark all intents in this batch as Batched on this node so they are not re-picked for future batches
                    for intent_hash in intent_hashes.iter() {
                        if let Some(user) = user_intent_manager
                            .get_user_by_intent_hash(intent_hash)
                            .await
                        {
                            if let Err(e) = user_intent_manager
                                .update_intent_status(
                                    &user.ethereum_address,
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

                    // Observer nodes (no DKG share) should not build chain TXs or sign;
                    // they already marked intents as Batched above for DB consistency.
                    let is_dkg_participant = if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.has_dkg_share().await
                    } else {
                        false
                    };
                    if !is_dkg_participant {
                        info!(
                            "ℹ️ [TICS_UTV_BATCH] Observer node skipping chain TX creation and signing for round {} (no DKG share)",
                            round
                        );
                        return Ok(());
                    }

                    let mut batch_intents = Vec::new();
                    for intent_hash in intent_hashes.iter() {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
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
                            let source_ok = intent.source_chain.eq_ignore_ascii_case("tics")
                                || intent.source_chain.eq_ignore_ascii_case("qubetics");
                            if !source_ok {
                                warn!(
                                    "⚠️ [TICS_UTV_BATCH] Intent {} source_chain is not TICS, skipping",
                                    intent_hash
                                );
                                continue;
                            }
                            if let Some(user) = user_intent_manager
                                .get_user_by_intent_hash(intent_hash)
                                .await
                            {
                                batch_intents.push((
                                    intent_hash.clone(),
                                    intent,
                                    user.ethereum_address,
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

                    // One VRF round; batch stored and signed per-slot; final node aggregates each slot and broadcasts one-by-one.
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
                        let target_amount = user_intent_manager
                            .get_intent_target_amount(intent_hash)
                            .await
                            .unwrap_or_else(|| intent.amount.parse().unwrap_or(0u128));
                        let amount = target_amount + (target_amount / 20);

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
                            crate::chain_abstraction::ChainTransaction::Ethereum(eth_tx) => {
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

                        use crate::signing::chains::EthereumSigner;
                        let mut eth_signer = EthereumSigner::new(&mut signing_node);
                        let n_slots = batch.len();
                        // Use coordinated nonces if available
                        if let Err(e) = eth_signer.sign_tics_user_to_vault_batch_with_nonces(round, batch, nonce_assignments.clone()).await
                        {
                            warn!(
                                "❌ [TICS_UTV_BATCH] Batch signing failed for round {}: {}",
                                round, e
                            );
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
                }

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    // Mark all intents in this batch as Batched on this node so they are not re-picked for future batches
                    for intent_hash in intent_hashes.iter() {
                        if let Some(user) = user_intent_manager
                            .get_user_by_intent_hash(intent_hash)
                            .await
                        {
                            if let Err(e) = user_intent_manager
                                .update_intent_status(
                                    &user.ethereum_address,
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

                    // Observer nodes (no DKG share) should not build chain TXs or sign;
                    // they already marked intents as Batched above for DB consistency.
                    let is_dkg_participant = if let Some(arc) = &self.signing_node {
                        let node = arc.lock().await;
                        node.has_dkg_share().await
                    } else {
                        false
                    };
                    if !is_dkg_participant {
                        info!(
                            "ℹ️ [BTC_UTV_BATCH] Observer node skipping chain TX creation and signing for round {} (no DKG share)",
                            round
                        );
                        return Ok(());
                    }

                    let mut batch_intents = Vec::new();
                    for intent_hash in intent_hashes.iter() {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
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
                            let source_ok = intent.source_chain.eq_ignore_ascii_case("bitcoin")
                                || intent.source_chain.eq_ignore_ascii_case("btc");
                            if !source_ok {
                                warn!(
                                    "⚠️ [BTC_UTV_BATCH] Intent {} source_chain is not Bitcoin, skipping",
                                    intent_hash
                                );
                                continue;
                            }
                            if let Some(user) = user_intent_manager
                                .get_user_by_intent_hash(intent_hash)
                                .await
                            {
                                batch_intents.push((
                                    intent_hash.clone(),
                                    intent,
                                    user.ethereum_address,
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
                                Some(crate::utils::get_btc_address_from_group_key(group_key))
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
                        let amount_sats: u128 = intent.amount.parse().unwrap_or(0);
                        let amount = amount_sats + (amount_sats / 20); // 5% buffer for fees

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
                        if let Err(e) = btc_signer.sign_btc_user_to_vault_batch(round, batch, &nonce_assignments).await
                        {
                            warn!(
                                "❌ [BTC_UTV_BATCH] Batch signing failed for round {}: {}",
                                round, e
                            );
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
                nonce_tuple_id,
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

                // Observer nodes (no DKG share) should not build chain TXs or sign.
                let is_dkg_participant = if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.has_dkg_share().await
                } else {
                    false
                };
                if !is_dkg_participant {
                    info!(
                        "ℹ️ [BTC_WITHDRAW] Observer node skipping chain TX creation and signing for round {} (no DKG share)",
                        round
                    );
                    return Ok(());
                }

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
                        // Only process BTC withdraws that are in strict Pending state and have no tx_id
                        if req.asset.to_uppercase() != "BTC"
                            || req.status != "Pending"
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

                let network_btc_address = crate::utils::get_btc_address_from_group_key(group_key);

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
                                info!("🔑 [BTC_WITHDRAW] Set network DKG group public key");
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
                    btc_signer
                        .sign_transaction(
                            tx_bytes,
                            &chain_handler,
                            Some(our_btc_tx),
                            None, // No user eth address
                            withdraw_identifiers,
                            Some(crate::types::TransactionType::WithdrawLiquidity),
                            signing_key,
                            None, // No per-withdraw solver address; encoded in identifiers
                            signing_key,
                            nonce_tuple_id.clone(), // coordinated nonce for threshold signing
                        )
                        .await?;

                    info!("✅ [BTC_WITHDRAW] Bitcoin withdraw batch transaction signing initiated");
                } else {
                    error!("❌ [BTC_WITHDRAW] Signing node not available");
                }
            }
            GossipsubMessage::BtcClaimRewardBatch {
                batch_id,
                requests,
                round: _round,
                timestamp,
                node_id,
                nonce_tuple_id,
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

                // Observer nodes (no DKG share) should not build chain TXs or sign.
                let is_dkg_participant = if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.has_dkg_share().await
                } else {
                    false
                };
                if !is_dkg_participant {
                    info!(
                        "ℹ️ [BTC_CLAIM_REWARD] Observer node skipping chain TX creation and signing for batch {} (no DKG share)",
                        batch_id
                    );
                    return Ok(());
                }

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
                    if req.status != "Pending" || req.tx_id.is_some() {
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

                    let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
                        .unwrap_or_else(|_| "http://localhost:8545".to_string());
                    let contract_address_env = std::env::var("SOLVER_CONTRACT_ADDRESS")
                        .unwrap_or_else(|_| {
                            "0x0000000000000000000000000000000000000000".to_string()
                        });
                    let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(9029);
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
                    if amount_sats < 546 {
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
                let network_btc_address = crate::utils::get_btc_address_from_group_key(group_key);

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
                    btc_signer
                        .sign_transaction(
                            tx_bytes,
                            &chain_handler,
                            Some(our_btc_tx),
                            None,
                            claim_reward_identifiers,
                            Some(crate::types::TransactionType::ClaimReward),
                            signing_key,
                            None,
                            signing_key,
                            nonce_tuple_id.clone(), // coordinated nonce for threshold signing
                        )
                        .await?;
                    info!("✅ [BTC_CLAIM_REWARD] Bitcoin claim-reward batch signing initiated");
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
                nonce_tuple_id,
            } => {
                use crate::types::rpc_server::PendingWithdrawRequest;
                use crate::utils::transaction::RemoveLiquidityBatchRequest;
                use ethers::types::U256;

                info!(
                    "📦 [TICS_WITHDRAW] Received TICS withdraw batch {} from node {} (round {}, timestamp {})",
                    batch_id, node_id, round, timestamp
                );

                if requests.is_empty() {
                    info!("ℹ️  [TICS_WITHDRAW] Empty TicsWithdrawBatch received, nothing to do");
                    return Ok(());
                }

                // Observer nodes (no DKG share) should not build chain TXs or sign.
                let is_dkg_participant = if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.has_dkg_share().await
                } else {
                    false
                };
                if !is_dkg_participant {
                    info!(
                        "ℹ️ [TICS_WITHDRAW] Observer node skipping chain TX creation and signing for round {} (no DKG share)",
                        round
                    );
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

                let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
                    .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
                if contract_address == "0x0000000000000000000000000000000000000000" {
                    warn!(
                        "⏭️ [TICS_WITHDRAW] Skipping TICS withdraw batch {} - solver contract address not configured",
                        batch_id
                    );
                    return Ok(());
                }

                let contract_chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
                    .unwrap_or_else(|_| "9029".to_string())
                    .parse::<u64>()
                    .unwrap_or(9029);
                let contract_chain_name = if contract_chain_id == 9029 {
                    "qubetics"
                } else {
                    "ethereum"
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
                        crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                            eth_tx.chain_id,
                        )
                        .into(),
                    );

                    let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

                    if let Some(ref _secret_share) = vault_tweaked_share {
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
                        let mut eth_signer = crate::signing::EthereumSigner::new(&mut signing_node);

                        eth_signer
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
                                Some(used_identifiers.clone()), // for tx-id broadcast to update each request
                                None, // tics_claim_reward_identifiers (not applicable)
                                nonce_tuple_id.clone(), // coordinated nonce for threshold signing
                            )
                            .await?;

                        info!(
                            "✅ [TICS_WITHDRAW] Submitted single removeLiquidity batch transaction ({} entries) into MPC signing flow",
                            batch_requests.len()
                        );
                    } else {
                        warn!(
                            "⚠️ [TICS_WITHDRAW] Skipping removeLiquidity batch - missing vault secret share"
                        );
                    }
                } else {
                    warn!("❌ [TICS_WITHDRAW] Signing node unavailable for TICS withdraw batch");
                }
            }
            GossipsubMessage::TicsClaimRewardBatch {
                batch_id,
                requests,
                round: _round,
                timestamp,
                node_id,
                nonce_tuple_id,
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

                if requests.is_empty() {
                    info!("ℹ️  [TICS_CLAIM_REWARD] Empty TicsClaimRewardBatch received, nothing to do");
                    return Ok(());
                }

                // Observer nodes (no DKG share) should not build chain TXs or sign.
                let is_dkg_participant = if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.has_dkg_share().await
                } else {
                    false
                };
                if !is_dkg_participant {
                    info!(
                        "ℹ️ [TICS_CLAIM_REWARD] Observer node skipping chain TX creation and signing for batch {} (no DKG share)",
                        batch_id
                    );
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
                        .ethereum_address
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
                let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
                    .unwrap_or_else(|_| "http://localhost:8545".to_string());
                let contract_address_env = std::env::var("SOLVER_CONTRACT_ADDRESS")
                    .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
                let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(9029);
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
                    if tics_unclaimed.is_zero() {
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

                let contract_address_str = std::env::var("SOLVER_CONTRACT_ADDRESS")
                    .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
                let contract_chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
                    .unwrap_or_else(|_| "9029".to_string())
                    .parse::<u64>()
                    .unwrap_or(9029);
                let contract_chain_name = if contract_chain_id == 9029 {
                    "qubetics"
                } else {
                    "ethereum"
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

                let crate::chain_abstraction::ChainTransaction::Ethereum(eth_tx) = &chain_tx else {
                    warn!("❌ [TICS_CLAIM_REWARD] Expected Ethereum transaction");
                    return Ok(());
                };

                if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);
                    signing_node.set_chain_handler(
                        crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                            eth_tx.chain_id,
                        )
                        .into(),
                    );

                    let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

                    if let Some(ref _secret_share) = vault_tweaked_share {
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
                        let mut eth_signer = crate::signing::EthereumSigner::new(&mut signing_node);

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
                                None, // tics_withdraw_identifiers (not applicable)
                                Some(used_identifiers.clone()), // for tx-id broadcast: store tx_id on TICS, mark done for all
                                nonce_tuple_id.clone(), // coordinated nonce for threshold signing
                            )
                            .await
                        {
                            warn!("⚠️ [TICS_CLAIM_REWARD] sign_contract_message failed: {}", e);
                        } else {
                            info!(
                                "✅ [TICS_CLAIM_REWARD] Submitted claimRewardsBatch (TICS) into MPC signing flow ({} claims)",
                                claims.len()
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [TICS_CLAIM_REWARD] Skipping claimRewardsBatch - missing vault secret share"
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
                nonce_tuple_id,
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
                    nonce_tuple_id
                );

                // Process the batch - create contract call
                // handle_btc_intent_manager_update_batch is a method on MpcNetworkLayer (in channel_handler.rs)
                // Since both are impl MpcNetworkLayer, we can call it directly
                if let Err(e) = self
                    .handle_btc_intent_manager_update_batch(
                        intent_hashes,
                        btc_txid,
                        btc_batch_round,
                        update_round,
                        timestamp,
                        node_id,
                        nonce_tuple_id,
                    )
                    .await
                {
                    error!(
                        "❌ [BTC_INTENT_MANAGER] Failed to handle contract update batch: {}",
                        e
                    );
                }
            }
            GossipsubMessage::SolverAddLiquidityBatch {
                request_ids,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                info!(
                    "💧 [ADD_LIQUIDITY_BATCH] Received solver_add_liquidity batch from node {} (round {})",
                    node_id, round
                );
                info!(
                    "💧 [ADD_LIQUIDITY_BATCH] {} requests to process (will look up from RocksDB), timestamp: {}, nonce: {:?}",
                    request_ids.len(), timestamp, nonce_tuple_id
                );

                // Observer nodes (no DKG share) should not build chain TXs or sign.
                let is_dkg_participant = if let Some(arc) = &self.signing_node {
                    let node = arc.lock().await;
                    node.has_dkg_share().await
                } else {
                    false
                };
                if !is_dkg_participant {
                    info!(
                        "ℹ️ [ADD_LIQUIDITY_BATCH] Observer node skipping chain TX creation and signing for round {} (no DKG share)",
                        round
                    );
                    return Ok(());
                }

                // Process the batch - all nodes look up full details from RocksDB and participate in signing
                if let Err(e) = self
                    .handle_solver_add_liquidity_batch(request_ids, round, timestamp, node_id, nonce_tuple_id)
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

                // Persist only if this solver has no existing Pending/Batched request (one in-flight per solver).
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
                let has_pending_or_batched = existing
                    .iter()
                    .any(|(_, r)| r.status == "Pending" || r.status == "Batched");
                if has_pending_or_batched {
                    info!(
                        "🚫 [WITHDRAW_LIQUIDITY] Ignoring duplicate withdraw request {} for solver {}: already has Pending/Batched",
                        request.request_id, request.solver_address
                    );
                    return Ok(());
                }

                let key = format!(
                    "pending_withdraw_liquidity:{}:{}",
                    solver_lower, request.request_id
                );

                if let Err(e) = self.db.put_string_async(&key, &request).await {
                    warn!(
                        "⚠️ [WITHDRAW_LIQUIDITY] Failed to persist PendingWithdrawRequest request_id={} from gossip: {}",
                        request.request_id, e
                    );
                } else {
                    info!(
                        "✅ [WITHDRAW_LIQUIDITY] Stored PendingWithdrawRequest from gossip (request_id={}, solver={})",
                        request.request_id, request.solver_address
                    );
                }
            }
            GossipsubMessage::PendingClaimRewardRequestBroadcast { request } => {
                use crate::types::rpc_server::PendingClaimRewardRequest;

                info!(
                    "🎁 [CLAIM_REWARD] Received pending claim reward request from gossip: request_id={}, solver={}",
                    request.request_id, request.solver_address
                );

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

                if let Err(e) = self.db.put_string_async(&key, &request).await {
                    warn!(
                        "⚠️ [CLAIM_REWARD] Failed to persist PendingClaimRewardRequest request_id={} from gossip: {}",
                        request.request_id, e
                    );
                } else {
                    info!(
                        "✅ [CLAIM_REWARD] Stored PendingClaimRewardRequest from gossip (request_id={}, solver={})",
                        request.request_id, request.solver_address
                    );
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
                    tuples.len(), node_id, batch_id
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
                crate::network::transport::types::TOPIC_TRANSACTION_ID_SYNC
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
