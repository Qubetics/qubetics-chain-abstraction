/// Gossipsub message handler
/// Handles all gossipsub message types: DKG, Signing, Command, Consensus, VRF, etc.
///
/// NOTE: This module contains the gossipsub message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~2038-3559 of the original file
use anyhow::{anyhow, Result};
use ff::PrimeField;
use libp2p::{gossipsub::Message, PeerId};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::{
    database::key_utils,
    signing::{BitcoinSigner, EthereumSigner},
    types::{
        p2p::SerializablePeerId, signing::SigningMessage, vrf::VrfRoundSyncResponse,
        ChannelMessage, ConsensusMessage, GossipsubMessage,
    },
};

use crate::network::transport::types::{
    MpcNetworkLayer, VrfDomain, TOPIC_CONSENSUS, TOPIC_MAIN_SEQUENCER_VRF,
};

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
                if let Some(signing_node) = &mut self.signing_node {
                    // 🛡️ Error recovery for signing message processing - prevent node crashes
                    // Handle signing messages
                    match &signing_msg {
                        SigningMessage::ECDSASignature {
                            from,
                            signature,
                            round,
                            timestamp: _timestamp,
                            user_eth_address,
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
                if let Some(signing_node) = &mut self.signing_node {
                    signing_node
                        .handle_consensus_message(consensus_msg.clone())
                        .await?;
                }

                // Also handle in sequencer consensus nodes (vault and main sequencer)
                // Check if this is for main sequencer based on round
                match &consensus_msg {
                    ConsensusMessage::FinalNodeResult { round, .. } => {
                        // Handle in main sequencer if available
                        if let Some(sequencer) = &self.network_transaction_sequencer {
                            if let Err(e) = sequencer
                                .handle_consensus_message(consensus_msg.clone())
                                .await
                            {
                                // Log error but don't fail - consensus might be for different domain
                                warn!(
                                    "⚠️ [MAIN_SEQUENCER] Failed to handle consensus message for round {}: {}",
                                    round, e
                                );
                            } else {
                                info!(
                                    "✅ [MAIN_SEQUENCER] Handled consensus message for round {}",
                                    round
                                );
                            }
                        }
                    }
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
                let local_node_id = self.local_peer_id;
                let sender_peer_id = match message.source {
                    Some(pid) => pid,
                    None => {
                        warn!("🚫 [SECURITY] Rejecting VrfSelectedNodes broadcast: message has no source");
                        return Ok(());
                    }
                };
                info!(
                    "📥 [VRF] Received VRF selected nodes broadcast: round={}, from={}, received_by={}",
                    round, selector_node_id, local_node_id
                );

                // ALWAYS send ACK for critical messages - this is critical for retry mechanism
                // Send acknowledgment BEFORE processing to ensure it's sent even if processing fails
                info!(
                    "📤 [RETRY] Sending ACK for VrfSelectedNodes round {} from selector {} (this node: {})",
                    round, selector_node_id, local_node_id
                );

                // Generate message ID to verify it matches what sender expects
                let msg_id_result =
                    crate::network::rpc::retry_manager::RetryManager::generate_message_id(
                        crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
                        &GossipsubMessage::VrfSelectedNodes(broadcast_msg.clone()),
                    );

                match &msg_id_result {
                    Ok(msg_id) => {
                        info!(
                            "🔑 [RETRY] Generated message ID for ACK: {:?} (round={}, selector={})",
                            msg_id, round, selector_node_id
                        );
                    }
                    Err(e) => {
                        error!(
                            "❌ [RETRY] CRITICAL: Failed to generate message ID for ACK: {}",
                            e
                        );
                        error!("❌ [RETRY] ACK will NOT be sent - this will cause retry failures!");
                    }
                }

                // Send acknowledgment - MUST happen for all critical messages
                // This is called BEFORE processing to ensure ACK is sent even if processing fails
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
                    &GossipsubMessage::VrfSelectedNodes(broadcast_msg.clone()),
                )
                .await;
                info!(
                    "✅ [RETRY] send_critical_message_ack completed for round {} from selector {}",
                    round, selector_node_id
                );

                // Store the received VRF selection in the signing node's VRF selector
                if let Some(signing_node) = &mut self.signing_node {
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

                if self.store_peer_round_if_valid(
                    VrfDomain::Signing,
                    &sync_request.context,
                    peer,
                    reference_round,
                    sync_request.current_round,
                ) {
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

                if self.store_peer_round_if_valid(
                    VrfDomain::Signing,
                    &sync_response.context,
                    peer,
                    reference_round,
                    sync_response.current_round,
                ) {
                    info!(
                        "💾 [VRF_SYNC] Stored round {:?} for peer {} from gossipsub response",
                        sync_response.current_round, peer
                    );
                }
            }
            GossipsubMessage::MainSequencerVrfRoundSyncRequest(sync_request) => {
                let peer = sync_request.from.0;
                let reference_round = self
                    .get_local_vrf_round_for_domain(
                        VrfDomain::MainSequencer,
                        Some(&sync_request.context),
                    )
                    .await;

                if self.store_peer_round_if_valid(
                    VrfDomain::MainSequencer,
                    &sync_request.context,
                    peer,
                    reference_round,
                    sync_request.current_round,
                ) {
                    info!(
                        "💾 [MAIN_VRF_SYNC] Stored round {:?} for peer {} from request",
                        sync_request.current_round, peer
                    );
                }

                let response_round = self
                    .get_local_vrf_round_for_domain(
                        VrfDomain::MainSequencer,
                        Some(&sync_request.context),
                    )
                    .await;
                let response =
                    GossipsubMessage::MainSequencerVrfRoundSyncResponse(VrfRoundSyncResponse {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round: response_round,
                        context: sync_request.context.clone(),
                    });

                match serde_json::to_vec(&response) {
                    Ok(data) => {
                        if let Err(e) = self
                            .message_tx
                            .send(ChannelMessage::Broadcast {
                                topic: TOPIC_MAIN_SEQUENCER_VRF.to_string(),
                                data,
                            })
                            .await
                        {
                            warn!(
                                "⚠️ [MAIN_VRF_SYNC] Failed to send round sync response to {}: {}",
                                peer, e
                            );
                        }
                    }
                    Err(e) => warn!(
                        "⚠️ [MAIN_VRF_SYNC] Failed to serialize VRF round sync response: {}",
                        e
                    ),
                }
            }
            GossipsubMessage::MainSequencerVrfRoundSyncResponse(sync_response) => {
                let peer = sync_response.from.0;
                let reference_round = self
                    .get_local_vrf_round_for_domain(
                        VrfDomain::MainSequencer,
                        Some(&sync_response.context),
                    )
                    .await;

                if self.store_peer_round_if_valid(
                    VrfDomain::MainSequencer,
                    &sync_response.context,
                    peer,
                    reference_round,
                    sync_response.current_round,
                ) {
                    info!(
                        "💾 [MAIN_VRF_SYNC] Stored round {:?} for peer {} from response",
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
                intent_hash,
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
                if let Some(hash) = &intent_hash {
                    info!("🔗 [NETWORK] Intent hash: {}", hash);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hash or solver address supplied with transaction ID broadcast");
                }

                // Send acknowledgment for critical message
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
                    &GossipsubMessage::TransactionIdBroadcast {
                        intent_hash: intent_hash.clone(),
                        transaction_id: transaction_id.clone(),
                        transaction_type: transaction_type.clone(),
                        solver_address: solver_address.clone(),
                        node_id: node_id.clone(),
                    },
                )
                .await;

                // Process using shared handler
                match (intent_hash.as_ref(), solver_address.as_ref()) {
                    (Some(intent_hash), _) => {
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
                                "❌ [NETWORK] Failed to handle transaction ID storage: {}",
                                e
                            );
                        }
                    }
                    (None, Some(solver_addr)) => {
                        let storage_result = match transaction_type.as_str() {
                            "reward_txn" => {
                                self.handle_reward_transaction_id_storage(
                                    solver_addr,
                                    &transaction_id,
                                    &transaction_type,
                                )
                                .await
                            }
                            "withdraw_liquidity" | "withdrawLiquidity" => {
                                self.handle_withdraw_liquidity_transaction_id_storage(
                                    solver_addr,
                                    &transaction_id,
                                    &transaction_type,
                                )
                                .await
                            }
                            _ => {
                                warn!(
                                    "❌ [NETWORK] Unknown transaction type: {}",
                                    transaction_type
                                );
                                return Err(anyhow!(
                                    "Unknown transaction type: {}",
                                    transaction_type
                                ));
                            }
                        };

                        if let Err(e) = storage_result {
                            error!(
                                "❌ [NETWORK] Failed to handle transaction ID storage: {}",
                                e
                            );
                        }
                    }
                    _ => {
                        warn!("⚠️ [NETWORK] Transaction ID broadcast missing both intent hash and solver address");
                    }
                }
            }
            GossipsubMessage::TransactionErrorBroadcast {
                intent_hash,
                error_message,
                transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction error broadcast from node {}",
                    node_id
                );
                if let Some(hash) = &intent_hash {
                    info!("🔗 [NETWORK] Intent hash: {}", hash);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hash or solver address supplied with transaction error broadcast");
                }

                // Store the error message in our local user registry
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    match (intent_hash.as_ref(), solver_address.as_ref()) {
                        (Some(intent_hash), _) => {
                            // Regular transaction error - store with intent hash
                            match user_intent_manager
                                .store_transaction_error(
                                    intent_hash,
                                    &error_message,
                                    Some(&node_id),
                                )
                                .await
                            {
                                Ok(()) => {
                                }
                                Err(e) => {
                                    error!(
                                        "❌ [NETWORK] Failed to store synchronized transaction error: {}",
                                        e
                                    );
                                }
                            }
                        }
                        (None, Some(solver_addr)) => {
                            // Reward transaction error - just log for now
                            // The user_intent_manager might need a method to store reward transaction errors
                        }
                        _ => {
                            warn!("⚠️ [NETWORK] Transaction error broadcast missing both intent hash and solver address");
                        }
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction error");
                }
            }
            GossipsubMessage::IntentHashBroadcast {
                intent_hash,
                node_id,
            } => {
                info!(
                    "📨 [GOSSIPSUB] Received intent hash broadcast {} from node {}",
                    intent_hash, node_id
                );
            }
            GossipsubMessage::IntentHash {
                intent_hash,
                signer,
                intent,
            } => {
                info!(
                    "📝 [GOSSIPSUB] Received intent hash {} from {}",
                    intent_hash, signer
                );

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    match hex::decode(&intent_hash) {
                        Ok(bytes) => {
                            if let Err(e) = user_intent_manager
                                .store_intent_hash(bytes, &signer, &intent)
                                .await
                            {
                                warn!("❌ [GOSSIPSUB] Failed to store intent hash: {}", e);
                            } else {
                            }
                        }
                        Err(e) => {
                            warn!("❌ [GOSSIPSUB] Invalid intent hash {}: {}", intent_hash, e);
                        }
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] No user registry available to store intent hash");
                }
            }
            GossipsubMessage::DepositIntent {
                intent,
                intent_id,
                user_eth_address,
                transaction_type,
                amount,
            } => {

                // CRITICAL FIX: For refund transactions, use the ORIGINAL intent_hash from intent_id
                // Refund intents have modified target_address/target_chain, so calculating hash from
                // the modified intent would produce a different hash than the original intent
                let intent_hash = if matches!(transaction_type, crate::types::TransactionType::Refund) 
                    && intent_id.starts_with("refund-") 
                {
                    // Extract original intent_hash from "refund-{original_intent_hash}"
                    let original_intent_hash = intent_id.strip_prefix("refund-").unwrap_or(&intent_id);
                    info!("🔐 [GOSSIPSUB] Refund transaction detected - using ORIGINAL intent hash: {} (from intent_id: {})", original_intent_hash, intent_id);
                    original_intent_hash.to_string()
                } else {
                    // For non-refund transactions, calculate hash from the intent
                    let calculated_hash = crate::utils::calculate_intent_hash(&intent)
                        .map_err(|e| anyhow::anyhow!("Failed to calculate intent hash: {}", e))?;
                    info!("🔐 [GOSSIPSUB] Calculated intent hash: {}", calculated_hash);
                    calculated_hash
                };

                // CRITICAL: Store the intent in database if not already stored
                // This ensures all nodes have the intent even if they missed the IntentHash broadcast
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    // Check if intent already exists
                    if user_intent_manager.get_intent(&intent_hash).await.is_none() {
                        // Decode intent_hash from hex to bytes for store_intent_hash
                        if let Ok(intent_hash_bytes) = hex::decode(&intent_hash) {
                            // Use the user_eth_address if available, otherwise use a placeholder
                            // The signer field is used for user identification
                            let signer = user_eth_address.as_ref()
                                .map(|addr| addr.clone())
                                .unwrap_or_else(|| "network".to_string());
                            
                            if let Err(e) = user_intent_manager
                                .store_intent_hash(intent_hash_bytes, &signer, &intent)
                                .await
                            {
                                warn!("❌ [GOSSIPSUB] Failed to store intent hash {}: {}", intent_hash, e);
                            } else {
                            }
                        } else {
                            warn!("❌ [GOSSIPSUB] Invalid intent hash format: {}", intent_hash);
                        }
                    } else {
                        debug!("✅ [GOSSIPSUB] Intent {} already exists in database", intent_hash);
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] User intent manager not available to store intent");
                }

                // Determine chain type based on transaction type:
                // - UserToVault: use source_chain (user is depositing FROM this chain)
                // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
                let chain_to_use = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        &intent.source_chain.to_lowercase()
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        &intent.target_chain.to_lowercase()
                    }
                    crate::types::TransactionType::Refund => {
                        &intent.source_chain.to_lowercase() // Refund goes back to source chain
                    }
                    crate::types::TransactionType::RewardTxn => {
                        // RewardTxn is not valid for intent flow
                        warn!("❌ [GOSSIPSUB] RewardTxn is not valid for deposit intent flow");
                        return Ok(());
                    }
                    crate::types::TransactionType::WithdrawLiquidity => {
                        warn!(
                            "❌ [GOSSIPSUB] WithdrawLiquidity is not valid for deposit intent flow"
                        );
                        return Ok(());
                    }
                    crate::types::TransactionType::AddLiquidity => {
                        warn!("❌ [GOSSIPSUB] AddLiquidity is not valid for deposit intent flow");
                        return Ok(());
                    }
                };

                // Get the appropriate signing key based on transaction type
                let signing_key: Option<k256::Scalar> = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        // For user deposits, use user's tweaked secret share
                        self.get_signing_key_for_user(user_eth_address.as_ref())
                            .await
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        // For network withdrawals, use network's DKG secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::Refund => {
                        // For refund transactions, use network's DKG secret share (same as NetworkToTarget)
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::RewardTxn => {
                        // RewardTxn is not valid for intent flow
                        None
                    }
                    crate::types::TransactionType::WithdrawLiquidity => {
                        warn!(
                            "❌ [GOSSIPSUB] WithdrawLiquidity is not supported for deposit intent signing"
                        );
                        None
                    }
                    crate::types::TransactionType::AddLiquidity => {
                        warn!(
                            "❌ [GOSSIPSUB] AddLiquidity is not supported for deposit intent signing"
                        );
                        None
                    }
                };

                if let Some(signing_node) = &mut self.signing_node {
                    let chain_handler: Option<Arc<dyn crate::chain_abstraction::ChainHandler>> =
                        if crate::utils::transaction::is_evm_chain(chain_to_use) {
                            crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                                .map(|chain_id| {
                                    let handler = crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(chain_id);
                                    Arc::from(handler) as Arc<dyn crate::chain_abstraction::ChainHandler>
                                })
                        } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                            let mut handler =
                                crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                                    crate::types::network::network_type()
                                        .bitcoin_network_label()
                                        .to_string(),
                                );

                            match transaction_type {
                                crate::types::TransactionType::UserToVault => {
                                    if let Some(eth_addr) = &user_eth_address {
                                        if let Some(user_intent_manager) = &self.user_intent_manager
                                        {
                                            if let Some(user) = user_intent_manager
                                                .get_user_by_address(eth_addr)
                                                .await
                                            {
                                                if let Some(user_group_key) = &user.user_group_key {
                                                    let affine_point = user_group_key.0;
                                                    let encoded_point =
                                                        k256::EncodedPoint::from(affine_point);
                                                    let compressed_bytes = encoded_point
                                                        .compress()
                                                        .to_bytes()
                                                        .to_vec();

                                                    if let Some(btc_handler) = handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                                        btc_handler.set_group_public_key(compressed_bytes);
                                                    }
                                                } else {
                                                    warn!("❌ [GOSSIPSUB] User {} has no group key for Bitcoin transaction", eth_addr);
                                                }
                                            } else {
                                                warn!("❌ [GOSSIPSUB] User {} not found for Bitcoin transaction", eth_addr);
                                            }
                                        } else {
                                            warn!("❌ [GOSSIPSUB] User registry not available for Bitcoin transaction");
                                        }
                                    } else {
                                        warn!("❌ [GOSSIPSUB] UserToVault transaction requires user_eth_address");
                                    }
                                }
                                crate::types::TransactionType::NetworkToTarget
                                | crate::types::TransactionType::Refund => {
                                    // Refund uses network DKG group key (same as NetworkToTarget)
                                    if let Some(dkg_node) = &self.dkg_node {
                                        if let Some(group_key) =
                                            dkg_node.get_final_public_key().await
                                        {
                                            let affine_point = group_key.to_affine();
                                            let encoded_point =
                                                k256::EncodedPoint::from(affine_point);
                                            let compressed_bytes =
                                                encoded_point.compress().to_bytes().to_vec();

                                            if let Some(btc_handler) = handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                                btc_handler.set_group_public_key(compressed_bytes);
                                                info!("🔑 [GOSSIPSUB] Set network DKG group public key in Bitcoin chain handler");
                                            }
                                        }
                                    }
                                }
                                crate::types::TransactionType::RewardTxn => {}
                                crate::types::TransactionType::WithdrawLiquidity => {
                                    warn!("❌ [GOSSIPSUB] WithdrawLiquidity is not supported for Bitcoin deposit handling");
                                }
                                crate::types::TransactionType::AddLiquidity => {
                                    warn!("❌ [GOSSIPSUB] AddLiquidity is not supported for Bitcoin deposit handling");
                                }
                            }

                            Some(Arc::from(handler)
                                as Arc<dyn crate::chain_abstraction::ChainHandler>)
                        } else {
                            error!(
                                "❌ [GOSSIPSUB] Unsupported chain requested: {}",
                                chain_to_use
                            );
                            None
                        };

                    let Some(chain_handler) = chain_handler else {
                        return Err(anyhow!("Unsupported chain: {}", chain_to_use));
                    };
                    // Get derived addresses based on transaction type
                    let (derived_eth_addr, derived_btc_addr) = match transaction_type {
                        crate::types::TransactionType::UserToVault => {
                            // For user deposits, use user's derived addresses
                            if let Some(eth_addr) = &user_eth_address {
                                if let Some(user_intent_manager) = &self.user_intent_manager {
                                    if let Some(user) =
                                        user_intent_manager.get_user_by_address(eth_addr).await
                                    {
                                        (
                                            user.derived_eth_address.clone(),
                                            user.derived_btc_address.clone(),
                                        )
                                    } else {
                                        warn!(
                                            "❌ [GOSSIPSUB] User {} not found in registry",
                                            eth_addr
                                        );
                                        (None, None)
                                    }
                                } else {
                                    warn!("❌ [GOSSIPSUB] User registry not available");
                                    (None, None)
                                }
                            } else {
                                warn!("❌ [GOSSIPSUB] UserToVault transaction requires user_eth_address");
                                (None, None)
                            }
                        }
                        crate::types::TransactionType::NetworkToTarget
                        | crate::types::TransactionType::Refund => {
                            // For network withdrawals and refunds, no derived addresses needed
                            (None, None)
                        }
                        crate::types::TransactionType::RewardTxn => {
                            // RewardTxn is not valid for intent flow
                            (None, None)
                        }
                        crate::types::TransactionType::WithdrawLiquidity => {
                            warn!(
                                "❌ [GOSSIPSUB] WithdrawLiquidity transaction type not supported for derived addresses"
                            );
                            (None, None)
                        }
                        crate::types::TransactionType::AddLiquidity => {
                            warn!(
                                "❌ [GOSSIPSUB] AddLiquidity transaction type not supported for derived addresses"
                            );
                            (None, None)
                        }
                    };

                    let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_public_key().await
                    } else {
                        None
                    };

                    // Get vault addresses from database
                    let (vault_eth_addr, vault_btc_addr) =
                        if let Some(registry) = &self.user_intent_manager {
                            let database = registry.get_database();
                            let vault_eth = database
                                .get_string(crate::database::keys::DKG_VAULT_ETH_ADDRESS)
                                .ok()
                                .flatten();
                            let vault_btc = database
                                .get_string(crate::database::keys::DKG_VAULT_BTC_ADDRESS)
                                .ok()
                                .flatten();
                            (vault_eth, vault_btc)
                        } else {
                            return Err(anyhow::anyhow!("User registry not available"));
                        };

                    let chain_transaction_result =
                        crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                            &intent,
                            group_public_key,
                            derived_eth_addr.as_ref(),
                            derived_btc_addr.as_ref(),
                            transaction_type.clone(),
                            vault_eth_addr.as_ref(),
                            vault_btc_addr.as_ref(),
                            amount,
                        )
                        .await;

                    match chain_transaction_result {
                        Ok(chain_transaction) => {
                            info!(
                                "📝 [GOSSIPSUB] Created {} transaction from deposit intent",
                                chain_handler.chain_type()
                            );

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> =
                                self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if signing_key.is_some() {
                            } else {
                                info!(
                                    "❌ [GOSSIPSUB] Could not get signing key for deposit intent"
                                );
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = chain_handler
                                .create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!(
                                "🔐 [GOSSIPSUB] Starting {} signing process for deposit intent: 0x{}",
                                chain_handler.chain_type(),
                                hex::encode(tx_bytes.clone())
                            );

                            // Handle Bitcoin and EVM differently - DummyTransaction is only for EVM!
                            match chain_transaction {
                                crate::chain_abstraction::ChainTransaction::Bitcoin(ref btc_tx) => {
                                    // For Bitcoin, use direct signing with tx_bytes and original transaction
                                    {
                                        let mut btc_signer = BitcoinSigner::new(signing_node);
                                        btc_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                &chain_handler,
                                                Some(btc_tx.clone()),
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                signing_key,
                                                None,
                                                signing_key,
                                            )
                                            .await?;
                                    }
                                }
                                crate::chain_abstraction::ChainTransaction::Ethereum(
                                    ref eth_tx,
                                ) => {
                                    let tx_bytes =
                                        crate::utils::transaction::create_transaction_for_signing(
                                            eth_tx,
                                        );
                                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                                    // Use the signing_key that was already fetched earlier to avoid redundant fetching
                                    let user_tweaked_share = signing_key;

                                    // For NetworkToTarget, queue to sequencer for coordinated signing
                                    if matches!(
                                        transaction_type,
                                        crate::types::TransactionType::NetworkToTarget
                                    ) {
                                        info!(
                                            "📝 [GOSSIPSUB] NetworkToTarget (EVM) detected - queuing via network transaction sequencer (intent_hash={})",
                                            intent_hash
                                        );
                                        self.submit_network_to_target_to_sequencer(
                                            &intent,
                                            &intent_hash,
                                            amount,
                                            tx_bytes.clone(),
                                            eth_tx.clone(),
                                            user_tweaked_share,
                                            user_eth_address.clone(),
                                        )
                                        .await?;
                                        return Ok(());
                                    }

                                    {
                                        let mut eth_signer = EthereumSigner::new(signing_node);
                                        eth_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                &chain_handler,
                                                eth_tx,
                                                user_tweaked_share,
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                None,
                                                signing_key,
                                            )
                                            .await?;
                                    }
                                }
                            }
                            info!(
                                "✅ [GOSSIPSUB] {} deposit intent signing completed",
                                signing_node.get_chain_type()
                            );
                        }
                        Err(e) => {
                            warn!("❌ [GOSSIPSUB] Failed to create chain transaction: {}", e);
                            return Ok(());
                        }
                    }
                } else {
                    warn!(
                        "❌ [GOSSIPSUB] Signing node not available for deposit intent processing"
                    );
                }
            }
            GossipsubMessage::ClaimReward {
                solver_address,
                btc_address,
                eth_address,
                reward_btc,
                reward_tics,
                transaction_type,
            } => {
                info!(
                    "🎁 [GOSSIPSUB] Processing claim reward received via gossipsub for solver: {}",
                    solver_address
                );
                info!(
                    "💰 [GOSSIPSUB] Reward details - BTC: {:?}, TICS: {:?}",
                    reward_btc, reward_tics
                );
                info!(
                    "📍 [GOSSIPSUB] Addresses - ETH: {:?}, BTC: {:?}",
                    eth_address, btc_address
                );

                let _ = self
                    .process_payout(
                        "claim_reward",
                        &solver_address,
                        &btc_address,
                        &eth_address,
                        &reward_btc,
                        &reward_tics,
                    )
                    .await?;
            }
            GossipsubMessage::WithdrawLiquidity {
                solver_address,
                btc_address,
                eth_address,
                amount_btc,
                amount_tics,
                transaction_type,
            } => {
                info!(
                    "💧 [GOSSIPSUB] Received withdraw-liquidity request for solver {}",
                    solver_address
                );
                info!(
                    "💧 [GOSSIPSUB] Target addresses - ETH: {:?}, BTC: {:?}",
                    eth_address, btc_address
                );
                info!(
                    "💧 [GOSSIPSUB] Amounts - BTC: {:?}, TICS: {:?}",
                    amount_btc, amount_tics
                );

                let (tics_payout_initiated, btc_payout_initiated) = self
                    .process_payout(
                        "withdraw_liquidity",
                        &solver_address,
                        &btc_address,
                        &eth_address,
                        &amount_btc,
                        &amount_tics,
                    )
                    .await?;

                // Apply the liquidity decrease locally only when the payout was actually initiated
                if let Some(signing_node) = &self.signing_node {
                    let delta_btc = if btc_payout_initiated {
                        amount_btc
                            .as_ref()
                            .and_then(|v| ethers::types::U256::from_dec_str(v).ok())
                    } else {
                        None
                    };
                    let delta_tics = if tics_payout_initiated {
                        amount_tics
                            .as_ref()
                            .and_then(|v| ethers::types::U256::from_dec_str(v).ok())
                    } else {
                        None
                    };

                    if delta_btc.is_some() || delta_tics.is_some() {
                        match signing_node
                            .apply_liquidity_delta(
                                &solver_address,
                                None,
                                delta_btc,
                                delta_tics,
                                false,
                            )
                            .await
                        {
                            Ok(()) => {
                                info!(
                                    "✅ [GOSSIPSUB] Applied local liquidity withdraw for {}",
                                    solver_address
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "⚠️ [GOSSIPSUB] Failed to apply local liquidity withdraw for {}: {}",
                                    solver_address, e
                                );
                            }
                        }
                    } else {
                        info!(
                            "⏭️ [GOSSIPSUB] Skipping local liquidity withdraw for {} because payout was not initiated",
                            solver_address
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [GOSSIPSUB] Signing node unavailable; cannot apply local liquidity withdraw for {}",
                        solver_address
                    );
                }
            }
            GossipsubMessage::AddLiquidity {
                solver_address,
                solver_id,
                amount_btc,
                amount_tics,
                request_id,
            } => {
                info!(
                    "💧 [GOSSIPSUB] Received add-liquidity broadcast for solver {} (solver_id: {})",
                    solver_address, solver_id
                );
                info!(
                    "💧 [GOSSIPSUB] Amounts - BTC: {:?}, TICS: {:?}",
                    amount_btc, amount_tics
                );
                // 1) Submit / relay the add-liquidity contract call on this node (if applicable)
                self.handle_add_liquidity_contract_calls(
                    &solver_address,
                    &solver_id,
                    &amount_btc,
                    &amount_tics,
                    &request_id,
                )
                .await?;

                // 2) Apply the liquidity increase locally based on the requested amount.
                if let Some(signing_node) = &self.signing_node {
                    let delta_btc = amount_btc
                        .as_ref()
                        .and_then(|v| ethers::types::U256::from_dec_str(v).ok());
                    let delta_tics = amount_tics
                        .as_ref()
                        .and_then(|v| ethers::types::U256::from_dec_str(v).ok());
                    match signing_node
                        .apply_liquidity_delta(
                            &solver_address,
                            Some(&solver_id),
                            delta_btc,
                            delta_tics,
                            true,
                        )
                        .await
                    {
                        Ok(()) => {
                            info!(
                                "✅ [GOSSIPSUB] Applied local liquidity add for {}",
                                solver_address
                            );
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [GOSSIPSUB] Failed to apply local liquidity add for {}: {}",
                                solver_address, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [GOSSIPSUB] Signing node unavailable; cannot apply local liquidity add for {}",
                        solver_address
                    );
                }
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

                        // Update signing node threshold to match current network state
                        if let Some(signing_node) = &mut self.signing_node {
                            let new_threshold = self.node_manager.get_threshold();
                            signing_node.set_threshold(new_threshold);
                            info!("🔄 [THRESHOLD] Updated signing node threshold to {} (total nodes: {})", new_threshold, total);
                        }

                        // If initial DKG is completed, existing nodes are aware of the new node
                        // Note: The new node itself won't receive this PeerDiscovery message (gossipsub doesn't echo)
                        // The new node handles resharing in ConnectionEstablished (dialer section)
                        if let Some(dkg_node) = &mut self.dkg_node {
                            let initial_dkg_complete = dkg_node.is_initial_dkg_complete().await;

                            if initial_dkg_complete {
                                info!("🔄 [EXISTING_NODE] New peer {} joined network, will respond to share requests", peer);
                                // Existing nodes will handle the NewNodeJoined DKG message when the new node broadcasts it
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
            GossipsubMessage::NetworkTransactionSequencerSync {
                transaction_id,
                sequence,
                node_id,
                state,
            } => {
                info!(
                    "🔄 [NETWORK_SEQUENCER] Received network transaction sequencer sync: tx_id={}, sequence={}, node={}, state={}",
                    transaction_id, sequence, node_id, state
                );

                // Initialize sequencer if not already initialized (e.g., when receiving sync before submitting)
                if self.network_transaction_sequencer.is_none() {
                    let mut sequencer =
                        crate::network::sequencer::NetworkTransactionSequencer::new();
                    let total_nodes = self.node_manager.get_total_nodes();
                    let node_id = self.local_peer_id.to_string();
                    let message_tx = self.message_tx.clone();
                    sequencer.initialize(message_tx, node_id, total_nodes).await;

                    // Configure VRF + Consensus for final node selection (mirrors initialization in network/utils)
                    sequencer.set_local_peer_id(self.local_peer_id);

                    // Use isolated VRF storage for main sequencer to avoid round collisions with signing or vault
                    let main_vrf_storage = crate::database::storage::VrfStorage::new_with_prefix(
                        self.db.clone(),
                        "main_seq:",
                    );
                    let main_vrf_service =
                        crate::protocols::VrfService::new_with_storage_and_context(
                            self.local_peer_id,
                            self.message_tx.clone(),
                            main_vrf_storage,
                            "network",
                        );
                    sequencer.set_vrf_service(Arc::new(main_vrf_service));

                    // Dedicated consensus node for network sequencer final node agreement
                    sequencer.set_consensus_node(Arc::new(tokio::sync::RwLock::new(
                        crate::consensus::ConsensusNode::new(),
                    )));

                    // Seed available nodes for deterministic selection
                    let available_nodes: Vec<libp2p::PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    sequencer.update_available_nodes(available_nodes).await;
                    self.network_transaction_sequencer = Some(sequencer);
                    info!(
                        "✅ [NETWORK_SEQUENCER] Initialized sequencer on sync message receipt with {} total nodes",
                        total_nodes
                    );
                }

                if let Some(sequencer) = &self.network_transaction_sequencer {
                    sequencer
                        .handle_sync_message(transaction_id, sequence, node_id, state)
                        .await;
                } else {
                    warn!("⚠️ [NETWORK_SEQUENCER] Failed to initialize sequencer");
                }
            }
            GossipsubMessage::MainSequencerSelect {
                round,
                request_id,
                final_node_id,
                signature: _signature,
            } => {
                info!(
                    "📨 [MAIN_SEQUENCER] Received SELECT: round={}, request_id={}, from={:?}",
                    round, request_id, final_node_id
                );

                // MainSequencerSelect removed from retry - has ACK/MISSING fallback
                // No acknowledgment needed for retry mechanism

                if let Some(sequencer) = &self.network_transaction_sequencer {
                    if let Err(e) = sequencer
                        .handle_select_message(round, request_id, final_node_id)
                        .await
                    {
                        error!("❌ [MAIN_SEQUENCER] Failed to handle SELECT: {}", e);
                    }
                }
            }
            GossipsubMessage::MainSequencerAck {
                round,
                request_id,
                node_id,
            } => {
                info!(
                    "✅ [MAIN_SEQUENCER] Received ACK: round={}, request_id={}, from={:?}",
                    round, request_id, node_id
                );

                if let Some(sequencer) = &self.network_transaction_sequencer {
                    sequencer
                        .handle_select_ack(round, &request_id, node_id)
                        .await;
                }
            }
            GossipsubMessage::MainSequencerMissing {
                round,
                request_id,
                node_id,
            } => {
                warn!(
                    "⚠️ [MAIN_SEQUENCER] Received MISSING: round={}, request_id={}, from={:?}",
                    round, request_id, node_id
                );
            }
            GossipsubMessage::MainSequencerVrfSelectedNodes(broadcast_msg) => {
                info!(
                    "📥 [MAIN_SEQUENCER] Received VRF broadcast: round={}, from={:?}",
                    broadcast_msg.round, broadcast_msg.selector_node_id
                );

                let sender_peer_id = match message.source {
                    Some(pid) => pid,
                    None => {
                        warn!("🚫 [SECURITY] Rejecting MainSequencerVrfSelectedNodes broadcast: message has no source");
                        return Ok(());
                    }
                };

                // Send acknowledgment for critical message
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::MainSequencerVrfSelectedNodes,
                    &GossipsubMessage::MainSequencerVrfSelectedNodes(broadcast_msg.clone()),
                ).await;

                if let Some(sequencer) = &self.network_transaction_sequencer {
                    let round = broadcast_msg.round;
                    let total_nodes = self.node_manager.get_total_nodes();
                    let min_selections = total_nodes;

                    // Clone for async task (matches signing module pattern)
                    let sequencer_clone = sequencer.clone();
                    let broadcast_msg_clone = broadcast_msg.clone();

                    // Spawn async task to handle VRF broadcast and check consensus
                    // This avoids blocking and matches signing module's approach
                    tokio::spawn(async move {
                        // Handle VRF broadcast
                        if let Err(e) = sequencer_clone
                            .handle_vrf_broadcast(broadcast_msg_clone, sender_peer_id, total_nodes)
                            .await
                        {
                            error!("❌ [MAIN_SEQUENCER] Failed to handle VRF broadcast: {}", e);
                            return;
                        }

                        // Check if we can start consensus
                        if sequencer_clone
                            .can_start_consensus(round, min_selections)
                            .await
                        {
                            info!(
                                "🎯 [MAIN_SEQUENCER] Enough VRF selections for round {}, waiting for retries before consensus",
                                round
                            );

                            // CRITICAL FIX: Wait for VRF retries to complete before triggering consensus
                            // With aggressive VRF retries (500ms initial + up to 2s of retries),
                            // we need to ensure ALL nodes have received ALL VRF broadcasts
                            // before calculating consensus. Otherwise, nodes calculate with
                            // incomplete data and reject each other's results.
                            //
                            // Wait time calculation:
                            // - VRF_INITIAL_WAIT: 500ms
                            // - First 4 retries: 100+200+300+500 = 1100ms
                            // - Safety margin: 400ms
                            // Total: 2000ms (2 seconds)
                            tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

                            info!(
                                "✅ [MAIN_SEQUENCER] Retry period complete, triggering consensus for round {}",
                                round
                            );

                            if let Err(e) = sequencer_clone
                                .check_and_trigger_consensus(round, min_selections)
                                .await
                            {
                                error!("❌ [MAIN_SEQUENCER] Failed to trigger consensus: {}", e);
                            }
                        }
                    });
                } else {
                    warn!(
                        "⚠️ [MAIN_SEQUENCER] Received VRF broadcast but sequencer not initialized"
                    );
                }
            }
            GossipsubMessage::CriticalMessageAck {
                message_type,
                message_id,
                node_id,
            } => {
                info!(
                    "✅ [RETRY] Received ACK for message type {} (id: {}) from {}",
                    message_type, message_id, node_id
                );

                // Parse message type and create message ID
                // Note: SELECT messages removed from retry (have ACK/MISSING fallback)
                let msg_type = match message_type.as_str() {
                    "TransactionIdBroadcast" => crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
                    "MainSequencerVrfSelectedNodes" => crate::network::rpc::retry_manager::CriticalMessageType::MainSequencerVrfSelectedNodes,
                    "VrfSelectedNodes" => crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
                    // Removed: VaultSequencerSelect and MainSequencerSelect (have ACK/MISSING fallback)
                    "MainSequencerSelect" => {
                        info!("ℹ️ [RETRY] Ignoring ACK for {} - not in retry system (has ACK/MISSING fallback)", message_type);
                        return Ok(());
                    }
                    _ => {
                        warn!("⚠️ [RETRY] Unknown message type in ACK: {}", message_type);
                        return Ok(());
                    }
                };

                let message_id_obj = crate::network::rpc::retry_manager::MessageId {
                    message_type: msg_type.clone(),
                    unique_id: message_id.clone(),
                };

                info!(
                    "🔍 [RETRY] Processing ACK: type={:?}, id={}, from={}",
                    msg_type, message_id, node_id
                );

                // Record acknowledgment
                if let Some(retry_mgr) = &self.retry_manager {
                    match retry_mgr
                        .record_acknowledgment(&message_id_obj, node_id)
                        .await
                    {
                        Ok(true) => {
                            info!("🎉 [RETRY] ACK recorded - all nodes have acknowledged!");
                        }
                        Ok(false) => {
                            info!("📝 [RETRY] ACK recorded - still waiting for more nodes");
                        }
                        Err(e) => {
                            error!("❌ [RETRY] Failed to record acknowledgment: {}", e);
                            error!(
                                "❌ [RETRY] This ACK from {} for message {} was NOT recorded!",
                                node_id, message_id
                            );
                        }
                    }
                } else {
                    warn!("⚠️ [RETRY] Retry manager not available - ACK not recorded");
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
            }
            GossipsubMessage::TransactionFailure {
                sequencer_request_id,
                blockchain_tx_hash,
                error,
                original_request,
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
        info!(
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
                info!("🔑 [RETRY] Generated message ID for ACK: {:?}", id);
                id
            }
            Ok(Err(e)) => {
                error!(
                    "❌ [RETRY] CRITICAL: Failed to generate message ID for ACK: {}",
                    e
                );
                error!("❌ [RETRY] Cannot send ACK without message ID - this will cause retry failures!");
                return;
            }
            Err(_) => {
                error!(
                    "❌ [RETRY] CRITICAL: Timeout generating message ID (>{}s)",
                    gen_timeout.as_secs()
                );
                error!("❌ [RETRY] Cannot send ACK - this will cause retry failures!");
                return;
            }
        };

        let unique_id = message_id.unique_id.clone();
        let ack_msg = GossipsubMessage::CriticalMessageAck {
            message_type: format!("{:?}", msg_type),
            message_id: unique_id.clone(),
            node_id: self.local_peer_id,
        };

        info!(
            "📝 [RETRY] Created ACK message: type={:?}, id={}, from={}",
            msg_type, unique_id, self.local_peer_id
        );

        let topic = match msg_type {
            crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast => {
                crate::network::transport::types::TOPIC_TRANSACTION_ID_SYNC
            }
            crate::network::rpc::retry_manager::CriticalMessageType::MainSequencerVrfSelectedNodes => {
                crate::network::transport::types::TOPIC_MAIN_SEQUENCER_VRF
            }
            crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes => {
                crate::network::transport::types::TOPIC_VRF_SELECTION
            }
        };

        // Serialize ACK message
        let data = match serde_json::to_vec(&ack_msg) {
            Ok(d) => d,
            Err(e) => {
                error!("❌ [RETRY] Failed to serialize ACK message: {}", e);
                return;
            }
        };

        // Send ACK via broadcast channel using try_send to avoid blocking
        // If channel is full, ACK delivery is deferred - sender will retry anyway
        info!(
            "📡 [RETRY] Sending ACK to topic {} for message {:?}",
            topic, message_id
        );

        match self.message_tx.try_send(ChannelMessage::Broadcast {
            topic: topic.to_string(),
            data,
        }) {
            Ok(_) => {
                info!(
                    "✅ [RETRY] ACK sent to channel for {:?} (will be broadcast to topic {})",
                    message_id, topic
                );
                // Record successful send for monitoring
                self.channel_health.record_send_success();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!("⚠️ [RETRY] Channel full - ACK queued for later delivery");
                warn!("⚠️ [RETRY] Sender will retry anyway - no message loss");
                warn!("⚠️ [RETRY] High load detected: 11+ parallel users");
                // Channel is full but not closed - sender will retry this message
                // So the ACK will be sent again when we receive the retry
                // Record for monitoring
                self.channel_health.record_send_full();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                error!("❌ [RETRY] CRITICAL: Channel closed - cannot send ACK!");
                error!(
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
