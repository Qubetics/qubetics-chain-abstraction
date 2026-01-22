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
    rpc_server::utils::{convert_src_smallest_to_dst_smallest, fetch_crypto_prices},
    signing::{BitcoinSigner, EthereumSigner},
    types::{
        p2p::SerializablePeerId, signing::SigningMessage, vrf::VrfRoundSyncResponse,
        ChannelMessage, GossipsubMessage,
    },
};

use crate::network::transport::types::{MpcNetworkLayer, VrfDomain, TOPIC_CONSENSUS};

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
                } else if let Some(solver_addr) = solver_address.as_ref() {
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
                            return Err(anyhow!("Unknown transaction type: {}", transaction_type));
                        }
                    };

                    if let Err(e) = storage_result {
                        error!(
                            "❌ [NETWORK] Failed to handle transaction ID storage: {}",
                            e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [NETWORK] Transaction ID broadcast missing both intent hashes and solver address"
                    );
                }
            }
            GossipsubMessage::TransactionErrorBroadcast {
                intent_hash,
                error_message,
                transaction_type: _transaction_type,
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
                                Ok(()) => {}
                                Err(e) => {
                                    error!(
                                        "❌ [NETWORK] Failed to store synchronized transaction error: {}",
                                        e
                                    );
                                }
                            }
                        }
                        (None, Some(_solver_addr)) => {
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
            GossipsubMessage::DepositIntent {
                intent,
                intent_id: _intent_id,
                user_eth_address,
                amount,
            } => {
                // user_eth_address is now mandatory (not Option)
                let user_eth_addr = user_eth_address;

                // Calculate intent hash from the intent
                let intent_hash = match crate::utils::calculate_intent_hash(&intent) {
                    Ok(hash) => hash,
                    Err(e) => {
                        warn!("❌ [GOSSIPSUB] Failed to calculate intent hash: {}", e);
                        return Ok(());
                    }
                };
                info!("🔐 [GOSSIPSUB] Calculated intent hash: {}", intent_hash);

                // CRITICAL: Reject immediately if intent_hash already exists in database
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if user_intent_manager.get_intent(&intent_hash).await.is_some() {
                        warn!(
                            "⚠️ [GOSSIPSUB] Rejecting DepositIntent - intent hash {} already exists in database",
                            intent_hash
                        );
                        return Ok(());
                    }

                    // Store the intent in database
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
                } else {
                    warn!("❌ [GOSSIPSUB] User intent manager not available to store intent");
                    return Ok(());
                }

                // UserToVault: use source_chain (user is depositing FROM this chain)
                let chain_to_use = &intent.source_chain.to_lowercase();

                // For UserToVault, use user's tweaked secret share
                let signing_key: Option<k256::Scalar> =
                    self.get_signing_key_for_user(Some(&user_eth_addr)).await;

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

                            // UserToVault: set user's group public key for Bitcoin
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                if let Some(user) = user_intent_manager
                                    .get_user_by_address(&user_eth_addr)
                                    .await
                                {
                                    if let Some(user_group_key) = &user.user_group_key {
                                        let affine_point = user_group_key.0;
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                        }
                                    } else {
                                        warn!("❌ [GOSSIPSUB] User {} has no group key for Bitcoin transaction", user_eth_addr);
                                    }
                                } else {
                                    warn!(
                                        "❌ [GOSSIPSUB] User {} not found for Bitcoin transaction",
                                        user_eth_addr
                                    );
                                }
                            } else {
                                warn!("❌ [GOSSIPSUB] User registry not available for Bitcoin transaction");
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
                    // For UserToVault, use user's derived addresses
                    let (derived_eth_addr, derived_btc_addr) =
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            if let Some(user) = user_intent_manager
                                .get_user_by_address(&user_eth_addr)
                                .await
                            {
                                (
                                    user.derived_eth_address.clone(),
                                    user.derived_btc_address.clone(),
                                )
                            } else {
                                warn!(
                                    "❌ [GOSSIPSUB] User {} not found in registry",
                                    user_eth_addr
                                );
                                (None, None)
                            }
                        } else {
                            warn!("❌ [GOSSIPSUB] User registry not available");
                            (None, None)
                        };

                    let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_public_key().await
                    } else {
                        None
                    };

                    // Get liquidity operator addresses from database
                    let (liquidity_operator_eth_addr, liquidity_operator_btc_addr) =
                        if let Some(registry) = &self.user_intent_manager {
                            let database = registry.get_database();
                            let liquidity_operator_eth = database
                                .get_string(
                                    crate::database::keys::DKG_LIQUIDITY_OPERATOR_ETH_ADDRESS,
                                )
                                .ok()
                                .flatten();
                            let liquidity_operator_btc = database
                                .get_string(
                                    crate::database::keys::DKG_LIQUIDITY_OPERATOR_BTC_ADDRESS,
                                )
                                .ok()
                                .flatten();
                            (liquidity_operator_eth, liquidity_operator_btc)
                        } else {
                            return Err(anyhow::anyhow!("User registry not available"));
                        };

                    let chain_transaction_result =
                        crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                            &intent,
                            group_public_key,
                            derived_eth_addr.as_ref(),
                            derived_btc_addr.as_ref(),
                            crate::types::TransactionType::UserToVault,
                            liquidity_operator_eth_addr.as_ref(),
                            liquidity_operator_btc_addr.as_ref(),
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
                                                Some(user_eth_addr.clone()),
                                                vec![intent_hash.clone()],
                                                Some(crate::types::TransactionType::UserToVault),
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

                                    {
                                        let mut eth_signer = EthereumSigner::new(signing_node);
                                        eth_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                &chain_handler,
                                                eth_tx,
                                                user_tweaked_share,
                                                Some(user_eth_addr.clone()),
                                                vec![intent_hash.clone()],
                                                Some(crate::types::TransactionType::UserToVault),
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
                transaction_type: _transaction_type,
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
                transaction_type: _transaction_type,
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
                let msg_type = match message_type.as_str() {
                    "TransactionIdBroadcast" => crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
                    "VrfSelectedNodes" => crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
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
            GossipsubMessage::IntentBatchBroadcast {
                intent_hashes,
                batch_type,
                timestamp,
                round,
                node_id,
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

                // Log the intent hashes
                for (i, hash) in intent_hashes.iter().enumerate() {
                    info!("  📋 [BATCH] Intent {}: {}", i + 1, hash);
                }

                // SHARED: Fetch intent details from database (same for BTC and TICS)
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    let mut batch_intents = Vec::new();

                    for intent_hash in &intent_hashes {
                        if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                            batch_intents.push((intent_hash.clone(), intent));
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

                    // DIFFERENT: Process based on batch type
                    if batch_type == "BTC" {
                        info!(
                            "🪙 [BTC_BATCH] Creating Bitcoin batch transaction with {} intents",
                            batch_intents.len()
                        );

                        // Fetch prices once for all intents (TICS -> BTC conversion)
                        let prices = match fetch_crypto_prices().await {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(
                                    "❌ [BTC_BATCH] Failed to fetch crypto prices for batch conversion: {}",
                                    e
                                );
                                return Ok(());
                            }
                        };

                        // Prepare batch outputs from intents (NetworkToTarget transactions)
                        let mut batch_outputs = Vec::new();
                        for (hash, intent) in &batch_intents {
                            // Parse amount from string (source chain smallest units)
                            let amount_src = match intent.amount.parse::<u128>() {
                                Ok(amt) => amt,
                                Err(e) => {
                                    warn!(
                                        "⚠️ [BTC_BATCH] Invalid amount for intent {}: {}",
                                        hash, e
                                    );
                                    continue;
                                }
                            };

                            // Convert from source chain (typically TICS) to BTC satoshis
                            let amount_dst = match convert_src_smallest_to_dst_smallest(
                                amount_src,
                                &intent.source_chain,
                                &intent.target_chain,
                                &prices,
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!(
                                        "⚠️ [BTC_BATCH] Failed to convert amount for intent {} ({} -> {}): {:?}",
                                        hash, intent.source_chain, intent.target_chain, e
                                    );
                                    continue;
                                }
                            };

                            let amount = match u64::try_from(amount_dst) {
                                Ok(v) => v,
                                Err(_) => {
                                    warn!(
                                        "⚠️ [BTC_BATCH] Converted amount for intent {} does not fit in u64: {}",
                                        hash, amount_dst
                                    );
                                    continue;
                                }
                            };

                            // NetworkToTarget: send to target_address on target chain (Bitcoin)
                            batch_outputs.push(
                                crate::signing::chains::bitcoin_batch::BatchOutput {
                                    address: intent.target_address.clone(),
                                    amount,
                                },
                            );
                        }

                        info!(
                            "📤 [BTC_BATCH] Prepared {} batch outputs for NetworkToTarget",
                            batch_outputs.len()
                        );

                        // Get DKG group public key for Bitcoin address derivation
                        let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_public_key().await
                        } else {
                            None
                        };

                        if group_public_key.is_none() {
                            warn!("❌ [BTC_BATCH] DKG group public key not available");
                            return Ok(());
                        }

                        // Derive Bitcoin address from group public key for change
                        let group_pubkey = group_public_key.unwrap();

                        // Convert ProjectivePoint to AffinePoint then to encoded point
                        use k256::elliptic_curve::sec1::ToEncodedPoint;
                        let affine_point = k256::AffinePoint::from(group_pubkey);
                        let compressed_pubkey = affine_point.to_encoded_point(true);
                        let pubkey_bytes = compressed_pubkey.as_bytes();

                        let bitcoin_pubkey =
                            bitcoin::PublicKey::from_slice(pubkey_bytes).map_err(|e| {
                                anyhow::anyhow!("Failed to create Bitcoin PublicKey: {}", e)
                            })?;

                        let is_testnet = crate::types::network::network_type().is_testnet();
                        let network = if is_testnet {
                            bitcoin::Network::Testnet
                        } else {
                            bitcoin::Network::Bitcoin
                        };
                        let change_address =
                            bitcoin::Address::p2pkh(&bitcoin_pubkey, network).to_string();

                        // Derive canonical P2PKH script_pubkey for the change address from the pubkey
                        let signer_h160 = {
                            use sha2::Digest;
                            let sha = sha2::Sha256::digest(pubkey_bytes);
                            let rip = ripemd::Ripemd160::digest(sha);
                            let mut out = [0u8; 20];
                            out.copy_from_slice(&rip);
                            out
                        };
                        let mut change_spk: Vec<u8> = Vec::with_capacity(25);
                        change_spk.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
                        change_spk.extend_from_slice(&signer_h160);
                        change_spk.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

                        info!("🔑 [BTC_BATCH] Derived change address: {}", change_address);

                        // Create batch policy
                        let policy = crate::signing::chains::bitcoin_batch::BatchPolicy {
                            fee_rate: 1, // 1 sat/byte
                            dust_threshold: 546,
                            change_address: change_address.clone(),
                        };

                        // Fetch UTXOs from the Bitcoin UTXO helper
                        info!(
                            "🔍 [BTC_BATCH] Fetching UTXOs for address {} from Bitcoin UTXO helper",
                            change_address
                        );

                        let available_utxos = match crate::utils::transaction::fetch_bitcoin_utxos(
                            &change_address,
                            is_testnet,
                        )
                        .await
                        {
                            Ok(utxos) => utxos,
                            Err(e) => {
                                warn!("❌ [BTC_BATCH] Failed to fetch UTXOs: {}", e);
                                warn!(
                                        "⚠️ [BTC_BATCH] Cannot proceed with batch transaction without UTXOs"
                                    );
                                return Ok(());
                            }
                        };

                        if available_utxos.is_empty() {
                            warn!(
                                "⚠️ [BTC_BATCH] No UTXOs available for address {}",
                                change_address
                            );
                            warn!("⚠️ [BTC_BATCH] Cannot create batch transaction without UTXOs");
                            return Ok(());
                        }

                        info!(
                            "✅ [BTC_BATCH] Fetched {} UTXOs for batch transaction",
                            available_utxos.len()
                        );

                        // Convert generic BitcoinUtxo into BatchUtxo with a shared script_pubkey

                        let batch_utxos: Vec<crate::signing::chains::bitcoin_batch::BatchUtxo> =
                            available_utxos
                                .iter()
                                .map(|u| crate::signing::chains::bitcoin_batch::BatchUtxo {
                                    txid: u.txid.clone(),
                                    vout: u.vout,
                                    value: u.value,
                                    // All UTXOs are for the same P2PKH change address
                                    script_pubkey: change_spk.clone(),
                                })
                                .collect();

                        // 1. Select UTXOs
                        let selected =
                            match crate::signing::chains::bitcoin_batch::select_utxos_for_batch(
                                &batch_utxos,
                                &batch_outputs,
                                &policy,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("❌ [BTC_BATCH] UTXO selection failed: {}", e);
                                    return Ok(());
                                }
                            };

                        info!("✅ [BTC_BATCH] Selected {} UTXOs, total: {} sats, fee: {} sats, change: {} sats",
                            selected.utxos.len(), selected.total_input_value, selected.fee, selected.change);

                        // 2. Build unsigned transaction (bitcoin::Transaction)
                        let unsigned_tx =
                            match crate::signing::chains::bitcoin_batch::build_batch_unsigned_tx(
                                &selected,
                                &batch_outputs,
                                &policy,
                            ) {
                                Ok(tx) => tx,
                                Err(e) => {
                                    warn!(
                                        "❌ [BTC_BATCH] Failed to build unsigned transaction: {}",
                                        e
                                    );
                                    return Ok(());
                                }
                            };

                        info!(
                            "✅ [BTC_BATCH] Built unsigned transaction with {} inputs and {} outputs",
                            unsigned_tx.input.len(),
                            unsigned_tx.output.len()
                        );

                        // 3. Convert unsigned Transaction into internal BitcoinTransaction and
                        //     hand off to the existing MPC signing pipeline.
                        //
                        // This reuses the exact same BTC per-input signing, unicast distribution,
                        // and final-node aggregation logic that single Bitcoin transactions use.
                        if let Some(signing_node) = &mut self.signing_node {
                            use crate::chain_abstraction::{
                                BitcoinInput, BitcoinOutput, BitcoinTransaction,
                                BitcoinWitnessUtxo, ChainTransaction,
                            };

                            // Map inputs: selected.utxos[i] ↔ unsigned_tx.input[i]
                            let mut inputs: Vec<BitcoinInput> =
                                Vec::with_capacity(unsigned_tx.input.len());
                            for (idx, utxo) in selected.utxos.iter().enumerate() {
                                let txin = &unsigned_tx.input[idx];
                                inputs.push(BitcoinInput {
                                    txid: utxo.txid.clone(),
                                    vout: utxo.vout,
                                    script_sig: Vec::new(),
                                    // RBF sequence is already set on the bitcoin::Transaction
                                    sequence: u32::from(txin.sequence),
                                    witness_utxo: Some(BitcoinWitnessUtxo {
                                        value: utxo.value,
                                        script_pubkey: utxo.script_pubkey.clone(),
                                    }),
                                });
                            }

                            // Map outputs
                            let mut outputs: Vec<BitcoinOutput> =
                                Vec::with_capacity(unsigned_tx.output.len());
                            for out in &unsigned_tx.output {
                                outputs.push(BitcoinOutput {
                                    value: out.value.to_sat(),
                                    script_pubkey: out.script_pubkey.as_bytes().to_vec(),
                                });
                            }

                            // Internal legacy P2PKH transaction – version/lock_time are fixed in builder
                            let internal_tx = BitcoinTransaction {
                                inputs,
                                outputs,
                                version: 2,
                                lock_time: 0,
                                witness: None,
                            };

                            // Build a Bitcoin chain handler and bytes for signing
                            let mut handler =
                                crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                                    crate::types::network::network_type()
                                        .bitcoin_network_label()
                                        .to_string(),
                                );
                            let chain_handler: Arc<dyn crate::chain_abstraction::ChainHandler> =
                                Arc::from(handler);

                            let chain_tx = ChainTransaction::Bitcoin(internal_tx.clone());
                            let tx_bytes = chain_handler
                                .create_transaction_bytes(&chain_tx)
                                .unwrap_or_else(|e| {
                                    warn!(
                                        "❌ [BTC_BATCH] Failed to create transaction bytes for batch: {}",
                                        e
                                    );
                                    Vec::new()
                                });

                            // Hand off to existing MPC Bitcoin signing flow (per-input signing,
                            // storage in btc_state, later RequestBtcSignatures, unicast, and finalization)
                            {
                                let mut btc_signer = BitcoinSigner::new(signing_node);
                                btc_signer
                                    .sign_transaction(
                                        tx_bytes,
                                        &chain_handler,
                                        Some(internal_tx),
                                        None,                  // user_eth_address
                                        intent_hashes.clone(), // intent hashes (batch)
                                        Some(crate::types::TransactionType::NetworkToTarget),
                                        None, // user_tweaked_share
                                        None, // solver_address
                                        None, // signing_key_override
                                    )
                                    .await?;
                            }

                            info!(
                                "✅ [BTC_BATCH] Submitted batch transaction into MPC BTC signing flow"
                            );
                        } else {
                            warn!(
                                "❌ [BTC_BATCH] Signing node not available; cannot start MPC signing for batch"
                            );
                        }
                    } else if batch_type == "TICS" {
                        info!(
                            "💎 [TICS_BATCH] Creating TICS batch transaction with {} intents",
                            batch_intents.len()
                        );

                        // Prepare BatchIntentInput array for processBatchIntents contract call
                        let mut batch_intent_inputs = Vec::new();

                        for (intent_hash, intent) in &batch_intents {
                            let amount = match intent.amount.parse::<u128>() {
                                Ok(amt) => amt,
                                Err(e) => {
                                    warn!(
                                        "⚠️ [TICS_BATCH] Invalid amount for intent {}: {}",
                                        intent_hash, e
                                    );
                                    continue;
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
                                amount,
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

                        // Create processBatchIntents calldata
                        let batch_timestamp = chrono::Utc::now().timestamp().to_string();

                        if let Some(calldata) =
                            crate::utils::transaction::encode_process_batch_intents_calldata(
                                &batch_intent_inputs,
                                crate::types::BatchType::TICS,
                                &batch_timestamp,
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
                            if let Some(signing_node) = &mut self.signing_node {
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
                                let mut eth_signer = EthereumSigner::new(signing_node);
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
                                    )
                                    .await?;

                                info!(
                                    "✅ [TICS_BATCH] Submitted processBatchIntents contract transaction into MPC signing flow ({} intents)",
                                    intent_hashes.len()
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
