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
use serde::{Deserialize, Serialize};
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
                debug!(
                    "📥 [VRF] Received VRF selected nodes broadcast: round={}, from={}, received_by={}",
                    round, selector_node_id, local_node_id
                );

                // ALWAYS send ACK for critical messages - this is critical for retry mechanism
                // Send acknowledgment BEFORE processing to ensure it's sent even if processing fails
                debug!(
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
                        debug!(
                            "🔑 [RETRY] Generated message ID for ACK: {:?} (round={}, selector={})",
                            msg_id, round, selector_node_id
                        );
                    }
                    Err(e) => {
                        debug!(
                            "❌ [RETRY] CRITICAL: Failed to generate message ID for ACK: {}",
                            e
                        );
                        debug!("❌ [RETRY] ACK will NOT be sent - this will cause retry failures!");
                    }
                }

                // Send acknowledgment - MUST happen for all critical messages
                // This is called BEFORE processing to ensure ACK is sent even if processing fails
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
                    &GossipsubMessage::VrfSelectedNodes(broadcast_msg.clone()),
                )
                .await;
                debug!(
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
                    info!("🔗 [NETWORK] Intent hashes: {} intent(s)", intent_hashes.len());
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hashes or solver address supplied with transaction error broadcast");
                }

                // Store the error in our local user registry (one store per intent)
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if !intent_hashes.is_empty() {
                        for h in &intent_hashes {
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

                // Re-verify signature using VERIFICATION_ADDRESS before accepting into local queue.
                use crate::rpc_server::utils::{normalize_eth_signature, recover_eth_address_secp};
                let verification_address = std::env::var("VERIFICATION_ADDRESS")
                    .unwrap_or_else(|_| "".to_string());
                if verification_address.is_empty() {
                    warn!("⚠️ [ADD_LIQUIDITY] VERIFICATION_ADDRESS not configured; dropping request");
                    return Ok(());
                }

                // Validate request_id is non-empty
                if request_id.trim().is_empty() {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Empty request_id in gossip, dropping",
                    );
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

                let recovered_address =
                    match recover_eth_address_secp(msg_bytes, &compact, v, true) {
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
                debug!(
                    "✅ [RETRY] Received ACK for message type {} (id: {}) from {}",
                    message_type, message_id, node_id
                );

                // Parse message type and create message ID
                let msg_type = match message_type.as_str() {
                    "TransactionIdBroadcast" => crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
                    "VrfSelectedNodes" => crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
                    _ => {
                        debug!("⚠️ [RETRY] Unknown message type in ACK: {}", message_type);
                        return Ok(());
                    }
                };

                let message_id_obj = crate::network::rpc::retry_manager::MessageId {
                    message_type: msg_type.clone(),
                    unique_id: message_id.clone(),
                };

                debug!(
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
                            debug!("🎉 [RETRY] ACK recorded - all nodes have acknowledged!");
                        }
                        Ok(false) => {
                            debug!("📝 [RETRY] ACK recorded - still waiting for more nodes");
                        }
                        Err(e) => {
                            debug!("❌ [RETRY] Failed to record acknowledgment: {}", e);
                            debug!(
                                "❌ [RETRY] This ACK from {} for message {} was NOT recorded!",
                                node_id, message_id
                            );
                        }
                    }
                } else {
                    debug!("⚠️ [RETRY] Retry manager not available - ACK not recorded");
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
                                error!("❌ [BATCH] Failed to fetch UTXOs for network vault: {}", e);
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
                        if let Some(signing_node) = &mut self.signing_node {
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
                            let mut btc_signer = BitcoinSigner::new(signing_node);
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
            GossipsubMessage::BtcIntentManagerTxUpdate {
                intent_hashes,
                btc_txid,
                btc_batch_round,
                update_round,
                timestamp,
                node_id,
            } => {
                info!(
                    "🔄 [BTC_INTENT_MANAGER] Received BTC intent manager update batch from node {} (round {})",
                    node_id, update_round
                );
                info!(
                    "🔄 [BTC_INTENT_MANAGER] {} intents, BTC batch round: {}, BTC txid: {}",
                    intent_hashes.len(), btc_batch_round, btc_txid
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
            } => {
                info!(
                    "💧 [ADD_LIQUIDITY_BATCH] Received solver_add_liquidity batch from node {} (round {})",
                    node_id, round
                );
                info!(
                    "💧 [ADD_LIQUIDITY_BATCH] {} requests to process (will look up from RocksDB), timestamp: {}",
                    request_ids.len(), timestamp
                );

                // Process the batch - all nodes look up full details from RocksDB and participate in signing
                if let Err(e) = self
                    .handle_solver_add_liquidity_batch(
                        request_ids,
                        round,
                        timestamp,
                        node_id,
                    )
                    .await
                {
                    error!(
                        "❌ [ADD_LIQUIDITY_BATCH] Failed to handle solver add_liquidity batch: {}",
                        e
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
            crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes => {
                crate::network::transport::types::TOPIC_VRF_SELECTION
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
                debug!("⚠️ [RETRY] Channel full - ACK queued for later delivery");
                debug!("⚠️ [RETRY] Sender will retry anyway - no message loss");
                debug!("⚠️ [RETRY] High load detected: 11+ parallel users");
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
