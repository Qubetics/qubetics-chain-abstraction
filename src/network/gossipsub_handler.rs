/// Gossipsub message handler
/// Handles all gossipsub message types: DKG, Signing, Command, Consensus, VRF, etc.
///
/// NOTE: This module contains the gossipsub message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~2038-3559 of the original file
use anyhow::Result;
use ff::PrimeField;
use libp2p::{gossipsub::Message, PeerId};
use tracing::{debug, error, info, warn};

use crate::{
    database::key_utils,
    types::{rpc::RPCRequest, signing::SigningMessage, GossipsubMessage},
    user_intent_manager::TransactionStatus,
};

use super::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Main gossipsub message handler - delegates to specific message type handlers
    pub(crate) async fn handle_gossipsub_message(&mut self, message: &Message) -> Result<()> {
        info!(
            "i am at handle_gossipsub_message ---------- {:?}",
            message.topic
        );

        // Better error handling for message deserialization
        let msg = match serde_json::from_slice::<GossipsubMessage>(&message.data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to deserialize gossipsub message: {:?}", e);
                warn!("Message data: {:?}", String::from_utf8_lossy(&message.data));
                return Ok(()); // Continue processing other messages
            }
        };

        info!("[GMSG] {:?}", msg);
        match msg {
            // this must be used by broadcast in dkg (sending end)
            // so, here it must match on the recieving end
            GossipsubMessage::DKG(dkg_msg) => {
                // Check if this is a NodeDisconnected message - handle it specially
                if let crate::threshold_dkg::DKGMessage::NodeDisconnected {
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
                info!(
                    "📥 [NETWORK] Received signing message on topic: {}",
                    message.topic
                );
                info!("📋 [NETWORK] Signing message type: {:?}", signing_msg);

                if let Some(signing_node) = &mut self.signing_node {
                    // 🛡️ Error recovery for signing message processing - prevent node crashes
                    let signing_result = if message.topic.to_string() == "signatures-to-final-node"
                    {
                        info!("🎯 [NETWORK] Processing signature for final node topic");
                        match signing_msg {
                            SigningMessage::ECDSASignature {
                                from,
                                signature,
                                round,
                                timestamp: _timestamp,
                                user_eth_address,
                            } => {
                                info!("📤 [NETWORK] Routing ECDSA signature to final node handler from: {} for round: {} (user_eth_address: {:?})", from, round, user_eth_address);
                                signing_node
                                    .handle_signature_to_final_node(from, signature, round)
                                    .await
                            }
                            SigningMessage::BtcSignaturesMessage {
                                from,
                                signatures,
                                round,
                                timestamp: _timestamp,
                                user_eth_address,
                            } => {
                                info!("📤 [NETWORK] Routing BTC signatures to final node handler from: {} for round: {} (user_eth_address: {:?})", from, round, user_eth_address);
                                // You may want to implement a similar handler for BTC signatures in signing_node
                                // For now, just call the generic handler
                                signing_node
                                    .handle_btc_signatures_to_final_node(from, signatures, round)
                                    .await
                            }
                            _ => {
                                info!(
                                    "📤 [NETWORK] Routing other signing message to normal handler"
                                );
                                // Handle other signing messages normally
                                signing_node.handle_message(signing_msg).await
                            }
                        }
                    } else {
                        info!(
                            "📤 [NETWORK] Processing normal signing message on topic: {}",
                            message.topic
                        );
                        // Handle normal signing messages
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
                            _ => {
                                info!("📥 [NETWORK] Received other signing message type");
                            }
                        }
                        signing_node.handle_message(signing_msg).await
                    };

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
                if let Some(cmd_processor) = &mut self.command_processor {
                    cmd_processor.handle_message(cmd).await?;
                }
            }
            GossipsubMessage::Consensus(consensus_msg) => {
                info!(
                    "📥 [CONSENSUS] Received consensus message: {:?}",
                    consensus_msg
                );

                // Handle consensus message in signing node
                if let Some(signing_node) = &mut self.signing_node {
                    signing_node
                        .handle_consensus_message(consensus_msg.clone())
                        .await?;
                }

                // Also handle in standalone consensus node if available
                if let Some(consensus_node) = &mut self.consensus_node {
                    consensus_node.handle_message(consensus_msg).await?;
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
                    info!("Received VRF selection message: {:?}", vrf_msg);
                } else {
                    info!(
                        "Received VRF selection message but node manager is not VRF-based: {:?}",
                        vrf_msg
                    );
                }
            }
            GossipsubMessage::VrfSelectedNodes(broadcast_msg) => {
                info!(
                    "📥 [VRF] Received VRF selected nodes broadcast: {:?}",
                    broadcast_msg
                );

                // Store the received VRF selection in the signing node's VRF selector
                if let Some(signing_node) = &mut self.signing_node {
                    let selector_node_id = broadcast_msg.selector_node_id.clone();
                    let round = broadcast_msg.round;
                    signing_node.handle_vrf_selected_nodes_broadcast(
                        self.node_manager.get_total_nodes(),
                        broadcast_msg,
                    );
                    info!(
                        "💾 [VRF] Stored VRF selected nodes from node {} for round {}",
                        selector_node_id.0, round
                    );
                }
            }
            GossipsubMessage::DKGCommand(dkg_cmd) => {
                info!("🚀 Received DKG command via gossipsub: {:?}", dkg_cmd);
                match dkg_cmd {
                    RPCRequest::StartADKG => {
                        if let Some(dkg_node) = &mut self.dkg_node {
                            info!("🚀 Starting DKG in response to gossipsub command");
                            if let Err(e) = dkg_node.start_dkg(self.node_manager.clone()).await {
                                warn!("❌ Failed to start DKG from gossipsub command: {:?}", e);
                            }
                        } else {
                            warn!("❌ DKG node not initialized for gossipsub command");
                        }
                    }
                    _ => {
                        info!("📋 Received other DKG command: {:?}", dkg_cmd);
                    }
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
                                                info!("🔑 [GOSSIPSUB] Stored user-specific group key and derived addresses for {}", ethereum_address);
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
                info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);
                if let Some(hash) = &intent_hash {
                    info!("🔗 [NETWORK] Intent hash: {}", hash);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hash or solver address supplied with transaction ID broadcast");
                }

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    match (intent_hash.as_ref(), solver_address.as_ref()) {
                        (Some(intent_hash), _) => {
                            let storage_result = match transaction_type.as_str() {
                                "user_to_vault" => {
                                    if let Some(signing_node) = &self.signing_node {
                                        if let Err(e) = signing_node
                                            .update_solver_amounts_for_user_to_vault(
                                                intent_hash.as_str(),
                                            )
                                            .await
                                        {
                                            warn!("⚠️ [SIGNING] Failed to update solver amounts for UserToVault transaction: {}", e);
                                        } else if let Err(e) = signing_node
                                            .calculate_reward_per_solver(intent_hash.as_str())
                                            .await
                                        {
                                            warn!("⚠️ [SIGNING] Failed to calculate rewards for UserToVault transaction: {}", e);
                                        } else {
                                            info!(
                                                "✅ [SIGNING] Successfully calculated rewards for UserToVault transaction: {}",
                                                intent_hash
                                            );
                                        }
                                    }
                                    user_intent_manager
                                        .store_user_to_vault_tx_id(
                                            intent_hash,
                                            transaction_id.as_str(),
                                            Some(&node_id),
                                        )
                                        .await
                                }
                                "network_to_target" => {
                                    user_intent_manager
                                        .store_network_to_target_tx_id(
                                            intent_hash,
                                            transaction_id.as_str(),
                                            Some(&node_id),
                                        )
                                        .await
                                }
                                "vault_to_network" => {
                                    user_intent_manager
                                        .store_vault_to_network_tx_id(
                                            intent_hash,
                                            transaction_id.as_str(),
                                            Some(&node_id),
                                        )
                                        .await
                                }
                                _ => {
                                    warn!(
                                        "❌ [NETWORK] Unknown transaction type: {}",
                                        transaction_type
                                    );
                                    return Ok(());
                                }
                            };

                            match storage_result {
                                Ok(()) => {
                                    if let Err(e) = user_intent_manager
                                        .store_transaction_status(
                                            &transaction_id,
                                            TransactionStatus::Pending,
                                        )
                                        .await
                                    {
                                        error!(
                                            "❌ [NETWORK] Failed to store transaction status for broadcast tx {}: {}",
                                            transaction_id, e
                                        );
                                    }
                                    info!(
                                        "✅ [NETWORK] Successfully synchronized transaction ID {} for intent {} (type: {})",
                                        transaction_id, intent_hash, transaction_type
                                    );

                                    if let Some(user_intent_manager) = &self.user_intent_manager {
                                        if let Some(intent) =
                                            user_intent_manager.get_intent(intent_hash).await
                                        {
                                            let tx_type_enum = match transaction_type.as_str() {
                                                "user_to_vault" => {
                                                    crate::types::TransactionType::UserToVault
                                                }
                                                "network_to_target" => {
                                                    crate::types::TransactionType::NetworkToTarget
                                                }
                                                "vault_to_network" => {
                                                    crate::types::TransactionType::VaultToNetwork
                                                }
                                                _ => {
                                                    warn!("❌ [CONTRACT] Unknown transaction type for contract call: {}", transaction_type);
                                                    return Ok(());
                                                }
                                            };

                                            let vault_group_key =
                                                if let Some(dkg_node) = &self.dkg_node {
                                                    dkg_node.get_vault_group_key().await
                                                } else {
                                                    None
                                                };

                                            if let Some(vault_group_key) = vault_group_key {
                                                if let Err(e) = self
                                                    .execute_contract_call_for_transaction(
                                                        &intent,
                                                        intent_hash,
                                                        tx_type_enum,
                                                        &transaction_id,
                                                        Some(vault_group_key),
                                                        intent.amount,
                                                    )
                                                    .await
                                                {
                                                    warn!(
                                                        "❌ [CONTRACT] Failed to execute contract call for transaction ID {}: {}",
                                                        transaction_id, e
                                                    );
                                                } else {
                                                    info!(
                                                        "✅ [CONTRACT] Successfully executed contract call for transaction ID {}",
                                                        transaction_id
                                                    );
                                                }
                                            } else {
                                                warn!("❌ [CONTRACT] No vault group key available for contract call execution");
                                            }
                                        } else {
                                            warn!(
                                                "❌ [CONTRACT] Could not retrieve intent {} for contract call execution",
                                                intent_hash
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("❌ [NETWORK] Failed to store synchronized transaction ID: {}", e);
                                }
                            }
                        }
                        (None, Some(solver_addr)) => {
                            let storage_result = match transaction_type.as_str() {
                                "tics_reward" => user_intent_manager
                                    .add_solver_tics_txn_hash(solver_addr, transaction_id.clone())
                                    .await
                                    .map_err(|e| e.to_string()),
                                "btc_reward" => user_intent_manager
                                    .add_solver_btc_txn_hash(solver_addr, transaction_id.clone())
                                    .await
                                    .map_err(|e| e.to_string()),
                                _ => {
                                    warn!(
                                        "❌ [NETWORK] Unknown reward transaction type: {}",
                                        transaction_type
                                    );
                                    return Ok(());
                                }
                            };

                            match storage_result {
                                Ok(()) => {
                                    if let Err(e) = user_intent_manager
                                        .store_transaction_status(
                                            &transaction_id,
                                            TransactionStatus::Pending,
                                        )
                                        .await
                                    {
                                        error!(
                                            "❌ [NETWORK] Failed to store transaction status for reward tx {}: {}",
                                            transaction_id, e
                                        );
                                    }
                                    info!(
                                        "✅ [NETWORK] Successfully synchronized reward transaction ID {} for solver {} (type: {})",
                                        transaction_id, solver_addr, transaction_type
                                    );

                                    // Handle reward transaction success - update claimed amounts and reduce rewards
                                    // Get the current reward amount and reduce it to 0 (since claim_reward claims all available rewards)
                                    let (currency, current_reward) =
                                        if transaction_type == "tics_reward" {
                                            (
                                                "tics",
                                                user_intent_manager
                                                    .get_solver_reward_tics(solver_addr)
                                                    .await
                                                    .unwrap_or_else(|| ethers::types::U256::zero()),
                                            )
                                        } else {
                                            (
                                                "btc",
                                                user_intent_manager
                                                    .get_solver_reward_btc(solver_addr)
                                                    .await
                                                    .unwrap_or_else(|| ethers::types::U256::zero()),
                                            )
                                        };

                                    if current_reward > ethers::types::U256::zero() {
                                        // Get current claimed amount
                                        let current_claimed = user_intent_manager
                                            .get_solver_claimed_request_amount(solver_addr)
                                            .await
                                            .unwrap_or_else(|| ethers::types::U256::zero());

                                        // Update claimed amount
                                        let new_claimed = current_claimed + current_reward;
                                        if let Err(e) = user_intent_manager
                                            .set_solver_claimed_request_amount(
                                                solver_addr,
                                                new_claimed,
                                            )
                                            .await
                                        {
                                            error!("❌ [NETWORK-REWARD] Failed to update claimed amount for solver {}: {}", solver_addr, e);
                                        } else {
                                            info!("✅ [NETWORK-REWARD] Updated claimed amount for solver {}: {} (was: {})", solver_addr, new_claimed, current_claimed);
                                        }

                                        // Set reward to 0 (all rewards claimed)
                                        let result = if currency == "tics" {
                                            user_intent_manager
                                                .set_solver_reward_tics(
                                                    solver_addr,
                                                    ethers::types::U256::zero(),
                                                )
                                                .await
                                        } else {
                                            user_intent_manager
                                                .set_solver_reward_btc(
                                                    solver_addr,
                                                    ethers::types::U256::zero(),
                                                )
                                                .await
                                        };

                                        match result {
                                            Ok(()) => {
                                                info!("✅ [NETWORK-REWARD] Successfully processed {} reward transaction {} for solver {}: claimed={}, remaining_reward=0", 
                                                      currency, transaction_id, solver_addr, new_claimed);
                                            }
                                            Err(e) => {
                                                error!("❌ [NETWORK-REWARD] Failed to reduce {} reward for solver {}: {}", currency, solver_addr, e);
                                            }
                                        }
                                    } else {
                                        info!("ℹ️ [NETWORK-REWARD] No {} reward to claim for solver {} (already claimed or zero)", currency, solver_addr);
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "❌ [NETWORK] Failed to store synchronized reward transaction ID for solver {}: {}",
                                        solver_addr, e
                                    );
                                }
                            }
                        }
                        _ => {
                            warn!("⚠️ [NETWORK] Transaction ID broadcast missing both intent hash and solver address");
                        }
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store synchronized transaction ID");
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
                info!("💥 [NETWORK] Error message: {}", error_message);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);
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
                                    info!("✅ [NETWORK] Successfully synchronized transaction error for intent {}: {}", intent_hash, error_message);
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
                            info!("✅ [NETWORK] Successfully synchronized reward transaction error for solver {}: {}", solver_addr, error_message);
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
                                info!("✅ [GOSSIPSUB] Stored intent hash from {}", signer);
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
                info!("📝 [GOSSIPSUB] Processing deposit intent received via gossipsub: {:?} (ID: {})", intent, intent_id);

                // Calculate intent hash for transaction ID storage
                let intent_hash = crate::utils::calculate_intent_hash(&intent);
                info!("🔐 [GOSSIPSUB] Calculated intent hash: {}", intent_hash);

                // Determine chain type based on transaction type:
                // - UserToVault: use source_chain (user is depositing FROM this chain)
                // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
                // - VaultToNetwork: use source_chain (vault is sending back to network on source chain)
                let chain_to_use = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        &intent.source_chain.to_lowercase()
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        &intent.target_chain.to_lowercase()
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        &intent.source_chain.to_lowercase()
                    }
                };
                info!("🔗 [GOSSIPSUB] Processing deposit intent for chain: {} (transaction_type: {:?})",
                      chain_to_use, transaction_type);

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
                    crate::types::TransactionType::VaultToNetwork => {
                        // For vault-to-network, use vault's tweaked secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_vault_tweaked_secret_share().await
                        } else {
                            None
                        }
                    }
                };

                if let Some(signing_node) = &mut self.signing_node {
                    // Set appropriate chain handler based on the determined chain
                    if crate::utils::transaction::is_evm_chain(chain_to_use) {
                        if let Some(chain_id) =
                            crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                        {
                            let chain_handler =
                                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                                    chain_id,
                                );
                            signing_node.set_chain_handler(chain_handler.into());
                            info!(
                                "🔗 [GOSSIPSUB] Set Ethereum chain handler for chain: {} (ID: {})",
                                chain_to_use, chain_id
                            );
                        }
                    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                        let mut chain_handler =
                            crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                                "testnet".to_string(),
                            );

                        // Set appropriate group public key in Bitcoin chain handler based on transaction type
                        match transaction_type {
                            crate::types::TransactionType::UserToVault => {
                                // For user deposits, use user's specific group key
                                if let Some(eth_addr) = &user_eth_address {
                                    if let Some(user_intent_manager) = &self.user_intent_manager {
                                        if let Some(user) =
                                            user_intent_manager.get_user_by_address(eth_addr).await
                                        {
                                            if let Some(user_group_key) = &user.user_group_key {
                                                let affine_point = user_group_key.0; // user_group_key is SerializablePoint(AffinePoint)
                                                let encoded_point =
                                                    k256::EncodedPoint::from(affine_point);
                                                let compressed_bytes =
                                                    encoded_point.compress().to_bytes().to_vec();

                                                if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                                    btc_handler.set_group_public_key(compressed_bytes);
                                                    info!("🔑 [GOSSIPSUB] Set user-specific group public key in Bitcoin chain handler for user: {}", eth_addr);
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
                            crate::types::TransactionType::NetworkToTarget => {
                                // For network withdrawals, use network's DKG group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                                        let affine_point = group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler
                                            .as_any_mut()
                                            .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                                        ) {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [GOSSIPSUB] Set network DKG group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                            crate::types::TransactionType::VaultToNetwork => {
                                // For vault-to-network, use vault's group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(vault_group_key) =
                                        dkg_node.get_vault_group_key().await
                                    {
                                        let affine_point = vault_group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler
                                            .as_any_mut()
                                            .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                                        ) {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [GOSSIPSUB] Set vault group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                        }

                        signing_node.set_chain_handler(chain_handler.into());
                        info!("🔗 [GOSSIPSUB] Set Bitcoin chain handler");
                    } else {
                        warn!(
                            "❌ [GOSSIPSUB] Unsupported chain: {}, using default Ethereum handler",
                            chain_to_use
                        );
                    }

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
                        | crate::types::TransactionType::VaultToNetwork => {
                            // For network withdrawals and vault-to-network, no derived addresses needed
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
                                .get_string(&crate::database::keys::DKG_VAULT_ETH_ADDRESS)
                                .ok()
                                .flatten();
                            let vault_btc = database
                                .get_string(&crate::database::keys::DKG_VAULT_BTC_ADDRESS)
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
                                signing_node.get_chain_type()
                            );

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> =
                                self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if let Some(key) = signing_key {
                                info!("🔐 [GOSSIPSUB] Got signing key for deposit intent");
                                signing_node.set_private_key_from_scalar(key);

                                // Set the appropriate group public key based on transaction type
                                match transaction_type {
                                    crate::types::TransactionType::UserToVault => {
                                        // For user deposits, use user-specific group key
                                        if let Some(eth_address) = &user_eth_address {
                                            if let Some(user_intent_manager) =
                                                &self.user_intent_manager
                                            {
                                                if let Some(user) = user_intent_manager
                                                    .get_user_by_address(eth_address)
                                                    .await
                                                {
                                                    if let Some(user_group_key) =
                                                        &user.user_group_key
                                                    {
                                                        signing_node.set_group_public_key(
                                                            user_group_key.0.into(),
                                                        ); // Convert AffinePoint to ProjectivePoint
                                                        info!("🔑 [GOSSIPSUB] Set user-specific group public key for: {}", eth_address);
                                                    } else {
                                                        warn!("❌ [GOSSIPSUB] User {} has no group key available", eth_address);
                                                        return Ok(());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::NetworkToTarget => {
                                        // For network withdrawals, use the original DKG group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(group_key) =
                                                dkg_node.get_final_public_key().await
                                            {
                                                signing_node.set_group_public_key(group_key);
                                                info!("🔑 [GOSSIPSUB] Set network DKG group public key");
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::VaultToNetwork => {
                                        // For vault-to-network, use the vault group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(vault_group_key) =
                                                dkg_node.get_vault_group_key().await
                                            {
                                                signing_node.set_vault_group_key(vault_group_key);
                                                info!("🔑 [GOSSIPSUB] Set vault group public key");
                                            }
                                        }
                                    }
                                }
                            } else {
                                info!(
                                    "❌ [GOSSIPSUB] Could not get signing key for deposit intent"
                                );
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = signing_node
                                .get_chain_handler()
                                .create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!("🔐 [GOSSIPSUB] Starting {} signing process for deposit intent: 0x{}",
                                  signing_node.get_chain_type(), hex::encode(tx_bytes.clone()));

                            // Handle Bitcoin and EVM differently - DummyTransaction is only for EVM!
                            match chain_transaction {
                                crate::chain_abstraction::ChainTransaction::Bitcoin(ref btc_tx) => {
                                    // For Bitcoin, use direct signing with tx_bytes and original transaction
                                    signing_node
                                        .sign_bitcoin_transaction(
                                            tx_bytes.clone(),
                                            Some(btc_tx.clone()),
                                            user_eth_address.clone(),
                                            Some(intent_hash.clone()),
                                            Some(transaction_type.clone()),
                                            signing_key,
                                            None,
                                        )
                                        .await?;
                                }
                                crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    let tx_bytes =
                                        crate::utils::transaction::create_transaction_for_signing(
                                            &eth_tx,
                                        );
                                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                                    let user_tweaked_share = match transaction_type {
                                        crate::types::TransactionType::UserToVault => {
                                            // For user deposits, use user's tweaked secret share
                                            if let Some(eth_addr) = &user_eth_address {
                                                if let Some(user_intent_manager) =
                                                    &self.user_intent_manager
                                                {
                                                    if let Some(user) = user_intent_manager
                                                        .get_user_by_address(eth_addr)
                                                        .await
                                                    {
                                                        user.tweaked_secret_share.map(|s| s.0)
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::NetworkToTarget => {
                                            // For network withdrawals, use network's DKG secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_final_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::VaultToNetwork => {
                                            // For vault-to-network, use vault's tweaked secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_vault_tweaked_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                    };

                                    signing_node
                                        .sign_message(
                                            tx_bytes.clone(),
                                            &eth_tx,
                                            user_tweaked_share,
                                            user_eth_address.clone(),
                                            Some(intent_hash.clone()),
                                            Some(transaction_type.clone()),
                                            None,
                                        )
                                        .await?; // // Only execute contract transaction for UserToVault transaction type
                                                 // if matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                                                 //     info!("📝 [GOSSIPSUB] UserToVault transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);

                                    //             match contract_transaction {
                                    //                 crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::types::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // } else if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget){
                                    //     info!("📝 [GOSSIPSUB] networkToTarget transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);

                                    //             match contract_transaction {
                                    //                 crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::types::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // }
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

                // Validate that at least one reward type is present
                if reward_btc.is_none() && reward_tics.is_none() {
                    warn!("❌ [GOSSIPSUB] Invalid reward claim - both BTC and TICS rewards are None for solver: {}", solver_address);
                    return Ok(());
                }

                // Process TICS rewards (Ethereum) if available
                if let Some(tics_reward_str) = reward_tics {
                    if let Some(eth_addr) = eth_address {
                        if let Ok(tics_amount) = tics_reward_str.parse::<u128>() {
                            info!(
                                "🎁 [GOSSIPSUB] Processing TICS reward: {} -> {} (amount: {})",
                                solver_address, eth_addr, tics_amount
                            );

                            // Get network address for sending rewards
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(group_key) = dkg_node.get_final_public_key().await {
                                    let network_address =
                                        crate::utils::get_eth_address_from_group_key(group_key);

                                    // Create Ethereum transaction for TICS reward
                                    match crate::utils::transaction::create_ethereum_transaction(
                                        &network_address,
                                        &eth_addr,
                                        tics_amount,
                                        "qubetics", // Use Qubetics chain for TICS
                                    )
                                    .await
                                    {
                                        Ok(eth_tx) => {
                                            info!("✅ [GOSSIPSUB] Created TICS reward transaction: {:?}", eth_tx);

                                            // Sign the transaction using MPC
                                            if let Some(signing_node) = &mut self.signing_node {
                                                // Set available nodes from node manager before signing
                                                let available_nodes: Vec<PeerId> = self
                                                    .node_manager
                                                    .get_active_nodes()
                                                    .into_iter()
                                                    .collect();
                                                signing_node.set_available_nodes(available_nodes);
                                                signing_node.set_chain_handler(crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(eth_tx.chain_id).into());

                                                if let Some(dkg_node) = &self.dkg_node {
                                                    if let Some(secret_share) =
                                                        dkg_node.get_final_secret_share().await
                                                    {
                                                        info!("🔐 [GOSSIPSUB] Got secret share from DKG for TICS reward");
                                                        signing_node.set_private_key_from_scalar(
                                                            secret_share,
                                                        );

                                                        // Set the DKG group public key
                                                        if let Some(group_key) =
                                                            dkg_node.get_final_public_key().await
                                                        {
                                                            signing_node
                                                                .set_group_public_key(group_key);
                                                            info!("🔑 [GOSSIPSUB] Set DKG group public key for TICS reward signing");
                                                        }

                                                        // Convert transaction to bytes for signing
                                                        let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&eth_tx);
                                                        info!("🔐 [GOSSIPSUB] Starting TICS reward signing process: 0x{}", hex::encode(tx_bytes.clone()));

                                                        // Sign with only necessary parameters for transaction
                                                        signing_node
                                                            .sign_message(
                                                                tx_bytes,
                                                                &eth_tx,
                                                                None,
                                                                None,
                                                                None,
                                                                None,
                                                                Some(solver_address.clone()),
                                                            )
                                                            .await?;
                                                        info!("✅ [GOSSIPSUB] TICS reward signing completed");
                                                    } else {
                                                        info!("⏳ [GOSSIPSUB] DKG not completed yet, no secret share available for TICS reward");
                                                    }
                                                } else {
                                                    info!("❌ [GOSSIPSUB] DKG node not available for TICS reward");
                                                }
                                            } else {
                                                warn!("❌ [GOSSIPSUB] Signing node not available for TICS reward");
                                            }
                                        }
                                        Err(e) => {
                                            error!("❌ [GOSSIPSUB] Failed to create TICS reward transaction: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("❌ [GOSSIPSUB] No group key available for TICS reward transaction");
                                }
                            } else {
                                warn!("❌ [GOSSIPSUB] DKG node not available for TICS reward transaction");
                            }
                        } else {
                            warn!(
                                "❌ [GOSSIPSUB] Invalid TICS reward amount: {}",
                                tics_reward_str
                            );
                        }
                    } else {
                        warn!("❌ [GOSSIPSUB] TICS reward available but no ETH address provided");
                    }
                }

                // Process BTC rewards if available
                if let Some(btc_reward_str) = reward_btc {
                    if let Some(btc_addr) = btc_address {
                        if let Ok(btc_amount) = btc_reward_str.parse::<u128>() {
                            info!(
                                "🎁 [GOSSIPSUB] Processing BTC reward: {} -> {} (amount: {})",
                                solver_address, btc_addr, btc_amount
                            );

                            // Get network BTC address for sending rewards
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(group_key) = dkg_node.get_final_public_key().await {
                                    let network_btc_address =
                                        crate::utils::get_btc_address_from_group_key(group_key);

                                    // Create Bitcoin transaction for BTC reward
                                    match crate::utils::transaction::create_bitcoin_transaction(
                                        &network_btc_address,
                                        &btc_addr,
                                        btc_amount,
                                    )
                                    .await
                                    {
                                        Ok(btc_tx) => {
                                            info!("✅ [GOSSIPSUB] Created BTC reward transaction: {:?}", btc_tx);

                                            // Sign the transaction using MPC
                                            if let Some(signing_node) = &mut self.signing_node {
                                                // Set available nodes from node manager before signing
                                                let available_nodes: Vec<PeerId> = self
                                                    .node_manager
                                                    .get_active_nodes()
                                                    .into_iter()
                                                    .collect();
                                                signing_node.set_available_nodes(available_nodes);
                                                signing_node.set_chain_handler(crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler("testnet".to_string()).into());

                                                if let Some(dkg_node) = &self.dkg_node {
                                                    if let Some(secret_share) =
                                                        dkg_node.get_final_secret_share().await
                                                    {
                                                        info!("🔐 [GOSSIPSUB] Got secret share from DKG for BTC reward");
                                                        signing_node.set_private_key_from_scalar(
                                                            secret_share,
                                                        );

                                                        // Set the DKG group public key
                                                        if let Some(group_key) =
                                                            dkg_node.get_final_public_key().await
                                                        {
                                                            signing_node
                                                                .set_group_public_key(group_key);
                                                            info!("🔑 [GOSSIPSUB] Set DKG group public key for BTC reward signing");
                                                        }
                                                        let chain_tx =
                                                            crate::chain_abstraction::ChainTransaction::Bitcoin(
                                                                btc_tx.clone(),
                                                            );
                                                        // set chain handler as btc
                                                        signing_node.set_chain_handler(crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler("testnet".to_string()).into());
                                                        let tx_bytes = signing_node
                                                            .get_chain_handler()
                                                            .create_transaction_bytes(&chain_tx)
                                                            .unwrap();
                                                        // Convert transaction to bytes for signing

                                                        // Sign with Bitcoin-specific parameters
                                                        signing_node
                                                            .sign_bitcoin_transaction(
                                                                tx_bytes.clone(),
                                                                Some(btc_tx),
                                                                None,
                                                                None,
                                                                None,
                                                                None,
                                                                Some(solver_address.clone()),
                                                            )
                                                            .await?;
                                                        info!("✅ [GOSSIPSUB] BTC reward signing completed");
                                                    } else {
                                                        info!("⏳ [GOSSIPSUB] DKG not completed yet, no secret share available for BTC reward");
                                                    }
                                                } else {
                                                    info!("❌ [GOSSIPSUB] DKG node not available for BTC reward");
                                                }
                                            } else {
                                                warn!("❌ [GOSSIPSUB] Signing node not available for BTC reward");
                                            }
                                        }
                                        Err(e) => {
                                            error!("❌ [GOSSIPSUB] Failed to create BTC reward transaction: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("❌ [GOSSIPSUB] No group key available for BTC reward transaction");
                                }
                            } else {
                                warn!("❌ [GOSSIPSUB] DKG node not available for BTC reward transaction");
                            }
                        } else {
                            warn!(
                                "❌ [GOSSIPSUB] Invalid BTC reward amount: {}",
                                btc_reward_str
                            );
                        }
                    } else {
                        warn!("❌ [GOSSIPSUB] BTC reward available but no BTC address provided");
                    }
                }

                info!(
                    "✅ [GOSSIPSUB] Reward claim processed successfully for solver: {}",
                    solver_address
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
                    info!("ℹ️ Peer {} already exists in node manager, skipping", peer);
                    return Ok(());
                }

                // If index provided, store and persist it
                if let Some(idx) = index {
                    self.peer_discovery.peer_indices.insert(peer.clone(), idx);
                    let key = key_utils::peer_index_key(&peer.to_string());
                    if let Err(e) = self.db.put_string(&key, &idx) {
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
                                info!("ℹ️ [NEW_NODE] Initial DKG not yet completed (waiting for 4 nodes)");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("❌ Failed to add peer {} to node manager: {:?}", peer, e);
                    }
                }
            }
        }
        Ok(())
    }
}
