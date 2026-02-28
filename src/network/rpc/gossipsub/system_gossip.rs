use anyhow::Result;
use libp2p::{gossipsub::Message, PeerId};
use tracing::{debug, error, info, warn};
use crate::network::transport::types::{MpcNetworkLayer, VrfDomain, TOPIC_CONSENSUS};
use crate::types::*;
use crate::protocols::*;
use crate::rpc_server::utils::*;
use crate::utils::transaction::*;
use crate::signing::TicsSigner;
use crate::database::key_utils;
use crate::types::p2p::SerializablePeerId;
use crate::types::vrf::{VrfRoundSyncResponse, VrfRoundSyncRequest};
use ff::PrimeField;
use std::time::Duration;
use super::*;

impl MpcNetworkLayer {
    pub(crate) async fn handle_command(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::Command(cmd) => {
                    if let Some(cmd_processor) = self.command_processor.as_ref() {
                        cmd_processor.handle_message(cmd).await?;
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_transactionidbroadcast(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_finalnodeidbroadcast(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::FinalNodeIdBroadcast {
                    intent_hashes,
                    final_node_id,
                } => {
                    info!(
                        "📡 [NETWORK] Received final node ID broadcast from node {}",
                        final_node_id
                    );
    
                    // SECURITY FIX: Authenticate sender - verify final_node_id is a trusted/active node
                    // It should match the ID of the node sending the message.
                    let sender_peer_id = match final_node_id.parse::<libp2p::PeerId>() {
                        Ok(pid) => pid,
                        Err(e) => {
                            warn!(
                                "🚫 [SECURITY] Rejecting FinalNodeIdBroadcast: invalid final_node_id format '{}': {}",
                                final_node_id, e
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
                            "🚫 [SECURITY] Rejecting FinalNodeIdBroadcast: sender {} is not a trusted/active node",
                            final_node_id
                        );
                        return Ok(());
                    }
    
                    info!(
                        "✅ [SECURITY] FinalNodeIdBroadcast authenticated from trusted node {}",
                        final_node_id
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_transactionerrorbroadcast(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_peerinvalidationdeleted(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_peerdiscovered(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_criticalmessageack(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_transactionbroadcast(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_peerdisconnection(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_peerinvalidationbatch(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_transactionfailure(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_activepeerlist(&mut self, message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

}
