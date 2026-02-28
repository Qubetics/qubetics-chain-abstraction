use super::*;
use crate::types::signing::SigningMessage;
use anyhow::Result;
use libp2p::PeerId;
use std::str::FromStr;
use tracing::{error, info, warn};
pub use chains::{BitcoinSigner, TicsSigner};
pub use config::{BroadcastConfig, ChainBroadcastConfig};
pub use coordination::Coordination;
pub use db_signing::DatabaseSigningNode;
pub use key::KeyStore;
pub use state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, BtcUtvAggregationState, PendingStore,
    PendingValue, RoundSlotKey, SignatureStore, SigningEnvironmentBuilder,
};
pub use nonce::{NonceGenerator, NonceManager};
use crate::protocols::VrfSelectedNodesBroadcast;
use crate::hrw;
use crate::types::{
    p2p::SerializablePeerId, ConsensusMessage, ConsensusResult, GossipsubMessage,
};

impl SigningNode {
    /// Replicate round into consensus so consensus stays aligned.
    /// Call after sync_rounds_before_signing or get_next_round.
    pub fn replicate_vrf_round_to_consensus(&mut self, round: u64) {
        self.coordination.replicate_vrf_round_to_consensus(round);
    }

    /// Initialize VrfService with network round synchronization
    /// This should be called only after the node has connected to the network
    /// and received round information from other nodes
    pub async fn initialize_vrf_service_with_network_sync(&mut self, network_round: Option<u64>) {
        let peer_id = PeerId::from_str(&self.id).unwrap_or_else(|_| PeerId::random());
        self.coordination
            .initialize_vrf_service_with_network_sync(
                peer_id,
                self.message_tx.clone(),
                network_round,
            )
            .await;
    }

    /// Sync round with network (simple approach)
    pub async fn sync_vrf_round_with_network(&mut self, network_round: u64) {
        if let Some(vrf_service) = self.coordination.vrf_service_mut() {
            vrf_service.set_current_round(network_round).await;
            info!("🔄 [SIGNING] Synced round to: {}", network_round);
        }
    }

    // Initiate a refund transaction when network-to-target broadcast fails
    /// Broadcast refund initiation message to the network
    /// This notifies other nodes that a refund transaction needs to be created
    pub(crate) async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
        self.coordination.get_available_nodes_from_manager().await
    }

    /// Handle selected nodes broadcast from another node
    pub fn handle_vrf_selected_nodes_broadcast(
        &mut self,
        total_nodes: usize,
        broadcast: VrfSelectedNodesBroadcast,
        sender_peer_id: libp2p::PeerId,
    ) {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = broadcast.round;
            let min_selections = total_nodes;

            // Use async task to handle selection broadcast
            let vrf_service_clone = vrf_service.clone();
            let mut signing_node_clone = self.clone();

            tokio::spawn(async move {
                // Handle selection broadcast via service
                if let Err(e) = vrf_service_clone
                    .handle_vrf_broadcast(broadcast, sender_peer_id, total_nodes)
                    .await
                {
                    error!("❌ [SIGNING] Failed to handle selection broadcast: {}", e);
                    return;
                }

                // Check if consensus should be triggered after receiving this broadcast
                if vrf_service_clone
                    .can_start_consensus(round, min_selections)
                    .await
                {
                    info!(
                    "🎯 [SELECTION] Enough selections collected for round {}, triggering consensus check",
                    round
                );

                    if let Err(e) = signing_node_clone
                        .check_and_trigger_consensus(round, min_selections)
                        .await
                    {
                        error!(
                            "❌ [CONSENSUS] Failed to trigger consensus for round {}: {}",
                            round, e
                        );
                    }
                }
            });
        }
    }

    /// Check and trigger consensus if ready
    pub async fn check_and_trigger_consensus(
        &mut self,
        round: u64,
        min_selections: usize,
    ) -> Result<Option<ConsensusResult>> {
        if self.can_start_consensus(round, min_selections).await {
            info!(
                "🎯 [CONSENSUS] Consensus ready for round {}, starting...",
                round
            );
            self.start_consensus_for_round(round).await
        } else {
            Ok(None)
        }
    }

    /// Start consensus for a specific round.
    /// Final node is chosen by HRW (DKG-based candidates) when dkg_storage is set; otherwise no-op.
    pub async fn start_consensus_for_round(
        &mut self,
        round: u64,
    ) -> Result<Option<ConsensusResult>> {
        let own_node_id = SerializablePeerId(PeerId::from_str(&self.id)?);

        // Extract operation_type from selection broadcast for this round (if available) for epoch mapping
        let operation_type = if let Some(vrf) = self.coordination.vrf_service() {
            vrf.create_broadcast_for_round(round)
                .await
                .and_then(|b| b.operation_type)
        } else {
            None
        };

        // Get available nodes from node_manager BEFORE borrowing consensus_node mutably.
        // node_manager is synced across all nodes via PeerDiscovered gossip,
        // NodeDisconnected broadcast, and ActivePeerList reconciliation.
        let active_nodes: std::collections::HashSet<PeerId> = self.coordination.get_available_nodes().await.into_iter().collect();

        let consensus_node = self
            .coordination
            .consensus_node_mut()
            .ok_or_else(|| anyhow::anyhow!("Consensus node not available"))?;

        // HRW path: canonical final node from DKG candidate set
        // Filter candidates to available nodes from node_manager (synced across all nodes)
        let all_selected_nodes: Vec<SerializablePeerId> = if let Some(ref dkg) = self.dkg_storage {
            let candidates = match hrw::candidates::get_hrw_candidates(dkg, Some(&active_nodes)) {
                Ok(c) if !c.is_empty() => c,
                Ok(_) => {
                    info!(
                        "⚠️ [CONSENSUS] No HRW candidates for round {} (empty DKG peer set)",
                        round
                    );
                    return Ok(None);
                }
                Err(e) => {
                    warn!(
                        "⚠️ [CONSENSUS] Failed to get HRW candidates for round {}: {}",
                        round, e
                    );
                    return Ok(None);
                }
            };
            match hrw::select_final(round, &candidates, hrw::HRW_DOMAIN_FINAL_NODE) {
                Some(winner) => {
                    info!(
                        "🎯 [CONSENSUS] HRW selected final node {} for round {} ({} candidates)",
                        winner, round, candidates.len()
                    );
                    vec![SerializablePeerId(winner)]
                }
                None => {
                    info!("⚠️ [CONSENSUS] HRW returned no winner for round {}", round);
                    return Ok(None);
                }
            }
        } else {
            info!(
                "⚠️ [CONSENSUS] No DKG storage for HRW; skipping consensus for round {}",
                round
            );
            return Ok(None);
        };

        info!(
            "🎯 [CONSENSUS] Starting consensus for round {} with final node from HRW",
            round
        );

        consensus_node.add_selected_nodes(round, all_selected_nodes);

        // Store internal operation type for this round.
        // External triggers use high-level types like "global_clock" or "btc_intent_manager_update".
        // For consensus / signing flows we normalize:
        // - "global_clock" + cycle_number % 3 => "epoch_1" / "epoch_2" / "epoch_3"
        //   (internal epochs for TICS batch, BTC batch, and withdraw settlement)
        // - other operation types are stored as-is.
        if let Some(op_type) = operation_type {
            let internal_op_type = if op_type == "global_clock" {
                let clock_interval_secs = crate::env_defaults::global_clock_interval_seconds()
                    .parse::<u64>()
                    .unwrap_or(crate::env_defaults::DEFAULT_GLOBAL_CLOCK_INTERVAL_SECONDS.parse().unwrap());

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let current_epoch_secs = now.as_secs();
                let cycle_number = current_epoch_secs / clock_interval_secs;

                // Map global clock cycles into internal epochs:
                // Signer key legend: (N) = network/main DKG key, (V) = vault/liquidity-operator key, (U) = user derived key, (A) = admin derived key
                // 0 mod 4 => epoch_1: TICS phase1 processBatchIntents (N), add_liquidity batchTransfer (V), BTC claim-reward (N), TICS UTV (U)
                // 1 mod 4 => epoch_2: BTC phase1 (N), BTC UTV (U), peer invalidation (V)
                // 2 mod 4 => epoch_3: withdraw settlement removeLiquidity (V), TICS platform fee claimPlatformFee (A)
                // 3 mod 4 => epoch_4: BTC platform fee (BTC key), TICS claim-reward claimRewardsBatch (V)
                let epoch_type = match cycle_number % 4 {
                    0 => "epoch_1".to_string(),
                    1 => "epoch_2".to_string(),
                    2 => "epoch_3".to_string(),
                    _ => "epoch_4".to_string(),
                };

                info!(
                    "⏰ [CLOCK] Normalized operation type 'global_clock' to '{}' for round {} (cycle={}, interval={}s)",
                    epoch_type, round, cycle_number, clock_interval_secs
                );

                epoch_type
            } else {
                op_type
            };

            consensus_node.set_operation_type_for_round(round, internal_op_type);
        }

        // Start consensus
        match consensus_node.start_consensus(round) {
            Ok(result) => {
                info!(
                    "✅ [CONSENSUS] Consensus completed for round {}: final node = {:?}",
                    round, result.final_node
                );

                // Broadcast the consensus result
                let consensus_msg = ConsensusMessage::FinalNodeResult {
                    result: result.clone(),
                    round,
                };

                // Wrap in GossipsubMessage::Consensus for proper deserialization
                let gossipsub_msg = GossipsubMessage::Consensus(consensus_msg);
                let broadcast_data = serde_json::to_vec(&gossipsub_msg)?;

                // Extract data before dropping consensus_node mutable borrow
                let is_final_node = consensus_node.is_final_node(round, &own_node_id);
                let operation_type = consensus_node
                    .get_operation_type_for_round(round)
                    .cloned();
                let _ = consensus_node; // Release the mutable borrow

                // Now we can safely borrow self immutably
                self.broadcast("consensus", &broadcast_data).await?;

                info!(
                    "📤 [CONSENSUS] Broadcasted consensus result for round {}",
                    round
                );

                // Store the final node for this round
                {
                    let mut final_nodes = self.signatures.final_nodes_by_round.write().await;
                    final_nodes.insert(round, result.final_node.0.to_string());
                    info!(
                        "💾 [CONSENSUS] Stored final node {} for round {}",
                        result.final_node.0, round
                    );
                }

                // Trigger parallel BTC contract update round on ALL nodes when this is a BTC epoch.
                // Internal operation type:
                // - "epoch_1" => TICS batch + add_liquidity
                // - "epoch_2" => BTC batch + BTC contract tx-id update + BTC withdraw
                // - "epoch_3" => withdraw settlement / cleanup (no new tx)
                if operation_type.as_deref() == Some("epoch_2") {
                    info!("🔄 [CLOCK] epoch_2 detected (all nodes), triggering parallel BTC contract update round...");
                    let mut signing_node_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = signing_node_clone
                            .trigger_btc_contract_update_round_parallel()
                            .await
                        {
                            error!(
                                "❌ [CLOCK] Failed to trigger BTC contract update round: {}",
                                e
                            );
                        }
                    });
                }

                // Check if this node is the final selected node
                if is_final_node {
                  // NEW: Dispatch by internal epoch operation type for this round.
                    if operation_type.as_deref() == Some("epoch_1") {
                        info!(
                            "⏰ [CLOCK] Round {} is epoch_1 (TICS batch + add_liquidity), processing phase 1 intents...",
                            round
                        );

                        // Process phase 1 intents (UserToVault done, NetworkToTarget pending) for TICS
                        if let Err(e) = self.process_phase1_intents_for_global_clock(round, "qubetics").await {
                            warn!(
                                "⚠️ [CLOCK] Failed to process phase 1 intents for round {}: {}",
                                round, e
                            );
                        }

                        // Also process pending solver_add_liquidity requests in batch
                        info!(
                            "💧 [ADD_LIQUIDITY] Processing pending add_liquidity requests for round {}...",
                            round
                        );
                        if let Err(e) =
                            self.process_solver_add_liquidity_batch_for_round(round).await
                        {
                            warn!(
                                "⚠️ [ADD_LIQUIDITY] Failed to process add_liquidity batch for round {}: {}",
                                round, e
                            );
                        }

                        // Pick a batch of pending BTC claim-reward requests and broadcast (same flow as BTC withdraw)
                        if let Err(e) = self.process_btc_claim_reward_batch_for_round(round).await {
                            warn!(
                                "⚠️ [CLOCK][BTC_CLAIM_REWARD] Failed to process BTC claim-reward batch for round {}: {}",
                                round, e
                            );
                        }

                        // Pick a batch of pending TICS-source intents (UserToVault not done) and broadcast for signing
                        if let Err(e) = self.process_tics_user_to_vault_intent_batch_for_round(round, None).await {
                            warn!(
                                "⚠️ [CLOCK][TICS_UTV_BATCH] Failed to process TICS UserToVault intent batch for round {}: {}",
                                round, e
                            );
                        }

                        // Trigger aggregate signature for the final node
                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;
                    } else if operation_type.as_deref() == Some("epoch_2") {
                        info!(
                            "⏰ [CLOCK] Round {} is epoch_2 (BTC batch + contract updates + withdraw), processing phase 1 intents...",
                            round
                        );

                        // Process phase 1 intents for BTC (passed explicitly by epoch).
                        if let Err(e) = self.process_phase1_intents_for_global_clock(round, "bitcoin").await {
                            warn!(
                                "⚠️ [CLOCK] Failed to process BTC phase 1 intents for round {}: {}",
                                round, e
                            );
                        }

                        // Pick a batch of pending BTC-source intents (UserToVault not done) and broadcast for signing
                        if let Err(e) = self.process_btc_user_to_vault_intent_batch_for_round(round, None).await {
                            warn!(
                                "⚠️ [CLOCK][BTC_UTV_BATCH] Failed to process BTC UserToVault intent batch for round {}: {}",
                                round, e
                            );
                        }

                        // Process peer invalidation batch (invalidate disconnected solver IDs)
                        if let Err(e) = self.process_peer_invalidation_batch(round).await {
                            warn!(
                                "⚠️ [CLOCK][PEER_INVALIDATION] Failed to process peer invalidation batch for round {}: {}",
                                round, e
                            );
                        }

                        // Trigger aggregate signature for the final node
                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;
                    } else if operation_type.as_deref() == Some("epoch_3") {
                        info!(
                            "⏰ [CLOCK] Round {} is epoch_3 (withdraw settlement + platform fee), finalizing withdraw request statuses...",
                            round
                        );

                        if let Err(e) = self.process_withdraw_settlement_epoch(round).await {
                            warn!(
                                "⚠️ [CLOCK] Failed to process withdraw settlement epoch for round {}: {}",
                                round, e
                            );
                        }
                        // TICS claim-platform-fee uses admin derived MPC key (no nonce conflict with withdraw's liquidity operator key)
                        if let Err(e) = self.process_tics_claim_platform_fee_settlement_epoch(round).await {
                            warn!(
                                "⚠️ [CLOCK] Failed to process TICS claim-platform-fee batch for round {}: {}",
                                round, e
                            );
                        }
                        // Pick a batch of pending TICS-source intents (UserToVault not done) and broadcast for signing
                        if let Err(e) = self.process_tics_user_to_vault_intent_batch_for_round(round, Some(true)).await {
                            warn!(
                                "⚠️ [CLOCK][TICS_UTV_BATCH] Failed to process TICS UserToVault intent batch for round {}: {}",
                                round, e
                            );
                        }

                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;
                    } else if operation_type.as_deref() == Some("epoch_4") {
                        info!(
                            "⏰ [CLOCK] Round {} is epoch_4 (BTC platform fee + TICS claim-reward), processing...",
                            round
                        );

                        if let Err(e) = self.process_btc_claim_platform_fee_batch_for_round(round).await {
                            warn!(
                                "⚠️ [CLOCK] Failed to process BTC claim-platform-fee batch for round {}: {}",
                                round, e
                            );
                        }

                        // TICS claim-reward uses liquidity operator key — moved here from epoch_3
                        // to avoid nonce conflict with withdraw settlement (also liquidity operator key)
                        if let Err(e) = self.process_tics_claim_reward_settlement_epoch(round).await {
                            warn!(
                                "⚠️ [CLOCK] Failed to process TICS claim-reward settlement for round {}: {}",
                                round, e
                            );
                        }

                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;
                    } else if operation_type.as_deref() == Some("btc_intent_manager_update") {
                        info!("🔄 [BTC_CONTRACT_UPDATE] Round {} was triggered by BTC intent manager update, processing contract update batch...", round);
                        // Process BTC contract update batch (intents with network_to_target_tx_id but not Solved)
                        // The final node will broadcast the batch, all nodes will sign, then final node aggregates
                        if let Err(e) = self.process_btc_contract_update_batch_for_round(round).await {
                            warn!("⚠️ [BTC_CONTRACT_UPDATE] Failed to process contract update batch for round {}: {}", round, e);
                        } else {
                            // After broadcasting the batch, trigger aggregation request immediately
                            // All nodes will receive the batch and start signing, then send signatures when requested
                            // The final node will aggregate when enough signatures arrive
                            if let Err(e) = self
                                .trigger_aggregate_signature_for_final_node(round)
                                .await
                            {
                                warn!("⚠️ [BTC_CONTRACT_UPDATE] Failed to trigger aggregate signature for round {}: {}", round, e);
                            } else {
                                info!("✅ [BTC_CONTRACT_UPDATE] Triggered aggregate signature request for contract call (round {})", round);
                            }
                        }
                    } else {
                        info!("ℹ️  [CONSENSUS] Round {} operation_type={:?}, skipping intent processing", round, operation_type);
                        // Trigger aggregate signature for the final node
                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;
                    }
                }

                Ok(Some(result))
            }
            Err(e) => {
                error!(
                    "❌ [CONSENSUS] Failed to start consensus for round {}: {}",
                    round, e
                );
                Err(e)
            }
        }
    }

    /// Check if consensus can be started for a round
    pub async fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            vrf_service.can_start_consensus(round, min_selections).await
        } else {
            false
        }
    }

    /// Handle consensus messages
    pub async fn handle_consensus_message(&mut self, msg: ConsensusMessage) -> Result<()> {
        let ConsensusMessage::FinalNodeResult { ref result, round } = msg;
            // Use available nodes from node_manager (synced across all nodes) for HRW validation
            let active_nodes: std::collections::HashSet<PeerId> = self.coordination.get_available_nodes().await.into_iter().collect();
            if let Some(ref dkg) = self.dkg_storage {
                if let Ok(candidates) = hrw::candidates::get_hrw_candidates(dkg, Some(&active_nodes)) {
                    if let Some(our_winner) =
                        hrw::select_final(round, &candidates, hrw::HRW_DOMAIN_FINAL_NODE)
                    {
                        if result.final_node.0 != our_winner {
                            warn!(
                                "⚠️ [CONSENSUS] Rejecting consensus result for round {}: HRW winner is {} but received {:?}",
                                round, our_winner, result.final_node
                            );
                            return Ok(());
                        }
                    }
                }
            }
        // Store the final node so signing functions can find it (even if this node
        // didn't locally trigger consensus due to min_required mismatch).
        let final_node_str = result.final_node.0.to_string();
        {
            let mut final_nodes = self.signatures.final_nodes_by_round.write().await;
            if !final_nodes.contains_key(&round) {
                final_nodes.insert(round, final_node_str.clone());
                info!(
                    "💾 [CONSENSUS] Stored final node {} for round {} (from received consensus result)",
                    final_node_str, round
                );
            }
        }
        if let Some(consensus_node) = self.coordination.consensus_node_mut() {
            consensus_node.handle_message(msg).await?;
        }
        Ok(())
    }

    /// Trigger aggregate signature for the final selected node
    pub(crate) async fn trigger_aggregate_signature_for_final_node(&self, round: u64) -> Result<()> {
        info!(
            "🚀 [SIGNING] Triggering aggregate signature for final node in round {}",
            round
        );

        // If we have BTC per-input signatures tracked for this round, request BTC signatures
        let is_btc_round = {
            let map = self.btc_state.btc_sigs_by_round.read().await;
            map.contains_key(&round)
        };

        let signature_request = if is_btc_round {
            SigningMessage::RequestBtcSignatures {
                round,
                final_node_id: self.id.clone(),
                message: "Aggregate BTC signatures request".to_string(),
            }
        } else {
            SigningMessage::RequestSignatures {
                round,
                final_node_id: self.id.clone(),
                message: "Aggregate signature request".to_string(),
            }
        };

        // Wrap in GossipsubMessage::Signing for proper message handling
        let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_request);
        let broadcast_data = serde_json::to_vec(&gossipsub_msg)?;
        self.broadcast("signing", &broadcast_data).await?;

        info!(
            "📤 [SIGNING] Broadcasted {} signature request for round {} to all nodes",
            if is_btc_round { "BTC" } else { "ECDSA" },
            round
        );

        Ok(())
    }

}
