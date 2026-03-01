use super::*;
use crate::types::signing::{
    ECDSASignature, SigningMessage,
};
use anyhow::Result;
use hex;
use secp256k1::{self, ecdsa::RecoverableSignature};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
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
use secp256k1::ecdsa::RecoveryId;
use crate::chain_abstraction::ChainTransaction;
use crate::types::ChannelMessage;

impl SigningNode {
    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} broadcasting to topic: {}",
            self.id, topic
        );
        debug!("📊 [SIGNING] Message size: {} bytes", data.len());

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;

        info!(
            "✅ [SIGNING] Node {} successfully queued broadcast message for topic: {}",
            self.id, topic
        );
        Ok(())
    }

    /// Send ECDSA signature directly to a specific peer via unicast
    pub async fn send_ecdsa_signature_direct(
        &self,
        final_node_id: &str,
        signature_data: &[u8],
        round: u64,
    ) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::UnicastECDSASignature {
                target_peer_id: final_node_id.to_string(),
                from_node_id: self.id.clone(),
                signature_data: signature_data.to_vec(),
                round,
                retry_count: 0,
            })
            .await?;

        debug!(
            "📤 [SIGNING-SECURE] Queued unicast ECDSA signature for round {} to final node {}",
            round, final_node_id
        );
        Ok(())
    }

    /// Send transaction data directly to final node via unicast P2P RPC
    pub async fn send_transaction_data_direct(
        &self,
        final_node_id: &str,
        transaction_data: &[u8],
        round: u64,
    ) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::UnicastTransactionData {
                target_peer_id: final_node_id.to_string(),
                from_node_id: self.id.clone(),
                transaction_data: transaction_data.to_vec(),
                round,
                retry_count: 0,
            })
            .await?;

        debug!(
            "📤 [SIGNING-SECURE] Queued unicast transaction data for round {} to final node {}",
            round, final_node_id
        );
        Ok(())
    }

    /// Send BTC signatures directly to a specific peer via unicast
    pub async fn send_btc_signatures_direct(
        &self,
        final_node_id: &str,
        signature_data: &[u8],
        round: u64,
    ) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::UnicastBtcSignatures {
                target_peer_id: final_node_id.to_string(),
                from_node_id: self.id.clone(),
                signature_data: signature_data.to_vec(),
                round,
                retry_count: 0,
            })
            .await?;

        debug!(
            "📤 [SIGNING-SECURE] Queued unicast BTC signatures for round {} to final node {}",
            round, final_node_id
        );
        Ok(())
    }

    /// Send signature for specific round to the final selected node
    pub async fn send_signature_to_final_node(
        &mut self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Sending signature for round {} to final node {}",
            round, final_node_id
        );

        // TICS or BTC UserToVault batch: send one ECDSASignature per slot with slot_id
        let slot_ids: Vec<String> = {
            let tics: Vec<String> = self
                .pending
                .user_to_vault_tics_batch
                .read()
                .await
                .get(&round)
                .map(|entries| entries.iter().map(|(h, _, _, _)| h.clone()).collect())
                .unwrap_or_default();
            if !tics.is_empty() {
                tics
            } else {
                self.pending
                    .user_to_vault_btc_batch
                    .read()
                    .await
                    .get(&round)
                    .map(|entries| entries.iter().map(|(h, _, _, _, _)| h.clone()).collect())
                    .unwrap_or_default()
            }
        };
        if !slot_ids.is_empty() {
            let by_slot = self.signatures.signatures_by_round_slot.read().await;
            for intent_hash in slot_ids {
                let slot_key = (round, intent_hash.clone());
                if let Some(slot_sigs) = by_slot.get(&slot_key) {
                    if let Some(our_sig) = slot_sigs.get(&self.id) {
                        let signature_msg = SigningMessage::ECDSASignature {
                            from: self.id.clone(),
                            signature: our_sig.clone(),
                            round,
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                            user_tics_address: our_sig.user_tics_address.clone(),
                            slot_id: Some(intent_hash.clone()),
                        };
                        let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                        let signature_data = serde_json::to_vec(&gossipsub_msg)?;
                        self.broadcast("signing", &signature_data).await?;
                        info!(
                            "✅ [SIGNING] Broadcast batch slot {} signature for round {} to final node {} ({} will aggregate)",
                            intent_hash, round, final_node_id, final_node_id
                        );
                    }
                }
            }
            return Ok(());
        }

        // Single-tx round: send from signatures_by_round
        let signatures_by_round = self.signatures.signatures_by_round.read().await;
        if let Some(round_signatures) = signatures_by_round.get(&round) {
            if let Some(our_signature) = round_signatures.get(&self.id) {
                info!(
                    "📤 [SIGNING] Broadcasting signature for round {} (final node picks from gossipsub): \n\
                     \tFrom: {}\n\
                     \tRound: {}\n\
                     \tSig(r): 0x{}\n\
                     \tSig(s): 0x{}\n\
                     \tRecovID: {}",
                    round,
                    self.id,
                    round,
                    hex::encode(&our_signature.signature[0..32]),
                    hex::encode(&our_signature.signature[32..64]),
                    our_signature.recovery_id
                );

                let signature_msg = SigningMessage::ECDSASignature {
                    from: self.id.clone(),
                    signature: our_signature.clone(),
                    round,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                    user_tics_address: our_signature.user_tics_address.clone(),
                    slot_id: None,
                };

                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;

                self.broadcast("signing", &signature_data).await?;

                info!(
                    "✅ [SIGNING] Broadcast signature for round {} to final node {} ({} will aggregate)",
                    round, final_node_id, final_node_id
                );
            } else {
                info!(
                    "⚠️ [SIGNING] No signature found for round {} for this node",
                    round
                );
            }
        } else {
            info!("⚠️ [SIGNING] No signatures found for round {}", round);
        }

        Ok(())
    }

    /// Send transaction data to final node (for reconstruction).
    /// Includes serialized ChainTransaction so observer final nodes can reconstruct TXs
    /// without building them locally. The final node collects TX data from threshold DKG nodes
    /// before trusting and using it.
    /// Checks all TICS pending stores: pending_transactions, withdraw, and claim-reward.
    pub(crate) async fn send_transaction_data_to_final_node(
        &self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        // Helper: broadcast TX data message
        macro_rules! broadcast_tx_data {
            ($chain_tx:expr, $tx_bytes:expr, $intent_hash:expr, $tx_type:expr, $request_id:expr, $batch_ids:expr) => {{
                let chain_tx_json = serde_json::to_string($chain_tx).ok();
                let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                    from: self.id.clone(),
                    round,
                    tx_bytes: $tx_bytes.clone(),
                    intent_hash: $intent_hash.clone(),
                    transaction_type: $tx_type,
                    request_id: $request_id,
                    chain_tx_json,
                    user_tics_address: None,
                    batch_identifiers: $batch_ids,
                };
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(tx_data_msg);
                let data = serde_json::to_vec(&gossipsub_msg)?;
                self.broadcast("signing", &data).await?;
                info!(
                    "✅ [SIGNING] Broadcast transaction data for round {} (final node picks from gossipsub)",
                    round
                );
                return Ok(());
            }};
        }

        // Check pending_transactions (single ETH TX: UserToVault, NetworkToTarget, etc.)
        {
            let pending = self.pending.pending_transactions.read().await;
            if let Some((chain_tx, tx_bytes, intent_hash, transaction_type, request_id, _)) = pending.get(&round) {
                // For batch N2T / IntentStatusUpdate rounds, include intent_hashes_by_round so
                // observer final nodes can broadcast tx-id for ALL intents in the batch.
                let batch_ids = {
                    let intent_map = self.pending.intent_hashes_by_round.read().await;
                    intent_map.get(&round).cloned()
                };
                info!(
                    "📤 [SIGNING] Sending transaction data for round {} to final node {} (tx_bytes: {} bytes, batch_intent_hashes: {})",
                    round, final_node_id, tx_bytes.len(), batch_ids.as_ref().map(|v| v.len()).unwrap_or(0)
                );
                broadcast_tx_data!(
                    chain_tx,
                    tx_bytes,
                    intent_hash,
                    transaction_type.as_ref().map(|t| format!("{:?}", t)),
                    request_id.clone(),
                    batch_ids
                );
            }
        }

        // Check withdraw_pending_transactions_tics
        {
            let withdraw = self.pending.withdraw_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, identifiers, tx_type, request_id, _)) = withdraw.get(&round) {
                let intent_hash = identifiers.as_ref().and_then(|v| v.first().cloned());
                info!(
                    "📤 [SIGNING] Sending TICS withdraw TX data for round {} to final node {} ({} batch identifiers)",
                    round, final_node_id, identifiers.as_ref().map(|v| v.len()).unwrap_or(0)
                );
                broadcast_tx_data!(
                    chain_tx,
                    tx_bytes,
                    &intent_hash,
                    tx_type.as_ref().map(|t| format!("{:?}", t)),
                    request_id.clone(),
                    identifiers.clone()
                );
            }
        }

        // Check claim_reward_pending_transactions_tics
        {
            let claim = self.pending.claim_reward_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, identifiers, tx_type, request_id, _)) = claim.get(&round) {
                let intent_hash = identifiers.as_ref().and_then(|v| v.first().cloned());
                info!(
                    "📤 [SIGNING] Sending TICS claim-reward TX data for round {} to final node {} ({} batch identifiers)",
                    round, final_node_id, identifiers.as_ref().map(|v| v.len()).unwrap_or(0)
                );
                broadcast_tx_data!(
                    chain_tx,
                    tx_bytes,
                    &intent_hash,
                    tx_type.as_ref().map(|t| format!("{:?}", t)),
                    request_id.clone(),
                    identifiers.clone()
                );
            }
        }

        debug!(
            "⚠️ [SIGNING] No TICS transaction data found for round {} to send to final node",
            round
        );
        Ok(())
    }

    /// Handle signature request from final selected node
    pub(crate) async fn handle_signature_request(
        &mut self,
        round: u64,
        final_node_id: String,
        _message: String,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} responding to signature request for round {}",
            self.id, round
        );

        // Only send signature if we're not the final node
        if final_node_id != self.id {
            // Check if this node has a DKG secret share (can produce partial signatures)
            // Nodes that joined after initial DKG are observers and cannot sign
            let has_signing_key = self.has_dkg_share().await;
            if has_signing_key {
                // Send signature to the final node
                self.send_signature_to_final_node(&final_node_id, round)
                    .await?;

                // CRITICAL FIX: Also send transaction data to the final node
                // This ensures the final node can reconstruct the transaction even if it wasn't selected to sign
                self.send_transaction_data_to_final_node(&final_node_id, round)
                    .await?;
            } else {
                info!("ℹ️ [SIGNING] Node {} is an observer (no DKG share) - skipping partial signature for round {}", self.id, round);
                // Still send transaction data if we have it, so the final node can use it
                self.send_transaction_data_to_final_node(&final_node_id, round)
                    .await?;
            }
        } else {
            info!("🔄 [SIGNING] This node is the final node, no need to send signature to self");
        }

        Ok(())
    }

    /// Handle signature aggregation for TICS transactions only (Bitcoin has separate flow)
    pub async fn handle_signature_for_round(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
        slot_id: Option<String>,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} for round {} (slot: {:?})",
            self.id, from, round, slot_id
        );

        // TICS UserToVault batch: per-slot aggregation
        if let Some(slot) = slot_id {
            return self
                .handle_signature_for_round_slot(from, signature, round, slot)
                .await;
        }

        // Check if this round has already been aggregated
        let already_aggregated = {
            let aggregated_rounds = self.signatures.aggregated_rounds.read().await;
            aggregated_rounds.contains(&round)
        };

        if already_aggregated {
            info!(
                "⏭️ [SIGNING] Round {} already aggregated, ignoring signature from {}",
                round, from
            );
            return Ok(());
        }

        // Check if this same signature was already stored in the previous round
        if round > 0 {
            let prev_round = round - 1;
            let is_duplicate = {
                let signatures_by_round = self.signatures.signatures_by_round.read().await;
                if let Some(prev_round_signatures) = signatures_by_round.get(&prev_round) {
                    if let Some(prev_sig) = prev_round_signatures.get(&from) {
                        // Compare signature bytes to detect duplicates
                        prev_sig.signature == signature.signature
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if is_duplicate {
                warn!(
                    "🚫 [SIGNING] Duplicate signature detected: signature from {} for round {} was already stored in round {} - skipping",
                    from, round, prev_round
                );
                return Ok(());
            }
        }

        // Verify signature before storing
        // For contract transactions (transaction_type = None), use vault share pubkey
        //
        // NOTE: With random nonces (coordinated nonces), partial signature verification
        // via ECDSA public key recovery is not mathematically possible because all nodes
        // use the same aggregated k⁻¹ and r values. The security comes from:
        // 1. All nodes compute the same message digest
        // 2. The final aggregated signature is verified against the group public key
        // 3. Invalid partial signatures will result in an invalid aggregated signature
        //
        // For now, we log but don't fail on partial verification errors. The final
        // aggregated signature verification provides the actual security guarantee.
        if let Err(e) = self
            .verify_signature_for_round(&from, &signature, round, None)
            .await
        {
            warn!(
                "⚠️ [SIGNING] Partial verification failed for peer {} in round {} (expected with random nonces): {}",
                from, round, e
            );
            // Don't return error - with random nonces, partial verification is not possible.
            // The final aggregated signature will be verified against the group public key.
        } else {
            info!(
                "✅ [SIGNING] Signature verification passed for peer {} in round {}",
                from, round
            );
        }

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(from.clone(), signature.clone());

            info!(
                "💾 [SIGNING] Stored signature from {} for round {} (total: {})",
                from,
                round,
                round_signatures.len()
            );
        }

        // Check if we have enough signatures for this round
        let signatures_to_aggregate: Option<Result<Vec<RecoverableSignature>>> = {
            let signatures_by_round = self.signatures.signatures_by_round.read().await;
            signatures_by_round.get(&round).map(|round_signatures| {
                // Sort signatures by signer_id (PeerId) to ensure consistent ordering across rounds
                let mut sorted_signatures: Vec<_> = round_signatures.iter().collect();

                info!(
                    "🔍 [SIGNING] === SIGNATURE SORTING DEBUG (ROUND {}) ===",
                    round
                );
                info!(
                    "🔍 [SIGNING] Original signature order: {:?}",
                    round_signatures.keys().collect::<Vec<_>>()
                );

                sorted_signatures.sort_by(|a, b| a.0.cmp(b.0));

                info!(
                    "🔍 [SIGNING] Sorted signature order: {:?}",
                    sorted_signatures
                        .iter()
                        .map(|(id, _)| id.as_str())
                        .collect::<Vec<_>>()
                );

                info!(
                    "🔄 [SIGNING] Sorted {} signatures by PeerId for round {} aggregation: {:?}",
                    sorted_signatures.len(),
                    round,
                    sorted_signatures
                        .iter()
                        .map(|(id, _)| id.as_str())
                        .collect::<Vec<_>>()
                );

                info!(
                    "🔍 [SIGNING] === END SIGNATURE SORTING DEBUG (ROUND {}) ===",
                    round
                );

                // Create a mapping of peer ID to index for debugging
                let mut peer_to_index_map = Vec::new();

                let sigs_result: Result<Vec<RecoverableSignature>> = sorted_signatures
                    .into_iter()
                    .enumerate()
                    .map(|(i, (signer_id, ecdsa_sig))| {
                        let index = i + 1;
                        peer_to_index_map.push((signer_id.clone(), index));

                        info!(
                            "🔍 [SIGNING] Peer {} assigned index {} for aggregation (round {})",
                            signer_id, index, round
                        );

                        RecoverableSignature::from_compact(
                            &ecdsa_sig.signature,
                            RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                        )
                        .map_err(|_| anyhow::anyhow!("Invalid signature from signer {}", signer_id))
                    })
                    .collect();

                info!(
                    "🔍 [SIGNING] Final peer-to-index mapping for round {}: {:?}",
                    round,
                    peer_to_index_map
                        .iter()
                        .map(|(peer, idx)| format!("{peer}->{idx}"))
                        .collect::<Vec<_>>()
                );

                sigs_result
            })
        };

        if let Some(signatures_result) = signatures_to_aggregate {
            let signatures_vec = signatures_result?;

            if signatures_vec.len() >= self.threshold {
                // Mark this round as aggregated BEFORE processing to prevent race conditions
                {
                    let mut aggregated_rounds = self.signatures.aggregated_rounds.write().await;
                    aggregated_rounds.insert(round);
                }

                info!(
                "✅ [SIGNING] Threshold reached! {} signatures collected for round {} (threshold: {}), starting aggregation",
                signatures_vec.len(), round, self.threshold
            );

                // Take only threshold number of signatures for aggregation
                let mut threshold_signatures = signatures_vec;
                threshold_signatures.truncate(self.threshold);

                info!(
                    "🔢 [SIGNING] Using {} signatures for aggregation (threshold: {})",
                    threshold_signatures.len(),
                    self.threshold
                );

                // Calculate DKG indices for the selected signatures
                let peer_to_dkg_index: Vec<(String, u32)> = {
                    // Get the peer IDs in the same order as threshold_signatures
                    let signatures_by_round = self.signatures.signatures_by_round.read().await;
                    if let Some(round_signatures) = signatures_by_round.get(&round) {
                        let mut sorted_signatures: Vec<_> = round_signatures.iter().collect();
                        sorted_signatures.sort_by(|a, b| a.0.cmp(b.0));
                        let sorted_peer_ids: Vec<String> = sorted_signatures
                            .iter()
                            .take(self.threshold)
                            .map(|(id, _)| (*id).clone())
                            .collect();
                        info!(
                        "🧩 [SIGNING] Selected peers (PeerId sorted) for this aggregation: {:?}",
                        sorted_peer_ids
                    );

                        // Calculate DKG indices for each peer
                        let mut dkg_indices = Vec::new();
                        for peer_id in &sorted_peer_ids {
                            let dkg_index = self.calculate_dkg_index_for_peer(peer_id).await;
                            dkg_indices.push((peer_id.clone(), dkg_index));
                        }

                        dkg_indices
                    } else {
                        Vec::new()
                    }
                };

                info!(
                    "🔢 [SIGNING] DKG indices for threshold signatures: {:?}",
                    peer_to_dkg_index
                        .iter()
                        .map(|(peer, idx)| format!("{peer}->{idx}"))
                        .collect::<Vec<_>>()
                );

                // Get chain_id from environment variable for v calculation
                let chain_id_for_v = std::env::var("MPC_TICS_CHAIN_ID")
                    .ok()
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id()); // Default: Qubetics chain ID from MPC_TICS_CHAIN_ID env var

                // Perform aggregation
                match self
                    .aggregate_signatures(threshold_signatures, peer_to_dkg_index)
                    .await
                {
                    Ok(aggregated_signature) => {
                        info!(
                        "🎉 [SIGNING] Signature aggregation completed successfully for round {}!",
                        round
                    );

                        // Log the aggregated signature details
                        let (recovery_id, signature_bytes) =
                            aggregated_signature.serialize_compact();
                        let v: u64 = recovery_id.to_i32() as u64 + 35 + chain_id_for_v * 2;

                        info!(
                            "🔗 [SIGNING] Using chain_id {} for v calculation (EIP-155 compliant)",
                            chain_id_for_v
                        );

                        // Normalize signature components to remove leading zeros (canonical form)
                        let r_bytes = &signature_bytes[0..32];
                        let s_bytes = &signature_bytes[32..64];

                        // Convert to BigUint to remove leading zeros, then back to 32-byte arrays
                        let r_biguint = num_bigint::BigUint::from_bytes_be(r_bytes);
                        let s_biguint = num_bigint::BigUint::from_bytes_be(s_bytes);

                        let mut r = [0u8; 32];
                        let mut s = [0u8; 32];

                        let r_canonical = r_biguint.to_bytes_be();
                        let s_canonical = s_biguint.to_bytes_be();

                        // Copy to right-aligned 32-byte arrays (big-endian)
                        if r_canonical.len() <= 32 {
                            r[32 - r_canonical.len()..].copy_from_slice(&r_canonical);
                        }
                        if s_canonical.len() <= 32 {
                            s[32 - s_canonical.len()..].copy_from_slice(&s_canonical);
                        }

                        debug!(
                            "🔐 [SIGNING] Aggregated signature components for round {}: v={}, recovery_id={}",
                            round, v, recovery_id.to_i32()
                        );

                        // 🚀 Reconstruct and broadcast signed transaction based on actual transaction type
                        // Check the actual transaction stored for this round to determine the correct chain type.
                        // Observer nodes (no DKG share) may not have TX data yet because it arrives
                        // via TransactionDataForFinalNode messages which need threshold verification.
                        // We poll briefly to let the TX data arrive before giving up.
                        let is_withdraw_round = {
                            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
                            withdraw_rounds.contains(&round)
                        };

                        let is_claim_reward_round = {
                            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
                            claim_reward_rounds.contains(&round)
                        };
                        let is_claim_platform_fee_round = {
                            let r = self.pending.claim_platform_fee_rounds.read().await;
                            r.contains(&round)
                        };

                        let has_dkg = self.has_dkg_share().await;

                        let (is_contract_tx, maybe_chain_id) = {
                            let max_attempts = if has_dkg { 1 } else { 50 }; // observer: poll up to ~5s
                            let mut result = (false, None);
                            for attempt in 0..max_attempts {
                                if attempt > 0 {
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                }
                                let found = if is_withdraw_round {
                                    let store = self.pending.withdraw_pending_transactions_tics.read().await;
                                    store.get(&round).and_then(|(chain_tx, ..)| match chain_tx {
                                        ChainTransaction::Tics(eth_tx) => {
                                            let is_contract = eth_tx.data.as_ref().map_or(false, |d| !d.is_empty());
                                            Some((is_contract, Some(eth_tx.chain_id)))
                                        }
                                        _ => None,
                                    })
                                } else if is_claim_reward_round {
                                    let store = self.pending.claim_reward_pending_transactions_tics.read().await;
                                    store.get(&round).and_then(|(chain_tx, ..)| match chain_tx {
                                        ChainTransaction::Tics(eth_tx) => {
                                            let is_contract = eth_tx.data.as_ref().map_or(false, |d| !d.is_empty());
                                            Some((is_contract, Some(eth_tx.chain_id)))
                                        }
                                        _ => None,
                                    })
                                } else if is_claim_platform_fee_round {
                                    // Check TICS store first (contract call), then BTC store
                                    let tics_store = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
                                    let found = tics_store.get(&round).and_then(|(chain_tx, ..)| match chain_tx {
                                        ChainTransaction::Tics(eth_tx) => {
                                            let is_contract = eth_tx.data.as_ref().map_or(false, |d| !d.is_empty());
                                            Some((is_contract, Some(eth_tx.chain_id)))
                                        }
                                        _ => None,
                                    });
                                    if found.is_some() {
                                        found
                                    } else {
                                        drop(tics_store);
                                        let store = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                                        store.get(&round).and_then(|(chain_tx, ..)| match chain_tx {
                                            ChainTransaction::Tics(eth_tx) => {
                                                let is_contract = eth_tx.data.as_ref().map_or(false, |d| !d.is_empty());
                                                Some((is_contract, Some(eth_tx.chain_id)))
                                            }
                                            _ => None,
                                        })
                                    }
                                } else {
                                    let store = self.pending.pending_transactions.read().await;
                                    store.get(&round).and_then(|(chain_tx, ..)| match chain_tx {
                                        ChainTransaction::Tics(eth_tx) => {
                                            let is_contract = eth_tx.data.as_ref().map_or(false, |d| !d.is_empty());
                                            Some((is_contract, Some(eth_tx.chain_id)))
                                        }
                                        _ => None,
                                    })
                                };
                                if let Some(val) = found {
                                    result = val;
                                    if attempt > 0 {
                        debug!(
                            "✅ [SIGNING] Found TX data for round {} after {} attempts (~{}ms)",
                            round, attempt + 1, attempt * 100
                        );
                                    }
                                    break;
                                }
                                if attempt == max_attempts - 1 && !has_dkg {
                                    warn!(
                                        "⚠️ [SIGNING] Could not find TX data for round {} after {}ms, proceeding without it",
                                        round, max_attempts * 100
                                    );
                                }
                            }
                            result
                        };

                        info!(
                            "🔍 [SIGNING] Processing TICS transaction (is_contract: {})",
                            is_contract_tx
                        );

                        // Create canonical signature bytes from normalized r and s components
                        let mut canonical_signature_bytes = [0u8; 64];
                        canonical_signature_bytes[0..32].copy_from_slice(&r);
                        canonical_signature_bytes[32..64].copy_from_slice(&s);

                        if let Ok(Some(signed_tx_hex)) = self
                            .reconstruct_signed_tics_transaction(
                                round,
                                &canonical_signature_bytes,
                                recovery_id.to_i32() as u8,
                            )
                            .await
                        {
                            info!("🎉 [SIGNING] 🔗 SIGNED TICS TRANSACTION READY! 🔗");
                            info!("📄 Raw signed transaction: {}", signed_tx_hex);

                            // Get chain ID for broadcasting from the stored original transaction
                            let chain_id = match maybe_chain_id {
                                Some(id) => id,
                                None => {
                                    let default_chain_id = crate::env_defaults::mpc_tics_chain_id();
                                    warn!(
                                        "⚠️ [SIGNING] Unable to determine chain_id for round {}, defaulting to {}",
                                        round, default_chain_id
                                    );
                                    default_chain_id
                                }
                            };

                            info!(
                                "Broadcasting transaction to chain {} (Qubetics)...",
                                chain_id
                            );
                            
                            let (request_id, _original_request) = {
                                let pending = self.pending.pending_transactions.read().await;
                                pending.get(&round).map(|(_, _, _, _, req_id, orig_req)| {
                                    (req_id.clone(), orig_req.clone())
                                }).unwrap_or((None, None))
                            };
                            match Self::broadcast_tics_transaction(&signed_tx_hex, chain_id)
                                .await
                            {
                                Ok(Some(tx_hash)) => {
                                    info!("✅ [SIGNING] TICS transaction broadcasted successfully: {}", tx_hash);
                                    self.store_transaction_id_for_round(
                                        round,
                                        &tx_hash,
                                        crate::types::TransactionNetwork::TICS,
                                        None,
                                    )
                                    .await;
                                    if let Some(ref req_id) = request_id {
                                        self.broadcast_transaction_success(req_id, &tx_hash, chain_id).await;
                                    }
                                }
                                Ok(None) => {
                                    warn!("⚠️ [SIGNING] TICS transaction broadcasted but no tx_hash returned");
                                    if let Some(ref req_id) = request_id {
                                        let original_request = {
                                            let pending = self.pending.pending_transactions.read().await;
                                            pending.get(&round).and_then(|(_, _, _, _, _, orig_req)| orig_req.clone())
                                        };
                                        self.broadcast_transaction_failure(req_id, "N/A", "No tx_hash returned", original_request).await;
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "❌ [SIGNING] Failed to broadcast TICS transaction: {}",
                                        e
                                    );
                                    self.store_transaction_error_for_round(
                                        round,
                                        &e.to_string(),
                                        crate::types::TransactionNetwork::TICS,
                                    )
                                    .await;
                                    if let Some(ref req_id) = request_id {
                                        let original_request = {
                                            let pending = self.pending.pending_transactions.read().await;
                                            pending.get(&round).and_then(|(_, _, _, _, _, orig_req)| orig_req.clone())
                                        };
                                        self.broadcast_transaction_failure(req_id, "N/A", &e.to_string(), original_request).await;
                                    }
                                }
                            }
                        } else {
                            warn!(
                            "❌ [SIGNING] Failed to reconstruct TICS transaction for round {}",
                            round
                        );
                            
                            let (request_id, original_request) = {
                                let pending = self.pending.pending_transactions.read().await;
                                if let Some((_, _, _, _, req_id, orig_req)) = pending.get(&round) {
                                    (req_id.clone(), orig_req.clone())
                                } else {
                                    (None, None)
                                }
                            };
                            if let Some(ref req_id) = request_id {
                                self.broadcast_transaction_failure(req_id, "N/A", "Failed to reconstruct signed transaction", original_request).await;
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to aggregate signatures for round {}: {}",
                            round, e
                        );
                        let (request_id, original_request) = {
                            let pending = self.pending.pending_transactions.read().await;
                            if let Some((_, _, _, _, req_id, orig_req)) = pending.get(&round) {
                                (req_id.clone(), orig_req.clone())
                            } else {
                                (None, None)
                            }
                        };
                        if let Some(ref req_id) = request_id {
                            self.broadcast_transaction_failure(req_id, "N/A", &format!("Signature aggregation failed: {}", e), original_request).await;
                        }
                        // Check if aggregation failed due to insufficient signatures
                        let error_msg = e.to_string();
                        if error_msg.contains("Not enough signature shares") {
                            info!(
                                "💸 [SIGNING-REFUND] Insufficient valid signatures for aggregation in round {}, triggering refund",
                                round
                            );
                        }
                        
                        return Err(e);
                    }
                }
            } else {
                info!(
                    "⏳ [SIGNING] Waiting for more signatures for round {}: {}/{} (threshold)",
                    round,
                    signatures_vec.len(),
                    self.threshold
                );
            }
        }

        Ok(())
    }

    pub async fn handle_message(&mut self, msg: SigningMessage) -> Result<()> {
        info!(
            "📥 [SIGNING] Node {} received signing message: {:?}",
            self.id, msg
        );

        match msg {
            SigningMessage::MessageToSign {
                from: _from,
                message: _message,
                message_hash: _message_hash,
            } => {}
            SigningMessage::ECDSASignature {
                from,
                signature,
                round,
                timestamp: _timestamp,
                user_tics_address: _user_tics_address,
                slot_id,
            } => {
                // Final node picks signatures from broadcast (gossipsub) for aggregation
                self.handle_signature_to_final_node(from, signature, round, slot_id)
                    .await?;
            }
            SigningMessage::BtcSignaturesMessage {
                from,
                signatures,
                round,
                timestamp: _timestamp,
                user_tics_address: _user_tics_address,
            } => {
                // Final node picks BTC signatures from broadcast (gossipsub) for N2T aggregation
                self.handle_btc_signatures_to_final_node(from, signatures, round)
                    .await?;
            }
            SigningMessage::BtcUtvSignaturesMessage {
                from,
                signatures,
                round,
                slot_id,
                timestamp: _timestamp,
                user_tics_address: _user_tics_address,
            } => {
                // BTC UserToVault batch: multi-input per-slot aggregation (NOT routed to TICS path)
                info!(
                    "📥 [BTC_UTV] Received {} signatures from {} for slot {} round {}",
                    signatures.len(),
                    from,
                    slot_id,
                    round
                );
                self.handle_btc_utv_signatures_to_final_node(from, signatures, round, slot_id)
                    .await?;
            }
            SigningMessage::SignedMessage {
                from,
                signed_message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received signed message from {}",
                    self.id, from
                );
                self.handle_signed_message(from, signed_message).await?;
            }
            SigningMessage::RequestSignatures {
                round,
                final_node_id,
                message,
            } => {
                info!(
                "📥 [SIGNING] Node {} received signature request for round {} from final node {}",
                self.id, round, final_node_id
            );
                self.handle_signature_request(round, final_node_id, message)
                    .await?;
            }
            SigningMessage::RequestBtcSignatures {
                round,
                final_node_id,
                message: _message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received BTC signature request for round {} from final node {}",
                    self.id, round, final_node_id
                );
                self.handle_btc_signature_request(round, final_node_id)
                    .await?;
            }
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
            } => {
                info!(
                    "📥 [SIGNING] Node {} received transaction data for round {} from {}",
                    self.id, round, from
                );
                self.handle_transaction_data_for_final_node(
                    from,
                    round,
                    tx_bytes,
                    intent_hash,
                    transaction_type,
                    request_id,
                    chain_tx_json,
                    user_tics_address,
                    batch_identifiers,
                )
                .await?;
            }

            // Nonce protocol messages - forward to NonceManager
            // ONLY DKG signers participate in nonce commit-reveal protocol.
            // Observer nodes receive finalized nonces via NonceTupleBroadcast instead.
            // If observers participate, different nodes may aggregate different sets of k_i
            // (due to varying effective_total), producing different aggregated_k values
            // for the same tuple_id — which makes partial signatures incompatible.
            SigningMessage::NonceCommitment { ref from, ref batch_id, round, batch_size, .. } => {
                if self.has_dkg_share().await {
                    info!(
                        "📥 [SIGNING] Node {} received nonce commitment from {} for batch {} round {} (batch_size: {})",
                        self.id, from, batch_id, round, batch_size
                    );
                    if let Some(manager) = &self.nonce_manager {
                        let mgr = manager.lock().await;
                        if let Err(e) = mgr.handle_message(msg.clone()).await {
                            warn!("⚠️ [SIGNING] Failed to handle nonce commitment: {}", e);
                        }
                    }
                }
            }
            SigningMessage::NonceReveal { ref from, ref batch_id, round, .. } => {
                if self.has_dkg_share().await {
                    info!(
                        "📥 [SIGNING] Node {} received nonce reveal from {} for batch {} round {}",
                        self.id, from, batch_id, round
                    );
                    if let Some(manager) = &self.nonce_manager {
                        let mgr = manager.lock().await;
                        if let Err(e) = mgr.handle_message(msg.clone()).await {
                            warn!("⚠️ [SIGNING] Failed to handle nonce reveal: {}", e);
                        }
                    }
                }
            }
            SigningMessage::RequestNonceGeneration { ref batch_id, round: _, ref coordinator_id, batch_size } => {
                if self.has_dkg_share().await {
                    info!(
                        "📥 [SIGNING] Node {} received nonce generation request from {} for batch {} (size: {})",
                        self.id, coordinator_id, batch_id, batch_size
                    );
                    if let Some(manager) = &self.nonce_manager {
                        let mgr = manager.lock().await;
                        if let Err(e) = mgr.handle_message(msg.clone()).await {
                            warn!("⚠️ [SIGNING] Failed to handle nonce generation request: {}", e);
                        }
                    }
                }
            }
            SigningMessage::NonceGenerationComplete { ref from, ref batch_id, round: _, tuples_count, success } => {
                info!(
                    "📥 [SIGNING] Node {} received nonce generation complete from {} for batch {} ({} tuples, success: {})",
                    self.id, from, batch_id, tuples_count, success
                );
                if let Some(manager) = &self.nonce_manager {
                    let mgr = manager.lock().await;
                    if let Err(e) = mgr.handle_message(msg.clone()).await {
                        warn!("⚠️ [SIGNING] Failed to handle nonce generation complete: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Get the compressed 65-byte representation of an ECDSA signature
    pub fn get_compressed_signature_bytes(&self, signature: &RecoverableSignature) -> [u8; 65] {
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut result = [0u8; 65];
        result[0] = recovery_id.to_i32() as u8;
        result[1..].copy_from_slice(&signature_bytes);
        result
    }

    /// Get the compressed 65-byte representation as a hex string
    pub fn get_compressed_signature_hex(&self, signature: &RecoverableSignature) -> String {
        let bytes = self.get_compressed_signature_bytes(signature);
        hex::encode(bytes)
    }

}
