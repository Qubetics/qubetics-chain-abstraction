use crate::signing::{state::BtcRoundExtras, state::RoundSlotKey, SigningNode};
use crate::{
    chain_abstraction::{BitcoinTransaction, ChainTransaction},
    types::{
        network as network_cfg,
        signing::{BtcIndexedSignature, ECDSASignature},
        GossipsubMessage, SigningMessage, SpendKind, TransactionType,
    },
};
use anyhow::{anyhow, bail, Result};
use hex;
use k256::Scalar;
use reqwest::Client;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Message;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};

/// Convenience wrapper that exposes Bitcoin-specific signing operations on a `SigningNode`.
pub struct BitcoinSigner<'a> {
    node: &'a mut SigningNode,
}

impl<'a> BitcoinSigner<'a> {
    pub fn new(node: &'a mut SigningNode) -> Self {
        Self { node }
    }

    pub fn node(&self) -> &SigningNode {
        self.node
    }

    pub fn node_mut(&mut self) -> &mut SigningNode {
        self.node
    }

    pub async fn sign_transaction(
        &mut self,
        tx_bytes: Vec<u8>,
        chain_handler: &Arc<dyn crate::chain_abstraction::ChainHandler>,
        original_tx: Option<BitcoinTransaction>,
        user_eth_address: Option<String>,
        intent_hashes: Vec<String>,
        transaction_type: Option<TransactionType>,
        user_tweaked_share: Option<Scalar>,
        solver_address: Option<String>,
        signing_key_override: Option<Scalar>,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_bitcoin_transaction(
                tx_bytes,
                chain_handler,
                original_tx,
                user_eth_address,
                intent_hashes,
                transaction_type,
                user_tweaked_share,
                solver_address,
                signing_key_override,
                nonce_tuple_id,
            )
            .await
    }

    pub async fn send_signatures_to_final_node(
        &mut self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        self.node
            .send_btc_signatures_to_final_node(final_node_id, round)
            .await
    }

    pub async fn handle_signatures_from_peer(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
    ) -> Result<()> {
        self.node
            .handle_btc_signatures_to_final_node(from, signatures, round)
            .await
    }

    pub fn finalize_transaction(
        &self,
        tx: BitcoinTransaction,
        from_kind: SpendKind,
        per_input_sigs: &[(usize, RecoverableSignature)],
        pubkey33: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32], Option<[u8; 32]>)> {
        SigningNode::finalize_and_serialize_tx(tx, from_kind, per_input_sigs, pubkey33)
    }

    /// BTC UserToVault batch: one round, multiple slots (up to 30).
    /// Each slot can have multiple inputs (UTXOs) - mirrors N2T multi-input signing.
    /// Store batch with BtcRoundExtras, create per-input partial signatures,
    /// store in btc_utv_state, and broadcast BtcUtvSignaturesMessage with slot_id.
    ///
    /// SECURITY: nonce_assignments parameter is REQUIRED - all intents must have
    /// coordinated nonces assigned by the coordinator node.
    pub async fn sign_btc_user_to_vault_batch(
        &mut self,
        round: u64,
        batch: Vec<(
            String,           // intent_hash (slot_id)
            String,           // user_eth_address
            ChainTransaction, // Bitcoin tx (potentially multi-input)
            Vec<u8>,          // tx_bytes
            Option<Scalar>,   // signing_key
        )>,
        nonce_assignments: &HashMap<String, String>,  // intent_hash -> nonce_tuple_id
    ) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let final_node_id = {
            let final_nodes = self.node.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .cloned()
                .ok_or_else(|| anyhow!("No final node for BTC UserToVault batch round {}", round))?
        };

        // Check if this node has a DKG share (needed for signing, not for TX building/storage)
        let has_dkg = self.node.has_dkg_share().await;

        info!(
            "📦 [BTC_UTV_BATCH] Node {} {} {} slots for round {} (final node: {})",
            self.node.id,
            if has_dkg { "signing" } else { "preparing (observer)" },
            batch.len(),
            round,
            final_node_id
        );

        // Helper for HASH160
        fn hash160(data: &[u8]) -> [u8; 20] {
            use sha2::Digest;
            let sha = sha2::Sha256::digest(data);
            let rip = ripemd::Ripemd160::digest(sha);
            let mut out = [0u8; 20];
            out.copy_from_slice(&rip);
            out
        }

        // Build batch storage with BtcRoundExtras per slot
        let mut batch_storage: Vec<(String, String, ChainTransaction, Vec<u8>, Option<BtcRoundExtras>)> = Vec::new();

        for (intent_hash, user_eth, chain_tx, tx_bytes, key_opt) in batch {
            let btc_tx = match &chain_tx {
                ChainTransaction::Bitcoin(t) => t,
                _ => {
                    warn!(
                        "⚠️ [BTC_UTV_BATCH] Intent {} is not Bitcoin, skipping",
                        intent_hash
                    );
                    continue;
                }
            };

            if btc_tx.inputs.is_empty() {
                warn!(
                    "⚠️ [BTC_UTV_BATCH] Slot {} has no inputs, skipping",
                    intent_hash
                );
                continue;
            }

            // Get group pubkey for this user (UserToVault uses user-derived key)
            let signer_pubkey33 = self
                .node
                .get_group_public_key_bytes(
                    Some(TransactionType::UserToVault),
                    Some(user_eth.clone()),
                )
                .await?;
            if signer_pubkey33.len() != 33 {
                warn!(
                    "⚠️ [BTC_UTV_BATCH] Invalid pubkey length for slot {}: {}",
                    intent_hash, signer_pubkey33.len()
                );
                continue;
            }

            let signer_h160 = hash160(&signer_pubkey33);
            let pubkey33_arr: [u8; 33] = signer_pubkey33
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Compressed pubkey must be 33 bytes"))?;
            let is_testnet = network_cfg::network_type().is_testnet();

            let extras = BtcRoundExtras {
                pubkey33: pubkey33_arr,
                signer_h160,
                from_kind: SpendKind::P2PKH,
                is_testnet,
            };

            // Validate all inputs have witness_utxo and are P2PKH
            let mut all_inputs_valid = true;
            for (idx, inp) in btc_tx.inputs.iter().enumerate() {
                let prev = match inp.witness_utxo.as_ref() {
                    Some(p) => p,
                    None => {
                        warn!(
                            "⚠️ [BTC_UTV_BATCH] Slot {} input {} missing witness_utxo",
                            intent_hash, idx
                        );
                        all_inputs_valid = false;
                        break;
                    }
                };

                let spk = &prev.script_pubkey;
                let is_p2pkh = spk.len() == 25
                    && spk[0] == 0x76
                    && spk[1] == 0xA9
                    && spk[2] == 0x14
                    && spk[23] == 0x88
                    && spk[24] == 0xAC;

                if !is_p2pkh {
                    warn!(
                        "⚠️ [BTC_UTV_BATCH] Slot {} input {} is not canonical P2PKH (len={})",
                        intent_hash, idx, spk.len()
                    );
                    all_inputs_valid = false;
                    break;
                }
            }

            if !all_inputs_valid {
                continue;
            }

            // DKG nodes: sign each input and broadcast signatures + TX data
            // Observer nodes: just add to batch_storage for final node reconstruction
            if has_dkg {
                let signing_key = match key_opt {
                    Some(scalar) => SigningNode::derive_secp_secret(&scalar)?,
                    None => {
                        warn!(
                            "⚠️ [BTC_UTV_BATCH] No signing key for intent {} (user {}), skipping",
                            intent_hash, user_eth
                        );
                        continue;
                    }
                };

                // Get the assigned nonce for this intent - REQUIRED for security
                let nonce_tuple = if let Some(tuple_id) = nonce_assignments.get(&intent_hash) {
                    info!(
                        "🔍 [BTC_UTV_BATCH] Intent {} has nonce assignment: {}",
                        intent_hash, tuple_id
                    );
                    // Acquire the specific nonce assigned by coordinator
                    if let Some(nm) = &self.node.nonce_manager {
                        let nm_guard = nm.lock().await;
                        match nm_guard.acquire_specific_nonce(tuple_id).await {
                            Ok(Some(tuple)) => {
                                info!(
                                    "🔐 [BTC_UTV_BATCH] Using coordinated nonce {} for intent {} (r_scalar: 0x{})",
                                    tuple.tuple_id, intent_hash, hex::encode(tuple.r_scalar.0.to_bytes())
                                );
                                tuple
                            }
                            Ok(None) => {
                                error!(
                                    "🔴 [BTC_UTV_BATCH] Nonce {} not found in local pool for intent {}, SKIPPING (fixed k removed for security)",
                                    tuple_id, intent_hash
                                );
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "🔴 [BTC_UTV_BATCH] Failed to acquire nonce {} for intent {}: {}, SKIPPING (fixed k removed for security)",
                                    tuple_id, intent_hash, e
                                );
                                continue;
                            }
                        }
                    } else {
                        error!(
                            "🔴 [BTC_UTV_BATCH] NonceManager not available for intent {}, SKIPPING (fixed k removed for security)",
                            intent_hash
                        );
                        continue;
                    }
                } else {
                    error!(
                        "🔴 [BTC_UTV_BATCH] No nonce assignment for intent {}, SKIPPING (fixed k removed for security)",
                        intent_hash
                    );
                    continue;
                };

                // Build per-input digests and signatures (like N2T)
                let mut btc_sigs: Vec<BtcIndexedSignature> = Vec::with_capacity(btc_tx.inputs.len());

                for (idx, inp) in btc_tx.inputs.iter().enumerate() {
                    let prev_spk = inp.witness_utxo.as_ref().unwrap().script_pubkey.clone();

                    let digest = self
                        .node
                        .compute_legacy_sighash_all_p2pkh(btc_tx, idx, &prev_spk)?;

                    let msg = Message::from_digest_slice(&digest)?;

                    // Sign using coordinated random nonce (fixed k removed for security)
                    let sig = self
                        .node
                        .create_ecdsa_signature_with_nonce(&msg, &signing_key, &nonce_tuple)?;
                    let (recovery_id, sig_bytes) = sig.serialize_compact();

                    let ecdsa_sig = ECDSASignature {
                        signature: sig_bytes.to_vec(),
                        signer_id: self.node.id.clone(),
                        recovery_id: recovery_id.to_i32() as u8,
                        user_eth_address: Some(user_eth.clone()),
                    };

                    btc_sigs.push(BtcIndexedSignature {
                        input_index: idx,
                        signature: ecdsa_sig,
                    });

                }

                // Store signatures in btc_utv_state: (round, slot_id) → input_index → peer → sig
                {
                    let slot_key: RoundSlotKey = (round, intent_hash.clone());
                    let mut by_slot = self.node.btc_utv_state.btc_utv_sigs_by_round_slot.write().await;
                    let slot_map = by_slot.entry(slot_key).or_default();
                    for btc_sig in &btc_sigs {
                        let input_map = slot_map.entry(btc_sig.input_index).or_default();
                        input_map.insert(self.node.id.clone(), btc_sig.signature.clone());
                    }
                }

                // Broadcast BtcUtvSignaturesMessage (NOT ECDSASignature with slot_id)
                let signature_msg = SigningMessage::BtcUtvSignaturesMessage {
                    from: self.node.id.clone(),
                    signatures: btc_sigs,
                    round,
                    slot_id: intent_hash.clone(),
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                    user_eth_address: Some(user_eth.clone()),
                };
                let gossipsub_msg = GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;
                self.node.broadcast("signing", &signature_data).await?;

                // Send TX data for this slot to the final node for threshold verification.
                // All DKG nodes broadcast their TX data; the final node accepts it once
                // threshold matching copies arrive.
                {
                    let chain_tx_json = serde_json::to_string(&chain_tx).ok();
                    let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                        from: self.node.id.clone(),
                        round,
                        tx_bytes: tx_bytes.clone(),
                        intent_hash: Some(intent_hash.clone()),
                        transaction_type: Some("UserToVault".to_string()),
                        request_id: None,
                        chain_tx_json,
                        user_eth_address: Some(user_eth.clone()),
                        batch_identifiers: None,
                    };
                    let tx_data_gossip = GossipsubMessage::Signing(tx_data_msg);
                    let tx_data_bytes = serde_json::to_vec(&tx_data_gossip)?;
                    self.node.broadcast("signing", &tx_data_bytes).await?;
                }
            }

            // All nodes (DKG + observer): add to batch storage with extras
            batch_storage.push((
                intent_hash,
                user_eth,
                chain_tx,
                tx_bytes,
                Some(extras),
            ));
        }

        // Store the full batch with extras for final node reconstruction (all nodes)
        {
            let mut store = self.node.pending.user_to_vault_btc_batch.write().await;
            store.insert(round, batch_storage.clone());
        }

        if !has_dkg {
            info!(
                "ℹ️ [BTC_UTV_BATCH] Observer node {} stored batch data for round {} ({} slots) — signing skipped",
                self.node.id, round, batch_storage.len()
            );
        }

        Ok(())
    }
}

impl SigningNode {
    /// Sign Bitcoin transaction – per-input (P2PKH / P2WPKH v0) and stash round context.
    pub async fn sign_bitcoin_transaction(
        &mut self,
        tx_bytes: Vec<u8>,
        _chain_handler: &Arc<dyn crate::chain_abstraction::ChainHandler>,
        original_tx: Option<BitcoinTransaction>,
        user_eth_address: Option<String>,
        intent_hashes: Vec<String>,
        transaction_type: Option<TransactionType>,
        user_tweaked_share: Option<Scalar>,
        _solver_address: Option<String>,
        signing_key_override: Option<Scalar>,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        use secp256k1::{ecdsa::RecoverableSignature, Message};

        info!(
            "📝 [SIGNING] Node {} starting Bitcoin transaction signing",
            self.id
        );

        // We require the full tx object to compute correct per-input digests.
        let tx = original_tx
            .as_ref()
            .ok_or_else(|| anyhow!("Missing original_tx: cannot compute Bitcoin sighashes"))?;

        // Pull the group pubkey once; used for safety checks and legacy P2PKH reconstruction.
        let signer_pubkey33 = self
            .get_group_public_key_bytes(transaction_type.clone(), user_eth_address.clone())
            .await?;
        if signer_pubkey33.len() != 33 {
            return Err(anyhow!(
                "Invalid pubkey length: {} (expected 33)",
                signer_pubkey33.len()
            ));
        }

        // We only support legacy P2PKH flows for now; reject any transaction that claims
        // to carry witness data so every peer hashes the same legacy preimage.
        if tx.witness.is_some() {
            bail!("Segwit/witness inputs are not supported; only P2PKH is allowed");
        }

        // Enforce that every input carries prevout data so all nodes hash the *same* preimage.
        // Missing witness_utxo data leads to some peers hashing a legacy path while others use
        // BIP143, which in turn produces an invalid aggregated signature on-chain.
        let expected_kind = SpendKind::P2PKH;
        for (idx, inp) in tx.inputs.iter().enumerate() {
            let prev = inp.witness_utxo.as_ref().ok_or_else(|| {
                error!(
                    "❌ [BTC-SIGNING] Input {} missing witness_utxo data (txid={}, vout={})",
                    idx, inp.txid, inp.vout
                );
                anyhow!("Input {} missing witness_utxo data", idx)
            })?;

            match expected_kind {
                SpendKind::P2WPKH => {
                    let is_p2wpkh = prev.script_pubkey.len() == 22
                        && prev.script_pubkey[0] == 0x00
                        && prev.script_pubkey[1] == 0x14;
                    if !is_p2wpkh {
                        error!(
                            "❌ [BTC-SIGNING] Input {} expected P2WPKH but script_pubkey is not v0 witness program (len={}, prefix={:02x?})",
                            idx,
                            prev.script_pubkey.len(),
                            prev.script_pubkey.get(0..2)
                        );
                        bail!("Input {} script_pubkey is not P2WPKH", idx);
                    }
                }
                SpendKind::P2PKH => {
                    let spk = &prev.script_pubkey;
                    let is_p2pkh = spk.len() == 25
                        && spk[0] == 0x76
                        && spk[1] == 0xa9
                        && spk[2] == 0x14
                        && spk[23] == 0x88
                        && spk[24] == 0xac;
                    if !is_p2pkh {
                        error!(
                            "❌ [BTC-SIGNING] Input {} expected P2PKH but script_pubkey is not canonical (len={}, prefix={:02x?})",
                            idx,
                            spk.len(),
                            spk.get(0..3)
                        );
                        bail!("Input {} script_pubkey is not canonical P2PKH", idx);
                    }
                }
            }
        }

        fn hash160(data: &[u8]) -> [u8; 20] {
            use sha2::Digest;
            let sha = sha2::Sha256::digest(data);
            let rip = ripemd::Ripemd160::digest(sha);
            let mut out = [0u8; 20];
            out.copy_from_slice(&rip);
            out
        }

        let signer_h160 = hash160(&signer_pubkey33);

        // Build per-input digests (either BIP143 or legacy SIGHASH_ALL).
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(tx.inputs.len());

        // Log transaction details for debugging digest mismatches
        info!(
            "🔍 [BTC-TX-DEBUG] Node {} transaction details: version={}, inputs={}, outputs={}, locktime={}",
            self.id, tx.version, tx.inputs.len(), tx.outputs.len(), tx.lock_time
        );

        for (i, inp) in tx.inputs.iter().enumerate() {
            let maybe_prev = inp.witness_utxo.as_ref();

            // Log input details for debugging
            info!(
                "🔍 [BTC-TX-DEBUG] Node {} input {}: txid={}, vout={}, sequence={}, witness_utxo={:?}",
                self.id, i, inp.txid, inp.vout, inp.sequence,
                maybe_prev.as_ref().map(|w| format!("value={}, script_pubkey_len={}, script_pubkey=0x{}", 
                    w.value, w.script_pubkey.len(), hex::encode(&w.script_pubkey)))
            );

            // With P2PKH-only enforcement, reject any witness program to avoid mixed sighash
            // computations across peers.
            let is_p2wpkh = maybe_prev
                .map(|p| {
                    p.script_pubkey.len() == 22
                        && p.script_pubkey[0] == 0x00
                        && p.script_pubkey[1] == 0x14
                })
                .unwrap_or(false);

            if is_p2wpkh {
                bail!("Input {} uses P2WPKH/witness; only P2PKH is supported", i);
            }

            info!(
                "🔍 [BTC-TX-DEBUG] Node {} input {}: enforcing P2PKH, signer_h160=0x{}",
                self.id,
                i,
                hex::encode(signer_h160)
            );

            // --- Legacy P2PKH ---
            // Prefer using the carried prev script if present; otherwise reconstruct from signer_h160.
            let prev_spk: Vec<u8> = if let Some(prev) = maybe_prev {
                info!(
                    "🔍 [BTC-TX-DEBUG] Node {} input {}: P2PKH detected, using witness_utxo script_pubkey (len={})",
                    self.id, i, prev.script_pubkey.len()
                );
                prev.script_pubkey.clone()
            } else {
                info!(
                    "🔍 [BTC-TX-DEBUG] Node {} input {}: P2PKH detected, reconstructing script_pubkey from signer_h160",
                    self.id, i
                );
                let mut v = Vec::with_capacity(25);
                v.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
                v.extend_from_slice(&signer_h160);
                v.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
                v
            };

            if prev_spk.len() != 25
                || !(prev_spk[0] == 0x76
                    && prev_spk[1] == 0xa9
                    && prev_spk[2] == 0x14
                    && prev_spk[23] == 0x88
                    && prev_spk[24] == 0xac)
            {
                anyhow::bail!("Input {}: prevout script is not canonical P2PKH", i);
            }

            info!(
                "🔍 [BTC-TX-DEBUG] Node {} input {}: P2PKH prev_spk=0x{}",
                self.id,
                i,
                hex::encode(&prev_spk)
            );

            let digest = self.compute_legacy_sighash_all_p2pkh(tx, i, &prev_spk)?;
            digests.push(digest);
        }

        // ===== Select round via VRF =====
        let available_nodes = self.coordination.get_available_nodes_from_manager().await;
        let current_round = if let Some(vrf_service) = self.coordination.vrf_service() {
            vrf_service.sync_rounds_before_signing().await?;
            let round = vrf_service.get_next_round().await;
            let _ = vrf_service
                .perform_node_selection(
                    &available_nodes,
                    crate::vrf::VRF_NODE_SELECTION_COUNT,
                    round,
                    "bitcoin",
                )
                .await;
            info!(
                "🎲 [SIGNING] Node {} using VRF round {} for Bitcoin transaction signing",
                self.id, round
            );
            round
        } else {
            warn!("⚠️ [SIGNING] No VRF service available, using round 0 as fallback");
            0
        };

        // Check if this node has a DKG share (needed for signing, not for TX building/storage)
        let has_dkg = self.has_dkg_share().await;

        if has_dkg {
            // ===== DKG node: Sign each input digest with our key share =====
            let signing_key = if let Some(tweaked_share) = user_tweaked_share {
                Self::derive_secp_secret(&tweaked_share)?
            } else if let Some(explicit_key) = signing_key_override {
                info!("🔑 [BTC-SIGNING] Using provided signing key override for signing");
                Self::derive_secp_secret(&explicit_key)?
            } else {
                self.key_store
                    .clone_private_key()
                    .ok_or_else(|| anyhow!("No private key available for signing"))?
            };

            // Log signing key for testing/debugging (Bitcoin)
            let signing_key_hex = hex::encode(signing_key.secret_bytes());
            info!(
                "🔐 [BTC-SIGNING-DEBUG] Node {} Bitcoin signing key (hex): 0x{}",
                self.id, signing_key_hex
            );

            // Calculate and log DKG index for this node (Bitcoin)
            let dkg_index = self.calculate_dkg_index_for_peer(&self.id).await;
            info!(
                "🔢 [BTC-SIGNING-DEBUG] Node {} Bitcoin DKG index: {}",
                self.id, dkg_index
            );

            let mut per_input_sigs: Vec<(usize, RecoverableSignature)> =
                Vec::with_capacity(digests.len());

            // Acquire the coordinated nonce by tuple_id (all nodes use the same k value)
            let nonce = if let Some(ref tuple_id) = nonce_tuple_id {
                if let Some(nm) = &self.nonce_manager {
                    let nm_guard = nm.lock().await;
                    match nm_guard.acquire_specific_nonce(tuple_id).await {
                        Ok(Some(tuple)) => {
                            info!(
                                "🔐 [BTC-SIGNING] Using coordinated nonce {} for signing (r_scalar: 0x{})",
                                tuple.tuple_id,
                                hex::encode(tuple.r_scalar.0.to_bytes())
                            );
                            tuple
                        }
                        Ok(None) => {
                            return Err(anyhow!(
                                "Coordinated nonce {} not found or already consumed - cannot sign",
                                tuple_id
                            ));
                        }
                        Err(e) => {
                            return Err(anyhow!(
                                "Failed to acquire coordinated nonce {}: {} - cannot sign",
                                tuple_id, e
                            ));
                        }
                    }
                } else {
                    return Err(anyhow!("NonceManager not available - cannot sign"));
                }
            } else {
                error!("🔴 [BTC-SIGNING] No nonce_tuple_id provided for BTC signing - this is a coordination bug!");
                return Err(anyhow!(
                    "No nonce_tuple_id provided. All BTC signing operations must use coordinated nonces."
                ));
            };

            for (i, digest) in digests.iter().enumerate() {
                let msg = Message::from_digest_slice(digest)?;

                // Sign using the coordinated random nonce (fixed k removed for security)
                let sig = self.create_ecdsa_signature_with_nonce(&msg, &signing_key, &nonce)?;
                per_input_sigs.push((i, sig));

                // Log the digest that this node signs with its share for debugging transaction failures
                info!(
                    "🔐 [BTC-TX-DIGEST] Node {} signing digest for round {} input {}: 0x{} (DKG index: {})",
                    self.id,
                    current_round,
                    i,
                    hex::encode(digest),
                    dkg_index
                );
                info!(
                    "✅ [SIGNING] Made signature for input {} (digest {})",
                    i,
                    hex::encode(digest)
                );
            }

            // Serialize to BtcIndexedSignature for network/storage
            let mut btc_sigs: Vec<BtcIndexedSignature> = Vec::with_capacity(per_input_sigs.len());
            for (i, rsig) in &per_input_sigs {
                let (recovery_id, comp) = rsig.serialize_compact();
                btc_sigs.push(BtcIndexedSignature {
                    input_index: *i,
                    signature: ECDSASignature {
                        signature: comp.to_vec(), // 64 bytes r||s
                        signer_id: self.id.clone(),
                        recovery_id: recovery_id.to_i32() as u8,
                        user_eth_address: user_eth_address.clone(),
                    },
                });
            }

            info!(
                "✅ [SIGNING] Node {} produced {} per-input signatures",
                self.id,
                btc_sigs.len()
            );

            // ===== Stash our signatures locally under (round → input_index → peer → sig) =====
            {
                let mut by_round = self.btc_state.btc_sigs_by_round.write().await;
                let rmap = by_round.entry(current_round).or_insert_with(HashMap::new);
                for btc_sig in &btc_sigs {
                    let imap = rmap.entry(btc_sig.input_index).or_insert_with(HashMap::new);
                    imap.insert(self.id.clone(), btc_sig.signature.clone());
                }
            }
        } else {
            // ===== Observer node: skip signing, just prepare TX data for aggregation =====
            info!(
                "ℹ️ [BTC-SIGNING] Observer node {} preparing BTC TX (no signing) for round {}",
                self.id, current_round
            );
        }

        // ===== Stash BTC extras alongside the unsigned tx for the finalizer =====
        // Both DKG and observer nodes store the TX data so any node can act as final node.
        let from_kind = SpendKind::P2PKH;

        // Convert to fixed arrays for serialization in extras
        let pubkey33_arr: [u8; 33] = signer_pubkey33
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Compressed pubkey must be 33 bytes"))?;

        // Choose broadcast network from the configured NETWORK_TYPE
        let is_testnet = network_cfg::network_type().is_testnet();

        let extras = BtcRoundExtras {
            pubkey33: pubkey33_arr,
            signer_h160,
            from_kind,
            is_testnet,
        };

        // Store tx + extras under this round (so final node can reconstruct without re-deriving)
        if let Some(original_tx) = &original_tx {
            if let Some(TransactionType::WithdrawLiquidity) = transaction_type {
                // For BTC withdraws we expect `intent_hashes` to carry batch metadata,
                // encoded as "request_id|solver_address" for each withdraw in the batch.
                self.store_withdraw_transaction_btc(
                    current_round,
                    ChainTransaction::Bitcoin(original_tx.clone()),
                    tx_bytes.clone(),
                    intent_hashes.clone(),
                    extras,
                )
                .await;

                {
                    let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                    withdraw_rounds.insert(current_round);
                    info!(
                        "💧 [BTC-SIGNING] Node {} added round {} to withdraw_rounds",
                        self.id, current_round
                    );
                }

                info!(
                    "💾 [BTC-SIGNING] Node {} stored BTC withdraw-liquidity transaction for round {} with solver address: {} (inputs={})",
                    self.id, current_round, intent_hashes.len(), original_tx.inputs.len()
                );
            } else if let Some(TransactionType::ClaimReward) = transaction_type {
                // BTC claim-reward batch: same encoding as withdraw ("request_id|solver_address").
                self.store_claim_reward_transaction_btc(
                    current_round,
                    ChainTransaction::Bitcoin(original_tx.clone()),
                    tx_bytes.clone(),
                    intent_hashes.clone(),
                    extras,
                )
                .await;

                info!(
                    "💾 [BTC-SIGNING] Node {} stored BTC claim-reward transaction for round {} with {} requests (inputs={})",
                    self.id, current_round, intent_hashes.len(), original_tx.inputs.len()
                );
            } else {
                // This is an intent-based transaction - store in regular pending transactions
                let mut pending = self.pending.pending_transactions_btc.write().await;

                // Store intent_hashes as Some(vec) if not empty, None otherwise
                let intent_hashes_opt = if !intent_hashes.is_empty() {
                    Some(intent_hashes.clone())
                } else {
                    None
                };

                pending.insert(
                    current_round,
                    (
                        ChainTransaction::Bitcoin(original_tx.clone()),
                        tx_bytes.clone(),
                        intent_hashes_opt.clone(),
                        transaction_type.clone(),
                        Some(extras), // <-- critical for aggregation/finalization
                    ),
                );

                // Track intent hash scope (single intent = vec![hash], batch = vec![hash1, hash2, ...], none = empty)
                {
                    let mut intent_map = self.pending.intent_hashes_by_round.write().await;
                    intent_map.insert(current_round, intent_hashes.clone());
                }

                info!(
                "💾 [BTC-SIGNING] Node {} stored intent-based BTC transaction for round {} reconstruction (intent_hashes: {:?}, inputs={})",
                self.id, current_round, intent_hashes_opt, original_tx.inputs.len()
            );
            }
        }

        Ok(())
    }

    pub(crate) async fn broadcast_transaction(
        raw_tx_hex: &str,
        is_testnet: bool,
    ) -> Result<Option<String>> {
        let default_url = if is_testnet {
            "https://mempool.space/testnet/api/tx"
        } else {
            "https://mempool.space/api/tx"
        };

        let url = std::env::var("MPC_BITCOIN_RPC_URL").unwrap_or_else(|_| default_url.to_string());
        info!("Broadcasting transaction to: {}", url);

        let client = Client::new();

        // Esplora expects raw tx hex in text/plain body and returns txid as plain text
        let response = client
            .post(&url)
            .header("Content-Type", "text/plain")
            .header("User-Agent", "mpc-node/0.1.0")
            .body(raw_tx_hex.to_string())
            .send()
            .await?;

        if response.status().is_success() {
            // Read body as text first to support multiple provider formats
            let body_text = response.text().await?;
            let body_trimmed = body_text.trim();

            // Try JSON parse first (handles { txid: ... } and { data: { txid: ... } })
            let txid_opt = serde_json::from_str::<serde_json::Value>(body_trimmed)
                .ok()
                .and_then(|v| {
                    v.get("txid")
                        .and_then(|t| t.as_str().map(|s| s.to_string()))
                        .or_else(|| {
                            v.get("data")
                                .and_then(|d| d.get("txid"))
                                .and_then(|t| t.as_str().map(|s| s.to_string()))
                        })
                })
                .or_else(|| {
                    // If not JSON, some providers return plain txid text
                    let t = body_trimmed;
                    let is_hex64 = t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit());
                    if is_hex64 {
                        Some(t.to_string())
                    } else {
                        None
                    }
                });

            if let Some(txid) = txid_opt {
                info!("✅ Transaction broadcasted successfully! TXID: {}", txid);
                Ok(Some(txid))
            } else {
                info!(
                    "✅ Transaction broadcasted successfully, but no txid found in response: {}",
                    body_trimmed
                );
                Ok(None)
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to broadcast transaction: {}", error_text);
            Err(anyhow!("Broadcast failed: {}", error_text))
        }
    }

    pub fn finalize_and_serialize_tx(
        tx: BitcoinTransaction,                           // unsigned skeleton
        from_kind: SpendKind,                             // P2PKH | P2WPKH
        per_input_sigs: &[(usize, RecoverableSignature)], // one (idx, sig) per input
        pubkey33: &[u8],                                  // 33-byte compressed
    ) -> Result<(Vec<u8>, [u8; 32], Option<[u8; 32]>)> {
        if pubkey33.len() != 33 {
            bail!("pubkey must be 33 bytes (compressed)");
        }
        if per_input_sigs.len() != tx.inputs.len() {
            bail!(
                "need exactly one signature per input (got {}, inputs {})",
                per_input_sigs.len(),
                tx.inputs.len()
            );
        }

        // Build a dense vec of DER+01 (SIGHASH_ALL) per input index.
        let mut sig_der_all: Vec<Vec<u8>> = vec![Vec::new(); tx.inputs.len()];
        for (idx, rsig) in per_input_sigs {
            if *idx >= tx.inputs.len() {
                bail!("input index {} out of range", idx);
            }
            sig_der_all[*idx] = Self::der_plus_sighash(*rsig)?;
        }
        // Ensure none are missing
        for (i, s) in sig_der_all.iter().enumerate() {
            if s.is_empty() {
                bail!("missing signature for input {}", i);
            }
        }

        // ----- Serialize two forms -----
        let legacy_bytes = {
            let mut out = Vec::new();
            out.extend_from_slice(&tx.version.to_le_bytes());
            Self::push_varint(&mut out, tx.inputs.len() as u64);

            for (i, inp) in tx.inputs.iter().enumerate() {
                // prev txid LE
                let mut prev = hex::decode(&inp.txid)
                    .map_err(|e| anyhow!("bad txid hex for input {}: {}", i, e))?;
                if prev.len() != 32 {
                    bail!("txid must be 32 bytes");
                }
                prev.reverse();
                out.extend_from_slice(&prev);

                out.extend_from_slice(&inp.vout.to_le_bytes());

                match from_kind {
                    SpendKind::P2PKH => {
                        // scriptSig = <PUSH(sig_der||01)> <PUSH(pubkey33)>
                        let ss = Self::build_p2pkh_scriptsig(&sig_der_all[i], pubkey33);
                        Self::push_varint(&mut out, ss.len() as u64);
                        out.extend_from_slice(&ss);
                    }
                    SpendKind::P2WPKH => {
                        // native segwit spends have EMPTY scriptSig
                        Self::push_varint(&mut out, 0);
                    }
                }

                out.extend_from_slice(&inp.sequence.to_le_bytes());
            }

            // outputs
            Self::push_varint(&mut out, tx.outputs.len() as u64);
            for o in &tx.outputs {
                out.extend_from_slice(&o.value.to_le_bytes());
                Self::push_varint(&mut out, o.script_pubkey.len() as u64);
                out.extend_from_slice(&o.script_pubkey);
            }

            out.extend_from_slice(&tx.lock_time.to_le_bytes());
            out
        };

        // 2) SegWit form (only used for P2WPKH): marker+flag, empty scriptSig in inputs,
        //    witness at the end = [<sig_der+01>, <pubkey33>] per input.
        let segwit_bytes_opt = match from_kind {
            SpendKind::P2WPKH => {
                let mut out = Vec::new();
                out.extend_from_slice(&tx.version.to_le_bytes());
                out.push(0x00); // marker
                out.push(0x01); // flag

                // inputs (empty scriptSig)
                Self::push_varint(&mut out, tx.inputs.len() as u64);
                for inp in &tx.inputs {
                    let mut prev = hex::decode(&inp.txid)?;
                    prev.reverse();
                    out.extend_from_slice(&prev);
                    out.extend_from_slice(&inp.vout.to_le_bytes());
                    Self::push_varint(&mut out, 0); // empty scriptSig
                    out.extend_from_slice(&inp.sequence.to_le_bytes());
                }

                // outputs
                Self::push_varint(&mut out, tx.outputs.len() as u64);
                for o in &tx.outputs {
                    out.extend_from_slice(&o.value.to_le_bytes());
                    Self::push_varint(&mut out, o.script_pubkey.len() as u64);
                    out.extend_from_slice(&o.script_pubkey);
                }

                // witness stacks: 2 items per input
                for i in 0..tx.inputs.len() {
                    Self::push_varint(&mut out, 2); // two stack items
                    Self::push_varint(&mut out, sig_der_all[i].len() as u64);
                    out.extend_from_slice(&sig_der_all[i]);
                    Self::push_varint(&mut out, pubkey33.len() as u64);
                    out.extend_from_slice(pubkey33);
                }

                out.extend_from_slice(&tx.lock_time.to_le_bytes());
                Some(out)
            }
            SpendKind::P2PKH => None,
        };

        // IDs:
        let txid = Self::dsha256(&legacy_bytes);
        let wtxid = segwit_bytes_opt.as_ref().map(|b| Self::dsha256(b));

        // Raw to return:
        let raw = match segwit_bytes_opt {
            Some(b) => b,         // segwit wire form
            None => legacy_bytes, // legacy wire form
        };

        Ok((raw, txid, wtxid))
    }

    fn der_plus_sighash(rsig: RecoverableSignature) -> Result<Vec<u8>> {
        use secp256k1::ecdsa::Signature as StdSig;
        let mut std: StdSig = rsig.to_standard();
        // low-s
        std.normalize_s();
        let mut der = std.serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL
        Ok(der)
    }

    fn build_p2pkh_scriptsig(sig_der_plus_01: &[u8], pubkey33: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(sig_der_plus_01.len() + pubkey33.len() + 8);
        Self::push_data(&mut s, sig_der_plus_01);
        Self::push_data(&mut s, pubkey33);
        s
    }

    pub(crate) fn push_varint(dst: &mut Vec<u8>, v: u64) {
        if v < 0xfd {
            dst.push(v as u8);
        } else if v <= 0xffff {
            dst.push(0xfd);
            dst.extend_from_slice(&(v as u16).to_le_bytes());
        } else if v <= 0xffff_ffff {
            dst.push(0xfe);
            dst.extend_from_slice(&(v as u32).to_le_bytes());
        } else {
            dst.push(0xff);
            dst.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn push_data(dst: &mut Vec<u8>, data: &[u8]) {
        let len = data.len();
        if len < 0x4c {
            dst.push(len as u8);
        } else if len <= 0xff {
            dst.push(0x4c); // OP_PUSHDATA1
            dst.push(len as u8);
        } else if len <= 0xffff {
            dst.push(0x4d); // OP_PUSHDATA2
            dst.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            dst.push(0x4e); // OP_PUSHDATA4
            dst.extend_from_slice(&(len as u32).to_le_bytes());
        }
        dst.extend_from_slice(data);
    }

    pub(crate) fn dsha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let h1 = sha2::Sha256::digest(bytes);
        let h2 = sha2::Sha256::digest(h1);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h2);
        out
    }

    // Compute legacy SIGHASH_ALL digest for P2PKH input `idx`
    pub(crate) fn compute_legacy_sighash_all_p2pkh(
        &self,
        tx: &BitcoinTransaction,
        idx: usize,
        prev_script_pubkey: &[u8], // 25 bytes: 76 a9 14 <20> 88 ac
    ) -> anyhow::Result<[u8; 32]> {
        // version
        let mut pre = Vec::new();
        pre.extend_from_slice(&tx.version.to_le_bytes());

        // inputs (legacy: no marker/flag; scriptSig for idx = prevout script; others empty)
        Self::push_varint(&mut pre, tx.inputs.len() as u64);
        for (j, inp) in tx.inputs.iter().enumerate() {
            let mut txid = hex::decode(&inp.txid)?;
            txid.reverse();
            pre.extend_from_slice(&txid);
            pre.extend_from_slice(&inp.vout.to_le_bytes());

            if j == idx {
                // scriptSig = prevout scriptPubKey
                Self::push_varint(&mut pre, prev_script_pubkey.len() as u64);
                pre.extend_from_slice(prev_script_pubkey);
            } else {
                Self::push_varint(&mut pre, 0);
            }
            pre.extend_from_slice(&inp.sequence.to_le_bytes());
        }

        // outputs
        Self::push_varint(&mut pre, tx.outputs.len() as u64);
        for out in &tx.outputs {
            pre.extend_from_slice(&out.value.to_le_bytes());
            Self::push_varint(&mut pre, out.script_pubkey.len() as u64);
            pre.extend_from_slice(&out.script_pubkey);
        }

        // locktime + sighash type
        pre.extend_from_slice(&tx.lock_time.to_le_bytes());
        pre.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        Ok(Self::dsha256(&pre))
    }

    /// Send BTC per-input signatures for a round to the final selected node
    pub async fn send_btc_signatures_to_final_node(
        &mut self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Sending BTC per-input signatures for round {} to final node {}",
            round, final_node_id
        );

        // Fetch our stored per-input signatures for this round
        let maybe_sigs = {
            let map = self.btc_state.btc_sigs_by_round.read().await;
            if let Some(rmap) = map.get(&round) {
                let mut all_sigs = Vec::new();
                for (input_idx, imap) in rmap {
                    for ecsig in imap.values() {
                        all_sigs.push(BtcIndexedSignature {
                            input_index: *input_idx,
                            signature: ecsig.clone(),
                        });
                    }
                }
                Some(all_sigs)
            } else {
                None
            }
        };

        if let Some(signatures) = maybe_sigs {
            let signature_msg = SigningMessage::BtcSignaturesMessage {
                from: self.id.clone(),
                signatures,
                round,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                user_eth_address: None,
            };

            // Wrap in GossipsubMessage::Signing and broadcast (final node picks from gossipsub)
            let gossipsub_msg = GossipsubMessage::Signing(signature_msg);
            let signature_data = serde_json::to_vec(&gossipsub_msg)?;

            self.broadcast("signing", &signature_data).await?;
        } else {
            info!(
                "⚠️ [SIGNING] No BTC per-input signatures found for round {} for this node",
                round
            );
        }

        Ok(())
    }

    /// Handle BTC signature request from final selected node
    pub(crate) async fn handle_btc_signature_request(
        &mut self,
        round: u64,
        final_node_id: String,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} responding to BTC signature request for round {}",
            self.id, round
        );

        // Only send signatures if we're not the final node
        if final_node_id != self.id {
            let has_signing_key = self.has_dkg_share().await;
            if has_signing_key {
                self.send_btc_signatures_to_final_node(&final_node_id, round)
                    .await?;
            } else {
                info!("ℹ️ [SIGNING] Node {} is an observer (no DKG share) - skipping BTC partial signature for round {}", self.id, round);
            }

            // Send BTC transaction data to final node for threshold verification.
            // Check all BTC pending stores for TX data.
            self.send_btc_transaction_data_to_final_node(round).await?;
        } else {
            info!(
                "🔄 [SIGNING] This node is the final node, no need to send BTC signatures to self"
            );
        }

        Ok(())
    }

    /// Send BTC transaction data to the final node for threshold verification.
    /// Checks pending_transactions_btc, withdraw, and claim-reward stores.
    async fn send_btc_transaction_data_to_final_node(
        &self,
        round: u64,
    ) -> Result<()> {
        // Check pending_transactions_btc (N2T BTC flows)
        {
            let btc_pending = self.pending.pending_transactions_btc.read().await;
            if let Some((chain_tx, tx_bytes, intent_hashes, tx_type, _extras)) = btc_pending.get(&round) {
                let chain_tx_json = serde_json::to_string(chain_tx).ok();
                let intent_hash = intent_hashes.as_ref().and_then(|v| v.first().cloned());
                // For batch N2T BTC rounds, include full intent_hashes_by_round so observer
                // final nodes can broadcast tx-id for ALL intents in the batch.
                let batch_ids = {
                    let intent_map = self.pending.intent_hashes_by_round.read().await;
                    intent_map.get(&round).cloned()
                };
                let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                    from: self.id.clone(),
                    round,
                    tx_bytes: tx_bytes.clone(),
                    intent_hash,
                    transaction_type: tx_type.as_ref().map(|t| format!("{:?}", t)),
                    request_id: None,
                    chain_tx_json,
                    user_eth_address: None,
                    batch_identifiers: batch_ids,
                };
                let gossipsub_msg = GossipsubMessage::Signing(tx_data_msg);
                let data = serde_json::to_vec(&gossipsub_msg)?;
                self.broadcast("signing", &data).await?;
                return Ok(());
            }
        }

        // Check withdraw_pending_transactions_btc
        {
            let btc_withdraw = self.pending.withdraw_pending_transactions_btc.read().await;
            if let Some((chain_tx, tx_bytes, intent_hashes, tx_type, _extras)) = btc_withdraw.get(&round) {
                let chain_tx_json = serde_json::to_string(chain_tx).ok();
                let intent_hash = intent_hashes.as_ref().and_then(|v| v.first().cloned());
                let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                    from: self.id.clone(),
                    round,
                    tx_bytes: tx_bytes.clone(),
                    intent_hash,
                    transaction_type: tx_type.as_ref().map(|t| format!("{:?}", t)),
                    request_id: None,
                    chain_tx_json,
                    user_eth_address: None,
                    batch_identifiers: intent_hashes.clone(),
                };
                let gossipsub_msg = GossipsubMessage::Signing(tx_data_msg);
                let data = serde_json::to_vec(&gossipsub_msg)?;
                self.broadcast("signing", &data).await?;
                return Ok(());
            }
        }

        // Check claim_reward_pending_transactions_btc
        {
            let btc_claim = self.pending.claim_reward_pending_transactions_btc.read().await;
            if let Some((chain_tx, tx_bytes, intent_hashes, tx_type, _extras)) = btc_claim.get(&round) {
                let chain_tx_json = serde_json::to_string(chain_tx).ok();
                let intent_hash = intent_hashes.as_ref().and_then(|v| v.first().cloned());
                let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                    from: self.id.clone(),
                    round,
                    tx_bytes: tx_bytes.clone(),
                    intent_hash,
                    transaction_type: tx_type.as_ref().map(|t| format!("{:?}", t)),
                    request_id: None,
                    chain_tx_json,
                    user_eth_address: None,
                    batch_identifiers: intent_hashes.clone(),
                };
                let gossipsub_msg = GossipsubMessage::Signing(tx_data_msg);
                let data = serde_json::to_vec(&gossipsub_msg)?;
                self.broadcast("signing", &data).await?;
                return Ok(());
            }
        }

        debug!(
            "⚠️ [SIGNING] No BTC transaction data found for round {} to send to final node",
            round
        );
        Ok(())
    }

    /// Handle BTC signatures received via broadcast (gossipsub); only final node aggregates.
    pub async fn handle_btc_signatures_to_final_node(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received {} BTC signatures from {} via broadcast/gossipsub",
            self.id,
            signatures.len(),
            from
        );

        // Check if this node is the final node for the specific round
        let is_final_node = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .map(|node_id| node_id == &self.id)
                .unwrap_or(false)
        };

        if is_final_node {
            info!(
                "✅ [SIGNING] This node {} is the final node for round {}, processing {} BTC signatures",
                self.id, round, signatures.len()
            );

            info!(
                "📥 [SIGNING] Node {} received BTC per-input signatures from {} for round {} (count: {})",
                self.id, from, round, signatures.len()
            );
            // Process each per-input signature via BTC per-input handler
            return self
                .handle_btc_signature_for_round(from.clone(), signatures, round)
                .await;
        }

        info!(
            "⚠️ [SIGNING] Received BTC signatures for round {} but this node is not the final node for that round",
            round
        );
        Ok(())
    }

    /// Handle BTC UTV signatures received via broadcast (gossipsub); only final node aggregates.
    /// This routes to the multi-input per-slot handler (NOT the TICS single-sig path).
    pub async fn handle_btc_utv_signatures_to_final_node(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
        slot_id: String,
    ) -> Result<()> {
        info!(
            "📥 [BTC_UTV] Final node {} received {} signatures from {} for slot {} round {}",
            self.id,
            signatures.len(),
            from,
            slot_id,
            round
        );

        // Check if this node is the final node for the specific round
        let is_final_node = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .map(|node_id| node_id == &self.id)
                .unwrap_or(false)
        };

        if is_final_node {
            info!(
                "✅ [BTC_UTV] This node {} is the final node for round {}, processing {} signatures for slot {}",
                self.id, round, signatures.len(), slot_id
            );

            // Route to the BTC UTV multi-input per-slot handler
            return self
                .handle_btc_utv_signature_for_round_slot(from, signatures, round, slot_id)
                .await;
        }

        info!(
            "⚠️ [BTC_UTV] Received signatures for round {} slot {} but this node is not the final node",
            round, slot_id
        );
        Ok(())
    }

    /// Reconstruct signed Bitcoin tx for one BTC UserToVault batch slot (round, intent_hash).
    /// DEPRECATED: This is the old single-input version. Use finalize_btc_utv_slot instead.
    /// Kept for backwards compatibility but should not be called for multi-input slots.
    pub async fn reconstruct_signed_bitcoin_transaction_for_batch_slot(
        &self,
        round: u64,
        slot_id: &str,
        aggregated_signature: &[u8],
        recovery_id: u8,
    ) -> Result<Option<String>> {
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

        let (_intent_hash, user_eth, chain_tx, _, extras_opt) = {
            let batch = self.pending.user_to_vault_btc_batch.read().await;
            let entries = batch
                .get(&round)
                .ok_or_else(|| anyhow!("No BTC UserToVault batch for round {}", round))?;
            entries
                .iter()
                .find(|(h, ..)| h == slot_id)
                .map(|(a, b, c, d, e)| (a.clone(), b.clone(), c.clone(), d.clone(), e.clone()))
                .ok_or_else(|| anyhow!("No slot {} in BTC batch for round {}", slot_id, round))?
        };
        let btc_tx = match &chain_tx {
            ChainTransaction::Bitcoin(t) => t.clone(),
            _ => return Ok(None),
        };

        // Use extras if available, otherwise derive pubkey
        let (pubkey33, is_testnet) = if let Some(extras) = extras_opt {
            (extras.pubkey33.to_vec(), extras.is_testnet)
        } else {
            let pubkey33 = self
                .get_group_public_key_bytes(
                    Some(TransactionType::UserToVault),
                    Some(user_eth.clone()),
                )
                .await?;
            let is_testnet = network_cfg::network_type().is_testnet();
            (pubkey33, is_testnet)
        };

        if pubkey33.len() != 33 {
            return Err(anyhow!(
                "Invalid pubkey length for BTC batch slot {}: {}",
                slot_id,
                pubkey33.len()
            ));
        }

        let recid = RecoveryId::from_i32(recovery_id as i32)?;
        let recov_sig = RecoverableSignature::from_compact(aggregated_signature, recid)
            .map_err(|e| anyhow!("Invalid aggregated signature for slot {}: {}", slot_id, e))?;
        let per_input_sigs = vec![(0usize, recov_sig)];

        let (raw_tx, txid, _) = Self::finalize_and_serialize_tx(
            btc_tx,
            SpendKind::P2PKH,
            &per_input_sigs,
            &pubkey33,
        )?;

        let raw_tx_hex = hex::encode(&raw_tx);
        if let Ok(Some(broadcast_txid)) =
            Self::broadcast_transaction(&raw_tx_hex, is_testnet).await
        {
            info!(
                "✅ [SIGNING] Reconstructed and broadcast BTC tx for batch slot {} (round {}): {}",
                slot_id, round, broadcast_txid
            );
            Ok(Some(broadcast_txid))
        } else {
            let txid_hex = hex::encode(txid);
            info!(
                "✅ [SIGNING] Reconstructed signed BTC tx for batch slot {} (round {}), txid: {}",
                slot_id, round, txid_hex
            );
            Ok(Some(txid_hex))
        }
    }
}
