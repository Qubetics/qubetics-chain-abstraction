use crate::signing::{state::BtcRoundExtras, SigningNode};
use crate::{
    chain_abstraction::{BitcoinTransaction, ChainTransaction},
    types::{
        signing::{BtcIndexedSignature, ECDSASignature},
        GossipsubMessage, SigningMessage, SpendKind, TransactionType,
    },
};
use anyhow::{anyhow, bail, Result};
use hex;
use k256::Scalar;
use reqwest::Client;
use secp256k1::ecdsa::RecoverableSignature;
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};

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
        original_tx: Option<BitcoinTransaction>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<TransactionType>,
        user_tweaked_share: Option<Scalar>,
        solver_address: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_bitcoin_transaction(
                tx_bytes,
                original_tx,
                user_eth_address,
                intent_hash,
                transaction_type,
                user_tweaked_share,
                solver_address,
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
}

impl SigningNode {
    /// Sign Bitcoin transaction – per-input (P2PKH / P2WPKH v0) and stash round context.
    pub async fn sign_bitcoin_transaction(
        &mut self,
        tx_bytes: Vec<u8>,
        original_tx: Option<BitcoinTransaction>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<TransactionType>,
        user_tweaked_share: Option<Scalar>,
        solver_address: Option<String>,
    ) -> Result<()> {
        use secp256k1::{ecdsa::RecoverableSignature, Message};

        // Validate parameters: if intent_hash is None, solver_address must be provided
        if intent_hash.is_none() && solver_address.is_none() {
            error!("❌ [BTC-SIGNING] Invalid parameters: when intent_hash is None, solver_address must be provided");
            return Err(anyhow!(
                "When intent_hash is None, solver_address must be provided"
            ));
        }

        if !self.key_store.has_private_key() {
            return Err(anyhow!("No private key available"));
        }

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

        fn hash160(data: &[u8]) -> [u8; 20] {
            use sha2::Digest;
            let sha = sha2::Sha256::digest(data);
            let rip = ripemd::Ripemd160::digest(&sha);
            let mut out = [0u8; 20];
            out.copy_from_slice(&rip);
            out
        }

        let signer_h160 = hash160(&signer_pubkey33);

        // Build per-input digests (either BIP143 or legacy SIGHASH_ALL).
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(tx.inputs.len());

        for (i, inp) in tx.inputs.iter().enumerate() {
            let maybe_prev = inp.witness_utxo.as_ref();
            let is_p2wpkh = maybe_prev
                .map(|p| {
                    p.script_pubkey.len() == 22
                        && p.script_pubkey[0] == 0x00
                        && p.script_pubkey[1] == 0x14
                })
                .unwrap_or(false);

            if is_p2wpkh {
                // --- P2WPKH (v0) ---
                let prev = maybe_prev.expect("Some above");
                let program20 = &prev.script_pubkey[2..22];

                // Safety: signer pubkey must match the witness program
                if signer_h160 != program20 {
                    anyhow::bail!(
                        "Input {}: signer HASH160(pubkey) != witness program ({} != {})",
                        i,
                        hex::encode(signer_h160),
                        hex::encode(program20)
                    );
                }

                let digest = self.compute_bip143_sighash_p2wpkh(tx, i, prev.value, program20)?;
                digests.push(digest);
            } else {
                // --- Legacy P2PKH ---
                // Prefer using the carried prev script if present; otherwise reconstruct from signer_h160.
                let prev_spk: Vec<u8> = if let Some(prev) = maybe_prev {
                    prev.script_pubkey.clone()
                } else {
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

                let digest = self.compute_legacy_sighash_all_p2pkh(tx, i, &prev_spk)?;
                digests.push(digest);
            }
        }

        // ===== Select round via VRF =====
        let available_nodes = self.coordination.get_available_nodes_from_manager().await;
        let current_round = if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = vrf_service.get_next_round().await;
            let _ = vrf_service
                .perform_node_selection(&available_nodes, 1, round, "bitcoin")
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

        // ===== Sign each input digest with our key share (or tweaked) =====
        let signing_key = if let Some(tweaked_share) = user_tweaked_share {
            Self::derive_secp_secret(&tweaked_share)?
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

        for (i, digest) in digests.iter().enumerate() {
            let msg = Message::from_digest_slice(digest)?;
            let sig = self.create_ecdsa_signature_with_signing_key(&msg, &signing_key)?;
            per_input_sigs.push((i, sig));
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
                info!(
                "💾 [BTC-SIGNING-DEBUG] Stored BTC signature for input {} - r: 0x{}, s: 0x{}, recovery_id: {}",
                btc_sig.input_index,
                hex::encode(&btc_sig.signature.signature[0..32]),
                hex::encode(&btc_sig.signature.signature[32..64]),
                btc_sig.signature.recovery_id
            );
                info!(
                "💾 [INDEX-PEER-DEBUG] BTC: Stored signature for Index {} => PeerId {} input {} (s-share: 0x{})",
                dkg_index, self.id, btc_sig.input_index,
                hex::encode(&btc_sig.signature.signature[32..64])
            );
            }
            info!(
                "💾 [SIGNING] Stored {} Bitcoin input signatures for round {}",
                btc_sigs.len(),
                current_round
            );
        }

        // ===== Stash BTC extras alongside the unsigned tx for the finalizer =====
        let from_kind = if tx.witness.is_some() {
            SpendKind::P2WPKH
        } else {
            SpendKind::P2PKH
        };

        // Convert to fixed arrays for serialization in extras
        let pubkey33_arr: [u8; 33] = signer_pubkey33
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Compressed pubkey must be 33 bytes"))?;

        // Choose broadcast network (or derive from addresses if you prefer)
        let is_testnet = true;

        let extras = BtcRoundExtras {
            pubkey33: pubkey33_arr,
            signer_h160,
            from_kind,
            is_testnet,
        };

        // Store tx + extras under this round (so final node can reconstruct without re-deriving)
        if let Some(original_tx) = &original_tx {
            if intent_hash.is_none() {
                // This is a reward transaction - store in reward pending transactions
                if let Some(solver_addr) = solver_address {
                    // Store in BTC reward pending transactions
                    self.store_reward_transaction_btc(
                        current_round,
                        ChainTransaction::Bitcoin(original_tx.clone()),
                        tx_bytes.clone(),
                        solver_addr.clone(),
                        extras,
                    )
                    .await;

                    // Insert round number into reward_rounds for reward transactions
                    {
                        let mut reward_rounds = self.pending.reward_rounds.write().await;
                        reward_rounds.insert(current_round);
                        info!(
                            "🎁 [BTC-SIGNING] Node {} added round {} to reward_rounds",
                            self.id, current_round
                        );
                    }

                    info!(
                    "💾 [BTC-SIGNING] Node {} stored BTC reward transaction for round {} with solver address: {} (inputs={})",
                    self.id, current_round, solver_addr, original_tx.inputs.len()
                );
                } else {
                    error!(
                        "❌ [BTC-SIGNING] Solver address is required for BTC reward transactions"
                    );
                    return Err(anyhow!(
                        "Solver address is required for BTC reward transactions"
                    ));
                }
            } else {
                // This is an intent-based transaction - store in regular pending transactions
                let mut pending = self.pending.pending_transactions_btc.write().await;
                pending.insert(
                    current_round,
                    (
                        ChainTransaction::Bitcoin(original_tx.clone()),
                        tx_bytes.clone(),
                        intent_hash.clone(),
                        transaction_type.clone(),
                        Some(extras), // <-- critical for aggregation/finalization
                    ),
                );
                info!(
                "💾 [BTC-SIGNING] Node {} stored intent-based BTC transaction for round {} reconstruction (intent_hash: {:?}, inputs={})",
                self.id, current_round, intent_hash, original_tx.inputs.len()
            );
            }
        }

        Ok(())
    }

    pub(crate) async fn broadcast_transaction(
        raw_tx_hex: &str,
        mainnet: bool,
    ) -> Result<Option<String>> {
        let default_url = if mainnet {
            "https://mempool.space/api/tx"
        } else {
            "https://mempool.space/testnet/api/tx"
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
                Ok(Some("broadcast_success".to_string()))
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

                out.extend_from_slice(&(inp.vout as u32).to_le_bytes());

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
                    out.extend_from_slice(&(inp.vout as u32).to_le_bytes());
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
        let _ = std.normalize_s();
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
        let h2 = sha2::Sha256::digest(&h1);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h2);
        out
    }

    // Build the canonical P2PKH script from a 20-byte hash160(pubkey)
    pub(crate) fn p2pkh_script_from_h160(&self, h160: &[u8; 20]) -> [u8; 25] {
        let mut s = [0u8; 25];
        s[0..3].copy_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
        s[3..23].copy_from_slice(h160);
        s[23..25].copy_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
        s
    }

    // Compute BIP143 digest for P2WPKH v0 input `idx`
    pub(crate) fn compute_bip143_sighash_p2wpkh(
        &self,
        tx: &BitcoinTransaction,
        idx: usize,
        prev_value: u64,
        program20: &[u8], // 20 bytes
    ) -> anyhow::Result<[u8; 32]> {
        // hashPrevouts
        let mut hpv = Vec::with_capacity(36 * tx.inputs.len());
        for inp in &tx.inputs {
            let mut txid = hex::decode(&inp.txid)?;
            txid.reverse(); // txid LE
            hpv.extend_from_slice(&txid);
            hpv.extend_from_slice(&(inp.vout as u32).to_le_bytes());
        }
        let hash_prevouts = Self::dsha256(&hpv);

        // hashSequence
        let mut hseq = Vec::with_capacity(4 * tx.inputs.len());
        for inp in &tx.inputs {
            hseq.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        let hash_sequence = Self::dsha256(&hseq);

        // hashOutputs
        let mut hout = Vec::new();
        for out in &tx.outputs {
            hout.extend_from_slice(&out.value.to_le_bytes());
            // varint script len
            let slen = out.script_pubkey.len() as u64;
            Self::push_varint(&mut hout, slen);
            hout.extend_from_slice(&out.script_pubkey);
        }
        let hash_outputs = Self::dsha256(&hout);

        // scriptCode for P2WPKH is canonical P2PKH built from program20
        let sc = {
            let mut v = Vec::with_capacity(1 + 25);
            v.push(0x19); // length 25
            v.extend_from_slice(&self.p2pkh_script_from_h160(
                <&[u8; 20]>::try_from(program20).map_err(|_| anyhow!("program20 len"))?,
            ));
            v
        };

        // preimage
        let mut pre = Vec::new();
        pre.extend_from_slice(&tx.version.to_le_bytes());
        pre.extend_from_slice(&hash_prevouts);
        pre.extend_from_slice(&hash_sequence);

        // outpoint of input idx
        let mut txid_i = hex::decode(&tx.inputs[idx].txid)?;
        txid_i.reverse();
        pre.extend_from_slice(&txid_i);
        pre.extend_from_slice(&(tx.inputs[idx].vout as u32).to_le_bytes());

        pre.extend_from_slice(&sc);
        pre.extend_from_slice(&prev_value.to_le_bytes());
        pre.extend_from_slice(&tx.inputs[idx].sequence.to_le_bytes());
        pre.extend_from_slice(&hash_outputs);
        pre.extend_from_slice(&tx.lock_time.to_le_bytes());
        pre.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        Ok(Self::dsha256(&pre))
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
            pre.extend_from_slice(&(inp.vout as u32).to_le_bytes());

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
                    for (_peer_id, ecsig) in imap {
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

            // Wrap in GossipsubMessage::Signing for proper message handling
            let gossipsub_msg = GossipsubMessage::Signing(signature_msg);
            let signature_data = serde_json::to_vec(&gossipsub_msg)?;

            // Broadcast to a specific topic that the final node subscribes to
            let res: std::result::Result<(), anyhow::Error> = self
                .broadcast("signatures-to-final-node", &signature_data)
                .await;
            match res {
                Ok(_) => info!(
                    "📤 [SIGNING] Successfully sent BTC signatures for round {} to final node {}",
                    round, final_node_id
                ),
                Err(e) => {
                    error!(
                    "❌ [SIGNING] Failed to send BTC signatures for round {} to final node {}: {}",
                    round, final_node_id, e
                );
                    return Err(e);
                }
            }
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
            self.send_btc_signatures_to_final_node(&final_node_id, round)
                .await?;
        } else {
            info!(
                "🔄 [SIGNING] This node is the final node, no need to send BTC signatures to self"
            );
        }

        Ok(())
    }

    /// Handle BTC signatures received on the signatures-to-final-node topic
    pub async fn handle_btc_signatures_to_final_node(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received {} BTC signatures from {} on signatures-to-final-node topic",
            self.id, signatures.len(), from
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
}
