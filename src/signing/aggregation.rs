use super::*;
use crate::types::signing::ECDSASignature;
use anyhow::{anyhow, Result};
use hex;
use num_bigint::BigUint;
use num_traits::identities::One;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, Secp256k1};
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
use num_bigint::{BigInt, ToBigInt};
use secp256k1::{constants::CURVE_ORDER, ecdsa::RecoveryId};
use num_traits::Zero;

impl SigningNode {
    pub async fn aggregate_signatures(
        &self,
        signatures: Vec<RecoverableSignature>,
        peer_to_dkg_index: Vec<(String, u32)>,
    ) -> Result<RecoverableSignature> {
        let n_shares = signatures.len();
        if n_shares < self.threshold {
            return Err(anyhow!(
                "Not enough signature shares: got {}, need at least {}",
                n_shares,
                self.threshold
            ));
        }

        // ─── 1) Pull r + recid straight from the first share ─────────────────────────
        let (first_recid, first_compact) = {
            let sig0 = &signatures[0];
            let (recid0, compact0) = sig0.serialize_compact();
            (recid0, compact0)
        };
        let agg_r = first_compact[0..32].to_vec();

        // ─── 2) Build the (index, s_bytes) list ──────────────────────────────────────
        debug!(
            "[SIGNING] Aggregating {} signatures with peer-to-index mapping: {:?}",
            signatures.len(),
            peer_to_dkg_index.iter().map(|(p, i)| format!("{}->{}", p, i)).collect::<Vec<_>>()
        );

        // Use DKG indices for signature aggregation
        let s_shares: Vec<(u32, Vec<u8>)> = signatures
            .into_iter()
            .zip(peer_to_dkg_index.iter())
            .map(|(sig, (_peer_id, dkg_index))| {
                let (_recid, compact) = sig.serialize_compact();
                let s_bytes = compact[32..64].to_vec();
                (*dkg_index, s_bytes)
            })
            .collect();

        // Log s_shares for debugging (debug level to avoid noisy hex in normal logs)
        for (idx, s_bytes) in &s_shares {
            debug!(
                "🔶 [SIGNING-SHARE] s_share from index {}: 0x{}",
                idx,
                hex::encode(s_bytes)
            );
        }
        debug!(
            "🔶 [SIGNING-SHARE] Built s_shares with indices: {:?}",
            s_shares.iter().map(|(idx, _)| idx).collect::<Vec<_>>()
        );

        // ─── 3) Reconstruct s via Lagrange at x=0 ───────────────────────────────────
        let mut agg_s = self.lagrange_interpolate(&s_shares)?;
        debug!(
            "🟡 [SIGNING-AGG] Lagrange interpolated s: 0x{} 🟡",
            hex::encode(&agg_s)
        );

        // ─── 3.5) Normalize aggregated s (enforce low-S) and adjust recovery ID ─────

        // Curve order n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();

        let s_bigint = BigUint::from_bytes_be(&agg_s);
        let half_n = &n >> 1;
        let was_high_s = s_bigint > half_n;

        let (normalized_s, adjusted_recid) = if was_high_s {
            // Normalize s to n - s
            let normalized_s_bigint = &n - &s_bigint;
            let mut normalized_s_bytes = normalized_s_bigint.to_bytes_be();

            // Pad to 32 bytes if needed
            if normalized_s_bytes.len() < 32 {
                let mut padded = vec![0u8; 32 - normalized_s_bytes.len()];
                padded.extend_from_slice(&normalized_s_bytes);
                normalized_s_bytes = padded;
            }

            // Adjust recovery ID by XORing with 1
            let adjusted_recid = RecoveryId::from_i32(first_recid.to_i32() ^ 1)
                .map_err(|e| anyhow!("invalid adjusted recovery ID: {}", e))?;

            (normalized_s_bytes, adjusted_recid)
        } else {
            (agg_s, first_recid)
        };

        agg_s = normalized_s;
        let final_recid = adjusted_recid;

        // ─── 4) Rebuild the recoverable signature with the adjusted recid ───────────
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&agg_r);
        sig_bytes[32..64].copy_from_slice(&agg_s);

        info!(
            "🟡🟡🟡 [SIGNING-AGG] Aggregated Signature COMPLETE 🟡🟡🟡\n\
             ╔══════════════════════════════════════════════════════════════════════════════╗\n\
             ║  r:           0x{}  ║\n\
             ║  s:           0x{}  ║\n\
             ║  recovery_id: {}                                                              ║\n\
             ║  was_high_s:  {}                                                           ║\n\
             ╚══════════════════════════════════════════════════════════════════════════════╝",
            hex::encode(&agg_r),
            hex::encode(&agg_s),
            final_recid.to_i32(),
            was_high_s
        );

        let agg_sig = RecoverableSignature::from_compact(&sig_bytes, final_recid)?;

        Ok(agg_sig)
    }

    pub(crate) fn lagrange_interpolate(&self, shares: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(anyhow!(
                "Not enough shares: got {}, need at least {}",
                shares.len(),
                self.threshold
            ));
        }

        // Select exactly threshold shares deterministically by sorting on DKG index.
        let mut sorted_shares = shares.to_vec();
        sorted_shares.sort_by_key(|(x, _)| *x);
        let selected_shares: Vec<(u32, Vec<u8>)> =
            sorted_shares.into_iter().take(self.threshold).collect();

        // Log chosen indices to aid debugging and ensure determinism across nodes.
        let selected_indices: Vec<u32> = selected_shares.iter().map(|(idx, _)| *idx).collect();
        info!(
            "🔍 [SIGNING] Using shares with indices for Lagrange interpolation: {:?}",
            selected_indices
        );

        let n = BigUint::from_bytes_be(&CURVE_ORDER);

        // Improved extended Euclidean algorithm for modular inverse
        pub(crate) fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
            if *a == BigUint::zero() {
                return None;
            }

            let mut old_r = m.clone();
            let mut r = a % m; // BUG FIX: Ensure a is reduced mod m
            let mut old_s = BigInt::zero();
            let mut s = BigInt::one();

            while r != BigUint::zero() {
                let quotient = &old_r / &r;

                let temp_r = r.clone();
                r = &old_r - &quotient * &r;
                old_r = temp_r;

                let temp_s = s.clone();
                s = &old_s - &quotient.to_bigint().unwrap() * &s;
                old_s = temp_s;
            }

            if old_r != BigUint::one() {
                return None; // Not invertible
            }

            let m_int = m.to_bigint().unwrap();
            let result = (old_s % &m_int + &m_int) % &m_int;
            Some(result.to_biguint().unwrap())
        }

        let mut accum = BigUint::from(0u32);

        // 🔧 FIX 2: Use selected_shares in BOTH loops
        for &(xj, ref yj_bytes) in selected_shares.iter() {
            let mut num = BigUint::from(1u32);
            let mut den = BigUint::from(1u32);

            // 🔧 FIX 3: Inner loop uses SAME selected_shares, not all shares
            for &(xm, _) in selected_shares.iter() {
                if xm != xj {
                    let xm_u = BigUint::from(xm);
                    let xj_u = BigUint::from(xj);

                    let neg_xm = (&n - &xm_u) % &n;
                    num = (num * &neg_xm) % &n;

                    let diff = if xj_u >= xm_u {
                        &xj_u - &xm_u
                    } else {
                        &xj_u + &n - &xm_u
                    };
                    den = (den * diff.clone()) % &n;
                }
            }

            let den_inv = modinv(&den, &n)
                .ok_or_else(|| anyhow!("Denominator not invertible for share x={}", xj))?;

            let lambda = (num.clone() * den_inv) % &n;

            let yj = BigUint::from_bytes_be(yj_bytes);
            let contribution = (&lambda * &yj) % &n;

            accum = (accum + contribution) % &n;
        }

        // Debug output removed

        // Rest of your conversion logic stays the same
        let mut result = accum.to_bytes_be();
        match result.len().cmp(&32) {
            std::cmp::Ordering::Less => {
                let mut padded = vec![0u8; 32 - result.len()];
                padded.extend_from_slice(&result);
                result = padded;
            }
            std::cmp::Ordering::Greater => {
                return Err(anyhow!("Result too large: {} bytes", result.len()));
            }
            std::cmp::Ordering::Equal => {}
        }

        Ok(result)
    }

    /// TICS UserToVault per-slot aggregation + broadcast (run in a spawned task).
    /// Call with owned data after threshold is reached.
    /// NOTE: BTC UserToVault now uses finalize_btc_utv_slot with multi-input support.
    pub async fn do_aggregate_and_broadcast_for_slot(
        &mut self,
        round: u64,
        slot_id: String,
        round_slot_signatures: Vec<(String, ECDSASignature)>,
        chain_id: u64,
        slot_kind: SlotKind,
    ) -> Result<()> {
        // BTC UTV should not reach here - it uses finalize_btc_utv_slot
        if matches!(slot_kind, SlotKind::BtcUserToVault) {
            warn!(
                "⚠️ [SIGNING] BTC UserToVault slot {} should use finalize_btc_utv_slot, not this function",
                slot_id
            );
            return Err(anyhow!(
                "BTC UserToVault should use dedicated multi-input handler"
            ));
        }

        let threshold = self.threshold;
        let mut sorted: Vec<_> = round_slot_signatures.into_iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let sigs_result: Result<Vec<RecoverableSignature>> = sorted
            .iter()
            .take(threshold)
            .map(|(signer_id, ecdsa_sig)| {
                RecoverableSignature::from_compact(
                    &ecdsa_sig.signature,
                    RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                )
                .map_err(|_| anyhow::anyhow!("Invalid signature from signer {}", signer_id))
            })
            .collect();
        let threshold_sigs = sigs_result?;
        let mut peer_to_dkg_index = Vec::new();
        for (id, _) in sorted.iter().take(threshold) {
            let idx = self.calculate_dkg_index_for_peer(id).await;
            peer_to_dkg_index.push((id.clone(), idx));
        }
        let aggregated_signature = self
            .aggregate_signatures(threshold_sigs, peer_to_dkg_index)
            .await?;

        let (recovery_id, sig_bytes) = aggregated_signature.serialize_compact();
        let r_biguint = num_bigint::BigUint::from_bytes_be(&sig_bytes[0..32]);
        let s_biguint = num_bigint::BigUint::from_bytes_be(&sig_bytes[32..64]);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        let r_canonical = r_biguint.to_bytes_be();
        let s_canonical = s_biguint.to_bytes_be();
        if r_canonical.len() <= 32 {
            r[32 - r_canonical.len()..].copy_from_slice(&r_canonical);
        }
        if s_canonical.len() <= 32 {
            s[32 - s_canonical.len()..].copy_from_slice(&s_canonical);
        }
        let mut canonical_signature_bytes = [0u8; 64];
        canonical_signature_bytes[0..32].copy_from_slice(&r);
        canonical_signature_bytes[32..64].copy_from_slice(&s);
        let recid_u8 = recovery_id.to_i32() as u8;

        // Verify aggregated signature against user's group public key
        {
            // Get the tx_bytes and user_eth for this slot to compute the digest
            let slot_data = {
                let batch = self.pending.user_to_vault_tics_batch.read().await;
                batch.get(&round).and_then(|entries| {
                    entries.iter().find(|(h, ..)| h == &slot_id).map(|(_, user_eth, _chain_tx, tx_bytes)| {
                        (user_eth.clone(), tx_bytes.clone())
                    })
                })
            };
            if let Some((user_eth, tx_bytes)) = slot_data {
                // Compute the message digest (keccak256 of unsigned tx bytes)
                use sha3::Digest;
                let mut hasher = sha3::Keccak256::new();
                hasher.update(&tx_bytes);
                let tx_hash = hasher.finalize();

                info!(
                    "🔍 [SIGNING] Verifying aggregated signature for slot {} against user {} group key (digest: 0x{})",
                    slot_id, user_eth, hex::encode(&tx_hash)
                );

                // Recover the public key from the aggregated signature
                if let Ok(msg) = Message::from_digest_slice(&tx_hash) {
                    let secp = Secp256k1::new();
                    if let Ok(recovered_pk) = secp.recover_ecdsa(&msg, &aggregated_signature) {
                        let recovered_pk_hex = hex::encode(recovered_pk.serialize());
                        let pk_uncompressed = recovered_pk.serialize_uncompressed();
                        let mut keccak = sha3::Keccak256::new();
                        keccak.update(&pk_uncompressed[1..]);
                        let hash = keccak.finalize();
                        let recovered_addr = format!("0x{}", hex::encode(&hash[12..]));

                        info!(
                            "🔍 [SIGNING] Aggregated signature for slot {} recovers to pubkey: 0x{}, ETH address: {}",
                            slot_id, recovered_pk_hex, recovered_addr
                        );

                        // Compare with user's expected group key and derived address
                        if let Some(ref uim) = self.user_intent_manager {
                            if let Some(user) = uim.get_user_by_address(&user_eth).await {
                                if let Some(ref expected_derived) = user.derived_eth_address {
                                    if recovered_addr.to_lowercase() == expected_derived.to_lowercase() {
                                        info!(
                                            "✅ [SIGNING] Aggregated signature verification PASSED for slot {}: recovered {} matches derived {}",
                                            slot_id, recovered_addr, expected_derived
                                        );
                                    } else {
                                        error!(
                                            "❌ [SIGNING] Aggregated signature verification FAILED for slot {}: recovered {} != derived {}",
                                            slot_id, recovered_addr, expected_derived
                                        );
                                    }
                                }
                                if let Some(ref ugk) = user.user_group_key {
                                    use k256::elliptic_curve::sec1::ToEncodedPoint;
                                    let expected_pk_hex = hex::encode(ugk.0.to_encoded_point(true).as_bytes());
                                    info!(
                                        "🔍 [SIGNING] User {} group key: 0x{}, recovered pubkey: 0x{}",
                                        user_eth, expected_pk_hex, recovered_pk_hex
                                    );
                                }
                            }
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING] Could not recover public key from aggregated signature for slot {}",
                            slot_id
                        );
                    }
                }
            }
        }

        // TICS UserToVault only
        if let Ok(Some(signed_tx_hex)) = self
            .reconstruct_signed_tics_transaction_for_batch_slot(
                round,
                &slot_id,
                &canonical_signature_bytes,
                recid_u8,
            )
            .await
        {
            info!(
                "🎉 [SIGNING] TICS UserToVault batch slot {} (round {}) ready, broadcasting",
                slot_id, round
            );
            match Self::broadcast_tics_transaction(&signed_tx_hex, chain_id).await {
                Ok(Some(tx_hash)) => {
                    info!(
                        "✅ [SIGNING] Batch slot {} broadcasted: {}",
                        slot_id, tx_hash
                    );
                    self.store_transaction_id_for_round(
                        round,
                        &tx_hash,
                        crate::types::TransactionNetwork::TICS,
                        Some(slot_id.clone()),
                    )
                    .await;
                }
                Ok(None) => {
                    warn!("⚠️ [SIGNING] Batch slot {} broadcasted but no tx_hash", slot_id);
                }
                Err(e) => {
                    error!(
                        "❌ [SIGNING] Failed to broadcast batch slot {}: {}",
                        slot_id, e
                    );
                    self.store_transaction_error_for_round(
                        round,
                        &e.to_string(),
                        crate::types::TransactionNetwork::TICS,
                    )
                    .await;
                }
            }
        } else {
            return Err(anyhow!(
                "Failed to reconstruct TICS signed tx for slot {} round {}",
                slot_id, round
            ));
        }
        Ok(())
    }

}

#[cfg(test)]
mod aggregation_tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey, Message};
    use secp256k1::ecdsa::RecoveryId;
    use tokio::sync::mpsc;

    fn make_signing_node() -> SigningNode {
        let _ = crate::types::network::init_network_type_from_env();
        let (tx, _rx) = mpsc::channel(1);
        SigningNode::new("test-agg-node".to_string(), 2, tx)
    }

    #[test]
    fn test_lagrange_interpolate_three_shares_deterministic() {
        // 3-of-3 scenario: verify that interpolation is deterministic
        // and produces a valid 32-byte result
        let node = make_signing_node();

        let mut share1 = vec![0u8; 31];
        share1.push(10);
        let mut share2 = vec![0u8; 31];
        share2.push(19);
        let mut share3 = vec![0u8; 31];
        share3.push(32);

        let shares: Vec<(u32, Vec<u8>)> = vec![(1, share1.clone()), (2, share2.clone()), (3, share3.clone())];
        let result1 = node.lagrange_interpolate(&shares).expect("run 1");
        let result2 = node.lagrange_interpolate(&shares).expect("run 2");

        assert_eq!(result1.len(), 32, "Result must be 32 bytes");
        assert_eq!(result1, result2, "Same shares must produce same interpolation result");
    }

    #[test]
    fn test_get_compressed_signature_bytes_format() {
        let node = make_signing_node();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).expect("valid key");
        let msg = Message::from_digest_slice(&[2u8; 32]).expect("valid msg");
        let sig = secp.sign_ecdsa_recoverable(&msg, &sk);

        let bytes = node.get_compressed_signature_bytes(&sig);
        assert_eq!(bytes.len(), 65, "Compressed signature must be 65 bytes");
    }

    #[test]
    fn test_get_compressed_signature_hex_format() {
        let node = make_signing_node();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).expect("valid key");
        let msg = Message::from_digest_slice(&[2u8; 32]).expect("valid msg");
        let sig = secp.sign_ecdsa_recoverable(&msg, &sk);

        let hex_str = node.get_compressed_signature_hex(&sig);
        assert_eq!(hex_str.len(), 130, "Hex signature must be 130 chars (65 bytes * 2)");
        assert!(hex::decode(&hex_str).is_ok(), "Must be valid hex");
    }

    #[test]
    fn test_lagrange_interpolate_two_shares() {
        // Create a simple 2-of-N secret sharing scenario
        // For polynomial f(x) = secret + a*x (degree 1):
        // f(1) = secret + a
        // f(2) = secret + 2a
        // Lagrange at x=0 should recover secret
        let node = make_signing_node();

        // Use small values for testability
        // secret = 10, a = 5
        // f(1) = 15, f(2) = 20
        let mut share1 = vec![0u8; 31];
        share1.push(15);
        let mut share2 = vec![0u8; 31];
        share2.push(20);

        let shares: Vec<(u32, Vec<u8>)> = vec![(1, share1), (2, share2)];
        let result = node.lagrange_interpolate(&shares);
        assert!(result.is_ok(), "Two-share interpolation should succeed");

        let secret = result.unwrap();
        assert_eq!(secret.len(), 32);
        // The last byte should be 10 (the secret)
        assert_eq!(secret[31], 10, "Lagrange should recover the original secret");
    }
}

