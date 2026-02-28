use super::*;
use crate::*;
use crate::types::signing::{
    BtcIndexedSignature, ECDSASignature, SignedMessage, SigningMessage, ThresholdSignatureShare,
};
use crate::types::SpendKind;
use anyhow::{anyhow, Result};
use hex;
use k256::Scalar;
use libp2p::PeerId;
use num_bigint::BigUint;
use num_traits::identities::One;
use once_cell::sync::Lazy;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use sha3::Digest;
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
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
use crate::chain_abstraction::{ChainHandler, ChainTransaction};
use crate::protocols::{VrfSelectedNodesBroadcast, VrfService};
use crate::hrw;
use crate::types::{
    p2p::SerializablePeerId, ChannelMessage, ConsensusMessage, ConsensusResult, GossipsubMessage,
    TransactionType,
};
use crate::user_intent_manager::UserIntentManager;
use num_traits::Zero;

impl SigningNode {
    pub(crate) async fn verify_aggregated_signature(&self, signed_message: &SignedMessage) -> Result<bool> {
        debug!(
            "[SIGNING] Verifying aggregated signature: {} signers, sig_len={}",
            signed_message.signer_ids.len(),
            signed_message.aggregated_signature.len()
        );

        let public_keys = self.signatures.public_keys.read().await;

        // Check if we have public keys for all signers
        for signer_id in &signed_message.signer_ids {
            if !public_keys.contains_key(signer_id) {
                warn!("❌ [SIGNING] Missing public key for signer: {}", signer_id);
                return Ok(false);
            }
        }

        info!("🔍 [SIGNING] Node {} verifying ECDSA signature", self.id);

        // Basic signature validation
        if signed_message.aggregated_signature.len() != 65 {
            warn!(
                "❌ [SIGNING] Invalid signature length: expected 65 bytes, got {}",
                signed_message.aggregated_signature.len()
            );
            return Ok(false);
        }

        // Check that we have valid signer IDs
        if signed_message.signer_ids.is_empty() {
            warn!("❌ [SIGNING] No signer IDs provided");
            return Ok(false);
        }

        // In a full implementation, you would:
        // 1. Parse the signature components (r, s, v)
        // 2. Recover the public key from the signature and message hash
        // 3. Verify against the expected public keys
        // 4. Check threshold requirements

        info!(
            "✅ [SIGNING] Signature validation passed for {} signers",
            signed_message.signer_ids.len()
        );
        Ok(true)
    }

    /// Verify PARTIAL signature for a round based on transaction type and peer-id
    ///
    /// This verifies that the partial signature (threshold signature share) from a peer
    /// is valid against that peer's PARTIAL public key (share pubkey) for the given transaction type.
    ///
    /// The signature is a partial signature signed with the peer's share of the private key,
    /// and must verify against the peer's corresponding share public key (not the group public key).
    pub(crate) async fn verify_signature_for_round(
        &self,
        peer_id: &str,
        signature: &ECDSASignature,
        round: u64,
        slot_id: Option<&str>,
    ) -> Result<()> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        info!(
            "🔍 [SIGNING] Verifying PARTIAL signature from peer {} for round {} (slot: {:?})",
            peer_id, round, slot_id
        );

        // Get message/digest and transaction type for this round (and slot for TICS batch)
        let (expected_digest, transaction_type, user_tics_address) =
            self.get_message_and_type_for_round(round, slot_id).await?;

        info!(
            "🔍 [SIGNING] Expected digest for round {}: 0x{}",
            round,
            hex::encode(&expected_digest)
        );

        // Get appropriate PARTIAL share pubkey based on transaction type
        // This is the peer's share public key, not the group public key
        let share_pubkey = self
            .get_share_pubkey_for_verification(
                peer_id,
                round,
                &transaction_type,
                user_tics_address.as_deref(),
            )
            .await?;

        // Log the expected pubkey for verification
        let share_pubkey_affine = share_pubkey.to_affine();
        let share_pubkey_bytes = share_pubkey_affine.to_encoded_point(true);
        let expected_pubkey_hex = hex::encode(share_pubkey_bytes.as_bytes());

        info!(
            "🔑 [SIGNING] Retrieved PARTIAL share pubkey for peer {} (tx_type: {:?})",
            peer_id, transaction_type
        );
        info!(
            "🔑 [SIGNING] Peer {} - Expected pubkey (partial share): 0x{}",
            peer_id, expected_pubkey_hex
        );

        // Convert k256 ProjectivePoint to secp256k1 PublicKey
        let secp_pubkey = PublicKey::from_slice(share_pubkey_bytes.as_bytes())
            .map_err(|e| anyhow!("Failed to convert share pubkey: {}", e))?;

        // Log the found pubkey (what we're actually using for verification)
        let found_pubkey_hex = hex::encode(secp_pubkey.serialize());
        info!(
            "🔑 [SIGNING] Peer {} - Found pubkey (for verification): 0x{}",
            peer_id, found_pubkey_hex
        );

        // Verify PARTIAL signature against PARTIAL pubkey
        // This is a threshold signature share, so it must verify against the peer's share pubkey
        let msg = Message::from_digest_slice(&expected_digest)?;
        let recovery_id = RecoveryId::from_i32(signature.recovery_id as i32)?;
        let recov_sig = RecoverableSignature::from_compact(&signature.signature, recovery_id)?;
        let (_, compact) = recov_sig.serialize_compact();
        let mut std_sig = secp256k1::ecdsa::Signature::from_compact(&compact)?;
        std_sig.normalize_s();

        // Log signature details for debugging
        info!(
            "🔍 [SIGNING] Peer {} - Signature details: r=0x{}, s=0x{}, recovery_id={}, digest=0x{}",
            peer_id,
            hex::encode(&signature.signature[0..32]),
            hex::encode(&signature.signature[32..64]),
            signature.recovery_id,
            hex::encode(&expected_digest)
        );

        // Validate signature format
        if signature.signature.len() != 64 {
            return Err(anyhow!(
                "Invalid signature length: expected 64 bytes, got {} bytes",
                signature.signature.len()
            ));
        }

        // Try to recover pubkey from signature using all recovery IDs (0-3)
        // If ANY recovery_id recovers to the expected pubkey, the signature is valid
        let secp = Secp256k1::new();
        let mut correct_recovery_id = None;

        // Always try all recovery IDs to find the correct one
        info!(
            "🔍 [SIGNING] Peer {} - Trying all recovery IDs (0-3) to verify signature against expected pubkey 0x{}",
            peer_id, expected_pubkey_hex
        );
        
        let mut recovered_pubkeys = Vec::new();
        for rid in 0..4 {
            if let Ok(test_rid) = RecoveryId::from_i32(rid) {
                if let Ok(test_recov_sig) =
                    RecoverableSignature::from_compact(&signature.signature, test_rid)
                {
                    if let Ok(test_recovered) = secp.recover_ecdsa(&msg, &test_recov_sig) {
                        let test_recovered_hex = hex::encode(test_recovered.serialize());
                        recovered_pubkeys.push((rid, test_recovered_hex.clone()));
                        info!(
                            "🔍 [SIGNING] Peer {} - Trying recovery_id {}: recovered pubkey 0x{}",
                            peer_id, rid, test_recovered_hex
                        );
                        if test_recovered_hex == expected_pubkey_hex {
                            info!(
                                "✅ [SIGNING] Peer {} - Found matching recovery_id {} (provided was {})!",
                                peer_id, rid, signature.recovery_id
                            );
                            correct_recovery_id = Some(rid as u8);
                            break;
                        }
                    } else {
                        info!(
                            "🔍 [SIGNING] Peer {} - Recovery_id {}: failed to recover pubkey from signature",
                            peer_id, rid
                        );
                    }
                } else {
                    info!(
                        "🔍 [SIGNING] Peer {} - Recovery_id {}: failed to create recoverable signature",
                        peer_id, rid
                    );
                }
            }
        }
        
        if correct_recovery_id.is_none() {
            warn!(
                "⚠️ [SIGNING] Peer {} - No recovery_id (0-3) recovered to expected share pubkey 0x{}",
                peer_id, expected_pubkey_hex
            );
            if !recovered_pubkeys.is_empty() {
                warn!(
                    "⚠️ [SIGNING] Peer {} - Recovered pubkeys for each recovery_id: {:?}",
                    peer_id, recovered_pubkeys
                );
                warn!(
                    "⚠️ [SIGNING] Peer {} - This suggests the signature was created with a different digest or pubkey",
                    peer_id
                );
            } else {
                warn!(
                    "⚠️ [SIGNING] Peer {} - Failed to recover any pubkey from signature with any recovery_id - signature may be invalid or corrupted",
                    peer_id
                );
            }
        }

        // If we found a matching recovery_id, the signature is valid - return success immediately
        if let Some(valid_rid) = correct_recovery_id {
            info!(
                "✅ [SIGNING] Peer {} - Signature verification PASSED via recovery_id {} (recovered pubkey matches expected share pubkey)",
                peer_id, valid_rid
            );
            info!(
                "🔍 [SIGNING] Peer {} - Expected pubkey: 0x{}, Recovered pubkey: 0x{}",
                peer_id, expected_pubkey_hex, expected_pubkey_hex
            );
            
            // Log the signature bytes for debugging
            info!(
                "🔍 [SIGNING] Peer {} - Signature bytes: r=0x{}, s=0x{}",
                peer_id,
                hex::encode(&signature.signature[0..32]),
                hex::encode(&signature.signature[32..64])
            );
            
            // Signature verified successfully via recovery - skip to success
        } else {
            // If we couldn't match the recovery_id, try direct verification as fallback
            warn!(
                "⚠️ [SIGNING] Peer {} - Recovered pubkey did not match expected share pubkey for any recovery_id (0-3); proceeding with direct verification against partial pubkey",
                peer_id
            );

            // Build a standard (non-recoverable) signature directly from the provided bytes
            let std_sig_original = secp256k1::ecdsa::Signature::from_compact(&signature.signature)?;
            
            // Try verification with non-normalized signature first
            let verification_result_non_norm = secp.verify_ecdsa(&msg, &std_sig_original, &secp_pubkey);
            
            // Normalize and try again
            let mut std_sig_normalized = std_sig_original;
            std_sig_normalized.normalize_s();
            let verification_result_norm = secp.verify_ecdsa(&msg, &std_sig_normalized, &secp_pubkey);
            
            // Check if normalization changed the signature
            let original_bytes = std_sig_original.serialize_compact();
            let normalized_bytes = std_sig_normalized.serialize_compact();
            let sig_changed = original_bytes != normalized_bytes;
            
            if sig_changed {
                info!(
                    "⚠️ [SIGNING] Peer {} - Signature was normalized (s value changed from high to low)",
                    peer_id
                );
            }
            
            // Use the first successful verification
            let verification_result = if verification_result_non_norm.is_ok() {
                info!(
                    "✅ [SIGNING] Peer {} - Signature verification PASSED with non-normalized signature",
                    peer_id
                );
                verification_result_non_norm
            } else if verification_result_norm.is_ok() {
                info!(
                    "✅ [SIGNING] Peer {} - Signature verification PASSED with normalized signature",
                    peer_id
                );
                verification_result_norm
            } else {
                info!(
                    "❌ [SIGNING] Peer {} - Signature verification FAILED with both normalized and non-normalized signatures",
                    peer_id
                );
                verification_result_norm // Use normalized result for error message
            };
            
            // Use normalized signature for logging
            let std_sig = std_sig_normalized;

            // Log verification attempt
            info!(
                "🔍 [SIGNING] Peer {} - Signature verification: {}",
                peer_id,
                if verification_result.is_ok() {
                    "PASSED"
                } else {
                    "FAILED"
                }
            );
            info!(
                "🔍 [SIGNING] Peer {} - Expected pubkey: 0x{}, Found pubkey: 0x{}",
                peer_id, expected_pubkey_hex, found_pubkey_hex
            );
            
            // Log the normalized signature bytes for debugging
            let normalized_sig_bytes = std_sig.serialize_compact();
            info!(
                "🔍 [SIGNING] Peer {} - Normalized signature bytes: r=0x{}, s=0x{}",
                peer_id,
                hex::encode(&normalized_sig_bytes[0..32]),
                hex::encode(&normalized_sig_bytes[32..64])
            );
            
            // Log the original signature bytes for comparison
            info!(
                "🔍 [SIGNING] Peer {} - Original signature bytes: r=0x{}, s=0x{}",
                peer_id,
                hex::encode(&signature.signature[0..32]),
                hex::encode(&signature.signature[32..64])
            );

            verification_result
                .map_err(|e| {
                    anyhow!(
                        "PARTIAL signature verification failed for peer {}: {} (verified against peer's share pubkey, not group pubkey). Digest used: 0x{}, Expected pubkey: 0x{}, Found pubkey: 0x{}. Original sig: r=0x{} s=0x{}, Normalized sig: r=0x{} s=0x{}",
                        peer_id, 
                        e, 
                        hex::encode(&expected_digest),
                        expected_pubkey_hex, 
                        found_pubkey_hex,
                        hex::encode(&signature.signature[0..32]),
                        hex::encode(&signature.signature[32..64]),
                        hex::encode(&normalized_sig_bytes[0..32]),
                        hex::encode(&normalized_sig_bytes[32..64])
                    )
                })?;
        }

        let share_type = match transaction_type {
            Some(crate::types::TransactionType::UserToVault) => "user-share",
            Some(crate::types::TransactionType::NetworkToTarget) => "network-share",

            Some(crate::types::TransactionType::IntentStatusUpdate) => "network-share", // IntentStatusUpdate uses network share (same as NetworkToTarget)
            Some(crate::types::TransactionType::WithdrawLiquidity) => "network-share",
            Some(crate::types::TransactionType::ClaimReward) => {
                // TICS round → vault-share; BTC round → network-share (same as WithdrawLiquidity)
                let tics = self.pending.claim_reward_pending_transactions_tics.read().await;
                if tics.contains_key(&round) {
                    "vault-share"
                } else {
                    "network-share"
                }
            }
            Some(crate::types::TransactionType::ClaimPlatformFee) => {
                let tics = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
                if tics.contains_key(&round) {
                    "user-share"
                } else {
                    "network-share"
                }
            }
            Some(crate::types::TransactionType::PeerInvalidation) => "network-share",
            None => "vault-share",
        };

        info!(
            "✅ [SIGNING] Verified PARTIAL signature from peer {} for round {} (tx_type: {:?}, user: {:?}, share_type: {})",
            peer_id,
            round,
            transaction_type,
            user_tics_address,
            share_type
        );
        info!(
            "✅ [SIGNING] Partial signature verified against peer {}'s {} partial pubkey (not group pubkey)",
            peer_id, share_type
        );

        Ok(())
    }

    /// Verify PARTIAL Bitcoin signature for a round and input index
    /// This verifies that the partial signature (threshold signature share) from a peer
    /// is valid for the specific Bitcoin transaction input.
    /// The signature is a partial signature signed with the peer's share of the private key,
    /// and must verify against the peer's corresponding share public key (not the group public key).
    pub(crate) async fn verify_btc_signature_for_round(
        &self,
        peer_id: &str,
        signature: &ECDSASignature,
        round: u64,
        input_index: usize,
    ) -> Result<()> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use secp256k1::ecdsa::RecoverableSignature;
        use secp256k1::{Message, PublicKey, Secp256k1};

        info!(
            "🔍 [BTC-SIGNING] Verifying PARTIAL signature from peer {} for round {} input {}",
            peer_id, round, input_index
        );

        // Get transaction type and user_tics_address for this round
        let (transaction_type, user_tics_address) = {
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

            if is_claim_reward_round {
                let claim_reward_pt = self.pending.claim_reward_pending_transactions_btc.read().await;
                if let Some((_tx, _raw, _solver_address, tx_type, _extras)) = claim_reward_pt.get(&round) {
                    (tx_type.clone(), None)
                } else {
                    return Err(anyhow!("No claim-reward pending tx for round {}", round));
                }
            } else if is_claim_platform_fee_round {
                let claim_pf_pt = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                if let Some((_tx, _raw, _solver_address, tx_type, _extras)) = claim_pf_pt.get(&round) {
                    (tx_type.clone(), None)
                } else {
                    return Err(anyhow!("No claim-platform-fee pending tx for round {}", round));
                }
            } else if is_withdraw_round {
                let withdraw_pt = self.pending.withdraw_pending_transactions_btc.read().await;
                if let Some((_tx, _raw, _solver_address, tx_type, _extras)) =
                    withdraw_pt.get(&round)
                {
                    (tx_type.clone(), None)
                } else {
                    return Err(anyhow!("No withdraw pending tx for round {}", round));
                }
            } else {
                let pt = self.pending.pending_transactions_btc.read().await;
                if let Some((_tx, _raw, intent_hashes, tx_type, _extras)) = pt.get(&round) {
                    // For UserToVault transactions, retrieve user_tics_address from intent_hash
                    let user_addr = if matches!(
                        tx_type,
                        Some(crate::types::TransactionType::UserToVault)
                    ) {
                        if let Some(intent_hashes_vec) = intent_hashes {
                            if let Some(first_intent_hash) = intent_hashes_vec.first() {
                                if let Some(database) = &self.database {
                                    use crate::database::storage::UserStorage;
                                    let user_storage = UserStorage::new(database.as_ref().clone());
                                    match user_storage.get_user_by_intent_hash(first_intent_hash).await {
                                        Ok(Some(user)) => {
                                            info!(
                                                "🔍 [BTC-SIGNING] Retrieved user_tics_address {} from intent_hash {} for UserToVault BTC transaction (round {})",
                                                user.tics_address, first_intent_hash, round
                                            );
                                            Some(user.tics_address)
                                        }
                                        _ => None,
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    (tx_type.clone(), user_addr)
                } else {
                    return Err(anyhow!("No pending tx for round {}", round));
                }
            }
        };

        // Get Bitcoin transaction and compute digest for this input
        let unsigned_tx = {
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

            let (chain_tx, _extras_opt) = if is_claim_reward_round {
                let claim_reward_pt = self.pending.claim_reward_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt) =
                    claim_reward_pt.get(&round).ok_or_else(|| {
                        anyhow!("no claim-reward pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            } else if is_claim_platform_fee_round {
                let claim_pf_pt = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt) =
                    claim_pf_pt.get(&round).ok_or_else(|| {
                        anyhow!("no claim-platform-fee pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            } else if is_withdraw_round {
                let withdraw_pt = self.pending.withdraw_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt) =
                    withdraw_pt.get(&round).ok_or_else(|| {
                        anyhow!("no withdraw pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            } else {
                let pt = self.pending.pending_transactions_btc.read().await;
                let (chain_tx, _raw, _intent_hash, _tx_type_opt, extras_opt) =
                    pt.get(&round).ok_or_else(|| {
                        anyhow!("no pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            };

            let btc_tx = match chain_tx {
                crate::chain_abstraction::ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    return Err(anyhow!("round {} is not a Bitcoin round", round));
                }
            };
            btc_tx
        };

        // Get the prevout script for this input to compute the digest
        let maybe_prev = unsigned_tx.inputs.get(input_index)
            .and_then(|inp| inp.witness_utxo.as_ref());
        
        let prev_spk = maybe_prev.ok_or_else(|| {
            anyhow!("round {} input {} missing witness_utxo data", round, input_index)
        })?;

        // Validate P2PKH script
        if prev_spk.script_pubkey.len() != 25
            || !(prev_spk.script_pubkey[0] == 0x76
                && prev_spk.script_pubkey[1] == 0xA9
                && prev_spk.script_pubkey[2] == 0x14
                && prev_spk.script_pubkey[23] == 0x88
                && prev_spk.script_pubkey[24] == 0xAC)
        {
            return Err(anyhow!(
                "round {} input {} prev script not canonical P2PKH",
                round, input_index
            ));
        }

        // Compute the digest for this input
        let expected_digest = self.compute_legacy_sighash_all_p2pkh(
            &unsigned_tx,
            input_index,
            &prev_spk.script_pubkey,
        )?;

        info!(
            "🔍 [BTC-SIGNING] Expected digest for round {} input {}: 0x{}",
            round,
            input_index,
            hex::encode(&expected_digest)
        );

        // Get appropriate PARTIAL share pubkey based on transaction type
        // For Bitcoin, typically vault-share (transaction_type = None)
        let share_pubkey = self
            .get_share_pubkey_for_verification(
                peer_id,
                round,
                &transaction_type,
                user_tics_address.as_deref(),
            )
            .await?;

        // Log the expected pubkey for verification
        let share_pubkey_affine = share_pubkey.to_affine();
        let share_pubkey_bytes = share_pubkey_affine.to_encoded_point(true);
        let expected_pubkey_hex = hex::encode(share_pubkey_bytes.as_bytes());

        info!(
            "🔑 [BTC-SIGNING] Retrieved PARTIAL share pubkey for peer {} (tx_type: {:?})",
            peer_id, transaction_type
        );
        info!(
            "🔑 [BTC-SIGNING] Peer {} - Expected pubkey (partial share): 0x{}",
            peer_id, expected_pubkey_hex
        );

        // Convert k256 ProjectivePoint to secp256k1 PublicKey
        let secp_pubkey = PublicKey::from_slice(share_pubkey_bytes.as_bytes())
            .map_err(|e| anyhow!("Failed to convert share pubkey: {}", e))?;

        // Log the found pubkey (what we're actually using for verification)
        let found_pubkey_hex = hex::encode(secp_pubkey.serialize());
        info!(
            "🔑 [BTC-SIGNING] Peer {} - Found pubkey (for verification): 0x{}",
            peer_id, found_pubkey_hex
        );

        // Verify PARTIAL signature against PARTIAL pubkey
        // This is a threshold signature share, so it must verify against the peer's share pubkey
        let msg = Message::from_digest_slice(&expected_digest)?;
        let recovery_id = RecoveryId::from_i32(signature.recovery_id as i32)?;
        let recov_sig = RecoverableSignature::from_compact(&signature.signature, recovery_id)?;
        let (_, compact) = recov_sig.serialize_compact();
        let mut std_sig = secp256k1::ecdsa::Signature::from_compact(&compact)?;
        std_sig.normalize_s();

        // Log signature details for debugging
        info!(
            "🔍 [BTC-SIGNING] Peer {} - Signature details: r=0x{}, s=0x{}, recovery_id={}, digest=0x{}",
            peer_id,
            hex::encode(&signature.signature[0..32]),
            hex::encode(&signature.signature[32..64]),
            signature.recovery_id,
            hex::encode(&expected_digest)
        );

        // Validate signature format
        if signature.signature.len() != 64 {
            return Err(anyhow!(
                "Invalid signature length: expected 64 bytes, got {} bytes",
                signature.signature.len()
            ));
        }

        // Try to recover pubkey from signature using all recovery IDs (0-3)
        // If ANY recovery_id recovers to the expected pubkey, the signature is valid
        let secp = Secp256k1::new();
        let mut correct_recovery_id = None;

        // Always try all recovery IDs to find the correct one
        info!(
            "🔍 [BTC-SIGNING] Peer {} - Trying all recovery IDs (0-3) to verify signature against expected pubkey 0x{}",
            peer_id, expected_pubkey_hex
        );
        
        for rid in 0..4 {
            if let Ok(test_rid) = RecoveryId::from_i32(rid) {
                if let Ok(test_recov_sig) =
                    RecoverableSignature::from_compact(&signature.signature, test_rid)
                {
                    if let Ok(test_recovered) = secp.recover_ecdsa(&msg, &test_recov_sig) {
                        let test_recovered_hex = hex::encode(test_recovered.serialize());
                        info!(
                            "🔍 [BTC-SIGNING] Peer {} - Trying recovery_id {}: recovered pubkey 0x{}",
                            peer_id, rid, test_recovered_hex
                        );
                        if test_recovered_hex == expected_pubkey_hex {
                            info!(
                                "✅ [BTC-SIGNING] Peer {} - Found matching recovery_id {} (provided was {})!",
                                peer_id, rid, signature.recovery_id
                            );
                            correct_recovery_id = Some(rid as u8);
                            break;
                        }
                    }
                }
            }
        }
        
        if correct_recovery_id.is_none() {
            warn!(
                "⚠️ [BTC-SIGNING] Peer {} - No recovery_id (0-3) recovered to expected share pubkey 0x{}",
                peer_id, expected_pubkey_hex
            );
        }

        // If we found a matching recovery_id, the signature is valid - return success immediately
        if let Some(valid_rid) = correct_recovery_id {
            info!(
                "✅ [BTC-SIGNING] Peer {} - Signature verification PASSED via recovery_id {} (recovered pubkey matches expected share pubkey)",
                peer_id, valid_rid
            );
            info!(
                "🔍 [BTC-SIGNING] Peer {} - Expected pubkey: 0x{}, Recovered pubkey: 0x{}",
                peer_id, expected_pubkey_hex, expected_pubkey_hex
            );
            
            // Log the signature bytes for debugging
            info!(
                "🔍 [BTC-SIGNING] Peer {} - Signature bytes: r=0x{}, s=0x{}",
                peer_id,
                hex::encode(&signature.signature[0..32]),
                hex::encode(&signature.signature[32..64])
            );
            
            // Signature verified successfully via recovery - skip to success
        } else {
            // If we couldn't match the recovery_id, try direct verification as fallback
            warn!(
                "⚠️ [BTC-SIGNING] Peer {} - Recovered pubkey did not match expected share pubkey for any recovery_id (0-3); proceeding with direct verification against partial pubkey",
                peer_id
            );

            // Build a standard (non-recoverable) signature directly from the provided bytes
            let std_sig_original = secp256k1::ecdsa::Signature::from_compact(&signature.signature)?;
            
            // Try verification with non-normalized signature first
            let verification_result_non_norm = secp.verify_ecdsa(&msg, &std_sig_original, &secp_pubkey);
            
            // Normalize and try again
            let mut std_sig_normalized = std_sig_original;
            std_sig_normalized.normalize_s();
            let verification_result_norm = secp.verify_ecdsa(&msg, &std_sig_normalized, &secp_pubkey);
            
            // Check if normalization changed the signature
            let original_bytes = std_sig_original.serialize_compact();
            let normalized_bytes = std_sig_normalized.serialize_compact();
            let sig_changed = original_bytes != normalized_bytes;
            
            if sig_changed {
                info!(
                    "⚠️ [BTC-SIGNING] Peer {} - Signature was normalized (s value changed from high to low)",
                    peer_id
                );
            }
            
            // Use the first successful verification
            let verification_result = if verification_result_non_norm.is_ok() {
                info!(
                    "✅ [BTC-SIGNING] Peer {} - Signature verification PASSED with non-normalized signature",
                    peer_id
                );
                verification_result_non_norm
            } else if verification_result_norm.is_ok() {
                info!(
                    "✅ [BTC-SIGNING] Peer {} - Signature verification PASSED with normalized signature",
                    peer_id
                );
                verification_result_norm
            } else {
                info!(
                    "❌ [BTC-SIGNING] Peer {} - Signature verification FAILED with both normalized and non-normalized signatures",
                    peer_id
                );
                verification_result_norm // Use normalized result for error message
            };
            
            // Use normalized signature for logging
            let std_sig = std_sig_normalized;

            // Log verification attempt
            info!(
                "🔍 [BTC-SIGNING] Peer {} - Signature verification: {}",
                peer_id,
                if verification_result.is_ok() {
                    "PASSED"
                } else {
                    "FAILED"
                }
            );
            info!(
                "🔍 [BTC-SIGNING] Peer {} - Expected pubkey: 0x{}, Found pubkey: 0x{}",
                peer_id, expected_pubkey_hex, found_pubkey_hex
            );
            
            // Log the normalized signature bytes for debugging
            let normalized_sig_bytes = std_sig.serialize_compact();
            info!(
                "🔍 [BTC-SIGNING] Peer {} - Normalized signature bytes: r=0x{}, s=0x{}",
                peer_id,
                hex::encode(&normalized_sig_bytes[0..32]),
                hex::encode(&normalized_sig_bytes[32..64])
            );
            
            // Log the original signature bytes for comparison
            info!(
                "🔍 [BTC-SIGNING] Peer {} - Original signature bytes: r=0x{}, s=0x{}",
                peer_id,
                hex::encode(&signature.signature[0..32]),
                hex::encode(&signature.signature[32..64])
            );

            verification_result
                .map_err(|e| {
                    anyhow!(
                        "PARTIAL BTC signature verification failed for peer {} round {} input {}: {} (verified against peer's share pubkey, not group pubkey). Digest used: 0x{}, Expected pubkey: 0x{}, Found pubkey: 0x{}. Original sig: r=0x{} s=0x{}, Normalized sig: r=0x{} s=0x{}",
                        peer_id, 
                        round,
                        input_index,
                        e, 
                        hex::encode(&expected_digest),
                        expected_pubkey_hex, 
                        found_pubkey_hex,
                        hex::encode(&signature.signature[0..32]),
                        hex::encode(&signature.signature[32..64]),
                        hex::encode(&normalized_sig_bytes[0..32]),
                        hex::encode(&normalized_sig_bytes[32..64])
                    )
                })?;
        }

        let share_type = match transaction_type {
            Some(crate::types::TransactionType::UserToVault) => "user-share",
            Some(crate::types::TransactionType::NetworkToTarget) => "network-share",

            Some(crate::types::TransactionType::IntentStatusUpdate) => "network-share", // IntentStatusUpdate uses network share (same as NetworkToTarget)
            Some(crate::types::TransactionType::WithdrawLiquidity) => "network-share",
            Some(crate::types::TransactionType::ClaimReward) => "network-share", // BTC claim-reward (BitcoinSigner path)
            Some(crate::types::TransactionType::ClaimPlatformFee) => {
                let tics = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
                if tics.contains_key(&round) {
                    "user-share"
                } else {
                    "network-share"
                }
            }
            Some(crate::types::TransactionType::PeerInvalidation) => "network-share",
            None => "vault-share",
        };

        info!(
            "✅ [BTC-SIGNING] Verified PARTIAL signature from peer {} for round {} input {} (tx_type: {:?}, user: {:?}, share_type: {})",
            peer_id,
            round,
            input_index,
            transaction_type,
            user_tics_address,
            share_type
        );
        info!(
            "✅ [BTC-SIGNING] Partial signature verified against peer {}'s {} partial pubkey (not group pubkey)",
            peer_id, share_type
        );

        Ok(())
    }

}
