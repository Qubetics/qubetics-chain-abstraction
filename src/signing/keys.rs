use super::*;
use anyhow::{anyhow, Result};
use hex;
use k256::Scalar;
use num_bigint::BigUint;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
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
use secp256k1::ecdsa::RecoveryId;
use crate::types::TransactionType;

impl SigningNode {
    pub fn generate_key_pair(&mut self) -> Result<()> {
        self.key_store.generate_key_pair(&self.id)
    }

    pub fn set_private_key(&mut self, private_key: SecretKey) {
        self.key_store.set_private_key(private_key, &self.id);
    }

    pub fn set_private_key_from_scalar(&mut self, scalar: Scalar) {
        if let Err(err) = self.key_store.set_private_key_from_scalar(scalar, &self.id) {
            error!(
                "❌ [SIGNING] Node {} failed to set private key from scalar: {}",
                self.id, err
            );
        }
    }

    pub fn derive_secp_secret(scalar: &Scalar) -> Result<SecretKey> {
        KeyStore::derive_secp_secret(scalar)
    }

    pub fn add_public_key(&self, node_id: String, public_key: PublicKey) {
        let node_id_clone = node_id.clone();
        tokio::spawn({
            let public_keys = self.signatures.public_keys.clone();
            async move {
                public_keys.write().await.insert(node_id, public_key);
            }
        });
        info!(
            "🔑 [SIGNING] Node {} added public key for {}",
            self.id, node_id_clone
        );
    }

    pub fn has_private_key(&self) -> bool {
        self.key_store.has_private_key()
    }

    /// Check if this node has a DKG secret share in storage.
    /// Returns true for initial DKG participants, false for observer nodes.
    pub async fn has_dkg_share(&self) -> bool {
        if let Some(dkg_storage) = &self.dkg_storage {
            dkg_storage.get_final_secret().await.ok().flatten().is_some()
        } else {
            false
        }
    }

    /// Helper: Get network group key from key store or database
    pub(crate) fn get_network_group_key_from_store_or_db(&self) -> Option<k256::ProjectivePoint> {
        use crate::database::keys;
        use crate::types::SerializablePoint;

        if let Some(key) = self.key_store.get_group_public_key() {
            Some(key)
        } else if let Some(database) = &self.database {
            match database.get_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC) {
                Ok(Some(serialized)) => Some(serialized.0.into()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Helper: Encode group key to compressed bytes
    pub(crate) fn encode_group_key_to_compressed_bytes(group_key: k256::ProjectivePoint) -> Vec<u8> {
        let encoded_point = k256::EncodedPoint::from(group_key.to_affine());
        encoded_point.compress().to_bytes().to_vec()
    }

    /// Get the appropriate public key bytes based on transaction type
    pub(crate) async fn get_group_public_key_bytes(
        &self,
        transaction_type: Option<crate::types::TransactionType>,
        user_tics_address: Option<String>,
    ) -> Result<Vec<u8>> {
        use crate::types::TransactionType;

        match transaction_type {
            Some(TransactionType::UserToVault) => {
                if let Some(user_addr) = &user_tics_address {
                    if let Some(user_intent_manager) = &self.user_intent_manager {
                        if let Some(user) = user_intent_manager.get_user_by_address(user_addr).await
                        {
                            if let Some(user_group_key) = &user.user_group_key {
                                let affine_point = user_group_key.0;
                                let encoded_point = k256::EncodedPoint::from(affine_point);
                                return Ok(encoded_point.compress().to_bytes().to_vec());
                            }
                        }
                    }

                    Err(anyhow!(
                        "User {} has no group key available - ensure user registration and key derivation is completed",
                        user_addr
                    ))
                } else {
                    Err(anyhow!("UserToVault transaction requires user_tics_address"))
                }
            }
            Some(TransactionType::NetworkToTarget) 
            | Some(TransactionType::IntentStatusUpdate)
            | Some(TransactionType::WithdrawLiquidity)
            | Some(TransactionType::ClaimReward)
            | Some(TransactionType::ClaimPlatformFee)
            | Some(TransactionType::PeerInvalidation) => {
                // All these transaction types use network group key
                self.get_network_group_key_from_store_or_db()
                    .map(Self::encode_group_key_to_compressed_bytes)
                    .ok_or_else(|| anyhow!(
                        "DKG group public key not available for {:?} transaction - ensure DKG process is completed",
                        transaction_type
                    ))
            }
            None => Err(anyhow!(
                "Transaction type is required for group public key retrieval"
            )),
        }
    }

    /// Set the DKG group public key
    pub fn set_group_public_key(&mut self, group_key: k256::ProjectivePoint) {
        self.key_store.set_group_public_key(group_key, &self.id);
    }

    /// Set the vault group public key
    pub fn set_vault_group_key(&mut self, vault_group_key: k256::ProjectivePoint) {
        self.key_store
            .set_vault_group_key(vault_group_key, &self.id);
    }

    pub async fn get_network_group_public_key(&self) -> Result<k256::ProjectivePoint> {
        use crate::database::keys;
        use crate::types::SerializablePoint;

        if let Some(group_key) = self.key_store.get_group_public_key() {
            return Ok(group_key);
        }

        if let Some(database) = &self.database {
            if let Ok(Some(serialized)) =
                database.get_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC)
            {
                return Ok(serialized.0.into());
            }
        }

        Err(anyhow!(
            "DKG group public key not available - ensure DKG process is completed",
        ))
    }

    pub async fn get_vault_group_public_key(&self) -> Result<k256::ProjectivePoint> {
        use crate::database::keys;
        use crate::types::SerializablePoint;

        if let Some(vault_key) = self.key_store.get_vault_group_key() {
            return Ok(vault_key);
        }

        if let Some(database) = &self.database {
            if let Ok(Some(serialized)) =
                database.get_string::<SerializablePoint>(keys::DKG_VAULT_GROUP_KEY)
            {
                return Ok(serialized.0.into());
            }
        }

        Err(anyhow!(
            "Liquidity operator group public key not available - ensure liquidity operator key is initialized",
        ))
    }

    /// Get the DKG group public key
    pub fn get_group_public_key(&self) -> Option<k256::ProjectivePoint> {
        self.key_store.get_group_public_key()
    }

    /// Get the vault group public key
    pub fn get_vault_group_key(&self) -> Option<k256::ProjectivePoint> {
        self.key_store.get_vault_group_key()
    }

    /// Get appropriate PARTIAL share pubkey for verification based on transaction type
    ///
    /// Returns the peer's partial public key (share pubkey) that corresponds to the transaction type.
    /// This is used to verify the peer's partial signature (threshold signature share).
    ///
    /// IMPORTANT: This returns the PARTIAL share pubkey, not the group pubkey.
    /// The partial signature must verify against this partial pubkey.
    pub(crate) async fn get_share_pubkey_for_verification(
        &self,
        peer_id: &str,
        round: u64,
        transaction_type: &Option<TransactionType>,
        user_tics_address: Option<&str>,
    ) -> Result<k256::ProjectivePoint> {
        use crate::database::DkgStorage;

        let database = self
            .database
            .as_ref()
            .ok_or_else(|| anyhow!("Database not available"))?
            .as_ref();
        let dkg_storage = DkgStorage::new(database.clone());

        // Determine which PARTIAL share pubkey to use based on transaction type
        // Mapping:
        // - UserToVault → per-node-user-share PARTIAL pubkey verification
        // - NetworkToTarget → per-node-network-share PARTIAL pubkey verification
        // - WithdrawLiquidity/ClaimReward → per-node-network-share or vault-share (by round) PARTIAL pubkey verification
        // Works for both ETH/TICS and BTC transactions
        match transaction_type {
            Some(crate::types::TransactionType::UserToVault) => {
                // UserToVault → per-node-user-share pubkey
                if let Some(user_addr) = user_tics_address {
                    // Try to get the stored user share pubkey first
                    match dkg_storage.get_user_share_pubkey(peer_id, user_addr).await {
                        Ok(Some(pubkey)) => Ok(pubkey),
                        Ok(None) => {
                            // User share pubkey not found - compute it on-the-fly
                            warn!(
                                "⚠️ [SIGNING] User share pubkey not found for peer {} and user {} - computing on-the-fly",
                                peer_id, user_addr
                            );

                            // Get user's HMAC constant from user storage
                            use crate::database::storage::UserStorage;
                            let user_storage = UserStorage::new(database.clone());
                            let user = user_storage
                                .get_user(user_addr)
                                .await?
                                .ok_or_else(|| {
                                    anyhow!(
                                        "User {} not found in database - cannot compute user share pubkey for peer {}",
                                        user_addr, peer_id
                                    )
                                })?;

                            // Compute user share pubkeys for this user (this will compute for all peers)
                            dkg_storage
                                .compute_and_store_user_share_pubkeys_for_user(
                                    user_addr,
                                    &user.hmac_constant,
                                )
                                .await?;

                            // Now retrieve the pubkey
                            dkg_storage
                                .get_user_share_pubkey(peer_id, user_addr)
                                .await?
                                .ok_or_else(|| {
                                    anyhow!(
                                        "Failed to compute user share pubkey for peer {} and user {} (UserToVault transaction)",
                                        peer_id,
                                        user_addr
                                    )
                                })
                        }
                        Err(e) => Err(anyhow!(
                            "Failed to retrieve user share pubkey for peer {} and user {}: {}",
                            peer_id,
                            user_addr,
                            e
                        )),
                    }
                } else {
                    return Err(anyhow!(
                        "UserToVault transaction requires user_tics_address for user share pubkey verification (peer: {})",
                        peer_id
                    ));
                }
            }
            Some(crate::types::TransactionType::NetworkToTarget)
            | Some(crate::types::TransactionType::IntentStatusUpdate)
            | Some(crate::types::TransactionType::PeerInvalidation) => {
                // NetworkToTarget, IntentStatusUpdate, and PeerInvalidation → per-node-network-share pubkey
                dkg_storage
                    .get_network_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "Network share pubkey not found for peer {} (NetworkToTarget/IntentStatusUpdate/PeerInvalidation transaction)",
                            peer_id
                        )
                    })
            }
            Some(crate::types::TransactionType::WithdrawLiquidity) => {
                // TICS withdraw batch (contract removeLiquidity) is signed with vault (liquidity operator) key;
                // BTC withdraw is signed with network key. Use vault-share when round is in withdraw_pending_transactions_tics.
                let is_tics_withdraw_round = {
                    let tics = self.pending.withdraw_pending_transactions_tics.read().await;
                    tics.contains_key(&round)
                };
                if is_tics_withdraw_round {
                    info!(
                        "🔑 [SIGNING] WithdrawLiquidity round {} is TICS contract withdraw; using liquidity operator (vault) share pubkey for peer {}",
                        round, peer_id
                    );
                    dkg_storage
                        .get_vault_share_pubkey(peer_id)
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "Vault share pubkey not found for peer {} (TICS withdraw round {})",
                                peer_id, round
                            )
                        })
                } else {
                    dkg_storage
                        .get_network_share_pubkey(peer_id)
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "Network share pubkey not found for peer {} (BTC withdraw / WithdrawLiquidity)",
                                peer_id
                            )
                        })
                }
            }
            Some(crate::types::TransactionType::ClaimReward) => {
                // ClaimReward: TICS vs BTC determined by which pending store has the round (same as WithdrawLiquidity)
                let is_tics_claim_round = {
                    let tics = self.pending.claim_reward_pending_transactions_tics.read().await;
                    tics.contains_key(&round)
                };
                if is_tics_claim_round {
                    info!(
                        "🔑 [SIGNING] ClaimReward round {} is TICS; using liquidity operator (vault) share pubkey for peer {}",
                        round, peer_id
                    );
                    dkg_storage
                        .get_vault_share_pubkey(peer_id)
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "Vault share pubkey not found for peer {} (ClaimReward TICS round {})",
                                peer_id, round
                            )
                        })
                } else {
                    dkg_storage
                        .get_network_share_pubkey(peer_id)
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "Network share pubkey not found for peer {} (ClaimReward BTC round {})",
                                peer_id, round
                            )
                        })
                }
            }
            Some(crate::types::TransactionType::ClaimPlatformFee) => {
                let is_tics_round = {
                    let tics = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
                    tics.contains_key(&round)
                };
                if is_tics_round {
                    // TICS platform fee: admin-specific user-share pubkey
                    if let Some(admin_addr) = user_tics_address {
                        dkg_storage
                            .get_user_share_pubkey(peer_id, admin_addr)
                            .await?
                            .ok_or_else(|| {
                                anyhow!(
                                    "Admin share pubkey not found for peer {} and admin {} (ClaimPlatformFee TICS round {})",
                                    peer_id, admin_addr, round
                                )
                            })
                    } else {
                        Err(anyhow!(
                            "ClaimPlatformFee TICS round {} requires admin tics_address for share pubkey verification (peer: {})",
                            round, peer_id
                        ))
                    }
                } else {
                    // BTC platform fee: network share (existing behavior)
                    dkg_storage
                        .get_network_share_pubkey(peer_id)
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "Network share pubkey not found for peer {} (ClaimPlatformFee BTC round {})",
                                peer_id, round
                            )
                        })
                }
            }
            None => {
                // Contract transaction (transaction_type = None) → use vault share pubkey
                info!(
                    "🔑 [SIGNING] Contract transaction detected, using liquidity operator share pubkey for peer {}",
                    peer_id
                );
                dkg_storage
                    .get_vault_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| anyhow!("Liquidity operator share pubkey not found for peer {} (contract transaction)", peer_id))
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn create_ecdsa_signature_with_signing_key_deprecated(
        &self,
        message: &Message,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        // SECURITY WARNING: This function uses a fixed nonce which is insecure!
        // It is kept only for historical reference and MUST NOT be used in production.
        error!("🔴 SECURITY: create_ecdsa_signature_with_signing_key_DEPRECATED called - THIS IS A SECURITY VULNERABILITY!");

        // 1) Use provided signing key and context
        let sk = signing_key;
        let secp = Secp256k1::new();

        // 2) INSECURE: Fixed nonce k = 0x42…42 - NEVER use in production!
        let k_bytes = [0x42u8; 32];
        let sec_nonce =
            SecretKey::from_slice(&k_bytes).map_err(|e| anyhow!("invalid nonce slice: {}", e))?;

        // 3) R = k·G
        let r = PublicKey::from_secret_key(&secp, &sec_nonce);
        let rser = r.serialize_uncompressed(); // [0x04 || X(32) || Y(32)]
        // info!("[SIGNING] R serialized: {:?}", rser); // Redacted for security
        if BigUint::from_bytes_be(&rser) == BigUint::from(0u32) {
            return Err(anyhow!("r is zero, need new nonce"));
        }

        // 4) r = X mod n
        let mut r_bytes: [u8; 32] = [0u8; 32];
        r_bytes.copy_from_slice(&rser[1..33]);
        let r = BigUint::from_bytes_be(&r_bytes);

        // 5) z = message hash as BigUint
        let z = BigUint::from_bytes_be(message.as_ref());

        // 6) x = private key as BigUint
        let sk_bytes = sk.secret_bytes();
        let x = BigUint::from_bytes_be(&sk_bytes);

        // 7) Curve order n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .ok_or_else(|| anyhow!("failed to parse secp256k1 curve order"))?;

        // 8) k⁻¹ mod n
        let k_inv = BigUint::from_bytes_be(&k_bytes)
            .modinv(&n)
            .ok_or_else(|| anyhow!("nonce not invertible"))?;

        // 9) s = k⁻¹·(z + r·x) mod n
        let s = (&k_inv * (&z + (&r * &x) % &n)) % &n;

        // 10) Serialize r‖s into 64-byte array
        let mut sig_bytes = [0u8; 64];
        let r_be: Vec<u8> = r.to_bytes_be();
        let s_be = s.to_bytes_be();
        sig_bytes[32 - r_be.len()..32].copy_from_slice(&r_be);
        sig_bytes[64 - s_be.len()..64].copy_from_slice(&s_be);

        // 11) Compute RecoveryId from R_y parity
        let y_parity = (rser[64] & 1) as i32;
        let rid: RecoveryId =
            RecoveryId::from_i32(y_parity).map_err(|e| anyhow!("invalid recovery ID: {}", e))?;

        // 12) Build the recoverable signature
        let rec_sig = RecoverableSignature::from_compact(&sig_bytes, rid)
            .map_err(|e| anyhow!("invalid compact signature: {}", e))?;

        Ok(rec_sig)
    }

    pub fn create_ecdsa_signature_with_nonce(
        &self,
        message: &Message,
        signing_key: &SecretKey,
        nonce: &crate::types::nonce::NonceTuple,
    ) -> Result<RecoverableSignature> {
        Self::enforce_nonce_digest_uniqueness(signing_key, &nonce.tuple_id, message.as_ref())?;

        // 1) Extract r, k, and k_inv from nonce tuple
        let r_scalar = &nonce.r_scalar.0;
        let k_inv_scalar = &nonce.k_inv.0;
        let k_scalar = &nonce.aggregated_k.0;

        // VERIFICATION: Check k * k_inv = 1 (mod n)
        {
            use k256::Scalar;
            let k_times_k_inv = *k_scalar * *k_inv_scalar;
            if k_times_k_inv != Scalar::ONE {
                error!(
                    "❌❌❌ [SIGNING-NONCE] CRITICAL: k * k_inv != 1 for nonce {}\n\
                     \tk * k_inv = 0x{}\n\
                     \tThis indicates corrupted nonce data!",
                    nonce.tuple_id,
                    hex::encode(k_times_k_inv.to_bytes())
                );
                return Err(anyhow!("Corrupted nonce: k * k_inv != 1"));
            }
        }

        // VERIFICATION: Check R = k * G
        {
            use k256::ProjectivePoint;
            use k256::elliptic_curve::sec1::ToEncodedPoint;

            let expected_r_point = (ProjectivePoint::GENERATOR * *k_scalar).to_affine();
            let stored_r_point = nonce.aggregate_r.0;

            if expected_r_point != stored_r_point {
                error!(
                    "❌❌❌ [SIGNING-NONCE] CRITICAL: R != k*G for nonce {}\n\
                     \tExpected R (from k*G): 0x{}\n\
                     \tStored aggregate_r:    0x{}\n\
                     \tThis indicates corrupted nonce data!",
                    nonce.tuple_id,
                    hex::encode(expected_r_point.to_encoded_point(true).as_bytes()),
                    hex::encode(stored_r_point.to_encoded_point(true).as_bytes())
                );
                return Err(anyhow!("Corrupted nonce: R != k*G"));
            }
        }

        // VERIFICATION: Check r_scalar = x(R) mod n
        {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            use k256::elliptic_curve::ops::Reduce;
            use k256::{Scalar, U256};

            let stored_r_point = nonce.aggregate_r.0;
            let encoded = stored_r_point.to_encoded_point(false);
            let x_bytes = encoded.x().ok_or_else(|| anyhow!("Point at infinity"))?;
            // Use Reduce (not ReduceNonZero) to get proper r = x(R) mod n
            let computed_r = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

            if computed_r != *r_scalar {
                error!(
                    "❌❌❌ [SIGNING-NONCE] CRITICAL: r_scalar != x(R) for nonce {}\n\
                     \tComputed r (from x(R)): 0x{}\n\
                     \tStored r_scalar:        0x{}\n\
                     \tThis indicates corrupted nonce data!",
                    nonce.tuple_id,
                    hex::encode(computed_r.to_bytes()),
                    hex::encode(r_scalar.to_bytes())
                );
                return Err(anyhow!("Corrupted nonce: r_scalar != x(R)"));
            }
        }

        // 2) Convert to BigUint for computation
        let r = BigUint::from_bytes_be(&r_scalar.to_bytes());
        let k_inv = BigUint::from_bytes_be(&k_inv_scalar.to_bytes());

        // 3) z = message hash as BigUint
        let z = BigUint::from_bytes_be(message.as_ref());

        // 4) x = private key share as BigUint
        let sk_bytes = signing_key.secret_bytes();
        let x = BigUint::from_bytes_be(&sk_bytes);

        // 5) Curve order n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .ok_or_else(|| anyhow!("failed to parse secp256k1 curve order"))?;
        // 6) s = k⁻¹ * (z + r * x) mod n
        // Note: With aggregated k, all nodes compute the same s for their key share
        let s = (&k_inv * (&z + (&r * &x) % &n)) % &n;

        // 7) Serialize r‖s into 64-byte array
        let mut sig_bytes = [0u8; 64];
        let r_be: Vec<u8> = r.to_bytes_be();
        let s_be = s.to_bytes_be();
        sig_bytes[32 - r_be.len()..32].copy_from_slice(&r_be);
        sig_bytes[64 - s_be.len()..64].copy_from_slice(&s_be);

        // 8) Use pre-computed recovery ID from nonce tuple
        let rid: RecoveryId = RecoveryId::from_i32(nonce.r_y_parity as i32)
            .map_err(|e| anyhow!("invalid recovery ID: {}", e))?;

        // 9) Build the recoverable signature
        let rec_sig = RecoverableSignature::from_compact(&sig_bytes, rid)
            .map_err(|e| anyhow!("invalid compact signature: {}", e))?;

        Ok(rec_sig)
    }

    /// Create ECDSA signature using a pre-computed nonce tuple (random k)
    ///
    /// This is the secure version that uses distributed random nonces instead of fixed k.
    ///
    /// The nonce tuple contains:
    /// - aggregated_k: The aggregated nonce k = Σk_i (same for all nodes)
    /// - k_inv: The inverse k⁻¹ = (Σk_i)⁻¹ (same for all nodes)
    /// - r_scalar: The r value (x-coordinate of R mod n)
    /// - r_y_parity: Y-parity of R for recovery ID
    ///
    /// The signature computation: s = k⁻¹ * (z + r * x) mod n
    /// where k is the aggregated nonce that all nodes computed from broadcasting their k_i.
    pub(crate) fn enforce_nonce_digest_uniqueness(
        signing_key: &SecretKey,
        nonce_tuple_id: &str,
        digest: &[u8],
    ) -> Result<()> {
        let compressed_pubkey_hex =
            hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), signing_key).serialize());

        if digest.len() != 32 {
            return Err(anyhow!(
                "invalid digest length for nonce audit: expected 32 bytes, got {}",
                digest.len()
            ));
        }

        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(digest);
        let key = (compressed_pubkey_hex, nonce_tuple_id.to_owned());

        let mut registry = super::node::NONCE_DIGEST_AUDIT_REGISTRY
            .write()
            .map_err(|e| anyhow!("nonce digest audit registry poisoned: {e}"))?;

        if let Some(first_digest) = registry.get(&key) {
            if first_digest != &digest_arr {
                return Err(anyhow!(
                    "nonce tuple reuse with different digest detected for tuple {}",
                    nonce_tuple_id
                ));
            }
        } else {
            registry.insert(key, digest_arr);
        }

        Ok(())
    }

    /// Create DER-encoded ECDSA signature with SIGHASH_ALL (based on working implementation)
    pub fn create_der_signature_p2wpkh(r32: &[u8; 32], s32: &[u8; 32]) -> Vec<u8> {
        // Encode integer with proper DER rules
        pub(crate) fn enc_int(mut v: Vec<u8>) -> Vec<u8> {
            // Strip leading zeros
            while v.len() > 1 && v[0] == 0 {
                v.remove(0);
            }
            // Add leading zero if MSB set to ensure positive
            if v[0] & 0x80 != 0 {
                let mut t = Vec::with_capacity(v.len() + 1);
                t.push(0x00);
                t.extend_from_slice(&v);
                return t;
            }
            v
        }

        let r = enc_int(r32.to_vec());
        let s = enc_int(s32.to_vec());

        let mut der = Vec::with_capacity(6 + r.len() + s.len());
        der.push(0x30); // SEQUENCE
        der.push((4 + r.len() + s.len()) as u8); // Total length
        der.push(0x02); // INTEGER tag for r
        der.push(r.len() as u8);
        der.extend_from_slice(&r);
        der.push(0x02); // INTEGER tag for s
        der.push(s.len() as u8);
        der.extend_from_slice(&s);
        // der.push(0x01); // SIGHASH_ALL

        der
    }

}

#[cfg(test)]
mod keys_tests {
    use super::*;
    use k256::Scalar;
    use secp256k1::{SecretKey, Message};
    use tokio::sync::mpsc;

    fn make_signing_node() -> SigningNode {
        let (tx, _rx) = mpsc::channel(1);
        SigningNode::new("test-node-keys".to_string(), 2, tx)
    }

    #[test]
    fn test_der_signature_format_basic() {
        let r = [0x01u8; 32];
        let s = [0x01u8; 32];
        let der = SigningNode::create_der_signature_p2wpkh(&r, &s);

        // DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
        assert_eq!(der[0], 0x30, "Must start with SEQUENCE tag");
        assert_eq!(der[2], 0x02, "r must have INTEGER tag");
        // Total length in der[1] should equal remaining bytes
        assert_eq!(der[1] as usize, der.len() - 2, "Length byte must match");
    }

    #[test]
    fn test_der_signature_high_bit_padding() {
        // r starts with 0x80 → should get a 0x00 prepended
        let mut r = [0x00u8; 32];
        r[0] = 0x80;
        let s = [0x01u8; 32];
        let der = SigningNode::create_der_signature_p2wpkh(&r, &s);

        // Find r data: starts at der[4]
        let r_len = der[3] as usize;
        // When MSB is set, DER adds 0x00 prefix → length should be 33
        assert_eq!(r_len, 33, "High-bit r should have 33-byte encoded length");
        assert_eq!(der[4], 0x00, "High-bit r must be prepended with 0x00");
    }

    #[test]
    fn test_der_signature_strips_leading_zeros() {
        // r has leading zeros → should be stripped
        let mut r = [0x00u8; 32];
        r[31] = 0x42; // Only last byte is non-zero
        let s = [0x01u8; 32];
        let der = SigningNode::create_der_signature_p2wpkh(&r, &s);

        let r_len = der[3] as usize;
        assert_eq!(r_len, 1, "Leading zeros in r should be stripped (only 0x42 remains)");
        assert_eq!(der[4], 0x42);
    }

    #[test]
    fn test_generate_key_pair_on_signing_node() {
        let mut node = make_signing_node();
        assert!(!node.has_private_key());

        node.generate_key_pair().expect("key generation should succeed");
        assert!(node.has_private_key());
    }

    #[test]
    fn test_set_private_key_from_scalar() {
        let mut node = make_signing_node();
        let scalar = Scalar::ONE;
        node.set_private_key_from_scalar(scalar);
        assert!(node.has_private_key());
    }

    #[test]
    fn test_derive_secp_secret_valid() {
        let scalar = Scalar::ONE;
        let result = SigningNode::derive_secp_secret(&scalar);
        assert!(result.is_ok(), "Scalar::ONE should produce a valid SecretKey");
    }

    #[test]
    fn test_set_and_get_group_public_key() {
        let mut node = make_signing_node();
        let point = k256::ProjectivePoint::GENERATOR;

        assert!(node.get_group_public_key().is_none());
        node.set_group_public_key(point);
        assert_eq!(node.get_group_public_key().unwrap(), point);
    }

    #[tokio::test]
    async fn test_has_dkg_share_without_storage() {
        let node = make_signing_node();
        // Without DKG storage set, should always return false
        assert!(!node.has_dkg_share().await);
    }
}

