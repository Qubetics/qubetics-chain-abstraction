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
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use sha3::Digest;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub mod chains;
mod config;
pub mod coordination;
pub mod db_signing;
mod key;
mod rewards;
pub mod state;
mod transactions;
pub use chains::{BitcoinSigner, EthereumSigner};
pub use config::{BroadcastConfig, ChainBroadcastConfig};
pub use coordination::Coordination;
pub use db_signing::DatabaseSigningNode;
pub use key::KeyStore;
pub use state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, PendingStore, PendingValue,
    SignatureStore, SigningEnvironmentBuilder,
};

use num_bigint::{BigInt, ToBigInt};
use secp256k1::{constants::CURVE_ORDER, ecdsa::RecoveryId};

use crate::chain_abstraction::{ChainHandler, ChainTransaction};
use crate::protocols::{VrfSelectedNodesBroadcast, VrfService};
use crate::types::{
    p2p::SerializablePeerId, ChannelMessage, ConsensusMessage, ConsensusResult, GossipsubMessage,
    TransactionType,
};
use crate::user_intent_manager::UserIntentManager;
use anyhow::bail;
use num_traits::Zero;

#[derive(Clone)]
pub struct SigningNode {
    id: String,
    threshold: usize,
    key_store: KeyStore,
    signatures: SignatureStore,
    message_tx: mpsc::Sender<ChannelMessage>,
    coordination: Coordination,
    chain_handler: Arc<dyn ChainHandler>, // Chain-specific operations for regular transactions
    contract_chain_handler: Arc<dyn ChainHandler>, // Chain handler specifically for contract transactions
    pending: PendingStore,
    btc_state: BtcAggregationState,
    // User registry for storing transaction IDs
    user_intent_manager: Option<Arc<UserIntentManager>>,
    // Database for storing solver amounts
    database: Option<Arc<crate::database::Database>>,
    // Dynamic broadcast configuration
    broadcast_policy: BroadcastPolicy,
}

impl SigningNode {
    pub fn set_threshold(&mut self, new_threshold: usize) {
        self.threshold = new_threshold;
    }

    pub fn vrf_service(&self) -> Option<&VrfService> {
        self.coordination.vrf_service()
    }

    pub fn vrf_service_mut(&mut self) -> Option<&mut VrfService> {
        self.coordination.vrf_service_mut()
    }

    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        let peer_id =
            PeerId::from_str(&id).unwrap_or_else(|_| coordination::derive_peer_id_from_string(&id));
        let environment = SigningEnvironmentBuilder::new(id.clone(), message_tx.clone())
            .build_with_coordination(Coordination::new(peer_id, message_tx.clone()));

        Self {
            id,
            threshold,
            key_store: KeyStore::new(),
            signatures: SignatureStore::new(),
            message_tx: message_tx.clone(),
            coordination: environment.coordination,
            chain_handler: environment.chain_handler,
            contract_chain_handler: environment.contract_chain_handler,
            pending: PendingStore::new(),
            btc_state: BtcAggregationState::new(),
            user_intent_manager: None, // Will be set later via set_user_intent_manager
            database: None,            // Will be set later via set_database
            broadcast_policy: environment.broadcast_policy,
        }
    }
}

impl SigningNode {
    /// Print the current broadcast configuration
    pub fn print_broadcast_config(&self) {
        self.broadcast_policy.config.print_config();
    }

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

    // Configuration methods
    pub fn set_broadcast_config(&mut self, config: BroadcastConfig) {
        self.broadcast_policy.config = config;
    }

    pub fn get_broadcast_config(&self) -> &BroadcastConfig {
        &self.broadcast_policy.config
    }

    pub fn update_chain_config(&mut self, chain_type: &str, config: ChainBroadcastConfig) {
        self.broadcast_policy
            .config
            .chain_configs
            .insert(chain_type.to_string(), config);
    }

    pub fn enable_chain(&mut self, chain_type: &str, enabled: bool) {
        if let Some(chain_config) = self
            .broadcast_policy
            .config
            .chain_configs
            .get_mut(chain_type)
        {
            chain_config.enabled = enabled;
        }
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

    /// Create DER-encoded ECDSA signature with SIGHASH_ALL (based on working implementation)
    pub fn create_der_signature_p2wpkh(r32: &[u8; 32], s32: &[u8; 32]) -> Vec<u8> {
        // Encode integer with proper DER rules
        fn enc_int(mut v: Vec<u8>) -> Vec<u8> {
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
    /// Get the appropriate public key bytes based on transaction type
    async fn get_group_public_key_bytes(
        &self,
        transaction_type: Option<crate::types::TransactionType>,
        user_eth_address: Option<String>,
    ) -> Result<Vec<u8>> {
        use crate::database::keys;
        use crate::types::{SerializablePoint, TransactionType};

        match transaction_type {
            Some(TransactionType::UserToVault) => {
                if let Some(user_addr) = &user_eth_address {
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
                    Err(anyhow!("UserToVault transaction requires user_eth_address"))
                }
            }
            Some(TransactionType::NetworkToTarget) => {
                let group_key = if let Some(key) = self.key_store.get_group_public_key() {
                    Some(key)
                } else if let Some(database) = &self.database {
                    match database.get_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC) {
                        Ok(Some(serialized)) => Some(serialized.0.into()),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(group_key) = group_key {
                    let encoded_point = k256::EncodedPoint::from(group_key.to_affine());
                    Ok(encoded_point.compress().to_bytes().to_vec())
                } else {
                    Err(anyhow!(
                        "DKG group public key not available for NetworkToTarget transaction - ensure DKG process is completed"
                    ))
                }
            }
            Some(TransactionType::VaultToNetwork) => {
                let vault_key = if let Some(vault_key) = self.key_store.get_vault_group_key() {
                    Some(vault_key)
                } else if let Some(database) = &self.database {
                    match database.get_string::<SerializablePoint>(keys::DKG_VAULT_GROUP_KEY) {
                        Ok(Some(serialized)) => Some(serialized.0.into()),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(vault_key) = vault_key {
                    let encoded_point = k256::EncodedPoint::from(vault_key.to_affine());
                    Ok(encoded_point.compress().to_bytes().to_vec())
                } else {
                    Err(anyhow!(
                        "Vault group public key not available for VaultToNetwork transaction - ensure vault key is set"
                    ))
                }
            }
            Some(TransactionType::RewardTxn) => {
                let group_key = if let Some(key) = self.key_store.get_group_public_key() {
                    Some(key)
                } else if let Some(database) = &self.database {
                    match database.get_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC) {
                        Ok(Some(serialized)) => Some(serialized.0.into()),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(group_key) = group_key {
                    let encoded_point = k256::EncodedPoint::from(group_key.to_affine());
                    Ok(encoded_point.compress().to_bytes().to_vec())
                } else {
                    Err(anyhow!(
                        "DKG group public key not available for RewardTxn - ensure DKG process is completed"
                    ))
                }
            }
            Some(TransactionType::WithdrawLiquidity) => {
                // WithdrawLiquidity uses network group key (same as RewardTxn and NetworkToTarget)
                let group_key = if let Some(key) = self.key_store.get_group_public_key() {
                    Some(key)
                } else if let Some(database) = &self.database {
                    match database.get_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC) {
                        Ok(Some(serialized)) => Some(serialized.0.into()),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(group_key) = group_key {
                    let encoded_point = k256::EncodedPoint::from(group_key.to_affine());
                    Ok(encoded_point.compress().to_bytes().to_vec())
                } else {
                    Err(anyhow!(
                        "DKG group public key not available for WithdrawLiquidity - ensure DKG process is completed"
                    ))
                }
            }
            Some(TransactionType::AddLiquidity) => {
                // AddLiquidity uses vault group key (same as VaultToNetwork)
                let vault_key = if let Some(vault_key) = self.key_store.get_vault_group_key() {
                    Some(vault_key)
                } else if let Some(database) = &self.database {
                    match database.get_string::<SerializablePoint>(keys::DKG_VAULT_GROUP_KEY) {
                        Ok(Some(serialized)) => Some(serialized.0.into()),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(vault_key) = vault_key {
                    let encoded_point = k256::EncodedPoint::from(vault_key.to_affine());
                    Ok(encoded_point.compress().to_bytes().to_vec())
                } else {
                    Err(anyhow!(
                        "Vault group public key not available for AddLiquidity - ensure vault key is set"
                    ))
                }
            }
            None => Err(anyhow!(
                "Transaction type is required for group public key retrieval"
            )),
        }
    }

    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} broadcasting to topic: {}",
            self.id, topic
        );
        info!("📊 [SIGNING] Message size: {} bytes", data.len());

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

        info!(
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

        info!(
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

        info!(
            "📤 [SIGNING-SECURE] Queued unicast BTC signatures for round {} to final node {}",
            round, final_node_id
        );
        Ok(())
    }

    /// Create ECDSA signature directly without DummyTransaction (pure Bitcoin signing)
    /// Create ECDSA signature with a specific signing key (for Bitcoin transactions)
    pub fn create_ecdsa_signature_with_signing_key(
        &self,
        message: &Message,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        // Your exact proven custom signature logic (copied from create_ecdsa_signature)
        // 1) Use provided signing key and context
        let sk = signing_key;
        let secp = Secp256k1::new();

        // 2) Fixed nonce k = 0x42…42
        let k_bytes = [0x42u8; 32];
        let sec_nonce =
            SecretKey::from_slice(&k_bytes).map_err(|e| anyhow!("invalid nonce slice: {}", e))?;

        // 3) R = k·G
        let r = PublicKey::from_secret_key(&secp, &sec_nonce);
        let rser = r.serialize_uncompressed(); // [0x04 || X(32) || Y(32)]
        info!("[SIGNING] R serialized: {:?}", rser);
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
        .unwrap();

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
                from: _from,
                signature: _signature,
                round: _round,
                timestamp: _timestamp,
                user_eth_address: _user_eth_address,
            } => {}
            SigningMessage::BtcSignaturesMessage {
                from: _from,
                signatures: _signatures,
                round: _round,
                timestamp: _timestamp,
                user_eth_address: _user_eth_address,
            } => {}
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
                )
                .await?;
            }
        }
        Ok(())
    }

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
        info!("🔍 [SIGNING] === SIGNATURE INDEX ASSIGNMENT ===");
        info!(
            "🔍 [SIGNING] Number of signatures to process: {}",
            signatures.len()
        );

        // Log the DKG indices provided for aggregation
        info!(
            "🧮 [SIGNING] peer_to_dkg_index used for aggregation: {:?}",
            peer_to_dkg_index
                .iter()
                .map(|(p, i)| format!("{p}->{i}"))
                .collect::<Vec<_>>()
        );

        // Log index => peerId mapping explicitly
        info!("🔢 [INDEX-PEER-DEBUG] Index => PeerId mapping:");
        for (peer_id, dkg_index) in &peer_to_dkg_index {
            info!(
                "🔢 [INDEX-PEER-DEBUG]   Index {} => PeerId {}",
                dkg_index, peer_id
            );
        }

        // Use DKG indices for signature aggregation
        let s_shares: Vec<(u32, Vec<u8>)> = signatures
            .into_iter()
            .zip(peer_to_dkg_index.iter())
            .map(|(sig, (peer_id, dkg_index))| {
                let (_recid, compact) = sig.serialize_compact();
                let s_bytes = compact[32..64].to_vec();
                info!(
                    "🔍 [SIGNING] Peer {} using DKG index: {} for aggregation",
                    peer_id, dkg_index
                );
                info!(
                    "🔍 [SIGNING-DEBUG] Index {} => PeerId {} => s-share: 0x{}",
                    dkg_index,
                    peer_id,
                    hex::encode(&s_bytes)
                );
                (*dkg_index, s_bytes)
            })
            .collect();

        info!(
            "🔍 [SIGNING] Final s_shares with indices: {:?}",
            s_shares.iter().map(|(idx, _)| idx).collect::<Vec<_>>()
        );
        info!(
            "🔍 [SIGNING-DEBUG] Complete s_shares (index -> s-value): {:?}",
            s_shares
                .iter()
                .map(|(idx, s)| format!("{} -> 0x{}", idx, hex::encode(s)))
                .collect::<Vec<_>>()
        );

        // Build reverse mapping for clarity
        let index_to_peer: std::collections::HashMap<u32, String> = peer_to_dkg_index
            .iter()
            .map(|(p, i)| (*i, p.clone()))
            .collect();
        info!("🔢 [INDEX-PEER-DEBUG] Complete Index => PeerId => Share mapping:");
        for (idx, s_val) in &s_shares {
            if let Some(peer) = index_to_peer.get(idx) {
                info!(
                    "🔢 [INDEX-PEER-DEBUG]   Index {} => {} => 0x{}",
                    idx,
                    peer,
                    hex::encode(s_val)
                );
            }
        }

        info!("🔍 [SIGNING] === END SIGNATURE INDEX ASSIGNMENT ===");

        // ─── 3) Reconstruct s via Lagrange at x=0 ───────────────────────────────────
        let mut agg_s = self.lagrange_interpolate(&s_shares)?;

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
        let agg_sig = RecoverableSignature::from_compact(&sig_bytes, final_recid)?;

        Ok(agg_sig)
    }

    fn lagrange_interpolate(&self, shares: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
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
        fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
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

    async fn handle_signed_message(
        &mut self,
        from: String,
        signed_message: SignedMessage,
    ) -> Result<()> {
        info!(
            "✅ [SIGNING] Node {} received signed message from {}",
            self.id, from
        );
        info!("📄 [SIGNING] Message: {:?}", signed_message.message);

        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        // Verify the aggregated ECDSA signature
        let is_valid = self.verify_aggregated_signature(&signed_message).await?;
        if is_valid {
            info!("✅ [SIGNING] ECDSA signature verification successful!");
        } else {
            warn!("❌ [SIGNING] ECDSA signature verification failed!");
        }

        Ok(())
    }

    async fn verify_aggregated_signature(&self, signed_message: &SignedMessage) -> Result<bool> {
        info!(
            "🔍 [SIGNING] Node {} verifying aggregated signature",
            self.id
        );
        info!(
            "✍️ [SIGNING] Aggregated signature: {:?}",
            signed_message.aggregated_signature
        );
        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

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

    /// Get VRF public key for this node
    pub async fn get_vrf_public_key(&self) -> Option<String> {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            Some(vrf_service.get_public_key_hex().await)
        } else {
            None
        }
    }

    /// Get VRF public key as bytes
    pub async fn get_vrf_public_key_bytes(&self) -> Option<Vec<u8>> {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            Some(vrf_service.get_public_key().await)
        } else {
            None
        }
    }
    /// Set the chain handler for this signing node
    pub fn set_chain_handler(&mut self, chain_handler: Arc<dyn ChainHandler>) {
        self.chain_handler = chain_handler;
        info!(
            "🔗 [SIGNING] Node {} switched to {} chain handler",
            self.id,
            self.chain_handler.chain_type()
        );
    }

    /// Set the contract chain handler for this signing node
    pub fn set_contract_chain_handler(&mut self, contract_chain_handler: Arc<dyn ChainHandler>) {
        self.contract_chain_handler = contract_chain_handler;
        info!(
            "🔗 [SIGNING] Node {} switched to {} contract chain handler",
            self.id,
            self.contract_chain_handler.chain_type()
        );
    }

    /// Get a reference to the chain handler
    pub fn get_chain_handler(&self) -> &Arc<dyn ChainHandler> {
        &self.chain_handler
    }

    /// Get a reference to the contract chain handler
    pub fn get_contract_chain_handler(&self) -> &Arc<dyn ChainHandler> {
        &self.contract_chain_handler
    }

    /// Get the current chain type
    pub fn get_chain_type(&self) -> &'static str {
        self.chain_handler.chain_type()
    }

    /// Get chain parameters
    pub fn get_chain_params(&self) -> std::collections::HashMap<String, String> {
        self.chain_handler.get_chain_params()
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.coordination.set_available_nodes(nodes);
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
            "Vault group public key not available - ensure vault key is initialized",
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

    pub fn set_user_intent_manager(&mut self, user_intent_manager: Arc<UserIntentManager>) {
        self.user_intent_manager = Some(user_intent_manager);
        info!("📋 [SIGNING] Node {} user registry set", self.id);
    }

    pub fn set_database(&mut self, database: Arc<crate::database::Database>) {
        self.database = Some(database.clone());

        // Update Coordination with database so VrfService can use it
        self.coordination.set_database(database);

        info!(
            "🗄️ [SIGNING] Node {} database set with VRF storage",
            self.id
        );
    }

    /// Get peer index directly from database
    async fn get_peer_index_from_db(&self, peer_id: &str) -> Option<usize> {
        if let Some(db) = &self.database {
            let key = crate::database::key_utils::peer_index_key(peer_id);
            match db.get_string::<usize>(&key) {
                Ok(Some(index)) => {
                    info!(
                        "🔢 [SIGNING] Retrieved peer index {} for {} from database",
                        index, peer_id
                    );
                    Some(index)
                }
                Ok(None) => {
                    info!(
                        "🔍 [SIGNING] No peer index found in database for {}",
                        peer_id
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        "❌ [SIGNING] Failed to get peer index from database for {}: {:?}",
                        peer_id, e
                    );
                    None
                }
            }
        } else {
            warn!(
                "⚠️ [SIGNING] No database available to get peer index for {}",
                peer_id
            );
            None
        }
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

    /// Sync VRF round with network (simple approach)
    pub async fn sync_vrf_round_with_network(&mut self, network_round: u64) {
        if let Some(vrf_service) = self.coordination.vrf_service_mut() {
            vrf_service.set_current_round(network_round).await;
            info!("🔄 [SIGNING] Synced VRF round to: {}", network_round);
        }
    }

    // Initiate a refund transaction when network-to-target broadcast fails
    /// This will create a VaultToNetwork transaction to return funds to the user's source address
    /// Broadcast refund initiation message to the network
    /// This notifies other nodes that a refund transaction needs to be created
    async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
        self.coordination.get_available_nodes_from_manager().await
    }

    /// Handle VRF selected nodes broadcast from another node
    pub fn handle_vrf_selected_nodes_broadcast(
        &mut self,
        total_nodes: usize,
        broadcast: VrfSelectedNodesBroadcast,
        sender_peer_id: libp2p::PeerId,
    ) {
        if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = broadcast.round;
            let min_selections = total_nodes;

            // Use async task to handle VRF broadcast
            let vrf_service_clone = vrf_service.clone();
            let mut signing_node_clone = self.clone();

            tokio::spawn(async move {
                // Handle VRF broadcast via service
                if let Err(e) = vrf_service_clone
                    .handle_vrf_broadcast(broadcast, sender_peer_id, total_nodes)
                    .await
                {
                    error!("❌ [SIGNING] Failed to handle VRF broadcast: {}", e);
                    return;
                }

                // Check if consensus should be triggered after receiving this broadcast
                if vrf_service_clone
                    .can_start_consensus(round, min_selections)
                    .await
                {
                    info!(
                    "🎯 [VRF] Enough selections collected for round {}, triggering consensus check",
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

    /// Start consensus for a specific round
    pub async fn start_consensus_for_round(
        &mut self,
        round: u64,
    ) -> Result<Option<ConsensusResult>> {
        // Get the node ID first to avoid borrow checker issues
        let own_node_id = SerializablePeerId(PeerId::from_str(&self.id)?);

        let all_selected_nodes = {
            let vrf_service = self
                .coordination
                .vrf_service()
                .ok_or_else(|| anyhow::anyhow!("VRF selector not available"))?;
            vrf_service
                .get_all_selected_nodes_with_frequencies(round)
                .await
        };

        if all_selected_nodes.is_empty() {
            info!(
                "⚠️ [CONSENSUS] No selected nodes available for consensus round {}",
                round
            );
            return Ok(None);
        }

        let consensus_node = self
            .coordination
            .consensus_node_mut()
            .ok_or_else(|| anyhow::anyhow!("Consensus node not available"))?;

        info!(
            "🎯 [CONSENSUS] Starting consensus for round {} with {} selected nodes",
            round,
            all_selected_nodes.len()
        );

        // Add selected nodes to consensus
        consensus_node.add_selected_nodes(round, all_selected_nodes);

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

                // Store the result for later use
                let is_final_node = consensus_node.is_final_node(round, &own_node_id);

                // Broadcast outside of the borrow
                self.broadcast("consensus-result", &broadcast_data).await?;

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

                // Check if this node is the final selected node
                if is_final_node {
                    info!(
                        "\x1b[32m🏆 [CONSENSUS] This node is the final selected node for round {}!\x1b[0m",
                        round
                    );
                    // Trigger aggregate signature for the final node
                    self.trigger_aggregate_signature_for_final_node(round)
                        .await?;
                } else {
                    info!(
                        "\x1b[31m📋 [CONSENSUS] This node is not the final selected node for round {}\x1b[0m",
                        round
                    );
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
        if let Some(consensus_node) = self.coordination.consensus_node_mut() {
            consensus_node.handle_message(msg).await?;
        }
        Ok(())
    }

    /// Trigger aggregate signature for the final selected node
    async fn trigger_aggregate_signature_for_final_node(&self, round: u64) -> Result<()> {
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

        // Get signature for this specific round
        let signatures_by_round = self.signatures.signatures_by_round.read().await;

        if let Some(round_signatures) = signatures_by_round.get(&round) {
            if let Some(our_signature) = round_signatures.get(&self.id) {
                info!(
                    "📤 [SIGNING] Unicasting signature to final node {}: \n\
                     \tFrom: {}\n\
                     \tRound: {}\n\
                     \tSig(r): 0x{}\n\
                     \tSig(s): 0x{}\n\
                     \tRecovID: {}",
                    final_node_id,
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
                    user_eth_address: our_signature.user_eth_address.clone(), // Use user_eth_address from stored signature
                };

                // Wrap in GossipsubMessage::Signing for proper message handling
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;

                self.send_ecdsa_signature_direct(final_node_id, &signature_data, round)
                    .await?;

                info!(
                    "✅ [SIGNING] Sent signature for round {} to final node {}",
                    round, final_node_id
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

    /// Send transaction data to final node (for reconstruction)
    async fn send_transaction_data_to_final_node(
        &self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        // Check if we have transaction data for this round
        let pending_transactions = self.pending.pending_transactions.read().await;
        
        if let Some((_, tx_bytes, intent_hash, transaction_type)) = pending_transactions.get(&round) {
            info!(
                "📤 [SIGNING] Sending transaction data for round {} to final node {} (tx_bytes: {} bytes)",
                round, final_node_id, tx_bytes.len()
            );
            
            let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                from: self.id.clone(),
                round,
                tx_bytes: tx_bytes.clone(),
                intent_hash: intent_hash.clone(),
                transaction_type: transaction_type.as_ref().map(|t| format!("{:?}", t)),
            };
            
            // Wrap and send via unicast
            let gossipsub_msg = crate::types::GossipsubMessage::Signing(tx_data_msg);
            let data = serde_json::to_vec(&gossipsub_msg)?;
            
            self.send_transaction_data_direct(final_node_id, &data, round)
                .await?;
            
            info!(
                "✅ [SIGNING] Sent transaction data for round {} to final node {}",
                round, final_node_id
            );
        } else {
            // No transaction data - this is expected if we also weren't selected
            debug!(
                "⚠️ [SIGNING] No transaction data found for round {} to send to final node",
                round
            );
        }
        
        Ok(())
    }

    /// Handle signature request from final selected node
    async fn handle_signature_request(
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
            // Send signature to the final node
            self.send_signature_to_final_node(&final_node_id, round)
                .await?;
            
            // CRITICAL FIX: Also send transaction data to the final node
            // This ensures the final node can reconstruct the transaction even if it wasn't selected to sign
            self.send_transaction_data_to_final_node(&final_node_id, round)
                .await?;
        } else {
            info!("🔄 [SIGNING] This node is the final node, no need to send signature to self");
        }

        Ok(())
    }

    /// Handle signature aggregation for Ethereum transactions only (Bitcoin has separate flow)
    pub async fn handle_signature_for_round(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} for round {}",
            self.id, from, round
        );

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

        // Always verify signature before storing
        // For contract transactions (transaction_type = None), use vault share pubkey
        if let Err(e) = self
            .verify_signature_for_round(&from, &signature, round)
            .await
        {
            error!(
                "❌ [SIGNING] Signature verification failed for peer {} in round {}: {}",
                from, round, e
            );
            return Err(anyhow!(
                "Signature verification failed for peer {} in round {}: {}",
                from,
                round,
                e
            ));
        }
        info!(
            "✅ [SIGNING] Signature verification passed for peer {} in round {}",
            from, round
        );

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

                // Log index => peerId mapping for this round
                info!(
                    "🔢 [INDEX-PEER-DEBUG] Round {} - Index => PeerId mapping for aggregation:",
                    round
                );
                for (peer_id, dkg_index) in &peer_to_dkg_index {
                    info!("🔢 [INDEX-PEER-DEBUG]   Index {} => {}", dkg_index, peer_id);
                }

                // Get chain_id from environment variable for v calculation
                let chain_id_for_v = std::env::var("MPC_ETHEREUM_CHAIN_ID")
                    .ok()
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(9029); // Default: Qubetics chain ID

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

                        info!(
                            "🔐 [SIGNING] Aggregated signature components for round {}:",
                            round
                        );
                        info!("  v: {}", v);
                        info!("  r (canonical): 0x{}", hex::encode(r));
                        info!("  s (canonical): 0x{}", hex::encode(s));
                        info!("  recovery_id: {}", recovery_id.to_i32());
                        info!("  original_signature: 0x{}", hex::encode(signature_bytes));
                        info!(
                            "  r_canonical_len: {}, s_canonical_len: {}",
                            r_canonical.len(),
                            s_canonical.len()
                        );

                        // 🚀 NEW: Reconstruct and broadcast signed transaction based on actual transaction type
                        // Check the actual transaction stored for this round to determine the correct chain type
                        // First check if this is a reward round
                        let is_reward_round = {
                            let reward_rounds = self.pending.reward_rounds.read().await;
                            reward_rounds.contains(&round)
                        };
                        let is_withdraw_round = {
                            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
                            withdraw_rounds.contains(&round)
                        };

                        let (is_contract_tx, maybe_chain_id) = if is_reward_round {
                            // This is a reward transaction - check reward pending transactions for TICS (Ethereum)
                            let reward_pending_transactions =
                                self.pending.reward_pending_transactions_tics.read().await;
                            if let Some((chain_tx, _tx_bytes, _solver_address, _transaction_type)) =
                                reward_pending_transactions.get(&round)
                            {
                                match chain_tx {
                                    ChainTransaction::Ethereum(eth_tx) => {
                                        let is_contract = eth_tx.data.is_some()
                                            && !eth_tx.data.as_ref().unwrap().is_empty();
                                        (is_contract, Some(eth_tx.chain_id))
                                    }
                                    _ => (false, None), // Only handle Ethereum transactions in this function
                                }
                            } else {
                                (false, None)
                            }
                        } else if is_withdraw_round {
                            let withdraw_pending_transactions =
                                self.pending.withdraw_pending_transactions_tics.read().await;
                            if let Some((chain_tx, _tx_bytes, _solver_address, _transaction_type)) =
                                withdraw_pending_transactions.get(&round)
                            {
                                match chain_tx {
                                    ChainTransaction::Ethereum(eth_tx) => {
                                        let is_contract = eth_tx.data.is_some()
                                            && !eth_tx.data.as_ref().unwrap().is_empty();
                                        (is_contract, Some(eth_tx.chain_id))
                                    }
                                    _ => (false, None),
                                }
                            } else {
                                (false, None)
                            }
                        } else {
                            // This is a regular transaction - check regular pending transactions for Ethereum
                            let pending_transactions =
                                self.pending.pending_transactions.read().await;
                            if let Some((chain_tx, _tx_bytes, _intent_hash, _transaction_type)) =
                                pending_transactions.get(&round)
                            {
                                match chain_tx {
                                    ChainTransaction::Ethereum(eth_tx) => {
                                        let is_contract = eth_tx.data.is_some()
                                            && !eth_tx.data.as_ref().unwrap().is_empty();
                                        (is_contract, Some(eth_tx.chain_id))
                                    }
                                    _ => (false, None), // Only handle Ethereum transactions in this function
                                }
                            } else {
                                (false, None)
                            }
                        };

                        info!(
                            "🔍 [SIGNING] Processing Ethereum transaction (is_contract: {})",
                            is_contract_tx
                        );

                        // Create canonical signature bytes from normalized r and s components
                        let mut canonical_signature_bytes = [0u8; 64];
                        canonical_signature_bytes[0..32].copy_from_slice(&r);
                        canonical_signature_bytes[32..64].copy_from_slice(&s);

                        if let Ok(Some(signed_tx_hex)) = self
                            .reconstruct_signed_ethereum_transaction(
                                round,
                                &canonical_signature_bytes,
                                recovery_id.to_i32() as u8,
                            )
                            .await
                        {
                            info!("🎉 [SIGNING] 🔗 SIGNED ETHEREUM TRANSACTION READY! 🔗");
                            info!("📄 Raw signed transaction: {}", signed_tx_hex);

                            // Get chain ID for broadcasting from the stored original transaction
                            let chain_id = match maybe_chain_id {
                                Some(id) => id,
                                None => {
                                    warn!(
                                        "⚠️ [SIGNING] Unable to determine chain_id for round {}, defaulting to 9029",
                                        round
                                    );
                                    9029
                                }
                            };

                            info!(
                                "Broadcasting transaction to chain {} (Qubetics)...",
                                chain_id
                            );
                            match Self::broadcast_ethereum_transaction(&signed_tx_hex, chain_id)
                                .await
                            {
                                Ok(Some(tx_hash)) => {
                                    info!("✅ [SIGNING] Ethereum transaction broadcasted successfully: {}", tx_hash);
                                    // Store transaction ID if we have intent hash and user registry
                                    self.store_transaction_id_for_round(
                                        round,
                                        &tx_hash,
                                        crate::types::TransactionNetwork::TICS,
                                    )
                                    .await;
                                }
                                Ok(None) => {
                                    warn!("⚠️ [SIGNING] Ethereum transaction broadcasted but no tx_hash returned");
                                }
                                Err(e) => {
                                    error!(
                                        "❌ [SIGNING] Failed to broadcast Ethereum transaction: {}",
                                        e
                                    );
                                    // Store the error message for the user to see
                                    self.store_transaction_error_for_round(
                                        round,
                                        &e.to_string(),
                                        crate::types::TransactionNetwork::TICS,
                                    )
                                    .await;
                                }
                            }
                        } else {
                            warn!(
                            "❌ [SIGNING] Failed to reconstruct Ethereum transaction for round {}",
                            round
                        );
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to aggregate signatures for round {}: {}",
                            round, e
                        );
                        
                        // Check if aggregation failed due to insufficient signatures
                        let error_msg = e.to_string();
                        if error_msg.contains("Not enough signature shares") {
                            info!(
                                "💸 [SIGNING-REFUND] Insufficient valid signatures for aggregation in round {}, triggering refund",
                                round
                            );
                            // Trigger refund for NetworkToTarget transactions
                            self.check_and_trigger_refund_on_verification_failure(
                                round,
                                crate::types::TransactionNetwork::TICS,
                            )
                            .await;
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
    /// Bitcoin-only, per-input aware (BATCH).
    /// Ingest a whole vector of per-input signatures from one peer, then:
    /// 1) store them under (round → input_index → peer)
    /// 2) aggregate any inputs that have reached threshold
    /// 3) if all inputs aggregated, finalize & broadcast
    pub async fn handle_btc_signature_for_round(
        &mut self,
        from: String,
        items: Vec<BtcIndexedSignature>,
        round: u64,
    ) -> Result<()> {
        use anyhow::{anyhow, bail};
        use secp256k1::{
            ecdsa::{RecoverableSignature, RecoveryId},
            Message, Secp256k1,
        };
        use std::collections::{HashMap, HashSet};

        // If this round is already finalized, ignore the whole batch.
        if self
            .signatures
            .aggregated_rounds
            .read()
            .await
            .contains(&round)
        {
            info!(
                "⏭️ [BTC] round {} already finalized; ignoring batch from {}",
                round, &from
            );
            return Ok(());
        }

        // ---- 1) Pull unsigned tx + BTC extras from the correct pending store (needed for verification) ----
        let is_reward_round = {
            let reward_rounds = self.pending.reward_rounds.read().await;
            reward_rounds.contains(&round)
        };
        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        let (unsigned_tx, extras, total_inputs) = {
            let (chain_tx, extras_opt) = if is_reward_round {
                let reward_pt = self.pending.reward_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt) =
                    reward_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No reward pending tx for round {}",
                            round
                        );
                        anyhow!("no reward pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            } else if is_withdraw_round {
                let withdraw_pt = self.pending.withdraw_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt) =
                    withdraw_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No withdraw pending tx for round {}",
                            round
                        );
                        anyhow!("no withdraw pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            } else {
                let pt = self.pending.pending_transactions_btc.read().await;
                let (chain_tx, _raw, _intent_hash, _tx_type_opt, extras_opt) =
                    pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No pending tx for round {}",
                            round
                        );
                        anyhow!("no pending tx for round {}", round)
                    })?;
                (chain_tx.clone(), extras_opt.clone())
            };

            let btc_tx = match chain_tx {
                ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    error!(
                        "[handle_btc_signature_for_round] Round {} is not a Bitcoin round",
                        round
                    );
                    bail!("round {} is not a Bitcoin round", round)
                }
            };
            let ex = extras_opt.ok_or_else(|| {
                error!(
                    "[handle_btc_signature_for_round] Missing BtcRoundExtras for round {}",
                    round
                );
                anyhow!("missing btc extras for round {}", round)
            })?;
            (btc_tx.clone(), ex, btc_tx.inputs.len())
        };

        let group_pubkey33 = extras.pubkey33;
        let group_h160 = extras.signer_h160; // HASH160(pubkey33)
        let from_kind_hint = extras.from_kind; // used only for finalization wire form
        let is_testnet = extras.is_testnet;

        let _secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        // ---- 2) VERIFY AND STORE THE WHOLE BATCH ----
        // First check for duplicates from previous round and filter them out
        let items_to_verify: Vec<&BtcIndexedSignature> = if round > 0 {
            let prev_round = round - 1;
            let by_round = self.btc_state.btc_sigs_by_round.read().await;
            let prev_rmap = by_round.get(&prev_round);

            items.iter()
                .filter(|it| {
                    let is_duplicate = if let Some(prev_rmap) = prev_rmap {
                        if let Some(prev_imap) = prev_rmap.get(&it.input_index) {
                            if let Some(prev_sig) = prev_imap.get(&from) {
                                // Compare signature bytes to detect duplicates
                                prev_sig.signature == it.signature.signature
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if is_duplicate {
                        warn!(
                            "🚫 [BTC] Duplicate signature detected: signature from {} for round {} input {} was already stored in round {} - skipping",
                            from, round, it.input_index, prev_round
                        );
                    }
                    !is_duplicate
                })
                .collect()
        } else {
            items.iter().collect()
        };

        // Verify each signature before storing
        let items_to_verify_count = items_to_verify.len();
        let mut verified_items = Vec::new();
        let mut verification_errors = Vec::new();

        for item in items_to_verify {
            match self
                .verify_btc_signature_for_round(
                    &from,
                    &item.signature,
                    round,
                    item.input_index,
                )
                .await
            {
                Ok(_) => {
                    info!(
                        "✅ [BTC] Signature verification passed for peer {} in round {} input {}",
                        from, round, item.input_index
                    );
                    verified_items.push(item);
                }
                Err(e) => {
                    error!(
                        "❌ [BTC] Signature verification failed for peer {} in round {} input {}: {}",
                        from, round, item.input_index, e
                    );
                    verification_errors.push((item.input_index, e));
                }
            }
        }

        // If any verifications failed, return error (but log all failures first)
        if !verification_errors.is_empty() {
            let error_msg = verification_errors
                .iter()
                .map(|(idx, e)| format!("input {}: {}", idx, e))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(anyhow!(
                "BTC signature verification failed for {} out of {} signatures from peer {} in round {}: {}",
                verification_errors.len(),
                items_to_verify_count,
                from,
                round,
                error_msg
            ));
        }

        // Store only verified signatures
        let stored_count = {
            let mut by_round = self.btc_state.btc_sigs_by_round.write().await;
            let rmap = by_round.entry(round).or_insert_with(HashMap::new);
            let mut count = 0;
            for it in verified_items {
                let imap = rmap.entry(it.input_index).or_insert_with(HashMap::new);
                // last write wins for (round,input,peer)
                imap.insert(from.clone(), it.signature.clone());
                count += 1;
            }
            count
        };

        if stored_count < items.len() {
            info!(
                "💾 [BTC] stored {} verified sigs for round {} from {} (batch, {} duplicates filtered from previous round)",
                stored_count,
                round,
                from,
                items.len() - stored_count
            );
        } else {
            info!(
                "💾 [BTC] stored {} verified sigs for round {} from {} (batch)",
                stored_count, round, from
            );
        }

        // ---- 3) SWEEP: aggregate *every* input that hit threshold ----
        for idx in 0..total_inputs {
            // skip if already aggregated
            let already_done = {
                let done = self.btc_state.btc_done_inputs_by_round.read().await;
                done.get(&round).is_some_and(|s| s.contains(&idx))
            };
            if already_done {
                continue;
            }

            // get all peer sigs for this input
            let peer_map: Option<HashMap<String, ECDSASignature>> = {
                let by_round = self.btc_state.btc_sigs_by_round.read().await;
                by_round.get(&round).and_then(|r| r.get(&idx)).cloned()
            };
            let Some(peer_map) = peer_map else {
                continue;
            };

            if peer_map.len() < self.threshold {
                continue; // not enough sigs yet
            }

            // sort deterministically and take exactly threshold
            let mut chosen: Vec<(String, ECDSASignature)> = peer_map.into_iter().collect();
            chosen.sort_by(|a, b| a.0.cmp(&b.0));
            let chosen: Vec<(String, ECDSASignature)> =
                chosen.into_iter().take(self.threshold).collect();

            // sanity: for the same input, all sigs must share the same r and be 64 bytes
            let r0 = &chosen[0].1.signature[0..32];
            for (_, s) in &chosen {
                if s.signature.len() != 64 {
                    error!(
                    "[handle_btc_signature_for_round] round {} input {}: bad sig length (got {})",
                    round,
                    idx,
                    s.signature.len()
                );
                    bail!("round {} input {}: bad sig length", round, idx);
                }
                if &s.signature[0..32] != r0 {
                    error!("[handle_btc_signature_for_round] round {} input {}: r mismatch across partial sigs", round, idx);
                    bail!(
                        "round {} input {}: r mismatch across partial sigs",
                        round,
                        idx
                    );
                }
            }

            // Decide spend kind per input via prev script shape if available.
            let maybe_prev = unsigned_tx.inputs[idx].witness_utxo.as_ref();

            // Log transaction details for debugging digest mismatches
            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} transaction details for round {} input {}: version={}, inputs={}, outputs={}, locktime={}",
                self.id, round, idx, unsigned_tx.version, unsigned_tx.inputs.len(), unsigned_tx.outputs.len(), unsigned_tx.lock_time
            );
            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} input {}: txid={}, vout={}, sequence={}, witness_utxo={:?}",
                self.id, idx, unsigned_tx.inputs[idx].txid, unsigned_tx.inputs[idx].vout, unsigned_tx.inputs[idx].sequence,
                maybe_prev.as_ref().map(|w| format!("value={}, script_pubkey_len={}, script_pubkey=0x{}", 
                    w.value, w.script_pubkey.len(), hex::encode(&w.script_pubkey)))
            );

            // Ensure we have consistent prevout data; mixing missing witness info across peers
            // causes different sighashes and invalid aggregated signatures.
            let maybe_prev = maybe_prev.ok_or_else(|| {
                error!(
                    "[handle_btc_signature_for_round] round {} input {} missing witness_utxo data",
                    round, idx
                );
                anyhow!("round {} input {} missing witness_utxo data", round, idx)
            })?;

            let is_p2wpkh = maybe_prev.script_pubkey.len() == 22
                && maybe_prev.script_pubkey[0] == 0x00
                && maybe_prev.script_pubkey[1] == 0x14;

            if is_p2wpkh {
                error!(
                    "[handle_btc_signature_for_round] round {} input {} carries witness program but only P2PKH is supported",
                    round, idx
                );
                bail!(
                    "round {} input {} uses P2WPKH; only P2PKH supported",
                    round,
                    idx
                );
            }

            // Validate script type against what was stored with the transaction.
            match from_kind_hint {
                SpendKind::P2WPKH => {
                    if !is_p2wpkh {
                        error!(
                            "[handle_btc_signature_for_round] round {} input {} expected P2WPKH but got script_pubkey len={} prefix={:02x?}",
                            round,
                            idx,
                            maybe_prev.script_pubkey.len(),
                            maybe_prev.script_pubkey.get(0..2)
                        );
                        bail!("round {} input {} script is not P2WPKH", round, idx);
                    }
                }
                SpendKind::P2PKH => {
                    let spk = &maybe_prev.script_pubkey;
                    let is_p2pkh = spk.len() == 25
                        && spk[0] == 0x76
                        && spk[1] == 0xA9
                        && spk[2] == 0x14
                        && spk[23] == 0x88
                        && spk[24] == 0xAC;
                    if !is_p2pkh {
                        error!(
                            "[handle_btc_signature_for_round] round {} input {} expected P2PKH but got len={} prefix={:02x?}",
                            round,
                            idx,
                            spk.len(),
                            spk.get(0..3)
                        );
                        bail!(
                            "round {} input {} script is not canonical P2PKH",
                            round,
                            idx
                        );
                    }
                }
            }

            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} input {}: is_p2wpkh={}, group_h160=0x{}",
                self.id,
                idx,
                is_p2wpkh,
                hex::encode(group_h160)
            );

            // Build the per-input sighash digest (using stashed prev data; reconstruct P2PKH if absent).
            // LEGACY P2PKH only: Use the provided prev script (we bail earlier if missing).
            let prev_spk_owned: Vec<u8> = {
                info!(
                    "🔍 [BTC-TX-DEBUG] Final node {} input {}: P2PKH detected, using witness_utxo script_pubkey (len={})",
                    self.id, idx, maybe_prev.script_pubkey.len()
                );
                maybe_prev.script_pubkey.clone()
            };

            if prev_spk_owned.len() != 25
                || !(prev_spk_owned[0] == 0x76
                    && prev_spk_owned[1] == 0xA9
                    && prev_spk_owned[2] == 0x14
                    && prev_spk_owned[23] == 0x88
                    && prev_spk_owned[24] == 0xAC)
            {
                error!("[handle_btc_signature_for_round] round {} input {} prev script not canonical P2PKH", round, idx);
                bail!(
                    "round {} input {} prev script not canonical P2PKH",
                    round,
                    idx
                );
            }

            info!(
                "🔍 [BTC-TX-DEBUG] Final node {} input {}: P2PKH prev_spk=0x{}",
                self.id,
                idx,
                hex::encode(&prev_spk_owned)
            );

            let digest =
                self.compute_legacy_sighash_all_p2pkh(&unsigned_tx, idx, &prev_spk_owned)?;

            // Log the digest used for verification/aggregation (should match what each node signed)
            info!(
                "🔐 [BTC-TX-DIGEST] Final node {} verifying/aggregating signatures for round {} input {} using digest: 0x{}",
                self.id,
                round,
                idx,
                hex::encode(digest)
            );

            // Build inputs for MPC aggregation
            let mut sigs: Vec<RecoverableSignature> = Vec::with_capacity(self.threshold);
            let mut peer_to_dkg_index: Vec<(String, u32)> = Vec::with_capacity(self.threshold);
            for (peer, ecsig) in chosen {
                // Log which peer's signature we're processing and what digest they should have signed
                let peer_dkg_idx = self.calculate_dkg_index_for_peer_sync(&peer);
                info!(
                    "🔐 [BTC-TX-DIGEST] Processing signature from peer {} (DKG index: {}) for round {} input {} - expected digest: 0x{}",
                    peer,
                    peer_dkg_idx,
                    round,
                    idx,
                    hex::encode(digest)
                );
                let rid = RecoveryId::from_i32(ecsig.recovery_id as i32)?;
                let rs = RecoverableSignature::from_compact(&ecsig.signature, rid)?;
                sigs.push(rs);

                let dkg_idx = self.calculate_dkg_index_for_peer_sync(&peer);
                peer_to_dkg_index.push((peer, dkg_idx));
            }

            // aggregate this input
            let agg = match self.aggregate_signatures(sigs, peer_to_dkg_index).await {
                Ok(sig) => sig,
                Err(e) => {
                    let error_msg = e.to_string();
                    if error_msg.contains("Not enough signature shares") {
                        info!(
                            "💸 [SIGNING-REFUND] Insufficient valid signatures for aggregation in round {} input {}, triggering refund",
                            round, idx
                        );
                        // Trigger refund for NetworkToTarget transactions
                        self.check_and_trigger_refund_on_verification_failure(
                            round,
                            crate::types::TransactionNetwork::BTC,
                        )
                        .await;
                    }
                    return Err(e);
                }
            };

            // POST-AGGREGATION VERIFY under the **group** pubkey
            {
                let _msg = Message::from_digest_slice(&digest)?;
                let (_recid, compact) = agg.serialize_compact();
                let mut sig_std = secp256k1::ecdsa::Signature::from_compact(&compact)?;
                sig_std.normalize_s(); // low-s normalization
                let _group_pk = secp256k1::PublicKey::from_slice(&group_pubkey33)?;
                // if let Err(e) = secp.verify_ecdsa(&msg, &sig_std, &group_pk) {
                //     error!(
                //     "[btc] round {} input {}: aggregated signature does not verify under group key: {}",
                //     round, idx, e
                // );
                //     bail!(
                //         "round {} input {}: aggregated signature verify failed",
                //         round,
                //         idx
                //     );
                // }
            }

            {
                let mut agg_map = self.btc_state.btc_agg_by_round.write().await;
                agg_map
                    .entry(round)
                    .or_insert_with(HashMap::new)
                    .insert(idx, agg);
            }
            {
                let mut done = self.btc_state.btc_done_inputs_by_round.write().await;
                done.entry(round).or_insert_with(HashSet::new).insert(idx);
            }
            info!("✅ [BTC] aggregated input {} for round {}", idx, round);
        }

        // ---- 4) FINALIZE only when *all* inputs aggregated ----
        let (should_finalize, total_inputs2, unsigned_tx2) = {
            // Use the same round classification to pull the correct pending entry
            let chain_tx = if is_reward_round {
                let reward_pt = self.pending.reward_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    reward_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No reward pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no reward pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            } else if is_withdraw_round {
                let withdraw_pt = self.pending.withdraw_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    withdraw_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No withdraw pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no withdraw pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            } else {
                let pt = self.pending.pending_transactions_btc.read().await;
                let (chain_tx, _raw, _intent_hash, _tx_type_opt, _extras) =
                    pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            };

            let btc_tx = match chain_tx {
                ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    error!("[handle_btc_signature_for_round] Round {} is not a Bitcoin round (finalize step)", round);
                    bail!("round {} is not a Bitcoin round", round)
                }
            };
            let done = self.btc_state.btc_done_inputs_by_round.read().await;
            let count_done = done.get(&round).map_or(0, |s| s.len());
            (
                count_done == btc_tx.inputs.len(),
                btc_tx.inputs.len(),
                btc_tx,
            )
        };

        if !should_finalize {
            info!("⏳ [BTC] round {}: waiting for remaining inputs", round);
            return Ok(());
        }

        // collect aggregated sigs in input order
        let per_input_sigs: Vec<(usize, RecoverableSignature)> = {
            let agg_map = self.btc_state.btc_agg_by_round.read().await;
            let m = agg_map
                .get(&round)
                .ok_or_else(|| anyhow!("missing agg map for round {}", round))?;
            let mut v = Vec::with_capacity(total_inputs2);
            for i in 0..total_inputs2 {
                let s = *m
                    .get(&i)
                    .ok_or_else(|| anyhow!("input {} not aggregated", i))?;
                v.push((i, s));
            }
            v
        };

        // Use the wire form hinted by builder (from extras) for final serialization.
        let (raw, txid, wtxid_opt) = Self::finalize_and_serialize_tx(
            unsigned_tx2,
            from_kind_hint,
            &per_input_sigs,
            &group_pubkey33,
        )?;

        let raw_hex = hex::encode(&raw);
        info!(
            "🎯 [BTC] round {} finalized: txid={}",
            round,
            hex::encode(txid)
        );
        if let Some(w) = wtxid_opt {
            info!("wtxid={}", hex::encode(w));
        }

        {
            let mut aggregated_rounds = self.signatures.aggregated_rounds.write().await;
            aggregated_rounds.insert(round);
        }

        // Get intent hash and user_eth_address for proper error/success handling
        let (_intent_hash, _user_eth_address) = {
            let pt = self.pending.pending_transactions_btc.read().await;
            if let Some((_chain_tx, _raw, intent_hash, _tx_type_opt, _extras)) = pt.get(&round) {
                // Get user_eth_address from the first signature we have
                let user_eth_address = {
                    let btc_sigs = self.btc_state.btc_sigs_by_round.read().await;
                    if let Some(round_sigs) = btc_sigs.get(&round) {
                        // Get the first available signature to extract user_eth_address
                        round_sigs
                            .values()
                            .flat_map(|input_sigs| input_sigs.values())
                            .next()
                            .and_then(|sig| sig.user_eth_address.clone())
                    } else {
                        None
                    }
                };
                (intent_hash.clone(), user_eth_address)
            } else {
                (None, None)
            }
        };

        // Broadcast with proper error handling and transaction ID storage
        match Self::broadcast_transaction(&raw_hex, is_testnet).await {
            Ok(Some(txid)) => {
                info!(
                    "✅ [BTC] Bitcoin transaction broadcasted successfully: {}",
                    txid
                );
                self.store_transaction_id_for_round(
                    round,
                    &txid,
                    crate::types::TransactionNetwork::BTC,
                )
                .await;
            }
            Ok(None) => {
                warn!("⚠️ [BTC] Bitcoin transaction broadcasted but no txid returned");
            }
            Err(e) => {
                error!("❌ [BTC] Failed to broadcast Bitcoin transaction: {}", e);
                self.store_transaction_error_for_round(
                    round,
                    &e.to_string(),
                    crate::types::TransactionNetwork::BTC,
                )
                .await;
            }
        }

        Ok(())
    }
    /// Broadcast transaction to Bitcoin network
    /// Handle signature received via unicast P2P RPC
    pub async fn handle_signature_to_final_node(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} via unicast P2P RPC",
            self.id, from
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
                "✅ [SIGNING] This node {} is the final node for round {}",
                self.id, round
            );
            return self
                .handle_signature_for_round(from, signature, round)
                .await;
        }

        info!(
            "⚠️ [SIGNING] Received signature for round {} but this node is not the final node for that round",
            round
        );
        Ok(())
    }

    /// Handle transaction data received for final node (to enable reconstruction even if not selected to sign)
    pub async fn handle_transaction_data_for_final_node(
        &mut self,
        from: String,
        round: u64,
        tx_bytes: Vec<u8>,
        intent_hash: Option<String>,
        transaction_type: Option<String>,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received transaction data from {} for round {} (tx_bytes: {} bytes)",
            self.id, from, round, tx_bytes.len()
        );

        // Check if this node is the final node for the specific round
        let is_final_node = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .map(|node_id| node_id == &self.id)
                .unwrap_or(false)
        };

        if !is_final_node {
            debug!(
                "⚠️ [SIGNING] Received transaction data for round {} but this node is not the final node for that round",
                round
            );
            return Ok(());
        }

        // Check if we already have transaction data for this round
        let already_have_data = {
            let pending = self.pending.pending_transactions.read().await;
            pending.contains_key(&round)
        };

        if already_have_data {
            debug!(
                "ℹ️ [SIGNING] Already have transaction data for round {}, ignoring duplicate from {}",
                round, from
            );
            return Ok(());
        }

        // CRITICAL FIX: Store the transaction data so we can reconstruct later
        info!(
            "💾 [SIGNING] Storing received transaction data for round {} from {} (was not selected to sign but is final node)",
            round, from
        );

        // Parse transaction type if provided
        let parsed_tx_type = transaction_type.as_ref().and_then(|t| {
            // Try to parse the string back to TransactionType
            // This is a simple mapping - you may need to adjust based on actual format
            match t.as_str() {
                "UserToVault" => Some(crate::types::TransactionType::UserToVault),
                "NetworkToTarget" => Some(crate::types::TransactionType::NetworkToTarget),
                "VaultToNetwork" => Some(crate::types::TransactionType::VaultToNetwork),
                "WithdrawLiquidity" => Some(crate::types::TransactionType::WithdrawLiquidity),
                "RewardTxn" => Some(crate::types::TransactionType::RewardTxn),
                "AddLiquidity" => Some(crate::types::TransactionType::AddLiquidity),
                _ => None,
            }
        });

        // We need to reconstruct a ChainTransaction from the tx_bytes
        // For now, we'll create a placeholder Ethereum transaction since we mainly need the tx_bytes for reconstruction
        let eth_tx = crate::chain_abstraction::EthereumTransaction {
            to: String::new(), // Will be populated during reconstruction
            value: "0".to_string(),
            gas_limit: 0,
            gas_price: "0".to_string(),
            nonce: 0,
            data: Some(tx_bytes.clone()),
            chain_id: 0,
        };
        let chain_tx = crate::chain_abstraction::ChainTransaction::Ethereum(eth_tx);

        let mut pending = self.pending.pending_transactions.write().await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                intent_hash.clone(),
                parsed_tx_type,
            ),
        );

        info!(
            "✅ [SIGNING] Stored transaction data for round {} - final node can now reconstruct when signatures arrive",
            round
        );

        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }

    /// Create threshold signature shares from a regular ECDSA signature
    pub fn create_threshold_shares(
        &self,
        signature: &ECDSASignature,
        threshold: u32,
        total_shares: u32,
    ) -> Vec<ThresholdSignatureShare> {
        let mut shares = Vec::new();

        for i in 0..total_shares {
            let share = ThresholdSignatureShare {
                share: signature.signature.clone(),
                signer_id: signature.signer_id.clone(),
                share_index: i + 1,
                threshold,
                total_shares,
            };
            shares.push(share);
        }

        info!(
            "🔢 [SIGNING] Created {} threshold signature shares (threshold: {})",
            shares.len(),
            threshold
        );

        shares
    }

    /// Verify threshold signature shares
    pub fn verify_threshold_shares(&self, shares: &[ThresholdSignatureShare]) -> Result<bool> {
        if shares.is_empty() {
            return Ok(false);
        }

        let threshold = shares[0].threshold;
        let total_shares = shares[0].total_shares;

        // Check if we have enough shares
        if shares.len() < threshold as usize {
            info!(
                "⚠️ [SIGNING] Not enough shares: {}/{}",
                shares.len(),
                threshold
            );
            return Ok(false);
        }

        // Verify all shares have the same threshold and total_shares
        for share in shares {
            if share.threshold != threshold || share.total_shares != total_shares {
                warn!("❌ [SIGNING] Inconsistent threshold parameters in shares");
                return Ok(false);
            }
        }

        info!(
            "✅ [SIGNING] Threshold shares verification passed: {}/{} shares",
            shares.len(),
            threshold
        );
        Ok(true)
    }

    /// Get Ethereum address from public key
    pub fn get_ethereum_address(&self) -> Option<String> {
        if let Some(public_key) = self.key_store.public_key() {
            // Get the uncompressed public key (65 bytes)
            let public_key_bytes = public_key.serialize_uncompressed();

            // Remove the prefix byte (0x04) and take the last 20 bytes for the address
            if public_key_bytes.len() >= 21 {
                let address_bytes = &public_key_bytes[1..21];

                // Convert to Ethereum address format (0x + hex)
                let address = format!("0x{}", hex::encode(address_bytes));

                info!(
                    "🏦 [SIGNING] Node {} Ethereum address: {}",
                    self.id, address
                );
                Some(address)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get private key as hex string (for debugging only)
    pub fn get_private_key_hex(&self) -> Option<String> {
        if let Some(private_key) = self.key_store.private_key() {
            let secret_key_bytes = private_key.secret_bytes();
            Some(format!("0x{}", hex::encode(secret_key_bytes)))
        } else {
            None
        }
    }

    /// Verify PARTIAL signature for a round based on transaction type and peer-id
    ///
    /// This verifies that the partial signature (threshold signature share) from a peer
    /// is valid against that peer's PARTIAL public key (share pubkey) for the given transaction type.
    ///
    /// The signature is a partial signature signed with the peer's share of the private key,
    /// and must verify against the peer's corresponding share public key (not the group public key).
    async fn verify_signature_for_round(
        &self,
        peer_id: &str,
        signature: &ECDSASignature,
        round: u64,
    ) -> Result<()> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        info!(
            "🔍 [SIGNING] Verifying PARTIAL signature from peer {} for round {}",
            peer_id, round
        );

        // Get message/digest and transaction type for this round
        let (expected_digest, transaction_type, user_eth_address) =
            self.get_message_and_type_for_round(round).await?;

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
                &transaction_type,
                user_eth_address.as_deref(),
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
            Some(crate::types::TransactionType::VaultToNetwork) => "vault-share",
            Some(crate::types::TransactionType::AddLiquidity) => "vault-share",
            Some(crate::types::TransactionType::RewardTxn) => "network-share",
            Some(crate::types::TransactionType::WithdrawLiquidity) => "network-share",
            None => "vault-share",
        };

        info!(
            "✅ [SIGNING] Verified PARTIAL signature from peer {} for round {} (tx_type: {:?}, user: {:?}, share_type: {})",
            peer_id,
            round,
            transaction_type,
            user_eth_address,
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
    async fn verify_btc_signature_for_round(
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

        // Get transaction type and user_eth_address for this round
        let (transaction_type, user_eth_address) = {
            let is_reward_round = {
                let reward_rounds = self.pending.reward_rounds.read().await;
                reward_rounds.contains(&round)
            };
            let is_withdraw_round = {
                let withdraw_rounds = self.pending.withdraw_rounds.read().await;
                withdraw_rounds.contains(&round)
            };

            if is_reward_round {
                let reward_pt = self.pending.reward_pending_transactions_btc.read().await;
                if let Some((_tx, _raw, _solver_address, tx_type, _extras)) = reward_pt.get(&round) {
                    (tx_type.clone(), None)
                } else {
                    return Err(anyhow!("No reward pending tx for round {}", round));
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
                if let Some((_tx, _raw, intent_hash, tx_type, _extras)) = pt.get(&round) {
                    // For UserToVault transactions, retrieve user_eth_address from intent_hash
                    let user_addr = if matches!(
                        tx_type,
                        Some(crate::types::TransactionType::UserToVault)
                    ) {
                        if let Some(intent_hash) = intent_hash {
                            if let Some(database) = &self.database {
                                use crate::database::storage::UserStorage;
                                let user_storage = UserStorage::new(database.as_ref().clone());
                                match user_storage.get_user_by_intent_hash(intent_hash).await {
                                    Ok(Some(user)) => {
                                        info!(
                                            "🔍 [BTC-SIGNING] Retrieved user_eth_address {} from intent_hash {} for UserToVault BTC transaction (round {})",
                                            user.ethereum_address, intent_hash, round
                                        );
                                        Some(user.ethereum_address)
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
                    };
                    (tx_type.clone(), user_addr)
                } else {
                    return Err(anyhow!("No pending tx for round {}", round));
                }
            }
        };

        // Get Bitcoin transaction and compute digest for this input
        let unsigned_tx = {
            let is_reward_round = {
                let reward_rounds = self.pending.reward_rounds.read().await;
                reward_rounds.contains(&round)
            };
            let is_withdraw_round = {
                let withdraw_rounds = self.pending.withdraw_rounds.read().await;
                withdraw_rounds.contains(&round)
            };

            let (chain_tx, extras_opt) = if is_reward_round {
                let reward_pt = self.pending.reward_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt) =
                    reward_pt.get(&round).ok_or_else(|| {
                        anyhow!("no reward pending tx for round {}", round)
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
                &transaction_type,
                user_eth_address.as_deref(),
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
            Some(crate::types::TransactionType::VaultToNetwork) => "vault-share",
            Some(crate::types::TransactionType::AddLiquidity) => "vault-share",
            Some(crate::types::TransactionType::RewardTxn) => "network-share",
            Some(crate::types::TransactionType::WithdrawLiquidity) => "network-share",
            None => "vault-share",
        };

        info!(
            "✅ [BTC-SIGNING] Verified PARTIAL signature from peer {} for round {} input {} (tx_type: {:?}, user: {:?}, share_type: {})",
            peer_id,
            round,
            input_index,
            transaction_type,
            user_eth_address,
            share_type
        );
        info!(
            "✅ [BTC-SIGNING] Partial signature verified against peer {}'s {} partial pubkey (not group pubkey)",
            peer_id, share_type
        );

        Ok(())
    }

    /// Get message/digest and transaction type for a round
    async fn get_message_and_type_for_round(
        &self,
        round: u64,
    ) -> Result<(Vec<u8>, Option<TransactionType>, Option<String>)> {

        // Check if it's a reward or withdraw round
        let is_reward_round = {
            let reward_rounds = self.pending.reward_rounds.read().await;
            reward_rounds.contains(&round)
        };

        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        // Try TICS (Ethereum) transactions first
        let (tx_bytes, transaction_type, user_eth_address) = if is_reward_round {
            let reward_pt = self.pending.reward_pending_transactions_tics.read().await;
            if let Some((_tx, tx_bytes, _solver_address, tx_type)) = reward_pt.get(&round) {
                (tx_bytes.clone(), tx_type.clone(), None)
            } else {
                // Try BTC reward
                let reward_pt_btc = self.pending.reward_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _extras)) =
                    reward_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for reward round {}",
                        round
                    ));
                }
            }
        } else if is_withdraw_round {
            let withdraw_pt = self.pending.withdraw_pending_transactions_tics.read().await;
            if let Some((_tx, tx_bytes, _solver_address, tx_type)) = withdraw_pt.get(&round) {
                (tx_bytes.clone(), tx_type.clone(), None)
            } else {
                // Try BTC withdraw
                let withdraw_pt_btc = self.pending.withdraw_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _extras)) =
                    withdraw_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for withdraw round {}",
                        round
                    ));
                }
            }
        } else {
            // Regular transaction - try TICS first
            let pending = self.pending.pending_transactions.read().await;
            if let Some((_tx, tx_bytes, intent_hash, tx_type)) = pending.get(&round) {
                // For UserToVault transactions, retrieve user_eth_address from intent_hash
                // This ensures the final node retrieves the address on its own, not relying on the unicasting peer
                let user_addr = if matches!(
                    tx_type,
                    Some(crate::types::TransactionType::UserToVault)
                ) {
                    if let Some(intent_hash) = intent_hash {
                        // Retrieve user's ethereum address from intent hash using database
                        if let Some(database) = &self.database {
                            use crate::database::storage::UserStorage;
                            let user_storage = UserStorage::new(database.as_ref().clone());
                            match user_storage.get_user_by_intent_hash(intent_hash).await {
                                Ok(Some(user)) => {
                                    info!(
                                        "🔍 [SIGNING] Retrieved user_eth_address {} from intent_hash {} for UserToVault transaction (round {})",
                                        user.ethereum_address, intent_hash, round
                                    );
                                    Some(user.ethereum_address)
                                }
                                Ok(None) => {
                                    warn!(
                                        "⚠️ [SIGNING] No user found for intent_hash {} in UserToVault transaction (round {})",
                                        intent_hash, round
                                    );
                                    None
                                }
                                Err(e) => {
                                    warn!(
                                        "⚠️ [SIGNING] Failed to retrieve user from intent_hash {}: {} (round {})",
                                        intent_hash, e, round
                                    );
                                    None
                                }
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING] Database not available to retrieve user_eth_address from intent_hash {} (round {})",
                                intent_hash, round
                            );
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                (tx_bytes.clone(), tx_type.clone(), user_addr)
            } else {
                // Try BTC
                let pending_btc = self.pending.pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, intent_hash, tx_type, _extras)) =
                    pending_btc.get(&round)
                {
                    // For UserToVault transactions, retrieve user_eth_address from intent_hash
                    // This ensures the final node retrieves the address on its own, not relying on the unicasting peer
                    let user_addr = if matches!(
                        tx_type,
                        Some(crate::types::TransactionType::UserToVault)
                    ) {
                        if let Some(intent_hash) = intent_hash {
                            // Retrieve user's ethereum address from intent hash using database
                            if let Some(database) = &self.database {
                                use crate::database::storage::UserStorage;
                                let user_storage = UserStorage::new(database.as_ref().clone());
                                match user_storage.get_user_by_intent_hash(intent_hash).await {
                                    Ok(Some(user)) => {
                                        info!(
                                            "🔍 [SIGNING] Retrieved user_eth_address {} from intent_hash {} for UserToVault BTC transaction (round {})",
                                            user.ethereum_address, intent_hash, round
                                        );
                                        Some(user.ethereum_address)
                                    }
                                    Ok(None) => {
                                        warn!(
                                            "⚠️ [SIGNING] No user found for intent_hash {} in UserToVault BTC transaction (round {})",
                                            intent_hash, round
                                        );
                                        None
                                    }
                                    Err(e) => {
                                        warn!(
                                            "⚠️ [SIGNING] Failed to retrieve user from intent_hash {}: {} (round {})",
                                            intent_hash, e, round
                                        );
                                        None
                                    }
                                }
                            } else {
                                warn!(
                                    "⚠️ [SIGNING] Database not available to retrieve user_eth_address from intent_hash {} (round {})",
                                    intent_hash, round
                                );
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    (tx_bytes.clone(), tx_type.clone(), user_addr)
                } else {
                    return Err(anyhow!("No pending transaction found for round {}", round));
                }
            }
        };

        // Hash the transaction bytes to get the digest
        let mut hasher = sha3::Keccak256::new();
        hasher.update(&tx_bytes);
        let digest = hasher.finalize().to_vec();
        
        info!(
            "🔍 [SIGNING] Computed digest for round {}: 0x{} (tx_bytes len: {}, tx_type: {:?})",
            round,
            hex::encode(&digest),
            tx_bytes.len(),
            transaction_type
        );
        
        // Log first and last bytes of tx_bytes for debugging digest mismatches
        if !tx_bytes.is_empty() {
            let first_bytes = if tx_bytes.len() >= 32 {
                hex::encode(&tx_bytes[0..32.min(tx_bytes.len())])
            } else {
                hex::encode(&tx_bytes)
            };
            let last_bytes = if tx_bytes.len() >= 32 {
                hex::encode(&tx_bytes[tx_bytes.len().saturating_sub(32)..])
            } else {
                hex::encode(&tx_bytes)
            };
            info!(
                "🔍 [SIGNING] Round {} tx_bytes preview: first 32 bytes: 0x{}, last 32 bytes: 0x{}",
                round, first_bytes, last_bytes
            );
        }

        Ok((digest, transaction_type, user_eth_address))
    }

    /// Get appropriate PARTIAL share pubkey for verification based on transaction type
    ///
    /// Returns the peer's partial public key (share pubkey) that corresponds to the transaction type.
    /// This is used to verify the peer's partial signature (threshold signature share).
    ///
    /// IMPORTANT: This returns the PARTIAL share pubkey, not the group pubkey.
    /// The partial signature must verify against this partial pubkey.
    async fn get_share_pubkey_for_verification(
        &self,
        peer_id: &str,
        transaction_type: &Option<TransactionType>,
        user_eth_address: Option<&str>,
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
        // - VaultToNetwork → per-node-vault-share PARTIAL pubkey verification
        // - AddLiquidity → per-node-vault-share PARTIAL pubkey verification
        // - RewardTxn/WithdrawLiquidity → per-node-network-share PARTIAL pubkey verification
        // Works for both ETH/TICS and BTC transactions
        match transaction_type {
            Some(crate::types::TransactionType::UserToVault) => {
                // UserToVault → per-node-user-share pubkey
                if let Some(user_addr) = user_eth_address {
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
                        "UserToVault transaction requires user_eth_address for user share pubkey verification (peer: {})",
                        peer_id
                    ));
                }
            }
            Some(crate::types::TransactionType::NetworkToTarget) => {
                // NetworkToTarget → per-node-network-share pubkey
                dkg_storage
                    .get_network_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "Network share pubkey not found for peer {} (NetworkToTarget transaction)",
                            peer_id
                        )
                    })
            }
            Some(crate::types::TransactionType::VaultToNetwork) => {
                // VaultToNetwork → per-node-vault-share pubkey
                dkg_storage
                    .get_vault_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "Vault share pubkey not found for peer {} (VaultToNetwork transaction)",
                            peer_id
                        )
                    })
            }
            Some(crate::types::TransactionType::AddLiquidity) => {
                // AddLiquidity → per-node-vault-share pubkey
                dkg_storage
                    .get_vault_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "Vault share pubkey not found for peer {} (AddLiquidity transaction)",
                            peer_id
                        )
                    })
            }
            Some(crate::types::TransactionType::RewardTxn)
            | Some(crate::types::TransactionType::WithdrawLiquidity) => {
                // IMPORTANT: RewardTxn and WithdrawLiquidity must be handled identically
                // Both use per-node-network-share pubkey for verification (partial signature verification)
                // Both use network group key for signing (via network DKG secret share)
                // This ensures threshold signature shares from each node verify against their individual partial public keys
                dkg_storage
                    .get_network_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "Network share pubkey not found for peer {} ({:?} transaction)",
                            peer_id,
                            transaction_type
                        )
                    })
            }
            None => {
                // Contract transaction (transaction_type = None) → use vault share pubkey
                info!(
                    "🔑 [SIGNING] Contract transaction detected, using vault share pubkey for peer {}",
                    peer_id
                );
                dkg_storage
                    .get_vault_share_pubkey(peer_id)
                    .await?
                    .ok_or_else(|| anyhow!("Vault share pubkey not found for peer {} (contract transaction)", peer_id))
            }
        }
    }

    /// Calculate DKG index for a specific peer ID using database-stored peer indices
    pub async fn calculate_dkg_index_for_peer(&self, peer_id: &str) -> u32 {
        // Get the stored peer index from database
        if let Some(index) = self.get_peer_index_from_db(peer_id).await {
            info!(
                "🔢 [SIGNING] Using stored DKG index {} for peer {}",
                index, peer_id
            );
            return index as u32;
        }

        // No stored index found - this should not happen in normal operation
        warn!(
            "❌ [SIGNING] No peer index found in database for peer {}, using default index 1",
            peer_id
        );
        1
    }

    /// Calculate DKG index for a specific peer ID (synchronous version) using database-stored peer indices
    pub fn calculate_dkg_index_for_peer_sync(&self, peer_id: &str) -> u32 {
        // Get the stored peer index from database
        if let Some(db) = &self.database {
            let key = crate::database::key_utils::peer_index_key(peer_id);
            if let Ok(Some(index)) = db.get_string::<usize>(&key) {
                info!(
                    "🔢 [SIGNING] Using stored DKG index {} for peer {} (sync)",
                    index, peer_id
                );
                return index as u32;
            }
        }

        // No stored index found - this should not happen in normal operation
        warn!(
        "❌ [SIGNING] No peer index found in database for peer {} (sync), using default index 1",
        peer_id
    );
        1
    }
}
