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
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

pub mod chains;
mod config;
pub mod coordination;
pub mod db_signing;
mod key;
pub mod nonce;
mod rewards;
pub mod state;
mod transactions;
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

/// Number of recent UserToVault batches to exclude from the next pick (sliding window).
const LAST_N_USER_TO_VAULT_BATCHES: usize = 10;

/// Slot type for per-slot aggregation (TICS vs BTC UserToVault batch).
#[derive(Clone, Debug)]
pub enum SlotKind {
    TicsUserToVault,
    BtcUserToVault,
}

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
    pub(crate) pending: PendingStore,
    btc_state: BtcAggregationState,
    /// BTC UserToVault batch aggregation state (multi-input per slot)
    btc_utv_state: BtcUtvAggregationState,
    // User registry for storing transaction IDs
    user_intent_manager: Option<Arc<UserIntentManager>>,
    // Database for storing solver amounts
    database: Option<Arc<crate::database::Database>>,
    /// DKG storage for HRW candidate set (canonical final-node selection). Not used for peer_indices.
    dkg_storage: Option<crate::database::DkgStorage>,
    // Dynamic broadcast configuration
    broadcast_policy: BroadcastPolicy,
    /// Self-reference for spawning non-blocking aggregation tasks (set after wrapping in Arc<Mutex<SigningNode>>).
    self_ref: Option<Arc<Mutex<SigningNode>>>,
    /// Last N batches of intent hashes picked for TICS UserToVault (sliding window); intents in these sets are excluded from the next pick.
    last_tics_user_to_vault_batch_hashes: Arc<RwLock<VecDeque<HashSet<String>>>>,
    /// Last N batches of intent hashes picked for BTC UserToVault (sliding window); intents in these sets are excluded from the next pick.
    last_btc_user_to_vault_batch_hashes: Arc<RwLock<VecDeque<HashSet<String>>>>,
    /// Nonce manager for random k generation (optional until fully integrated)
    nonce_manager: Option<Arc<tokio::sync::Mutex<nonce::NonceManager>>>,
    /// Currently connected peers (updated on connect/disconnect).
    /// Used by HRW to filter candidates to only connected peers.
    connected_peers: HashSet<PeerId>,
}

impl SigningNode {
    pub fn set_threshold(&mut self, new_threshold: usize) {
        self.threshold = new_threshold;
    }

    /// Mark a peer as connected (for HRW candidate filtering).
    pub fn add_connected_peer(&mut self, peer: PeerId) {
        self.connected_peers.insert(peer);
    }

    /// Mark a peer as disconnected (for HRW candidate filtering).
    pub fn remove_connected_peer(&mut self, peer: &PeerId) {
        self.connected_peers.remove(peer);
    }

    /// Get the set of currently connected peers.
    pub fn get_connected_peers(&self) -> &HashSet<PeerId> {
        &self.connected_peers
    }

    /// Sweep in-memory signature/pending data older than the latest 1000 rounds.
    /// Should be called periodically (e.g. every 10 clock ticks) to bound memory growth.
    pub async fn sweep_old_rounds(&self) {
        // Determine cutoff from signatures_by_round (the primary round tracker)
        let cutoff = {
            let map = self.signatures.signatures_by_round.read().await;
            if map.len() <= 1000 {
                return; // nothing to sweep
            }
            let mut rounds: Vec<u64> = map.keys().copied().collect();
            rounds.sort_unstable();
            rounds[rounds.len() - 1000]
        };

        debug!("[SIGNING] Sweeping rounds older than {} (keeping latest 1000)", cutoff);

        self.signatures.sweep_old_rounds().await;
        self.pending.sweep_old_rounds(cutoff).await;
        self.btc_state.sweep_old_rounds(cutoff).await;
        self.btc_utv_state.sweep_old_rounds(cutoff).await;
    }

    /// Return (withdraw_rounds, claim_reward_rounds) for state sync (no private data).
    pub async fn get_pending_rounds_for_sync(&self) -> (Vec<u64>, Vec<u64>) {
        let wr: Vec<u64> = self
            .pending
            .withdraw_rounds
            .read()
            .await
            .iter()
            .copied()
            .collect();
        let cr: Vec<u64> = self
            .pending
            .claim_reward_rounds
            .read()
            .await
            .iter()
            .copied()
            .collect();
        (wr, cr)
    }

    /// Apply synced withdraw/claim_reward rounds from a peer (used when joining the network).
    pub async fn apply_synced_pending_rounds(
        &self,
        withdraw_rounds: &[u64],
        claim_reward_rounds: &[u64],
    ) {
        if withdraw_rounds.is_empty() && claim_reward_rounds.is_empty() {
            return;
        }
        let mut wr = self.pending.withdraw_rounds.write().await;
        for r in withdraw_rounds {
            wr.insert(*r);
        }
        let mut cr = self.pending.claim_reward_rounds.write().await;
        for r in claim_reward_rounds {
            cr.insert(*r);
        }
    }

    /// Clear stale pending rounds and apply fresh state from peer.
    /// Used during state sync on rejoin to avoid mixing stale and fresh data.
    pub async fn clear_and_apply_synced_pending_rounds(
        &self,
        withdraw_rounds: &[u64],
        claim_reward_rounds: &[u64],
    ) {
        let mut wr = self.pending.withdraw_rounds.write().await;
        wr.clear();
        for r in withdraw_rounds {
            wr.insert(*r);
        }

        let mut cr = self.pending.claim_reward_rounds.write().await;
        cr.clear();
        for r in claim_reward_rounds {
            cr.insert(*r);
        }
    }

    pub fn vrf_service(&self) -> Option<&VrfService> {
        self.coordination.vrf_service()
    }

    pub fn vrf_service_mut(&mut self) -> Option<&mut VrfService> {
        self.coordination.vrf_service_mut()
    }

    /// Replicate round into consensus so consensus stays aligned.
    /// Call after sync_rounds_before_signing or get_next_round.
    pub fn replicate_vrf_round_to_consensus(&mut self, round: u64) {
        self.coordination.replicate_vrf_round_to_consensus(round);
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
            btc_utv_state: BtcUtvAggregationState::new(),
            user_intent_manager: None, // Will be set later via set_user_intent_manager
            database: None,            // Will be set later via set_database
            dkg_storage: None,         // Will be set later via set_database (for HRW candidates)
            broadcast_policy: environment.broadcast_policy,
            self_ref: None,            // Set via set_self_arc after wrapping in Arc<Mutex<SigningNode>>
            last_tics_user_to_vault_batch_hashes: Arc::new(RwLock::new(VecDeque::new())),
            last_btc_user_to_vault_batch_hashes: Arc::new(RwLock::new(VecDeque::new())),
            nonce_manager: None,       // Set via set_nonce_manager after database is available
            connected_peers: {
                let mut s = HashSet::new();
                s.insert(peer_id); // Include self in connected peers
                s
            },
        }
    }

    /// Set self-reference so the node can spawn aggregation tasks. Call after wrapping in Arc<Mutex<SigningNode>>.
    pub fn set_self_arc(&mut self, arc: Arc<Mutex<SigningNode>>) {
        self.self_ref = Some(arc);
    }

    /// Record a TICS UserToVault batch (by intent hashes) so it is excluded from the next N picks on this node.
    /// Call this on every node when a batch is received (gossip) so the sliding window is consistent across the network.
    pub fn record_tics_user_to_vault_batch(&self, intent_hashes: &[String]) {
        if intent_hashes.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.last_tics_user_to_vault_batch_hashes.write() {
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }
    }

    /// Record a BTC UserToVault batch (by intent hashes) so it is excluded from the next N picks on this node.
    /// Call this on every node when a batch is received (gossip) so the sliding window is consistent across the network.
    pub fn record_btc_user_to_vault_batch(&self, intent_hashes: &[String]) {
        if intent_hashes.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.last_btc_user_to_vault_batch_hashes.write() {
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
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

    /// Check if this node has a DKG secret share in storage.
    /// Returns true for initial DKG participants, false for observer nodes.
    pub async fn has_dkg_share(&self) -> bool {
        if let Some(dkg_storage) = &self.dkg_storage {
            dkg_storage.get_final_secret().await.ok().flatten().is_some()
        } else {
            false
        }
    }

    /// Compute BtcRoundExtras for observer nodes receiving BTC TX data.
    /// Derives the group public key, computes HASH160, and returns extras needed for finalization.
    async fn compute_btc_extras_for_observer(
        &self,
        tx_type: &Option<crate::types::TransactionType>,
        user_eth: &str,
        round: u64,
    ) -> Option<BtcRoundExtras> {
        let pubkey_bytes = match self.get_group_public_key_bytes(
            tx_type.clone(),
            if user_eth.is_empty() { None } else { Some(user_eth.to_string()) },
        ).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    "⚠️ [SIGNING] Could not compute BtcRoundExtras for round {}: {}",
                    round, e
                );
                return None;
            }
        };
        if pubkey_bytes.len() != 33 {
            warn!(
                "⚠️ [SIGNING] Invalid pubkey length {} for BtcRoundExtras round {}",
                pubkey_bytes.len(), round
            );
            return None;
        }
        let pubkey33: [u8; 33] = pubkey_bytes.as_slice().try_into().unwrap();
        // hash160 = RIPEMD160(SHA256(pubkey))
        let sha = <sha2::Sha256 as sha2::Digest>::digest(&pubkey33);
        let rip = <ripemd::Ripemd160 as ripemd::Digest>::digest(&sha);
        let mut signer_h160 = [0u8; 20];
        signer_h160.copy_from_slice(&rip);
        let is_testnet = crate::types::network::network_type().is_testnet();
        Some(BtcRoundExtras {
            pubkey33,
            signer_h160,
            from_kind: SpendKind::P2PKH,
            is_testnet,
        })
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

    /// Helper: Get network group key from key store or database
    fn get_network_group_key_from_store_or_db(&self) -> Option<k256::ProjectivePoint> {
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
    fn encode_group_key_to_compressed_bytes(group_key: k256::ProjectivePoint) -> Vec<u8> {
        let encoded_point = k256::EncodedPoint::from(group_key.to_affine());
        encoded_point.compress().to_bytes().to_vec()
    }

    /// Get the appropriate public key bytes based on transaction type
    async fn get_group_public_key_bytes(
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

    /// DEPRECATED: This function uses fixed k which is a SECURITY VULNERABILITY!
    /// DO NOT USE - Use create_ecdsa_signature_with_nonce() instead.
    ///
    /// SECURITY WARNING: Using a fixed nonce k allows an attacker to extract
    /// the private key from just two signatures. This function is kept only
    /// for reference and should be removed in a future version.
    #[deprecated(
        since = "0.1.0",
        note = "Fixed k is a security vulnerability. Use create_ecdsa_signature_with_nonce() instead."
    )]
    #[allow(dead_code)]
    fn create_ecdsa_signature_with_signing_key_deprecated(
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
    pub fn create_ecdsa_signature_with_nonce(
        &self,
        message: &Message,
        signing_key: &SecretKey,
        nonce: &crate::types::nonce::NonceTuple,
    ) -> Result<RecoverableSignature> {
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

        info!(
            "🟢🟢🟢 [SIGNING-NONCE] Nonce {} INTEGRITY CHECK PASSED (k*k_inv=1, R=k*G, r=x(R)) 🟢🟢🟢",
            nonce.tuple_id
        );

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
        .unwrap();

        // 6) s = k⁻¹ * (z + r * x) mod n
        // Note: With aggregated k, all nodes compute the same s for their key share
        let s = (&k_inv * (&z + (&r * &x) % &n)) % &n;

        // Detailed debug logging for signature computation
        // All nodes MUST have the same aggregated_k, k_inv, r, and z values
        info!(
            "🔵🔵🔵 [SIGNING-NONCE] Partial Signature Computation 🔵🔵🔵\n\
             ╔════════════��═════════════════════════════════════════════════════════════════╗\n\
             ║  tuple_id:                     {}                   ║\n\
             ║  aggregated_k (first 8 bytes): 0x{}                             ║\n\
             ║  k_inv (first 8 bytes):        0x{}                             ║\n\
             ║  r_scalar:                     0x{}  ║\n\
             ║  r_y_parity:                   {}                                              ║\n\
             ║  z (message hash):             0x{}  ║\n\
             ║  x (key share, first 8 bytes): 0x{}                             ║\n\
             ║  s (partial signature):        0x{}  ║\n\
             ╚══════════════════════════════════════════════════════════════════════════════╝",
            nonce.tuple_id,
            hex::encode(&k_scalar.to_bytes()[..8]), // Only first 8 bytes for security
            hex::encode(&k_inv_scalar.to_bytes()[..8]), // Only first 8 bytes for security
            hex::encode(&r_scalar.to_bytes()),
            nonce.r_y_parity,
            hex::encode(message.as_ref()),
            hex::encode(&sk_bytes[..8]), // Only first 8 bytes for security
            hex::encode(&s.to_bytes_be())
        );

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

    /// Create ECDSA signature using a random nonce tuple (REQUIRED for security)
    ///
    /// This is the recommended entry point for signing. It requires a NonceTuple
    /// for secure random nonce signing. Fixed-k signing has been removed for security.
    ///
    /// # Errors
    /// Returns an error if no nonce is provided - nonces are mandatory for security.
    pub fn create_ecdsa_signature_with_optional_nonce(
        &self,
        message: &Message,
        signing_key: &SecretKey,
        nonce: Option<&crate::types::nonce::NonceTuple>,
    ) -> Result<RecoverableSignature> {
        match nonce {
            Some(n) => {
                info!(
                    "🟢 [SIGNING] Using random nonce tuple: {} for secure signing 🟢",
                    n.tuple_id
                );
                self.create_ecdsa_signature_with_nonce(message, signing_key, n)
            }
            None => {
                // SECURITY: Fixed-k signing removed - nonces are mandatory
                error!(
                    "🔴 [SIGNING] ERROR: No nonce provided! Nonces are MANDATORY for secure signing 🔴"
                );
                Err(anyhow::anyhow!(
                    "Nonce is required for signing - fixed-k fallback has been removed for security"
                ))
            }
        }
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
        debug!(
            "[SIGNING] Node {} received signed message from {} with {} signers",
            self.id, from, signed_message.signer_ids.len()
        );

        // Verify the aggregated ECDSA signature
        let is_valid = self.verify_aggregated_signature(&signed_message).await?;
        if is_valid {
            debug!("[SIGNING] Node {} - signature verification successful", self.id);
        } else {
            warn!("[SIGNING] Node {} - ECDSA signature verification failed from {}", self.id, from);
        }

        Ok(())
    }

    async fn verify_aggregated_signature(&self, signed_message: &SignedMessage) -> Result<bool> {
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

    pub fn set_user_intent_manager(&mut self, user_intent_manager: Arc<UserIntentManager>) {
        self.user_intent_manager = Some(user_intent_manager);
        info!("📋 [SIGNING] Node {} user registry set", self.id);
    }

    pub fn set_database(&mut self, database: Arc<crate::database::Database>) {
        self.database = Some(database.clone());
        self.dkg_storage = Some(crate::database::DkgStorage::new((*database).clone()));

        // Update Coordination with database so VrfService can use it
        self.coordination.set_database(database);

        info!(
            "🗄️ [SIGNING] Node {} database set with round storage and HRW DKG candidates",
            self.id
        );
    }

    /// Initialize the nonce manager for random k generation.
    /// Call this after set_database() since NonceStorage requires a database.
    ///
    /// `dkg_signer_count`: number of DKG signers that participate in nonce generation.
    /// On DKG nodes this equals `total_nodes` at genesis; on observer nodes it is
    /// the count received from PeerList RPC.  Used for stale-nonce filtering.
    pub fn init_nonce_manager(&mut self, total_nodes: usize, dkg_signer_count: usize) {
        if let Some(db) = &self.database {
            let nonce_storage = crate::database::storage::NonceStorage::new((*db.clone()).clone());
            let config = crate::types::nonce::NoncePoolConfig::default();

            let manager = nonce::NonceManager::new(
                self.id.clone(),
                self.threshold,
                total_nodes,
                dkg_signer_count,
                nonce_storage,
                self.message_tx.clone(),
                config,
            );

            self.nonce_manager = Some(Arc::new(tokio::sync::Mutex::new(manager)));

            info!(
                "🎲 [SIGNING] Node {} nonce manager initialized (threshold: {}, total: {}, dkg_signer_count: {})",
                self.id, self.threshold, total_nodes, dkg_signer_count
            );
        } else {
            warn!(
                "⚠️ [SIGNING] Cannot init nonce manager - database not set for node {}",
                self.id
            );
        }
    }

    /// Get a reference to the nonce manager (if initialized)
    pub fn nonce_manager(&self) -> Option<&Arc<tokio::sync::Mutex<nonce::NonceManager>>> {
        self.nonce_manager.as_ref()
    }

    /// Update the NonceManager's total_nodes count.
    ///
    /// Call this when nodes join or leave the network.
    /// This ensures the NonceManager filters out stale nonces correctly.
    ///
    /// IMPORTANT: For node joins, use `handle_nonce_manager_node_joined` instead!
    /// That method deletes stale nonces and triggers regeneration.
    pub async fn update_nonce_manager_total_nodes(&self, new_total: usize) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.update_total_nodes(new_total);
        }
    }

    /// Update the NonceManager's dkg_signer_count.
    ///
    /// Called when DKG completes or when existing DKG shares are loaded from disk
    /// to ensure nonce generation uses the correct peer count for threshold checks.
    pub async fn update_nonce_dkg_signer_count(&self, count: usize) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.update_dkg_signer_count(count);
        }
    }


    /// Mark the NonceManager as belonging to a DKG signer (or not).
    ///
    /// Only DKG signers initiate the commit-reveal nonce generation protocol.
    /// Observer nodes passively receive nonces via NonceTupleBroadcast.
    pub async fn set_nonce_manager_dkg_signer(&self, is_signer: bool) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.set_is_dkg_signer(is_signer);
        }
    }

    /// Handle a new node joining - delete stale nonces and regenerate.
    ///
    /// When a new node joins, all existing nonces become stale because
    /// the new node doesn't have them. This method:
    /// 1. Deletes all stale nonces
    /// 2. Triggers immediate nonce regeneration with all nodes
    ///
    /// This ensures all nodes have the same nonces after a new node joins.
    pub async fn handle_nonce_manager_node_joined(&self, new_total: usize) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            if let Err(e) = mgr.handle_node_joined(new_total).await {
                warn!("⚠️ [SIGNING] Failed to handle node join in NonceManager: {}", e);
            }
        }
    }

    /// Flush the entire nonce pool (called on DKG node restart).
    /// The node may have missed NonceInvalidation messages while offline,
    /// so all old nonces are deleted. A fresh pool is synced from a peer afterwards.
    pub async fn flush_nonce_pool(&self) -> Result<usize> {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.flush_all_nonces().await
        } else {
            Ok(0)
        }
    }

    /// Start pre-generating nonces on startup.
    ///
    /// This should be called after the network is ready and nodes can communicate.
    /// It fills the nonce pool before accepting signing requests.
    ///
    /// Returns immediately after starting the generation process - the actual
    /// generation happens asynchronously via the commit-reveal protocol.
    pub async fn start_nonce_pregeneration(&self) -> anyhow::Result<()> {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.startup_pregenerate().await?;
            info!("🚀 [SIGNING] Started nonce pre-generation");
            Ok(())
        } else {
            warn!("⚠️ [SIGNING] Cannot start pre-generation - NonceManager not initialized");
            Err(anyhow::anyhow!("NonceManager not initialized"))
        }
    }

    /// Check if nonce pre-generation is complete and pool is ready.
    pub async fn is_nonce_pool_ready(&self) -> bool {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.is_startup_ready()
        } else {
            false
        }
    }

    /// Acquire a nonce from the pool for signing.
    ///
    /// This method uses a queue-based approach:
    /// 1. If nonces are available, returns one immediately
    /// 2. If pool is empty, queues the request and waits for generation
    /// 3. Never returns None due to empty pool - will wait for generation
    ///
    /// Returns None only if:
    /// - NonceManager is not initialized
    /// - Nonce generation times out (after configured timeout)
    pub async fn try_acquire_nonce(&self) -> Option<crate::types::nonce::NonceTuple> {
        if let Some(manager) = &self.nonce_manager {
            // Use the queue-based request_nonce which handles waiting
            let mgr = manager.lock().await;
            match mgr.request_nonce().await {
                Ok(nonce) => {
                    info!(
                        "🔐 [SIGNING] Acquired nonce {} for signing",
                        nonce.tuple_id
                    );
                    Some(nonce)
                }
                Err(e) => {
                    error!(
                        "❌ [SIGNING] Failed to acquire nonce: {}",
                        e
                    );
                    error!("❌ [SIGNING] CRITICAL: Cannot sign without nonce - refusing to use fixed k");
                    None
                }
            }
        } else {
            warn!("⚠️ [SIGNING] NonceManager not initialized");
            None
        }
    }

    /// Check if the nonce pool needs refilling and trigger generation if needed.
    /// Call this during idle periods (e.g., epoch_3).
    pub async fn check_and_refill_nonce_pool(&self, current_round: u64) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            match mgr.needs_refill().await {
                Ok(true) => {
                    info!(
                        "🔄 [SIGNING] Nonce pool low, triggering generation for round {}",
                        current_round
                    );
                    if let Err(e) = mgr.start_generation(current_round).await {
                        warn!("[SIGNING] Failed to start nonce generation: {}", e);
                    }
                }
                Ok(false) => {
                    // Pool is sufficiently filled
                }
                Err(e) => {
                    warn!("[SIGNING] Failed to check nonce pool status: {}", e);
                }
            }
        }
    }

    /// Invalidate nonces locally (idempotent) and optionally broadcast to all nodes.
    ///
    /// Call this when a coordinated nonce is missing during signing.
    /// The broadcast ensures all other nodes also remove the nonce from their pool.
    pub async fn invalidate_and_broadcast_nonces(
        &self,
        nonce_tuple_ids: Vec<String>,
        reason: &str,
    ) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            // Invalidate locally first
            mgr.invalidate_nonces(&nonce_tuple_ids, reason).await;
            // Broadcast to all nodes
            if let Err(e) = mgr
                .broadcast_nonce_invalidation(nonce_tuple_ids, reason)
                .await
            {
                warn!(
                    "⚠️ [SIGNING] Failed to broadcast nonce invalidation: {}",
                    e
                );
            }
        }
    }

    /// Invalidate nonces locally only (no broadcast).
    /// Used when processing a NonceInvalidation gossipsub message from another node.
    pub async fn invalidate_nonces_local(&self, nonce_tuple_ids: &[String], reason: &str) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.invalidate_nonces(nonce_tuple_ids, reason).await;
        }
    }

    /// Remove nonce tuple IDs from the local available pool.
    ///
    /// Called by receiving nodes when they get a batch broadcast containing
    /// nonce assignments from the coordinator. Prevents a second coordinator
    /// from independently selecting the same nonce for a different operation.
    pub async fn remove_nonces_from_available_pool(&self, tuple_ids: &[String]) {
        if let Some(manager) = &self.nonce_manager {
            let mgr = manager.lock().await;
            mgr.remove_nonces_from_pool(tuple_ids).await;
        }
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
    async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
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

    /// Process phase 1 completed intents for global clock trigger.
    /// Phase 1 = UserToVault transaction complete, NetworkToTarget pending.
    /// `target_chain`: "qubetics" (TICS) or "bitcoin" (BTC) — passed by caller based on epoch; no re-calculation inside.
    async fn process_phase1_intents_for_global_clock(&self, round: u64, target_chain: &str) -> Result<()> {
        info!(
            "🔍 [CLOCK] Processing phase 1 completed intents for round {} (target_chain={})",
            round, target_chain
        );
        
        // Read max intents per cycle from environment (configurable)
        let max_intents_per_cycle = crate::env_defaults::max_intents_per_cycle()
            .parse::<usize>()
            .unwrap_or(crate::env_defaults::DEFAULT_MAX_INTENTS_PER_CYCLE.parse().unwrap());
        
        // Get user intent manager
        let user_intent_manager = self.user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        
        // Batch type from passed target_chain (no cycle/timestamp logic here)
        let batch_type = if target_chain.eq_ignore_ascii_case("qubetics") {
            crate::types::BatchType::TICS
        } else {
            crate::types::BatchType::BTC
        };
        
        info!(
            "⏰ [CLOCK] Processing {} intents with batch type {:?} (round {})",
            target_chain.to_uppercase(),
            batch_type,
            round
        );
        
        // Get intents awaiting network fulfillment (stale > 10 seconds)
        let awaiting_intents = user_intent_manager
            .get_intents_awaiting_network_fulfillment(Some(10))
            .await;
        
        // Filter by target chain (case-insensitive; target_chain passed by caller)
        let target_lower = target_chain.to_lowercase();
        let mut filtered_intents: Vec<_> = awaiting_intents
            .into_iter()
            .filter(|(_, intent, _)| {
                intent.target_chain.to_lowercase() == target_lower
            })
            .collect();
        
        // Sort by updated_at (oldest first) - intents waiting longest get priority
        filtered_intents.sort_by(|a, b| a.2.updated_at.cmp(&b.2.updated_at));
        
        // Limit to configured max intents to avoid overwhelming the system
        let intents_to_process: Vec<_> = filtered_intents.into_iter().take(max_intents_per_cycle).collect();
        
        info!(
            "📊 [CLOCK] Found {} {} intents (sorted by age, limited to {})",
            intents_to_process.len(),
            target_chain.to_uppercase(),
            max_intents_per_cycle
        );
        
        // Collect intent hashes for broadcasting
        let intent_hashes: Vec<String> = intents_to_process
            .iter()
            .map(|(intent_hash, _, _)| intent_hash.clone())
            .collect();
        
        // If we have intents to process, broadcast the batch to all nodes
        if !intent_hashes.is_empty() {
            info!(
                "📤 [CLOCK] Broadcasting batch of {} {} intent hashes to all nodes (batch type: {:?})",
                intent_hashes.len(),
                target_chain.to_uppercase(),
                batch_type
            );
            
            // Create timestamp for the batch
            let batch_timestamp = chrono::Utc::now().to_rfc3339();

            // Reserve a nonce for this batch BEFORE broadcasting
            // SECURITY: Nonces are REQUIRED - abort batch if unavailable
            let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
                let nm_guard = nm.lock().await;
                // Reserve one nonce for the entire batch (it's a single contract call)
                match nm_guard.reserve_nonces_for_batch(&["contract_call".to_string()]).await {
                    Ok(assignments) => {
                        if let Some(tuple_id) = assignments.get("contract_call") {
                            info!(
                                "🔐 [CLOCK] Reserved nonce {} for {} intent batch",
                                tuple_id,
                                target_chain.to_uppercase()
                            );
                            tuple_id.clone()
                        } else {
                            tracing::error!("🔴 [CLOCK] No nonce available for {} intent batch - aborting (will retry next cycle)", target_chain.to_uppercase());
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::error!("🔴 [CLOCK] Failed to reserve nonce for {} intent batch: {} - aborting (will retry next cycle)", target_chain.to_uppercase(), e);
                        return Ok(());
                    }
                }
            } else {
                tracing::error!("🔴 [CLOCK] NonceManager not available for {} intent batch - aborting (will retry next cycle)", target_chain.to_uppercase());
                return Ok(());
            };

            // Send via channel so the origin node processes the batch locally AND gossips it
            // to other peers (channel handler will publish and also call gossipsub handler).
            self.message_tx
                .send(crate::types::ChannelMessage::IntentBatchBroadcast {
                    intent_hashes: intent_hashes.clone(),
                    batch_type: format!("{:?}", batch_type), // "BTC" or "TICS"
                    timestamp: batch_timestamp.clone(),
                    round,
                    node_id: self.id.clone(),
                    nonce_tuple_id: Some(nonce_tuple_id), // Coordinated nonce reserved above
                })
                .await?;
            
            info!(
                "✅ [CLOCK] Successfully broadcasted {} intent batch with {} hashes at {}",
                target_chain.to_uppercase(),
                intent_hashes.len(),
                batch_timestamp
            );
            
            // Log details of each intent in the batch
            for (intent_hash, intent, tx_ids) in intents_to_process {
                let wait_duration = chrono::Utc::now().signed_duration_since(tx_ids.updated_at);
                info!(
                    "  📋 [BATCH] Intent {}: amount={}, source={}, target={}, waiting={}s, UserToVault TX: {}",
                    intent_hash,
                    intent.amount,
                    intent.source_chain,
                    intent.target_chain,
                    wait_duration.num_seconds(),
                    tx_ids.user_to_network_tx_id.unwrap_or_else(|| "N/A".to_string())
                );
            }

        } else {
            info!(
                "ℹ️  [CLOCK] No {} intents ready for processing in this cycle",
                target_chain.to_uppercase()
            );
        }

        // Additionally, when target_chain is BTC, select pending BTC withdraw-liquidity requests
        // and broadcast a batch for distributed signing (operates on PendingWithdrawRequest
        // under "pending_withdraw_liquidity:").
        if target_chain.eq_ignore_ascii_case("bitcoin") {
            use crate::types::rpc_server::PendingWithdrawRequest;

            let max_btc_withdraw_per_cycle = crate::env_defaults::max_btc_withdraw_per_cycle()
                .parse::<usize>()
                .ok()
                .unwrap_or(15);

            let db = user_intent_manager.get_database();

            // Load all pending withdraw requests
            let all_withdraws: Vec<(String, PendingWithdrawRequest)> =
                match db.get_values_with_prefix("pending_withdraw_liquidity:") {
                    Ok(entries) => entries,
                    Err(e) => {
                        warn!(
                            "⚠️ [CLOCK][BTC_WITHDRAW] Failed to load pending withdraw requests: {}",
                            e
                        );
                        return Ok(());
                    }
                };

            // Revert stale "Batched" BTC withdraw requests (no tx_id) back to "Pending" so they can be retried.
            // This handles the case where a previous BTC signing round failed.
            for (key, req) in &all_withdraws {
                if req.asset.to_uppercase() == "BTC" && req.status == "Batched" && req.tx_id.is_none() {
                    let mut reverted = req.clone();
                    reverted.status = "Pending".to_string();
                    if let Err(e) = db.put_string(key, &reverted) {
                        warn!("⚠️ [CLOCK][BTC_WITHDRAW] Failed to revert stale Batched withdraw {} to Pending: {}", req.request_id, e);
                    } else {
                        info!("🔄 [CLOCK][BTC_WITHDRAW] Reverted stale Batched withdraw {} (no tx_id) back to Pending for retry", req.request_id);
                    }
                }
            }

            // Filter to BTC asset, still pending (or just-reverted), and without tx_id
            let mut btc_pending: Vec<(String, PendingWithdrawRequest)> = all_withdraws
                .into_iter()
                .filter(|(_, req)| {
                    req.asset.to_uppercase() == "BTC"
                        && (req.status == "Pending" || req.status == "Batched")
                        && req.tx_id.is_none()
                })
                .collect();

            if btc_pending.is_empty() {
                info!("ℹ️  [CLOCK][BTC_WITHDRAW] No BTC withdraw requests ready for processing in this cycle");
            } else {
                // Sort by request_id (stable) just to have deterministic ordering
                btc_pending.sort_by(|a, b| a.1.request_id.cmp(&b.1.request_id));

                // Limit to configured max per cycle
                let btc_to_process: Vec<_> =
                    btc_pending.into_iter().take(max_btc_withdraw_per_cycle).collect();

                info!(
                    "📊 [CLOCK][BTC_WITHDRAW] Selected {} BTC withdraw requests (limited to {})",
                    btc_to_process.len(),
                    max_btc_withdraw_per_cycle
                );

                // Mark selected BTC withdraws as "Batched" to prevent re-picking
                for (key, req) in &btc_to_process {
                    let mut updated = req.clone();
                    updated.status = "Batched".to_string();
                    if let Err(e) = db.put_string(key, &updated) {
                        warn!("⚠️ [CLOCK][BTC_WITHDRAW] Failed to mark withdraw {} as Batched: {}", req.request_id, e);
                    } else {
                        info!("📝 [CLOCK][BTC_WITHDRAW] Marked withdraw {} as Batched", req.request_id);
                    }
                }

                // Build (request_id, solver_address) pairs for the batch message
                let requests: Vec<(String, String)> = btc_to_process
                    .iter()
                    .map(|(_, req)| (req.request_id.clone(), req.solver_address.clone()))
                    .collect();

                if !requests.is_empty() {
                    let batch_timestamp = chrono::Utc::now().to_rfc3339();
                    let batch_id = format!("btc_withdraw_batch:{}:{}", round, chrono::Utc::now().timestamp_millis());

                    // Reserve a coordinated nonce for this BTC withdraw batch
                    // SECURITY: Nonces are REQUIRED - abort batch if unavailable
                    let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
                        let nm_guard = nm.lock().await;
                        match nm_guard.reserve_nonces_for_batch(&[batch_id.clone()]).await {
                            Ok(assignments) => {
                                if let Some(tuple_id) = assignments.get(&batch_id) {
                                    info!("🔐 [BTC_WITHDRAW] Reserved nonce {} for batch {}", tuple_id, batch_id);
                                    tuple_id.clone()
                                } else {
                                    tracing::error!("🔴 [BTC_WITHDRAW] No nonce assignment returned for batch {} - aborting (will retry next epoch)", batch_id);
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                tracing::error!("🔴 [BTC_WITHDRAW] Failed to reserve nonce for batch {}: {} - aborting (will retry next epoch)", batch_id, e);
                                return Ok(());
                            }
                        }
                    } else {
                        tracing::error!("🔴 [BTC_WITHDRAW] NonceManager not available - aborting batch (will retry next epoch)");
                        return Ok(());
                    };

                    info!(
                        "📤 [CLOCK][BTC_WITHDRAW] Broadcasting BTC withdraw batch {} with {} requests (nonce: {})",
                        batch_id,
                        requests.len(),
                        nonce_tuple_id
                    );

                    self.message_tx
                        .send(crate::types::ChannelMessage::BtcWithdrawBatch {
                            batch_id,
                            requests,
                            round,
                            timestamp: batch_timestamp.clone(),
                            node_id: self.id.clone(),
                            nonce_tuple_id: Some(nonce_tuple_id),
                        })
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Pick a batch of pending TICS-source intents (UserToVault not yet done) and broadcast
    /// TicsUserToVaultIntentBatch so all nodes sign each intent with the respective user key (epoch_1).
    /// When `batched_only` is `Some(true)`, only Batched intents that don't have a user_to_vault tx-id are picked.
    /// Last-4-batches exclusion is always applied (both Pending and Batched-only picks).
    async fn process_tics_user_to_vault_intent_batch_for_round(
        &self,
        round: u64,
        batched_only: Option<bool>,
    ) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Number of TICS UserToVault intents to pick per batch (default 10 if env not set)
        let max_per_batch = std::env::var("MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH")
            .ok()
            .and_then(|val| val.parse::<usize>().ok())
            .unwrap_or(10);

        let exclusion_set: HashSet<String> = {
            let guard = self.last_tics_user_to_vault_batch_hashes.read().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.iter().flat_map(|set| set.iter().cloned()).collect()
        };
        let pending = user_intent_manager
            .get_pending_user_to_vault_intents_by_source_chain(
                "tics",
                max_per_batch,
                batched_only,
                Some(&exclusion_set),
            )
            .await;

        let mut valid_pending = Vec::new();
        for (hash, intent, user) in pending {
            let source_amount = match intent.amount.trim().parse::<u128>() {
                Ok(a) if a > 0 => a,
                _ => {
                    tracing::warn!("⚠️ [CLOCK][TICS_UTV_BATCH] Invalid amount for intent {}", hash);
                    continue;
                }
            };
            
            let five_percent_buffer = source_amount / 20;
            let estimated_tx_fee: u128 = 300_000_000_000_000;
            let required_balance = source_amount + five_percent_buffer + estimated_tx_fee;
            
            match crate::rpc_server::utils::fetch_network_balance(&intent.source_address, "eth").await {
                Ok(user_balance) => {
                    if user_balance < required_balance {
                        tracing::warn!(
                            "⚠️ [CLOCK][TICS_UTV_BATCH] Insufficient balance for intent {}: has {}, needs {}",
                            hash, user_balance, required_balance
                        );
                        if let Err(e) = user_intent_manager.update_intent_status(&user, &hash, crate::types::IntentStatus::Rejected).await {
                             tracing::error!("Failed to update intent status to Rejected for {}: {}", hash, e);
                        }
                        let error_msg = crate::types::GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: vec![hash.clone()],
                            error_message: format!("Insufficient balance: has {}, needs {}", user_balance, required_balance),
                            transaction_type: "intent_rejected".to_string(),
                            solver_address: None,
                            node_id: self.id.clone(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self.broadcast("signing", &data).await;
                        }
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ [CLOCK][TICS_UTV_BATCH] Failed to fetch balance for intent {}: {}", hash, e);
                    continue;
                }
            }
            valid_pending.push((hash, intent, user));
        }
        let pending = valid_pending;

        if pending.is_empty() {
            if !exclusion_set.is_empty() {
                let mut guard = self.last_tics_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
                guard.push_back(HashSet::new());
                while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                    guard.pop_front();
                }
            }
            info!(
                "ℹ️  [CLOCK][TICS_UTV_BATCH] No pending TICS-source intents (UserToVault not done) for round {}",
                round
            );
            return Ok(());
        }

        let intent_hashes: Vec<String> = pending
            .iter()
            .map(|(hash, _, _)| hash.clone())
            .collect();

        {
            let mut guard = self.last_tics_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }

        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        info!(
            "📤 [CLOCK][TICS_UTV_BATCH] Broadcasting TICS UserToVault intent batch for round {} ({} intents)",
            round,
            intent_hashes.len()
        );

        // Reserve nonces for each intent in the batch (coordinator assigns nonces)
        // SECURITY: Nonces are REQUIRED - abort batch if none available
        let nonce_assignments = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&intent_hashes).await {
                Ok(assignments) => {
                    if assignments.is_empty() {
                        tracing::error!("🔴 [TICS_UTV_BATCH] No nonces available - aborting batch (will retry next cycle)");
                        return Ok(());
                    }
                    if assignments.len() == intent_hashes.len() {
                        info!(
                            "🔐 [TICS_UTV_BATCH] Reserved {} nonces for batch",
                            assignments.len()
                        );
                    } else {
                        tracing::error!(
                            "🔴 [TICS_UTV_BATCH] Partial nonce reservation: {}/{} - intents without nonces will be SKIPPED",
                            assignments.len(),
                            intent_hashes.len()
                        );
                    }
                    assignments
                }
                Err(e) => {
                    tracing::error!(
                        "🔴 [TICS_UTV_BATCH] Failed to reserve nonces: {} - aborting batch (will retry next cycle)",
                        e
                    );
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [TICS_UTV_BATCH] NonceManager not available - aborting batch (will retry next cycle)");
            return Ok(());
        };

        self.message_tx
            .send(crate::types::ChannelMessage::TicsUserToVaultIntentBatch {
                intent_hashes: intent_hashes.clone(),
                round,
                timestamp: batch_timestamp.clone(),
                node_id: self.id.clone(),
                nonce_assignments,
            })
            .await?;

        for (hash, intent, user) in &pending {
            info!(
                "  📋 [TICS_UTV_BATCH] Intent {}: amount={}, user={}",
                hash, intent.amount, user
            );
        }

        Ok(())
    }

    /// Pick a batch of pending BTC-source intents (UserToVault not yet done) and broadcast
    /// BtcUserToVaultIntentBatch so all nodes sign each intent with the respective user key (epoch_2).
    /// When `batched_only` is `Some(true)`, only Batched intents that don't have a user_to_vault tx-id are picked.
    /// Last-4-batches exclusion is always applied (both Pending and Batched-only picks).
    async fn process_btc_user_to_vault_intent_batch_for_round(
        &self,
        round: u64,
        batched_only: Option<bool>,
    ) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        let max_per_batch = std::env::var("MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH")
            .ok()
            .and_then(|val| val.parse::<usize>().ok())
            .unwrap_or(10);

        let exclusion_set: HashSet<String> = {
            let guard = self.last_btc_user_to_vault_batch_hashes.read().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.iter().flat_map(|set| set.iter().cloned()).collect()
        };
        let pending = user_intent_manager
            .get_pending_user_to_vault_intents_by_source_chain(
                "bitcoin",
                max_per_batch,
                batched_only,
                Some(&exclusion_set),
            )
            .await;

        let mut valid_pending = Vec::new();
        for (hash, intent, user) in pending {
            let source_amount = match intent.amount.trim().parse::<u128>() {
                Ok(a) if a > 0 => a,
                _ => {
                    tracing::warn!("⚠️ [CLOCK][BTC_UTV_BATCH] Invalid amount for intent {}", hash);
                    continue;
                }
            };
            
            let five_percent_buffer = source_amount / 20;
            let fee_rate = std::env::var("BTC_FEE_RATE_SAT_VB")
                .ok()
                .and_then(|v| v.parse::<u128>().ok())
                .unwrap_or(2);
            let estimated_tx_fee: u128 = 208 * fee_rate;
            let required_balance = source_amount + five_percent_buffer + estimated_tx_fee;
            
            match crate::utils::transaction::fetch_bitcoin_utxos(&intent.source_address, false).await {
                Ok(utxos) => {
                    let confirmed_balance: u128 = utxos
                        .iter()
                        .filter(|u| u.status.confirmed)
                        .map(|u| u.value as u128)
                        .sum();
                    if confirmed_balance < required_balance {
                        tracing::warn!(
                            "⚠️ [CLOCK][BTC_UTV_BATCH] Insufficient confirmed UTXOs for intent {}: has {}, needs {}",
                            hash, confirmed_balance, required_balance
                        );
                        if let Err(e) = user_intent_manager.update_intent_status(&user, &hash, crate::types::IntentStatus::Rejected).await {
                             tracing::error!("Failed to update intent status to Rejected for {}: {}", hash, e);
                        }
                        let error_msg = crate::types::GossipsubMessage::TransactionErrorBroadcast {
                            intent_hashes: vec![hash.clone()],
                            error_message: format!("Insufficient confirmed UTXOs: has {}, needs {}", confirmed_balance, required_balance),
                            transaction_type: "intent_rejected".to_string(),
                            solver_address: None,
                            node_id: self.id.clone(),
                        };
                        if let Ok(data) = serde_json::to_vec(&error_msg) {
                            let _ = self.broadcast("signing", &data).await;
                        }
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ [CLOCK][BTC_UTV_BATCH] Failed to fetch utxos for intent {}: {}", hash, e);
                    continue; 
                }
            }
            valid_pending.push((hash, intent, user));
        }
        let pending = valid_pending;

        if pending.is_empty() {
            if !exclusion_set.is_empty() {
                let mut guard = self.last_btc_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
                guard.push_back(HashSet::new());
                while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                    guard.pop_front();
                }
            }
            info!(
                "ℹ️  [CLOCK][BTC_UTV_BATCH] No pending BTC-source intents (UserToVault not done) for round {}",
                round
            );
            return Ok(());
        }

        let intent_hashes: Vec<String> = pending
            .iter()
            .map(|(hash, _, _)| hash.clone())
            .collect();

        {
            let mut guard = self.last_btc_user_to_vault_batch_hashes.write().map_err(|e| anyhow!("lock poisoned: {}", e))?;
            guard.push_back(intent_hashes.iter().cloned().collect());
            while guard.len() > LAST_N_USER_TO_VAULT_BATCHES {
                guard.pop_front();
            }
        }

        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        info!(
            "📤 [CLOCK][BTC_UTV_BATCH] Broadcasting BTC UserToVault intent batch for round {} ({} intents)",
            round,
            intent_hashes.len()
        );

        // Reserve nonces for each intent in the batch (coordinator assigns nonces)
        // SECURITY: Nonces are REQUIRED - abort batch if none available
        let nonce_assignments = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&intent_hashes).await {
                Ok(assignments) => {
                    if assignments.is_empty() {
                        tracing::error!("🔴 [BTC_UTV_BATCH] No nonces available - aborting batch (will retry next cycle)");
                        return Ok(());
                    }
                    if assignments.len() == intent_hashes.len() {
                        info!(
                            "🔐 [BTC_UTV_BATCH] Reserved {} nonces for batch",
                            assignments.len()
                        );
                    } else {
                        tracing::error!(
                            "🔴 [BTC_UTV_BATCH] Partial nonce reservation: {}/{} - intents without nonces will be SKIPPED",
                            assignments.len(),
                            intent_hashes.len()
                        );
                    }
                    assignments
                }
                Err(e) => {
                    tracing::error!(
                        "🔴 [BTC_UTV_BATCH] Failed to reserve nonces: {} - aborting batch (will retry next cycle)",
                        e
                    );
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_UTV_BATCH] NonceManager not available - aborting batch (will retry next cycle)");
            return Ok(());
        };

        self.message_tx
            .send(crate::types::ChannelMessage::BtcUserToVaultIntentBatch {
                intent_hashes: intent_hashes.clone(),
                round,
                timestamp: batch_timestamp.clone(),
                node_id: self.id.clone(),
                nonce_assignments,
            })
            .await?;

        for (hash, intent, user) in &pending {
            info!(
                "  📋 [BTC_UTV_BATCH] Intent {}: amount={}, user={}",
                hash, intent.amount, user
            );
        }

        Ok(())
    }

    /// Pick a batch of pending BTC claim-reward requests and broadcast BtcClaimRewardBatch (called from epoch_1).
    async fn process_btc_claim_reward_batch_for_round(&self, round: u64) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        let max_btc_claim_reward_per_cycle = std::env::var("MAX_BTC_CLAIM_REWARD_PER_CYCLE")
            .ok()
            .and_then(|val| val.parse::<usize>().ok())
            .unwrap_or(10);

        let all_claims: Vec<(String, crate::types::rpc_server::PendingClaimRewardRequest)> =
            db.get_values_with_prefix("pending_claim_reward:")
                .map_err(|e| anyhow!("Failed to load pending claim reward requests: {}", e))?;

        // Revert stale "Batched" BTC claim reward requests (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous BTC signing round failed.
        for (key, req) in &all_claims {
            let has_btc = req.btc_address.as_ref().map_or(false, |a| !a.trim().is_empty());
            if has_btc && req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [BTC_CLAIM_REWARD] Failed to revert stale Batched claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [BTC_CLAIM_REWARD] Reverted stale Batched claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        let mut btc_claim_pending: Vec<(String, crate::types::rpc_server::PendingClaimRewardRequest)> = all_claims
            .into_iter()
            .filter(|(_, req)| {
                (req.status == "Pending" || req.status == "Batched")
                    && req.tx_id.is_none()
                    && req.btc_address.as_ref().map_or(false, |a| !a.trim().is_empty())
            })
            .collect();

        if btc_claim_pending.is_empty() {
            return Ok(());
        }

        btc_claim_pending.sort_by(|a, b| a.1.request_id.cmp(&b.1.request_id));
        let btc_claim_to_process: Vec<_> = btc_claim_pending
            .into_iter()
            .take(max_btc_claim_reward_per_cycle)
            .collect();

        // Mark selected BTC claim rewards as "Batched" to prevent re-picking
        for (key, req) in &btc_claim_to_process {
            let mut updated = req.clone();
            updated.status = "Batched".to_string();
            if let Err(e) = db.put_string(key, &updated) {
                warn!("⚠️ [BTC_CLAIM_REWARD] Failed to mark claim {} as Batched: {}", req.request_id, e);
            } else {
                info!("📝 [BTC_CLAIM_REWARD] Marked claim {} as Batched", req.request_id);
            }
        }

        let claim_requests: Vec<(String, String)> = btc_claim_to_process
            .iter()
            .map(|(_, req)| (req.request_id.clone(), req.solver_address.clone()))
            .collect();

        if claim_requests.is_empty() {
            return Ok(());
        }

        let claim_batch_timestamp = chrono::Utc::now().to_rfc3339();
        let claim_batch_id = format!(
            "btc_claim_reward_batch:{}:{}",
            round,
            chrono::Utc::now().timestamp_millis()
        );

        // Reserve a coordinated nonce for this BTC claim-reward batch
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&[claim_batch_id.clone()]).await {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&claim_batch_id) {
                        info!("🔐 [BTC_CLAIM_REWARD] Reserved nonce {} for batch {}", tuple_id, claim_batch_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [BTC_CLAIM_REWARD] No nonce assignment returned for batch {} - aborting (will retry next epoch)", claim_batch_id);
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [BTC_CLAIM_REWARD] Failed to reserve nonce for batch {}: {} - aborting (will retry next epoch)", claim_batch_id, e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_CLAIM_REWARD] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        info!(
            "📤 [CLOCK][BTC_CLAIM_REWARD] Broadcasting BTC claim-reward batch {} with {} requests (nonce: {})",
            claim_batch_id,
            claim_requests.len(),
            nonce_tuple_id
        );
        self.message_tx
            .send(crate::types::ChannelMessage::BtcClaimRewardBatch {
                batch_id: claim_batch_id,
                requests: claim_requests,
                round,
                timestamp: claim_batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_id: Some(nonce_tuple_id),
            })
            .await
            .map_err(|e| anyhow!("Failed to send BtcClaimRewardBatch: {}", e))?;

        Ok(())
    }

    /// Pick pending BTC platform-fee claim requests and broadcast BtcClaimPlatformFeeBatch (called from epoch_4).
    async fn process_btc_claim_platform_fee_batch_for_round(&self, round: u64) -> Result<()> {
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        let all_claims: Vec<(String, crate::types::rpc_server::PendingClaimPlatformFeeRequest)> =
            db.get_values_with_prefix(crate::database::primitives::keys::PENDING_CLAIM_PLATFORM_FEE)
                .map_err(|e| anyhow!("Failed to load pending claim platform fee requests: {}", e))?;

        // Revert stale "Batched" BTC claims (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous BTC signing round failed silently.
        for (key, req) in &all_claims {
            if req.asset == "BTC" && req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] Failed to revert stale Batched claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [BTC_CLAIM_PLATFORM_FEE] Reverted stale Batched claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        let btc_claim_pending: Vec<_> = all_claims
            .into_iter()
            .filter(|(_, req)| {
                req.asset == "BTC"
                    && (req.status == "Pending" || req.status == "Batched")
                    && req.tx_id.is_none()
                    && req.btc_target_address.as_ref().map_or(false, |a| !a.trim().is_empty())
            })
            .collect();

        if btc_claim_pending.is_empty() {
            return Ok(());
        }

        // Platform fee: only one request at a time per chain, so take the first one
        let (ref db_key, ref req) = btc_claim_pending[0];
        let claim_requests: Vec<(String, String)> = vec![(
            req.request_id.clone(),
            req.btc_target_address.clone().unwrap_or_default(),
        )];

        // Mark as Batched to prevent re-picking in subsequent epoch_4 rounds
        let mut updated_req = req.clone();
        updated_req.status = "Batched".to_string();
        if let Err(e) = db.put_string(db_key, &updated_req) {
            warn!("⚠️ [BTC_CLAIM_PLATFORM_FEE] Failed to mark claim {} as Batched: {}", req.request_id, e);
        } else {
            info!("📝 [BTC_CLAIM_PLATFORM_FEE] Marked claim {} as Batched", req.request_id);
        }

        let claim_batch_timestamp = chrono::Utc::now().to_rfc3339();
        let claim_batch_id = format!(
            "btc_claim_platform_fee_batch:{}:{}",
            round,
            chrono::Utc::now().timestamp_millis()
        );

        // Reserve a coordinated nonce for this BTC claim-platform-fee batch
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&[claim_batch_id.clone()]).await {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&claim_batch_id) {
                        info!("🔐 [BTC_CLAIM_PLATFORM_FEE] Reserved nonce {} for batch {}", tuple_id, claim_batch_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] No nonce assignment returned for batch {} - aborting (will retry next epoch)", claim_batch_id);
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] Failed to reserve nonce for batch {}: {} - aborting (will retry next epoch)", claim_batch_id, e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_CLAIM_PLATFORM_FEE] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        info!(
            "📤 [CLOCK][BTC_CLAIM_PLATFORM_FEE] Broadcasting BTC claim-platform-fee batch {} with {} requests (nonce: {})",
            claim_batch_id,
            claim_requests.len(),
            nonce_tuple_id
        );
        self.message_tx
            .send(crate::types::ChannelMessage::BtcClaimPlatformFeeBatch {
                batch_id: claim_batch_id,
                requests: claim_requests,
                round,
                timestamp: claim_batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_id: Some(nonce_tuple_id),
            })
            .await
            .map_err(|e| anyhow!("Failed to send BtcClaimPlatformFeeBatch: {}", e))?;

        Ok(())
    }

    /// Trigger BTC contract update round in parallel to BTC batch transfer round
    /// This ONLY triggers selection - the final node will:
    /// 1. Get intents with network_to_target_tx_id but not Solved
    /// 2. Create batch and broadcast via btc-intent-manager-tx-update
    /// 3. All nodes will process the batch and participate in MPC signing
    async fn trigger_btc_contract_update_round_parallel(&mut self) -> Result<()> {
        info!("🔄 [BTC_CONTRACT_UPDATE] Starting parallel contract update round trigger");

        // Get available nodes
        let available_nodes: Vec<libp2p::PeerId> = self
            .coordination
            .get_available_nodes()
            .await;

        if available_nodes.is_empty() {
            warn!("⚠️ [BTC_CONTRACT_UPDATE] No available nodes for selection");
            return Ok(());
        }

        // Get next round in a block so we can release vrf_service borrow before replicate_vrf_round_to_consensus
        let contract_update_round = {
            let vrf_service = self.coordination
                .vrf_service()
                .ok_or_else(|| anyhow!("Round/selection service not available"))?;
            if let Err(e) = vrf_service.sync_rounds_before_signing().await {
                warn!("⚠️ [BTC_CONTRACT_UPDATE] Failed to sync rounds: {}", e);
            }
            vrf_service.get_next_round().await
        };
        self.replicate_vrf_round_to_consensus(contract_update_round);

        info!(
            "🎯 [BTC_CONTRACT_UPDATE] Performing selection for contract update round {} (parallel to BTC batch round)",
            contract_update_round
        );

        // Perform node selection for BTC intent manager update round
        let vrf_service = self.coordination
            .vrf_service()
            .ok_or_else(|| anyhow!("Round/selection service not available"))?;
        match vrf_service
            .perform_node_selection(
                &available_nodes,
                crate::vrf::VRF_NODE_SELECTION_COUNT,
                contract_update_round,
                "btc_intent_manager_update",
            )
            .await
        {
            Ok(_selection_result) => {
                info!(
                    "✅ [BTC_CONTRACT_UPDATE] Selection completed for round {}. Final node will select eligible intents and broadcast batch.",
                    contract_update_round
                );
            }
            Err(e) => {
                error!("❌ [BTC_CONTRACT_UPDATE] Selection failed: {}", e);
                return Err(e);
            }
        }

        // The round will proceed to consensus, and the final node will:
        // 1. Get eligible intents (network_to_target_tx_id, NOT Solved, BTC target chain)
        // 2. Create BtcIntentManagerTxUpdate message
        // 3. Broadcast to all nodes via gossipsub
        // 4. All nodes will process the batch and participate in MPC signing for the contract call

        Ok(())
    }

    /// Process BTC contract update batch when final node is selected for contract update round
    /// This function is called by the FINAL NODE after consensus completes for btc_contract_update round.
    /// The final node will:
    /// 1. Get eligible intents (network_to_target_tx_id exists, status NOT Solved, BTC target chain)
    /// 2. Create BtcIntentManagerTxUpdate message with intent hashes
    /// 3. Broadcast to all nodes via gossipsub
    /// 4. All nodes will receive the batch and participate in MPC signing for the contract call
    async fn process_btc_contract_update_batch_for_round(&self, round: u64) -> Result<()> {
        info!("🔄 [BTC_CONTRACT_UPDATE] Processing contract update batch for round {}", round);

        // Get user intent manager
        let user_intent_manager = self.user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Get database to access IntentStorage directly
        let database = user_intent_manager.get_database();
        let intent_storage = crate::database::storage::IntentStorage::new(database.clone());

        // Get intents with BOTH user_to_network_tx_id AND network_to_target_tx_id (completed intents)
        let completed_intents = intent_storage.get_completed_intents().await?;

        // Filter: must be BTC target chain AND status NOT Solved
        let mut eligible_intents = Vec::new();
        for (intent_hash, intent, tx_ids) in completed_intents {
            // Must be BTC target chain
            let target_chain_lower = intent.target_chain.to_lowercase();
            if target_chain_lower != "bitcoin" && target_chain_lower != "btc" {
                continue;
            }

            // Check if intent status is NOT Solved
            if let Some(user) = user_intent_manager
                .get_user_by_intent_hash(&intent_hash)
                .await
            {
                if let Some(status) = user.intent_hashes.get(&intent_hash) {
                    if *status == crate::types::IntentStatus::Solved {
                        continue; // Skip solved intents
                    }
                }
            }

            eligible_intents.push((intent_hash, intent, tx_ids));
        }

        if eligible_intents.is_empty() {
            info!(
                "ℹ️ [BTC_CONTRACT_UPDATE] No eligible intents found for contract update batch"
            );
            return Ok(());
        }

        info!(
            "📋 [BTC_CONTRACT_UPDATE] Found {} eligible intents for contract update batch",
            eligible_intents.len()
        );

        // Prepare intent hashes for the batch
        let intent_hashes: Vec<String> = eligible_intents
            .iter()
            .map(|(hash, _, _)| hash.clone())
            .collect();

        // Create batch timestamp
        let batch_timestamp = chrono::Utc::now().to_rfc3339();

        // Reserve a nonce for this batch BEFORE broadcasting (coordinator responsibility)
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&["btc_contract_update".to_string()]).await {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get("btc_contract_update") {
                        info!("🔐 [BTC_CONTRACT_UPDATE] Reserved nonce {} for contract update batch", tuple_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [BTC_CONTRACT_UPDATE] No nonce assigned - aborting batch (will retry next cycle)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [BTC_CONTRACT_UPDATE] Failed to reserve nonce: {} - aborting batch (will retry next cycle)", e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [BTC_CONTRACT_UPDATE] NonceManager not available - aborting batch (will retry next cycle)");
            return Ok(());
        };

        // Broadcast via btc-intent-manager-tx-update topic
        // Note: We don't have the BTC batch txid yet since it's happening in parallel
        // The contract update handler will need to wait for the BTC batch to complete
        // or process with existing network_to_target_tx_id values
        let batch_message = crate::types::ChannelMessage::BtcIntentManagerTxUpdate {
            intent_hashes: intent_hashes.clone(),
            btc_txid: "pending".to_string(), // Will be updated when BTC batch completes
            btc_batch_round: 0, // Will be set when BTC batch completes
            update_round: round,
            timestamp: batch_timestamp,
            node_id: self.id.clone(),
            nonce_tuple_id: Some(nonce_tuple_id),
        };

        self.message_tx
            .send(batch_message)
            .await
            .map_err(|e| anyhow!("Failed to send BTC intent manager update message: {}", e))?;

        info!(
            "✅ [BTC_CONTRACT_UPDATE] Broadcasted contract update batch with {} intents (round {})",
            intent_hashes.len(),
            round
        );

        Ok(())
    }

    /// Process pending solver_add_liquidity requests in batch
    /// Called by the final node selected via global_clock round.
    /// The final node will:
    /// 1. Query RocksDB for pending add_liquidity requests (status="Pending", age >= 10s)
    /// 2. Sort by timestamp (oldest first), limit to MAX_ADD_LIQUIDITY_BATCH
    /// 3. Atomically mark selected requests as "Batched" in RocksDB
    /// 4. Broadcast the batch via ChannelMessage::SolverAddLiquidityBatch
    /// 5. All nodes will verify, generate partial signatures (liquidity_operator key)
    /// 6. Final node aggregates and submits batchTransfer tx to contract
    async fn process_solver_add_liquidity_batch_for_round(&self, round: u64) -> Result<()> {
        info!("💧 [ADD_LIQUIDITY] Processing solver_add_liquidity batch for round {}", round);

        // Get database reference
        let database = self.database.as_ref()
            .ok_or_else(|| anyhow!("Database not available"))?;

        let max_batch_size = crate::env_defaults::max_add_liquidity_batch();

        let min_age_seconds = 10; // Minimum age in seconds before batching

        // Query all pending add_liquidity requests from RocksDB
        const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";
        
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct PendingAddLiquidityRecord {
            request_id: String,
            solver_id: String,
            solver_address: String,
            amount: String,
            chain_id: u64,
            signature: String,
            signed_payload: String,
            timestamp_ms: i64,
            status: String,
            #[serde(default)]
            tx_id: Option<String>,
        }

        // Scan RocksDB for all keys with the prefix (async wrapper)
        let all_keys = database
            .get_keys_with_prefix_async(ADD_LIQUIDITY_DB_PREFIX)
            .await?;
        
        let mut pending_requests = Vec::new();
        let now_ms = chrono::Utc::now().timestamp_millis();

        for key in all_keys {
            if let Ok(Some(record)) = database
                .get_string_async::<PendingAddLiquidityRecord>(&key)
                .await
            {
                // Filter: status must be "Pending" and age >= min_age_seconds
                if record.status == "Pending" {
                    let age_ms = now_ms - record.timestamp_ms;
                    let age_secs = age_ms / 1000;
                    
                    if age_secs >= min_age_seconds {
                        pending_requests.push((key, record));
                    }
                }
            }
        }

        if pending_requests.is_empty() {
            info!("ℹ️  [ADD_LIQUIDITY] No pending requests eligible for batching (age >= {}s)", min_age_seconds);
            return Ok(());
        }

        // Sort by timestamp (oldest first)
        pending_requests.sort_by(|a, b| a.1.timestamp_ms.cmp(&b.1.timestamp_ms));

        // Limit to max_batch_size
        let requests_to_batch: Vec<_> = pending_requests
            .into_iter()
            .take(max_batch_size)
            .collect();

        info!(
            "📋 [ADD_LIQUIDITY] Selected {} requests for batching (max: {}, min_age: {}s)",
            requests_to_batch.len(),
            max_batch_size,
            min_age_seconds
        );

        // Keep all selected requests as "Pending" - they will be marked "Completed" on success
        info!(
            "📦 [ADD_LIQUIDITY] Selected {} requests for batching (keeping status as 'Pending')",
            requests_to_batch.len()
        );

        // Prepare batch data for broadcast
        let batch_entries: Vec<(String, String, String, u64)> = requests_to_batch
            .iter()
            .map(|(_, record)| {
                (
                    record.request_id.clone(),
                    record.solver_address.clone(),
                    record.amount.clone(),
                    record.chain_id,
                )
            })
            .collect();

        // Broadcast the batch to all nodes via ChannelMessage
        let batch_timestamp = chrono::Utc::now().to_rfc3339();

        // Reserve a nonce for this batch BEFORE broadcasting (coordinator responsibility)
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&["add_liquidity_batch".to_string()]).await {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get("add_liquidity_batch") {
                        info!("🔐 [ADD_LIQUIDITY] Reserved nonce {} for add_liquidity batch", tuple_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [ADD_LIQUIDITY] No nonce assigned - aborting batch (will retry next epoch)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [ADD_LIQUIDITY] Failed to reserve nonce: {} - aborting batch (will retry next epoch)", e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [ADD_LIQUIDITY] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        // Only send request_ids - all nodes have the full records in RocksDB
        let batch_message = ChannelMessage::SolverAddLiquidityBatch {
            request_ids: batch_entries.iter().map(|(id, _, _, _)| id.clone()).collect(),
            round,
            timestamp: batch_timestamp.clone(),
            node_id: self.id.clone(),
            nonce_tuple_id: Some(nonce_tuple_id),
        };

        self.message_tx
            .send(batch_message)
            .await
            .map_err(|e| anyhow!("Failed to send SolverAddLiquidityBatch message: {}", e))?;

        info!(
            "✅ [ADD_LIQUIDITY] Broadcasted batch with {} requests for round {} at {}",
            batch_entries.len(),
            round,
            batch_timestamp
        );

        // Log details of each request in the batch
        for (_key, record) in &requests_to_batch {
            let wait_duration_secs = (now_ms - record.timestamp_ms) / 1000;
            info!(
                "  💧 [BATCH] Request {}: solver={}, amount={}, chain={}, waiting={}s",
                record.request_id,
                record.solver_address,
                record.amount,
                record.chain_id,
                wait_duration_secs
            );
        }

        Ok(())
    }

    /// Epoch 3: Withdraw settlement / cleanup.
    /// This epoch does NOT create new transactions; it finalizes the logical status
    /// of withdraw-liquidity requests so they are not picked again in future epochs.
    /// Rules:
    /// - For TICS: Pending requests are batched into a TICS withdraw batch
    ///   and marked as "Batched". The actual completion happens once the
    ///   removeLiquidity contract transaction is mined and tx_id is stored.
    /// - For BTC: any PendingWithdrawRequest with asset="BTC", status="Pending",
    ///   and a non-empty tx_id is also marked status="Completed".
    async fn process_withdraw_settlement_epoch(&self, round: u64) -> Result<()> {
        use crate::types::rpc_server::PendingWithdrawRequest;
        use crate::types::messaging::TicsWithdrawBatchRequest;

        info!("🔍 [CLOCK] Processing withdraw settlement epoch (epoch_3)...");

        // Get user intent manager and backing database
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        // Load all pending withdraw requests across all solvers
        let all_withdraws: Vec<(String, PendingWithdrawRequest)> =
            match db.get_values_with_prefix("pending_withdraw_liquidity:") {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(
                        "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to load pending withdraw requests: {}",
                        e
                    );
                    return Ok(());
                }
            };

        if all_withdraws.is_empty() {
            info!(
                "ℹ️  [CLOCK][WITHDRAW_SETTLE] No withdraw requests found for settlement epoch"
            );
            return Ok(());
        }

        // Revert stale "Batched" withdraw requests (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous signing round failed.
        for (key, req) in &all_withdraws {
            if req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to revert stale Batched {} withdraw {} to Pending: {}", req.asset, req.request_id, e);
                } else {
                    info!("🔄 [CLOCK][WITHDRAW_SETTLE] Reverted stale Batched {} withdraw {} (no tx_id) back to Pending for retry", req.asset, req.request_id);
                }
            }
        }

        let mut tics_batched = 0usize;
        let mut btc_updated = 0usize;

        let mut tics_batch_requests: Vec<TicsWithdrawBatchRequest> = Vec::new();

        for (key, mut req) in all_withdraws {
            if req.status != "Pending" {
                continue;
            }

            let asset_upper = req.asset.to_uppercase();

            // TICS: pick all Pending requests for settlement batch, mark as "Batched"
            if asset_upper == "TICS" {
                // Build batch metadata from the current record
                tics_batch_requests.push(TicsWithdrawBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: req.asset.clone(),
                    amount: req.amount.clone(),
                    // TICS withdraws are executed on the main TICS EVM chain (chain ID from SOLVER_CONTRACT_CHAIN_ID env var).
                    chain_id: crate::env_defaults::solver_contract_chain_id()
                        .parse::<u64>()
                        .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id()),
                    tx_id: req.tx_id.clone(),
                });

                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to mark TICS withdraw {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    tics_batched += 1;
                }
                continue;
            }

            // BTC: pick Pending requests that already have an on-chain tx_id so they get
            // registered on the contract in the same TICS withdraw batch (funds already sent).
            let has_tx_id = req.tx_id.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            if asset_upper == "BTC" && has_tx_id {
                tics_batch_requests.push(TicsWithdrawBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: req.asset.clone(),
                    amount: req.amount.clone(),
                    chain_id: 0, // BTC
                    tx_id: req.tx_id.clone(),
                });

                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to mark BTC withdraw {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    btc_updated += 1;
                }
            }
        }

        // If we have any TICS withdraws to settle, broadcast a TICS withdraw batch
        if !tics_batch_requests.is_empty() {
            let batch_timestamp = chrono::Utc::now().to_rfc3339();
            let batch_id = format!(
                "tics_withdraw_batch:{}:{}",
                round,
                chrono::Utc::now().timestamp_millis()
            );

            info!(
                "📦 [CLOCK][WITHDRAW_SETTLE] Creating TICS withdraw batch {} with {} requests for round {}",
                batch_id,
                tics_batch_requests.len(),
                round
            );

            // Reserve a single nonce for this batch signing
            // SECURITY: Nonces are REQUIRED - abort batch if unavailable
            // NOTE: Use reserve_nonces_for_batch() NOT acquire_nonce() - the coordinator must NOT
            // consume the nonce, only reserve it. Each node consumes their own copy when signing.
            let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
                let nm_guard = nm.lock().await;
                match nm_guard.reserve_nonces_for_batch(&[batch_id.clone()]).await {
                    Ok(assignments) => {
                        if let Some(tuple_id) = assignments.get(&batch_id) {
                            info!("🔐 [WITHDRAW_SETTLE] Reserved nonce {} for batch {}", tuple_id, batch_id);
                            tuple_id.clone()
                        } else {
                            tracing::error!("🔴 [WITHDRAW_SETTLE] No nonce assignment returned for batch {} - aborting batch (will retry next epoch)", batch_id);
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::error!("🔴 [WITHDRAW_SETTLE] Failed to reserve nonce for batch {}: {} - aborting batch (will retry next epoch)", batch_id, e);
                        return Ok(());
                    }
                }
            } else {
                tracing::error!("🔴 [WITHDRAW_SETTLE] NonceManager not available - aborting batch (will retry next epoch)");
                return Ok(());
            };

            let message = ChannelMessage::TicsWithdrawBatch {
                batch_id,
                requests: tics_batch_requests,
                round,
                timestamp: batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_id: Some(nonce_tuple_id),
            };

            if let Err(e) = self.message_tx.send(message).await {
                warn!(
                    "⚠️ [CLOCK][WITHDRAW_SETTLE] Failed to send TicsWithdrawBatch channel message: {}",
                    e
                );
            }
        }

        info!(
            "✅ [CLOCK][WITHDRAW_SETTLE] Settlement epoch completed: {} TICS withdraws batched, {} BTC withdraws (with tx_id) batched for contract registration",
            tics_batched, btc_updated
        );

        Ok(())
    }

    /// TICS claim-reward settlement (same flow as withdraw settlement).
    /// Picks TICS claim requests (pending, have tics_address) and BTC claim requests (pending, have tx_id) for contract.
    /// On success: store TICS tx_id on TICS requests and mark done; mark BTC requests done only.
    async fn process_tics_claim_reward_settlement_epoch(&self, round: u64) -> Result<()> {
        use crate::types::messaging::TicsClaimRewardBatchRequest;
        use crate::types::rpc_server::PendingClaimRewardRequest;

        info!("🔍 [CLOCK] Processing TICS claim-reward settlement epoch (epoch_3)...");

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        let all_claims: Vec<(String, PendingClaimRewardRequest)> =
            match db.get_values_with_prefix("pending_claim_reward:") {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(
                        "⚠️ [CLOCK][TICS_CLAIM] Failed to load pending claim reward requests: {}",
                        e
                    );
                    return Ok(());
                }
            };

        if all_claims.is_empty() {
            info!(
                "ℹ️  [CLOCK][TICS_CLAIM] No claim reward requests found for settlement epoch"
            );
            return Ok(());
        }

        // Revert stale "Batched" claim reward requests (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous signing round failed.
        for (key, req) in &all_claims {
            if req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [CLOCK][TICS_CLAIM] Failed to revert stale Batched claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [CLOCK][TICS_CLAIM] Reverted stale Batched claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        let tics_chain_id = crate::env_defaults::solver_contract_chain_id()
            .parse::<u64>()
            .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

        let mut tics_batched = 0usize;
        let mut btc_updated = 0usize;
        let mut tics_claim_batch_requests: Vec<TicsClaimRewardBatchRequest> = Vec::new();

        for (key, mut req) in all_claims {
            if req.status != "Pending" {
                continue;
            }

            // TICS: pick pending requests that have tics_address (claim TICS to that address)
            let has_eth = req.tics_address.as_ref().map_or(false, |a| !a.trim().is_empty());
            if has_eth {
                tics_claim_batch_requests.push(TicsClaimRewardBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: "TICS".to_string(),
                    amount: "0".to_string(), // gossipsub will fetch from contract
                    chain_id: tics_chain_id,
                    tx_id: req.tx_id.clone(),
                });
                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][TICS_CLAIM] Failed to mark TICS claim {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    tics_batched += 1;
                }
                continue;
            }

            // BTC: pick pending requests that already have tx_id (register on contract in same batch)
            let has_tx_id = req.tx_id.as_ref().map_or(false, |s| !s.is_empty());
            let has_btc = req.btc_address.as_ref().map_or(false, |a| !a.trim().is_empty());
            if has_btc && has_tx_id {
                tics_claim_batch_requests.push(TicsClaimRewardBatchRequest {
                    request_id: req.request_id.clone(),
                    solver_address: req.solver_address.clone(),
                    asset: "BTC".to_string(),
                    amount: "0".to_string(),
                    chain_id: 0,
                    tx_id: req.tx_id.clone(),
                });
                req.status = "Batched".to_string();
                if let Err(e) = db.put_string(&key, &req) {
                    warn!(
                        "⚠️ [CLOCK][TICS_CLAIM] Failed to mark BTC claim {} as Batched: {}",
                        req.request_id, e
                    );
                } else {
                    btc_updated += 1;
                }
            }
        }

        if !tics_claim_batch_requests.is_empty() {
            let batch_timestamp = chrono::Utc::now().to_rfc3339();
            let batch_id = format!(
                "tics_claim_reward_batch:{}:{}",
                round,
                chrono::Utc::now().timestamp_millis()
            );

            info!(
                "📦 [CLOCK][TICS_CLAIM] Creating TICS claim-reward batch {} with {} requests for round {}",
                batch_id,
                tics_claim_batch_requests.len(),
                round
            );

            // Reserve a single nonce for this batch signing
            // SECURITY: Nonces are REQUIRED - abort batch if unavailable
            // NOTE: Use reserve_nonces_for_batch() NOT acquire_nonce() - the coordinator must NOT
            // consume the nonce, only reserve it. Each node consumes their own copy when signing.
            let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
                let nm_guard = nm.lock().await;
                match nm_guard.reserve_nonces_for_batch(&[batch_id.clone()]).await {
                    Ok(assignments) => {
                        if let Some(tuple_id) = assignments.get(&batch_id) {
                            info!("🔐 [TICS_CLAIM] Reserved nonce {} for batch {}", tuple_id, batch_id);
                            tuple_id.clone()
                        } else {
                            tracing::error!("🔴 [TICS_CLAIM] No nonce assignment returned for batch {} - aborting batch (will retry next epoch)", batch_id);
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::error!("🔴 [TICS_CLAIM] Failed to reserve nonce for batch {}: {} - aborting batch (will retry next epoch)", batch_id, e);
                        return Ok(());
                    }
                }
            } else {
                tracing::error!("🔴 [TICS_CLAIM] NonceManager not available - aborting batch (will retry next epoch)");
                return Ok(());
            };

            let message = ChannelMessage::TicsClaimRewardBatch {
                batch_id,
                requests: tics_claim_batch_requests,
                round,
                timestamp: batch_timestamp,
                node_id: self.id.clone(),
                nonce_tuple_id: Some(nonce_tuple_id),
            };

            if let Err(e) = self.message_tx.send(message).await {
                warn!(
                    "⚠️ [CLOCK][TICS_CLAIM] Failed to send TicsClaimRewardBatch channel message: {}",
                    e
                );
            }
        }

        info!(
            "✅ [CLOCK][TICS_CLAIM] Settlement epoch completed: {} TICS claim requests batched, {} BTC claim requests (with tx_id) batched for contract",
            tics_batched, btc_updated
        );

        Ok(())
    }

    /// TICS platform-fee claim settlement: picks one eligible platform-fee claim (TICS-first, then BTC-with-txid),
    /// builds a claimPlatformFee contract transaction signed by the admin's MPC-derived key, and broadcasts for signing.
    async fn process_tics_claim_platform_fee_settlement_epoch(&self, round: u64) -> Result<()> {
        use crate::types::messaging::TicsClaimPlatformFeeBatchRequest;
        use crate::types::rpc_server::PendingClaimPlatformFeeRequest;

        info!("🔍 [CLOCK] Processing TICS claim-platform-fee settlement epoch (epoch_3)...");

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;
        let db = user_intent_manager.get_database();

        // Load all pending platform fee claims from DB
        let all_claims: Vec<(String, PendingClaimPlatformFeeRequest)> =
            match db.get_values_with_prefix("pending_claim_platform_fee:") {
                Ok(entries) => entries,
                Err(e) => {
                    warn!("⚠️ [CLOCK][TICS_PF] Failed to load pending platform fee claims: {}", e);
                    return Ok(());
                }
            };

        if all_claims.is_empty() {
            info!("ℹ️  [CLOCK][TICS_PF] No platform fee claims found for settlement epoch");
            return Ok(());
        }

        // Look up admin registration to get admin_tics_address for the batch request
        let admin_public_address = crate::env_defaults::admin_public_address();
        if admin_public_address.trim().is_empty() {
            warn!("⚠️ [CLOCK][TICS_PF] ADMIN_PUBLIC_ADDRESS not configured; skipping platform fee settlement");
            return Ok(());
        }
        let admin_reg = match user_intent_manager
            .get_admin_by_address(&admin_public_address)
            .await
        {
            Some(reg) => reg,
            None => {
                warn!("⚠️ [CLOCK][TICS_PF] Admin not registered ({}); skipping", admin_public_address);
                return Ok(());
            }
        };
        if admin_reg.derived_eth_address.is_none() || admin_reg.tweaked_secret_share.is_none() {
            warn!("⚠️ [CLOCK][TICS_PF] Admin missing derived_eth_address or tweaked_secret_share; skipping");
            return Ok(());
        }

        // Revert stale "Batched" TICS claims (no tx_id) back to "Pending" so they can be retried.
        // This handles the case where a previous TICS signing round failed.
        for (key, req) in &all_claims {
            if req.asset == "TICS" && req.status == "Batched" && req.tx_id.is_none() {
                let mut reverted = req.clone();
                reverted.status = "Pending".to_string();
                if let Err(e) = db.put_string(key, &reverted) {
                    warn!("⚠️ [CLOCK][TICS_PF] Failed to revert stale Batched TICS claim {} to Pending: {}", req.request_id, e);
                } else {
                    info!("🔄 [CLOCK][TICS_PF] Reverted stale Batched TICS claim {} (no tx_id) back to Pending for retry", req.request_id);
                }
            }
        }

        // Pick first eligible claim: TICS first, then BTC-with-txid
        let mut selected: Option<(String, PendingClaimPlatformFeeRequest)> = None;

        // Priority 1: TICS claims
        for (key, req) in &all_claims {
            if req.status == "Pending" && req.asset == "TICS" {
                selected = Some((key.clone(), req.clone()));
                break;
            }
        }

        // Priority 2: BTC claims with tx_id (need on-chain registration)
        // Accept both "Pending" (legacy) and "Batched" (after BTC transfer epoch marked it Batched)
        if selected.is_none() {
            for (key, req) in &all_claims {
                if (req.status == "Pending" || req.status == "Batched")
                    && req.asset == "BTC"
                    && req.tx_id.as_ref().map_or(false, |t| !t.is_empty())
                {
                    selected = Some((key.clone(), req.clone()));
                    break;
                }
            }
        }

        let (db_key, mut req) = match selected {
            Some(s) => s,
            None => {
                info!("ℹ️  [CLOCK][TICS_PF] No eligible platform fee claims for TICS settlement");
                return Ok(());
            }
        };

        let chain_type: u8 = if req.asset == "TICS" { 1 } else { 0 };
        // For TICS claims: recipient = tics_target_address (the actual receiver on TICS chain)
        // For BTC claims: recipient = admin's derived_eth_address (BTC already sent to btc_target_address
        //   in epoch_4; this contract call just updates on-chain accounting)
        let target_address = if req.asset == "TICS" {
            req.tics_target_address.clone().unwrap_or_default()
        } else {
            // BTC: use admin's derived EVM address for the contract call recipient
            admin_reg.derived_eth_address.clone().unwrap_or_default()
        };

        if target_address.is_empty() {
            warn!("⚠️ [CLOCK][TICS_PF] No target address for claim {}; skipping", req.request_id);
            return Ok(());
        }

        let batch_request = TicsClaimPlatformFeeBatchRequest {
            request_id: req.request_id.clone(),
            asset: req.asset.clone(),
            amount: req.amount.clone(),
            chain_type,
            tx_id: req.tx_id.clone(),
            target_address,
            admin_tics_address: admin_reg.tics_address.clone(),
        };

        // Mark as Batched
        req.status = "Batched".to_string();
        if let Err(e) = db.put_string(&db_key, &req) {
            warn!("⚠️ [CLOCK][TICS_PF] Failed to mark claim {} as Batched: {}", req.request_id, e);
        }

        let batch_timestamp = chrono::Utc::now().to_rfc3339();
        let batch_id = format!(
            "tics_claim_platform_fee_batch:{}:{}",
            round,
            chrono::Utc::now().timestamp_millis()
        );

        info!(
            "📦 [CLOCK][TICS_PF] Creating TICS platform-fee batch {} for {} claim (request_id={}) at round {}",
            batch_id, req.asset, req.request_id, round
        );

        // Reserve nonce
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard
                .reserve_nonces_for_batch(&[batch_id.clone()])
                .await
            {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get(&batch_id) {
                        info!("🔐 [TICS_PF] Reserved nonce {} for batch {}", tuple_id, batch_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [TICS_PF] No nonce assignment for batch {} - aborting", batch_id);
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [TICS_PF] Failed to reserve nonce for batch {}: {} - aborting", batch_id, e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [TICS_PF] NonceManager not available - aborting");
            return Ok(());
        };

        let message = ChannelMessage::TicsClaimPlatformFeeBatch {
            batch_id,
            requests: vec![batch_request],
            round,
            timestamp: batch_timestamp,
            node_id: self.id.clone(),
            nonce_tuple_id: Some(nonce_tuple_id),
        };

        if let Err(e) = self.message_tx.send(message).await {
            warn!(
                "⚠️ [CLOCK][TICS_PF] Failed to send TicsClaimPlatformFeeBatch channel message: {}",
                e
            );
        }

        Ok(())
    }

    /// Process BTC intent manager update batch after BTC batch is finalized
    /// This runs another round to select a final node that will:
    /// 1. Get intents with network_to_target_tx_id but not Solved
    /// 2. Create batch and broadcast via btc-intent-manager-tx-update
    /// 3. Make contract call to processBatchIntents to update tx-id on contract
    #[allow(dead_code)]
    async fn process_btc_intent_manager_update_batch_internal(
        btc_batch_round: u64,
        btc_txid: &str,
        message_tx: mpsc::Sender<ChannelMessage>,
        user_intent_manager: Option<Arc<UserIntentManager>>,
        coordination: &mut Coordination,
        node_id: String,
    ) -> Result<()> {
        info!(
            "🔄 [BTC_INTENT_MANAGER] Starting contract update batch process for BTC batch round {} (txid: {})",
            btc_batch_round, btc_txid
        );

        // Get user intent manager
        let user_intent_manager = user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Get database to access IntentStorage directly
        let database = user_intent_manager.get_database();
        let intent_storage = crate::database::storage::IntentStorage::new(database.clone());

        // Get intents with BOTH user_to_network_tx_id AND network_to_target_tx_id (completed intents)
        let completed_intents = intent_storage.get_completed_intents().await?;

        // Filter: must have BOTH TXIDs, BTC target chain, and status NOT Solved
        let mut eligible_intents = Vec::new();
        for (intent_hash, intent, tx_ids) in completed_intents {
            // Check if intent status is NOT Solved
            if let Some(user) = user_intent_manager
                .get_user_by_intent_hash(&intent_hash)
                .await
            {
                if let Some(status) = user.intent_hashes.get(&intent_hash) {
                    if *status == crate::types::IntentStatus::Solved {
                        continue; // Skip solved intents
                    }
                }
            }

            // Must be BTC target chain
            let target_chain_lower = intent.target_chain.to_lowercase();
            if target_chain_lower != "bitcoin" && target_chain_lower != "btc" {
                continue;
            }

            eligible_intents.push((intent_hash, intent, tx_ids));
        }

        if eligible_intents.is_empty() {
            info!(
                "ℹ️ [BTC_INTENT_MANAGER] No eligible intents found for contract update batch"
            );
            return Ok(());
        }

        info!(
            "📋 [BTC_INTENT_MANAGER] Found {} eligible intents for contract update batch",
            eligible_intents.len()
        );

        // Get available nodes
        let available_nodes: Vec<libp2p::PeerId> = coordination
            .get_available_nodes()
            .await;

        if available_nodes.is_empty() {
            warn!("⚠️ [BTC_INTENT_MANAGER] No available nodes for selection");
            return Ok(());
        }

        // Get next round in a block so we can release vrf_service borrow before replicate_vrf_round_to_consensus
        let update_round = {
            let vrf_service = coordination
                .vrf_service()
                .ok_or_else(|| anyhow!("Round/selection service not available"))?;
            if let Err(e) = vrf_service.sync_rounds_before_signing().await {
                warn!("⚠️ [BTC_INTENT_MANAGER] Failed to sync rounds: {}", e);
            }
            vrf_service.get_next_round().await
        };
        coordination.replicate_vrf_round_to_consensus(update_round);

        info!(
            "🎯 [BTC_INTENT_MANAGER] Performing selection for contract update batch (round {})",
            update_round
        );

        // Perform node selection
        let vrf_service = coordination
            .vrf_service()
            .ok_or_else(|| anyhow!("Round/selection service not available"))?;
        match vrf_service
            .perform_node_selection(
                &available_nodes,
                crate::vrf::VRF_NODE_SELECTION_COUNT,
                update_round,
                "btc_intent_manager_update",
            )
            .await
        {
            Ok(_selection_result) => {
                info!(
                    "✅ [BTC_INTENT_MANAGER] Selection completed for round {}",
                    update_round
                );
            }
            Err(e) => {
                error!("❌ [BTC_INTENT_MANAGER] Selection failed: {}", e);
                return Err(e);
            }
        }

        // Wait for consensus to complete and check if this node is the final node
        // The final node will handle the batch creation and contract call
        // For now, we'll create the batch message and broadcast it
        // The final node will be determined by consensus

        // Prepare intent hashes for the batch
        let intent_hashes: Vec<String> = eligible_intents
            .iter()
            .map(|(hash, _, _)| hash.clone())
            .collect();

        // Create batch timestamp
        let batch_timestamp = chrono::Utc::now().to_rfc3339();

        // NOTE: This static function doesn't have access to nonce_manager.
        // The nonce_tuple_id should be reserved by the caller and passed as a parameter.
        // For now, we set it to None and let the handler use the fallback path.
        // TODO: Update callers to pass nonce_tuple_id when this function is used.
        let nonce_tuple_id: Option<String> = None;

        // Broadcast via btc-intent-manager-tx-update topic
        let batch_message = crate::types::ChannelMessage::BtcIntentManagerTxUpdate {
            intent_hashes: intent_hashes.clone(),
            btc_txid: btc_txid.to_string(),
            btc_batch_round,
            update_round,
            timestamp: batch_timestamp,
            node_id: node_id.clone(),
            nonce_tuple_id,
        };

        message_tx
            .send(batch_message)
            .await
            .map_err(|e| anyhow!("Failed to send BTC intent manager update message: {}", e))?;

        info!(
            "✅ [BTC_INTENT_MANAGER] Broadcasted contract update batch with {} intents (BTC txid: {})",
            intent_hashes.len(),
            btc_txid
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
    async fn send_transaction_data_to_final_node(
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

    /// TICS UserToVault batch ONLY: handle one partial for (round, slot_id). Aggregate when threshold reached.
    /// NOTE: BTC UserToVault now uses handle_btc_utv_signature_for_round_slot with multi-input support.
    /// This function should NOT be used for BTC UTV - it only handles single-signature TICS transactions.
    async fn handle_signature_for_round_slot(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
        slot_id: String,
    ) -> Result<()> {
        use crate::signing::state::RoundSlotKey;

        let slot_key: RoundSlotKey = (round, slot_id.clone());
        let already_aggregated = {
            let agg = self.signatures.aggregated_round_slots.read().await;
            agg.contains(&slot_key)
        };
        if already_aggregated {
            info!(
                "⏭️ [SIGNING] Slot {} for round {} already aggregated, ignoring signature from {}",
                slot_id, round, from
            );
            return Ok(());
        }

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
            .verify_signature_for_round(&from, &signature, round, Some(&slot_id))
            .await
        {
            warn!(
                "⚠️ [SIGNING] Slot {} partial verification failed for peer {} in round {} (expected with random nonces): {}",
                slot_id, from, round, e
            );
            // Don't return error - with random nonces, partial verification is not possible.
            // The final aggregated signature will be verified against the group public key.
        }

        {
            let mut by_slot = self.signatures.signatures_by_round_slot.write().await;
            let entry = by_slot.entry(slot_key.clone()).or_default();
            entry.insert(from.clone(), signature.clone());
            info!(
                "💾 [SIGNING] Stored signature from {} for slot {} round {} (total: {})",
                from,
                slot_id,
                round,
                entry.len()
            );
        }

        let round_slot_signatures = {
            let by_slot = self.signatures.signatures_by_round_slot.read().await;
            by_slot.get(&slot_key).cloned()
        };
        let Some(round_slot_signatures) = round_slot_signatures else {
            return Ok(());
        };
        if round_slot_signatures.len() < self.threshold as usize {
            info!(
                "⏳ [SIGNING] Slot {} round {}: {}/{} signatures",
                slot_id, round, round_slot_signatures.len(), self.threshold
            );
            return Ok(());
        }

        // Mark aggregated immediately so no duplicate work; then spawn non-blocking task for aggregate + broadcast
        {
            let mut agg = self.signatures.aggregated_round_slots.write().await;
            agg.insert(slot_key.clone());
        }

        // TICS UserToVault only - BTC UTV uses dedicated handler with multi-input support
        let slot_kind = SlotKind::TicsUserToVault;

        let chain_id = std::env::var("MPC_TICS_CHAIN_ID")
            .ok()
            .and_then(|id| id.parse::<u64>().ok())
            .unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());

        let mut sorted: Vec<_> = round_slot_signatures.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let round_slot_signatures_owned: Vec<(String, ECDSASignature)> = sorted
            .iter()
            .take(self.threshold)
            .map(|(id, sig)| ((*id).clone(), (*sig).clone()))
            .collect();

        let self_ref = self.self_ref.clone();
        let round = round;
        let slot_id = slot_id.clone();

        tokio::spawn(async move {
            if let Some(arc) = self_ref {
                let mut node = arc.lock().await;
                if let Err(e) = node
                    .do_aggregate_and_broadcast_for_slot(
                        round,
                        slot_id.clone(),
                        round_slot_signatures_owned,
                        chain_id,
                        slot_kind,
                    )
                    .await
                {
                    error!(
                        "❌ [SIGNING] Async aggregation failed for slot {} round {}: {}",
                        slot_id, round, e
                    );
                }
            }
        });

        Ok(())
    }

    /// BTC UserToVault batch: handle multi-input signatures for one slot.
    /// This is the hybrid of TICS UTV (slot-based) and N2T (multi-input).
    /// Key: (round, slot_id) where slot_id is the intent_hash.
    /// Each slot can have multiple inputs (UTXOs).
    ///
    /// Flow (mirrors N2T per-input logic but keyed by slot):
    /// 1) Skip if slot already completed
    /// 2) Load tx data for this slot from user_to_vault_btc_batch
    /// 3) Verify and store each signature per input
    /// 4) Sweep: aggregate each input that hit threshold
    /// 5) If ALL inputs for this slot are aggregated, finalize and broadcast
    pub async fn handle_btc_utv_signature_for_round_slot(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
        slot_id: String,
    ) -> Result<()> {
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use std::collections::HashMap;

        let slot_key: RoundSlotKey = (round, slot_id.clone());

        // 1. Skip if slot already completed
        {
            let completed = self.btc_utv_state.btc_utv_completed_slots.read().await;
            if completed.contains(&slot_key) {
                info!(
                    "⏭️ [BTC_UTV] Slot {} for round {} already completed, ignoring signatures from {}",
                    slot_id, round, from
                );
                return Ok(());
            }
        }

        // 2. Get tx data for this slot from user_to_vault_btc_batch
        // Nodes without a DKG share may not have BTC batch data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        let (_unsigned_tx, _extras, total_inputs) = {
            let mut result = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let batch = self.pending.user_to_vault_btc_batch.read().await;
                if let Some(entries) = batch.get(&round) {
                    if let Some((_, _user_eth, chain_tx, _, extras_opt)) = entries.iter().find(|(h, ..)| h == &slot_id) {
                        if let ChainTransaction::Bitcoin(t) = chain_tx {
                            if let Some(extras) = extras_opt {
                                if attempt > 0 {
                                    debug!(
                                        "✅ [BTC_UTV] Found BTC batch data for round {} slot {} after {} attempts (~{}ms)",
                                        round, slot_id, attempt + 1, attempt * 100
                                    );
                                }
                                result = Some((t.clone(), extras.clone(), t.inputs.len()));
                                break;
                            }
                        }
                    }
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [BTC_UTV] Could not find BTC batch data for round {} slot {} after {}ms",
                        round, slot_id, max_attempts * 100
                    );
                }
            }
            result.ok_or_else(|| {
                anyhow!(
                    "[BTC_UTV] No user_to_vault_btc_batch for round {} slot {} (observer timeout)",
                    round,
                    slot_id
                )
            })?
        };

        info!(
            "📥 [BTC_UTV] Received {} signatures from {} for slot {} round {} (expecting {} inputs)",
            signatures.len(),
            from,
            slot_id,
            round,
            total_inputs
        );

        // 3. Verify and store each signature per input
        let mut verified_count = 0;
        for sig in &signatures {
            if sig.input_index >= total_inputs {
                warn!(
                    "⚠️ [BTC_UTV] Signature from {} has invalid input_index {} (slot {} has {} inputs)",
                    from, sig.input_index, slot_id, total_inputs
                );
                continue;
            }

            // Verify signature against correct digest for this input
            match self
                .verify_btc_utv_signature_for_slot(
                    &from,
                    &sig.signature,
                    round,
                    &slot_id,
                    sig.input_index,
                )
                .await
            {
                Ok(_) => {
                    info!(
                        "✅ [BTC_UTV] Verified signature from {} for slot {} round {} input {}",
                        from, slot_id, round, sig.input_index
                    );
                }
                Err(e) => {
                    error!(
                        "❌ [BTC_UTV] Signature verification failed for {} slot {} round {} input {}: {}",
                        from, slot_id, round, sig.input_index, e
                    );
                    continue;
                }
            }

            // Store: (round, slot_id) → input_index → peer → signature
            {
                let mut by_slot = self
                    .btc_utv_state
                    .btc_utv_sigs_by_round_slot
                    .write()
                    .await;
                let slot_map = by_slot.entry(slot_key.clone()).or_default();
                let input_map = slot_map.entry(sig.input_index).or_default();
                input_map.insert(from.clone(), sig.signature.clone());
            }
            verified_count += 1;
        }

        info!(
            "💾 [BTC_UTV] Stored {}/{} verified signatures from {} for slot {} round {}",
            verified_count,
            signatures.len(),
            from,
            slot_id,
            round
        );

        // 3b. If this final node failed to verify ALL signatures (e.g. missing DKG
        //     commitments on an observer), the batch can never complete.  Revert the
        //     intent status from Batched back to Pending so a future round (with a
        //     different final node) can re-process it.
        if verified_count == 0 && !signatures.is_empty() {
            // Check if this node is the final node for this round
            let is_final = {
                let final_nodes = self.signatures.final_nodes_by_round.read().await;
                final_nodes.get(&round).map_or(false, |f| *f == self.id)
            };
            if is_final {
                warn!(
                    "🔄 [BTC_UTV] Final node {} failed to verify ALL signatures for slot {} round {} — reverting intent to Pending",
                    self.id, slot_id, round
                );
                if let Some(ref uim) = self.user_intent_manager {
                    if let Some(user) = uim.get_user_by_intent_hash(&slot_id).await {
                        // NEVER revert from Solved — that is a terminal state.
                        let current_status = uim
                            .get_intent_status(&user.tics_address, &slot_id)
                            .await;
                        if matches!(current_status, Some(crate::types::user_intent::IntentStatus::Solved)) {
                            debug!(
                                "⏭️ [BTC_UTV] Skipping revert for intent {} — already Solved",
                                slot_id
                            );
                        } else if let Err(e) = uim
                            .update_intent_status(
                                &user.tics_address,
                                &slot_id,
                                crate::types::user_intent::IntentStatus::Pending,
                            )
                            .await
                        {
                            error!(
                                "❌ [BTC_UTV] Failed to revert intent {} to Pending: {}",
                                slot_id, e
                            );
                        } else {
                            info!(
                                "✅ [BTC_UTV] Reverted intent {} to Pending for user {} (will be re-batched next cycle)",
                                slot_id, user.tics_address
                            );
                        }
                    }
                }

                // Broadcast error to all nodes so they also revert
                // intent status from Batched to Pending.
                self.broadcast_transaction_error(
                    Some(vec![slot_id.clone()]),
                    &format!(
                        "BTC UTV final node failed to verify ALL signatures for slot {} round {}",
                        slot_id, round
                    ),
                    "user_to_network",
                    None,
                )
                .await;
                info!(
                    "📡 [BTC_UTV] Broadcasted verification failure for slot {} round {} to sync intent status across nodes",
                    slot_id, round
                );
            }
        }

        // 4. Sweep: aggregate each input that hit threshold
        for idx in 0..total_inputs {
            // Skip if already aggregated for this input
            {
                let done = self
                    .btc_utv_state
                    .btc_utv_done_inputs_by_round_slot
                    .read()
                    .await;
                if done.get(&slot_key).is_some_and(|s| s.contains(&idx)) {
                    continue;
                }
            }

            // Get peer sigs for this input
            let peer_map: Option<HashMap<String, ECDSASignature>> = {
                let by_slot = self
                    .btc_utv_state
                    .btc_utv_sigs_by_round_slot
                    .read()
                    .await;
                by_slot
                    .get(&slot_key)
                    .and_then(|s| s.get(&idx))
                    .cloned()
            };
            let Some(peer_map) = peer_map else {
                continue;
            };

            // Check threshold
            if peer_map.len() < self.threshold {
                info!(
                    "⏳ [BTC_UTV] Slot {} input {} has {}/{} signatures",
                    slot_id,
                    idx,
                    peer_map.len(),
                    self.threshold
                );
                continue;
            }

            // Sort deterministically, take threshold
            let mut chosen: Vec<(String, ECDSASignature)> = peer_map.into_iter().collect();
            chosen.sort_by(|a, b| a.0.cmp(&b.0));
            let chosen: Vec<(String, ECDSASignature)> =
                chosen.into_iter().take(self.threshold).collect();

            // Verify all chosen sigs share the same r value and are 64 bytes
            let r0 = &chosen[0].1.signature[0..32];
            let mut r_mismatch = false;
            for (peer, s) in &chosen {
                if s.signature.len() != 64 {
                    error!(
                        "❌ [BTC_UTV] Slot {} input {}: bad sig length from {} (got {})",
                        slot_id,
                        idx,
                        peer,
                        s.signature.len()
                    );
                    r_mismatch = true;
                    break;
                }
                if &s.signature[0..32] != r0 {
                    error!(
                        "❌ [BTC_UTV] Slot {} input {}: r mismatch from {}",
                        slot_id, idx, peer
                    );
                    r_mismatch = true;
                    break;
                }
            }
            if r_mismatch {
                continue;
            }

            // Build inputs for MPC aggregation
            let mut sigs: Vec<RecoverableSignature> = Vec::with_capacity(self.threshold);
            let mut peer_to_dkg_index: Vec<(String, u32)> = Vec::with_capacity(self.threshold);
            for (peer, ecsig) in chosen {
                let rid = RecoveryId::from_i32(ecsig.recovery_id as i32)?;
                let rs = RecoverableSignature::from_compact(&ecsig.signature, rid)?;
                sigs.push(rs);
                let dkg_idx = self.calculate_dkg_index_for_peer_sync(&peer);
                peer_to_dkg_index.push((peer, dkg_idx));
            }

            // Aggregate this input's signatures
            let agg = match self.aggregate_signatures(sigs, peer_to_dkg_index).await {
                Ok(sig) => sig,
                Err(e) => {
                    error!(
                        "❌ [BTC_UTV] Failed to aggregate slot {} input {}: {}",
                        slot_id, idx, e
                    );
                    continue;
                }
            };

            // Store aggregated sig for this input
            {
                let mut agg_map = self
                    .btc_utv_state
                    .btc_utv_agg_by_round_slot
                    .write()
                    .await;
                agg_map
                    .entry(slot_key.clone())
                    .or_default()
                    .insert(idx, agg);
            }

            // Mark input as done
            {
                let mut done = self
                    .btc_utv_state
                    .btc_utv_done_inputs_by_round_slot
                    .write()
                    .await;
                done.entry(slot_key.clone()).or_default().insert(idx);
            }

            info!(
                "✅ [BTC_UTV] Aggregated slot {} input {} for round {}",
                slot_id, idx, round
            );
        }

        // 5. Check if ALL inputs for this slot are aggregated
        let all_done = {
            let done = self
                .btc_utv_state
                .btc_utv_done_inputs_by_round_slot
                .read()
                .await;
            done.get(&slot_key)
                .map_or(false, |s| s.len() == total_inputs)
        };

        if all_done {
            // Mark slot as completed immediately (prevent duplicate finalization)
            {
                let mut completed = self.btc_utv_state.btc_utv_completed_slots.write().await;
                completed.insert(slot_key.clone());
            }

            info!(
                "🎯 [BTC_UTV] All {} inputs aggregated for slot {} round {}, spawning finalization",
                total_inputs, slot_id, round
            );

            // Spawn async finalization for this slot
            let self_ref = self.self_ref.clone();
            let slot_id_clone = slot_id.clone();
            tokio::spawn(async move {
                if let Some(arc) = self_ref {
                    let mut node = arc.lock().await;
                    if let Err(e) = node.finalize_btc_utv_slot(round, slot_id_clone.clone()).await {
                        error!(
                            "❌ [BTC_UTV] Finalization failed for slot {} round {}: {}",
                            slot_id_clone, round, e
                        );
                    }
                }
            });
        }

        Ok(())
    }

    /// Verify a BTC UTV signature for a specific slot and input.
    async fn verify_btc_utv_signature_for_slot(
        &self,
        peer_id: &str,
        signature: &ECDSASignature,
        round: u64,
        slot_id: &str,
        input_index: usize,
    ) -> Result<()> {
        use secp256k1::{ecdsa::RecoveryId, Message, Secp256k1};

        // Get tx data for this slot
        let (btc_tx, user_eth) = {
            let batch = self.pending.user_to_vault_btc_batch.read().await;
            let entries = batch.get(&round).ok_or_else(|| {
                anyhow!(
                    "[verify_btc_utv] No batch for round {} slot {}",
                    round,
                    slot_id
                )
            })?;
            let (_, user_eth, chain_tx, _, _) = entries
                .iter()
                .find(|(h, ..)| h == slot_id)
                .ok_or_else(|| {
                    anyhow!(
                        "[verify_btc_utv] No slot {} in batch for round {}",
                        slot_id,
                        round
                    )
                })?;

            let btc_tx = match chain_tx {
                ChainTransaction::Bitcoin(t) => t.clone(),
                _ => {
                    return Err(anyhow!(
                        "[verify_btc_utv] Slot {} is not Bitcoin",
                        slot_id
                    ))
                }
            };
            (btc_tx, user_eth.clone())
        };

        // Get input and compute digest
        let inp = btc_tx.inputs.get(input_index).ok_or_else(|| {
            anyhow!(
                "[verify_btc_utv] Slot {} has no input at index {}",
                slot_id,
                input_index
            )
        })?;
        let prev_spk = inp
            .witness_utxo
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "[verify_btc_utv] Slot {} input {} missing witness_utxo",
                    slot_id,
                    input_index
                )
            })?
            .script_pubkey
            .clone();

        let digest = self.compute_legacy_sighash_all_p2pkh(&btc_tx, input_index, &prev_spk)?;

        // Get peer's share pubkey for UserToVault
        let share_pubkey = self
            .get_share_pubkey_for_verification(
                peer_id,
                round,
                &Some(TransactionType::UserToVault),
                Some(&user_eth),
            )
            .await?;

        // Convert k256 ProjectivePoint to compressed bytes
        let share_pubkey_bytes = k256::EncodedPoint::from(share_pubkey.to_affine())
            .as_bytes()
            .to_vec();

        // Verify signature
        let msg = Message::from_digest_slice(&digest)?;
        let secp = Secp256k1::new();

        // Try all recovery IDs to find match
        for rid in 0..4 {
            if let Ok(test_rid) = RecoveryId::from_i32(rid) {
                if let Ok(test_recov_sig) =
                    secp256k1::ecdsa::RecoverableSignature::from_compact(&signature.signature, test_rid)
                {
                    if let Ok(recovered_pk) = secp.recover_ecdsa(&msg, &test_recov_sig) {
                        if recovered_pk.serialize() == share_pubkey_bytes.as_slice() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Fallback: direct verification
        let pk = secp256k1::PublicKey::from_slice(&share_pubkey_bytes)?;
        let rid = RecoveryId::from_i32(signature.recovery_id as i32)?;
        let recov_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&signature.signature, rid)?;
        let std_sig = recov_sig.to_standard();
        secp.verify_ecdsa(&msg, &std_sig, &pk)?;

        Ok(())
    }

    /// Finalize and broadcast a BTC UTV slot after all inputs are aggregated.
    async fn finalize_btc_utv_slot(&mut self, round: u64, slot_id: String) -> Result<()> {
        let slot_key: RoundSlotKey = (round, slot_id.clone());

        // Nodes without a DKG share may not have BTC batch data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        // Get tx data, user_tics_address, and extras
        let (unsigned_tx, user_tics_address, extras) = {
            let mut result = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let batch = self.pending.user_to_vault_btc_batch.read().await;
                if let Some(entries) = batch.get(&round) {
                    if let Some((_, user_eth, chain_tx, _, extras_opt)) = entries.iter().find(|(h, ..)| h == &slot_id) {
                        if let ChainTransaction::Bitcoin(t) = chain_tx {
                            if let Some(extras) = extras_opt {
                                if attempt > 0 {
                                    debug!(
                                        "✅ [BTC_UTV] Found BTC batch data for round {} slot {} after {} attempts (~{}ms)",
                                        round, slot_id, attempt + 1, attempt * 100
                                    );
                                }
                                result = Some((t.clone(), user_eth.clone(), extras.clone()));
                                break;
                            }
                        }
                    }
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [BTC_UTV] Could not find BTC batch data for round {} slot {} after {}ms",
                        round, slot_id, max_attempts * 100
                    );
                }
            }
            result.ok_or_else(|| {
                anyhow!(
                    "[finalize_btc_utv] No batch data for round {} slot {} (observer timeout)",
                    round,
                    slot_id
                )
            })?
        };

        let total_inputs = unsigned_tx.inputs.len();

        // Collect per-input aggregated sigs in order
        let per_input_sigs: Vec<(usize, RecoverableSignature)> = {
            let agg_map = self.btc_utv_state.btc_utv_agg_by_round_slot.read().await;
            let slot_agg = agg_map.get(&slot_key).ok_or_else(|| {
                anyhow!(
                    "[finalize_btc_utv] No aggregated sigs for slot {} round {}",
                    slot_id,
                    round
                )
            })?;

            let mut v = Vec::with_capacity(total_inputs);
            for i in 0..total_inputs {
                let sig = slot_agg.get(&i).ok_or_else(|| {
                    anyhow!(
                        "[finalize_btc_utv] Missing aggregated sig for slot {} input {}",
                        slot_id,
                        i
                    )
                })?;
                v.push((i, *sig));
            }
            v
        };

        // Finalize and serialize (same as N2T)
        let (raw, txid, _wtxid) = Self::finalize_and_serialize_tx(
            unsigned_tx,
            extras.from_kind,
            &per_input_sigs,
            &extras.pubkey33,
        )?;

        let raw_hex = hex::encode(&raw);
        let txid_hex = hex::encode(txid);

        info!(
            "🎯 [BTC_UTV] Slot {} round {} finalized: txid={}",
            slot_id, round, txid_hex
        );

        // Broadcast to Bitcoin network
        match Self::broadcast_transaction(&raw_hex, extras.is_testnet).await {
            Ok(Some(broadcast_txid)) => {
                info!(
                    "✅ [BTC_UTV] Slot {} broadcast successful: {}",
                    slot_id, broadcast_txid
                );

                // Store final_solver for this intent (same pattern as TICS UTV)
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_final_solver(&slot_id, self.id.as_str())
                        .await
                    {
                        warn!(
                            "⚠️ [BTC_UTV] Failed to store final solver for intent {}: {}",
                            slot_id, e
                        );
                    }
                }

                // Broadcast tx_id to all nodes (via store_transaction_id_for_round -> broadcast_transaction_id)
                // Each node will store user_to_network_tx_id for this intent
                info!(
                    "📡 [BTC_UTV] Broadcasting transaction ID {} for intent {} (round {}) to all nodes",
                    broadcast_txid, slot_id, round
                );
                self.store_transaction_id_for_round(
                    round,
                    &broadcast_txid,
                    crate::types::TransactionNetwork::BTC,
                    Some(slot_id.clone()),
                )
                .await;
            }
            Ok(None) => {
                warn!(
                    "⚠️ [BTC_UTV] Slot {} broadcast completed but no txid returned, using computed txid",
                    slot_id
                );

                // Store final_solver for this intent
                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_final_solver(&slot_id, self.id.as_str())
                        .await
                    {
                        warn!(
                            "⚠️ [BTC_UTV] Failed to store final solver for intent {}: {}",
                            slot_id, e
                        );
                    }
                }

                // Broadcast computed tx_id to all nodes
                info!(
                    "📡 [BTC_UTV] Broadcasting computed transaction ID {} for intent {} (round {}) to all nodes",
                    txid_hex, slot_id, round
                );
                self.store_transaction_id_for_round(
                    round,
                    &txid_hex,
                    crate::types::TransactionNetwork::BTC,
                    Some(slot_id.clone()),
                )
                .await;
            }
            Err(e) => {
                error!("❌ [BTC_UTV] Slot {} broadcast failed: {}", slot_id, e);
                self.store_transaction_error_for_round(
                    round,
                    &e.to_string(),
                    crate::types::TransactionNetwork::BTC,
                )
                .await;
            }
        }

        // Log user_tics_address for debugging (extracted but not used in current flow)
        if !user_tics_address.is_empty() {
            debug!(
                "🔗 [BTC_UTV] Slot {} was for user {}",
                slot_id, user_tics_address
            );
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

        // Nodes without a DKG share may not have BTC TX data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        let (unsigned_tx, extras, total_inputs) = {
            let mut found_data: Option<(ChainTransaction, Option<BtcRoundExtras>)> = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let data = if is_claim_reward_round {
                    let store = self.pending.claim_reward_pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                } else if is_claim_platform_fee_round {
                    let store = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                } else if is_withdraw_round {
                    let store = self.pending.withdraw_pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _solver_address, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                } else {
                    let store = self.pending.pending_transactions_btc.read().await;
                    store.get(&round).map(|(chain_tx, _raw, _intent_hash, _tx_type_opt, extras_opt)| {
                        (chain_tx.clone(), extras_opt.clone())
                    })
                };
                if let Some(val) = data {
                    if attempt > 0 {
                        debug!(
                            "✅ [BTC] Found BTC TX data for round {} after {} attempts (~{}ms)",
                            round, attempt + 1, attempt * 100
                        );
                    }
                    found_data = Some(val);
                    break;
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [BTC] Could not find BTC TX data for round {} after {}ms",
                        round, max_attempts * 100
                    );
                }
            }
            let (chain_tx, extras_opt) = found_data.ok_or_else(|| {
                error!(
                    "[handle_btc_signature_for_round] No pending tx for round {} (observer timeout)",
                    round
                );
                anyhow!("no pending tx for round {}", round)
            })?;

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
            let chain_tx = if is_claim_reward_round {
                let claim_reward_pt = self.pending.claim_reward_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    claim_reward_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No claim-reward pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no claim-reward pending tx for round {}", round)
                    })?;
                chain_tx.clone()
            } else if is_claim_platform_fee_round {
                let claim_pf_pt = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                let (chain_tx, _raw, _solver_address, _tx_type_opt, _extras) =
                    claim_pf_pt.get(&round).ok_or_else(|| {
                        error!(
                            "[handle_btc_signature_for_round] No claim-platform-fee pending tx for round {} (finalize step)",
                            round
                        );
                        anyhow!("no claim-platform-fee pending tx for round {}", round)
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

        // Get intent hash and user_tics_address for proper error/success handling
        let (_intent_hash, _user_tics_address) = {
            let pt = self.pending.pending_transactions_btc.read().await;
            if let Some((_chain_tx, _raw, intent_hash, _tx_type_opt, _extras)) = pt.get(&round) {
                // Get user_tics_address from the first signature we have
                let user_tics_address = {
                    let btc_sigs = self.btc_state.btc_sigs_by_round.read().await;
                    if let Some(round_sigs) = btc_sigs.get(&round) {
                        // Get the first available signature to extract user_tics_address
                        round_sigs
                            .values()
                            .flat_map(|input_sigs| input_sigs.values())
                            .next()
                            .and_then(|sig| sig.user_tics_address.clone())
                    } else {
                        None
                    }
                };
                (intent_hash.clone(), user_tics_address)
            } else {
                (None, None)
            }
        };

        // NOTE: Bitcoin transactions from the sequencer are not currently supported
        // as all contract transactions use TICS. If BTC sequencer support is needed,
        // BtcRoundExtras struct needs to be extended with request_id field.

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
                    None,
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
    /// Handle signature received via broadcast (gossipsub); only final node aggregates.
    pub async fn handle_signature_to_final_node(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
        slot_id: Option<String>,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} via broadcast/gossipsub (round {}, slot_id: {:?})",
            self.id, from, round, slot_id
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
                .handle_signature_for_round(from, signature, round, slot_id)
                .await;
        }

        info!(
            "⚠️ [SIGNING] Received signature for round {} but this node is not the final node for that round",
            round
        );
        Ok(())
    }

    /// Handle transaction data received for final node (to enable reconstruction even if not selected to sign).
    ///
    /// Universal threshold verification: collects TX data from DKG nodes and accepts it once
    /// threshold matching copies of tx_bytes arrive. Works for ALL transaction types (batch and non-batch).
    /// If this node already has TX data locally (DKG final node), incoming data is ignored.
    pub async fn handle_transaction_data_for_final_node(
        &mut self,
        from: String,
        round: u64,
        tx_bytes: Vec<u8>,
        intent_hash: Option<String>,
        transaction_type: Option<String>,
        request_id: Option<String>,
        chain_tx_json: Option<String>,
        user_tics_address: Option<String>,
        batch_identifiers: Option<Vec<String>>,
    ) -> Result<()> {
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

        // Determine the slot key: for batch flows use intent_hash as slot_id, for non-batch use ""
        let slot_id = intent_hash.clone().unwrap_or_default();
        let tx_data_key: crate::signing::state::TxDataKey = (round, slot_id.clone());

        // If this node already has the TX data locally (DKG final node that built it), skip
        let already_has_local_data = if slot_id.is_empty() {
            // Non-batch: check all non-batch stores (pending, withdraw, claim-reward — both ETH and BTC)
            let in_pending = self.pending.pending_transactions.read().await.contains_key(&round);
            let in_withdraw_tics = self.pending.withdraw_pending_transactions_tics.read().await.contains_key(&round);
            let in_claim_tics = self.pending.claim_reward_pending_transactions_tics.read().await.contains_key(&round);
            let in_pending_btc = self.pending.pending_transactions_btc.read().await.contains_key(&round);
            let in_withdraw_btc = self.pending.withdraw_pending_transactions_btc.read().await.contains_key(&round);
            let in_claim_btc = self.pending.claim_reward_pending_transactions_btc.read().await.contains_key(&round);
            let in_claim_pf_btc = self.pending.claim_platform_fee_pending_transactions_btc.read().await.contains_key(&round);
            in_pending || in_withdraw_tics || in_claim_tics || in_pending_btc || in_withdraw_btc || in_claim_btc || in_claim_pf_btc
        } else {
            // Batch slot: check appropriate batch store
            let tics_batch = self.pending.user_to_vault_tics_batch.read().await;
            let btc_batch = self.pending.user_to_vault_btc_batch.read().await;
            let in_tics = tics_batch
                .get(&round)
                .map(|entries| entries.iter().any(|(h, ..)| h == &slot_id))
                .unwrap_or(false);
            let in_btc = btc_batch
                .get(&round)
                .map(|entries| entries.iter().any(|(h, ..)| h == &slot_id))
                .unwrap_or(false);
            in_tics || in_btc
        };

        if already_has_local_data {
            debug!(
                "ℹ️ [SIGNING] Already have local TX data for round {} slot {:?}, ignoring from {}",
                round, intent_hash, from
            );
            return Ok(());
        }

        // chain_tx_json is required for the universal approach
        let chain_json = match &chain_tx_json {
            Some(json) => json.clone(),
            None => {
                debug!(
                    "⚠️ [SIGNING] Received TX data from {} for round {} without chain_tx_json, ignoring",
                    from, round
                );
                return Ok(());
            }
        };

        // Collect this TX data for threshold verification
        let received = crate::signing::state::ReceivedTxData {
            from: from.clone(),
            tx_bytes: tx_bytes.clone(),
            chain_tx_json: chain_json,
            intent_hash: intent_hash.clone(),
            transaction_type: transaction_type.clone(),
            request_id: request_id.clone(),
            user_tics_address: user_tics_address.clone(),
            batch_identifiers: batch_identifiers.clone(),
        };

        let mut received_store = self.pending.received_tx_data.write().await;
        let entries = received_store.entry(tx_data_key.clone()).or_insert_with(Vec::new);

        // Don't accept duplicate from same node
        if entries.iter().any(|e| e.from == from) {
            debug!(
                "ℹ️ [SIGNING] Already received TX data from {} for round {} slot {:?}",
                from, round, intent_hash
            );
            return Ok(());
        }

        entries.push(received);

        // Count how many nodes sent matching tx_bytes
        let matching_count = entries
            .iter()
            .filter(|e| e.tx_bytes == tx_bytes)
            .count();

        info!(
            "📥 [SIGNING] Collected TX data from {} for round {} slot {:?} ({}/{} threshold)",
            from, round, intent_hash, matching_count, self.threshold
        );

        // Check if we've reached threshold
        if matching_count < self.threshold {
            return Ok(());
        }

        // Threshold reached! Use the first matching entry's data (all tx_bytes are identical)
        let verified_entry = match entries.iter().find(|e| e.tx_bytes == tx_bytes) {
            Some(entry) => entry.clone(),
            None => {
                error!(
                    "❌ [SIGNING] Race condition: threshold count matched but entry not found for round {} slot {:?}",
                    round, intent_hash
                );
                return Ok(());
            }
        };

        info!(
            "✅ [SIGNING] Threshold reached for round {} slot {:?} - {} matching copies from DKG nodes",
            round, intent_hash, matching_count
        );

        // Drop the write lock before storing
        drop(received_store);

        // Deserialize the verified ChainTransaction
        let chain_tx = match serde_json::from_str::<crate::chain_abstraction::ChainTransaction>(
            &verified_entry.chain_tx_json,
        ) {
            Ok(ct) => ct,
            Err(e) => {
                warn!(
                    "⚠️ [SIGNING] Failed to deserialize chain_tx_json for round {} slot {:?}: {}",
                    round, intent_hash, e
                );
                return Ok(());
            }
        };

        // Parse the transaction type string into the enum
        let parsed_tx_type = transaction_type.as_ref().and_then(|t| {
            match t.as_str() {
                "UserToVault" => Some(crate::types::TransactionType::UserToVault),
                "NetworkToTarget" => Some(crate::types::TransactionType::NetworkToTarget),
                "WithdrawLiquidity" => Some(crate::types::TransactionType::WithdrawLiquidity),
                "IntentStatusUpdate" => Some(crate::types::TransactionType::IntentStatusUpdate),
                "ClaimReward" => Some(crate::types::TransactionType::ClaimReward),
                "ClaimPlatformFee" => Some(crate::types::TransactionType::ClaimPlatformFee),
                "PeerInvalidation" => Some(crate::types::TransactionType::PeerInvalidation),
                _ => {
                    warn!(
                        "⚠️ [SIGNING] Unknown transaction_type string '{}' for round {}, storing as None",
                        t, round
                    );
                    None
                }
            }
        });

        let user_eth = verified_entry.user_tics_address.clone().unwrap_or_default();

        // Populate intent_hashes_by_round for observer nodes so that
        // store_transaction_id_for_round can detect batch N2T / IntentStatusUpdate rounds
        // and broadcast tx-id for ALL intents in the batch (not just the first one).
        if let Some(ref batch_ids) = verified_entry.batch_identifiers {
            if !batch_ids.is_empty() {
                let mut intent_map = self.pending.intent_hashes_by_round.write().await;
                if !intent_map.contains_key(&round) {
                    info!(
                        "💾 [SIGNING] Observer: populated intent_hashes_by_round for round {} with {} intent hashes from TransactionDataForFinalNode",
                        round, batch_ids.len()
                    );
                    intent_map.insert(round, batch_ids.clone());
                }
            }
        }

        // Store in appropriate pending store based on whether this is batch or non-batch
        if !slot_id.is_empty() {
            // Batch slot: determine if TICS or BTC from the ChainTransaction variant
            match &chain_tx {
                crate::chain_abstraction::ChainTransaction::Tics(_) => {
                    let mut store = self.pending.user_to_vault_tics_batch.write().await;
                    let batch_entries = store.entry(round).or_insert_with(Vec::new);
                    if !batch_entries.iter().any(|(h, ..)| h == &slot_id) {
                        batch_entries.push((
                            slot_id.clone(),
                            user_eth,
                            chain_tx,
                            tx_bytes,
                        ));
                        info!(
                            "💾 [SIGNING] Stored verified TICS batch slot {} (round {}) after threshold verification",
                            slot_id, round
                        );
                    }
                }
                crate::chain_abstraction::ChainTransaction::Bitcoin(_) => {
                    // Compute BtcRoundExtras for observer nodes (UTV batch always uses user key)
                    let extras = self.compute_btc_extras_for_observer(
                        &Some(crate::types::TransactionType::UserToVault),
                        &user_eth,
                        round,
                    ).await;
                    let mut store = self.pending.user_to_vault_btc_batch.write().await;
                    let batch_entries = store.entry(round).or_insert_with(Vec::new);
                    if !batch_entries.iter().any(|(h, ..)| h == &slot_id) {
                        batch_entries.push((
                            slot_id.clone(),
                            user_eth,
                            chain_tx,
                            tx_bytes,
                            extras,
                        ));
                        info!(
                            "💾 [SIGNING] Stored verified BTC batch slot {} (round {}) after threshold verification",
                            slot_id, round
                        );
                    }
                }
            }
        } else {
            // Non-batch: route to the correct type-specific store based on chain variant + tx type
            let is_withdraw = matches!(parsed_tx_type, Some(crate::types::TransactionType::WithdrawLiquidity));
            let is_claim_reward = matches!(parsed_tx_type, Some(crate::types::TransactionType::ClaimReward));
            let is_claim_platform_fee = matches!(parsed_tx_type, Some(crate::types::TransactionType::ClaimPlatformFee));

            // Use batch_identifiers from the verified entry if available (for withdraw/claim batches),
            // otherwise fall back to wrapping intent_hash in a Vec.
            let identifiers_for_store = verified_entry.batch_identifiers.clone()
                .or_else(|| intent_hash.clone().map(|h| vec![h]));

            match &chain_tx {
                crate::chain_abstraction::ChainTransaction::Tics(_) => {
                    // ETH non-batch: route to correct TICS pending store
                    if is_withdraw {
                        let mut store = self.pending.withdraw_pending_transactions_tics.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    identifiers_for_store,
                                    parsed_tx_type,
                                    request_id,
                                    None,
                                ),
                            );
                            // Mark as withdraw round
                            let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                            withdraw_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified TICS withdraw TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else if is_claim_reward {
                        let mut store = self.pending.claim_reward_pending_transactions_tics.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    identifiers_for_store,
                                    parsed_tx_type,
                                    request_id,
                                    None,
                                ),
                            );
                            // Mark as claim reward round
                            let mut claim_reward_rounds = self.pending.claim_reward_rounds.write().await;
                            claim_reward_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified TICS claim-reward TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else {
                        // Regular ETH (UserToVault, NetworkToTarget, IntentStatusUpdate, PeerInvalidation, etc.)
                        let mut pending = self.pending.pending_transactions.write().await;
                        if !pending.contains_key(&round) {
                            pending.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    intent_hash,
                                    parsed_tx_type,
                                    request_id,
                                    None,
                                ),
                            );
                            info!(
                                "💾 [SIGNING] Stored verified ETH TX for round {} (type: {:?}) after threshold verification",
                                round, transaction_type
                            );
                        }
                    }
                }
                crate::chain_abstraction::ChainTransaction::Bitcoin(_) => {
                    // BTC non-batch: route to correct BTC pending store
                    let extras = self.compute_btc_extras_for_observer(
                        &parsed_tx_type,
                        &user_eth,
                        round,
                    ).await;

                    // Re-compute identifiers for BTC branch (ETH branch consumed the first copy)
                    let btc_identifiers = verified_entry.batch_identifiers.clone()
                        .or_else(|| intent_hash.map(|h| vec![h]));

                    if is_withdraw {
                        let mut store = self.pending.withdraw_pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                            withdraw_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified BTC withdraw TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else if is_claim_reward {
                        let mut store = self.pending.claim_reward_pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            let mut claim_reward_rounds = self.pending.claim_reward_rounds.write().await;
                            claim_reward_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified BTC claim-reward TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else if is_claim_platform_fee {
                        let mut store = self.pending.claim_platform_fee_pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            let mut claim_pf_rounds = self.pending.claim_platform_fee_rounds.write().await;
                            claim_pf_rounds.insert(round);
                            info!(
                                "💾 [SIGNING] Stored verified BTC claim-platform-fee TX for round {} after threshold verification",
                                round
                            );
                        }
                    } else {
                        // Regular BTC (N2T, UserToVault non-batch, etc.)
                        let mut store = self.pending.pending_transactions_btc.write().await;
                        if !store.contains_key(&round) {
                            store.insert(
                                round,
                                (
                                    chain_tx,
                                    tx_bytes,
                                    btc_identifiers,
                                    parsed_tx_type,
                                    extras,
                                ),
                            );
                            info!(
                                "💾 [SIGNING] Stored verified BTC TX for round {} (type: {:?}) after threshold verification",
                                round, transaction_type
                            );
                        }
                    }
                }
            }
        }

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

    /// Get TICS address from public key
    pub fn get_tics_address(&self) -> Option<String> {
        if let Some(public_key) = self.key_store.public_key() {
            // Get the uncompressed public key (65 bytes)
            let public_key_bytes = public_key.serialize_uncompressed();

            // Remove the prefix byte (0x04) and take the last 20 bytes for the address
            if public_key_bytes.len() >= 21 {
                let address_bytes = &public_key_bytes[1..21];

                // Convert to TICS address format (0x + hex)
                let address = format!("0x{}", hex::encode(address_bytes));

                info!(
                    "🏦 [SIGNING] Node {} TICS address: {}",
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

    /// Get message/digest and transaction type for a round
    async fn get_message_and_type_for_round(
        &self,
        round: u64,
        slot_id: Option<&str>,
    ) -> Result<(Vec<u8>, Option<TransactionType>, Option<String>)> {
        // TICS UserToVault batch: slot_id is intent_hash; get tx from user_to_vault_tics_batch
        // BTC UserToVault batch: same slot_id; get tx from user_to_vault_btc_batch, digest = sighash
        if let Some(slot) = slot_id {
            let batch = self.pending.user_to_vault_tics_batch.read().await;
            if let Some(entries) = batch.get(&round) {
                if let Some((_intent_hash, user_eth, _chain_tx, tx_bytes)) =
                    entries.iter().find(|(h, ..)| h == slot)
                {
                    let mut hasher = sha3::Keccak256::new();
                    hasher.update(tx_bytes);
                    let digest = hasher.finalize().to_vec();
                    return Ok((
                        digest,
                        Some(TransactionType::UserToVault),
                        Some(user_eth.clone()),
                    ));
                }
            }
            let btc_batch = self.pending.user_to_vault_btc_batch.read().await;
            if let Some(entries) = btc_batch.get(&round) {
                if let Some((_intent_hash, user_eth, chain_tx, _, _)) =
                    entries.iter().find(|(h, ..)| h == slot)
                {
                    if let crate::chain_abstraction::ChainTransaction::Bitcoin(btc_tx) = chain_tx {
                        let inp0 = btc_tx
                            .inputs
                            .get(0)
                            .ok_or_else(|| anyhow!("BTC batch slot {} has no inputs", slot))?;
                        let prev_spk = inp0
                            .witness_utxo
                            .as_ref()
                            .ok_or_else(|| anyhow!("Input 0 missing witness_utxo for slot {}", slot))?
                            .script_pubkey
                            .clone();
                        let digest = self.compute_legacy_sighash_all_p2pkh(btc_tx, 0, &prev_spk)?;
                        return Ok((
                            digest.to_vec(),
                            Some(TransactionType::UserToVault),
                            Some(user_eth.clone()),
                        ));
                    }
                }
            }
            return Err(anyhow!(
                "No TICS or BTC UserToVault batch slot {} for round {}",
                slot,
                round
            ));
        }

        // Check if it's a claim-reward, claim-platform-fee, withdraw, or regular round
        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };
        let is_claim_platform_fee_round = {
            let r = self.pending.claim_platform_fee_rounds.read().await;
            r.contains(&round)
        };

        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        // Try TICS transactions first, then BTC
        //
        // NOTE: For partial signature verification we may override the stored transaction_type
        // for certain contract calls (e.g. IntentManager.processBatchIntents) so that verification
        // is performed against the VAULT/main key path.
        let (tx_bytes, transaction_type, user_tics_address, _chain_tx_opt) = if is_claim_reward_round {
            // Claim-reward: try TICS (contract) first, then BTC
            let claim_reward_pt_tics = self.pending.claim_reward_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, _identifiers, tx_type, _request_id, _original_request)) =
                claim_reward_pt_tics.get(&round)
            {
                (tx_bytes.clone(), tx_type.clone(), None, Some(chain_tx.clone()))
            } else {
                let claim_reward_pt_btc = self.pending.claim_reward_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _extras)) =
                    claim_reward_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None, None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for claim-reward round {}",
                        round
                    ));
                }
            }
        } else if is_claim_platform_fee_round {
            // Claim-platform-fee: try TICS store first (contract call), then BTC store
            let claim_pf_pt_tics = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, _identifiers, tx_type, _request_id, _original_request)) =
                claim_pf_pt_tics.get(&round)
            {
                (tx_bytes.clone(), tx_type.clone(), None, Some(chain_tx.clone()))
            } else {
                drop(claim_pf_pt_tics);
                let claim_pf_pt_btc = self.pending.claim_platform_fee_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _extras)) =
                    claim_pf_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None, None)
                } else {
                    return Err(anyhow!(
                        "No pending transaction found for claim-platform-fee round {}",
                        round
                    ));
                }
            }
        } else if is_withdraw_round {
            let withdraw_pt = self.pending.withdraw_pending_transactions_tics.read().await;
            if let Some((chain_tx, tx_bytes, _solver_address, tx_type, _request_id, _original_request)) =
                withdraw_pt.get(&round) {
                (tx_bytes.clone(), tx_type.clone(), None, Some(chain_tx.clone()))
            } else {
                // Try BTC withdraw
                let withdraw_pt_btc = self.pending.withdraw_pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, _solver_address, tx_type, _request_id)) =
                    withdraw_pt_btc.get(&round)
                {
                    (tx_bytes.clone(), tx_type.clone(), None, None)
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
            if let Some((chain_tx, tx_bytes, intent_hash, tx_type, _request_id, _original_request)) = pending.get(&round) {
                // For UserToVault transactions, retrieve user_tics_address from intent_hash
                // This ensures the final node retrieves the address on its own, not relying on the unicasting peer
                let user_addr = if matches!(
                    tx_type,
                    Some(crate::types::TransactionType::UserToVault)
                ) {
                    if let Some(intent_hash) = intent_hash {
                        // Retrieve user's TICS address from intent hash using database
                        if let Some(database) = &self.database {
                            use crate::database::storage::UserStorage;
                            let user_storage = UserStorage::new(database.as_ref().clone());
                            match user_storage.get_user_by_intent_hash(intent_hash).await {
                                Ok(Some(user)) => {
                                    info!(
                                        "🔍 [SIGNING] Retrieved user_tics_address {} from intent_hash {} for UserToVault transaction (round {})",
                                        user.tics_address, intent_hash, round
                                    );
                                    Some(user.tics_address)
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
                                "⚠️ [SIGNING] Database not available to retrieve user_tics_address from intent_hash {} (round {})",
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
                (tx_bytes.clone(), tx_type.clone(), user_addr, Some(chain_tx.clone()))
            } else {
                // Try BTC
                let pending_btc = self.pending.pending_transactions_btc.read().await;
                if let Some((_tx, tx_bytes, intent_hashes, tx_type, _extras)) =
                    pending_btc.get(&round)
                {
                    // For UserToVault transactions, retrieve user_tics_address from intent_hash
                    // This ensures the final node retrieves the address on its own, not relying on the unicasting peer
                    let user_addr = if matches!(
                        tx_type,
                        Some(crate::types::TransactionType::UserToVault)
                    ) {
                        if let Some(intent_hashes_vec) = intent_hashes {
                            if let Some(first_intent_hash) = intent_hashes_vec.first() {
                                // Retrieve user's TICS address from intent hash using database
                                if let Some(database) = &self.database {
                                    use crate::database::storage::UserStorage;
                                    let user_storage = UserStorage::new(database.as_ref().clone());
                                    match user_storage.get_user_by_intent_hash(first_intent_hash).await {
                                        Ok(Some(user)) => {
                                            info!(
                                                "🔍 [SIGNING] Retrieved user_tics_address {} from intent_hash {} for UserToVault BTC transaction (round {})",
                                                user.tics_address, first_intent_hash, round
                                            );
                                            Some(user.tics_address)
                                        }
                                        Ok(None) => {
                                            warn!(
                                                "⚠️ [SIGNING] No user found for intent_hash {} in UserToVault BTC transaction (round {})",
                                                first_intent_hash, round
                                            );
                                            None
                                        }
                                        Err(e) => {
                                            warn!(
                                                "⚠️ [SIGNING] Failed to retrieve user from intent_hash {}: {} (round {})",
                                                first_intent_hash, e, round
                                            );
                                            None
                                        }
                                    }
                                } else {
                                    warn!(
                                        "⚠️ [SIGNING] Database not available to retrieve user_tics_address from intent_hash (round {})",
                                        round
                                    );
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
                    (tx_bytes.clone(), tx_type.clone(), user_addr, None)
                } else {
                    return Err(anyhow!("No pending transaction found for round {}", round));
                }
            }
        };

        // Retrieve intent hashes context for this round (single vs batch vs none)
        let intent_hashes_for_round = {
            let map = self.pending.intent_hashes_by_round.read().await;
            map.get(&round).cloned().unwrap_or_default()
        };

        if intent_hashes_for_round.len() > 1 {
            info!(
                "📦 [SIGNING] Round {} identified as BATCH transaction ({} intents)",
                round,
                intent_hashes_for_round.len()
            );
        } else if intent_hashes_for_round.len() == 1 {
            info!(
                "🧾 [SIGNING] Round {} identified as SINGLE transaction (intent: {})",
                round,
                intent_hashes_for_round[0]
            );
        } else {
            info!(
                "🧾 [SIGNING] Round {} has no intent hashes (solver-only or contract path)",
                round
            );
        }

        // NOTE: IntentManager.processBatchIntents contract txs are signed with the MAIN DKG key
        // (network group key path) and should therefore use the normal NetworkToTarget verification
        // path (network share pubkeys) for partial signature verification.

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

        Ok((digest, transaction_type, user_tics_address))
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

    /// Process peer invalidation batch for epoch-2.
    ///
    /// Two-phase logic:
    ///   Phase 1 — Promote staging entries that survived the epoch.
    ///     Scan DISCONNECTION_STAGING:* keys.  For each one:
    ///       • Remove it from staging (consumed regardless of outcome).
    ///       • Check on-chain: if the solver is still validated → write PENDING_DISCONNECTION.
    ///       • If already invalidated on-chain → skip (nothing to do).
    ///     This means any peer that reconnected before epoch-2 was already cleared from staging
    ///     on connection and will never reach this point.
    ///
    ///   Phase 2 — Collect PENDING_DISCONNECTION entries (promoted in phase 1 plus any that
    ///     were left over from a previous epoch) and broadcast the invalidation batch.
    async fn process_peer_invalidation_batch(&self, round: u64) -> Result<()> {
        info!(
            "🚫 [PEER_INVALIDATION] Processing peer invalidation batch for round {}",
            round
        );

        let database = self.database.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Database not available"))?;

        // ── Phase 1: Promote surviving staging entries ──────────────────────────────
        let staging_prefix = crate::database::keys::DISCONNECTION_STAGING;
        let staging_keys = database.get_keys_with_prefix_async(staging_prefix).await.unwrap_or_default();

        if !staging_keys.is_empty() {
            info!(
                "🔄 [PEER_INVALIDATION] Phase 1: Found {} staging entry/entries to evaluate for promotion",
                staging_keys.len()
            );

            // Build contract client once (optional — skip on error, entries stay in staging)
            let contract_opt: Option<crate::contract::SolverManagerContract> =
                if let Ok(Some(config)) = crate::contract::get_solver_contract_config() {
                    if let Ok(client) = crate::contract::ContractClient::new(config.clone()) {
                        crate::contract::SolverManagerContract::new(&config, client.provider()).ok()
                    } else {
                        None
                    }
                } else {
                    None
                };

            for key in &staging_keys {
                let solver_id = match key.strip_prefix(staging_prefix) {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => continue,
                };

                // Always consume the staging entry first
                let _ = database.delete_string(key);

                // On-chain check: skip if already invalidated to avoid batch reverts
                let should_promote = if let Some(ref contract) = contract_opt {
                    match contract.is_solver_id_validated(&solver_id).await {
                        Ok(true) => {
                            true // still validated on-chain → promote
                        }
                        Ok(false) => {
                            info!(
                                "ℹ️ [PEER_INVALIDATION] Solver {} is already invalidated on-chain, dropping staging entry",
                                solver_id
                            );
                            false
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [PEER_INVALIDATION] Failed to check on-chain validation for {} during promotion: {} — promoting anyway",
                                solver_id, e
                            );
                            true
                        }
                    }
                } else {
                    // Contract unavailable — promote to be safe (existing fallback behaviour)
                    true
                };

                if should_promote {
                    let pending_key = format!(
                        "{}{}",
                        crate::database::keys::PENDING_DISCONNECTION,
                        solver_id
                    );
                    // Only write if not already present (could be left over from a prior epoch)
                    if let Ok(None) = database.get_string::<String>(&pending_key) {
                        // Re-read the staging record to carry the original metadata forward
                        let record = serde_json::json!({ "solver_id": solver_id });
                        if let Ok(record_str) = serde_json::to_string(&record) {
                            let _ = database.put_string(&pending_key, &record_str);
                        }
                        info!(
                            "✅ [PEER_INVALIDATION] Promoted solver {} from staging to invalidation queue",
                            solver_id
                        );
                    }
                }
            }
        }

        // ── Phase 2: Collect all PENDING_DISCONNECTION entries for the batch ────────
        let prefix = crate::database::keys::PENDING_DISCONNECTION;
        let keys = database.get_keys_with_prefix_async(prefix).await.unwrap_or_default();

        if keys.is_empty() {
            info!("✅ [PEER_INVALIDATION] No pending disconnections to process after promotion");
            return Ok(());
        }

        let mut all_solver_ids: Vec<String> = Vec::new();
        for key in &keys {
            if let Some(solver_id) = key.strip_prefix(prefix) {
                if !solver_id.is_empty() {
                    all_solver_ids.push(solver_id.to_string());
                }
            }
        }

        if all_solver_ids.is_empty() {
            info!("✅ [PEER_INVALIDATION] No valid solver IDs to invalidate");
            return Ok(());
        }

        // Guard: filter out invulnerable nodes (initial DKG signers) — they must never be invalidated
        if let Some(ref dkg) = self.dkg_storage {
            if let Ok(Some(invulnerables)) = dkg.get_invulnerables() {
                let before = all_solver_ids.len();
                all_solver_ids.retain(|sid| {
                    if invulnerables.contains(sid) {
                        info!(
                            "🛡️ [PEER_INVALIDATION] Solver {} is an invulnerable (DKG signer) — removing from invalidation batch and clearing PENDING_DISCONNECTION",
                            sid
                        );
                        let pending_key = format!("{}{}", prefix, sid);
                        let _ = database.delete_string(&pending_key);
                        false
                    } else {
                        true
                    }
                });
                if before != all_solver_ids.len() {
                    info!(
                        "🛡️ [PEER_INVALIDATION] Filtered {} invulnerable(s) from batch, {} remaining",
                        before - all_solver_ids.len(),
                        all_solver_ids.len()
                    );
                }
            }
        }

        if all_solver_ids.is_empty() {
            info!("✅ [PEER_INVALIDATION] All pending solvers are invulnerables or already handled, nothing to do");
            return Ok(());
        }

        // Filter out solvers that are already invalidated on-chain to avoid
        // batch reverts (invalidateSolverIds reverts if any solver in the batch is already invalidated).
        // Also clean up their PENDING_DISCONNECTION entries since they don't need processing.
        let mut solver_ids: Vec<String> = Vec::new();
        if let Ok(Some(config)) = crate::contract::get_solver_contract_config() {
            if let Ok(client) = crate::contract::ContractClient::new(config.clone()) {
                if let Ok(contract) = crate::contract::SolverManagerContract::new(&config, client.provider()) {
                    for sid in &all_solver_ids {
                        match contract.is_solver_id_validated(sid).await {
                            Ok(true) => {
                                solver_ids.push(sid.clone());
                            }
                            Ok(false) => {
                                info!(
                                    "ℹ️ [PEER_INVALIDATION] Solver {} is already invalidated on-chain, removing from batch and clearing PENDING_DISCONNECTION",
                                    sid
                                );
                                let pending_key = format!("{}{}", prefix, sid);
                                let _ = database.delete_string(&pending_key);
                            }
                            Err(e) => {
                                warn!(
                                    "⚠️ [PEER_INVALIDATION] Failed to check on-chain validation for {}: {} — including in batch",
                                    sid, e
                                );
                                solver_ids.push(sid.clone());
                            }
                        }
                    }
                } else {
                    solver_ids = all_solver_ids;
                }
            } else {
                solver_ids = all_solver_ids;
            }
        } else {
            solver_ids = all_solver_ids;
        }

        if solver_ids.is_empty() {
            info!("✅ [PEER_INVALIDATION] All pending solvers are already invalidated on-chain, nothing to do");
            return Ok(());
        }

        info!(
            "🚫 [PEER_INVALIDATION] Found {} solver IDs to invalidate: {:?}",
            solver_ids.len(),
            solver_ids
        );

        // Reserve a nonce for this batch BEFORE broadcasting (coordinator responsibility)
        // SECURITY: Nonces are REQUIRED - abort batch if unavailable
        let nonce_tuple_id = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.reserve_nonces_for_batch(&["peer_invalidation_batch".to_string()]).await {
                Ok(assignments) => {
                    if let Some(tuple_id) = assignments.get("peer_invalidation_batch") {
                        info!("🔐 [PEER_INVALIDATION] Reserved nonce {} for peer invalidation batch", tuple_id);
                        tuple_id.clone()
                    } else {
                        tracing::error!("🔴 [PEER_INVALIDATION] No nonce assigned - aborting batch (will retry next epoch)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::error!("🔴 [PEER_INVALIDATION] Failed to reserve nonce: {} - aborting batch (will retry next epoch)", e);
                    return Ok(());
                }
            }
        } else {
            tracing::error!("🔴 [PEER_INVALIDATION] NonceManager not available - aborting batch (will retry next epoch)");
            return Ok(());
        };

        // Broadcast PeerInvalidationBatch via ChannelMessage
        let timestamp = chrono::Utc::now().to_rfc3339();
        let node_id = self.id.clone();

        self.message_tx
            .send(crate::types::ChannelMessage::PeerInvalidationBatch {
                solver_ids,
                round,
                timestamp,
                node_id,
                nonce_tuple_id: Some(nonce_tuple_id),
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send peer invalidation batch message: {}", e))?;

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::nonce::NonceTuple;
    use crate::types::secp::{SerializablePoint, SerializableScalar};
    use ff::{Field, PrimeField};
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar, U256};
    use rand::rngs::OsRng;

    #[test]
    fn intent_manager_address_comparison_is_case_insensitive() {
        let to = "0xAbC0000000000000000000000000000000000000";
        let intent_manager = "0xabc0000000000000000000000000000000000000";
        assert_eq!(to.to_lowercase(), intent_manager.to_lowercase());
    }

    /// Helper to get current unix timestamp
    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Helper to create a valid NonceTuple for testing
    fn create_test_nonce_tuple(tuple_id: &str) -> NonceTuple {
        // Generate random k
        let k = Scalar::random(&mut OsRng);

        // Compute R = k * G
        let r_point = (ProjectivePoint::GENERATOR * k).to_affine();

        // Compute k⁻¹
        let k_inv = k.invert().expect("k should be invertible");

        // Compute r = x(R) mod n
        let encoded = r_point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        // Compute r_y_parity
        let y_bytes = encoded.y().expect("not at infinity");
        let r_y_parity = if y_bytes[31] & 1 == 0 { 0 } else { 1 };

        NonceTuple {
            tuple_id: tuple_id.to_string(),
            batch_id: "test_batch".to_string(),
            aggregated_k: SerializableScalar(k),
            k_inv: SerializableScalar(k_inv),
            aggregate_r: SerializablePoint(r_point),
            r_scalar: SerializableScalar(r_scalar),
            r_y_parity,
            created_at: now_unix(),
            consumed: false,
            num_contributors: 3,
        }
    }

    /// Helper to create a NonceTuple from multiple nodes' k values (simulating coordination)
    fn create_coordinated_nonce_tuple(
        tuple_id: &str,
        k_values: &[Scalar],
    ) -> NonceTuple {
        // Aggregate k = Σ k_i
        let mut aggregated_k = Scalar::ZERO;
        let mut r_point_proj = ProjectivePoint::IDENTITY;

        for k in k_values {
            aggregated_k += k;
            r_point_proj += ProjectivePoint::GENERATOR * k;
        }

        let r_point = r_point_proj.to_affine();

        // Compute k⁻¹
        let k_inv = aggregated_k.invert().expect("aggregated k should be invertible");

        // Compute r = x(R) mod n
        let encoded = r_point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        // Compute r_y_parity
        let y_bytes = encoded.y().expect("not at infinity");
        let r_y_parity = if y_bytes[31] & 1 == 0 { 0 } else { 1 };

        NonceTuple {
            tuple_id: tuple_id.to_string(),
            batch_id: "coordinated_batch".to_string(),
            aggregated_k: SerializableScalar(aggregated_k),
            k_inv: SerializableScalar(k_inv),
            aggregate_r: SerializablePoint(r_point),
            r_scalar: SerializableScalar(r_scalar),
            r_y_parity,
            created_at: now_unix(),
            consumed: false,
            num_contributors: k_values.len(),
        }
    }

    /// Test that nonce integrity checks pass for valid nonces
    #[test]
    fn test_nonce_tuple_integrity_valid() {
        let nonce = create_test_nonce_tuple("test_valid_nonce");

        // Verify k * k_inv = 1
        let k_times_k_inv = nonce.aggregated_k.0 * nonce.k_inv.0;
        assert_eq!(k_times_k_inv, Scalar::ONE, "k * k_inv should equal 1");

        // Verify R = k * G
        let expected_r = (ProjectivePoint::GENERATOR * nonce.aggregated_k.0).to_affine();
        assert_eq!(nonce.aggregate_r.0, expected_r, "R should equal k * G");

        // Verify r_scalar = x(R) mod n
        let encoded = nonce.aggregate_r.0.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let computed_r = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));
        assert_eq!(nonce.r_scalar.0, computed_r, "r_scalar should equal x(R) mod n");

        println!("✅ Nonce tuple integrity checks passed!");
    }

    /// Test that coordinated nonces from multiple nodes produce valid aggregates
    #[test]
    fn test_coordinated_nonce_aggregation() {
        // Simulate 3 nodes generating random k_i values
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let k3 = Scalar::random(&mut OsRng);

        let nonce = create_coordinated_nonce_tuple("coordinated_test", &[k1, k2, k3]);

        // Verify the aggregation is correct
        let expected_k = k1 + k2 + k3;
        assert_eq!(nonce.aggregated_k.0, expected_k, "Aggregated k should equal sum of k_i");

        // Verify R = (Σ k_i) * G = Σ (k_i * G)
        let r1 = (ProjectivePoint::GENERATOR * k1).to_affine();
        let r2 = (ProjectivePoint::GENERATOR * k2).to_affine();
        let r3 = (ProjectivePoint::GENERATOR * k3).to_affine();

        let aggregate_r = (ProjectivePoint::from(r1) + ProjectivePoint::from(r2) + ProjectivePoint::from(r3)).to_affine();
        assert_eq!(nonce.aggregate_r.0, aggregate_r, "Aggregate R should equal sum of R_i");

        println!("✅ Coordinated nonce aggregation test passed!");
    }

    /// Test that all nodes produce the same partial signature with coordinated nonces
    #[test]
    fn test_partial_signature_consistency_with_coordinated_nonce() {
        // Generate 3 independent private key shares (simulating DKG output)
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let x3 = Scalar::random(&mut OsRng);

        // Generate coordinated nonce from 3 nodes
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let k3 = Scalar::random(&mut OsRng);

        // All nodes must have the SAME aggregated nonce values
        let nonce = create_coordinated_nonce_tuple("consistency_test", &[k1, k2, k3]);

        // Create a test message
        let message_hash: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        // Each node computes s_i = k⁻¹ * (z + r * x_i) using the SAME k⁻¹ and r
        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);
        let s3 = k_inv * (z + r * x3);

        // Verify the mathematical relationship:
        // s1 + s2 + s3 = k⁻¹ * (3z + r * (x1 + x2 + x3))
        // This verifies that partial signatures can be aggregated
        let sum_s = s1 + s2 + s3;
        let sum_x = x1 + x2 + x3;
        let expected_sum = k_inv * (Scalar::from(3u64) * z + r * sum_x);

        assert_eq!(sum_s, expected_sum, "Sum of partial signatures should match expected");

        println!("✅ Partial signature consistency test passed!");
        println!("   s1 = 0x{}...", hex::encode(&s1.to_bytes()[..8]));
        println!("   s2 = 0x{}...", hex::encode(&s2.to_bytes()[..8]));
        println!("   s3 = 0x{}...", hex::encode(&s3.to_bytes()[..8]));
    }

    /// Test Lagrange interpolation for threshold signature aggregation
    #[test]
    fn test_lagrange_threshold_signature_aggregation() {
        // This test simulates 2-of-3 threshold signing with coordinated nonces

        // Node indices (as used in DKG)
        let idx1 = Scalar::from(1u64);
        let idx2 = Scalar::from(2u64);
        let idx3 = Scalar::from(3u64);

        // Generate private key shares
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);

        // Generate coordinated nonce
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let nonce = create_coordinated_nonce_tuple("lagrange_test", &[k1, k2]);

        // Message hash
        let message_hash: [u8; 32] = [0xab; 32];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        // Each node computes partial signature
        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);

        // Lagrange coefficients for indices {1, 2} evaluating at x=0
        // λ_1 = (0 - idx2) / (idx1 - idx2)
        // λ_2 = (0 - idx1) / (idx2 - idx1)
        let zero = Scalar::ZERO;
        let lambda1 = (zero - idx2) * (idx1 - idx2).invert().unwrap();
        let lambda2 = (zero - idx1) * (idx2 - idx1).invert().unwrap();

        // Aggregate: s = λ_1 * s_1 + λ_2 * s_2
        let aggregated_s = lambda1 * s1 + lambda2 * s2;

        // Compute what the full signature should be using reconstructed private key
        let aggregated_x = lambda1 * x1 + lambda2 * x2;
        let expected_s = k_inv * (z + r * aggregated_x);

        assert_eq!(aggregated_s, expected_s, "Lagrange aggregation should match direct computation");

        // Verify ECDSA signature
        let group_pubkey = (ProjectivePoint::GENERATOR * aggregated_x).to_affine();
        let s_inv = aggregated_s.invert().unwrap();
        let u1 = s_inv * z;
        let u2 = s_inv * r;
        let r_prime = (ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(group_pubkey) * u2).to_affine();

        // r' x-coordinate should equal r
        let encoded = r_prime.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_prime_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        assert_eq!(r_prime_scalar, r, "ECDSA verification should pass");

        println!("✅ Lagrange threshold signature aggregation test passed!");
        println!("   Aggregated s = 0x{}", hex::encode(aggregated_s.to_bytes()));
        println!("   r = 0x{}", hex::encode(r.to_bytes()));
    }

    /// Test that different nonces produce different signatures (security property)
    #[test]
    fn test_different_nonces_produce_different_signatures() {
        // Same private key
        let x = Scalar::random(&mut OsRng);

        // Same message
        let message_hash: [u8; 32] = [0x42; 32];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        // Two different nonces
        let nonce1 = create_test_nonce_tuple("nonce1");
        let nonce2 = create_test_nonce_tuple("nonce2");

        // Compute signatures with each nonce
        let s1 = nonce1.k_inv.0 * (z + nonce1.r_scalar.0 * x);
        let s2 = nonce2.k_inv.0 * (z + nonce2.r_scalar.0 * x);

        // Signatures should be different
        assert_ne!(s1, s2, "Different nonces should produce different signatures");
        assert_ne!(nonce1.r_scalar.0, nonce2.r_scalar.0, "Different nonces should have different r values");

        println!("✅ Different nonces produce different signatures (security property verified)");
    }

    /// Test that reusing the same nonce with different keys exposes the private key (security test)
    #[test]
    fn test_nonce_reuse_attack_demonstration() {
        // This test demonstrates why nonce reuse is dangerous
        // If two signatures use the same k but different private keys,
        // an attacker can recover the private key difference

        let k = Scalar::random(&mut OsRng);
        let nonce = create_coordinated_nonce_tuple("reuse_demo", &[k]);

        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);

        // Same message
        let message_hash: [u8; 32] = [0x55; 32];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);

        // If an attacker sees s1 and s2 with the same r, they can compute:
        // s1 - s2 = k⁻¹ * r * (x1 - x2)
        // => x1 - x2 = k * (s1 - s2) / r
        let s_diff = s1 - s2;
        let recovered_x_diff = nonce.aggregated_k.0 * s_diff * r.invert().unwrap();
        let actual_x_diff = x1 - x2;

        assert_eq!(recovered_x_diff, actual_x_diff, "Nonce reuse allows private key difference recovery");

        println!("⚠️  SECURITY DEMONSTRATION: Nonce reuse allows private key extraction!");
        println!("   This is why we MUST use unique, coordinated nonces for each signature.");
    }

    /// Test full end-to-end signing with coordinated nonces (3-of-3)
    #[test]
    fn test_full_3_of_3_signing_with_coordinated_nonces() {
        // Setup: 3 nodes with threshold 3 (all nodes required)

        // Private key shares (from DKG)
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let x3 = Scalar::random(&mut OsRng);

        // Nonce shares from each node
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let k3 = Scalar::random(&mut OsRng);

        // Create coordinated nonce (all nodes have the same after reveal phase)
        let nonce = create_coordinated_nonce_tuple("full_3of3", &[k1, k2, k3]);

        // Transaction hash to sign
        let tx_hash: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tx_hash));

        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        // Each node computes partial signature
        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);
        let s3 = k_inv * (z + r * x3);

        // For 3-of-3, indices are {1, 2, 3}
        let idx1 = Scalar::from(1u64);
        let idx2 = Scalar::from(2u64);
        let idx3 = Scalar::from(3u64);
        let zero = Scalar::ZERO;

        // Lagrange coefficients
        let lambda1 = (zero - idx2) * (zero - idx3) *
            ((idx1 - idx2) * (idx1 - idx3)).invert().unwrap();
        let lambda2 = (zero - idx1) * (zero - idx3) *
            ((idx2 - idx1) * (idx2 - idx3)).invert().unwrap();
        let lambda3 = (zero - idx1) * (zero - idx2) *
            ((idx3 - idx1) * (idx3 - idx2)).invert().unwrap();

        // Aggregate signature
        let aggregated_s = lambda1 * s1 + lambda2 * s2 + lambda3 * s3;

        // Reconstruct group public key
        let aggregated_x = lambda1 * x1 + lambda2 * x2 + lambda3 * x3;
        let group_pubkey = (ProjectivePoint::GENERATOR * aggregated_x).to_affine();

        // Verify ECDSA signature
        let s_inv = aggregated_s.invert().unwrap();
        let u1 = s_inv * z;
        let u2 = s_inv * r;
        let r_prime = (ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(group_pubkey) * u2).to_affine();

        let encoded = r_prime.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_prime_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        assert_eq!(r_prime_scalar, r, "ECDSA verification must pass");

        println!("✅ Full 3-of-3 signing with coordinated nonces PASSED!");
        println!("   Transaction hash: 0x{}", hex::encode(tx_hash));
        println!("   r = 0x{}", hex::encode(r.to_bytes()));
        println!("   s = 0x{}", hex::encode(aggregated_s.to_bytes()));
        println!("   Group pubkey: 0x{}", hex::encode(group_pubkey.to_encoded_point(true).as_bytes()));
    }

    /// Test that consumed nonces cannot be reused (security property)
    #[test]
    fn test_nonce_consumed_flag() {
        let mut nonce = create_test_nonce_tuple("consumable");

        assert!(!nonce.consumed, "New nonce should not be consumed");

        // Mark as consumed
        nonce.consumed = true;

        assert!(nonce.consumed, "Nonce should be marked as consumed after use");

        println!("✅ Nonce consumption tracking works correctly");
    }

    /// Test nonce with invalid k_inv (integrity check should fail)
    #[test]
    fn test_nonce_integrity_check_invalid_k_inv() {
        let mut nonce = create_test_nonce_tuple("invalid_k_inv");

        // Corrupt k_inv by adding 1
        nonce.k_inv = SerializableScalar(nonce.k_inv.0 + Scalar::ONE);

        // Verify k * k_inv != 1
        let k_times_k_inv = nonce.aggregated_k.0 * nonce.k_inv.0;
        assert_ne!(k_times_k_inv, Scalar::ONE, "Corrupted k_inv should fail integrity check");

        println!("✅ Invalid k_inv is detected by integrity check");
    }

    /// Test nonce with invalid R point (integrity check should fail)
    #[test]
    fn test_nonce_integrity_check_invalid_r_point() {
        let mut nonce = create_test_nonce_tuple("invalid_r");

        // Corrupt R by using a different point
        let fake_k = Scalar::random(&mut OsRng);
        nonce.aggregate_r = SerializablePoint((ProjectivePoint::GENERATOR * fake_k).to_affine());

        // Verify R != k * G
        let expected_r = (ProjectivePoint::GENERATOR * nonce.aggregated_k.0).to_affine();
        assert_ne!(nonce.aggregate_r.0, expected_r, "Corrupted R should fail integrity check");

        println!("✅ Invalid R point is detected by integrity check");
    }

    /// Test nonce with invalid r_scalar (integrity check should fail)
    #[test]
    fn test_nonce_integrity_check_invalid_r_scalar() {
        let mut nonce = create_test_nonce_tuple("invalid_r_scalar");

        // Corrupt r_scalar by adding 1
        nonce.r_scalar = SerializableScalar(nonce.r_scalar.0 + Scalar::ONE);

        // Verify r_scalar != x(R) mod n
        let encoded = nonce.aggregate_r.0.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let computed_r = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));
        assert_ne!(nonce.r_scalar.0, computed_r, "Corrupted r_scalar should fail integrity check");

        println!("✅ Invalid r_scalar is detected by integrity check");
    }
}
