use crate::rpc_server::DummyTransaction;
use anyhow::anyhow;
use anyhow::Result;
use bls12_381::Scalar;
use ethereum_types::U64;
use hex;
use libp2p::PeerId;
use num_bigint::BigUint;
use num_traits::identities::One;
use rand::rngs::OsRng;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use num_bigint::{BigInt, ToBigInt};
use secp256k1::{constants::CURVE_ORDER, ecdsa::RecoveryId};

use num_traits::Zero;

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage};
use crate::vrf::VrfNodeSelector;

#[derive(Debug, Clone)]
pub struct SecretKeyShare {
    pub secret_key: SecretKey, // The secret key directly
    pub signer_id: String,
    pub threshold: u32,
    pub total_shares: u32,
}

impl Serialize for SecretKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecretKeyShare", 4)?;
        state.serialize_field("secret_key", &hex::encode(self.secret_key.secret_bytes()))?;
        state.serialize_field("signer_id", &self.signer_id)?;
        state.serialize_field("threshold", &self.threshold)?;
        state.serialize_field("total_shares", &self.total_shares)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SecretKeyShareHelper {
            secret_key: String,
            signer_id: String,
            threshold: u32,
            total_shares: u32,
        }

        let helper = SecretKeyShareHelper::deserialize(deserializer)?;
        let secret_key_bytes = hex::decode(&helper.secret_key)
            .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|e| serde::de::Error::custom(format!("Invalid secret key: {}", e)))?;

        Ok(SecretKeyShare {
            secret_key,
            signer_id: helper.signer_id,
            threshold: helper.threshold,
            total_shares: helper.total_shares,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub aggregated_signature: Vec<u8>, // ECDSA signature
    pub signer_ids: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    MessageToSign {
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    },
    SecretKeyShare {
        from: String,
        secret_key_share: SecretKeyShare,
        timestamp: u128,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
    RequestSecretShares {
        round: u64,
        final_node_id: String,
        message: String,
    },
}

#[derive(Clone)]
pub struct SigningNode {
    id: String,
    threshold: usize,
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    public_keys: Arc<RwLock<HashMap<String, PublicKey>>>, // Other nodes' public keys

    secret_key_shares: Arc<RwLock<HashMap<String, SecretKeyShare>>>, // node_id -> secret_key_share
    secret_key_shares_by_round: Arc<RwLock<HashMap<u64, HashMap<String, SecretKeyShare>>>>, // round -> node_id -> secret_key_share
    final_nodes_by_round: Arc<RwLock<HashMap<u64, String>>>, // round -> final_node_id
    message_tx: mpsc::Sender<ChannelMessage>,
    vrf_selector: Option<VrfNodeSelector>, // VRF selector for node selection
    consensus_node: Option<ConsensusNode>, // Consensus node for final node selection
    available_nodes: Option<Vec<PeerId>>,  // Available nodes from node manager
    curr_round: u64,                       // Current round for signing
    next_round: u64,                       // Next round to be processed
}

impl SigningNode {
    pub fn set_threshold(&mut self, new_threshold: usize) {
        self.threshold = new_threshold;
    }

    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        // Parse the actual PeerId from the string ID
        let peer_id = PeerId::from_str(&id).unwrap_or_else(|_| {
            // Fallback to derived PeerId if parsing fails
            Self::derive_peer_id_from_string(&id)
        });

        Self {
            id,
            threshold,
            private_key: None,
            public_key: None,
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            secret_key_shares: Arc::new(RwLock::new(HashMap::new())),
            secret_key_shares_by_round: Arc::new(RwLock::new(HashMap::new())),
            final_nodes_by_round: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            vrf_selector: Some(VrfNodeSelector::new(peer_id)),
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
            curr_round: 0,
            next_round: 0,
        }
    }

    /// Derive a deterministic PeerId from a string ID
    fn derive_peer_id_from_string(id: &str) -> PeerId {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let hash = hasher.finalize();

        // Create a deterministic keypair from the hash
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash[..32]);

        // Create a deterministic Ed25519 keypair
        let ed_kp = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut key_bytes)
            .unwrap_or_else(|_| libp2p::identity::ed25519::Keypair::generate());
        let kp = libp2p::identity::Keypair::from(ed_kp);

        PeerId::from_public_key(&kp.public())
    }

    pub fn generate_key_pair(&mut self) -> Result<()> {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (private_key, public_key) = secp.generate_keypair(&mut rng);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        info!("🔐 [SIGNING] Node {} generated ECDSA key pair", self.id);
        info!("🔑 [SIGNING] Public key: {:?}", public_key);
        Ok(())
    }

    pub fn set_private_key(&mut self, private_key: SecretKey) {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        info!("🔐 [SIGNING] Node {} private key set", self.id);
    }

    pub fn set_private_key_from_bls_scalar(&mut self, bls_scalar: Scalar) {
        // Convert BLS scalar to secp256k1 secret key using proper field conversion
        let scalar_bytes = bls_scalar.to_bytes();
        let secret_key = Self::derive_secp_secret(&bls_scalar);

        info!(
            "🔐 [SIGNING] Node {} private key set from BLS scalar",
            self.id
        );
        info!("🔐 [SIGNING] BLS scalar bytes: {:?}", scalar_bytes);
        // info!("🔐 [SIGNING] Derived key bytes: {:?}", final_key_bytes);
        info!(
            "🔐 OOKK [SIGNING] Final secret key: {:?}",
            hex::encode(secret_key.as_ref())
        );

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        info!("🔑 [SIGNING] Node {} public key: {:?}", self.id, public_key);

        self.private_key = Some(secret_key);
        self.public_key = Some(public_key);

        info!(
            "🔐 [SIGNING] Node {} private key set from BLS scalar with proper Ethereum conversion",
            self.id
        );
    }

    pub fn derive_secp_secret(bls_scalar: &Scalar) -> SecretKey {
        // 1) Get the 32‑byte LE from BLS
        let mut le = bls_scalar.to_bytes();

        // 2) Reverse to big‑endian so that from_bytes_be() sees the right integer
        le.reverse();

        // 4) Pad or trim to 32 bytes BE
        let mut be32 = [0u8; 32];
        let trimmed = if le.len() > 32 {
            &le[le.len() - 32..]
        } else {
            &le
        };
        be32[32 - trimmed.len()..].copy_from_slice(trimmed);

        // 5) Build the ECDSA SecretKey (expects BE)
        SecretKey::from_slice(&be32).expect("valid secp256k1 scalar")
    }

    pub fn add_public_key(&self, node_id: String, public_key: PublicKey) {
        let node_id_clone = node_id.clone();
        tokio::spawn({
            let public_keys = self.public_keys.clone();
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
        self.private_key.is_some()
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

    pub async fn sign_message(
        &mut self,
        message: Vec<u8>,
        transaction: &DummyTransaction,
    ) -> Result<()> {
        if self.private_key.is_none() {
            error!(
                "❌ [SIGNING] Node {} cannot sign: no private key available",
                self.id
            );
            return Err(anyhow::anyhow!("No private key available"));
        }

        // let message_hash = self.hash_message(message);
        let mut hasher = sha3::Keccak256::new();
        hasher.update(&message); // ← hash the real RLP bytes!
        let tx_hash = hasher.finalize();
        println!("Tx hash: 0x{}", hex::encode(&tx_hash));

        info!(
            "📝 [SIGNING] Node {} starting to sign message: {:?}",
            self.id, tx_hash
        );

        // Get available nodes before the mutable borrow
        let available_nodes = self.get_available_nodes_from_manager().await;
        let round = self.next_round;
        self.curr_round = round; // Set current round to the next round
        self.next_round += 1; // Increment round for next signing operation
                              // Generate VRF proof for this signing operation
        if let Some(vrf_selector) = &mut self.vrf_selector {
            let selection_result = vrf_selector.select_mpc_nodes(&available_nodes, 1, round);
            info!(
                "🎯 [VRF] Node {} selected {} MPC nodes for signing round {}: {:?}",
                self.id,
                selection_result.selected_nodes.len(),
                round,
                selection_result.selected_nodes
            );
            info!("available nodes for vrf are : {:?}", available_nodes);

            // Broadcast the VRF-selected nodes to all peers
            if let Some(broadcast_msg) = vrf_selector.create_selected_nodes_broadcast(round) {
                let broadcast_data = serde_json::to_vec(
                    &crate::types::GossipsubMessage::VrfSelectedNodes(broadcast_msg),
                )?;
                self.broadcast("vrf-selection", &broadcast_data).await?;
                info!(
                    "📤 [VRF] Node {} broadcasted VRF-selected nodes for round {}",
                    self.id, round
                );
            }
        }

        // Create secret key share instead of ECDSA signature
        let secret_key_share = self.create_secret_key_share(&tx_hash, round)?;

        info!(
            "✍️ [SIGNING] Node {} created secret key share: \x1b[34m{:?}\x1b[0m",
            self.id,
            hex::encode(secret_key_share.secret_key.secret_bytes())
        );
        println!("\nSecret Key Share Components:");
        println!("  threshold: {}", secret_key_share.threshold);
        println!("  total_shares: {}", secret_key_share.total_shares);
        println!(
            "  secret_key: 0x{}",
            hex::encode(secret_key_share.secret_key.secret_bytes())
        );

        // Store secret key share by round
        {
            let mut secret_key_shares_by_round = self.secret_key_shares_by_round.write().await;
            let round_secret_key_shares = secret_key_shares_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_secret_key_shares.insert(self.id.clone(), secret_key_share.clone());
            info!(
                "💾 [SIGNING] Node {} stored secret key share for round {}",
                self.id, round
            );
        }

        let msg = serde_json::to_vec(&crate::types::GossipsubMessage::Signing(
            SigningMessage::SecretKeyShare {
                from: self.id.clone(),
                secret_key_share: secret_key_share,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            },
        ))?;

        self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted secret key share", self.id);
        Ok(())
    }

    pub fn create_ecdsa_signature(
        &self,
        message: &Message,
        _transaction: &DummyTransaction,
    ) -> Result<RecoverableSignature> {
        // 1) Get secret key and context
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("No private key available"))?;
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
        let mut r_bytes = [0u8; 32];
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

        // 9) s = k⁻¹·(z + r·x) mod n, then low-S normalize
        let s_full = (&k_inv * (&z + (&r * &x) % &n)) % &n;
        let half_n = &n >> 1;
        // let s = if s_full > half_n { &n - &s_full } else { s_full };
        let was_high_s = s_full > half_n;
        let s = if was_high_s { &n - &s_full } else { s_full };

        // 10) Serialize r‖s into 64-byte array
        let mut sig_bytes = [0u8; 64];
        let r_be: Vec<u8> = r.to_bytes_be();
        let s_be = s.to_bytes_be();
        sig_bytes[32 - r_be.len()..32].copy_from_slice(&r_be);
        sig_bytes[64 - s_be.len()..64].copy_from_slice(&s_be);

        // // 11) Compute correct RecoveryId from R_y parity
        // let y_parity = rser[64] & 1;
        // let rid = RecoveryId::from_i32(y_parity as i32)
        //     .map_err(|e| anyhow!("invalid recovery ID: {}", e))?;

        // 11) Compute RecoveryId from R_y parity **and** low-S normalization
        let y_parity = (rser[64] & 1) as i32;
        let rid_val = y_parity ^ (was_high_s as i32);
        let rid: RecoveryId =
            RecoveryId::from_i32(rid_val).map_err(|e| anyhow!("invalid recovery ID: {}", e))?;

        // 12) Build the recoverable signature
        let rec_sig = RecoverableSignature::from_compact(&sig_bytes, rid)
            .map_err(|e| anyhow!("invalid compact signature: {}", e))?;

        Ok(rec_sig)
    }

    pub fn create_secret_key_share(
        &self,
    ) -> Result<SecretKeyShare> {
        // Get the secret key
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("No secret key available"))?;

        // Create secret key share (simply sharing the secret key)
        let secret_key_share = SecretKeyShare {
            secret_key: sk.clone(),
            signer_id: self.id.clone(),
            threshold: self.threshold as u32,
            total_shares: self.threshold as u32 + 1,
        };

        info!("🔐 [SIGNING] Created secret key share for node {}", self.id);

        Ok(secret_key_share)
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
            } => {
                // info!(
                //     "📥 [SIGNING] Node {} received message to sign from {}",
                //     self.id, from
                // );
                // self.handle_message_to_sign(from, message, message_hash)
                //     .await?;
            }
            SigningMessage::SecretKeyShare {
                from,
                secret_key_share,
                timestamp: _timestamp,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received secret key share from {}",
                    self.id, from
                );
                self.handle_secret_key_share(from, secret_key_share).await?;
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
            SigningMessage::RequestSecretShares {
                round,
                final_node_id,
                message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received secret share request for round {} from final node {}",
                    self.id, round, final_node_id
                );
                self.handle_secret_share_request(round, final_node_id, message)
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_secret_key_share(
        &mut self,
        from: String,
        secret_key_share: SecretKeyShare,
    ) -> Result<()> {
        info!(
            "🚀 [SIGNING] handle_secret_key_share called for node {} from {}",
            self.id, from
        );
        info!(
            "📋 [SIGNING] Secret key share details - signer_id: {}, threshold: {}, total_shares: {}",
            secret_key_share.signer_id, secret_key_share.threshold, secret_key_share.total_shares
        );

        // Store secret key share from node
        self.secret_key_shares
            .write()
            .await
            .insert(from.clone(), secret_key_share.clone());

        info!(
            "💾 [SIGNING] Node {} stored secret key share from {}",
            self.id, from
        );

        let round_to_handle = {
            let final_nodes = self.final_nodes_by_round.read().await;
            let mut found_round = None;
            for (round, final_node_id) in final_nodes.iter() {
                if final_node_id == &self.id && self.curr_round == *round {
                    found_round = Some(*round);
                    break;
                }
            }
            found_round
        };

        if let Some(round) = round_to_handle {
            // Store secret key share by round
            let should_aggregate = {
                let mut secret_key_shares_by_round = self.secret_key_shares_by_round.write().await;
                let round_secret_key_shares = secret_key_shares_by_round.entry(round).or_default();
                round_secret_key_shares.insert(from.clone(), secret_key_share.clone());

                info!(
                    "💾 [SIGNING] Final node {} stored secret key share from {} for round {} (total: {})",
                    self.id,
                    from,
                    round,
                    round_secret_key_shares.len()
                );
                info!(
                    "threshold: {}, total: {}",
                    self.threshold,
                    round_secret_key_shares.len()
                );
                round_secret_key_shares.len() >= self.threshold + 1
            };

            if should_aggregate {
                // Prepare secret key shares for aggregation
                let secret_key_shares_to_aggregate: Vec<SecretKeyShare> = {
                    let secret_key_shares_by_round = self.secret_key_shares_by_round.read().await;
                    secret_key_shares_by_round
                        .get(&round)
                        .unwrap()
                        .values()
                        .cloned()
                        .collect()
                };
                info!(
                    "🔍 [SIGNING] Node {} preparing to aggregate {} secret key shares for round {}",
                    self.id,
                    secret_key_shares_to_aggregate.len(),
                    round
                );

                // Aggregate secret key shares
                match self
                    .aggregate_secret_key_shares(secret_key_shares_to_aggregate)
                    .await
                {
                    Ok(aggregated_secret_key) => {
                        info!(
                            "🎉 [SIGNING] Secret key aggregation successful for round {}!",
                            round
                        );

                        info!(
                            "🔐 [SIGNING] Aggregated secret key: 0x{}",
                            hex::encode(&aggregated_secret_key)
                        );

                        // Store the aggregated secret key as this node's secret key
                        let aggregated_secret_key =
                            SecretKey::from_slice(&aggregated_secret_key)
                                .map_err(|e| anyhow!("Invalid aggregated secret key: {}", e))?;

                        // Set the aggregated secret key as this node's secret key
                        self.private_key = Some(aggregated_secret_key);

                        // Generate public key from the aggregated secret key
                        let secp = Secp256k1::new();
                        let aggregated_public_key =
                            PublicKey::from_secret_key(&secp, &aggregated_secret_key);
                        self.public_key = Some(aggregated_public_key);

                        info!("🔐 [SIGNING] Set aggregated secret key as node's secret key for round {}", round);
                        info!(
                            "🔑 [SIGNING] Aggregated public key: {:?}",
                            aggregated_public_key
                        );

                        // Create signature from aggregated secret key
                        match self.create_signature_from_private_key(round).await {
                            Ok(signature) => {
                                info!("✅ [SIGNING] Created signature from aggregated secret key for round {}", round);
                                let (recovery_id, signature_bytes) = signature.serialize_compact();
                                let v: u64 = recovery_id.to_i32() as u64 + 35 + 1043 * 2;
                                let r = &signature_bytes[0..32];
                                let s = &signature_bytes[32..64];

                                info!("🔐 [SIGNING] Final signature components:");
                                info!("  v: {}", v);
                                info!("  r: 0x{}", hex::encode(r));
                                info!("  s: 0x{}", hex::encode(s));
                                info!("  recovery_id: {}", recovery_id.to_i32());
                                info!("  full_signature: 0x{}", hex::encode(signature_bytes));
                            }
                            Err(e) => {
                                error!("❌ [SIGNING] Failed to create signature from aggregated private key: {}", e);
                                return Err(e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ [SIGNING] Private key aggregation failed: {}", e);
                        return Err(e);
                    }
                }
            } else {
                info!(
                    "⏳ [SIGNING] Waiting for more private key shares: {}/{}",
                    self.secret_key_shares_by_round
                        .read()
                        .await
                        .get(&round)
                        .unwrap()
                        .len(),
                    self.threshold
                );
            }
        }

        Ok(())
    }

    async fn handle_secret_share_request(
        &mut self,
        round: u64,
        final_node_id: String,
        _message: String,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} responding to secret share request for round {}",
            self.id, round
        );

        // Only broadcast secret key share if we're not the final node
        if final_node_id != self.id {
            // Broadcast secret key share to the signing topic
            self.broadcast_secret_key_share(round).await?;
        } else {
            info!(
                "🔄 [SIGNING] This node is the final node, no need to broadcast secret key share"
            );
        }

        Ok(())
    }

    pub async fn aggregate_secret_key_shares(
        &self,
        secret_key_shares: Vec<SecretKeyShare>,
    ) -> Result<Vec<u8>> {
        let n_shares = secret_key_shares.len();
        if n_shares <= self.threshold {
            return Err(anyhow!(
                "Not enough secret key shares: got {}, need {}",
                n_shares,
                self.threshold
            ));
        }

        info!("🔍 [SIGNING] Aggregating {} secret key shares", n_shares);

        // Simple addition of secret keys (modulo curve order)
        let curve_order = BigUint::from_bytes_be(&CURVE_ORDER);
        let mut aggregated_key = BigUint::from(0u32);

        for secret_key_share in secret_key_shares {
            let key_bytes = secret_key_share.secret_key.secret_bytes();
            let key_bigint = BigUint::from_bytes_be(&key_bytes);
            aggregated_key = (aggregated_key + key_bigint) % &curve_order;
        }

        // Convert back to bytes
        let mut result = aggregated_key.to_bytes_be();
        if result.len() < 32 {
            let mut padded = vec![0u8; 32 - result.len()];
            padded.extend_from_slice(&result);
            result = padded;
        } else if result.len() > 32 {
            result = result[result.len() - 32..].to_vec();
        }

        info!("✅ [SIGNING] Successfully aggregated secret key shares");
        Ok(result)
    }

    async fn create_signature_from_private_key(&self, round: u64) -> Result<RecoverableSignature> {
        info!(
            "🔐 [SIGNING] Creating signature from node's private key for round {}",
            round
        );

        // Get the private key from the node
        let secret_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("No private key available"))?;

        // Get the message hash for this round (you might need to store this)
        // For now, we'll use a dummy message hash
        let message_hash = vec![0u8; 32]; // This should be the actual message hash for the round

        // Create the message to sign
        let msg = Message::from_slice(&message_hash)?;

        // Create ECDSA signature using the node's private key
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa_recoverable(&msg, &secret_key);

        info!("✅ [SIGNING] Created signature from node's private key");
        Ok(signature)
    }

    pub async fn broadcast_secret_key_share(&mut self, round: u64) -> Result<()> {
        info!(
            "📤 [SIGNING] Broadcasting secret key share for round {} to signing topic",
            round
        );

        // Get our secret key share for this round
        let secret_key_shares_by_round = self.secret_key_shares_by_round.read().await;

        if let Some(round_secret_key_shares) = secret_key_shares_by_round.get(&round) {
            if let Some(our_secret_key_share) = round_secret_key_shares.get(&self.id) {
                let secret_key_share_msg = SigningMessage::SecretKeyShare {
                    from: self.id.clone(),
                    secret_key_share: our_secret_key_share.clone(),
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                };

                // Wrap in GossipsubMessage::Signing for proper message handling
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(secret_key_share_msg);
                let secret_key_share_data = serde_json::to_vec(&gossipsub_msg)?;

                // Broadcast to the main signing topic
                let res = self.broadcast("signing", &secret_key_share_data).await;
                match res {
                    Ok(_) => info!(
                        "📤 [SIGNING] Successfully broadcasted secret key share for round {} to signing topic",
                        round
                    ),
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to broadcast secret key share for round {}: {}",
                            round, e
                        );
                        return Err(e);
                    }
                }

                info!(
                    "✅ [SIGNING] Broadcasted secret key share for round {} to signing topic",
                    round
                );
            } else {
                info!(
                    "⚠️ [SIGNING] No secret key share found for round {} for this node",
                    round
                );
            }
        } else {
            info!(
                "⚠️ [SIGNING] No secret key shares found for round {}",
                round
            );
        }

        Ok(())
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

        let public_keys = self.public_keys.read().await;

        // Check if we have public keys for all signers
        for signer_id in &signed_message.signer_ids {
            if !public_keys.contains_key(signer_id) {
                warn!("❌ [SIGNING] Missing public key for signer: {}", signer_id);
                return Ok(false);
            }
        }

        info!("🔍 [SIGNING] Node {} verifying ECDSA signature", self.id);

        // For now, return true as a placeholder
        // In a real implementation, you'd verify each signature individually
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
    pub fn get_vrf_public_key(&self) -> Option<String> {
        self.vrf_selector
            .as_ref()
            .map(|vrf| vrf.get_public_key_hex())
    }

    /// Get VRF public key as bytes
    pub fn get_vrf_public_key_bytes(&self) -> Option<Vec<u8>> {
        self.vrf_selector.as_ref().map(|vrf| vrf.get_public_key())
    }

    /// Generate VRF proof for a given input
    pub fn generate_vrf_proof(&self, input: &[u8]) -> Option<crate::vrf::VrfOutput> {
        self.vrf_selector
            .as_ref()
            .map(|vrf| vrf.generate_vrf_proof(input))
    }

    /// Verify VRF proof from another node
    pub fn verify_vrf_proof(
        &self,
        node_public_key: &[u8],
        input: &[u8],
        output: &crate::vrf::VrfOutput,
    ) -> bool {
        self.vrf_selector
            .as_ref()
            .map(|vrf| vrf.verify_vrf_proof(node_public_key, input, output))
            .unwrap_or(false)
    }

    /// Get available nodes as PeerIds derived from stored public keys
    async fn get_available_nodes(&self) -> Vec<PeerId> {
        self.available_nodes.clone().unwrap()
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.available_nodes = Some(nodes);
    }

    async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
        if let Some(ref nodes) = self.available_nodes {
            nodes.clone()
        } else {
            self.get_available_nodes().await
        }
    }

    /// Handle VRF selected nodes broadcast from another node
    pub fn handle_vrf_selected_nodes_broadcast(
        &mut self,
        broadcast: crate::vrf::VrfSelectedNodesBroadcast,
    ) {
        if let Some(vrf_selector) = &mut self.vrf_selector {
            // Extract round before moving broadcast
            let round = broadcast.round;
            let min_selections = 4; // Or set to your desired threshold

            vrf_selector.handle_selected_nodes_broadcast(broadcast);

            // Check if consensus should be triggered after receiving this broadcast
            if vrf_selector.can_start_consensus(round, min_selections) {
                info!(
                    "🎯 [VRF] Enough selections collected for round {}, triggering consensus check",
                    round
                );

                // Spawn a task to trigger consensus asynchronously
                let mut signing_node_clone = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = signing_node_clone
                        .check_and_trigger_consensus(round, min_selections)
                        .await
                    {
                        error!(
                            "❌ [CONSENSUS] Failed to trigger consensus for round {}: {}",
                            round, e
                        );
                    }
                });
            }
        }
    }

    /// Check and trigger consensus if ready
    pub async fn check_and_trigger_consensus(
        &mut self,
        round: u64,
        min_selections: usize,
    ) -> Result<Option<ConsensusResult>> {
        if self.can_start_consensus(round, min_selections) {
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

        if let (Some(vrf_selector), Some(consensus_node)) =
            (&self.vrf_selector, &mut self.consensus_node)
        {
            // Get all selected nodes with frequencies for this round
            let all_selected_nodes = vrf_selector.get_all_selected_nodes_with_frequencies(round);

            if all_selected_nodes.is_empty() {
                info!(
                    "⚠️ [CONSENSUS] No selected nodes available for consensus round {}",
                    round
                );
                return Ok(None);
            }

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

                    let broadcast_data = serde_json::to_vec(&consensus_msg)?;

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
                        let mut final_nodes = self.final_nodes_by_round.write().await;
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

                        // Start collecting signatures after a short delay
                        let mut signing_node_clone = self.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            if let Err(e) = signing_node_clone
                                .collect_and_aggregate_signatures(round)
                                .await
                            {
                                error!(
                                    "❌ [SIGNING] Failed to collect and aggregate signatures: {}",
                                    e
                                );
                            }
                        });
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
        } else {
            Err(anyhow::anyhow!(
                "VRF selector or consensus node not available"
            ))
        }
    }

    /// Check if consensus can be started for a round
    pub fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        if let Some(vrf_selector) = &self.vrf_selector {
            vrf_selector.can_start_consensus(round, min_selections)
        } else {
            false
        }
    }

    /// Handle consensus messages
    pub async fn handle_consensus_message(&mut self, msg: ConsensusMessage) -> Result<()> {
        if let Some(consensus_node) = &mut self.consensus_node {
            consensus_node.handle_message(msg).await?;
        }
        Ok(())
    }

    /// Trigger aggregate signature for the final selected node
    async fn trigger_aggregate_signature_for_final_node(&self, round: u64) -> Result<()> {
        info!(
            "🚀 [SIGNING] Triggering secret share aggregation for final node in round {}",
            round
        );

        // Broadcast a message to all nodes to send their secret shares to the final node
        let secret_share_request = SigningMessage::RequestSecretShares {
            round,
            final_node_id: self.id.clone(),
            message: "Aggregate secret share request".to_string(),
        };

        // Wrap in GossipsubMessage::Signing for proper message handling
        let gossipsub_msg = crate::types::GossipsubMessage::Signing(secret_share_request);
        let broadcast_data = serde_json::to_vec(&gossipsub_msg)?;
        self.broadcast("signing", &broadcast_data).await?;

        info!(
            "📤 [SIGNING] Broadcasted secret share request for round {} to all nodes",
            round
        );

        Ok(())
    }

    /// Collect private key shares and perform aggregation (for final selected node)
    pub async fn collect_and_aggregate_signatures(&mut self, round: u64) -> Result<()> {
        info!(
            "🔍 [SIGNING] Final node {} waiting for private key shares for round {}",
            self.id, round
        );

        // Wait a bit for secret key shares to arrive
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Check current secret key share count for this round
        let secret_key_shares_by_round = self.secret_key_shares_by_round.read().await;
        if let Some(round_secret_key_shares) = secret_key_shares_by_round.get(&round) {
            info!(
                "📊 [SIGNING] Final node {} has {} secret key shares for round {}",
                self.id,
                round_secret_key_shares.len(),
                round
            );
        } else {
            info!(
                "⚠️ [SIGNING] No secret key shares found for round {}",
                round
            );
        }

        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }

    /// Get Ethereum address from public key
    pub fn get_ethereum_address(&self) -> Option<String> {
        if let Some(public_key) = &self.public_key {
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
        if let Some(private_key) = &self.private_key {
            let secret_key_bytes = private_key.secret_bytes();
            Some(format!("0x{}", hex::encode(secret_key_bytes)))
        } else {
            None
        }
    }
}
