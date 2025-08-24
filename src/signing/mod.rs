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
use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage};
use crate::vrf::VrfNodeSelector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDSASignature {
    pub signature: Vec<u8>, // 65-byte recoverable signature
    pub signer_id: String,
    pub recovery_id: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignatureShare {
    pub share: Vec<u8>, // The signature share
    pub signer_id: String,
    pub share_index: u32,
    pub threshold: u32,
    pub total_shares: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub aggregated_signature: Vec<u8>,
    pub signer_ids: Vec<String>,
    pub message_hash: Vec<u8>,
    pub threshold: u32,
    pub total_shares: u32,
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
    ECDSASignature {
        from: String,
        signature: ECDSASignature,
        timestamp: u128,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
    RequestSignatures {
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
    signatures: Arc<RwLock<HashMap<String, ECDSASignature>>>,
    signatures_by_round: Arc<RwLock<HashMap<u64, HashMap<String, ECDSASignature>>>>, // round -> node_id -> signature
    final_nodes_by_round: Arc<RwLock<HashMap<u64, String>>>, // round -> final_node_id
    aggregated_rounds: Arc<RwLock<std::collections::HashSet<u64>>>, // Track rounds that have been aggregated
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
            signatures: Arc::new(RwLock::new(HashMap::new())),
            signatures_by_round: Arc::new(RwLock::new(HashMap::new())),
            final_nodes_by_round: Arc::new(RwLock::new(HashMap::new())),
            aggregated_rounds: Arc::new(RwLock::new(std::collections::HashSet::new())),
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

        // Create ECDSA signature
        let msg = Message::from_slice(&tx_hash)?;

        let signature = self.create_ecdsa_signature(&msg, transaction)?;
        // Extract signature components
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let v: u64 = recovery_id.to_i32() as u64 + 35 + 1043 * 2; // ✅ use u64 to prevent overflow
        let r = &signature_bytes[0..32];
        let s = &signature_bytes[32..64];

        info!(
            "✍️ [SIGNING] Node {} created ECDSA signature: \x1b[34m{:?} {:?}\x1b[0m",
            self.id,
            signature.serialize_compact(),
            self.private_key.clone()
        );
        println!("\nSignature Components:");
        println!("  v: {}", v);
        println!("  r: 0x{}", hex::encode(r));
        println!("  s: 0x{}", hex::encode(s));

        let ecdsa_signature = ECDSASignature {
            signature: signature.serialize_compact().1.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: signature.serialize_compact().0.to_i32() as u8,
        };

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(self.id.clone(), ecdsa_signature.clone());
            info!(
                "💾 [SIGNING] Node {} stored signature for round {}",
                self.id, round
            );
        }

        let msg = serde_json::to_vec(&crate::types::GossipsubMessage::Signing(
            SigningMessage::ECDSASignature {
                from: self.id.clone(),
                signature: ecdsa_signature,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            },
        ))?;

        self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted ECDSA signature", self.id);
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
            } => {
                // info!(
                //     "📥 [SIGNING] Node {} received message to sign from {}",
                //     self.id, from
                // );
                // self.handle_message_to_sign(from, message, message_hash)
                //     .await?;
            }
            SigningMessage::ECDSASignature {
                from,
                signature,
                timestamp: _timestamp,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received ECDSA signature from {}",
                    self.id, from
                );
                self.handle_ecdsa_signature(from, signature).await?;
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
        }
        Ok(())
    }

    async fn handle_ecdsa_signature(
        &mut self,
        from: String,
        signature: ECDSASignature,
    ) -> Result<()> {
        info!(
            "🚀 [SIGNING] handle_ecdsa_signature called for node {} from {}",
            self.id, from
        );
        info!(
            "📋 [SIGNING] Signature details - signer_id: {}, recovery_id: {}",
            signature.signer_id, signature.recovery_id
        );

        // Store signature from node
        self.signatures
            .write()
            .await
            .insert(from.clone(), signature.clone());

        info!(
            "💾 [SIGNING] Node {} stored ECDSA signature from {}",
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
            // Check if this round has already been aggregated
            let already_aggregated = {
                let aggregated_rounds = self.aggregated_rounds.read().await;
                aggregated_rounds.contains(&round)
            };

            if already_aggregated {
                info!(
                    "⏭️ [SIGNING] Round {} already aggregated, ignoring signature from {}",
                    round, from
                );
                return Ok(());
            }

            // Store signature by round
            let should_aggregate = {
                let mut signatures_by_round = self.signatures_by_round.write().await;
                let round_signatures = signatures_by_round.entry(round).or_default();
                round_signatures.insert(from.clone(), signature.clone());

                info!(
                    "💾 [SIGNING] Final node {} stored signature from {} for round {} (total: {})",
                    self.id,
                    from,
                    round,
                    round_signatures.len()
                );
                let total_nodes = self
                    .available_nodes
                    .as_ref()
                    .map(|nodes| nodes.len())
                    .unwrap_or(0);
                info!(
                    "📊 [SIGNING] Aggregation check: current signatures: {}, total_nodes: {}, threshold: {}",
                    round_signatures.len(),
                    total_nodes,
                    self.threshold
                );
                round_signatures.len() >= total_nodes && total_nodes > 0
            };

            if should_aggregate {
                // Mark this round as aggregated to prevent future aggregations
                {
                    let mut aggregated_rounds = self.aggregated_rounds.write().await;
                    aggregated_rounds.insert(round);
                }
                info!(
                    "🎯 [SIGNING] Round {} marked as aggregated, starting aggregation process",
                    round
                );

                // Prepare signatures for aggregation
                let signatures_to_aggregate: Vec<RecoverableSignature> = {
                    let signatures_by_round = self.signatures_by_round.read().await;
                    let round_signatures = signatures_by_round.get(&round).unwrap();

                    // Sort signatures by signer_id (PeerId) to ensure consistent ordering across rounds
                    let mut sorted_signatures: Vec<_> = round_signatures.iter().collect();

                    info!("🔍 [SIGNING] === SIGNATURE SORTING DEBUG ===");
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
                        sorted_signatures.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>()
                    );

                    info!("🔍 [SIGNING] === END SIGNATURE SORTING DEBUG ===");

                    // Create a mapping of peer ID to index for debugging
                    let mut peer_to_index_map = Vec::new();

                    let sigs_to_aggregate: Vec<RecoverableSignature> = sorted_signatures
                        .into_iter()
                        .enumerate()
                        .map(|(i, (signer_id, ecdsa_sig))| {
                            let index = i + 1;
                            peer_to_index_map.push((signer_id.clone(), index));

                            info!(
                                "🔍 [SIGNING] Peer {} assigned index {} for aggregation",
                                signer_id, index
                            );

                            RecoverableSignature::from_compact(
                                &ecdsa_sig.signature,
                                RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                            )
                            .map_err(|_| {
                                anyhow::anyhow!("Invalid signature from signer {}", signer_id)
                            })
                        })
                        .collect::<Result<_>>()?;

                    info!(
                        "🔍 [SIGNING] Final peer-to-index mapping: {:?}",
                        peer_to_index_map
                            .iter()
                            .map(|(peer, idx)| format!("{}->{}", peer, idx))
                            .collect::<Vec<_>>()
                    );

                    sigs_to_aggregate
                };
                info!(
                    "🔍 [SIGNING] Node {} preparing to aggregate {} signatures for round {} signatures are {:?}",
                    self.id,
                    signatures_to_aggregate.len(),
                    round,
                    signatures_to_aggregate
                        .iter()
                        .map(|sig| sig.serialize_compact().1)
                        .collect::<Vec<_>>()
                );

                // Aggregate signatures
                match self.aggregate_signatures(signatures_to_aggregate).await {
                    Ok(aggregated_signature) => {
                        info!(
                            "🎉 [SIGNING] Signature aggregation successful for round {}!",
                            round
                        );

                        let (recid, signature_bytes) = aggregated_signature.serialize_compact();
                        let v: u64 = recid.to_i32() as u64 + 35 + 1043 * 2;
                        let r = &signature_bytes[0..32];
                        let s = &signature_bytes[32..64];

                        info!("🔐 [SIGNING] Aggregated signature components:");
                        info!("  v: {}", v);
                        info!("  r: 0x{}", hex::encode(r));
                        info!("  s: 0x{}", hex::encode(s));
                        info!("  recovery_id: {}", 0);
                        info!("  full_signature: 0x{}", hex::encode(signature_bytes));
                    }
                    Err(e) => {
                        error!("❌ [SIGNING] Aggregation failed: {}", e);
                        return Err(e);
                    }
                }
            } else {
                let total_nodes = self
                    .available_nodes
                    .as_ref()
                    .map(|nodes| nodes.len())
                    .unwrap_or(0);
                info!(
                    "⏳ [SIGNING] Waiting for more signatures: {}/{}",
                    self.signatures_by_round
                        .read()
                        .await
                        .get(&round)
                        .unwrap()
                        .len(),
                    total_nodes
                );
            }
        }

        Ok(())
    }

    pub async fn aggregate_signatures(
        &self,
        signatures: Vec<RecoverableSignature>,
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

        // TODO: This should use the same deterministic index calculation as DKG
        // Currently using positional index which may not match DKG indices
        let s_shares: Vec<(u32, Vec<u8>)> = signatures
            .into_iter()
            .enumerate()
            .map(|(i, sig)| {
                let (_recid, compact) = sig.serialize_compact();
                let index = (i + 1) as u32;
                info!(
                    "🔍 [SIGNING] Signature {} assigned positional index: {}",
                    i, index
                );
                (index, compact[32..64].to_vec())
            })
            .collect();

        info!(
            "🔍 [SIGNING] Final s_shares with indices: {:?}",
            s_shares.iter().map(|(idx, _)| idx).collect::<Vec<_>>()
        );
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

    /// Shamir‐style Lagrange interpolation at x=0 over the field of order CURVE_ORDER.
    // fn lagrange_interpolate(
    //     &self,
    //     shares: &[(u32, Vec<u8>)],
    // ) -> Result<Vec<u8>> {
    //     // 1) Check count
    //     if shares.len() <= self.threshold {
    //         return Err(anyhow!(
    //             "Not enough shares: got {}, need {}",
    //             shares.len(),
    //             self.threshold
    //         ));
    //     }

    //     // 2) Prepare modulus and accumulator
    //     let n = BigUint::from_bytes_be(&CURVE_ORDER);
    //     // simple extended‐Euclid modinv
    //     fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    //         let mut mn = (m.clone(), a.clone());
    //         let mut xy = (BigInt::zero(), BigInt::one());
    //         while mn.1 != BigUint::zero() {
    //             let q = &mn.0 / &mn.1;
    //             mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
    //             xy = (xy.1.clone(), &xy.0 - &q.to_bigint().unwrap() * &xy.1);
    //         }
    //         if mn.0 != BigUint::one() {
    //             return None;
    //         }
    //         let m_int = m.to_bigint().unwrap();
    //         let res = (xy.0 % &m_int + &m_int) % &m_int;
    //         Some(res.to_biguint().unwrap())
    //     }

    //     let mut accum = BigUint::from(0u32);

    //     // 3) For each share j, compute λ_j and add λ_j * y_j
    //     for &(xj, ref yj_bytes) in shares {
    //         let mut num = BigUint::from(1u32);
    //         let mut den = BigUint::from(1u32);

    //         for &(xm, _) in shares {
    //             if xm != xj {
    //                 let xm_u = BigUint::from(xm);
    //                 num = (num * (&n - &xm_u)) % &n;
    //                 let xj_u = BigUint::from(xj);
    //                 let diff = if xj_u >= xm_u {
    //                     &xj_u - &xm_u
    //                 } else {
    //                     &xj_u + &n - &xm_u
    //                 };
    //                 den = (den * diff) % &n;
    //             }
    //         }

    //         let den_inv = modinv(&den, &n)
    //             .ok_or_else(|| anyhow!("Denominator not invertible"))?;
    //         let lambda = (num * den_inv) % &n;

    //         let yj = BigUint::from_bytes_be(yj_bytes);
    //         accum = (accum + (&lambda * yj)) % &n;
    //     }

    //     // 4) Pad to 32-byte big-endian
    //     let mut be = accum.to_bytes_be();
    //     if be.len() < 32 {
    //         let mut pad = vec![0u8; 32 - be.len()];
    //         pad.extend_from_slice(&be);
    //         be = pad;
    //     }
    //     Ok(be)
    // }

    fn lagrange_interpolate(&self, shares: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(anyhow!(
                "Not enough shares: got {}, need at least {}",
                shares.len(),
                self.threshold
            ));
        }

        println!("=== Lagrange Interpolation Debug ===");
        println!("Threshold: {}, Got {} shares", self.threshold, shares.len());

        for (i, &(x, ref y_bytes)) in shares.iter().enumerate() {
            let y_val = BigUint::from_bytes_be(y_bytes);
            println!("Share {}: x={}, y={}", i + 1, x, y_val);
        }

        // // 🔧 FIX 1: Select exactly threshold shares deterministically
        // let mut selected_shares = shares.to_vec();
        // selected_shares.sort_by_key(|(x, _)| *x);
        // selected_shares.truncate(self.threshold);

        // With this:
        let mut rng = thread_rng();
        let mut selected_shares = shares.to_vec();
        selected_shares.shuffle(&mut rng);
        // selected_shares.truncate(self.threshold);


        println!(
            "Selected {} shares for interpolation:",
            selected_shares.len()
        );
        for (i, &(x, ref y_bytes)) in selected_shares.iter().enumerate() {
            let y_val = BigUint::from_bytes_be(y_bytes);
            println!("Share {}: x={}, y={}", i + 1, x, y_val);
        }

        let n = BigUint::from_bytes_be(&CURVE_ORDER);
        println!("Working modulo n = {}", n);

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
        println!("\n=== Computing Lagrange Coefficients ===");

        // 🔧 FIX 2: Use selected_shares in BOTH loops
        for (share_idx, &(xj, ref yj_bytes)) in selected_shares.iter().enumerate() {
            println!("\n--- Processing Share {} (x={}) ---", share_idx + 1, xj);

            let mut num = BigUint::from(1u32);
            let mut den = BigUint::from(1u32);

            println!("Computing λ_{} = ", xj);
            let mut debug_terms = Vec::new();

            // 🔧 FIX 3: Inner loop uses SAME selected_shares, not all shares
            for &(xm, _) in selected_shares.iter() {
                // ← FIXED: Use selected_shares
                if xm != xj {
                    let xm_u = BigUint::from(xm);
                    let xj_u = BigUint::from(xj);

                    // Numerator: -xₘ ≡ (n - xₘ) mod n
                    let neg_xm = (&n - &xm_u) % &n;
                    num = (num * &neg_xm) % &n;

                    // Denominator: (xⱼ - xₘ) mod n
                    let diff = if xj_u >= xm_u {
                        &xj_u - &xm_u
                    } else {
                        &xj_u + &n - &xm_u
                    };
                    den = (den * diff.clone()) % &n;

                    debug_terms.push(format!("(-{}/({}-{})) = ({}/{})", xm, xj, xm, neg_xm, diff));
                }
            }

            println!("  = {}", debug_terms.join(" × "));
            println!("  numerator = {} (mod {})", num, n);
            println!("  denominator = {} (mod {})", den, n);

            let den_inv = modinv(&den, &n)
                .ok_or_else(|| anyhow!("Denominator not invertible for share x={}", xj))?;

            println!("  denominator⁻¹ = {} (mod {})", den_inv, n);

            let lambda = (num.clone() * den_inv.clone()) % &n;
            println!(
                "  λ_{} = {} × {} = {} (mod {})",
                xj, num, den_inv, lambda, n
            );

            let yj = BigUint::from_bytes_be(yj_bytes);
            let contribution = (&lambda * &yj) % &n;
            println!(
                "  Contribution: {} × {} = {} (mod {})",
                lambda, yj, contribution, n
            );

            accum = (accum + contribution) % &n;
            println!("  Running total: {} (mod {})", accum, n);
        }

        println!("\n=== Final Result ===");
        println!("Reconstructed value: {} (mod {})", accum, n);

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
    /// From a slice of RecoveryIds, pick the one that appears most often.
    fn get_most_common_recovery_id(&self, recid_ints: &[i32]) -> Result<RecoveryId> {
        let mut counts = HashMap::new();
        for &v in recid_ints {
            *counts.entry(v).or_insert(0usize) += 1;
        }
        let (&common, _) = counts
            .iter()
            .max_by_key(|&(_, &cnt)| cnt)
            .ok_or_else(|| anyhow!("No recovery IDs provided"))?;
        RecoveryId::from_i32(common).map_err(|e| anyhow!("invalid recid {}: {}", common, e))
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
        total_nodes: usize,
        broadcast: crate::vrf::VrfSelectedNodesBroadcast,
    ) {
        if let Some(vrf_selector) = &mut self.vrf_selector {
            // Extract round before moving broadcast
            let round = broadcast.round;
            let min_selections = total_nodes; // Or set to your desired threshold

            vrf_selector.handle_selected_nodes_broadcast(broadcast, total_nodes);

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
            "🚀 [SIGNING] Triggering aggregate signature for final node in round {}",
            round
        );

        // Broadcast a message to all nodes to send their signatures to the final node
        let signature_request = SigningMessage::RequestSignatures {
            round,
            final_node_id: self.id.clone(),
            message: "Aggregate signature request".to_string(),
        };

        // Wrap in GossipsubMessage::Signing for proper message handling
        let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_request);
        let broadcast_data = serde_json::to_vec(&gossipsub_msg)?;
        self.broadcast("signing", &broadcast_data).await?;

        info!(
            "📤 [SIGNING] Broadcasted signature request for round {} to all nodes",
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
        let signatures_by_round = self.signatures_by_round.read().await;

        if let Some(round_signatures) = signatures_by_round.get(&round) {
            if let Some(our_signature) = round_signatures.get(&self.id) {
                let signature_msg = SigningMessage::ECDSASignature {
                    from: self.id.clone(),
                    signature: our_signature.clone(),
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                };

                // Wrap in GossipsubMessage::Signing for proper message handling
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;

                // Broadcast to a specific topic that the final node subscribes to
                let res = self
                    .broadcast("signatures-to-final-node", &signature_data)
                    .await;
                match res {
                    Ok(_) => info!(
                        "📤 [SIGNING] Successfully sent signature for round {} to final node {}",
                        round, final_node_id
                    ),
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to send signature for round {} to final node {}: {}",
                            round, final_node_id, e
                        );
                        return Err(e);
                    }
                }

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

    /// Collect signatures and perform aggregation (for final selected node)
    pub async fn collect_and_aggregate_signatures(&mut self, round: u64) -> Result<()> {
        info!(
            "🔍 [SIGNING] Final node {} waiting for signatures for round {}",
            self.id, round
        );

        // Wait a bit for signatures to arrive
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Check current signature count for this round
        let signatures_by_round = self.signatures_by_round.read().await;
        if let Some(round_signatures) = signatures_by_round.get(&round) {
            info!(
                "📊 [SIGNING] Final node {} has {} signatures for round {}",
                self.id,
                round_signatures.len(),
                round
            );
        } else {
            info!("⚠️ [SIGNING] No signatures found for round {}", round);
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
        } else {
            info!("🔄 [SIGNING] This node is the final node, no need to send signature to self");
        }

        Ok(())
    }

    /// Handle signature received by final node for specific round

    /// Handle signature received by final node for specific round
    /// Handle signature received by final node for specific round
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
            let aggregated_rounds = self.aggregated_rounds.read().await;
            aggregated_rounds.contains(&round)
        };

        if already_aggregated {
            info!(
                "⏭️ [SIGNING] Round {} already aggregated, ignoring signature from {}",
                round, from
            );
            return Ok(());
        }

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
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
            let signatures_by_round = self.signatures_by_round.read().await;
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
                        .map(|(peer, idx)| format!("{}->{}", peer, idx))
                        .collect::<Vec<_>>()
                );

                sigs_result
            })
        };

        if let Some(signatures_result) = signatures_to_aggregate {
            let signatures_vec = signatures_result?;
            let total_nodes = self
                .available_nodes
                .as_ref()
                .map(|nodes| nodes.len())
                .unwrap_or(0);
            if signatures_vec.len() >= total_nodes && total_nodes > 0 {
                // Mark this round as aggregated to prevent future aggregations
                {
                    let mut aggregated_rounds = self.aggregated_rounds.write().await;
                    aggregated_rounds.insert(round);
                }

                info!(
                    "✅ [SIGNING] All nodes participated! {} signatures collected for round {} (total_nodes: {}), starting aggregation",
                    signatures_vec.len(), round, total_nodes
                );

                // Perform aggregation
                match self.aggregate_signatures(signatures_vec).await {
                    Ok(aggregated_signature) => {
                        info!(
                            "🎉 [SIGNING] Signature aggregation completed successfully for round {}!",
                            round
                        );

                        // Log the aggregated signature details
                        let (recovery_id, signature_bytes) =
                            aggregated_signature.serialize_compact();
                        let v: u64 = recovery_id.to_i32() as u64 + 35 + 1043 * 2;
                        let r = &signature_bytes[0..32];
                        let s = &signature_bytes[32..64];

                        info!(
                            "🔐 [SIGNING] Aggregated signature components for round {}:",
                            round
                        );
                        info!("  v: {}", v);
                        info!("  r: 0x{}", hex::encode(r));
                        info!("  s: 0x{}", hex::encode(s));
                        info!("  recovery_id: {}", recovery_id.to_i32());
                        info!("  full_signature: 0x{}", hex::encode(signature_bytes));
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to aggregate signatures for round {}: {}",
                            round, e
                        );
                        return Err(e);
                    }
                }
            } else {
                info!(
                    "⏳ [SIGNING] Waiting for more signatures for round {}: {}/{}",
                    round,
                    signatures_vec.len(),
                    self.threshold
                );
            }
        }

        Ok(())
    }

    /// Handle signature received on the signatures-to-final-node topic
    pub async fn handle_signature_to_final_node(
        &mut self,
        from: String,
        signature: ECDSASignature,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} on signatures-to-final-node topic",
            self.id, from
        );

        // Get the round from the final nodes by round map
        let round_to_handle = {
            let final_nodes = self.final_nodes_by_round.read().await;
            final_nodes.iter().find_map(|(round, final_node_id)| {
                info!(
                    "🔍 [SIGNING] Checking final node {} for round {}",
                    final_node_id, round
                );
                info!(
                    "🔍 [SIGNING] Current round: {} Next round: {}",
                    self.curr_round, self.next_round
                );
                if final_node_id == &self.id && *round == self.curr_round {
                    Some(*round)
                } else {
                    None
                }
            })
        };

        if let Some(round) = round_to_handle {
            return self
                .handle_signature_for_round(from, signature, round)
                .await;
        }

        info!("⚠️ [SIGNING] Received signature but this node is not the final node for any round");
        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }

    /// Debug function to test ECDSA signature handling
    pub async fn test_ecdsa_signature_handling(&mut self) -> Result<()> {
        info!(
            "🧪 [DEBUG] Testing ECDSA signature handling for node {}",
            self.id
        );

        // Create a test signature
        let test_signature = ECDSASignature {
            signature: vec![1, 2, 3, 4, 5], // Dummy signature
            signer_id: "test_signer".to_string(),
            // message_hash: vec![10, 20, 30, 40], // Dummy hash
            recovery_id: 0,
        };

        // Test the handle_ecdsa_signature function directly
        self.handle_ecdsa_signature("test_signer".to_string(), test_signature)
            .await?;

        info!("✅ [DEBUG] ECDSA signature handling test completed successfully");
        Ok(())
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
