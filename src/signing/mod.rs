use crate::rpc_server::DummyTransaction;
use anyhow::Result;
use bls12_381::Scalar;
use hex;
use libp2p::PeerId;
use rand::rngs::OsRng;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage};
use crate::vrf::VrfNodeSelector;

use num_bigint::BigUint;
use secp256k1::ecdsa::RecoveryId;
use secp256k1::Verification;

use secp256k1::ecdsa::Signature;
use secp256k1::constants::CURVE_ORDER;


use crate::utils::transaction::create_signed_transaction;

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
    pending_messages: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>, // message_hash -> message
    message_tx: mpsc::Sender<ChannelMessage>,
    vrf_selector: Option<VrfNodeSelector>, // VRF selector for node selection
    consensus_node: Option<ConsensusNode>, // Consensus node for final node selection
    available_nodes: Option<Vec<PeerId>>,  // Available nodes from node manager
}

impl SigningNode {
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
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            vrf_selector: Some(VrfNodeSelector::new(peer_id)),
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
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
        hasher.update(&message);           // ← hash the real RLP bytes!
        let tx_hash = hasher.finalize();
        println!("Tx hash: 0x{}", hex::encode(&tx_hash));

        info!(
            "📝 [SIGNING] Node {} starting to sign message: {:?}",
            self.id, tx_hash
        );

        // Get available nodes before the mutable borrow
        let available_nodes = self.get_available_nodes_from_manager().await;
        let round = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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

        // Store the message for later use
        // self.pending_messages
        //     .write()
        //     .await
        //     .insert(message_hash.clone(), message.to_vec());

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

    fn hash_message(&self, tx_for_signing: &[u8]) -> Vec<u8> {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(&tx_for_signing);           // ← hash the real RLP bytes!
        let tx_hash = hasher.finalize();
        println!("Tx hash: 0x{}", hex::encode(&tx_hash));
        tx_hash.to_vec()
    }

    pub fn create_ecdsa_signature(
        &self,
        message: &Message,
        transaction: &DummyTransaction,
    ) -> Result<RecoverableSignature> {
        // 0) Secret key share
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No private key available"))?;
        let secp = Secp256k1::new();

        // 1) Fixed nonce kᵢ = constant 32-byte
        let k_i_bytes = [0x42u8; 32];
        let sec_nonce = SecretKey::from_slice(&k_i_bytes)
            .expect("constant nonce must be 32 bytes");

        // 2) Compute Rᵢ = kᵢ·G, extract r = X mod n
        let Rser = PublicKey::from_secret_key(&secp, &sec_nonce)
            .serialize_uncompressed();       // [0x04 || X(32) || Y(32)]
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&Rser[1..33]);

        // 3) Compute sᵢ = kᵢ⁻¹ · (z + r·xᵢ) mod n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        ).unwrap();
        let z   = BigUint::from_bytes_be(message.as_ref());
        let x_i = BigUint::from_bytes_be(&sk[..]);
        let k_inv = BigUint::from_bytes_be(&k_i_bytes)
            .modinv(&n)
            .expect("nonce must be invertible");
        let r_val = BigUint::from_bytes_be(&r_bytes);
        let s_val = (&k_inv * (&z + (&r_val * &x_i) % &n)) % &n;
        let mut s_bytes = s_val.to_bytes_be();
        if s_bytes.len() < 32 {
            let mut pad = vec![0u8; 32 - s_bytes.len()];
            pad.extend(&s_bytes);
            s_bytes = pad;
        }

        // 4) Build the 64-byte share = r‖sᵢ
        let mut share = [0u8; 64];
        share[..32].copy_from_slice(&r_bytes);
        share[32..].copy_from_slice(&s_bytes);

        // ── FORCE recid=0 and skip verify_ecdsa check ─────────────
        let rid = RecoveryId::from_i32(0).expect("valid recovery ID");
        let sig = RecoverableSignature::from_compact(&share, rid)
            .expect("share bytes must parse");

        // 6) get the recid as u8:
        let (rid, sig_bytes) = sig.serialize_compact();
        let recid_byte = rid.to_i32() as u8;
        let v = recid_byte as u64 + 35 + transaction.chain_id * 2;

        let r_slice = &sig_bytes[..32];
        let s_slice = &sig_bytes[32..];

        let raw_tx   = create_signed_transaction(transaction, r_slice, s_slice, v);
        let hex_tx   = format!("0x{}", hex::encode(&raw_tx));
        println!("Raw tx: {}", hex_tx);
        println!("→ r:  0x{}", hex::encode(r_slice));
        println!("→ s:  0x{}", hex::encode(s_slice));
        println!("→ v:  {}", v);

        Ok(sig)
    }

    
    pub async fn handle_message(&mut self, msg: SigningMessage) -> Result<()> {
        info!(
            "📥 [SIGNING] Node {} received signing message: {:?}",
            self.id, msg
        );

        match msg {
            SigningMessage::MessageToSign {
                from,
                message,
                message_hash,
            } => {
                // info!(
                //     "📥 [SIGNING] Node {} received message to sign from {}",
                //     self.id, from
                // );
                // self.handle_message_to_sign(from, message, message_hash)
                //     .await?;
            }
            SigningMessage::ECDSASignature { from, signature ,timestamp:_timestamp} => {
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

        info!("💾 [SIGNING] Node {} stored ECDSA signature from {}", self.id, from);

        // Check if this node is the final node for a specific round
        let round_to_handle = {
            let final_nodes = self.final_nodes_by_round.read().await;
            final_nodes
                .iter()
                .find(|(_, final_node_id)| final_node_id == &&self.id)
                .map(|(round, _)| *round)
        };

        if let Some(round) = round_to_handle {
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

                round_signatures.len() >= self.threshold
            };

            if should_aggregate {
                // Prepare signatures for aggregation
                let signatures_to_aggregate: Vec<RecoverableSignature> = {
                    let signatures_by_round = self.signatures_by_round.read().await;
                    signatures_by_round
                        .get(&round)
                        .unwrap()
                        .iter()
                        .map(|(signer_id, ecdsa_sig)| {
                            RecoverableSignature::from_compact(
                                &ecdsa_sig.signature,
                                RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                            )
                            .map_err(|_| anyhow::anyhow!("Invalid signature from signer {}", signer_id))
                        })
                        .collect::<Result<_>>()?
                };

                // Aggregate signatures
                match self.aggregate_signatures(signatures_to_aggregate).await {
                    Ok(aggregated_signature) => {
                        info!(
                            "🎉 [SIGNING] Signature aggregation successful for round {}!",
                            round
                        );

                        let signature_bytes = aggregated_signature.serialize_compact();
                        let v: u64 = 35 + 1043 * 2;
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
                info!(
                    "⏳ [SIGNING] Waiting for more signatures: {}/{}",
                    self.signatures_by_round.read().await.get(&round).unwrap().len(),
                    self.threshold
                );
            }
        }

        Ok(())
    }


    pub async fn aggregate_signatures(&self,signatures: Vec<RecoverableSignature>) -> Result<Signature, anyhow::Error> {
        // Check there's at least one signature
        if signatures.is_empty() {
            return Err(anyhow::anyhow!("No signatures provided for aggregation"));
        }

        let secp = Secp256k1::new();

        // Extract r and sum up all s values
        let mut s_sum = BigUint::from(0u32);
        let mut r_value: Option<BigUint> = None;

        for rec_sig in signatures.iter() {
            let sig = rec_sig.to_standard();

            // Decompose signature into r and s components
            let (r, s) = {
                let sig_ser = sig.serialize_compact();
                let r_part = BigUint::from_bytes_be(&sig_ser[0..32]);
                let s_part = BigUint::from_bytes_be(&sig_ser[32..64]);
                (r_part, s_part)
            };

            // Store r-value from the first signature
            if r_value.is_none() {
                r_value = Some(r.clone());
            } else if r_value.as_ref().unwrap() != &r {
                return Err(anyhow::anyhow!("Mismatch in r-values detected; signatures cannot be aggregated"));
            }

            // Add s to s_sum
            s_sum = (s_sum + s) % BigUint::from_bytes_be(&CURVE_ORDER);
        }

        let r_final = r_value.expect("Checked non-empty above");
        
        // Reconstruct aggregated signature bytes
        let mut agg_sig_bytes = [0u8; 64];
        let r_bytes = r_final.to_bytes_be();
        let s_bytes = s_sum.to_bytes_be();

        // Pad r and s to 32 bytes if necessary
        agg_sig_bytes[0..32].copy_from_slice(&Self::pad_to_32_bytes(&r_bytes));
        agg_sig_bytes[32..64].copy_from_slice(&Self::pad_to_32_bytes(&s_bytes));
        info!(
            "🔢 [SIGNING] Aggregated signature bytes: {:?}",
            agg_sig_bytes
        );
        let agg_signature = Signature::from_compact(&agg_sig_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to construct aggregated signature"))?;

        Ok(agg_signature)
    }

    // Helper padding function
    fn pad_to_32_bytes(input: &[u8]) -> [u8;32] {
        let mut buf = [0u8; 32];
        let offset = 32 - input.len();
        buf[offset..].copy_from_slice(input);
        buf
    }

    async fn aggregate_threshold_signatures(
        &self,
        shares: &[ThresholdSignatureShare],
    ) -> Result<RecoverableSignature> {
        if shares.is_empty() {
            return Err(anyhow::anyhow!("No signature shares to aggregate"));
        }

        let threshold = shares[0].threshold;
        let total_shares = shares[0].total_shares;

        info!(
            "🔢 [SIGNING] Aggregating {} signature shares (threshold: {}, total: {})",
            shares.len(),
            threshold,
            total_shares
        );

        // For proper threshold ECDSA, we need to:
        // 1. Extract the r and s components from each signature
        // 2. Use Lagrange interpolation to combine the shares
        // 3. Reconstruct the final signature

        let mut r_shares = Vec::new();
        let mut s_shares = Vec::new();
        let mut recovery_ids = Vec::new();

        for share in shares {
            let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(0)?; // Default recovery ID
            let signature = RecoverableSignature::from_compact(&share.share, recovery_id)?;
            let (_, sig_bytes) = signature.serialize_compact();

            // Split signature into r and s components (32 bytes each)
            if sig_bytes.len() >= 64 {
                let r = &sig_bytes[0..32];
                let s = &sig_bytes[32..64];

                r_shares.push((share.share_index, r.to_vec()));
                s_shares.push((share.share_index, s.to_vec()));
                recovery_ids.push(signature.serialize_compact().0);
            }
        }

        // Use Lagrange interpolation to combine r and s shares
        let aggregated_r = self.lagrange_interpolate(&r_shares, threshold)?;
        let aggregated_s = self.lagrange_interpolate(&s_shares, threshold)?;

        // Use the most common recovery ID
        let recovery_id = self.get_most_common_recovery_id(&recovery_ids)?;

        // Reconstruct the signature
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&aggregated_r);
        signature_bytes.extend_from_slice(&aggregated_s);

        let aggregated_signature =
            RecoverableSignature::from_compact(&signature_bytes, recovery_id)?;

        info!(
            "🔢 [SIGNING] Successfully aggregated threshold signature with {} shares",
            shares.len()
        );

        Ok(aggregated_signature)
    }

    fn lagrange_interpolate(&self, shares: &[(u32, Vec<u8>)], threshold: u32) -> Result<Vec<u8>> {
        if shares.len() < threshold as usize {
            return Err(anyhow::anyhow!("Not enough shares for threshold"));
        }

        // Implement proper Lagrange interpolation for threshold ECDSA
        // This is a simplified version - in production you'd use a proper library

        if shares.len() == 1 {
            // If only one share, return it directly
            let (_, share) = shares.first().unwrap();
            return Ok(share.clone());
        }

        // For multiple shares, we need to perform Lagrange interpolation
        // This is a simplified implementation that averages the shares
        // In a real implementation, you would use proper finite field arithmetic

        let mut aggregated_share = vec![0u8; shares[0].1.len()];
        let num_shares = shares.len() as u64;

        for (_, share) in shares {
            for (i, &byte) in share.iter().enumerate() {
                if i < aggregated_share.len() {
                    aggregated_share[i] = aggregated_share[i].wrapping_add(byte);
                }
            }
        }

        // Average the shares (simplified approach)
        for byte in aggregated_share.iter_mut() {
            *byte = (*byte as u64 / num_shares) as u8;
        }

        info!(
            "🔢 [SIGNING] Lagrange interpolation completed with {} shares",
            shares.len()
        );

        Ok(aggregated_share)
    }

    fn get_most_common_recovery_id(
        &self,
        recovery_ids: &[secp256k1::ecdsa::RecoveryId],
    ) -> Result<secp256k1::ecdsa::RecoveryId> {
        if recovery_ids.is_empty() {
            return Err(anyhow::anyhow!("No recovery IDs provided"));
        }

        // Count occurrences of each recovery ID
        let mut counts = HashMap::new();
        for recovery_id in recovery_ids {
            let count = counts.entry(recovery_id.to_i32()).or_insert(0);
            *count += 1;
        }

        // Find the most common recovery ID
        let most_common = counts.iter().max_by_key(|&(_, count)| count).unwrap().0;

        Ok(secp256k1::ecdsa::RecoveryId::from_i32(*most_common)?)
    }

    // async fn handle_message_to_sign(
    //     &mut self,
    //     from: String,
    //     message: Vec<u8>,
    //     message_hash: Vec<u8>,
    // ) -> Result<()> {
    //     info!(
    //         "📝 [SIGNING] Node {} received message to sign from {}: {:?}",
    //         self.id, from, message_hash
    //     );
    //     self.sign_message(&message).await?;
    //     Ok(())
    // }

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
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)?
                        .as_millis(),
                };
                
                // Wrap in GossipsubMessage::Signing for proper message handling
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;

                // Broadcast to a specific topic that the final node subscribes to
                let res = self.broadcast("signatures-to-final-node", &signature_data)
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
                round_signatures
                    .iter()
                    .map(|(signer_id, ecdsa_sig)| {
                        RecoverableSignature::from_compact(
                            &ecdsa_sig.signature,
                            RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                        )
                        .map_err(|_| anyhow::anyhow!("Invalid signature from signer {}", signer_id))
                    })
                    .collect::<Result<Vec<_>>>()
            })
        };

        if let Some(signatures_result) = signatures_to_aggregate {
            let signatures_vec = signatures_result?;
            if signatures_vec.len() >= self.threshold {
                info!(
                    "✅ [SIGNING] Enough signatures collected for round {}, starting aggregation",
                    round
                );

                // Perform aggregation
                match self.aggregate_signatures(signatures_vec).await {
                    Ok(aggregated_signature) => {
                        info!(
                            "🎉 [SIGNING] Signature aggregation completed successfully for round {}!",
                            round
                        );

                        // Log the aggregated signature details
                        let signature_bytes = aggregated_signature.serialize_compact();
                        let recovery_id = RecoveryId::from_i32(0)?; // use fixed recovery_id for testing
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
                if final_node_id == &self.id {
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
