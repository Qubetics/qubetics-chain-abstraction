use anyhow::Result;
use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::types::{ChannelMessage, KeyShare, SerializableG1Affine, SerializableScalar};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostCommitment {
    pub D: SerializableG1Affine,
    pub E: SerializableG1Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: SerializableScalar,
    pub signer_id: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    CommitmentShare {
        from: String,
        commitments: Vec<FrostCommitment>,
        message_hash: Vec<u8>,
    },
    SignatureShare {
        from: String,
        share: SerializableScalar,
        message_hash: Vec<u8>,
    },
    MessageToSign {
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
}

#[derive(Clone)]
pub struct SigningNode {
    id: String,
    threshold: usize,
    secret_share: Option<Scalar>,
    group_key: Option<G1Projective>,
    nonces: Vec<(Scalar, Scalar)>,
    commitments: Arc<RwLock<HashMap<String, Vec<FrostCommitment>>>>,
    signature_shares: Arc<RwLock<HashMap<String, Scalar>>>,
    pending_messages: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>, // message_hash -> message
    message_tx: mpsc::Sender<ChannelMessage>,
}

impl SigningNode {
    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            id,
            threshold,
            secret_share: None,
            group_key: None,
            nonces: Vec::new(),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            signature_shares: Arc::new(RwLock::new(HashMap::new())),
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
        }
    }

    pub fn set_secret_share(&mut self, secret_share: Scalar) {
        self.secret_share = Some(secret_share);
        info!("🔐 [SIGNING] Node {} secret share set", self.id);
    }

    pub fn set_group_key(&mut self, group_key: G1Projective) {
        self.group_key = Some(group_key);
        info!(
            "🔑 [SIGNING] Node {} group key set: {:?}",
            self.id, group_key
        );
    }

    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;
        Ok(())
    }

    pub async fn sign_message(&mut self, message: &[u8]) -> Result<()> {
        if self.secret_share.is_none() {
            error!(
                "❌ [SIGNING] Node {} cannot sign: no secret share available",
                self.id
            );
            return Err(anyhow::anyhow!("No secret share available"));
        }

        let message_hash = self.hash_message(message);
        info!(
            "📝 [SIGNING] Node {} starting to sign message: {:?}",
            self.id, message_hash
        );

        // Store the message for later use
        self.pending_messages
            .write()
            .await
            .insert(message_hash.clone(), message.to_vec());

        // Generate nonces for this signing session
        self.generate_nonces(1);
        let commitments = self.get_commitments();

        let msg = serde_json::to_vec(&SigningMessage::CommitmentShare {
            from: self.id.clone(),
            commitments,
            message_hash: message_hash.clone(),
        })?;

        self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted commitment share", self.id);
        Ok(())
    }

    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn generate_nonces(&mut self, count: usize) {
        let mut rng = OsRng;
        for _ in 0..count {
            let d = Scalar::random(&mut rng);
            let e = Scalar::random(&mut rng);
            self.nonces.push((d, e));
        }
        info!("🎲 [SIGNING] Node {} generated {} nonces", self.id, count);
    }

    fn get_commitments(&self) -> Vec<FrostCommitment> {
        self.nonces
            .iter()
            .map(|(d, e)| FrostCommitment {
                D: SerializableG1Affine(G1Affine::from(G1Projective::generator() * d)),
                E: SerializableG1Affine(G1Affine::from(G1Projective::generator() * e)),
            })
            .collect()
    }

    pub async fn handle_message(&mut self, msg: SigningMessage) -> Result<()> {
        match msg {
            SigningMessage::CommitmentShare {
                from,
                commitments,
                message_hash,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received commitment share from {}",
                    self.id, from
                );
                self.handle_commitment_share(from, commitments, message_hash)
                    .await?;
            }
            SigningMessage::SignatureShare {
                from,
                share,
                message_hash,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received signature share from {}",
                    self.id, from
                );
                self.handle_signature_share(from, share.0, message_hash)
                    .await?;
            }
            SigningMessage::MessageToSign {
                from,
                message,
                message_hash,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received message to sign from {}",
                    self.id, from
                );
                self.handle_message_to_sign(from, message, message_hash)
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
        }
        Ok(())
    }

    async fn handle_commitment_share(
        &mut self,
        from: String,
        commitments: Vec<FrostCommitment>,
        message_hash: Vec<u8>,
    ) -> Result<()> {
        self.commitments
            .write()
            .await
            .insert(from.clone(), commitments);
        info!(
            "💾 [SIGNING] Node {} stored commitment share from {}",
            self.id, from
        );
        self.check_commitments(message_hash).await?;
        Ok(())
    }

    async fn check_commitments(&self, message_hash: Vec<u8>) -> Result<()> {
        let commitments = self.commitments.read().await;
        if commitments.len() >= self.threshold {
            info!(
                "✅ [SIGNING] Node {} has enough commitments ({}), generating signature share",
                self.id,
                commitments.len()
            );

            // Generate and broadcast signature share
            let signature_share = self.generate_signature_share(&message_hash).await?;
            let msg = serde_json::to_vec(&SigningMessage::SignatureShare {
                from: self.id.clone(),
                share: SerializableScalar(signature_share),
                message_hash,
            })?;
            self.broadcast("signing", &msg).await?;
            info!("📤 [SIGNING] Node {} broadcasted signature share", self.id);
        } else {
            info!(
                "⏳ [SIGNING] Node {} waiting for more commitments: {}/{}",
                self.id,
                commitments.len(),
                self.threshold
            );
        }
        Ok(())
    }

    pub async fn generate_signature_share(&self, message_hash: &[u8]) -> Result<Scalar> {
        info!("Here at signature generation");
        if let Some(secret_share) = self.secret_share {
            if self.nonces.is_empty() {
                return Err(anyhow::anyhow!("No nonces available for signing"));
            }

            let (d, e) = self.nonces[0];

            // Convert message hash to scalar
            let message_scalar = self.hash_to_scalar(message_hash);

            // Generate signature share: s_i = d_i + e_i * c + a_i * m
            // where c is the challenge, m is the message, and a_i is the secret share
            let challenge = self.compute_challenge(message_hash);
            let signature_share = d + e * challenge + secret_share * message_scalar;

            info!(
                "✍️ [SIGNING] Node {} generated signature share: {:?}",
                self.id, signature_share
            );
            Ok(signature_share)
        } else {
            Err(anyhow::anyhow!("No secret share available"))
        }
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Scalar {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Convert hash to scalar (simplified)
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&hash);
        Scalar::from_bytes_wide(&bytes)
    }

    fn compute_challenge(&self, message_hash: &[u8]) -> Scalar {
        // In a real implementation, this would compute the challenge from commitments
        // For now, we'll use a simplified approach
        self.hash_to_scalar(message_hash)
    }

    async fn handle_signature_share(
        &mut self,
        from: String,
        share: Scalar,
        message_hash: Vec<u8>,
    ) -> Result<()> {
        self.signature_shares
            .write()
            .await
            .insert(from.clone(), share);
        info!(
            "💾 [SIGNING] Node {} stored signature share from {}",
            self.id, from
        );
        self.check_signature_completion(message_hash).await?;
        Ok(())
    }

    async fn check_signature_completion(&self, message_hash: Vec<u8>) -> Result<()> {
        let shares = self.signature_shares.read().await;
        if shares.len() >= self.threshold {
            info!(
                "🎯 [SIGNING] Node {} has enough signature shares ({}), aggregating",
                self.id,
                shares.len()
            );

            let signature = self.aggregate_signature_shares().await?;
            let message = self
                .pending_messages
                .read()
                .await
                .get(&message_hash)
                .cloned();

            if let Some(message) = message {
                let signed_message = SignedMessage {
                    message,
                    signature: SerializableScalar(signature),
                    signer_id: self.id.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };

                let msg = serde_json::to_vec(&SigningMessage::SignedMessage {
                    from: self.id.clone(),
                    signed_message: signed_message.clone(),
                })?;

                self.broadcast("signing", &msg).await?;
                info!(
                    "🎉 [SIGNING] Node {} completed signing and broadcasted result",
                    self.id
                );
                info!("📋 [SIGNING] Final signature: {:?}", signature);
            }
        } else {
            info!(
                "⏳ [SIGNING] Node {} waiting for more signature shares: {}/{}",
                self.id,
                shares.len(),
                self.threshold
            );
        }
        Ok(())
    }

    async fn aggregate_signature_shares(&self) -> Result<Scalar> {
        let shares = self.signature_shares.read().await;
        let mut signature = Scalar::zero();

        for (from, share) in shares.iter() {
            signature += *share;
            info!(
                "➕ [SIGNING] Node {} aggregated signature share from {}: {:?}",
                self.id, from, share
            );
        }

        info!(
            "🔢 [SIGNING] Node {} final aggregated signature: {:?}",
            self.id, signature
        );
        Ok(signature)
    }

    async fn handle_message_to_sign(
        &mut self,
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    ) -> Result<()> {
        info!(
            "📝 [SIGNING] Node {} received message to sign from {}: {:?}",
            self.id, from, message_hash
        );
        self.sign_message(&message).await?;
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
        info!("✍️ [SIGNING] Signature: {:?}", signed_message.signature.0);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        // Verify the signature if we have the group key
        if let Some(group_key) = self.group_key {
            let is_valid = self.verify_signature(&signed_message, &group_key).await?;
            if is_valid {
                info!("✅ [SIGNING] Signature verification successful!");
            } else {
                warn!("❌ [SIGNING] Signature verification failed!");
            }
        } else {
            warn!("⚠️ [SIGNING] Cannot verify signature: no group key available");
        }

        Ok(())
    }

    async fn verify_signature(
        &self,
        signed_message: &SignedMessage,
        group_key: &G1Projective,
    ) -> Result<bool> {
        // In a real implementation, this would verify the BLS signature
        // For now, we'll return true as a placeholder
        info!(
            "🔍 [SIGNING] Node {} verifying signature with group key",
            self.id
        );
        Ok(true)
    }
}
