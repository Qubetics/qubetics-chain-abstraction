use std::collections::HashMap;
use anyhow::Result;
use blstrs::{G1Projective, G1Affine, G2Affine, Scalar, pairing};
use group::{Curve, Group};
use group::prime::PrimeCurveAffine;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tokio::sync::{RwLock, mpsc};
use tracing::log::{info, error};

use crate::types::{ChannelMessage, GossipsubMessage, KeyShare};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableScalar(pub Scalar);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableG1Affine(pub G1Affine);

impl From<G1Projective> for SerializableG1Affine {
    fn from(p: G1Projective) -> Self {
        SerializableG1Affine(p.to_affine())
    }
}

impl From<&SerializableG1Affine> for G1Projective {
    fn from(sig: &SerializableG1Affine) -> G1Projective {
        G1Projective::from(sig.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    pub index: usize,
    pub signature: SerializableG1Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    PartialSignature(SignatureShare),
    AggregatedSignature(SerializableG1Affine),
}

/// Signing Node structure for BLS Threshold Signing
pub struct SigningNode {
    id: String,
    threshold: usize,
    key_share: KeyShare,
    group_key: G2Affine,
    received_signatures: RwLock<HashMap<usize, SignatureShare>>,
    message_tx: mpsc::Sender<ChannelMessage>,
}

impl SigningNode {
    pub fn new(
        id: String,
        threshold: usize,
        key_share: KeyShare,
        group_key: G2Affine,
        message_tx: mpsc::Sender<ChannelMessage>,
    ) -> Self {
        Self {
            id,
            threshold,
            key_share,
            group_key,
            received_signatures: RwLock::new(HashMap::new()),
            message_tx,
        }
    }

    /// Start signing process for given message
    pub async fn start_signing(&self, message: &[u8]) -> Result<()> {
        let sig_share = sign_message(message, &self.key_share);
        let msg = SigningMessage::PartialSignature(sig_share.clone());
        let gossip_msg = GossipsubMessage::Signing(msg);
        let encoded = serde_json::to_vec(&gossip_msg)
        .map_err(|e| anyhow::anyhow!("failed to serialize signing gossip: {:?}", e))?;
        self.broadcast("signing", &encoded).await?;
        Ok(())
    }

    pub async fn handle_message(&self, msg: SigningMessage, message_bytes: &[u8]) -> Result<()> {
        match msg {
            SigningMessage::PartialSignature(share) => {
                self.received_signatures.write().await.insert(share.index, share.clone());
                print!("[SIGNATURE] Received signature share from node {}: {:?}\n", share.index, share.signature.0);
                self.check_signature_completion(message_bytes).await?;
            }
            SigningMessage::AggregatedSignature(sig) => {
                let valid = verify_signature(message_bytes, &self.group_key, &G1Projective::from(&sig));
                if valid {
                    info!("[FINAL] Signature is valid");
                } else {
                    error!("[FINAL] Invalid signature received!");
                }
            }
        }
        Ok(())
    }

    async fn check_signature_completion(&self, message: &[u8]) -> Result<()> {
        let shares = self.received_signatures.read().await;
        info!(
            "[SIGNATURE] Received {} signature shares out of {} required",
            shares.len(),
            self.threshold
        );
        if shares.len() >= self.threshold {
            let agg = aggregate_signatures(shares.values().cloned().collect());
            let agg_msg: SigningMessage = SigningMessage::AggregatedSignature(SerializableG1Affine::from(agg));
            let wrapped_msg = GossipsubMessage::Signing(agg_msg);
            let encoded = serde_json::to_vec(&wrapped_msg)?;
            self.broadcast("signing", &encoded).await?;
        }
        Ok(())
    }

    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        self.message_tx.send(ChannelMessage::Broadcast {
            topic: topic.to_string(),
            data: data.to_vec(),
        }).await?;
        Ok(())
    }
}

/// Hash message to G1 curve
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, b"BLS_SIG_DOMAIN", &[])
}

/// Sign a message using a BLS share
pub fn sign_message(msg: &[u8], share: &KeyShare) -> SignatureShare {
    let msg_hash = hash_to_g1(msg);
    let sig = msg_hash * share.value.0;

    info!(
        "[SIGNATURE] Node index {} signed message: {:?}",
        share.index,
        sig.to_affine()
    );

    SignatureShare {
        index: share.index,
        signature: SerializableG1Affine::from(sig),
    }
}

/// Aggregate threshold number of signatures
pub fn aggregate_signatures(sigs: Vec<SignatureShare>) -> G1Projective {
    info!("[AGGREGATION] Aggregating {} signature shares...", sigs.len());

    let agg = sigs
        .iter()
        .map(|s| G1Projective::from(&s.signature))
        .fold(G1Projective::identity(), |a, b| a + b);

    info!("[AGGREGATION] Aggregated signature: {:?}", agg.to_affine());

    agg
}

/// Verify the aggregated signature
pub fn verify_signature(msg: &[u8], group_pubkey: &G2Affine, agg_sig: &G1Projective) -> bool {
    let msg_hash = hash_to_g1(msg);
    let lhs = pairing(&agg_sig.to_affine(), &G2Affine::generator());
    let rhs = pairing(&msg_hash.to_affine(), group_pubkey);

    let result = lhs == rhs;

    if result {
        info!("[VERIFY] Aggregated signature is valid.");
    } else {
        error!("[VERIFY] Aggregated signature is INVALID!");
    }

    result
}
