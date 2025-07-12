use anyhow::Result;
use bls12_381::{G1Affine, G1Projective, Scalar};
use ethers::core::k256::ecdsa::Error;
use ff::Field;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{any, usize};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::info;

use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{
    ChannelMessage, GossipsubMessage, KeyShare, SerializableG1Affine, SerializableScalar,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DKGMessage {
    ShareDistribution {
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializableG1Affine>,
    },
    ShareValidation {
        from: String,
        to: String,
        is_valid: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DKGStatus {
    New,
    Error { kind: String },
    Started,
    Completed,
}

pub type DKGCompletionCallback = Box<dyn Fn(Scalar, G1Projective) + Send + Sync>;

pub struct DKGNode {
    id: String,
    status: DKGStatus,
    threshold: usize,
    total_nodes: usize,
    shares: RwLock<HashMap<String, KeyShare>>,
    commitments: RwLock<HashMap<String, Vec<G1Affine>>>,
    validations: RwLock<HashMap<String, Vec<bool>>>,
    message_tx: mpsc::Sender<ChannelMessage>,
    final_secret_share: RwLock<Option<Scalar>>,
    final_public_key: RwLock<Option<G1Projective>>,
    completion_callback: Option<DKGCompletionCallback>,
}

impl DKGNode {
    pub fn new(
        id: String,
        threshold: usize,
        total_nodes: usize,
        message_tx: mpsc::Sender<ChannelMessage>,
    ) -> Self {
        Self {
            id,
            status: DKGStatus::New,
            threshold,
            total_nodes,
            shares: RwLock::new(HashMap::new()),
            commitments: RwLock::new(HashMap::new()),
            validations: RwLock::new(HashMap::new()),
            message_tx,
            final_secret_share: RwLock::new(None),
            final_public_key: RwLock::new(None),
            completion_callback: None,
        }
    }

    pub fn set_completion_callback(&mut self, callback: DKGCompletionCallback) {
        self.completion_callback = Some(callback);
        info!("🔗 [DKG] Node {} set completion callback", self.id);
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

    pub fn get_status(&self) -> DKGStatus {
        self.status.clone()
    }

    pub async fn start_dkg(&mut self) -> Result<()> {
        info!(
            "🚀 Starting DKG for node {} with threshold {} and total nodes {}",
            self.id, self.threshold, self.total_nodes
        );

        let polynomial = self.generate_polynomial()?;
        let shares = self.generate_shares(&polynomial)?;
        let commitments = self.generate_commitments(&polynomial)?;

        self.status = DKGStatus::Started;
        info!("📤 Broadcasting DKG shares and commitments...");
        self.broadcast_shares(shares, commitments).await?;
        Ok(())
    }

    fn generate_polynomial(&self) -> Result<Vec<Scalar>> {
        let mut rng = OsRng;
        let mut coefficients = Vec::with_capacity(self.threshold);

        for _ in 0..self.threshold {
            coefficients.push(Scalar::random(&mut rng));
        }

        info!(
            "🔢 Generated polynomial with {} coefficients",
            coefficients.len()
        );
        Ok(coefficients)
    }

    pub fn update_node_params(&mut self, total_nodes: usize, threshold: usize) {
        info!(
            "🔄 Updating DKGNode params: total_nodes = {}, threshold = {}",
            total_nodes, threshold
        );
        self.total_nodes = total_nodes;
        self.threshold = threshold;
    }

    fn generate_shares(&self, polynomial: &[Scalar]) -> Result<Vec<KeyShare>> {
        info!("📊 Generating shares for {} nodes", self.total_nodes);

        let mut shares = Vec::with_capacity(self.total_nodes);

        for i in 1..=self.total_nodes {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::zero();

            for (j, coeff) in polynomial.iter().enumerate() {
                y += *coeff * x.pow(&[j as u64, 0, 0, 0]);
            }

            shares.push(KeyShare {
                index: i,
                value: SerializableScalar(y),
            });
        }
        info!("✅ Generated {} shares", shares.len());
        Ok(shares)
    }

    fn generate_commitments(&self, polynomial: &[Scalar]) -> Result<Vec<SerializableG1Affine>> {
        let commitments: Vec<SerializableG1Affine> = polynomial
            .iter()
            .map(|coeff| SerializableG1Affine(G1Affine::from(G1Projective::generator() * coeff)))
            .collect();

        info!("🔐 Generated {} commitments", commitments.len());
        Ok(commitments)
    }

    async fn broadcast_shares(
        &self,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializableG1Affine>,
    ) -> Result<()> {
        let dkg_msg = DKGMessage::ShareDistribution {
            from: self.id.clone(),
            shares,
            commitments,
        };

        let gossip_wrap = GossipsubMessage::DKG(dkg_msg);

        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        info!("📡 Broadcasting DKG message: {} bytes", msg_bytes.len());
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        Ok(())
    }

    pub async fn handle_message(&mut self, msg: DKGMessage) -> Result<()> {
        match msg {
            DKGMessage::ShareDistribution {
                from,
                shares,
                commitments,
            } => {
                info!("📥 Received share distribution from {}", from);
                self.handle_share_distribution(from, shares, commitments)
                    .await?;
            }
            DKGMessage::ShareValidation { from, to, is_valid } => {
                info!(
                    "✅ Received share validation from {} to {}: {}",
                    from, to, is_valid
                );
                self.handle_share_validation(from, to, is_valid).await?;
            }
        }
        Ok(())
    }

    async fn handle_share_distribution(
        &mut self,
        from: String,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializableG1Affine>,
    ) -> Result<()> {
        let raw_commitments: Vec<G1Affine> = commitments.into_iter().map(|c| c.0).collect();

        let node_index = self.get_node_index();

        info!(
            "🔍 Looking for share with index {} in {} shares",
            node_index,
            shares.len()
        );

        if self.verify_shares(&shares, &raw_commitments) {
            let my_share = shares.into_iter().find(|s| s.index == node_index);
            if let Some(share) = my_share {
                info!("✅ Found valid share for node {} from {}", self.id, from);
                self.shares.write().await.insert(from.clone(), share);
                self.commitments
                    .write()
                    .await
                    .insert(from.clone(), raw_commitments);

                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: true,
                };
                let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
                let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
                self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
            } else {
                info!(
                    "❌ Share for index {} not found in shares from {}",
                    node_index, from
                );
                let validation_msg = DKGMessage::ShareValidation {
                    from: self.id.clone(),
                    to: from,
                    is_valid: false,
                };
                let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
                let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
                self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
            }
        } else {
            info!("❌ Share verification failed for shares from {}", from);
            let validation_msg = DKGMessage::ShareValidation {
                from: self.id.clone(),
                to: from,
                is_valid: false,
            };
            let gossip_wrapped = GossipsubMessage::DKG(validation_msg);
            let msg_bytes = serde_json::to_vec(&gossip_wrapped)?;
            self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        }
        Ok(())
    }

    fn get_node_index(&self) -> usize {
        if let Ok(index) = self.id.parse::<usize>() {
            return index;
        }

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.id.hash(&mut hasher);
        let hash = hasher.finish();

        ((hash % self.total_nodes as u64) + 1) as usize
    }

    pub fn verify_share(
        &self,
        share: &SerializableScalar,
        commitments: &[SerializableG1Affine],
    ) -> bool {
        if commitments.is_empty() {
            return false;
        }
        true
    }

    pub fn verify_shares(&self, shares: &[KeyShare], commitments: &[G1Affine]) -> bool {
        if shares.is_empty() || commitments.is_empty() {
            return false;
        }

        for share in shares {
            let x = Scalar::from(share.index as u64);
            let mut expected = G1Projective::identity();

            for (j, commitment) in commitments.iter().enumerate() {
                expected += G1Projective::from(*commitment) * x.pow(&[j as u64, 0, 0, 0]);
            }

            let actual = G1Projective::generator() * share.value.0;
            if expected != actual {
                info!("❌ Share verification failed for index {}", share.index);
                return false;
            }
        }

        info!("✅ All shares verified successfully");
        true
    }

    async fn handle_share_validation(
        &mut self,
        from: String,
        to: String,
        is_valid: bool,
    ) -> Result<()> {
        {
            let mut validations = self.validations.write().await;
            validations
                .entry(to.clone())
                .or_insert_with(Vec::new)
                .push(is_valid);

            info!("📊 Validation from {} to {}: {}", from, to, is_valid);
        } // validations lock guard dropped here
        self.check_completion().await?;
        Ok(())
    }

    async fn check_completion(&mut self) -> Result<()> {
        let (shares_len, validations_len, valid_validations) = {
            let validations = self.validations.read().await;
            let shares = self.shares.read().await;
            let valid_validations: usize = validations
                .values()
                .map(|v| v.iter().filter(|&&valid| valid).count())
                .sum();
            (shares.len(), validations.len(), valid_validations)
        }; // lock guards dropped here

        info!(
            "🔍 Checking DKG completion - shares: {}, validations: {}",
            shares_len, validations_len
        );

        if valid_validations >= self.threshold && shares_len >= self.threshold {
            info!("🎉 DKG completion criteria met! Generating final keys...");
            self.generate_group_key().await?;
        } else {
            info!(
                "⏳ DKG not yet complete - need {} validations and {} shares, have {} and {}",
                self.threshold, self.threshold, valid_validations, shares_len
            );
        }
        Ok(())
    }

    async fn generate_group_key(&mut self) -> Result<()> {
        let shares = self.shares.read().await;
        let commitments = self.commitments.read().await;

        // Calculate final secret share (sum of all received shares)
        let mut final_secret_share = Scalar::zero();
        for share in shares.values() {
            final_secret_share += share.value.0;
        }

        // Calculate final public key (sum of all commitment constant terms)
        let mut final_public_key = G1Projective::identity();
        for comms in commitments.values() {
            if !comms.is_empty() {
                final_public_key += G1Projective::from(comms[0]);
            }
        }

        // Store the results
        *self.final_secret_share.write().await = Some(final_secret_share);
        *self.final_public_key.write().await = Some(final_public_key);

        // Update status
        self.status = DKGStatus::Completed;

        // Log the final results
        info!("🎯 DKG COMPLETED for node {}!", self.id);
        info!("🔐 Final secret share: {:?}", final_secret_share);
        info!("🔑 Final public key: {:?}", final_public_key);
        info!("📊 Total shares collected: {}", shares.len());
        info!("✅ DKG status: {:?}", self.status);

        // Log all collected shares for debugging
        for (from, share) in shares.iter() {
            info!(
                "📋 Share from {}: index={}, value={:?}",
                from, share.index, share.value.0
            );
        }

        if let Some(callback) = self.completion_callback.take() {
            callback(final_secret_share, final_public_key);
        }

        Ok(())
    }

    pub async fn get_final_secret_share(&self) -> Option<Scalar> {
        self.final_secret_share.read().await.clone()
    }

    pub async fn get_final_public_key(&self) -> Option<G1Projective> {
        self.final_public_key.read().await.clone()
    }

    pub async fn is_completed(&self) -> bool {
        matches!(self.status, DKGStatus::Completed)
    }
}
