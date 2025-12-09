use crate::dkg::{artifacts::DKGMessage, DKGNode};
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{ChannelMessage, GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar};
use crate::NodeMembership;
use anyhow::Result;
use ff::Field;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap;
use tokio::time::Duration;
use tracing::{info, warn};

impl DKGNode {
    pub async fn start_dkg(&mut self, _node_manager: Box<dyn NodeMembership>) -> Result<()> {
        info!(
            "🚀 Starting DKG for node {} with threshold {} and total nodes {}",
            self.id,
            self.threshold(),
            self.total_nodes()
        );

        let polynomial = self.generate_polynomial()?;
        info!("🔢 Generated polynomial: {:?}", polynomial);

        // Store the polynomial for later use when new nodes join
        self.storage.set_polynomial(&polynomial).await?;
        info!("💾 Stored polynomial for future share generation");

        let shares = self.generate_shares(&polynomial)?;
        let commitments = self.generate_commitments(&polynomial)?;

        self.transition_status(crate::dkg::artifacts::DKGStatus::Started)?;
        info!("📤 Distributing DKG shares securely via P2P...");
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Handle our own share locally first
        {
            let my_index = self.storage.get_peer_index_for(&self.id).unwrap_or(None);
            if let Some(idx) = my_index {
                if let Some(my_share) = shares.iter().find(|s| s.index == idx) {
                    info!("🔐 [DKG] Processing own share locally (index {})", idx);
                    self.storage.store_share(&self.id, my_share).await?;
                    let raw_commitments: Vec<AffinePoint> = commitments.iter().map(|c| c.0).collect();
                    self.storage.store_commitments(&self.id, &raw_commitments).await?;
                    
                    // Self-validation
                    self.storage.add_validation(&self.id, &self.id, true).await?;
                }
            }
        }

        // Get peer indices for secure distribution
        let peer_indices = self.storage.get_peer_indices().await?;
        
        self.distribute_shares_to_peers(shares, commitments.clone(), peer_indices).await?;
        
        self.broadcast_commitments_only(commitments).await?;
        
        Ok(())
    }


    async fn distribute_shares_to_peers(
        &self,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
        peer_indices: HashMap<String, usize>,
    ) -> Result<()> {
        info!("🔐 [DKG-SECURE] === DISTRIBUTING SHARES VIA UNICAST ===");
        info!("🔐 [DKG-SECURE] Sending each share ONLY to its intended recipient");
        info!("🔐 [DKG-SECURE] peer_indices has {} entries: {:?}", peer_indices.len(), peer_indices);
        
        let round = self.current_round();
        
        // Build reverse mapping: index -> peer_id
        let index_to_peer: HashMap<usize, String> = peer_indices
            .iter()
            .map(|(peer_id, &idx)| (idx, peer_id.clone()))
            .collect();
        
        info!("🔐 [DKG-SECURE] index_to_peer mapping: {:?}", index_to_peer);
        info!("🔐 [DKG-SECURE] shares to distribute: {:?}", shares.iter().map(|s| s.index).collect::<Vec<_>>());
        
        for share in shares {
            // Skip our own share (already handled locally)
            if let Some(my_index) = self.storage.get_peer_index_for(&self.id).unwrap_or(None) {
                if share.index == my_index {
                    info!("🔐 [DKG-SECURE] Skipping own share (index {})", share.index);
                    continue;
                }
            }
            
            // Find the peer for this share index
            if let Some(target_peer_id) = index_to_peer.get(&share.index) {
                info!(
                    "📤 [DKG-SECURE] UNICAST share index {} -> peer {} (NOT broadcast!)",
                    share.index, target_peer_id
                );
                
                // Send via channel message to unicast 
                let send_msg = ChannelMessage::UnicastShareDKG {
                    target_peer_id: target_peer_id.clone(),
                    from_node_id: self.id.clone(),
                    share_index: share.index,
                    share_value: share.value.clone(),
                    commitments: commitments.clone(),
                    round,
                    retry_count: 0,
                };
                
                if let Err(e) = self.message_tx.send(send_msg).await {
                    warn!(
                        "❌ [DKG-SECURE] Failed to send share to {}: {}",
                        target_peer_id, e
                    );
                } else {
                    info!(
                        "✅ [DKG-SECURE] Share for index {} queued for unicast to {}",
                        share.index, target_peer_id
                    );
                }
            } else {
                warn!(
                    "⚠️ [DKG-SECURE] No peer found for share index {} in peer_indices",
                    share.index
                );
            }
        }
        
        info!("🔐 [DKG-SECURE] === SHARE DISTRIBUTION COMPLETE ===");
        Ok(())
    }

    /// SAFE: Broadcast only the commitments (public, for verification)
    /// Individual shares are sent privately via distribute_shares_to_peers
    async fn broadcast_commitments_only(&self, commitments: Vec<SerializablePoint>) -> Result<()> {
        let round = self.current_round();
        
        let dkg_msg = DKGMessage::CommitmentBroadcast {
            from: self.id.clone(),
            commitments,
            round,
        };

        let gossip_wrap = GossipsubMessage::DKG(dkg_msg);
        let msg_bytes = serde_json::to_vec(&gossip_wrap)?;
        
        info!(
            "📡 [DKG-SECURE] Broadcasting COMMITMENTS ONLY: {} bytes (shares sent privately)",
            msg_bytes.len()
        );
        self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
        Ok(())
    }

    pub(crate) fn generate_polynomial(&self) -> Result<Vec<Scalar>> {
        let mut rng = OsRng;
        let threshold = self.threshold();
        let mut coefficients = Vec::with_capacity(threshold);

        for _ in 0..threshold {
            coefficients.push(Scalar::random(&mut rng));
        }

        info!(
            "🔢 Generated polynomial with {} coefficients {:?}",
            coefficients.len(),
            coefficients
                .iter()
                .map(|c| format!("{c:?}"))
                .collect::<Vec<String>>()
        );
        Ok(coefficients)
    }

    pub(crate) fn generate_shares(&self, polynomial: &[Scalar]) -> Result<Vec<KeyShare>> {
        info!("🔍 [DKG] === SECRET SHARE GENERATION ===");
        info!(
            "📊 [DKG] Node {} generating shares for {} nodes",
            self.id,
            self.total_nodes()
        );

        let mut shares = Vec::with_capacity(self.total_nodes());

        for i in 1..=self.total_nodes() {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;

            for (j, coeff) in polynomial.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                let term = *coeff * x_pow;
                y += term;
            }

            shares.push(KeyShare {
                index: i,
                value: SerializableScalar(y),
            });
        }

        info!(
            "✅ [DKG] Node {} generated {} shares (will be sent via UNICAST)",
            self.id,
            shares.len()
        );
        info!("🔍 [DKG] === END SECRET SHARE GENERATION ===");
        Ok(shares)
    }

    pub(crate) fn generate_shares_for_indices(
        &self,
        polynomial: &[Scalar],
        indices: &[usize],
    ) -> Result<Vec<KeyShare>> {
        info!("🔍 [REFRESH] === REFRESH SHARE GENERATION FOR SPECIFIC INDICES ===");
        info!(
            "📊 [REFRESH] Node {} generating shares for indices: {:?}",
            self.id, indices
        );

        let mut shares = Vec::with_capacity(indices.len());

        for &index in indices {
            let x = Scalar::from(index as u64);
            let mut y = Scalar::ZERO;

            for (j, coeff) in polynomial.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                let term = *coeff * x_pow;
                y += term;
            }

            shares.push(KeyShare {
                index,
                value: SerializableScalar(y),
            });
        }

        info!("🔍 [REFRESH] === GENERATED REFRESH SHARES SUMMARY ===");
        for share in shares.iter() {
            info!("🔍 [REFRESH] Share generated for index {}", share.index);
        }

        Ok(shares)
    }

    pub(crate) fn generate_commitments(
        &self,
        polynomial: &[Scalar],
    ) -> Result<Vec<SerializablePoint>> {
        let commitments: Vec<SerializablePoint> = polynomial
            .iter()
            .map(|coeff| SerializablePoint(AffinePoint::from(ProjectivePoint::GENERATOR * *coeff)))
            .collect();

        info!("🔐 Generated {} commitments", commitments.len());
        Ok(commitments)
    }
}

