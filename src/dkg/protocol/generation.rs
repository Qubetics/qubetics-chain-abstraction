use crate::dkg::{artifacts::DKGMessage, DKGNode};
use crate::types::dkg::MSG_TOPIC_DKG;
use crate::types::{
    ChannelMessage, GossipsubMessage, KeyShare, SerializablePoint, SerializableScalar,
};
use crate::NodeMembership;
use anyhow::Result;
use ff::Field;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use tokio::time::Duration;
use tracing::info;

impl DKGNode {
    pub async fn start_dkg(&mut self, node_manager: Box<dyn NodeMembership>) -> Result<()> {
        info!(
            "🚀 Starting DKG for node {} with threshold {} and total nodes {}",
            self.id, self.threshold, self.total_nodes
        );

        let polynomial = self.generate_polynomial()?;
        info!("🔢 Generated polynomial: {:?}", polynomial);

        // Store the polynomial for later use when new nodes join
        self.storage.set_polynomial(&polynomial).await?;
        info!("💾 Stored polynomial for future share generation");

        let shares = self.generate_shares(&polynomial)?;
        let commitments = self.generate_commitments(&polynomial)?;

        self.status = crate::dkg::artifacts::DKGStatus::Started;
        info!("📤 Broadcasting DKG shares and commitments...");
        tokio::time::sleep(Duration::from_secs(1)).await;
        {
            let my_shares = shares.clone();
            let my_commitments = commitments.clone();
            // This will verify, store in database
            // and even send you a local "validation" message if you want.
            self.handle_share_distribution(
                self.id.clone(),
                my_shares,
                my_commitments,
                node_manager,
            )
            .await?;
        }
        self.broadcast_shares(shares, commitments).await?;
        Ok(())
    }

    pub(crate) fn generate_polynomial(&self) -> Result<Vec<Scalar>> {
        let mut rng = OsRng;
        let mut coefficients = Vec::with_capacity(self.threshold);

        for _ in 0..self.threshold {
            coefficients.push(Scalar::random(&mut rng));
        }

        info!(
            "🔢 Generated polynomial with {} coefficients {:?}",
            coefficients.len(),
            coefficients
                .iter()
                .map(|c| format!("{:?}", c))
                .collect::<Vec<String>>()
        );
        Ok(coefficients)
    }

    pub(crate) fn generate_shares(&self, polynomial: &[Scalar]) -> Result<Vec<KeyShare>> {
        info!("🔍 [DKG] === SECRET SHARE GENERATION ===");
        info!(
            "📊 [DKG] Node {} generating shares for {} nodes",
            self.id, self.total_nodes
        );
        info!(
            "🔢 [DKG] Node {} polynomial coefficients: {:?}",
            self.id, polynomial
        );

        let mut shares = Vec::with_capacity(self.total_nodes);

        info!("🔍 [DKG] Generating shares for each index:");
        for i in 1..=self.total_nodes {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;

            info!("🔍 [DKG] Calculating share for index {} (x = {:?})", i, x);

            for (j, coeff) in polynomial.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                let term = *coeff * x_pow;
                y += term;
                info!(
                    "🔍 [DKG]   Term {}: coeff[{}] * x^{} = {:?} * {:?}^{} = {:?}",
                    j, j, j, coeff, x, j, term
                );
            }

            info!("🔍 [DKG] Final share for index {}: y = {:?}", i, y);

            shares.push(KeyShare {
                index: i,
                value: SerializableScalar(y),
            });
        }

        info!("🔍 [DKG] === GENERATED SHARES SUMMARY ===");
        for (i, share) in shares.iter().enumerate() {
            info!(
                "🔍 [DKG] Share {}: index={}, value={:?}",
                i + 1,
                share.index,
                share.value.0
            );
        }
        info!("🔍 [DKG] === END GENERATED SHARES SUMMARY ===");

        info!(
            "✅ [DKG] Node {} generated {} shares",
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
        info!("🔢 [REFRESH] Polynomial coefficients: {:?}", polynomial);

        let mut shares = Vec::with_capacity(indices.len());

        for &index in indices {
            let x = Scalar::from(index as u64);
            let mut y = Scalar::ZERO;

            info!(
                "🔍 [REFRESH] Calculating share for index {} (x = {:?})",
                index, x
            );

            for (j, coeff) in polynomial.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                let term = *coeff * x_pow;
                y += term;
            }

            info!("🔍 [REFRESH] Final share for index {}: y = {:?}", index, y);

            shares.push(KeyShare {
                index,
                value: SerializableScalar(y),
            });
        }

        info!("🔍 [REFRESH] === GENERATED REFRESH SHARES SUMMARY ===");
        for share in shares.iter() {
            info!(
                "🔍 [REFRESH] Share: index={}, value={:?}",
                share.index, share.value.0
            );
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

    async fn broadcast_shares(
        &self,
        shares: Vec<KeyShare>,
        commitments: Vec<SerializablePoint>,
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
}
