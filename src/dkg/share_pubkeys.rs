use super::node::DKGNode;
use crate::utils::hmac_helper::hmac_scalar_mod_n;
use crate::utils::get_eth_address_from_group_key;
use anyhow::{anyhow, Result};
use ff::PrimeField;
use k256::{ProjectivePoint, Scalar};
use tracing::info;

impl DKGNode {
    /// Compute and store all share public keys for all peers
    /// This includes:
    /// - Network share pubkeys (base DKG shares)
    /// - Vault share pubkeys (vault tweaked shares)
    pub async fn compute_and_store_all_share_pubkeys(&self) -> Result<()> {
        info!("🔑 [SHARE_PUBKEYS] === Computing and storing all share public keys ===");

        // Use original commitments (permanently stored during DKG, never deleted on disconnect)
        // to ensure correct aggregation even after network topology changes.
        let commitments = self.storage.get_all_original_commitments().await?;
        let peer_indices = self.storage.get_peer_indices().await?;

        if commitments.is_empty() {
            return Err(anyhow!("No original commitments available - DKG may not be complete"));
        }

        // Get vault tweak scalar
        let final_public = self
            .storage
            .get_final_public()
            .await?
            .ok_or_else(|| anyhow!("Final public key not available"))?;
        let eth_address = get_eth_address_from_group_key(final_public);
        let vault_hmac_reduced = hmac_scalar_mod_n(&eth_address, &self.chain_code)
            .map_err(|e| anyhow!("Failed to generate vault HMAC: {}", e))?;
        let vault_tweak_scalar = Scalar::from_repr(vault_hmac_reduced.into())
            .into_option()
            .ok_or_else(|| anyhow!("Failed to create scalar from vault HMAC"))?;

        info!("🔑 [SHARE_PUBKEYS] Processing {} peers", commitments.len());

        // Step 1: Aggregate all commitments coefficient-wise
        // Find the maximum degree (max length of commitment arrays)
        let max_degree = commitments
            .values()
            .map(|comms| comms.len())
            .max()
            .unwrap_or(0);

        if max_degree == 0 {
            return Err(anyhow!("No commitments found in any peer"));
        }

        info!(
            "🔑 [SHARE_PUBKEYS] Aggregating commitments (max degree: {})",
            max_degree
        );

        // Aggregate commitments: aggregated_C[k] = sum over all peers i of C_i[k]
        let mut aggregated_commitments: Vec<ProjectivePoint> = vec![ProjectivePoint::IDENTITY; max_degree];
        for (_peer_id, peer_commitments) in commitments.iter() {
            for (k, commitment) in peer_commitments.iter().enumerate() {
                if k < max_degree {
                    aggregated_commitments[k] += ProjectivePoint::from(*commitment);
                }
            }
        }

        info!("🔑 [SHARE_PUBKEYS] Aggregated {} commitment coefficients", max_degree);

        // Step 2: Evaluate aggregated polynomial at each peer's index.
        // Only process keys that are peer IDs (in peer_indices). Skip refresh_* and disconnected peers.
        for (peer_id, _) in commitments.iter() {
            let dkg_index = match peer_indices.get(peer_id) {
                Some(&idx) => idx,
                None => continue, // skip refresh_* keys and peers no longer in DB (e.g. disconnected)
            };

            info!("🔑 [SHARE_PUBKEYS] Processing peer: {} (DKG index: {})", peer_id, dkg_index);

            // Evaluate aggregated polynomial: aggregated_C[0] + aggregated_C[1]*j + aggregated_C[2]*j^2 + ...
            let network_share_pubkey = self.evaluate_aggregated_polynomial(
                &aggregated_commitments,
                dkg_index as u32,
            )?;

            self.storage
                .store_network_share_pubkey(peer_id, &network_share_pubkey)
                .await?;

            // 2. Compute and store vault share pubkey (vault tweaked)
            let vault_share_pubkey = network_share_pubkey
                + (ProjectivePoint::GENERATOR * vault_tweak_scalar);
            self.storage
                .store_vault_share_pubkey(peer_id, &vault_share_pubkey)
                .await?;

            info!(
                "✅ [SHARE_PUBKEYS] Stored network and vault share pubkeys for peer: {}",
                peer_id
            );
        }

        info!("✅ [SHARE_PUBKEYS] === Completed computing and storing all share public keys ===");
        Ok(())
    }

    /// Evaluate aggregated polynomial at a given index
    /// This computes: aggregated_C[0] + aggregated_C[1]*x + aggregated_C[2]*x^2 + ...
    fn evaluate_aggregated_polynomial(
        &self,
        aggregated_commitments: &[ProjectivePoint],
        dkg_index: u32,
    ) -> Result<ProjectivePoint> {
        use k256::Scalar;
        let x = Scalar::from(dkg_index as u64);
        let mut share_pubkey = ProjectivePoint::IDENTITY;

        for (j, commitment) in aggregated_commitments.iter().enumerate() {
            let mut x_pow = Scalar::ONE;
            for _ in 0..j {
                x_pow *= x;
            }
            share_pubkey += *commitment * x_pow;
        }

        Ok(share_pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};

    // A dummy implementation of DKGNode just for accessing the polynomial method
    // Since evaluate_aggregated_polynomial doesn't actually use self in its logic!
    struct DummyNode;
    impl DummyNode {
        fn evaluate_aggregated_polynomial(
            &self,
            aggregated_commitments: &[ProjectivePoint],
            dkg_index: u32,
        ) -> Result<ProjectivePoint> {
            use k256::Scalar;
            let x = Scalar::from(dkg_index as u64);
            let mut share_pubkey = ProjectivePoint::IDENTITY;

            for (j, commitment) in aggregated_commitments.iter().enumerate() {
                let mut x_pow = Scalar::ONE;
                for _ in 0..j {
                    x_pow *= x;
                }
                share_pubkey += *commitment * x_pow;
            }

            Ok(share_pubkey)
        }
    }

    #[test]
    fn test_evaluate_aggregated_polynomial() {
        let node = DummyNode;
        
        let g = ProjectivePoint::GENERATOR;
        let c0 = g * Scalar::from(2u64); // Intercept = 2*G
        let c1 = g * Scalar::from(3u64); // Slope = 3*G
        
        let commitments = vec![c0, c1];
        
        // P(x) = 2G + 3G * x
        
        // At index 0 (should be just intercept)
        let eval_0 = node.evaluate_aggregated_polynomial(&commitments, 0).unwrap();
        assert_eq!(eval_0, c0);
        
        // At index 1: 2G + 3G(1) = 5G
        let eval_1 = node.evaluate_aggregated_polynomial(&commitments, 1).unwrap();
        assert_eq!(eval_1, g * Scalar::from(5u64));
        
        // At index 2: 2G + 3G(2) = 8G
        let eval_2 = node.evaluate_aggregated_polynomial(&commitments, 2).unwrap();
        assert_eq!(eval_2, g * Scalar::from(8u64));
    }
}
