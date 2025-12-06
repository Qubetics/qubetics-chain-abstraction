use super::node::DKGNode;
use anyhow::{anyhow, Result};
use k256::{ProjectivePoint, Scalar};
use tracing::{info, warn};

impl DKGNode {
    pub async fn calculate_vault_tweaked_secret_share(
        &self,
        tweak_scalar: Scalar,
    ) -> Result<Scalar> {
        let final_secret_share = self
            .storage
            .get_final_secret()
            .await?
            .ok_or_else(|| anyhow!("No final secret share available"))?;

        let vault_tweaked_secret = final_secret_share + tweak_scalar;

        info!("🔐 [DKG] Calculated vault tweaked secret share");

        Ok(vault_tweaked_secret)
    }

    pub async fn derive_user_specific_group_key_from_commitments(
        &self,
        tweak_scalar: Scalar,
    ) -> Result<ProjectivePoint> {
        let commitments = self.storage.get_all_commitments().await?;
        if commitments.is_empty() {
            return Err(anyhow!("No commitments available (database is empty)"));
        }

        let peer_indices = self.storage.get_peer_indices().await?;
        if peer_indices.is_empty() {
            return Err(anyhow!("No peer indices available in database"));
        }

        let mut solver_with_indices: Vec<(String, usize)> = commitments
            .keys()
            .filter_map(|sid| peer_indices.get(sid).map(|&idx| (sid.clone(), idx)))
            .collect();
        solver_with_indices.sort_by_key(|(_, idx)| *idx);

        info!(
            "🔢 [DKG] Processing commitments in peer index order: {:?}",
            solver_with_indices
                .iter()
                .map(|(sid, idx)| format!("{sid}:{idx}"))
                .collect::<Vec<_>>()
        );

        let mut p_base = ProjectivePoint::IDENTITY;
        let mut added = 0usize;
        for (sid, _) in &solver_with_indices {
            if let Some(comms) = commitments.get(sid) {
                if let Some(c0) = comms.first() {
                    p_base += ProjectivePoint::from(*c0);
                    added += 1;
                } else {
                    warn!("⚠️ [DKG] Solver {} has no C0 (index 0 missing)", sid);
                }
            }
        }

        if added == 0 {
            return Err(anyhow!(
                "No C0 found in any solver commitments; cannot derive base group key"
            ));
        }

        let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
        let p_user = p_base + tweak_point;

        if let Some(stored) = self.storage.get_final_public().await? {
            let delta = p_user + (-stored);
            info!("🔄 [DKG] Δ vs stored final_public_key: {:?}", delta);
        }

        Ok(p_user)
    }

    pub async fn derive_vault_group_key_from_original_commitments(
        &self,
        tweak_scalar: Scalar,
    ) -> Result<ProjectivePoint> {
        let commitments = self.storage.get_all_original_commitments().await?;
        if commitments.is_empty() {
            return Err(anyhow!(
                "No original commitments available - vault cannot be derived"
            ));
        }

        let peer_indices = self.storage.get_peer_indices().await?;
        if peer_indices.is_empty() {
            return Err(anyhow!("No peer indices available in database"));
        }

        let mut solver_with_indices: Vec<(String, usize)> = commitments
            .keys()
            .filter_map(|sid| peer_indices.get(sid).map(|&idx| (sid.clone(), idx)))
            .collect();
        solver_with_indices.sort_by_key(|(_, idx)| *idx);

        info!(
            "🔢 [VAULT] Processing original commitments in peer index order: {:?}",
            solver_with_indices
                .iter()
                .map(|(sid, idx)| format!("{sid}:{idx}"))
                .collect::<Vec<_>>()
        );

        let mut p_base = ProjectivePoint::IDENTITY;
        let mut added = 0usize;
        for (sid, _) in &solver_with_indices {
            if let Some(comms) = commitments.get(sid) {
                if let Some(c0) = comms.first() {
                    p_base += ProjectivePoint::from(*c0);
                    added += 1;
                } else {
                    warn!(
                        "⚠️ [VAULT] Solver {} has no C0 in original commitments",
                        sid
                    );
                }
            }
        }

        if added == 0 {
            return Err(anyhow!(
                "No C0 found in original commitments; cannot derive vault"
            ));
        }

        info!(
            "🏦 [VAULT] Using {} original commitment C0s for vault derivation",
            added
        );

        let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
        Ok(p_base + tweak_point)
    }
}
