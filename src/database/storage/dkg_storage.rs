use crate::database::{keys, Database};
use crate::types::{KeyShare, SerializablePoint, SerializableScalar};
use anyhow::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Clone)]
pub struct DkgStorage {
    db: Database,
}

impl DkgStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn store_share(&self, from: &str, share: &KeyShare) -> Result<()> {
        let key = format!("{}{}", keys::DKG_SHARE, from);
        self.db.put_encrypted_string(&key, share)?;
        Ok(())
    }

    pub async fn get_all_shares(&self) -> Result<HashMap<String, KeyShare>> {
        let prefix = keys::DKG_SHARE;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for key in keys_vec {
            if let Some(id) = key.strip_prefix(prefix) {
                if let Some(share) = self.db.get_encrypted_string::<KeyShare>(&key)? {
                    map.insert(id.to_string(), share);
                }
            }
        }
        Ok(map)
    }

    pub async fn clear_shares(&self) -> Result<()> {
        let prefix = keys::DKG_SHARE;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        for key in keys_vec {
            self.db.delete_string(&key)?;
        }
        Ok(())
    }

    pub async fn store_commitments(&self, from: &str, commitments: &[AffinePoint]) -> Result<()> {
        let key = format!("{}{}", keys::DKG_COMMITMENT, from);
        let serializable: Vec<SerializablePoint> =
            commitments.iter().cloned().map(SerializablePoint).collect();
        self.db.put_encrypted_string(&key, &serializable)?;
        Ok(())
    }

    pub async fn get_all_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
        let prefix = keys::DKG_COMMITMENT;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for key in keys_vec {
            if let Some(id) = key.strip_prefix(prefix) {
                if let Some(ser_vec) = self.db.get_encrypted_string::<Vec<SerializablePoint>>(&key)? {
                    let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
                    map.insert(id.to_string(), vec);
                }
            }
        }
        Ok(map)
    }

    pub async fn clear_commitments(&self) -> Result<()> {
        let prefix = keys::DKG_COMMITMENT;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        for key in keys_vec {
            self.db.delete_string(&key)?;
        }
        Ok(())
    }

    /// Delete a specific share by key (used for cleaning up refresh shares)
    pub async fn delete_share(&self, share_key: &str) -> Result<()> {
        let key = format!("{}{}", keys::DKG_SHARE, share_key);
        self.db.delete_string(&key)?;
        Ok(())
    }

    /// Delete a specific commitment by key (used for cleaning up refresh commitments)
    pub async fn delete_commitment(&self, commitment_key: &str) -> Result<()> {
        let key = format!("{}{}", keys::DKG_COMMITMENT, commitment_key);
        self.db.delete_string(&key)?;
        Ok(())
    }

    /// Store original DKG commitments (these NEVER change after initial DKG)
    pub async fn store_original_commitments(
        &self,
        from: &str,
        commitments: &[AffinePoint],
    ) -> Result<()> {
        let key = format!("{}{}", keys::DKG_ORIGINAL_COMMITMENT, from);
        let serializable: Vec<SerializablePoint> =
            commitments.iter().cloned().map(SerializablePoint).collect();
        self.db.put_encrypted_string(&key, &serializable)?;
        tracing::info!(
            "💾 [DKG_STORAGE] Stored ORIGINAL commitments for {} (count: {})",
            from,
            commitments.len()
        );
        Ok(())
    }

    /// Get all original DKG commitments (used for vault address derivation)
    pub async fn get_all_original_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
        let prefix = keys::DKG_ORIGINAL_COMMITMENT;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for key in keys_vec {
            if let Some(id) = key.strip_prefix(prefix) {
                if let Some(ser_vec) = self.db.get_encrypted_string::<Vec<SerializablePoint>>(&key)? {
                    let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
                    map.insert(id.to_string(), vec);
                }
            }
        }
        tracing::debug!(
            "🔍 [DKG_STORAGE] Retrieved {} original commitment sets",
            map.len()
        );
        Ok(map)
    }

    pub async fn add_validation(&self, to: &str, from: &str, is_valid: bool) -> Result<()> {
        let key = format!("{}{}:{}", keys::DKG_VALIDATION, to, from);
        self.db.put_string(&key, &is_valid)?;
        Ok(())
    }

    pub async fn get_all_validations(&self) -> Result<HashMap<String, HashMap<String, bool>>> {
        let prefix = keys::DKG_VALIDATION;
        let results: Vec<(String, bool)> = self.db.get_values_with_prefix(prefix)?;
        let mut map: HashMap<String, HashMap<String, bool>> = HashMap::new();
        for (key, is_valid) in results {
            if let Some(stripped) = key.strip_prefix(prefix) {
                if let Some((to, from)) = stripped.split_once(':') {
                    map.entry(to.to_string())
                        .or_default()
                        .insert(from.to_string(), is_valid);
                } else {
                    tracing::warn!(
                        "⚠️ [DKG_STORAGE] Skipping malformed validation key: {}",
                        key
                    );
                }
            }
        }
        Ok(map)
    }

    pub async fn clear_validations(&self) -> Result<()> {
        let prefix = keys::DKG_VALIDATION;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        for key in keys_vec {
            self.db.delete_string(&key)?;
        }
        Ok(())
    }

    pub async fn set_final_secret(&self, secret: Scalar) -> Result<()> {
        let ser = SerializableScalar(secret);
        self.db.put_encrypted_string(keys::DKG_FINAL_SECRET, &ser)?;
        Ok(())
    }

    pub async fn get_final_secret(&self) -> Result<Option<Scalar>> {
        Ok(self
            .db
            .get_encrypted_string::<SerializableScalar>(keys::DKG_FINAL_SECRET)?
            .map(|s| s.0))
    }

    pub async fn delete_final_secret(&self) -> Result<()> {
        self.db.delete_string(keys::DKG_FINAL_SECRET)?;
        Ok(())
    }

    pub async fn set_final_public(&self, pk: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = pk.into();
        let ser = SerializablePoint(affine);
        self.db.put_encrypted_string(keys::DKG_FINAL_PUBLIC, &ser)?;
        Ok(())
    }

    pub async fn get_final_public(&self) -> Result<Option<ProjectivePoint>> {
        Ok(self
            .db
            .get_encrypted_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC)?
            .map(|p| ProjectivePoint::from(p.0)))
    }

    pub async fn delete_final_public(&self) -> Result<()> {
        self.db.delete_string(keys::DKG_FINAL_PUBLIC)?;
        Ok(())
    }

    pub async fn set_vault_addresses(&self, eth_address: &str, btc_address: &str) -> Result<()> {
        self.db
            .put_string(keys::DKG_VAULT_ETH_ADDRESS, &eth_address.to_string())?;
        self.db
            .put_string(keys::DKG_VAULT_BTC_ADDRESS, &btc_address.to_string())?;
        Ok(())
    }

    pub async fn get_vault_addresses(&self) -> Result<Option<(String, String)>> {
        let eth: Option<String> = self.db.get_string(keys::DKG_VAULT_ETH_ADDRESS)?;
        let btc: Option<String> = self.db.get_string(keys::DKG_VAULT_BTC_ADDRESS)?;
        if let (Some(e), Some(b)) = (eth, btc) {
            Ok(Some((e, b)))
        } else {
            Ok(None)
        }
    }

    pub async fn set_vault_tweaked_secret(&self, tweaked_secret: Scalar) -> Result<()> {
        let ser = SerializableScalar(tweaked_secret);
        self.db.put_encrypted_string(keys::DKG_VAULT_TWEAKED_SECRET, &ser)?;
        tracing::info!("💾 [DKG_STORAGE] Stored vault tweaked secret share");
        Ok(())
    }

    pub async fn get_vault_tweaked_secret(&self) -> Result<Option<Scalar>> {
        let result = self
            .db
            .get_encrypted_string::<SerializableScalar>(keys::DKG_VAULT_TWEAKED_SECRET)?
            .map(|s| s.0);

        if result.is_some() {
            tracing::info!("🔍 [DKG_STORAGE] Retrieved vault tweaked secret share");
        } else {
            tracing::debug!("🔍 [DKG_STORAGE] No vault tweaked secret share found in database");
        }

        Ok(result)
    }

    pub async fn delete_vault_tweaked_secret(&self) -> Result<()> {
        self.db.delete_string(keys::DKG_VAULT_TWEAKED_SECRET)?;
        tracing::info!("🗑️ [DKG_STORAGE] Deleted vault tweaked secret share from database");
        Ok(())
    }

    pub async fn set_vault_group_key(&self, vault_group_key: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = vault_group_key.into();
        let ser = SerializablePoint(affine);
        self.db.put_encrypted_string(keys::DKG_VAULT_GROUP_KEY, &ser)?;
        tracing::info!(
            "💾 [DKG_STORAGE] Stored vault group key: {:?}",
            vault_group_key
        );
        Ok(())
    }

    pub async fn get_vault_group_key(&self) -> Result<Option<ProjectivePoint>> {
        let result = self
            .db
            .get_encrypted_string::<SerializablePoint>(keys::DKG_VAULT_GROUP_KEY)?
            .map(|p| ProjectivePoint::from(p.0));

        if result.is_some() {
            tracing::info!(
                "🔍 [DKG_STORAGE] Retrieved vault group key: {:?}",
                result.unwrap()
            );
        } else {
            tracing::debug!("🔍 [DKG_STORAGE] No vault group key found in database");
        }

        Ok(result)
    }

    pub async fn delete_vault_group_key(&self) -> Result<()> {
        self.db.delete_string(keys::DKG_VAULT_GROUP_KEY)?;
        tracing::info!("🗑️ [DKG_STORAGE] Deleted vault group key from database");
        Ok(())
    }

    /// Store the polynomial coefficients for this node
    pub async fn set_polynomial(&self, polynomial: &[Scalar]) -> Result<()> {
        let serializable: Vec<SerializableScalar> =
            polynomial.iter().map(|&s| SerializableScalar(s)).collect();
        self.db.put_encrypted_string(keys::DKG_POLYNOMIAL, &serializable)?;
        tracing::info!(
            "💾 [DKG_STORAGE] Stored polynomial with {} coefficients",
            polynomial.len()
        );
        Ok(())
    }

    /// Get the stored polynomial coefficients
    pub async fn get_polynomial(&self) -> Result<Option<Vec<Scalar>>> {
        let result = self
            .db
            .get_encrypted_string::<Vec<SerializableScalar>>(keys::DKG_POLYNOMIAL)?
            .map(|v| v.into_iter().map(|s| s.0).collect::<Vec<Scalar>>());

        if let Some(ref poly) = result {
            tracing::info!(
                "🔍 [DKG_STORAGE] Retrieved polynomial with {} coefficients",
                poly.len()
            );
        } else {
            tracing::debug!("🔍 [DKG_STORAGE] No polynomial found in database");
        }

        Ok(result)
    }

    /// Delete the stored polynomial
    pub async fn delete_polynomial(&self) -> Result<()> {
        self.db.delete_string(keys::DKG_POLYNOMIAL)?;
        tracing::info!("🗑️ [DKG_STORAGE] Deleted polynomial from database");
        Ok(())
    }

    /// Mark whether a DKG refresh is currently in progress
    pub async fn set_refresh_in_progress(&self, in_progress: bool) -> Result<()> {
        self.db
            .put_string(keys::DKG_REFRESH_IN_PROGRESS, &in_progress)?;
        tracing::info!(
            "🔄 [DKG_STORAGE] Set refresh_in_progress flag: {}",
            in_progress
        );
        Ok(())
    }

    /// Check if a DKG refresh is currently in progress
    pub async fn is_refresh_in_progress(&self) -> Result<bool> {
        let result = self
            .db
            .get_string::<bool>(keys::DKG_REFRESH_IN_PROGRESS)?
            .unwrap_or(false);
        tracing::debug!(
            "🔍 [DKG_STORAGE] refresh_in_progress flag: {}",
            result
        );
        Ok(result)
    }

    /// Set the initial DKG completion flag (marks that the initial 4-node DKG is complete)
    pub async fn set_initial_dkg_complete(&self, is_complete: bool) -> Result<()> {
        self.db
            .put_string(keys::DKG_INITIAL_COMPLETE, &is_complete)?;
        tracing::info!(
            "🎯 [DKG_STORAGE] Set initial DKG complete flag: {}",
            is_complete
        );
        Ok(())
    }

    /// Get the initial DKG completion flag
    pub async fn is_initial_dkg_complete(&self) -> Result<bool> {
        let result = self
            .db
            .get_string::<bool>(keys::DKG_INITIAL_COMPLETE)?
            .unwrap_or(false);

        tracing::debug!("🔍 [DKG_STORAGE] Initial DKG complete flag: {}", result);
        Ok(result)
    }

    /// Store the node's permanent index (assigned during initial DKG or resharing)
    pub async fn set_my_permanent_index(&self, index: usize) -> Result<()> {
        self.db.put_encrypted_string(keys::DKG_MY_PERMANENT_INDEX, &index)?;
        tracing::info!("🔢 [DKG_STORAGE] Stored permanent index: {}", index);
        Ok(())
    }

    /// Get the node's permanent index
    pub async fn get_my_permanent_index(&self) -> Result<Option<usize>> {
        let result = self.db.get_encrypted_string::<usize>(keys::DKG_MY_PERMANENT_INDEX)?;

        if let Some(idx) = result {
            tracing::debug!("🔍 [DKG_STORAGE] Retrieved permanent index: {}", idx);
        } else {
            tracing::debug!("🔍 [DKG_STORAGE] No permanent index found in database");
        }

        Ok(result)
    }

    /// Get peer indices from database for deterministic ordering
    pub async fn get_peer_indices(&self) -> Result<HashMap<String, usize>> {
        let prefix = crate::database::keys::PEER_INDEX;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        let mut indices = HashMap::new();

        for key in keys_vec {
            // Extract peer ID from key (format: "peer_index:<peer_id>")
            if let Some(peer_id) = key.strip_prefix(prefix) {
                if let Some(index) = self.db.get_encrypted_string::<usize>(&key)? {
                    indices.insert(peer_id.to_string(), index);
                }
            }
        }

        info!(
            "🔢 [DKG_STORAGE] Retrieved {} peer indices from database",
            indices.len()
        );
        Ok(indices)
    }

    /// Get a single peer's index from database (synchronous helper)
    pub fn get_peer_index_for(&self, peer_id: &str) -> Result<Option<usize>> {
        // Log all peer indices for visibility
        match self.get_all_peer_indices() {
            Ok(map) => info!("🔢 [DKG_STORAGE] all peer indices: {:?}", map),
            Err(e) => info!("⚠️ [DKG_STORAGE] failed to read all peer indices: {:?}", e),
        }

        // Return the specific peer's index
        let key = format!("{}{}", crate::database::keys::PEER_INDEX, peer_id);
        let idx = self.db.get_encrypted_string::<usize>(&key)?;
        info!("🔎 [DKG_STORAGE] index for {} => {:?}", peer_id, idx);
        Ok(idx)
    }

    /// Get all peer indices from database (synchronous helper)
    pub fn get_all_peer_indices(&self) -> Result<HashMap<String, usize>> {
        let prefix = crate::database::keys::PEER_INDEX;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        let mut indices = HashMap::new();
        for key in keys_vec {
            if let Some(peer_id) = key.strip_prefix(prefix) {
                if let Some(index) = self.db.get_encrypted_string::<usize>(&key)? {
                    indices.insert(peer_id.to_string(), index);
                }
            }
        }
        Ok(indices)
    }

    // ============ SHARE TRACKING METHODS (Database-persistent) ============

    /// Set the list of peer IDs from which we expect to receive shares this round
    pub async fn set_expected_shares(&self, peer_ids: &[String]) -> Result<()> {
        self.db.put_string(keys::DKG_EXPECTED_SHARES, &peer_ids.to_vec())?;
        info!(
            "📋 [DKG_STORAGE] Set expected shares from {} peers: {:?}",
            peer_ids.len(),
            peer_ids
        );
        Ok(())
    }

    /// Get the list of peer IDs from which we expect to receive shares
    pub async fn get_expected_shares(&self) -> Result<Vec<String>> {
        let result = self
            .db
            .get_string::<Vec<String>>(keys::DKG_EXPECTED_SHARES)?
            .unwrap_or_default();
        Ok(result)
    }

    /// Mark that we have received a share from a specific peer
    pub async fn mark_share_received(&self, from_peer_id: &str) -> Result<bool> {
        let key = format!("{}{}", keys::DKG_RECEIVED_SHARE, from_peer_id);
        
        // Check if already received (return false if duplicate)
        if self.db.get_string::<bool>(&key)?.unwrap_or(false) {
            info!(
                "⚠️ [DKG_STORAGE] Share from {} already marked as received",
                from_peer_id
            );
            return Ok(false);
        }

        self.db.put_string(&key, &true)?;
        info!(
            "✅ [DKG_STORAGE] Marked share received from {}",
            from_peer_id
        );
        Ok(true)
    }

    /// Check if we have already received a share from a specific peer
    pub async fn is_share_received(&self, from_peer_id: &str) -> Result<bool> {
        let key = format!("{}{}", keys::DKG_RECEIVED_SHARE, from_peer_id);
        Ok(self.db.get_string::<bool>(&key)?.unwrap_or(false))
    }

    /// Get list of all peers from which we have received shares
    pub async fn get_received_shares(&self) -> Result<Vec<String>> {
        let prefix = keys::DKG_RECEIVED_SHARE;
        let results: Vec<(String, bool)> = self.db.get_values_with_prefix(prefix)?;
        let received: Vec<String> = results
            .into_iter()
            .filter_map(|(key, received)| {
                if received {
                    key.strip_prefix(prefix).map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();
        Ok(received)
    }

    /// Get pending shares (expected but not yet received)
    pub async fn get_pending_shares(&self) -> Result<Vec<String>> {
        let expected = self.get_expected_shares().await?;
        let received = self.get_received_shares().await?;
        let received_set: std::collections::HashSet<_> = received.into_iter().collect();
        let pending: Vec<String> = expected
            .into_iter()
            .filter(|peer| !received_set.contains(peer))
            .collect();
        Ok(pending)
    }

    /// Clear all share tracking data (called at reset/new round start)
    pub async fn clear_share_tracking(&self) -> Result<()> {
        // Clear received shares
        let prefix = keys::DKG_RECEIVED_SHARE;
        let keys_vec = self.db.get_keys_with_prefix(prefix)?;
        for key in keys_vec {
            self.db.delete_string(&key)?;
        }

        // Clear expected shares
        self.db.delete_string(keys::DKG_EXPECTED_SHARES)?;
        
        info!("🗑️ [DKG_STORAGE] Cleared share tracking data");
        Ok(())
    }

    /// Get commitments from a specific sender
    pub async fn get_commitments_for(&self, from: &str) -> Result<Option<Vec<AffinePoint>>> {
        let key = format!("{}{}", keys::DKG_COMMITMENT, from);
        let result = self
            .db
            .get_string::<Vec<SerializablePoint>>(&key)?
            .map(|ser_vec| ser_vec.into_iter().map(|p| p.0).collect());
        Ok(result)
    }

    /// Store network share public key for a peer (base DKG share)
    pub async fn store_network_share_pubkey(
        &self,
        peer_id: &str,
        pubkey: &ProjectivePoint,
    ) -> Result<()> {
        use crate::database::key_utils;
        let key = key_utils::node_share_pubkey_network_key(peer_id);
        let affine = pubkey.to_affine();
        let serial = SerializablePoint(affine);
        self.db.put_string(&key, &serial)?;
        
        // Derive and log ETH/BTC addresses
        let eth_addr = crate::utils::get_eth_address_from_group_key(*pubkey);
        let btc_addr = crate::utils::get_btc_address_from_group_key(*pubkey);
        
        info!(
            "✅ [DKG_STORAGE] Stored network share pubkey for peer: {}",
            peer_id
        );
        info!(
            "   📍 Network Share ETH Address: {}",
            eth_addr
        );
        info!(
            "   📍 Network Share BTC Address: {}",
            btc_addr
        );
        Ok(())
    }

    /// Get network share public key for a peer
    pub async fn get_network_share_pubkey(
        &self,
        peer_id: &str,
    ) -> Result<Option<ProjectivePoint>> {
        use crate::database::key_utils;
        let key = key_utils::node_share_pubkey_network_key(peer_id);
        let result = self.db.get_string::<SerializablePoint>(&key)?;
        Ok(result.map(|sp| ProjectivePoint::from(sp.0)))
    }

    /// Store vault share public key for a peer (vault tweaked share)
    pub async fn store_vault_share_pubkey(
        &self,
        peer_id: &str,
        pubkey: &ProjectivePoint,
    ) -> Result<()> {
        use crate::database::key_utils;
        let key = key_utils::node_share_pubkey_vault_key(peer_id);
        let affine = pubkey.to_affine();
        let serial = SerializablePoint(affine);
        self.db.put_string(&key, &serial)?;
        
        // Derive and log ETH/BTC addresses
        let eth_addr = crate::utils::get_eth_address_from_group_key(*pubkey);
        let btc_addr = crate::utils::get_btc_address_from_group_key(*pubkey);
        
        info!(
            "✅ [DKG_STORAGE] Stored vault share pubkey for peer: {}",
            peer_id
        );
        info!(
            "   📍 Vault Share ETH Address: {}",
            eth_addr
        );
        info!(
            "   📍 Vault Share BTC Address: {}",
            btc_addr
        );
        Ok(())
    }

    /// Get vault share public key for a peer
    pub async fn get_vault_share_pubkey(
        &self,
        peer_id: &str,
    ) -> Result<Option<ProjectivePoint>> {
        use crate::database::key_utils;
        let key = key_utils::node_share_pubkey_vault_key(peer_id);
        let result = self.db.get_string::<SerializablePoint>(&key)?;
        Ok(result.map(|sp| ProjectivePoint::from(sp.0)))
    }

    /// Store user share public key for a peer (user tweaked share)
    pub async fn store_user_share_pubkey(
        &self,
        peer_id: &str,
        user_eth_address: &str,
        pubkey: &ProjectivePoint,
    ) -> Result<()> {
        use crate::database::key_utils;
        let key = key_utils::node_share_pubkey_user_key(peer_id, user_eth_address);
        let affine = pubkey.to_affine();
        let serial = SerializablePoint(affine);
        self.db.put_string(&key, &serial)?;
        
        // Derive and log ETH/BTC addresses
        let eth_addr = crate::utils::get_eth_address_from_group_key(*pubkey);
        let btc_addr = crate::utils::get_btc_address_from_group_key(*pubkey);
        
        info!(
            "✅ [DKG_STORAGE] Stored user share pubkey for peer: {} user: {}",
            peer_id, user_eth_address
        );
        info!(
            "   📍 User Share ETH Address: {}",
            eth_addr
        );
        info!(
            "   📍 User Share BTC Address: {}",
            btc_addr
        );
        Ok(())
    }

    /// Get user share public key for a peer
    pub async fn get_user_share_pubkey(
        &self,
        peer_id: &str,
        user_eth_address: &str,
    ) -> Result<Option<ProjectivePoint>> {
        use crate::database::key_utils;
        let key = key_utils::node_share_pubkey_user_key(peer_id, user_eth_address);
        let result = self.db.get_string::<SerializablePoint>(&key)?;
        Ok(result.map(|sp| ProjectivePoint::from(sp.0)))
    }

    /// Get all user share public keys for a peer
    pub async fn get_all_user_share_pubkeys_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<HashMap<String, ProjectivePoint>> {
        let prefix = format!("{}{}:", keys::NODE_SHARE_PUBKEY_USER, peer_id);
        let results: Vec<(String, SerializablePoint)> = self.db.get_values_with_prefix(&prefix)?;
        let mut map = HashMap::new();
        for (key, sp) in results {
            // Extract user address from key: "node_share_pubkey_user:peer_id:user_address"
            if let Some(user_addr) = key.strip_prefix(&prefix) {
                map.insert(user_addr.to_string(), ProjectivePoint::from(sp.0));
            }
        }
        Ok(map)
    }

    /// Compute and store user share pubkeys for all peers for a specific user
    /// This should be called when a user registers
    pub async fn compute_and_store_user_share_pubkeys_for_user(
        &self,
        user_eth_address: &str,
        user_hmac_constant: &[u8; 32],
    ) -> Result<()> {
        use crate::utils::hmac_helper::bytes_to_scalar_mod_n;
        use k256::Scalar;

        info!(
            "🔑 [DKG_STORAGE] Computing user share pubkeys for user: {}",
            user_eth_address
        );

        let commitments = self.get_all_commitments().await?;
        let peer_indices = self.get_peer_indices().await?;

        if commitments.is_empty() {
            return Err(anyhow::anyhow!(
                "No commitments available - DKG may not be complete"
            ));
        }

        // Compute user tweak scalar
        use ff::PrimeField;
        let user_tweak_scalar = bytes_to_scalar_mod_n(user_hmac_constant);
        let user_tweak_scalar_k256 = Scalar::from_repr(user_tweak_scalar.into())
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("Failed to create scalar from user HMAC"))?;
        let user_tweak_point = ProjectivePoint::GENERATOR * user_tweak_scalar_k256;

        info!(
            "🔑 [DKG_STORAGE] Processing {} peers for user: {}",
            commitments.len(),
            user_eth_address
        );

        // Step 1: Aggregate all commitments coefficient-wise
        // Find the maximum degree (max length of commitment arrays)
        let max_degree = commitments
            .values()
            .map(|comms| comms.len())
            .max()
            .unwrap_or(0);

        if max_degree == 0 {
            return Err(anyhow::anyhow!("No commitments found in any peer"));
        }

        info!(
            "🔑 [DKG_STORAGE] Aggregating commitments (max degree: {}) for user: {}",
            max_degree, user_eth_address
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

        info!(
            "🔑 [DKG_STORAGE] Aggregated {} commitment coefficients for user: {}",
            max_degree, user_eth_address
        );

        // Step 2: Evaluate aggregated polynomial at each peer's index
        for (peer_id, _) in commitments.iter() {
            let dkg_index = peer_indices
                .get(peer_id)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("No DKG index found for peer {}", peer_id))?;

            // Evaluate aggregated polynomial: aggregated_C[0] + aggregated_C[1]*j + aggregated_C[2]*j^2 + ...
            let network_share_pubkey = self.evaluate_aggregated_polynomial(
                &aggregated_commitments,
                dkg_index as u32,
            )?;

            // Compute user share pubkey: network_share + user_tweak_point
            let user_share_pubkey = network_share_pubkey + user_tweak_point;

            // Store user share pubkey
            self.store_user_share_pubkey(peer_id, user_eth_address, &user_share_pubkey)
                .await?;
        }

        info!(
            "✅ [DKG_STORAGE] Completed computing user share pubkeys for user: {}",
            user_eth_address
        );
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

    /// Derive share public key from commitments using polynomial evaluation
    /// NOTE: This method is deprecated in favor of evaluate_aggregated_polynomial
    /// which correctly aggregates all commitments first. This is kept for backward compatibility.
    fn derive_share_pubkey_from_commitments(
        &self,
        commitments: &[AffinePoint],
        dkg_index: u32,
    ) -> Result<ProjectivePoint> {
        use k256::Scalar;
        let x = Scalar::from(dkg_index as u64);
        let mut share_pubkey = ProjectivePoint::IDENTITY;

        for (j, commitment) in commitments.iter().enumerate() {
            let mut x_pow = Scalar::ONE;
            for _ in 0..j {
                x_pow *= x;
            }
            share_pubkey += ProjectivePoint::from(*commitment) * x_pow;
        }

        Ok(share_pubkey)
    }

    /// Retrieve and log all stored share pubkeys for verification
    /// This is useful for debugging and verification
    pub async fn log_all_stored_share_pubkeys(&self) -> Result<()> {
        use crate::utils::{get_btc_address_from_group_key, get_eth_address_from_group_key};
        
        info!("🔍 [DKG_STORAGE] === Logging all stored share public keys ===");
        
        let commitments = self.get_all_commitments().await?;
        
        for (peer_id, _) in commitments.iter() {
            info!("🔍 [DKG_STORAGE] === Share Pubkeys for Peer: {} ===", peer_id);
            
            // Network share pubkey
            if let Ok(Some(network_pubkey)) = self.get_network_share_pubkey(peer_id).await {
                let eth_addr = get_eth_address_from_group_key(network_pubkey);
                let btc_addr = get_btc_address_from_group_key(network_pubkey);
                info!("  🔑 Network Share Pubkey:");
                info!("     ETH Address: {}", eth_addr);
                info!("     BTC Address: {}", btc_addr);
            } else {
                warn!("  ⚠️ Network share pubkey not found for peer: {}", peer_id);
            }
            
            // Vault share pubkey
            if let Ok(Some(vault_pubkey)) = self.get_vault_share_pubkey(peer_id).await {
                let eth_addr = get_eth_address_from_group_key(vault_pubkey);
                let btc_addr = get_btc_address_from_group_key(vault_pubkey);
                info!("  🔑 Vault Share Pubkey:");
                info!("     ETH Address: {}", eth_addr);
                info!("     BTC Address: {}", btc_addr);
            } else {
                warn!("  ⚠️ Vault share pubkey not found for peer: {}", peer_id);
            }
            
            // User share pubkeys
            if let Ok(user_pubkeys) = self.get_all_user_share_pubkeys_for_peer(peer_id).await {
                if !user_pubkeys.is_empty() {
                    info!("  🔑 User Share Pubkeys ({} users):", user_pubkeys.len());
                    for (user_addr, user_pubkey) in user_pubkeys.iter() {
                        let eth_addr = get_eth_address_from_group_key(*user_pubkey);
                        let btc_addr = get_btc_address_from_group_key(*user_pubkey);
                        info!("     User: {} -> ETH: {}, BTC: {}", user_addr, eth_addr, btc_addr);
                    }
                } else {
                    info!("  ℹ️ No user share pubkeys stored for peer: {}", peer_id);
                }
            } else {
                warn!("  ⚠️ Failed to retrieve user share pubkeys for peer: {}", peer_id);
            }
        }
        
        info!("✅ [DKG_STORAGE] === Finished logging all stored share public keys ===");
        Ok(())
    }
}
