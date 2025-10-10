use crate::database::{Database, keys};
use crate::types::{KeyShare, SerializablePoint, SerializableScalar};
use anyhow::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::collections::HashMap;

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
        self.db.put_string(&key, share)?;
        Ok(())
    }

    pub async fn get_all_shares(&self) -> Result<HashMap<String, KeyShare>> {
        let prefix = keys::DKG_SHARE;
        let results: Vec<(String, KeyShare)> = self.db.get_values_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for (key, share) in results {
            if let Some(id) = key.strip_prefix(prefix) {
                map.insert(id.to_string(), share);
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
        let serializable: Vec<SerializablePoint> = commitments.iter().cloned().map(SerializablePoint).collect();
        self.db.put_string(&key, &serializable)?;
        Ok(())
    }

    pub async fn get_all_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
        let prefix = keys::DKG_COMMITMENT;
        let results: Vec<(String, Vec<SerializablePoint>)> = self.db.get_values_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for (key, ser_vec) in results {
            if let Some(id) = key.strip_prefix(prefix) {
                let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
                map.insert(id.to_string(), vec);
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

    /// Store original DKG commitments (these NEVER change after initial DKG)
    pub async fn store_original_commitments(&self, from: &str, commitments: &[AffinePoint]) -> Result<()> {
        let key = format!("{}{}", keys::DKG_ORIGINAL_COMMITMENT, from);
        let serializable: Vec<SerializablePoint> = commitments.iter().cloned().map(SerializablePoint).collect();
        self.db.put_string(&key, &serializable)?;
        tracing::info!("💾 [DKG_STORAGE] Stored ORIGINAL commitments for {} (count: {})", from, commitments.len());
        Ok(())
    }

    /// Get all original DKG commitments (used for vault address derivation)
    pub async fn get_all_original_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
        let prefix = keys::DKG_ORIGINAL_COMMITMENT;
        let results: Vec<(String, Vec<SerializablePoint>)> = self.db.get_values_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for (key, ser_vec) in results {
            if let Some(id) = key.strip_prefix(prefix) {
                let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
                map.insert(id.to_string(), vec);
            }
        }
        tracing::debug!("🔍 [DKG_STORAGE] Retrieved {} original commitment sets", map.len());
        Ok(map)
    }

    pub async fn add_validation(&self, to: &str, is_valid: bool) -> Result<()> {
        let key = format!("{}{}", keys::DKG_VALIDATION, to);
        let mut current: Vec<bool> = self.db.get_string(&key)?.unwrap_or_default();
        current.push(is_valid);
        self.db.put_string(&key, &current)?;
        Ok(())
    }

    pub async fn get_all_validations(&self) -> Result<HashMap<String, Vec<bool>>> {
        let prefix = keys::DKG_VALIDATION;
        let results: Vec<(String, Vec<bool>)> = self.db.get_values_with_prefix(prefix)?;
        let mut map = HashMap::new();
        for (key, vals) in results {
            if let Some(id) = key.strip_prefix(prefix) {
                map.insert(id.to_string(), vals);
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
        self.db.put_string(keys::DKG_FINAL_SECRET, &ser)?;
        Ok(())
    }

    pub async fn get_final_secret(&self) -> Result<Option<Scalar>> {
        Ok(self
            .db
            .get_string::<SerializableScalar>(keys::DKG_FINAL_SECRET)?
            .map(|s| s.0))
    }

    pub async fn delete_final_secret(&self) -> Result<()> {
        self.db.delete_string(keys::DKG_FINAL_SECRET)?;
        Ok(())
    }

    pub async fn set_final_public(&self, pk: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = pk.into();
        let ser = SerializablePoint(affine);
        self.db.put_string(keys::DKG_FINAL_PUBLIC, &ser)?;
        Ok(())
    }

    pub async fn get_final_public(&self) -> Result<Option<ProjectivePoint>> {
        Ok(self
            .db
            .get_string::<SerializablePoint>(keys::DKG_FINAL_PUBLIC)?
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
        self.db.put_string(keys::DKG_VAULT_TWEAKED_SECRET, &ser)?;
        tracing::info!("💾 [DKG_STORAGE] Stored vault tweaked secret share: {:?}", tweaked_secret);
        Ok(())
    }

    pub async fn get_vault_tweaked_secret(&self) -> Result<Option<Scalar>> {
        let result = self
            .db
            .get_string::<SerializableScalar>(keys::DKG_VAULT_TWEAKED_SECRET)?
            .map(|s| s.0);
        
        if result.is_some() {
            tracing::info!("🔍 [DKG_STORAGE] Retrieved vault tweaked secret share: {:?}", result.unwrap());
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
        self.db.put_string(keys::DKG_VAULT_GROUP_KEY, &ser)?;
        tracing::info!("💾 [DKG_STORAGE] Stored vault group key: {:?}", vault_group_key);
        Ok(())
    }

    pub async fn get_vault_group_key(&self) -> Result<Option<ProjectivePoint>> {
        let result = self
            .db
            .get_string::<SerializablePoint>(keys::DKG_VAULT_GROUP_KEY)?
            .map(|p| ProjectivePoint::from(p.0));
        
        if result.is_some() {
            tracing::info!("🔍 [DKG_STORAGE] Retrieved vault group key: {:?}", result.unwrap());
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
        let serializable: Vec<SerializableScalar> = polynomial
            .iter()
            .map(|&s| SerializableScalar(s))
            .collect();
        self.db.put_string(keys::DKG_POLYNOMIAL, &serializable)?;
        tracing::info!("💾 [DKG_STORAGE] Stored polynomial with {} coefficients", polynomial.len());
        Ok(())
    }

    /// Get the stored polynomial coefficients
    pub async fn get_polynomial(&self) -> Result<Option<Vec<Scalar>>> {
        let result = self
            .db
            .get_string::<Vec<SerializableScalar>>(keys::DKG_POLYNOMIAL)?
            .map(|v| v.into_iter().map(|s| s.0).collect::<Vec<Scalar>>());
        
        if let Some(ref poly) = result {
            tracing::info!("🔍 [DKG_STORAGE] Retrieved polynomial with {} coefficients", poly.len());
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

    /// Set the initial DKG completion flag (marks that the initial 4-node DKG is complete)
    pub async fn set_initial_dkg_complete(&self, is_complete: bool) -> Result<()> {
        self.db.put_string(keys::DKG_INITIAL_COMPLETE, &is_complete)?;
        tracing::info!("🎯 [DKG_STORAGE] Set initial DKG complete flag: {}", is_complete);
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
        self.db.put_string(keys::DKG_MY_PERMANENT_INDEX, &index)?;
        tracing::info!("🔢 [DKG_STORAGE] Stored permanent index: {}", index);
        Ok(())
    }

    /// Get the node's permanent index
    pub async fn get_my_permanent_index(&self) -> Result<Option<usize>> {
        let result = self.db.get_string::<usize>(keys::DKG_MY_PERMANENT_INDEX)?;
        
        if let Some(idx) = result {
            tracing::debug!("🔍 [DKG_STORAGE] Retrieved permanent index: {}", idx);
        } else {
            tracing::debug!("🔍 [DKG_STORAGE] No permanent index found in database");
        }
        
        Ok(result)
    }
}

