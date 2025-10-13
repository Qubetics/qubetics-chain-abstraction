use crate::{
    database::{
        constants::{
            DKG_COMMITMENT_PREFIX, DKG_SHARE_PREFIX, DKG_VALIDATION_PREFIX,
            DKG_FINAL_SECRET_PREFIX, DKG_FINAL_PUBLIC_PREFIX, DKG_VAULT_ETH_ADDRESS_PREFIX,
            DKG_VAULT_BTC_ADDRESS_PREFIX, DKG_VAULT_TWEAKED_SECRET_PREFIX, DKG_VAULT_GROUP_KEY_PREFIX,
        },
        db::Database,
        keys::{
            DkgCommitmentKey, DkgFinalPublicKey, DkgFinalSecretKey, DkgShareKey, DkgValidationKey,
            DkgVaultBtcAddressKey, DkgVaultEthAddressKey, DkgVaultGroupKey, DkgVaultTweakedSecretKey,
        },
        traits::Storage,
    },
    define_storage_adapter,
    types::{KeyShare, SerializablePoint, SerializableScalar},
};

use anyhow::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::collections::HashMap;

define_storage_adapter!(
    DkgShareAdapter,
    DkgShareKey,
    KeyShare,
    DKG_SHARE_PREFIX
);

define_storage_adapter!(
    DkgCommitmentAdapter,
    DkgCommitmentKey,
    Vec<SerializablePoint>,
    DKG_COMMITMENT_PREFIX
);

define_storage_adapter!(
    DkgValidationAdapter,
    DkgValidationKey,
    Vec<bool>,
    DKG_VALIDATION_PREFIX
);

define_storage_adapter!(
    DkgFinalSecretAdapter,
    DkgFinalSecretKey,
    SerializableScalar,
    DKG_FINAL_SECRET_PREFIX
);

define_storage_adapter!(
    DkgFinalPublicAdapter,
    DkgFinalPublicKey,
    SerializablePoint,
    DKG_FINAL_PUBLIC_PREFIX
);

define_storage_adapter!(
    DkgVaultEthAddressAdapter,
    DkgVaultEthAddressKey,
    String,
    DKG_VAULT_ETH_ADDRESS_PREFIX
);

define_storage_adapter!(
    DkgVaultBtcAddressAdapter,
    DkgVaultBtcAddressKey,
    String,
    DKG_VAULT_BTC_ADDRESS_PREFIX
);

define_storage_adapter!(
    DkgVaultTweakedSecretAdapter,
    DkgVaultTweakedSecretKey,
    SerializableScalar,
    DKG_VAULT_TWEAKED_SECRET_PREFIX
);

define_storage_adapter!(
    DkgVaultGroupKeyAdapter,
    DkgVaultGroupKey,
    SerializablePoint,
    DKG_VAULT_GROUP_KEY_PREFIX
);

// Type aliases for typed storage
pub type DkgShareStorage = Storage<DkgShareAdapter>;
pub type DkgCommitmentStorage = Storage<DkgCommitmentAdapter>;
pub type DkgValidationStorage = Storage<DkgValidationAdapter>;
pub type DkgFinalSecretStorage = Storage<DkgFinalSecretAdapter>;
pub type DkgFinalPublicStorage = Storage<DkgFinalPublicAdapter>;
pub type DkgVaultEthAddressStorage = Storage<DkgVaultEthAddressAdapter>;
pub type DkgVaultBtcAddressStorage = Storage<DkgVaultBtcAddressAdapter>;
pub type DkgVaultTweakedSecretStorage = Storage<DkgVaultTweakedSecretAdapter>;
pub type DkgVaultGroupKeyStorage = Storage<DkgVaultGroupKeyAdapter>;

#[derive(Clone)]
pub struct DkgStorage {
    pub shares: DkgShareStorage,
    pub commitments: DkgCommitmentStorage,
    pub validations: DkgValidationStorage,
    pub final_secret: DkgFinalSecretStorage,
    pub final_public: DkgFinalPublicStorage,
    pub vault_eth_address: DkgVaultEthAddressStorage,
    pub vault_btc_address: DkgVaultBtcAddressStorage,
    pub vault_tweaked_secret: DkgVaultTweakedSecretStorage,
    pub vault_group_key: DkgVaultGroupKeyStorage,
}

impl DkgStorage {
	pub fn new(db: Database) -> Self {
		Self {
            shares: DkgShareStorage::new(db.clone()),
            commitments: DkgCommitmentStorage::new(db.clone()),
            validations: DkgValidationStorage::new(db.clone()),
            final_secret: DkgFinalSecretStorage::new(db.clone()),
            final_public: DkgFinalPublicStorage::new(db.clone()),
            vault_eth_address: DkgVaultEthAddressStorage::new(db.clone()),
            vault_btc_address: DkgVaultBtcAddressStorage::new(db.clone()),
            vault_tweaked_secret: DkgVaultTweakedSecretStorage::new(db.clone()),
            vault_group_key: DkgVaultGroupKeyStorage::new(db),
        }
	}


    pub async fn store_share(&self, from: &str, share: &KeyShare) -> Result<()> {
        let key = DkgShareKey {
            from: from.to_string(),
        };
        self.shares.put(key, share)
    }

    pub async fn get_all_shares(&self) -> Result<HashMap<String, KeyShare>> {
        let mut shares = HashMap::new();
        let kvs = self.shares.get_all()?;
        for (key_bytes, share) in kvs {
            if let Ok(from) = String::from_utf8(key_bytes) {
                shares.insert(from, share);
            }
        }
        Ok(shares)
    }

    pub async fn clear_shares(&self) -> Result<()> {
        let shares = self.get_all_shares().await?;
        for from in shares.keys() {
            let key = DkgShareKey { from: from.clone() };
            self.shares.delete(key)?;
        }
        Ok(())
    }

    pub async fn store_commitments(&self, from: &str, commitments: &[AffinePoint]) -> Result<()> {
        let key = DkgCommitmentKey {
            from: from.to_string(),
        };
        let serializable: Vec<SerializablePoint> =
            commitments.iter().cloned().map(SerializablePoint).collect();
        self.commitments.put(key, &serializable)
    }

    pub async fn get_all_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
        let mut map = HashMap::new();
        let kvs = self.commitments.get_all()?;
        for (key_bytes, ser_vec) in kvs {
            if let Ok(id) = String::from_utf8(key_bytes) {
                let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
                map.insert(id, vec);
            }
        }
        Ok(map)
    }

    pub async fn clear_commitments(&self) -> Result<()> {
        let commitments = self.get_all_commitments().await?;
        for from in commitments.keys() {
            let key = DkgCommitmentKey { from: from.clone() };
            self.commitments.delete(key)?;
        }
        Ok(())
    }

    pub async fn add_validation(&self, to: &str, is_valid: bool) -> Result<()> {
        let key = DkgValidationKey {
            to: to.to_string(),
        };
        let mut current: Vec<bool> = self.validations.get(key.clone())?.unwrap_or_default();
        current.push(is_valid);
        self.validations.put(key, &current)
    }

    pub async fn get_all_validations(&self) -> Result<HashMap<String, Vec<bool>>> {
        let mut map = HashMap::new();
        let kvs = self.validations.get_all()?;
        for (key_bytes, vals) in kvs {
            if let Ok(id) = String::from_utf8(key_bytes) {
                map.insert(id, vals);
            }
        }
        Ok(map)
    }

    pub async fn clear_validations(&self) -> Result<()> {
        let validations = self.get_all_validations().await?;
        for to in validations.keys() {
            let key = DkgValidationKey { to: to.clone() };
            self.validations.delete(key)?;
        }
        Ok(())
    }

    pub async fn set_final_secret(&self, secret: Scalar) -> Result<()> {
        let ser = SerializableScalar(secret);
        self.final_secret.put(DkgFinalSecretKey {}, &ser)
    }

    pub async fn get_final_secret(&self) -> Result<Option<Scalar>> {
        Ok(self
            .final_secret.get(DkgFinalSecretKey {})?
            .map(|s| s.0))
    }

    pub async fn delete_final_secret(&self) -> Result<()> {
        self.final_secret.delete(DkgFinalSecretKey {})
    }

    pub async fn set_final_public(&self, pk: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = pk.into();
        let ser = SerializablePoint(affine);
        self.final_public.put(DkgFinalPublicKey {}, &ser)
    }

    pub async fn get_final_public(&self) -> Result<Option<ProjectivePoint>> {
        Ok(self
            .final_public.get(DkgFinalPublicKey {})?
            .map(|p| ProjectivePoint::from(p.0)))
    }

    pub async fn delete_final_public(&self) -> Result<()> {
        self.final_public.delete(DkgFinalPublicKey {})
    }


    pub async fn set_vault_addresses(&self, eth_address: &str, btc_address: &str) -> Result<()> {
        self.vault_eth_address.put(DkgVaultEthAddressKey {}, &eth_address.to_string())?;
        self.vault_btc_address.put(DkgVaultBtcAddressKey {}, &btc_address.to_string())?;
        Ok(())
    }

    pub async fn get_vault_addresses(&self) -> Result<Option<(String, String)>> {
        let eth: Option<String> = self.vault_eth_address.get(DkgVaultEthAddressKey {})?;
        let btc: Option<String> = self.vault_btc_address.get(DkgVaultBtcAddressKey {})?;
        if let (Some(e), Some(b)) = (eth, btc) {
            Ok(Some((e, b)))
        } else {
            Ok(None)
        }
    }

    pub async fn set_vault_tweaked_secret(&self, tweaked_secret: Scalar) -> Result<()> {
        let ser = SerializableScalar(tweaked_secret);
        self.vault_tweaked_secret.put(DkgVaultTweakedSecretKey {}, &ser)
    }

    pub async fn get_vault_tweaked_secret(&self) -> Result<Option<Scalar>> {
        Ok(self
            .vault_tweaked_secret.get(DkgVaultTweakedSecretKey {})?
            .map(|s| s.0))
    }

    pub async fn delete_vault_tweaked_secret(&self) -> Result<()> {
        self.vault_tweaked_secret.delete(DkgVaultTweakedSecretKey {})
    }

    pub async fn set_vault_group_key(&self, vault_group_key: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = vault_group_key.into();
        let ser = SerializablePoint(affine);
        self.vault_group_key.put(DkgVaultGroupKey {}, &ser)
    }

    pub async fn get_vault_group_key(&self) -> Result<Option<ProjectivePoint>> {
        Ok(self
            .vault_group_key.get(DkgVaultGroupKey {})?
            .map(|p| ProjectivePoint::from(p.0)))
    }

    pub async fn delete_vault_group_key(&self) -> Result<()> {
        self.vault_group_key.delete(DkgVaultGroupKey {})
    }
}


