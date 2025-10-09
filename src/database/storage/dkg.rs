use crate::database::{
    constants::{
        DKG_COMMITMENT_PREFIX, DKG_SHARE_PREFIX, DKG_VALIDATION_PREFIX,
    },
    db::Database,
    keys::{
        DkgCommitmentKey, DkgFinalPublicKey, DkgFinalSecretKey, DkgShareKey, DkgValidationKey,
        DkgVaultBtcAddressKey, DkgVaultEthAddressKey, DkgVaultGroupKey, DkgVaultTweakedSecretKey,
    },
    traits::KvStorage,
};
use crate::types::{KeyShare, SerializablePoint, SerializableScalar};

use anyhow::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::collections::HashMap;
use rocksdb::DB;
use std::sync::Arc;

#[derive(Clone)]
pub struct DkgStorage {
	db: Database,
}

impl KvStorage for DkgStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}



impl DkgStorage {
	pub fn new(db: Database) -> Self {
		Self { db }
	}

    pub async fn store_share(&self, from: &str, share: &KeyShare) -> Result<()> {
        let key = DkgShareKey {
            from: from.to_string(),
        };
        self.put(key, share)
    }

    pub async fn get_all_shares(&self) -> Result<HashMap<String, KeyShare>> {
        let mut shares = HashMap::new();
        let iter = self.db().prefix_iterator(DKG_SHARE_PREFIX);
        for item in iter {
            let (key, value) = item?;
            if let Ok(share) = bincode::deserialize::<KeyShare>(&value) {
                if let Ok(from) = String::from_utf8(key[DKG_SHARE_PREFIX.len()..].to_vec()) {
                    shares.insert(from, share);
                }
            }
        }
        Ok(shares)
    }

    pub async fn clear_shares(&self) -> Result<()> {
        let keys_to_delete: Vec<_> = self
            .db()
            .prefix_iterator(DKG_SHARE_PREFIX)
            .map(|item| item.map(|(key, _)| key.to_vec()))
            .collect::<Result<_, _>>()?;

        for key in keys_to_delete {
            self.db().delete(key)?;
        }
        Ok(())
    }

    pub async fn store_commitments(&self, from: &str, commitments: &[AffinePoint]) -> Result<()> {
        let key = DkgCommitmentKey {
            from: from.to_string(),
        };
        let serializable: Vec<SerializablePoint> =
            commitments.iter().cloned().map(SerializablePoint).collect();
        self.put(key, &serializable)
    }

    pub async fn get_all_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
        let mut map = HashMap::new();
        let iter = self.db().prefix_iterator(DKG_COMMITMENT_PREFIX);
        for item in iter {
            let (key, value) = item?;
            if let Ok(ser_vec) = bincode::deserialize::<Vec<SerializablePoint>>(&value) {
                if let Ok(id) = String::from_utf8(key[DKG_COMMITMENT_PREFIX.len()..].to_vec()) {
                    let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
                    map.insert(id, vec);
                }
            }
        }
        Ok(map)
    }

    pub async fn clear_commitments(&self) -> Result<()> {
        let keys_to_delete: Vec<_> = self
            .db()
            .prefix_iterator(DKG_COMMITMENT_PREFIX)
            .map(|item| item.map(|(key, _)| key.to_vec()))
            .collect::<Result<_, _>>()?;

        for key in keys_to_delete {
            self.db().delete(key)?;
        }
        Ok(())
    }

    pub async fn add_validation(&self, to: &str, is_valid: bool) -> Result<()> {
        let key = DkgValidationKey {
            to: to.to_string(),
        };
        let mut current: Vec<bool> = self.get(key.clone())?.unwrap_or_default();
        current.push(is_valid);
        self.put(key, &current)
    }

    pub async fn get_all_validations(&self) -> Result<HashMap<String, Vec<bool>>> {
        let mut map = HashMap::new();
        let iter = self.db().prefix_iterator(DKG_VALIDATION_PREFIX);
        for item in iter {
            let (key, value) = item?;
            if let Ok(vals) = bincode::deserialize::<Vec<bool>>(&value) {
                if let Ok(id) = String::from_utf8(key[DKG_VALIDATION_PREFIX.len()..].to_vec()) {
                    map.insert(id, vals);
                }
            }
        }
        Ok(map)
    }


    pub async fn clear_validations(&self) -> Result<()> {
        let keys_to_delete: Vec<_> = self
            .db()
            .prefix_iterator(DKG_VALIDATION_PREFIX)
            .map(|item| item.map(|(key, _)| key.to_vec()))
            .collect::<Result<_, _>>()?;

        for key in keys_to_delete {
            self.db().delete(key)?;
        }
        Ok(())
    }

    pub async fn set_final_secret(&self, secret: Scalar) -> Result<()> {
        let ser = SerializableScalar(secret);
        self.put(DkgFinalSecretKey {}, &ser)
    }

    pub async fn get_final_secret(&self) -> Result<Option<Scalar>> {
        Ok(self
            .get::<_, SerializableScalar>(DkgFinalSecretKey {})?
            .map(|s| s.0))
    }

    pub async fn delete_final_secret(&self) -> Result<()> {
        self.delete(DkgFinalSecretKey {})
    }

    pub async fn set_final_public(&self, pk: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = pk.into();
        let ser = SerializablePoint(affine);
        self.put(DkgFinalPublicKey {}, &ser)
    }

    pub async fn get_final_public(&self) -> Result<Option<ProjectivePoint>> {
        Ok(self
            .get::<_, SerializablePoint>(DkgFinalPublicKey {})?
            .map(|p| ProjectivePoint::from(p.0)))
    }

    pub async fn delete_final_public(&self) -> Result<()> {
        self.delete(DkgFinalPublicKey {})
    }


    pub async fn set_vault_addresses(&self, eth_address: &str, btc_address: &str) -> Result<()> {
        self.put(DkgVaultEthAddressKey {}, &eth_address.to_string())?;
        self.put(DkgVaultBtcAddressKey {}, &btc_address.to_string())?;
        Ok(())
    }

    pub async fn get_vault_addresses(&self) -> Result<Option<(String, String)>> {
        let eth: Option<String> = self.get(DkgVaultEthAddressKey {})?;
        let btc: Option<String> = self.get(DkgVaultBtcAddressKey {})?;
        if let (Some(e), Some(b)) = (eth, btc) {
            Ok(Some((e, b)))
        } else {
            Ok(None)
        }
    }

    pub async fn set_vault_tweaked_secret(&self, tweaked_secret: Scalar) -> Result<()> {
        let ser = SerializableScalar(tweaked_secret);
        self.put(DkgVaultTweakedSecretKey {}, &ser)
    }

    pub async fn get_vault_tweaked_secret(&self) -> Result<Option<Scalar>> {
        Ok(self
            .get::<_, SerializableScalar>(DkgVaultTweakedSecretKey {})?
            .map(|s| s.0))
    }



    pub async fn delete_vault_tweaked_secret(&self) -> Result<()> {
        self.delete(DkgVaultTweakedSecretKey {})
    }


    pub async fn set_vault_group_key(&self, vault_group_key: ProjectivePoint) -> Result<()> {
        let affine: AffinePoint = vault_group_key.into();
        let ser = SerializablePoint(affine);
        self.put(DkgVaultGroupKey {}, &ser)
    }

    pub async fn get_vault_group_key(&self) -> Result<Option<ProjectivePoint>> {
        Ok(self
            .get::<_, SerializablePoint>(DkgVaultGroupKey {})?
            .map(|p| ProjectivePoint::from(p.0)))
    }

    pub async fn delete_vault_group_key(&self) -> Result<()> {
        self.delete(DkgVaultGroupKey {})
    }
}


