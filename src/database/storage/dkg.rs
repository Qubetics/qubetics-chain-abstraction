use crate::{
	database::{
		constants::{
			DKG_COMMITMENT_PREFIX, DKG_FINAL_PUBLIC_PREFIX, DKG_FINAL_SECRET_PREFIX,
			DKG_INITIAL_COMPLETE_PREFIX, DKG_MY_PERMANENT_INDEX_PREFIX,
			DKG_ORIGINAL_COMMITMENT_PREFIX, DKG_POLYNOMIAL_PREFIX, DKG_SHARE_PREFIX,
			DKG_VALIDATION_PREFIX, DKG_VAULT_BTC_ADDRESS_PREFIX, DKG_VAULT_ETH_ADDRESS_PREFIX,
			DKG_VAULT_GROUP_KEY_PREFIX, DKG_VAULT_TWEAKED_SECRET_PREFIX, PEER_INDEX_PREFIX,
		},
		db::Database,
		keys::{
			DkgCommitmentKey, DkgFinalPublicKey, DkgFinalSecretKey, DkgInitialCompleteKey,
			DkgMyPermanentIndexKey, DkgOriginalCommitmentKey, DkgPolynominalKey, DkgShareKey,
			DkgValidationKey, DkgVaultBtcAddressKey, DkgVaultEthAddressKey, DkgVaultGroupKey,
			DkgVaultTweakedSecretKey, PeerIndexKey,
		},
		traits::Storage,
	},
	define_storage_adapter,
	types::{KeyShare, SerializablePoint, SerializableScalar},
};

use anyhow::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::collections::HashMap;
use tracing::info;

define_storage_adapter!(DkgShareAdapter, DkgShareKey, KeyShare, DKG_SHARE_PREFIX);

define_storage_adapter!(
	DkgCommitmentAdapter,
	DkgCommitmentKey,
	Vec<SerializablePoint>,
	DKG_COMMITMENT_PREFIX
);

define_storage_adapter!(DkgValidationAdapter, DkgValidationKey, Vec<bool>, DKG_VALIDATION_PREFIX);

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

define_storage_adapter!(
	DkgOriginalCommitmentAdapter,
	DkgOriginalCommitmentKey,
	Vec<SerializablePoint>,
	DKG_ORIGINAL_COMMITMENT_PREFIX
);

define_storage_adapter!(
	DkgPolynomialAdapter,
	DkgPolynominalKey,
	Vec<SerializableScalar>,
	DKG_POLYNOMIAL_PREFIX
);

define_storage_adapter!(
	DkgInitialCompleteAdapter,
	DkgInitialCompleteKey,
	bool,
	DKG_INITIAL_COMPLETE_PREFIX
);

define_storage_adapter!(
	DkgMyPermanentIndexAdapter,
	DkgMyPermanentIndexKey,
	usize,
	DKG_MY_PERMANENT_INDEX_PREFIX
);

define_storage_adapter!(PeerIndexAdapter, PeerIndexKey, usize, PEER_INDEX_PREFIX);

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
pub type DkgOriginalCommitmentStorage = Storage<DkgOriginalCommitmentAdapter>;
pub type DkgPolynomialStorage = Storage<DkgPolynomialAdapter>;
pub type DkgInitialCompleteStorage = Storage<DkgInitialCompleteAdapter>;
pub type DkgMyPermanentIndexStorage = Storage<DkgMyPermanentIndexAdapter>;
pub type PeerIndexStorage = Storage<PeerIndexAdapter>;

#[derive(Clone)]
pub struct DkgStorage {
	pub shares: DkgShareStorage,
	pub commitments: DkgCommitmentStorage,
	pub original_commitments: DkgOriginalCommitmentStorage,
	pub validations: DkgValidationStorage,
	pub final_secret: DkgFinalSecretStorage,
	pub final_public: DkgFinalPublicStorage,
	pub vault_eth_address: DkgVaultEthAddressStorage,
	pub vault_btc_address: DkgVaultBtcAddressStorage,
	pub vault_tweaked_secret: DkgVaultTweakedSecretStorage,
	pub vault_group_key: DkgVaultGroupKeyStorage,
	pub polynomial: DkgPolynomialStorage,
	pub initial_complete: DkgInitialCompleteStorage,
	pub my_permanent_index: DkgMyPermanentIndexStorage,
	pub peer_indices: PeerIndexStorage,
}

impl DkgStorage {
	pub fn new(db: Database) -> Self {
		Self {
			shares: DkgShareStorage::new(db.clone()),
			commitments: DkgCommitmentStorage::new(db.clone()),
			original_commitments: DkgOriginalCommitmentStorage::new(db.clone()),
			validations: DkgValidationStorage::new(db.clone()),
			final_secret: DkgFinalSecretStorage::new(db.clone()),
			final_public: DkgFinalPublicStorage::new(db.clone()),
			vault_eth_address: DkgVaultEthAddressStorage::new(db.clone()),
			vault_btc_address: DkgVaultBtcAddressStorage::new(db.clone()),
			vault_tweaked_secret: DkgVaultTweakedSecretStorage::new(db.clone()),
			vault_group_key: DkgVaultGroupKeyStorage::new(db.clone()),
			polynomial: DkgPolynomialStorage::new(db.clone()),
			initial_complete: DkgInitialCompleteStorage::new(db.clone()),
			my_permanent_index: DkgMyPermanentIndexStorage::new(db.clone()),
			peer_indices: PeerIndexStorage::new(db),
		}
	}

	pub async fn store_share(&self, from: &str, share: &KeyShare) -> Result<()> {
		let key = DkgShareKey { from: from.to_string() };
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
		let key = DkgCommitmentKey { from: from.to_string() };
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

	/// Store original DKG commitments (these NEVER change after initial DKG)
	pub async fn store_original_commitments(
		&self,
		from: &str,
		commitments: &[AffinePoint],
	) -> Result<()> {
		let key = DkgOriginalCommitmentKey { from: from.to_string() };
		let serializable: Vec<SerializablePoint> =
			commitments.iter().cloned().map(SerializablePoint).collect();
		self.original_commitments.put(key, &serializable)?;
		tracing::info!(
			"💾 [DKG_STORAGE] Stored ORIGINAL commitments for {} (count: {})",
			from,
			commitments.len()
		);
		Ok(())
	}

	/// Get all original DKG commitments (used for vault address derivation)
	pub async fn get_all_original_commitments(&self) -> Result<HashMap<String, Vec<AffinePoint>>> {
		let mut map = HashMap::new();
		let kvs = self.original_commitments.get_all()?;
		for (key_bytes, ser_vec) in kvs {
			if let Ok(from) = String::from_utf8(key_bytes) {
				let vec: Vec<AffinePoint> = ser_vec.into_iter().map(|p| p.0).collect();
				map.insert(from, vec);
			}
		}
		tracing::debug!("🔍 [DKG_STORAGE] Retrieved {} original commitment sets", map.len());
		Ok(map)
	}

	pub async fn add_validation(&self, to: &str, is_valid: bool) -> Result<()> {
		let key = DkgValidationKey { to: to.to_string() };
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
		Ok(self.final_secret.get(DkgFinalSecretKey {})?.map(|s| s.0))
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
		Ok(self.final_public.get(DkgFinalPublicKey {})?.map(|p| ProjectivePoint::from(p.0)))
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
		let result = self.vault_tweaked_secret.get(DkgVaultTweakedSecretKey {})?.map(|s| s.0);

		if result.is_some() {
			tracing::info!(
				"🔍 [DKG_STORAGE] Retrieved vault tweaked secret share: {:?}",
				result.unwrap()
			);
		} else {
			tracing::debug!("🔍 [DKG_STORAGE] No vault tweaked secret share found in database");
		}

		Ok(result)
	}

	pub async fn delete_vault_tweaked_secret(&self) -> Result<()> {
		self.vault_tweaked_secret.delete(DkgVaultTweakedSecretKey {});

		tracing::info!("🗑️ [DKG_STORAGE] Deleted vault tweaked secret share from database");
		Ok(())
	}

	pub async fn set_vault_group_key(&self, vault_group_key: ProjectivePoint) -> Result<()> {
		let affine: AffinePoint = vault_group_key.into();
		let ser = SerializablePoint(affine);
		self.vault_group_key.put(DkgVaultGroupKey {}, &ser);
		tracing::info!("💾 [DKG_STORAGE] Stored vault group key: {:?}", vault_group_key);

		Ok(())
	}

	pub async fn get_vault_group_key(&self) -> Result<Option<ProjectivePoint>> {
		let result = self
			.vault_group_key
			.get(DkgVaultGroupKey {})?
			.map(|p| ProjectivePoint::from(p.0));

		if result.is_some() {
			tracing::info!("🔍 [DKG_STORAGE] Retrieved vault group key: {:?}", result.unwrap());
		} else {
			tracing::debug!("🔍 [DKG_STORAGE] No vault group key found in database");
		}

		Ok(result)
	}

	pub async fn delete_vault_group_key(&self) -> Result<()> {
		self.vault_group_key.delete(DkgVaultGroupKey {});
		tracing::info!("🗑️ [DKG_STORAGE] Deleted vault group key from database");

		Ok(())
	}
	/// Store the polynomial coefficients for this node
	pub async fn set_polynomial(&self, polynomial: &[Scalar]) -> Result<()> {
		let serializable: Vec<SerializableScalar> =
			polynomial.iter().map(|&s| SerializableScalar(s)).collect();
		self.polynomial.put(DkgPolynominalKey {}, &serializable)?;
		tracing::info!("💾 [DKG_STORAGE] Stored polynomial with {} coefficients", polynomial.len());
		Ok(())
	}

	/// Get the stored polynomial coefficients
	pub async fn get_polynomial(&self) -> Result<Option<Vec<Scalar>>> {
		let result = self
			.polynomial
			.get(DkgPolynominalKey {})?
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
		self.polynomial.delete(DkgPolynominalKey {})?;
		tracing::info!("🗑️ [DKG_STORAGE] Deleted polynomial from database");
		Ok(())
	}

	/// Set the initial DKG completion flag (marks that the initial 4-node DKG is complete)
	pub async fn set_initial_dkg_complete(&self, is_complete: bool) -> Result<()> {
		self.initial_complete.put(DkgInitialCompleteKey {}, &is_complete)?;
		tracing::info!("🎯 [DKG_STORAGE] Set initial DKG complete flag: {}", is_complete);
		Ok(())
	}

	/// Get the initial DKG completion flag
	pub async fn is_initial_dkg_complete(&self) -> Result<bool> {
		let result = self.initial_complete.get(DkgInitialCompleteKey {})?.unwrap_or(false);

		tracing::debug!("🔍 [DKG_STORAGE] Initial DKG complete flag: {}", result);
		Ok(result)
	}

	/// Store the node's permanent index (assigned during initial DKG or resharing)
	pub async fn set_my_permanent_index(&self, index: usize) -> Result<()> {
		self.my_permanent_index.put(DkgMyPermanentIndexKey {}, &index)?;
		tracing::info!("🔢 [DKG_STORAGE] Stored permanent index: {}", index);
		Ok(())
	}

	/// Get the node's permanent index
	pub async fn get_my_permanent_index(&self) -> Result<Option<usize>> {
		let result = self.my_permanent_index.get(DkgMyPermanentIndexKey {})?;

		if let Some(idx) = result {
			tracing::debug!("🔍 [DKG_STORAGE] Retrieved permanent index: {}", idx);
		} else {
			tracing::debug!("🔍 [DKG_STORAGE] No permanent index found in database");
		}

		Ok(result)
	}

	/// Get peer indices from database for deterministic ordering
	pub async fn get_peer_indices(&self) -> Result<HashMap<String, usize>> {
		let mut indices = HashMap::new();
		let kvs = self.peer_indices.get_all()?;

		for (key_bytes, index) in kvs {
			if let Ok(peer_id) = String::from_utf8(key_bytes) {
				indices.insert(peer_id, index);
			}
		}

		tracing::info!("🔢 [DKG_STORAGE] Retrieved {} peer indices from database", indices.len());
		Ok(indices)
	}

	/// Store a peer's index in the database
	pub fn set_peer_index(&self, peer_id: &str, index: usize) -> Result<()> {
		info!("🔢 [DKG_STORAGE] Set peer index: {} for {}", index, peer_id);
		let key = PeerIndexKey { peer_id: peer_id.to_string() };
		self.peer_indices.put(key, &index)?;
		tracing::info!("💾 [DKG_STORAGE] Stored peer index {} for {}", index, peer_id);
		Ok(())
	}

	/// Get a single peer's index from database (synchronous helper)
	pub fn get_peer_index_for(&self, peer_id: &str) -> Result<Option<usize>> {
		// Log all peer indices for visibility
		match self.get_all_peer_indices() {
			Ok(map) => tracing::info!("🔢 [DKG_STORAGE] all peer indices: {:?}", map),
			Err(e) => tracing::info!("⚠️ [DKG_STORAGE] failed to read all peer indices: {:?}", e),
		}

		// Return the specific peer's index
		let key = PeerIndexKey { peer_id: peer_id.to_string() };
		let idx = self.peer_indices.get(key)?;
		tracing::info!("🔎 [DKG_STORAGE] index for {} => {:?}", peer_id, idx);
		Ok(idx)
	}

	/// Get all peer indices from database (synchronous helper)
	pub fn get_all_peer_indices(&self) -> Result<HashMap<String, usize>> {
		let mut indices = HashMap::new();
		let kvs = self.peer_indices.get_all()?;
		tracing::info!("🔢 [DKG_STORAGE] Get all peer indices: {:?}", kvs);
		for (key_bytes, index) in kvs {
			tracing::info!("🔢 [DKG_STORAGE] Key bytes: {:?}, index: {}", key_bytes, index);
			if let Ok(peer_id) = String::from_utf8(key_bytes) {
				tracing::info!("🔢 [DKG_STORAGE] Peer id: {}, index: {}", peer_id, index);
				indices.insert(peer_id, index);
			}
		}
		tracing::info!("🔢 [DKG_STORAGE] All peer indices here: {:?}", indices);
		Ok(indices)
	}

	/// Get the maximum peer index from the database
	pub fn get_max_peer_index(&self) -> Result<usize> {
		let indices = self.get_all_peer_indices()?;
		let max_idx = indices.values().max().copied().unwrap_or(0);
		tracing::debug!("🔢 [DKG_STORAGE] Max peer index: {}", max_idx);
		Ok(max_idx)
	}
}
