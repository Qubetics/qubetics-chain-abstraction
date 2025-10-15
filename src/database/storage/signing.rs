use crate::{
	chain::ChainTransaction,
	database::{
		constants::{
			AGGREGATED_ROUND_PREFIX, FINAL_NODE_ROUND_PREFIX, PENDING_TRANSACTION_PREFIX,
			PUBLIC_KEY_PREFIX, SIGNATURE_PREFIX, SIGNATURE_ROUND_PREFIX,
		},
		db::Database,
		keys::{
			AggregatedRoundKey, FinalNodeRoundKey, PendingTransactionKey, PublicKeyKey,
			SignatureKey, SignatureRoundKey,
		},
		traits::Storage,
	},
	define_storage_adapter,
	signing::ECDSASignature,
};

use anyhow::Result;
use secp256k1::PublicKey;
use std::collections::HashMap;
use tracing::{debug, info};

define_storage_adapter!(PublicKeyAdapter, PublicKeyKey, Vec<u8>, PUBLIC_KEY_PREFIX);

define_storage_adapter!(SignatureAdapter, SignatureKey, ECDSASignature, SIGNATURE_PREFIX);

define_storage_adapter!(
	SignatureRoundAdapter,
	SignatureRoundKey,
	ECDSASignature,
	SIGNATURE_ROUND_PREFIX
);

define_storage_adapter!(FinalNodeRoundAdapter, FinalNodeRoundKey, String, FINAL_NODE_ROUND_PREFIX);

define_storage_adapter!(
	PendingTransactionAdapter,
	PendingTransactionKey,
	(ChainTransaction, Vec<u8>),
	PENDING_TRANSACTION_PREFIX
);

define_storage_adapter!(AggregatedRoundAdapter, AggregatedRoundKey, bool, AGGREGATED_ROUND_PREFIX);

pub type PublicKeyStorage = Storage<PublicKeyAdapter>;
pub type SignatureStorage = Storage<SignatureAdapter>;
pub type SignatureRoundStorage = Storage<SignatureRoundAdapter>;
pub type FinalNodeRoundStorage = Storage<FinalNodeRoundAdapter>;
pub type PendingTransactionStorage = Storage<PendingTransactionAdapter>;
pub type AggregatedRoundStorage = Storage<AggregatedRoundAdapter>;

/// Database-backed signing storage
#[derive(Clone)]
pub struct SigningStorage {
	public_keys: PublicKeyStorage,
	signatures: SignatureStorage,
	signature_rounds: SignatureRoundStorage,
	final_node_rounds: FinalNodeRoundStorage,
	pending_transactions: PendingTransactionStorage,
	aggregated_rounds: AggregatedRoundStorage,
}

impl SigningStorage {
	pub fn new(db: Database) -> Self {
		Self {
			public_keys: PublicKeyStorage::new(db.clone()),
			signatures: SignatureStorage::new(db.clone()),
			signature_rounds: SignatureRoundStorage::new(db.clone()),
			final_node_rounds: FinalNodeRoundStorage::new(db.clone()),
			pending_transactions: PendingTransactionStorage::new(db.clone()),
			aggregated_rounds: AggregatedRoundStorage::new(db),
		}
	}

	/// Store a public key for a node
	pub async fn store_public_key(&self, node_id: &str, public_key: &PublicKey) -> Result<()> {
		let key = PublicKeyKey { node_id: node_id.to_string() };
		let public_key_bytes = public_key.serialize().to_vec();
		self.public_keys.put(key, &public_key_bytes)?;
		info!("✅ [SIGNING_STORAGE] Stored public key for node: {}", node_id);
		Ok(())
	}

	/// Get a public key for a node
	pub async fn get_public_key(&self, node_id: &str) -> Result<Option<PublicKey>> {
		let key = PublicKeyKey { node_id: node_id.to_string() };
		let public_key_bytes: Option<Vec<u8>> = self.public_keys.get(key)?;
		if let Some(bytes) = public_key_bytes {
			let public_key = PublicKey::from_slice(&bytes)
				.map_err(|e| anyhow::anyhow!("Failed to deserialize public key: {}", e))?;
			debug!("🔍 [SIGNING_STORAGE] Retrieved public key for node: {}", node_id);
			Ok(Some(public_key))
		} else {
			Ok(None)
		}
	}

	/// Get all public keys
	pub async fn get_all_public_keys(&self) -> Result<HashMap<String, PublicKey>> {
		let mut keys = HashMap::new();
		let kvs = self.public_keys.get_all()?;
		for (key_bytes, value_bytes) in kvs {
			if let Ok(node_id) = String::from_utf8(key_bytes) {
				match PublicKey::from_slice(&value_bytes) {
					Ok(public_key) => {
						keys.insert(node_id, public_key);
					},
					Err(e) => {
						tracing::error!(
							"Failed to deserialize public key for node {}: {}",
							node_id,
							e
						);
					},
				}
			}
		}
		debug!("🔍 [SIGNING_STORAGE] Retrieved {} public keys", keys.len());
		Ok(keys)
	}

	/// Store a signature for a node
	pub async fn store_signature(&self, node_id: &str, signature: &ECDSASignature) -> Result<()> {
		let key = SignatureKey { node_id: node_id.to_string() };
		self.signatures.put(key, signature)?;
		info!("✅ [SIGNING_STORAGE] Stored signature for node: {}", node_id);
		Ok(())
	}

	/// Get a signature for a node
	pub async fn get_signature(&self, node_id: &str) -> Result<Option<ECDSASignature>> {
		let key = SignatureKey { node_id: node_id.to_string() };
		let signature = self.signatures.get(key)?;
		if signature.is_some() {
			debug!("🔍 [SIGNING_STORAGE] Retrieved signature for node: {}", node_id);
		}
		Ok(signature)
	}

	/// Get all signatures
	pub async fn get_all_signatures(&self) -> Result<HashMap<String, ECDSASignature>> {
		let mut signatures = HashMap::new();
		let kvs = self.signatures.get_all()?;
		for (key_bytes, signature) in kvs {
			if let Ok(node_id) = String::from_utf8(key_bytes) {
				signatures.insert(node_id, signature);
			}
		}
		debug!("🔍 [SIGNING_STORAGE] Retrieved {} signatures", signatures.len());
		Ok(signatures)
	}

	/// Store a signature for a specific round and node
	pub async fn store_signature_for_round(
		&self,
		round: u64,
		node_id: &str,
		signature: &ECDSASignature,
	) -> Result<()> {
		let key = SignatureRoundKey { round, node_id: node_id.to_string() };
		self.signature_rounds.put(key, signature)?;
		info!("✅ [SIGNING_STORAGE] Stored signature for round {} node: {}", round, node_id);
		Ok(())
	}

	/// Get a signature for a specific round and node
	pub async fn get_signature_for_round(
		&self,
		round: u64,
		node_id: &str,
	) -> Result<Option<ECDSASignature>> {
		let key = SignatureRoundKey { round, node_id: node_id.to_string() };
		let signature = self.signature_rounds.get(key)?;
		if signature.is_some() {
			debug!(
				"🔍 [SIGNING_STORAGE] Retrieved signature for round {} node: {}",
				round, node_id
			);
		}
		Ok(signature)
	}

	/// Get all signatures for a specific round
	pub async fn get_signatures_for_round(
		&self,
		round: u64,
	) -> Result<HashMap<String, ECDSASignature>> {
		let mut signatures = HashMap::new();
		let kvs = self.signature_rounds.get_all()?;
		let round_str = round.to_string();

		for (key_bytes, signature) in kvs {
			if let Ok(key_str) = String::from_utf8(key_bytes) {
				// Parse key format: "round:node_id"
				if let Some((key_round_str, node_id)) = key_str.split_once(':') {
					if key_round_str == round_str {
						signatures.insert(node_id.to_string(), signature);
					}
				}
			}
		}
		debug!(
			"🔍 [SIGNING_STORAGE] Retrieved {} signatures for round {}",
			signatures.len(),
			round
		);
		Ok(signatures)
	}

	/// Store the final node for a round
	pub async fn store_final_node_for_round(&self, round: u64, node_id: &str) -> Result<()> {
		let key = FinalNodeRoundKey { round };
		self.final_node_rounds.put(key, &node_id.to_string())?;
		info!("✅ [SIGNING_STORAGE] Stored final node for round {}: {}", round, node_id);
		Ok(())
	}

	/// Get the final node for a round
	pub async fn get_final_node_for_round(&self, round: u64) -> Result<Option<String>> {
		let key = FinalNodeRoundKey { round };
		let node_id = self.final_node_rounds.get(key)?;
		if node_id.is_some() {
			debug!("🔍 [SIGNING_STORAGE] Retrieved final node for round {}", round);
		}
		Ok(node_id)
	}

	/// Get all final nodes by round
	pub async fn get_all_final_nodes_by_round(&self) -> Result<HashMap<u64, String>> {
		let mut final_nodes = HashMap::new();
		let kvs = self.final_node_rounds.get_all()?;
		for (key_bytes, node_id) in kvs {
			if let Ok(round_str) = String::from_utf8(key_bytes) {
				if let Ok(round) = round_str.parse::<u64>() {
					final_nodes.insert(round, node_id);
				}
			}
		}
		debug!("🔍 [SIGNING_STORAGE] Retrieved {} final nodes by round", final_nodes.len());
		Ok(final_nodes)
	}

	/// Store a pending transaction for a round
	pub async fn store_pending_transaction(
		&self,
		round: u64,
		transaction: &ChainTransaction,
		tx_bytes: &[u8],
	) -> Result<()> {
		let key = PendingTransactionKey { round };
		let tx_data = (transaction.clone(), tx_bytes.to_vec());
		self.pending_transactions.put(key, &tx_data)?;
		info!("✅ [SIGNING_STORAGE] Stored pending transaction for round: {}", round);
		Ok(())
	}

	/// Get a pending transaction for a round
	pub async fn get_pending_transaction(
		&self,
		round: u64,
	) -> Result<Option<(ChainTransaction, Vec<u8>)>> {
		let key = PendingTransactionKey { round };
		let tx_data = self.pending_transactions.get(key)?;
		if tx_data.is_some() {
			debug!("🔍 [SIGNING_STORAGE] Retrieved pending transaction for round: {}", round);
		}
		Ok(tx_data)
	}

	/// Get all pending transactions
	pub async fn get_all_pending_transactions(
		&self,
	) -> Result<HashMap<u64, (ChainTransaction, Vec<u8>)>> {
		let mut transactions = HashMap::new();
		let kvs = self.pending_transactions.get_all()?;
		for (key_bytes, tx_data) in kvs {
			if let Ok(round_str) = String::from_utf8(key_bytes) {
				if let Ok(round) = round_str.parse::<u64>() {
					transactions.insert(round, tx_data);
				}
			}
		}
		debug!("🔍 [SIGNING_STORAGE] Retrieved {} pending transactions", transactions.len());
		Ok(transactions)
	}

	/// Delete a pending transaction for a round
	pub async fn delete_pending_transaction(&self, round: u64) -> Result<()> {
		let key = PendingTransactionKey { round };
		self.pending_transactions.delete(key)?;
		info!("🗑️ [SIGNING_STORAGE] Deleted pending transaction for round: {}", round);
		Ok(())
	}

	/// Clear all signatures for a specific round (cleanup after aggregation)
	pub async fn clear_signatures_for_round(&self, round: u64) -> Result<()> {
		let kvs = self.signature_rounds.get_all()?;
		let round_str = round.to_string();
		let mut keys_to_delete = Vec::new();

		// Find all keys for this round
		for (key_bytes, _) in kvs {
			if let Ok(key_str) = String::from_utf8(key_bytes.clone()) {
				if let Some((key_round_str, node_id)) = key_str.split_once(':') {
					if key_round_str == round_str {
						let key = SignatureRoundKey { round, node_id: node_id.to_string() };
						keys_to_delete.push(key);
					}
				}
			}
		}

		// Delete all found keys
		let key_count = keys_to_delete.len();
		for key in keys_to_delete {
			self.signature_rounds.delete(key)?;
		}

		info!("🧹 [SIGNING_STORAGE] Cleared {} signatures for round {}", key_count, round);
		Ok(())
	}

	/// Check if a round has been aggregated (used to prevent duplicate aggregation)
	pub async fn is_round_aggregated(&self, round: u64) -> Result<bool> {
		let key = AggregatedRoundKey { round };
		Ok(self.aggregated_rounds.get(key)?.unwrap_or(false))
	}

	/// Mark a round as aggregated
	pub async fn mark_round_aggregated(&self, round: u64) -> Result<()> {
		let key = AggregatedRoundKey { round };
		self.aggregated_rounds.put(key, &true)?;
		info!("✅ [SIGNING_STORAGE] Marked round {} as aggregated", round);
		Ok(())
	}
}
