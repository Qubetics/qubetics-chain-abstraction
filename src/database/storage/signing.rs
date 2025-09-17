use crate::{
    chain::ChainTransaction,
    database::{
        constants::*,
        db::Database,
        keys::{
            AggregatedRoundKey, FinalNodeRoundKey, PendingTransactionKey, PublicKeyKey,
            SignatureKey, SignatureRoundKey,
        },
        traits::KvStorage,
    },
    signing::ECDSASignature,
};
use anyhow::Result;
use rocksdb::DB;
use secp256k1::PublicKey;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, info};

/// Database-backed signing storage
#[derive(Clone)]
pub struct SigningStorage {
    db: Database,
}

impl KvStorage for SigningStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}

impl SigningStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn get_database(&self) -> &Database {
        &self.db
    }


    /// Store a public key for a node
    pub async fn store_public_key(&self, node_id: &str, public_key: &PublicKey) -> Result<()> {
        let key = PublicKeyKey {
            node_id: node_id.to_string(),
        };
        let public_key_bytes = public_key.serialize().to_vec();
        self.put(key, &public_key_bytes)?;
        info!(
            "✅ [SIGNING_STORAGE] Stored public key for node: {}",
            node_id
        );
        Ok(())
    }

    /// Get a public key for a node
    pub async fn get_public_key(&self, node_id: &str) -> Result<Option<PublicKey>> {
        let key = PublicKeyKey {
            node_id: node_id.to_string(),
        };
        let public_key_bytes: Option<Vec<u8>> = self.get(key)?;
        if let Some(bytes) = public_key_bytes {
            let public_key = PublicKey::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize public key: {}", e))?;
            debug!(
                "🔍 [SIGNING_STORAGE] Retrieved public key for node: {}",
                node_id
            );
            Ok(Some(public_key))
        } else {
            Ok(None)
        }
    }

    /// Get all public keys
    pub async fn get_all_public_keys(&self) -> Result<HashMap<String, PublicKey>> {
        let mut keys = HashMap::new();
        let iter = self.db().prefix_iterator(PUBLIC_KEY_PREFIX);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Some(node_id_bytes) = key_bytes.strip_prefix(PUBLIC_KEY_PREFIX) {
                if let Ok(node_id) = String::from_utf8(node_id_bytes.to_vec()) {
                    match PublicKey::from_slice(&value_bytes) {
                        Ok(public_key) => {
                            keys.insert(node_id, public_key);
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to deserialize public key for node {}: {}",
                                String::from_utf8_lossy(node_id_bytes),
                                e
                            );
                        }
                    }
                }
            }
        }
        debug!("🔍 [SIGNING_STORAGE] Retrieved {} public keys", keys.len());
        Ok(keys)
    }

    /// Store a signature for a node
    pub async fn store_signature(&self, node_id: &str, signature: &ECDSASignature) -> Result<()> {
        let key = SignatureKey {
            node_id: node_id.to_string(),
        };
        self.put(key, signature)?;
        info!(
            "✅ [SIGNING_STORAGE] Stored signature for node: {}",
            node_id
        );
        Ok(())
    }

    /// Get a signature for a node
    pub async fn get_signature(&self, node_id: &str) -> Result<Option<ECDSASignature>> {
        let key = SignatureKey {
            node_id: node_id.to_string(),
        };
        let signature = self.get(key)?;
        if signature.is_some() {
            debug!(
                "🔍 [SIGNING_STORAGE] Retrieved signature for node: {}",
                node_id
            );
        }
        Ok(signature)
    }

    /// Get all signatures
    pub async fn get_all_signatures(&self) -> Result<HashMap<String, ECDSASignature>> {
        let mut signatures = HashMap::new();
        let iter = self.db().prefix_iterator(SIGNATURE_PREFIX);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Some(node_id_bytes) = key_bytes.strip_prefix(SIGNATURE_PREFIX) {
                if let Ok(node_id) = String::from_utf8(node_id_bytes.to_vec()) {
                    if let Ok(signature) = bincode::deserialize(&value_bytes) {
                        signatures.insert(node_id, signature);
                    }
                }
            }
        }
        debug!(
            "🔍 [SIGNING_STORAGE] Retrieved {} signatures",
            signatures.len()
        );
        Ok(signatures)
    }

    /// Store a signature for a specific round and node
    pub async fn store_signature_for_round(
        &self,
        round: u64,
        node_id: &str,
        signature: &ECDSASignature,
    ) -> Result<()> {
        let key = SignatureRoundKey {
            round,
            node_id: node_id.to_string(),
        };
        self.put(key, signature)?;
        info!(
            "✅ [SIGNING_STORAGE] Stored signature for round {} node: {}",
            round, node_id
        );
        Ok(())
    }

    /// Get a signature for a specific round and node
    pub async fn get_signature_for_round(
        &self,
        round: u64,
        node_id: &str,
    ) -> Result<Option<ECDSASignature>> {
        let key = SignatureRoundKey {
            round,
            node_id: node_id.to_string(),
        };
        let signature = self.get(key)?;
        if signature.is_some() {
            debug!(
                "🔍 [SIGNING_STORAGE] Retrieved signature for round {} node: {}",
                round, node_id
            );
        }
        Ok(signature)
    }

    /// Get all signatures for a specific round
    pub async fn get_signatures_for_round(&self, round: u64) -> Result<HashMap<String, ECDSASignature>> {
        let prefix = [SIGNATURE_ROUND_PREFIX, round.to_string().as_bytes(), b":"].concat();
        let mut signatures = HashMap::new();
        let iter = self.db().prefix_iterator(prefix.clone());
        for item in iter {
            let (key, value) = item?;
            if let Ok(signature) = bincode::deserialize::<ECDSASignature>(&value) {
                if let Ok(node_id) = String::from_utf8(key[prefix.len()..].to_vec()) {
                    signatures.insert(node_id, signature);
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
        self.put(key, &node_id.to_string())?;
        info!(
            "✅ [SIGNING_STORAGE] Stored final node for round {}: {}",
            round, node_id
        );
        Ok(())
    }

    /// Get the final node for a round
    pub async fn get_final_node_for_round(&self, round: u64) -> Result<Option<String>> {
        let key = FinalNodeRoundKey { round };
        let node_id = self.get(key)?;
        if node_id.is_some() {
            debug!(
                "🔍 [SIGNING_STORAGE] Retrieved final node for round {}",
                round
            );
        }
        Ok(node_id)
    }

    /// Get all final nodes by round
    pub async fn get_all_final_nodes_by_round(&self) -> Result<HashMap<u64, String>> {
        let mut final_nodes = HashMap::new();
        let iter = self.db().prefix_iterator(FINAL_NODE_ROUND_PREFIX);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Ok(node_id) = bincode::deserialize(&value_bytes) {
                if let Some(round_bytes) = key_bytes.strip_prefix(FINAL_NODE_ROUND_PREFIX) {
                    if let Ok(round_str) = String::from_utf8(round_bytes.to_vec()) {
                        if let Ok(round) = round_str.parse::<u64>() {
                            final_nodes.insert(round, node_id);
                        }
                    }
                }
            }
        }
        debug!(
            "🔍 [SIGNING_STORAGE] Retrieved {} final nodes by round",
            final_nodes.len()
        );
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
        self.put(key, &tx_data)?;
        info!(
            "✅ [SIGNING_STORAGE] Stored pending transaction for round: {}",
            round
        );
        Ok(())
    }

    /// Get a pending transaction for a round
    pub async fn get_pending_transaction(
        &self,
        round: u64,
    ) -> Result<Option<(ChainTransaction, Vec<u8>)>> {
        let key = PendingTransactionKey { round };
        let tx_data = self.get(key)?;
        if tx_data.is_some() {
            debug!(
                "🔍 [SIGNING_STORAGE] Retrieved pending transaction for round: {}",
                round
            );
        }
        Ok(tx_data)
    }

    /// Get all pending transactions
    pub async fn get_all_pending_transactions(
        &self,
    ) -> Result<HashMap<u64, (ChainTransaction, Vec<u8>)>> {
        let mut transactions = HashMap::new();
        let iter = self.db().prefix_iterator(PENDING_TRANSACTION_PREFIX);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Ok(tx_data) = bincode::deserialize(&value_bytes) {
                if let Some(round_bytes) = key_bytes.strip_prefix(PENDING_TRANSACTION_PREFIX) {
                    if let Ok(round_str) = String::from_utf8(round_bytes.to_vec()) {
                        if let Ok(round) = round_str.parse::<u64>() {
                            transactions.insert(round, tx_data);
                        }
                    }
                }
            }
        }
        debug!(
            "🔍 [SIGNING_STORAGE] Retrieved {} pending transactions",
            transactions.len()
        );
        Ok(transactions)
    }

    /// Delete a pending transaction for a round
    pub async fn delete_pending_transaction(&self, round: u64) -> Result<()> {
        let key = PendingTransactionKey { round };
        self.delete(key)?;
        info!(
            "🗑️ [SIGNING_STORAGE] Deleted pending transaction for round: {}",
            round
        );
        Ok(())
    }

    /// Clear all signatures for a specific round (cleanup after aggregation)
    pub async fn clear_signatures_for_round(&self, round: u64) -> Result<()> {
        let prefix = [SIGNATURE_ROUND_PREFIX, round.to_string().as_bytes(), b":"].concat();
        let keys_to_delete: Vec<_> = self
            .db()
            .prefix_iterator(prefix)
            .map(|item| item.map(|(key, _)| key.to_vec()))
            .collect::<Result<_, _>>()?;

        let key_count = keys_to_delete.len();
        for key in keys_to_delete {
            self.db().delete(key)?;
        }

        info!(
            "🧹 [SIGNING_STORAGE] Cleared {} signatures for round {}",
            key_count, round
        );
        Ok(())
    }

    /// Check if a round has been aggregated (used to prevent duplicate aggregation)
    pub async fn is_round_aggregated(&self, round: u64) -> Result<bool> {
        let key = AggregatedRoundKey { round };
        self.get::<_, bool>(key).map(|opt| opt.is_some())
    }

    /// Mark a round as aggregated
    pub async fn mark_round_aggregated(&self, round: u64) -> Result<()> {
        let key = AggregatedRoundKey { round };
        self.put(key, &true)?;
        info!("✅ [SIGNING_STORAGE] Marked round {} as aggregated", round);
        Ok(())
    }
}
