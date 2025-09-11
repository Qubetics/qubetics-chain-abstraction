use crate::chain::ChainTransaction;
use crate::database::{key_utils, Database};
use crate::signing::ECDSASignature;
use anyhow::Result;
use secp256k1::PublicKey;
use std::collections::HashMap;
use tracing::{debug, info};

/// Database-backed signing storage
#[derive(Clone)]
pub struct SigningStorage {
    db: Database,
}

impl SigningStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get access to the underlying database
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Store a public key for a node
    pub async fn store_public_key(&self, node_id: &str, public_key: &PublicKey) -> Result<()> {
        let key = key_utils::public_key_key(node_id);
        let public_key_bytes = public_key.serialize().to_vec();
        self.db.put_string(&key, &public_key_bytes)?;
        info!(
            "✅ [SIGNING_STORAGE] Stored public key for node: {}",
            node_id
        );
        Ok(())
    }

    /// Get a public key for a node
    pub async fn get_public_key(&self, node_id: &str) -> Result<Option<PublicKey>> {
        let key = key_utils::public_key_key(node_id);
        let public_key_bytes: Option<Vec<u8>> = self.db.get_string(&key)?;
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
        let prefix = crate::database::keys::PUBLIC_KEY;
        let results: Vec<(String, Vec<u8>)> = self.db.get_values_with_prefix(prefix)?;

        let mut keys = HashMap::new();
        for (key, public_key_bytes) in results {
            // Extract node_id from key by removing prefix
            if let Some(node_id) = key.strip_prefix(prefix) {
                match PublicKey::from_slice(&public_key_bytes) {
                    Ok(public_key) => {
                        keys.insert(node_id.to_string(), public_key);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to deserialize public key for node {}: {}",
                            node_id,
                            e
                        );
                        continue;
                    }
                }
            }
        }

        debug!("🔍 [SIGNING_STORAGE] Retrieved {} public keys", keys.len());
        Ok(keys)
    }

    /// Store a signature for a node
    pub async fn store_signature(&self, node_id: &str, signature: &ECDSASignature) -> Result<()> {
        let key = key_utils::signature_key(node_id);
        self.db.put_string(&key, signature)?;
        info!(
            "✅ [SIGNING_STORAGE] Stored signature for node: {}",
            node_id
        );
        Ok(())
    }

    /// Get a signature for a node
    pub async fn get_signature(&self, node_id: &str) -> Result<Option<ECDSASignature>> {
        let key = key_utils::signature_key(node_id);
        let signature = self.db.get_string(&key)?;
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
        let prefix = crate::database::keys::SIGNATURE;
        let results: Vec<(String, ECDSASignature)> = self.db.get_values_with_prefix(prefix)?;

        let mut signatures = HashMap::new();
        for (key, signature) in results {
            // Extract node_id from key by removing prefix
            if let Some(node_id) = key.strip_prefix(prefix) {
                signatures.insert(node_id.to_string(), signature);
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
        let key = key_utils::signature_round_key(round, node_id);
        self.db.put_string(&key, signature)?;
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
        let key = key_utils::signature_round_key(round, node_id);
        let signature = self.db.get_string(&key)?;
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
        let prefix = format!("{}{}", crate::database::keys::SIGNATURE_ROUND, round);
        let results: Vec<(String, ECDSASignature)> = self.db.get_values_with_prefix(&prefix)?;

        let mut signatures = HashMap::new();
        for (key, signature) in results {
            // Extract node_id from key: format is "sig_round:{round}:{node_id}"
            if let Some(suffix) = key.strip_prefix(&format!(
                "{}{}:",
                crate::database::keys::SIGNATURE_ROUND,
                round
            )) {
                signatures.insert(suffix.to_string(), signature);
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
        let key = key_utils::final_node_round_key(round);
        self.db.put_string(&key, &node_id.to_string())?;
        info!(
            "✅ [SIGNING_STORAGE] Stored final node for round {}: {}",
            round, node_id
        );
        Ok(())
    }

    /// Get the final node for a round
    pub async fn get_final_node_for_round(&self, round: u64) -> Result<Option<String>> {
        let key = key_utils::final_node_round_key(round);
        let node_id = self.db.get_string(&key)?;
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
        let prefix = crate::database::keys::FINAL_NODE_ROUND;
        let results: Vec<(String, String)> = self.db.get_values_with_prefix(prefix)?;

        let mut final_nodes = HashMap::new();
        for (key, node_id) in results {
            // Extract round from key by removing prefix
            if let Some(round_str) = key.strip_prefix(prefix) {
                if let Ok(round) = round_str.parse::<u64>() {
                    final_nodes.insert(round, node_id);
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
        let key = key_utils::pending_transaction_key(round);
        let tx_data = (transaction.clone(), tx_bytes.to_vec());
        self.db.put_string(&key, &tx_data)?;
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
        let key = key_utils::pending_transaction_key(round);
        let tx_data = self.db.get_string(&key)?;
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
        let prefix = crate::database::keys::PENDING_TRANSACTION;
        let results: Vec<(String, (ChainTransaction, Vec<u8>))> =
            self.db.get_values_with_prefix(prefix)?;

        let mut transactions = HashMap::new();
        for (key, tx_data) in results {
            // Extract round from key by removing prefix
            if let Some(round_str) = key.strip_prefix(prefix) {
                if let Ok(round) = round_str.parse::<u64>() {
                    transactions.insert(round, tx_data);
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
        let key = key_utils::pending_transaction_key(round);
        self.db.delete_string(&key)?;
        info!(
            "🗑️ [SIGNING_STORAGE] Deleted pending transaction for round: {}",
            round
        );
        Ok(())
    }

    /// Clear all signatures for a specific round (cleanup after aggregation)
    pub async fn clear_signatures_for_round(&self, round: u64) -> Result<()> {
        let prefix = format!("{}{}", crate::database::keys::SIGNATURE_ROUND, round);
        let keys = self.db.get_keys_with_prefix(&prefix)?;

        let key_count = keys.len();
        for key in keys {
            self.db.delete_string(&key)?;
        }

        info!(
            "🧹 [SIGNING_STORAGE] Cleared {} signatures for round {}",
            key_count, round
        );
        Ok(())
    }

    /// Check if a round has been aggregated (used to prevent duplicate aggregation)
    pub async fn is_round_aggregated(&self, round: u64) -> Result<bool> {
        let key = format!("aggregated_round:{}", round);
        self.db.contains_string_key(&key)
    }

    /// Mark a round as aggregated
    pub async fn mark_round_aggregated(&self, round: u64) -> Result<()> {
        let key = format!("aggregated_round:{}", round);
        self.db.put_string(&key, &true)?;
        info!("✅ [SIGNING_STORAGE] Marked round {} as aggregated", round);
        Ok(())
    }

}
