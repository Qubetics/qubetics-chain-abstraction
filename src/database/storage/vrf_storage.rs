use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::database::{key_utils, Database};

/// Storage wrapper for VRF metadata persisted in RocksDB.
#[derive(Clone)]
pub struct VrfStorage {
    db: Database,
    /// Optional prefix for storage keys to isolate different VRF contexts
    /// (e.g., "vault_seq:", "main_seq:", "" for signing/default)
    prefix: String,
}

impl VrfStorage {
    /// Create a new VrfStorage with no prefix (for signing/default context)
    pub fn new(db: Database) -> Self {
        Self {
            db,
            prefix: String::new(),
        }
    }

    /// Create a new VrfStorage with a custom prefix for isolated storage
    pub fn new_with_prefix(db: Database, prefix: impl Into<String>) -> Self {
        Self {
            db,
            prefix: prefix.into(),
        }
    }

    /// Get access to the underlying database (primarily for testing/introspection).
    pub fn database(&self) -> &Database {
        &self.db
    }

    fn namespaced_round_key(&self, namespace: &str) -> String {
        let namespace_prefix = if namespace.is_empty() {
            String::new()
        } else {
            format!("{}:", namespace)
        };

        format!(
            "{}{}{}",
            self.prefix,
            namespace_prefix,
            key_utils::vrf_current_round_key()
        )
    }

    fn namespaced_peer_round_key(&self, namespace: &str, peer_id: &str) -> String {
        let namespace_prefix = if namespace.is_empty() {
            String::new()
        } else {
            format!("{}:", namespace)
        };

        format!(
            "{}{}{}",
            self.prefix,
            namespace_prefix,
            key_utils::vrf_peer_round_key(peer_id)
        )
    }

    /// Fetch the current VRF round from storage, initializing to 0 if absent.
    pub fn get_current_round(&self) -> Result<u64> {
        self.get_current_round_for_context("")
    }

    pub fn get_current_round_for_context(&self, namespace: &str) -> Result<u64> {
        let key = self.namespaced_round_key(namespace);
        match self.db.get_string::<u64>(&key)? {
            Some(round) => {
                debug!(
                    "🔍 [VRF_STORAGE:{}{}] Retrieved current round: {}",
                    self.prefix, namespace, round
                );
                Ok(round)
            }
            None => {
                // Initialize to 0 if missing to keep behavior deterministic.
                self.set_current_round_for_context(namespace, 0)?;
                warn!(
                    "ℹ️ [VRF_STORAGE:{}{}] current round not found; defaulting to 0",
                    self.prefix, namespace
                );
                Ok(0)
            }
        }
    }

    /// Persist the provided round as the current VRF round.
    pub fn set_current_round(&self, round: u64) -> Result<()> {
        self.set_current_round_for_context("", round)
    }

    pub fn set_current_round_for_context(&self, namespace: &str, round: u64) -> Result<()> {
        let key = self.namespaced_round_key(namespace);
        self.db.put_string(&key, &round)?;
        info!(
            "✅ [VRF_STORAGE:{}{}] Set current round to {}",
            self.prefix, namespace, round
        );
        Ok(())
    }

    /// Store a peer's VRF round in the database.
    pub fn set_peer_round(&self, peer_id: &str, round: u64) -> Result<()> {
        self.set_peer_round_for_context("", peer_id, round)
    }

    pub fn set_peer_round_for_context(
        &self,
        namespace: &str,
        peer_id: &str,
        round: u64,
    ) -> Result<()> {
        let key = self.namespaced_peer_round_key(namespace, peer_id);
        self.db.put_string(&key, &round)?;
        debug!(
            "💾 [VRF_STORAGE:{}{}] Stored peer {} round {}",
            self.prefix, namespace, peer_id, round
        );
        Ok(())
    }

    /// Get a peer's VRF round from the database.
    pub fn get_peer_round(&self, peer_id: &str) -> Result<Option<u64>> {
        self.get_peer_round_for_context("", peer_id)
    }

    pub fn get_peer_round_for_context(
        &self,
        namespace: &str,
        peer_id: &str,
    ) -> Result<Option<u64>> {
        let key = self.namespaced_peer_round_key(namespace, peer_id);
        self.db.get_string::<u64>(&key)
    }

    /// Get all peer rounds from the database.
    pub fn get_all_peer_rounds(&self) -> Result<HashMap<String, u64>> {
        self.get_all_peer_rounds_for_context("")
    }

    pub fn get_all_peer_rounds_for_context(&self, namespace: &str) -> Result<HashMap<String, u64>> {
        let namespace_prefix = if namespace.is_empty() {
            String::new()
        } else {
            format!("{}:", namespace)
        };

        let base_prefix = crate::database::primitives::keys::VRF_PEER_ROUND;
        let full_prefix = format!("{}{}{}", self.prefix, namespace_prefix, base_prefix);
        let results: Vec<(String, u64)> = self.db.get_values_with_prefix(&full_prefix)?;

        let mut peer_rounds = HashMap::new();
        for (key, round) in results {
            // Extract peer_id from key by removing both prefixes
            if let Some(peer_id) = key.strip_prefix(&full_prefix) {
                peer_rounds.insert(peer_id.to_string(), round);
            }
        }

        debug!(
            "🔍 [VRF_STORAGE:{}{}] Retrieved {} peer rounds from database",
            self.prefix,
            namespace,
            peer_rounds.len()
        );
        Ok(peer_rounds)
    }

    /// Remove a peer's VRF round from the database (for cleanup).
    pub fn remove_peer_round(&self, peer_id: &str) -> Result<()> {
        let key = format!("{}{}", self.prefix, key_utils::vrf_peer_round_key(peer_id));
        self.db.delete(&key)?;
        debug!(
            "🗑️ [VRF_STORAGE:{}] Removed peer {} round",
            self.prefix, peer_id
        );
        Ok(())
    }

    /// Store selected nodes for a specific round
    /// This allows recovery of selected_nodes after node restarts
    pub fn store_selected_nodes(
        &self,
        round: u64,
        nodes: &[crate::types::p2p::SerializablePeerId],
    ) -> Result<()> {
        let key = format!("{}selected_nodes:{}", self.prefix, round);
        let nodes_json = serde_json::to_string(nodes)?;
        self.db.put_string(&key, &nodes_json)?;
        debug!(
            "💾 [VRF_STORAGE:{}] Stored {} selected nodes for round {}",
            self.prefix,
            nodes.len(),
            round
        );
        Ok(())
    }

    /// Get selected nodes for a specific round
    pub fn get_selected_nodes(
        &self,
        round: u64,
    ) -> Result<Option<Vec<crate::types::p2p::SerializablePeerId>>> {
        let key = format!("{}selected_nodes:{}", self.prefix, round);
        let json_str_opt: Option<String> = self.db.get_string(&key)?;
        match json_str_opt {
            Some(json_str) => Ok(Some(serde_json::from_str(&json_str)?)),
            None => Ok(None),
        }
    }
}
