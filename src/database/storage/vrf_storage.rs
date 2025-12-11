use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::database::{key_utils, Database};

/// Storage wrapper for VRF metadata persisted in RocksDB.
#[derive(Clone)]
pub struct VrfStorage {
    db: Database,
}

impl VrfStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get access to the underlying database (primarily for testing/introspection).
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Fetch the current VRF round from storage, initializing to 0 if absent.
    pub fn get_current_round(&self) -> Result<u64> {
        let key = key_utils::vrf_current_round_key();
        match self.db.get_string::<u64>(&key)? {
            Some(round) => {
                debug!("🔍 [VRF_STORAGE] Retrieved current round: {}", round);
                Ok(round)
            }
            None => {
                // Initialize to 0 if missing to keep behavior deterministic.
                self.set_current_round(0)?;
                warn!("ℹ️ [VRF_STORAGE] current round not found; defaulting to 0");
                Ok(0)
            }
        }
    }

    /// Persist the provided round as the current VRF round.
    pub fn set_current_round(&self, round: u64) -> Result<()> {
        let key = key_utils::vrf_current_round_key();
        self.db.put_string(&key, &round)?;
        info!("✅ [VRF_STORAGE] Set current round to {}", round);
        Ok(())
    }

    /// Store a peer's VRF round in the database.
    pub fn set_peer_round(&self, peer_id: &str, round: u64) -> Result<()> {
        let key = key_utils::vrf_peer_round_key(peer_id);
        self.db.put_string(&key, &round)?;
        debug!("💾 [VRF_STORAGE] Stored peer {} round {}", peer_id, round);
        Ok(())
    }

    /// Get a peer's VRF round from the database.
    pub fn get_peer_round(&self, peer_id: &str) -> Result<Option<u64>> {
        let key = key_utils::vrf_peer_round_key(peer_id);
        self.db.get_string::<u64>(&key)
    }

    /// Get all peer rounds from the database.
    pub fn get_all_peer_rounds(&self) -> Result<HashMap<String, u64>> {
        let prefix = crate::database::primitives::keys::VRF_PEER_ROUND;
        let results: Vec<(String, u64)> = self.db.get_values_with_prefix(prefix)?;

        let mut peer_rounds = HashMap::new();
        for (key, round) in results {
            // Extract peer_id from key by removing prefix
            if let Some(peer_id) = key.strip_prefix(prefix) {
                peer_rounds.insert(peer_id.to_string(), round);
            }
        }

        debug!(
            "🔍 [VRF_STORAGE] Retrieved {} peer rounds from database",
            peer_rounds.len()
        );
        Ok(peer_rounds)
    }

    /// Remove a peer's VRF round from the database (for cleanup).
    pub fn remove_peer_round(&self, peer_id: &str) -> Result<()> {
        let key = key_utils::vrf_peer_round_key(peer_id);
        self.db.delete(&key)?;
        debug!("🗑️ [VRF_STORAGE] Removed peer {} round", peer_id);
        Ok(())
    }
}
