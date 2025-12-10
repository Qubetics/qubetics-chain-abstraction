use anyhow::Result;
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
}
