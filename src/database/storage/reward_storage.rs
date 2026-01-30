use crate::database::{key_utils, Database};
use anyhow::Result;
use ethers::types::U256;
use serde_json;

/// Database-backed reward storage
#[derive(Clone)]
pub struct RewardStorage {
    db: Database,
}

impl RewardStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // Total liquidity helpers (TICS/BTC) have been removed.
    // Liquidity is now derived directly from the on-chain SolverManager contract.

    /// Store reward for a specific solver (legacy single-metric key - kept for BC)
    pub async fn set_solver_reward(&self, solver_address: &str, reward: U256) -> Result<()> {
        let key = key_utils::solver_reward_key(solver_address);
        self.db.put_string(&key, &reward.to_string())?;
        Ok(())
    }

    /// Get reward for a specific solver (legacy single-metric key - kept for BC)
    pub async fn get_solver_reward(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = key_utils::solver_reward_key(solver_address);
        if let Some(value) = self.db.get_string::<String>(&key)? {
            let reward = U256::from_dec_str(&value)
                .map_err(|e| anyhow::anyhow!("Failed to parse reward: {}", e))?;
            Ok(Some(reward))
        } else {
            Ok(None)
        }
    }

    /// Store TICS reward for a specific solver
    pub async fn set_solver_reward_tics(
        &self,
        solver_address: &str,
        reward_tics: U256,
    ) -> Result<()> {
        let key = key_utils::solver_reward_tics_key(solver_address);
        self.db.put_string(&key, &reward_tics.to_string())?;
        Ok(())
    }

    /// Get TICS reward for a specific solver
    pub async fn get_solver_reward_tics(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = key_utils::solver_reward_tics_key(solver_address);
        if let Some(value) = self.db.get_string::<String>(&key)? {
            let reward = U256::from_dec_str(&value)
                .map_err(|e| anyhow::anyhow!("Failed to parse tics reward: {}", e))?;
            Ok(Some(reward))
        } else {
            Ok(None)
        }
    }

    /// Store BTC reward for a specific solver (in satoshis as U256)
    pub async fn set_solver_reward_btc(
        &self,
        solver_address: &str,
        reward_btc_sats: U256,
    ) -> Result<()> {
        let key = key_utils::solver_reward_btc_key(solver_address);
        self.db.put_string(&key, &reward_btc_sats.to_string())?;
        Ok(())
    }

    /// Get BTC reward for a specific solver (in satoshis as U256)
    pub async fn get_solver_reward_btc(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = key_utils::solver_reward_btc_key(solver_address);
        if let Some(value) = self.db.get_string::<String>(&key)? {
            let reward = U256::from_dec_str(&value)
                .map_err(|e| anyhow::anyhow!("Failed to parse btc reward: {}", e))?;
            Ok(Some(reward))
        } else {
            Ok(None)
        }
    }

    /// Store claimed request amount for a specific solver
    pub async fn set_claimed_request_amount(
        &self,
        solver_address: &str,
        amount: U256,
    ) -> Result<()> {
        let key = key_utils::claimed_request_amount_key(solver_address);
        self.db.put_string(&key, &amount.to_string())?;
        Ok(())
    }

    /// Get claimed request amount for a specific solver
    pub async fn get_claimed_request_amount(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = key_utils::claimed_request_amount_key(solver_address);
        if let Some(value) = self.db.get_string::<String>(&key)? {
            let amount = U256::from_dec_str(&value)
                .map_err(|e| anyhow::anyhow!("Failed to parse claimed amount: {}", e))?;
            Ok(Some(amount))
        } else {
            Ok(None)
        }
    }

    /// Set reward calculation status for a specific intent hash
    pub async fn set_intent_reward_status(&self, intent_hash: &str, status: bool) -> Result<()> {
        let key = key_utils::intent_reward_status_key(intent_hash);
        self.db.put_string(&key, &status)?;
        Ok(())
    }

    /// Get reward calculation status for a specific intent hash
    pub async fn get_intent_reward_status(&self, intent_hash: &str) -> Result<Option<bool>> {
        let key = key_utils::intent_reward_status_key(intent_hash);
        self.db.get_string(&key)
    }

    /// Store the latest TICS transaction hash for a specific solver
    pub async fn set_solver_tics_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        let key = key_utils::solver_tics_txn_hashes_key(solver_address);
        self.db.put_string(&key, &txn_hash)?;
        Ok(())
    }

    /// Get the latest TICS transaction hash for a specific solver.
    /// Supports legacy serialized Vec<String> values by returning the most recent entry.
    pub async fn get_solver_tics_txn_hash(&self, solver_address: &str) -> Result<Option<String>> {
        let key = key_utils::solver_tics_txn_hashes_key(solver_address);
        if let Some(serialized) = self.db.get_string::<String>(&key)? {
            if let Ok(mut txn_hashes) = serde_json::from_str::<Vec<String>>(&serialized) {
                Ok(txn_hashes.pop())
            } else if serialized.is_empty() {
                Ok(None)
            } else {
                Ok(Some(serialized))
            }
        } else {
            Ok(None)
        }
    }

    /// Add a single TICS transaction hash (overwrites with the latest)
    pub async fn add_solver_tics_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        self.set_solver_tics_txn_hash(solver_address, txn_hash)
            .await
    }

    /// Store the latest BTC transaction hash for a specific solver
    pub async fn set_solver_btc_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        let key = key_utils::solver_btc_txn_hashes_key(solver_address);
        self.db.put_string(&key, &txn_hash)?;
        Ok(())
    }

    /// Get the latest BTC transaction hash for a specific solver (supports legacy Vec<String>)
    pub async fn get_solver_btc_txn_hash(&self, solver_address: &str) -> Result<Option<String>> {
        let key = key_utils::solver_btc_txn_hashes_key(solver_address);
        if let Some(serialized) = self.db.get_string::<String>(&key)? {
            if let Ok(mut txn_hashes) = serde_json::from_str::<Vec<String>>(&serialized) {
                Ok(txn_hashes.pop())
            } else if serialized.is_empty() {
                Ok(None)
            } else {
                Ok(Some(serialized))
            }
        } else {
            Ok(None)
        }
    }

    /// Add a single BTC transaction hash (overwrites with the latest)
    pub async fn add_solver_btc_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        self.set_solver_btc_txn_hash(solver_address, txn_hash).await
    }

    /// Clear TICS transaction hashes for a specific solver
    pub async fn clear_solver_tics_txn_hashes(&self, solver_address: &str) -> Result<()> {
        let key = key_utils::solver_tics_txn_hashes_key(solver_address);
        self.db.delete_string(&key)?;
        Ok(())
    }

    /// Clear BTC transaction hashes for a specific solver
    pub async fn clear_solver_btc_txn_hashes(&self, solver_address: &str) -> Result<()> {
        let key = key_utils::solver_btc_txn_hashes_key(solver_address);
        self.db.delete_string(&key)?;
        Ok(())
    }
}
