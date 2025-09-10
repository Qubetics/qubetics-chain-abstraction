use crate::database::{Database, key_utils, keys};
use anyhow::Result;
use ethers::types::U256;

/// Database-backed reward storage
#[derive(Clone)]
pub struct RewardStorage {
    db: Database,
}

impl RewardStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store total liquidity in tics
    pub async fn set_total_liquidity_tics(&self, tics: u64) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_TICS, &tics)?;
        Ok(())
    }

    /// Get total liquidity in tics
    pub async fn get_total_liquidity_tics(&self) -> Result<Option<u64>> {
        self.db.get_string(keys::TOTAL_LIQUIDITY_TICS)
    }

    /// Store total liquidity in BTC (as f64)
    pub async fn set_total_liquidity_btc(&self, btc: f64) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_BTC, &btc.to_string())?;
        Ok(())
    }

    /// Get total liquidity in BTC (as f64)
    pub async fn get_total_liquidity_btc(&self) -> Result<Option<f64>> {
        self.db.get_string(keys::TOTAL_LIQUIDITY_BTC)
    }

    /// Delete total liquidity tics
    pub async fn delete_total_liquidity_tics(&self) -> Result<()> {
        self.db.delete_string(keys::TOTAL_LIQUIDITY_TICS)?;
        Ok(())
    }

    /// Delete total liquidity btc
    pub async fn delete_total_liquidity_btc(&self) -> Result<()> {
        self.db.delete_string(keys::TOTAL_LIQUIDITY_BTC)?;
        Ok(())
    }

    /// Store reward for a specific solver
    pub async fn set_solver_reward(&self, solver_address: &str, reward: U256) -> Result<()> {
        let key = key_utils::solver_reward_key(solver_address);
       self.db.put_string(&key, &reward.to_string())?;
        Ok(())
    }

    /// Get reward for a specific solver
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
}
