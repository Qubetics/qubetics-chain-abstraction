use crate::database::{key_utils, keys, Database};
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

    /// Store total liquidity in tics (legacy u64)
    pub async fn set_total_liquidity_tics(&self, tics: u64) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_TICS, &tics)?;
        Ok(())
    }

    /// Get total liquidity in tics (legacy u64)
    pub async fn get_total_liquidity_tics(&self) -> Result<Option<u64>> {
        self.db.get_string(keys::TOTAL_LIQUIDITY_TICS)
    }

    /// Store total liquidity in TICS as U256 (string)
    pub async fn set_total_liquidity_tics_u256(&self, tics: U256) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_TICS, &tics.to_string())?;
        Ok(())
    }

    /// Get total liquidity in TICS as U256 (string)
    pub async fn get_total_liquidity_tics_u256(&self) -> Result<Option<U256>> {
        if let Some(s) = self.db.get_string::<String>(keys::TOTAL_LIQUIDITY_TICS)? {
            Ok(Some(U256::from_dec_str(&s).map_err(|e| anyhow::anyhow!("parse tics u256: {}", e))?))
        } else {
            Ok(None)
        }
    }

    /// Store total liquidity in BTC (legacy f64)
    pub async fn set_total_liquidity_btc(&self, btc: f64) -> Result<()> {
        self.db
            .put_string(keys::TOTAL_LIQUIDITY_BTC, &btc.to_string())?;
        Ok(())
    }

    /// Get total liquidity in BTC (legacy f64)
    pub async fn get_total_liquidity_btc(&self) -> Result<Option<f64>> {
        self.db.get_string(keys::TOTAL_LIQUIDITY_BTC)
    }

    /// Store total liquidity in BTC as U256 satoshis (string)
    pub async fn set_total_liquidity_btc_u256(&self, sats: U256) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_BTC, &sats.to_string())?;
        Ok(())
    }

    /// Get total liquidity in BTC as U256 satoshis (string)
    pub async fn get_total_liquidity_btc_u256(&self) -> Result<Option<U256>> {
        if let Some(s) = self.db.get_string::<String>(keys::TOTAL_LIQUIDITY_BTC)? {
            Ok(Some(U256::from_dec_str(&s).map_err(|e| anyhow::anyhow!("parse btc u256: {}", e))?))
        } else {
            Ok(None)
        }
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
    pub async fn set_solver_reward_tics(&self, solver_address: &str, reward_tics: U256) -> Result<()> {
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
    pub async fn set_solver_reward_btc(&self, solver_address: &str, reward_btc_sats: U256) -> Result<()> {
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
}
