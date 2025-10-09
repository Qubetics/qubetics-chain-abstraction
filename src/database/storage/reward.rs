use crate::database::{db::Database, traits::KvStorage, ClaimedRequestAmountKey, IntentRewardStatusKey, SolverRewardBtcKey, SolverRewardKey, SolverRewardTicsKey, TotalLiquidityBtcKey, TotalLiquidityTicsKey };
use anyhow::Result;
use ethers::types::U256;
use rocksdb::DB;
use std::sync::Arc;


/// Database-backed reward storage
#[derive(Clone)]
pub struct RewardStorage {
	db: Database,
}

impl KvStorage for RewardStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}


impl RewardStorage {
	pub fn new(db: Database) -> Self {
		Self { db }
	}

	/// Store total liquidity in tics (legacy u64)
	pub async fn set_total_liquidity_tics(&self, tics: u64) -> Result<()> {
        let key = TotalLiquidityTicsKey {};
		self.put(key, &tics)?;
		Ok(())
	}

	/// Get total liquidity in tics (legacy u64)
	pub async fn get_total_liquidity_tics(&self) -> Result<Option<u64>> {
        let key = TotalLiquidityTicsKey{};

		self.get(key)
	}

	/// Store total liquidity in TICS as U256 (string)
	pub async fn set_total_liquidity_tics_u256(&self, tics: U256) -> Result<()> {
        let key = TotalLiquidityTicsKey{};
		self.put(key, &tics)?;
		Ok(())
	}

	/// Get total liquidity in TICS as U256 (string)
	pub async fn get_total_liquidity_tics_u256(&self) -> Result<Option<U256>> {
        let key = TotalLiquidityTicsKey{};
		if let Some(s) = self.get::<_, String>(key)? {
			Ok(Some(U256::from_dec_str(&s).map_err(|e| anyhow::anyhow!("parse tics u256: {}", e))?))
		} else {
			Ok(None)
		}
	}

	/// Store total liquidity in BTC (legacy f64)
	pub async fn set_total_liquidity_btc(&self, btc: f64) -> Result<()> {
        let key = TotalLiquidityBtcKey{};
		self.put(key, &btc)?;
		Ok(())
	}

	/// Get total liquidity in BTC (legacy f64)
	pub async fn get_total_liquidity_btc(&self) -> Result<Option<f64>> {
        let key = TotalLiquidityBtcKey{};
		self.get(key)
	}

	/// Store total liquidity in BTC as U256 satoshis (string)
	pub async fn set_total_liquidity_btc_u256(&self, sats: U256) -> Result<()> {
        let key = TotalLiquidityBtcKey{};
		self.put(key, &sats)?;
		Ok(())
	}

	/// Get total liquidity in BTC as U256 satoshis (string)
	pub async fn get_total_liquidity_btc_u256(&self) -> Result<Option<U256>> {
        let key = TotalLiquidityBtcKey{};
		if let Some(s) = self.get::<_, String>(key)? {
			Ok(Some(U256::from_dec_str(&s).map_err(|e| anyhow::anyhow!("parse btc u256: {}", e))?))
		} else {
			Ok(None)
		}
	}

	/// Delete total liquidity tics
	pub async fn delete_total_liquidity_tics(&self) -> Result<()> {
        let key = TotalLiquidityTicsKey{};

		self.delete(key)?;
		Ok(())
	}

	/// Delete total liquidity btc
	pub async fn delete_total_liquidity_btc(&self) -> Result<()> {
        let key = TotalLiquidityBtcKey{};
		self.delete(key)?;
		Ok(())
	}

	/// Store reward for a specific solver (legacy single-metric key - kept for BC)
	pub async fn set_solver_reward(&self, solver_address: &str, reward: U256) -> Result<()> {
		let key = SolverRewardKey {
            solver_address: solver_address.to_string(),
        };
		self.put(key, &reward)?;
		Ok(())
	}

	/// Get reward for a specific solver (legacy single-metric key - kept for BC)
	pub async fn get_solver_reward(&self, solver_address: &str) -> Result<Option<U256>> {
		let key = SolverRewardKey {
            solver_address: solver_address.to_string(),
        };
		if let Some(value) = self.get::<_, String>(key)? {
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
        let key = SolverRewardTicsKey {
            solver_address: solver_address.to_string(),
        };
		self.put(key, &reward_tics)?;
		Ok(())
	}

	/// Get TICS reward for a specific solver
	pub async fn get_solver_reward_tics(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = SolverRewardTicsKey {
            solver_address: solver_address.to_string(),
        };

		if let Some(value) = self.get::<_,String>(key)? {
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
        let key = SolverRewardBtcKey {
            solver_address: solver_address.to_string(),
        };
		self.put(key, &reward_btc_sats)?;
		Ok(())
	}

	/// Get BTC reward for a specific solver (in satoshis as U256)
	pub async fn get_solver_reward_btc(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = SolverRewardBtcKey {
            solver_address: solver_address.to_string(),
        };
		if let Some(value) = self.get::<_,String>(key)? {
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
        let key = ClaimedRequestAmountKey {
            solver_address: solver_address.to_string(),
        };

		self.put(key, &amount)?;
		Ok(())
	}

	/// Get claimed request amount for a specific solver
	pub async fn get_claimed_request_amount(&self, solver_address: &str) -> Result<Option<U256>> {
        let key = ClaimedRequestAmountKey {
            solver_address: solver_address.to_string(),
        };
		if let Some(value) = self.get::<_,String>(key)? {
			let amount = U256::from_dec_str(&value)
				.map_err(|e| anyhow::anyhow!("Failed to parse claimed amount: {}", e))?;
			Ok(Some(amount))
		} else {
			Ok(None)
		}
	}

	/// Set reward calculation status for a specific intent hash
	pub async fn set_intent_reward_status(&self, intent_hash: &str, status: bool) -> Result<()> {
        let key = IntentRewardStatusKey {
            intent_hash: intent_hash.to_string(),
        };
		self.put(key, &status)?;
		Ok(())
	}

	/// Get reward calculation status for a specific intent hash
	pub async fn get_intent_reward_status(&self, intent_hash: &str) -> Result<Option<bool>> {
        let key = IntentRewardStatusKey{
            intent_hash: intent_hash.to_string(),
        };
		self.get(key)
	}
}


