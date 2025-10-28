use crate::{
	database::{
		constants::{
			CLAIMED_REQUEST_AMOUNT_PREFIX, INTENT_REWARD_STATUS_PREFIX,
			SOLVER_BTC_TXN_HASHES_PREFIX, SOLVER_REWARD_BTC_PREFIX, SOLVER_REWARD_PREFIX,
			SOLVER_REWARD_TICS_PREFIX, SOLVER_TICS_TXN_HASHES_PREFIX, TOTAL_LIQUIDITY_BTC_PREFIX,
			TOTAL_LIQUIDITY_TICS_PREFIX,
		},
		db::Database,
		keys::{
			ClaimedRequestAmountKey, IntentRewardStatusKey, SolverBtcTxnHashesKey,
			SolverRewardBtcKey, SolverRewardKey, SolverRewardTicsKey, SolverTicsTxnHashesKey,
			TotalLiquidityBtcKey, TotalLiquidityTicsKey,
		},
		traits::Storage,
	},
	define_storage_adapter,
};
use anyhow::Result;
use ethers::types::U256;

define_storage_adapter!(
	TotalLiquidityTicsAdapter,
	TotalLiquidityTicsKey,
	String,
	TOTAL_LIQUIDITY_TICS_PREFIX
);

define_storage_adapter!(
	TotalLiquidityBtcAdapter,
	TotalLiquidityBtcKey,
	String,
	TOTAL_LIQUIDITY_BTC_PREFIX
);

define_storage_adapter!(SolverRewardAdapter, SolverRewardKey, String, SOLVER_REWARD_PREFIX);

define_storage_adapter!(
	SolverRewardTicsAdapter,
	SolverRewardTicsKey,
	String,
	SOLVER_REWARD_TICS_PREFIX
);

define_storage_adapter!(
	SolverRewardBtcAdapter,
	SolverRewardBtcKey,
	String,
	SOLVER_REWARD_BTC_PREFIX
);

define_storage_adapter!(
	ClaimedRequestAmountAdapter,
	ClaimedRequestAmountKey,
	String,
	CLAIMED_REQUEST_AMOUNT_PREFIX
);

define_storage_adapter!(
	IntentRewardStatusAdapter,
	IntentRewardStatusKey,
	bool,
	INTENT_REWARD_STATUS_PREFIX
);

define_storage_adapter!(
	SolverTicsTxnHashesAdapter,
	SolverTicsTxnHashesKey,
	Vec<String>,
	SOLVER_TICS_TXN_HASHES_PREFIX
);

define_storage_adapter!(
	SolverBtcTxnHashesAdapter,
	SolverBtcTxnHashesKey,
	Vec<String>,
	SOLVER_BTC_TXN_HASHES_PREFIX
);

pub type TotalLiquidityTicsStorage = Storage<TotalLiquidityTicsAdapter>;
pub type TotalLiquidityBtcStorage = Storage<TotalLiquidityBtcAdapter>;
pub type SolverRewardStorage = Storage<SolverRewardAdapter>;
pub type SolverRewardTicsStorage = Storage<SolverRewardTicsAdapter>;
pub type SolverRewardBtcStorage = Storage<SolverRewardBtcAdapter>;
pub type ClaimedRequestAmountStorage = Storage<ClaimedRequestAmountAdapter>;
pub type IntentRewardStatusStorage = Storage<IntentRewardStatusAdapter>;
pub type SolverTicsTxnHashesStorage = Storage<SolverTicsTxnHashesAdapter>;
pub type SolverBtcTxnHashesStorage = Storage<SolverBtcTxnHashesAdapter>;

/// Database-backed reward storage
#[derive(Clone)]
pub struct RewardStorage {
	total_liquidity_tics: TotalLiquidityTicsStorage,
	total_liquidity_btc: TotalLiquidityBtcStorage,
	solver_reward: SolverRewardStorage,
	solver_reward_tics: SolverRewardTicsStorage,
	solver_reward_btc: SolverRewardBtcStorage,
	claimed_request_amount: ClaimedRequestAmountStorage,
	intent_reward_status: IntentRewardStatusStorage,
	solver_tics_txn_hashes: SolverTicsTxnHashesStorage,
	solver_btc_txn_hashes: SolverBtcTxnHashesStorage,
}

impl RewardStorage {
	pub fn new(db: Database) -> Self {
		Self {
			total_liquidity_tics: TotalLiquidityTicsStorage::new(db.clone()),
			total_liquidity_btc: TotalLiquidityBtcStorage::new(db.clone()),
			solver_reward: SolverRewardStorage::new(db.clone()),
			solver_reward_tics: SolverRewardTicsStorage::new(db.clone()),
			solver_reward_btc: SolverRewardBtcStorage::new(db.clone()),
			claimed_request_amount: ClaimedRequestAmountStorage::new(db.clone()),
			intent_reward_status: IntentRewardStatusStorage::new(db.clone()),
			solver_tics_txn_hashes: SolverTicsTxnHashesStorage::new(db.clone()),
			solver_btc_txn_hashes: SolverBtcTxnHashesStorage::new(db),
		}
	}

	/// Store total liquidity in tics (legacy u64)
	pub async fn set_total_liquidity_tics(&self, tics: u64) -> Result<()> {
		let key = TotalLiquidityTicsKey {};
		self.total_liquidity_tics.put(key, &tics.to_string())?;
		Ok(())
	}

	/// Get total liquidity in tics (legacy u64)
	pub async fn get_total_liquidity_tics(&self) -> Result<Option<u64>> {
		let key = TotalLiquidityTicsKey {};
		if let Some(value_str) = self.total_liquidity_tics.get(key)? {
			Ok(Some(
				value_str
					.parse::<u64>()
					.map_err(|e| anyhow::anyhow!("Failed to parse tics u64: {}", e))?,
			))
		} else {
			Ok(None)
		}
	}

	/// Store total liquidity in TICS as U256 (string)
	pub async fn set_total_liquidity_tics_u256(&self, tics: U256) -> Result<()> {
		let key = TotalLiquidityTicsKey {};
		self.total_liquidity_tics.put(key, &tics.to_string())?;
		Ok(())
	}

	/// Get total liquidity in TICS as U256 (string)
	pub async fn get_total_liquidity_tics_u256(&self) -> Result<Option<U256>> {
		let key = TotalLiquidityTicsKey {};
		if let Some(s) = self.total_liquidity_tics.get(key)? {
			Ok(Some(U256::from_dec_str(&s).map_err(|e| anyhow::anyhow!("parse tics u256: {}", e))?))
		} else {
			Ok(None)
		}
	}

	/// Store total liquidity in BTC (legacy f64)
	pub async fn set_total_liquidity_btc(&self, btc: f64) -> Result<()> {
		let key = TotalLiquidityBtcKey {};
		self.total_liquidity_btc.put(key, &btc.to_string())?;
		Ok(())
	}

	/// Get total liquidity in BTC (legacy f64)
	pub async fn get_total_liquidity_btc(&self) -> Result<Option<f64>> {
		let key = TotalLiquidityBtcKey {};
		if let Some(value_str) = self.total_liquidity_btc.get(key)? {
			Ok(Some(
				value_str
					.parse::<f64>()
					.map_err(|e| anyhow::anyhow!("Failed to parse btc f64: {}", e))?,
			))
		} else {
			Ok(None)
		}
	}

	/// Store total liquidity in BTC as U256 satoshis (string)
	pub async fn set_total_liquidity_btc_u256(&self, sats: U256) -> Result<()> {
		let key = TotalLiquidityBtcKey {};
		self.total_liquidity_btc.put(key, &sats.to_string())?;
		Ok(())
	}

	/// Get total liquidity in BTC as U256 satoshis (string)
	pub async fn get_total_liquidity_btc_u256(&self) -> Result<Option<U256>> {
		let key = TotalLiquidityBtcKey {};
		if let Some(s) = self.total_liquidity_btc.get(key)? {
			Ok(Some(U256::from_dec_str(&s).map_err(|e| anyhow::anyhow!("parse btc u256: {}", e))?))
		} else {
			Ok(None)
		}
	}

	/// Delete total liquidity tics
	pub async fn delete_total_liquidity_tics(&self) -> Result<()> {
		let key = TotalLiquidityTicsKey {};
		self.total_liquidity_tics.delete(key)?;
		Ok(())
	}

	/// Delete total liquidity btc
	pub async fn delete_total_liquidity_btc(&self) -> Result<()> {
		let key = TotalLiquidityBtcKey {};
		self.total_liquidity_btc.delete(key)?;
		Ok(())
	}

	/// Store reward for a specific solver (legacy single-metric key - kept for BC)
	pub async fn set_solver_reward(&self, solver_address: &str, reward: U256) -> Result<()> {
		let key = SolverRewardKey { solver_address: solver_address.to_string() };
		self.solver_reward.put(key, &reward.to_string())?;
		Ok(())
	}

	/// Get reward for a specific solver (legacy single-metric key - kept for BC)
	pub async fn get_solver_reward(&self, solver_address: &str) -> Result<Option<U256>> {
		let key = SolverRewardKey { solver_address: solver_address.to_string() };
		if let Some(value) = self.solver_reward.get(key)? {
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
		let key = SolverRewardTicsKey { solver_address: solver_address.to_string() };
		self.solver_reward_tics.put(key, &reward_tics.to_string())?;
		Ok(())
	}

	/// Get TICS reward for a specific solver
	pub async fn get_solver_reward_tics(&self, solver_address: &str) -> Result<Option<U256>> {
		let key = SolverRewardTicsKey { solver_address: solver_address.to_string() };

		if let Some(value) = self.solver_reward_tics.get(key)? {
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
		let key = SolverRewardBtcKey { solver_address: solver_address.to_string() };
		self.solver_reward_btc.put(key, &reward_btc_sats.to_string())?;
		Ok(())
	}

	/// Get BTC reward for a specific solver (in satoshis as U256)
	pub async fn get_solver_reward_btc(&self, solver_address: &str) -> Result<Option<U256>> {
		let key = SolverRewardBtcKey { solver_address: solver_address.to_string() };
		if let Some(value) = self.solver_reward_btc.get(key)? {
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
		let key = ClaimedRequestAmountKey { solver_address: solver_address.to_string() };

		self.claimed_request_amount.put(key, &amount.to_string())?;
		Ok(())
	}

	/// Get claimed request amount for a specific solver
	pub async fn get_claimed_request_amount(&self, solver_address: &str) -> Result<Option<U256>> {
		let key = ClaimedRequestAmountKey { solver_address: solver_address.to_string() };
		if let Some(value) = self.claimed_request_amount.get(key)? {
			let amount = U256::from_dec_str(&value)
				.map_err(|e| anyhow::anyhow!("Failed to parse claimed amount: {}", e))?;
			Ok(Some(amount))
		} else {
			Ok(None)
		}
	}

	/// Set reward calculation status for a specific intent hash
	pub async fn set_intent_reward_status(&self, intent_hash: &str, status: bool) -> Result<()> {
		let key = IntentRewardStatusKey { intent_hash: intent_hash.to_string() };
		self.intent_reward_status.put(key, &status)?;
		Ok(())
	}

	/// Get reward calculation status for a specific intent hash
	pub async fn get_intent_reward_status(&self, intent_hash: &str) -> Result<Option<bool>> {
		let key = IntentRewardStatusKey { intent_hash: intent_hash.to_string() };
		self.intent_reward_status.get(key)
	}

	/// Store TICS transaction hashes for a specific solver
	pub async fn set_solver_tics_txn_hashes(
		&self,
		solver_address: &str,
		txn_hashes: Vec<String>,
	) -> Result<()> {
		let key = SolverTicsTxnHashesKey { solver_address: solver_address.to_string() };
		self.solver_tics_txn_hashes.put(key, &txn_hashes)?;
		Ok(())
	}

	/// Get TICS transaction hashes for a specific solver
	pub async fn get_solver_tics_txn_hashes(
		&self,
		solver_address: &str,
	) -> Result<Option<Vec<String>>> {
		let key = SolverTicsTxnHashesKey { solver_address: solver_address.to_string() };
		self.solver_tics_txn_hashes.get(key)
	}

	/// Add a single TICS transaction hash to a solver's list
	pub async fn add_solver_tics_txn_hash(
		&self,
		solver_address: &str,
		txn_hash: String,
	) -> Result<()> {
		let mut existing_hashes =
			self.get_solver_tics_txn_hashes(solver_address).await?.unwrap_or_default();
		existing_hashes.push(txn_hash);
		self.set_solver_tics_txn_hashes(solver_address, existing_hashes).await
	}

	/// Store BTC transaction hashes for a specific solver
	pub async fn set_solver_btc_txn_hashes(
		&self,
		solver_address: &str,
		txn_hashes: Vec<String>,
	) -> Result<()> {
		let key = SolverBtcTxnHashesKey { solver_address: solver_address.to_string() };
		self.solver_btc_txn_hashes.put(key, &txn_hashes)?;
		Ok(())
	}

	/// Get BTC transaction hashes for a specific solver
	pub async fn get_solver_btc_txn_hashes(
		&self,
		solver_address: &str,
	) -> Result<Option<Vec<String>>> {
		let key = SolverBtcTxnHashesKey { solver_address: solver_address.to_string() };
		self.solver_btc_txn_hashes.get(key)
	}

	/// Add a single BTC transaction hash to a solver's list
	pub async fn add_solver_btc_txn_hash(
		&self,
		solver_address: &str,
		txn_hash: String,
	) -> Result<()> {
		let mut existing_hashes =
			self.get_solver_btc_txn_hashes(solver_address).await?.unwrap_or_default();
		existing_hashes.push(txn_hash);
		self.set_solver_btc_txn_hashes(solver_address, existing_hashes).await
	}

	/// Clear TICS transaction hashes for a specific solver
	pub async fn clear_solver_tics_txn_hashes(&self, solver_address: &str) -> Result<()> {
		let key = SolverTicsTxnHashesKey { solver_address: solver_address.to_string() };
		self.solver_tics_txn_hashes.delete(key)?;
		Ok(())
	}

	/// Clear BTC transaction hashes for a specific solver
	pub async fn clear_solver_btc_txn_hashes(&self, solver_address: &str) -> Result<()> {
		let key = SolverBtcTxnHashesKey { solver_address: solver_address.to_string() };
		self.solver_btc_txn_hashes.delete(key)?;
		Ok(())
	}
}
