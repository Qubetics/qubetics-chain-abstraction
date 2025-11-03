use crate::{
	database::{
		constants::*,
		keys::{AllSolverLiquidityKey, LiquidityLastUpdateKey, SolverLiquidity},
		traits::Storage,
		Database,
	},
	define_storage_adapter,
};
use anyhow::Result;
use ethers::types::U256;
use std::collections::HashMap;
use tracing::{debug, error, info};

define_storage_adapter!(
	SolverLiquidityAdapter,
	SolverLiquidity,
	Vec<String>,
	SOLVER_LIQUIDITY_PREFIX
);

define_storage_adapter!(
	AllSolverLiquidityAdapter,
	AllSolverLiquidityKey,
	HashMap<String, Vec<String>>,
	ALL_SOLVER_LIQUIDITY_PREFIX
);

define_storage_adapter!(
	LiquidityLastUpdateAdapter,
	LiquidityLastUpdateKey,
	String,
	LIQUIDITY_LAST_UPDATE_PREFIX
);

pub type SolverLiquidityStorage = Storage<SolverLiquidityAdapter>;
pub type AllSolverLiquidityStorage = Storage<AllSolverLiquidityAdapter>;
pub type LiquidityLastUpdateStorage = Storage<LiquidityLastUpdateAdapter>;

/// Database-backed solver storage
#[derive(Clone)]
pub struct SolverStorage {
	solver_liquidity: SolverLiquidityStorage,
	all_solver_liquidity: AllSolverLiquidityStorage,
	liquidity_last_update: LiquidityLastUpdateStorage,
}

impl SolverStorage {
	pub fn new(db: Database) -> Self {
		Self {
			solver_liquidity: SolverLiquidityStorage::new(db.clone()),
			all_solver_liquidity: AllSolverLiquidityStorage::new(db.clone()),
			liquidity_last_update: LiquidityLastUpdateStorage::new(db.clone()),
		}
	}

	/// Store liquidity amounts for a specific solver
	pub async fn store_solver_liquidity(
		&self,
		solver_address: &str,
		liquidity_amounts: &Vec<String>,
	) -> Result<()> {
		let key = SolverLiquidity { address: solver_address.to_string() };

		info!("💾 [SOLVER_STORAGE] Starting to store solver liquidity:");
		info!("  🔗 Solver address: {}", solver_address);
		info!("  💰 Liquidity amounts: {:?}", liquidity_amounts);
		info!("  🗄️  Database key: {:?}", key);

		match self.solver_liquidity.put(key.clone(), &liquidity_amounts) {
			Ok(()) => {
				info!(
					"✅ [SOLVER_STORAGE] Successfully stored solver liquidity: {}",
					solver_address
				);
				info!("  💰 Stored {} liquidity entries", liquidity_amounts.len());
				Ok(())
			},
			Err(e) => {
				error!("❌ [SOLVER_STORAGE] Failed to store solver liquidity: {}", solver_address);
				error!("  🗄️  Database key: {:?}", key);
				error!("  💥 Error: {}", e);
				Err(e)
			},
		}
	}

	/// Get liquidity amounts for a specific solver
	pub async fn get_solver_liquidity(&self, solver_address: &str) -> Result<Option<Vec<String>>> {
		let key = SolverLiquidity { address: solver_address.to_string() };
		let liquidity = self.solver_liquidity.get(key)?;
		if liquidity.is_some() {
			debug!("🔍 [SOLVER_STORAGE] Retrieved solver liquidity: {}", solver_address);
		}
		Ok(liquidity)
	}

	/// Get all solver liquidity data
	pub async fn get_all_solver_liquidity(&self) -> Result<HashMap<String, Vec<String>>> {
		let liquidity_data = self.solver_liquidity.get_all();
		liquidity_data.map(|data| {
			data.into_iter()
				.map(|(key, value)| (String::from_utf8(key).unwrap(), value))
				.collect()
		})
	}

	/// Delete liquidity data for a specific solver
	pub async fn delete_solver_liquidity(&self, solver_address: &str) -> Result<()> {
		let key = SolverLiquidity { address: solver_address.to_string() };
		self.solver_liquidity.delete(key)?;
		info!("🗑️ [SOLVER_STORAGE] Deleted solver liquidity: {}", solver_address);
		Ok(())
	}

	/// Store all solver liquidity data in a single record
	pub async fn store_all_solver_liquidity(
		&self,
		all_liquidity: &HashMap<String, Vec<String>>,
	) -> Result<()> {
		let key = AllSolverLiquidityKey;

		info!("💾 [SOLVER_STORAGE] Starting to store all solver liquidity:");
		info!("  📊 Total solvers: {}", all_liquidity.len());
		info!("  🗄️  Database key: {:?}", key);

		match self.all_solver_liquidity.put(key.clone(), all_liquidity) {
			Ok(()) => {
				info!("✅ [SOLVER_STORAGE] Successfully stored all solver liquidity");
				info!("  📊 Stored liquidity for {} solvers", all_liquidity.len());
				Ok(())
			},
			Err(e) => {
				error!("❌ [SOLVER_STORAGE] Failed to store all solver liquidity");
				error!("  🗄️  Database key: {:?}", key);
				error!("  💥 Error: {}", e);
				Err(e)
			},
		}
	}

	/// Get all solver liquidity data from the single record
	pub async fn get_all_solver_liquidity_record(
		&self,
	) -> Result<Option<HashMap<String, Vec<String>>>> {
		let key = AllSolverLiquidityKey;
		let all_liquidity = self.all_solver_liquidity.get(key)?;
		if all_liquidity.is_some() {
			debug!("🔍 [SOLVER_STORAGE] Retrieved all solver liquidity record");
		}
		Ok(all_liquidity)
	}

	/// Delete all solver liquidity record
	pub async fn delete_all_solver_liquidity_record(&self) -> Result<()> {
		let key = AllSolverLiquidityKey;
		self.all_solver_liquidity.delete(key)?;
		info!("🗑️ [SOLVER_STORAGE] Deleted all solver liquidity record");
		Ok(())
	}

	/// Store the last update timestamp for liquidity
	pub async fn store_liquidity_last_update(&self, timestamp: &str) -> Result<()> {
		let key = LiquidityLastUpdateKey;

		info!("💾 [SOLVER_STORAGE] Storing liquidity last update timestamp: {}", timestamp);

		match self.liquidity_last_update.put(key.clone(), &timestamp.to_string()) {
			Ok(()) => {
				info!(
					"✅ [SOLVER_STORAGE] Successfully stored liquidity last update: {}",
					timestamp
				);
				Ok(())
			},
			Err(e) => {
				error!("❌ [SOLVER_STORAGE] Failed to store liquidity last update");
				error!("  💥 Error: {}", e);
				Err(e)
			},
		}
	}

	/// Get the last update timestamp for liquidity
	pub async fn get_liquidity_last_update(&self) -> Result<Option<String>> {
		let key = LiquidityLastUpdateKey;
		let timestamp = self.liquidity_last_update.get(key)?;

		if timestamp.is_some() {
			debug!("🔍 [SOLVER_STORAGE] Retrieved liquidity last update timestamp");
		} else {
			debug!("🔍 [SOLVER_STORAGE] No liquidity last update timestamp found");
		}

		Ok(timestamp)
	}

	/// Delete the last update timestamp
	pub async fn delete_liquidity_last_update(&self) -> Result<()> {
		let key = LiquidityLastUpdateKey;
		self.liquidity_last_update.delete(key)?;
		info!("🗑️ [SOLVER_STORAGE] Deleted liquidity last update timestamp");
		Ok(())
	}

	/// Update liquidity last update to current timestamp
	pub async fn update_liquidity_timestamp(&self) -> Result<()> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs()
			.to_string();

		self.store_liquidity_last_update(&now).await
	}
}
