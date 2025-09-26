use std::env;
#[derive(Debug, Clone)]
pub struct EnvVars {
	// Ethereum configuration
	pub mpc_ethereum_rpc_url: String,
	pub mpc_ethereum_chain_id: u64,

	// Bitcoin configuration
	pub mpc_bitcoin_rpc_url: String,

	// Backend API configuration
	pub backend_api_url: String,
	pub btc_utxo_api_base: String,

	// Solver contract configuration
	pub solver_contract_rpc_url: String,
	pub solver_contract_address: String,
	pub solver_contract_chain_id: u64,

	// Intent 
	pub intent_manager_contract_address: String, 

	// MPC broadcast configuration
	pub mpc_continue_on_broadcast_failure: bool,
	pub mpc_max_broadcast_retries: u32,
	pub mpc_retry_delay_ms: u64,
	pub mpc_log_failures_as_warnings: bool,
}

#[allow(dead_code)]
impl EnvVars {
	/// Load environment variables from the system
	pub fn load() -> Result<Self, String> {
		dotenv::dotenv().ok();

		let mpc_ethereum_rpc_url = env::var("MPC_ETHEREUM_RPC_URL")
			.map_err(|_| "MPC_ETHEREUM_RPC_URL environment variable is required")?;

		let mpc_ethereum_chain_id = env::var("MPC_ETHEREUM_CHAIN_ID")
			.map_err(|_| "MPC_ETHEREUM_CHAIN_ID environment variable is required")?
			.parse()
			.map_err(|_| "MPC_ETHEREUM_CHAIN_ID should be a number")?;

		// Load Bitcoin configuration
		let mpc_bitcoin_rpc_url = env::var("MPC_BITCOIN_RPC_URL")
			.map_err(|_| "MPC_BITCOIN_RPC_URL environment variable is required")?;

		// Load Backend API configuration
		let backend_api_url = env::var("BACKEND_API_URL")
			.map_err(|_| "BACKEND_API_URL environment variable is required")?;
		let btc_utxo_api_base = env::var("BTC_UTXO_API_BASE")
			.map_err(|_| "BTC_UTXO_API_BASE environment variable is required")?;

		// Load Solver contract configuration
		let solver_contract_rpc_url = env::var("SOLVER_CONTRACT_RPC_URL")
			.map_err(|_| "SOLVER_CONTRACT_RPC_URL environment variable is required")?;

		let solver_contract_address = env::var("SOLVER_CONTRACT_ADDRESS")
			.map_err(|_| "SOLVER_CONTRACT_ADDRESS environment variable is required")?;

		let solver_contract_chain_id = env::var("SOLVER_CONTRACT_CHAIN_ID")
			.map_err(|_| "SOLVER_CONTRACT_CHAIN_ID environment variable is required")?
			.parse()
			.map_err(|_| "SOLVER_CONTRACT_CHAIN_ID should be a number")?;


		let intent_manager_contract_address = env::var("INTENT_MANAGER_CONTRACT_ADDRESS")
			.map_err(|_| "INTENT_MANAGER_CONTRACT_ADDRESS environment variable is required")?;

		let mpc_continue_on_broadcast_failure =
			if let Ok(val) = env::var("MPC_CONTINUE_ON_BROADCAST_FAILURE") {
				val.parse().unwrap_or(true)
			} else {
				true
			};

		let mpc_max_broadcast_retries = if let Ok(val) = env::var("MPC_MAX_BROADCAST_RETRIES") {
			val.parse().unwrap_or(3)
		} else {
			3
		};

		let mpc_retry_delay_ms = if let Ok(val) = env::var("MPC_RETRY_DELAY_MS") {
			val.parse().unwrap_or(1000)
		} else {
			1000
		};

		let mpc_log_failures_as_warnings = if let Ok(val) = env::var("MPC_LOG_FAILURES_AS_WARNINGS")
		{
			val.parse().unwrap_or(true)
		} else {
			true
		};

		Ok(EnvVars {
			mpc_ethereum_rpc_url,
			mpc_ethereum_chain_id,
			mpc_bitcoin_rpc_url,
			backend_api_url,
			btc_utxo_api_base,
			solver_contract_rpc_url,
			solver_contract_address,
			solver_contract_chain_id,
			intent_manager_contract_address,
			mpc_continue_on_broadcast_failure,
			mpc_max_broadcast_retries,
			mpc_retry_delay_ms,
			mpc_log_failures_as_warnings,
		})
	}

	pub fn load_with_dotenv() -> Result<Self, String> {
		Self::load()
	}
}
