use anyhow::{anyhow, Result};
use ethers::{
    providers::{Http, Provider},
    types::Address,
};
use std::sync::Arc;

pub mod solver_manager;
pub mod solver_validation;

pub use solver_manager::SolverManagerContract;
pub use solver_validation::{
    create_solver_contract, get_solver_contract_config, validate_solver_active,
    validate_solver_active_strict, validate_solver_onboarded,
};

/// Configuration for contract interactions
#[derive(Debug, Clone)]
pub struct ContractConfig {
    pub rpc_url: String,
    pub contract_address: Address,
    pub chain_id: u64,
}

impl Default for ContractConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            contract_address: Address::zero(),
            chain_id: 1,
        }
    }
}

/// Contract client for interacting with TICS contracts
#[derive(Clone)]
pub struct ContractClient {
    provider: Arc<Provider<Http>>,
    config: ContractConfig,
}

impl ContractClient {
    /// Create a new contract client
    pub fn new(config: ContractConfig) -> Result<Self> {
        let provider = Provider::<Http>::try_from(&config.rpc_url)
            .map_err(|e| anyhow!("Failed to create provider: {}", e))?;

        Ok(Self {
            provider: Arc::new(provider),
            config,
        })
    }

    /// Get the provider
    pub fn provider(&self) -> Arc<Provider<Http>> {
        self.provider.clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &ContractConfig {
        &self.config
    }
}

/// Fetch dynamic fee basis points from the SolverManager contract.
/// Returns a fallback of 500 bps (5%) if the contract call fails or is not configured.
pub async fn fetch_dynamic_fee_bps() -> u128 {
    match fetch_dynamic_fees_impl().await {
        Ok(bps) => {
            tracing::info!(
                "📊 [DYNAMIC_FEE] Successfully fetched fees from contract: {} bps",
                bps
            );
            bps
        }
        Err(e) => {
            tracing::warn!(
                "⚠️ [DYNAMIC_FEE] Failed to fetch fees from contract, falling back to 500 bps (5%): {}",
                e
            );
            500
        }
    }
}

async fn fetch_dynamic_fees_impl() -> Result<u128, String> {
    let rpc_url = crate::env_defaults::solver_contract_rpc_url();
    let contract_address = crate::env_defaults::solver_contract_address();
    let chain_id = crate::env_defaults::solver_contract_chain_id()
        .parse::<u64>()
        .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

    if contract_address == "0x0000000000000000000000000000000000000000" {
        return Ok(500); // 5% fallback
    }

    let contract_addr = contract_address
        .parse::<Address>()
        .map_err(|e| format!("Invalid solver contract address: {e}"))?;

    let config = ContractConfig {
        rpc_url,
        contract_address: contract_addr,
        chain_id,
    };

    let client = ContractClient::new(config.clone())
        .map_err(|e| format!("Failed to create contract client: {e}"))?;

    let solver_contract = SolverManagerContract::new(&config, client.provider())
        .map_err(|e| format!("Failed to create solver contract interface: {e}"))?;

    let solver_fee = solver_contract
        .get_solver_fee_percentage()
        .await
        .map_err(|e| format!("Failed to get solver fee: {e}"))?;
    let platform_fee = solver_contract
        .get_platform_fee_percentage()
        .await
        .map_err(|e| format!("Failed to get platform fee: {e}"))?;

    Ok(solver_fee.as_u128() + platform_fee.as_u128())
}
