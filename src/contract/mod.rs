use anyhow::{anyhow, Result};
use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::Address,
};
use std::sync::Arc;

pub mod solver_manager;

pub use solver_manager::SolverManagerContract;

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

/// Contract client for interacting with Ethereum contracts
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
