use crate::types::network as network_cfg;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Dynamic configuration structures for flexible broadcast behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastConfig {
    /// Whether to continue running when broadcast fails
    pub continue_on_failure: bool,
    /// Maximum retry attempts for failed broadcasts
    pub max_retries: u32,
    /// Delay between retry attempts (in milliseconds)
    pub retry_delay_ms: u64,
    /// Whether to log broadcast failures as warnings instead of errors
    pub log_failures_as_warnings: bool,
    /// Chain-specific configurations
    pub chain_configs: HashMap<String, ChainBroadcastConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBroadcastConfig {
    /// Whether this chain is enabled for broadcasting
    pub enabled: bool,
    /// RPC endpoint for this chain
    pub rpc_url: String,
    /// Chain ID
    pub chain_id: u64,
    /// Whether to use testnet
    pub testnet: bool,
    /// Custom headers for RPC requests
    pub custom_headers: HashMap<String, String>,
    /// Timeout for RPC requests (in seconds)
    pub timeout_seconds: u64,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        let is_testnet = network_cfg::network_type().is_testnet();
        let mut chain_configs = HashMap::new();

        // Default TICS configuration
        chain_configs.insert(
            "tics".to_string(),
            ChainBroadcastConfig {
                enabled: true,
                rpc_url: String::new(),
                chain_id: 9029,
                testnet: is_testnet,
                custom_headers: HashMap::new(),
                timeout_seconds: 30,
            },
        );

        // Default Bitcoin configuration - using public Bitcoin RPC service
        chain_configs.insert(
            "bitcoin".to_string(),
            ChainBroadcastConfig {
                enabled: true, // Enabled with public API
                rpc_url: String::new(),
                chain_id: 0,
                testnet: is_testnet,
                custom_headers: HashMap::new(),
                timeout_seconds: 30,
            },
        );

        Self {
            continue_on_failure: true,
            max_retries: 3,
            retry_delay_ms: 1000,
            log_failures_as_warnings: true,
            chain_configs,
        }
    }
}

impl Default for ChainBroadcastConfig {
    fn default() -> Self {
        let is_testnet = network_cfg::network_type().is_testnet();
        Self {
            enabled: true,
            rpc_url: String::new(),
            chain_id: 0,
            testnet: is_testnet,
            custom_headers: HashMap::new(),
            timeout_seconds: 30,
        }
    }
}

// Configuration loading from environment variables
impl BroadcastConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Load from environment variables
        if let Ok(val) = std::env::var("MPC_CONTINUE_ON_BROADCAST_FAILURE") {
            config.continue_on_failure = val.parse().unwrap_or(true);
        }

        if let Ok(val) = std::env::var("MPC_MAX_BROADCAST_RETRIES") {
            config.max_retries = val.parse().unwrap_or(3);
        }

        if let Ok(val) = std::env::var("MPC_RETRY_DELAY_MS") {
            config.retry_delay_ms = val.parse().unwrap_or(1000);
        }

        if let Ok(val) = std::env::var("MPC_LOG_FAILURES_AS_WARNINGS") {
            config.log_failures_as_warnings = val.parse().unwrap_or(true);
        }

        // Load chain-specific configurations
        if let Some(eth_config) = config.chain_configs.get_mut("tics") {
            eth_config.rpc_url = network_cfg::qubetics_rpc_url_from_env()
                .expect("Unable to determine MPC_ETHEREUM_RPC_URL for Qubetics chain");
        }

        if let Ok(chain_id) = std::env::var("MPC_TICS_CHAIN_ID") {
            if let Some(eth_config) = config.chain_configs.get_mut("tics") {
                eth_config.chain_id = chain_id.parse().unwrap_or(9029);
            }
        }

        if let Some(btc_config) = config.chain_configs.get_mut("bitcoin") {
            btc_config.rpc_url = crate::env_defaults::mpc_bitcoin_rpc_url();
        }

        config
    }

    pub fn get_chain_config(&self, chain_type: &str) -> Option<&ChainBroadcastConfig> {
        self.chain_configs.get(chain_type)
    }

    pub fn is_chain_enabled(&self, chain_type: &str) -> bool {
        self.chain_configs
            .get(chain_type)
            .map(|config| config.enabled)
            .unwrap_or(false)
    }

    pub fn print_config(&self) {
        info!("�� [CONFIG] Broadcast Configuration:");
        info!("   Continue on failure: {}", self.continue_on_failure);
        info!("   Max retries: {}", self.max_retries);
        info!("   Retry delay: {}ms", self.retry_delay_ms);
        info!(
            "   Log failures as warnings: {}",
            self.log_failures_as_warnings
        );

        for (chain, config) in &self.chain_configs {
            info!(
                "   Chain {}: enabled={}, rpc={}, chain_id={}",
                chain, config.enabled, config.rpc_url, config.chain_id
            );
        }
    }
}
