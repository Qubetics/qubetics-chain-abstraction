use anyhow::{anyhow, Result};
use ethers::types::Address;
use tracing::{debug, info, warn};

use crate::contract::{ContractClient, ContractConfig, SolverManagerContract};

/// Helper module for solver contract validation operations
/// Provides wrapper functions to eliminate redundant contract configuration code

/// Get contract configuration from environment variables
pub fn get_solver_contract_config() -> Result<Option<ContractConfig>> {
    let contract_address_env = std::env::var("SOLVER_CONTRACT_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    // Check if contract is configured
    if contract_address_env == "0x0000000000000000000000000000000000000000" {
        return Ok(None);
    }

    let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());

    let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
        .unwrap_or_else(|_| "9029".to_string())
        .parse::<u64>()
        .unwrap_or(9029);

    let contract_address = contract_address_env
        .parse::<Address>()
        .map_err(|e| anyhow!("Invalid contract address: {}", e))?;

    Ok(Some(ContractConfig {
        rpc_url,
        contract_address,
        chain_id,
    }))
}

/// Create a SolverManagerContract instance from configuration
pub fn create_solver_contract(config: &ContractConfig) -> Result<SolverManagerContract> {
    let client = ContractClient::new(config.clone())
        .map_err(|e| anyhow!("Failed to create contract client: {}", e))?;

    SolverManagerContract::new(config, client.provider())
        .map_err(|e| anyhow!("Failed to create solver contract: {}", e))
}

/// TESTING: Set to true to bypass node-is-active check (always treat as active).
const TESTING_BYPASS_ACTIVE_CHECK: bool = true;

/// Validate if a solver is active by solver ID
/// Returns Ok(true) if active, Ok(false) if inactive or not configured
/// Returns Err if validation fails (network error, etc.)
pub async fn validate_solver_active(solver_id: &str, log_prefix: &str) -> Result<bool> {
    // TESTING: bypass — pass boolean true to always treat node as active before connection
    if TESTING_BYPASS_ACTIVE_CHECK {
        info!(
            "✅ [{}] (TESTING BYPASS) Treating solver as active: {}",
            log_prefix, solver_id
        );
        return Ok(true);
    }

    // -------- ACTUAL LOGIC (used when TESTING_BYPASS_ACTIVE_CHECK is false) --------
    // Get contract configuration
    let config = match get_solver_contract_config()? {
        Some(cfg) => cfg,
        None => {
            debug!(
                "⚠️ [{}] Solver contract not configured, skipping validation for solver {}",
                log_prefix, solver_id
            );
            return Ok(true); // Allow if not configured (development mode)
        }
    };

    // Create contract instance
    let contract =
        create_solver_contract(&config).map_err(|e| anyhow!("[{}] {}", log_prefix, e))?;

    // Check if solver is active
    match contract.is_solver_active(solver_id).await {
        Ok(is_active) => {
            if is_active {
                info!(
                    "✅ [{}] Accepted solver: {} (active)",
                    log_prefix, solver_id
                );
            } else {
                warn!(
                    "🚫 [{}] Rejecting solver: {} (inactive)",
                    log_prefix, solver_id
                );
            }
            Ok(is_active)
        }
        Err(e) => {
            warn!(
                "🚫 [{}] Contract call failed for solver {}, rejecting: {}",
                log_prefix, solver_id, e
            );
            Err(anyhow!("Contract validation failed: {}", e))
        }
    }
}

/// Validate if a solver is active, with strict security mode
/// Returns Ok(()) if active, Err if inactive or validation fails
/// This is the strict version that rejects on any error
pub async fn validate_solver_active_strict(solver_id: &str, log_prefix: &str) -> Result<()> {
    match validate_solver_active(solver_id, log_prefix).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(anyhow!("Solver {} is not active", solver_id)),
        Err(e) => Err(e),
    }
}
