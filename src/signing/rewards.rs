use super::SigningNode;
use crate::contract::{ContractClient, SolverManagerContract};
use anyhow::{anyhow, Error, Result};
use ethereum_types::U256 as EthereumU256;
use ethers::types::U256;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

impl SigningNode {
    pub async fn update_solver_liquidity(
        &self,
        solver_evm_address: &str,
    ) -> Result<()> {
        let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string());
        let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
        let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<u64>()
            .unwrap_or(1);

        if contract_address == "0x0000000000000000000000000000000000000000" {
            info!(
                "⏭️ [SOLVER] Skipping solver liquidity update - using placeholder contract address"
            );
            return Ok(());
        }

        info!(
            "🔄 [SOLVER] Updating solver liquidity for EVM address: {}",
            solver_evm_address
        );

        let contract_addr = contract_address
            .parse::<ethers::types::Address>()
            .map_err(|e| anyhow!("Invalid contract address: {}", e))?;

        let config = crate::contract::ContractConfig {
            rpc_url: rpc_url.clone(),
            contract_address: contract_addr,
            chain_id,
        };

        let client = ContractClient::new(config.clone())
            .map_err(|e| anyhow!("Failed to create contract client: {}", e))?;

        let solver_contract = SolverManagerContract::new(&config, client.provider())
            .map_err(|e| anyhow!("Failed to create solver contract interface: {}", e))?;

        // Resolve solver ID from the provided EVM address
        let solver_addr = solver_evm_address
            .parse::<ethers::types::Address>()
            .map_err(|e| anyhow!("Invalid solver EVM address {}: {}", solver_evm_address, e))?;

        let contract_for_solver_id = solver_contract.clone();
        let solver_id = self
            .contract_call_with_retry("get_solver_id", move || {
                let contract = contract_for_solver_id.clone();
                async move { contract.get_solver_id(solver_addr).await }
            })
            .await
            .map_err(|e| anyhow!("Failed to get solver ID for address {}: {}", solver_evm_address, e))?;

        info!(
            "🔍 [SOLVER] Resolved solver ID {} for EVM address {}",
            solver_id, solver_evm_address
        );

        let contract_for_amounts = solver_contract.clone();
        let solver_id_for_amounts = solver_id.clone();
        let amounts = self
            .contract_call_with_retry("get_solver_all_chain_amounts", move || {
                let contract = contract_for_amounts.clone();
                let solver_id = solver_id_for_amounts.clone();
                async move { contract.get_all_chain_amounts(&solver_id).await }
            })
            .await
            .map_err(|e| anyhow!("Failed to get amounts for solver {}: {}", solver_id, e))?;

        let liquidity_amounts: Vec<String> = amounts.iter().map(|u| u.to_string()).collect();
        let solver_liquidity_key =
            format!("solver_liquidity:{}", solver_evm_address.to_lowercase());

        if let Some(ref database) = self.database {
            // 1) Update this solver's liquidity entry
            if let Err(e) = database.put_string(&solver_liquidity_key, &liquidity_amounts) {
                warn!(
                    "⚠️ [SOLVER] Failed to store liquidity for solver {} (address: {}): {}",
                    solver_id, solver_evm_address, e
                );
            } else {
                info!(
                    "💾 [SOLVER] Stored liquidity for solver {} (address: {}): {:?}",
                    solver_id, solver_evm_address, liquidity_amounts
                );
            }

            // 2) Recompute global totals and aggregate map from all solver_liquidity:* keys
            match database.get_values_with_prefix::<Vec<String>>("solver_liquidity:") {
                Ok(entries) => {
                    let mut total_tics = U256::zero();
                    let mut total_btc = U256::zero();
                    let mut solver_liquidity_map =
                        std::collections::HashMap::<String, Vec<String>>::new();

                    for (key, amounts) in entries {
                        // Expect key format "solver_liquidity:<evm_address>"
                        if let Some(addr) = key.strip_prefix("solver_liquidity:") {
                            // Sum BTC (index 0) and TICS (index 1) if present
                            if let Some(btc_str) = amounts.get(0) {
                                if let Ok(btc) = U256::from_dec_str(btc_str) {
                                    total_btc += btc;
                                }
                            }
                            if let Some(tics_str) = amounts.get(1) {
                                if let Ok(tics) = U256::from_dec_str(tics_str) {
                                    total_tics += tics;
                                }
                            }

                            solver_liquidity_map.insert(addr.to_lowercase(), amounts);
                        }
                    }

                    // Store aggregate solver liquidity map
                    let all_solver_liquidity_key = "solver_liquidity:all";
                    if let Err(e) =
                        database.put_string(all_solver_liquidity_key, &solver_liquidity_map)
                    {
                        warn!("⚠️ [SOLVER] Failed to store all solver liquidity: {}", e);
                    } else {
                        info!(
                            "💾 [SOLVER] Stored all solver liquidity: {} solvers",
                            solver_liquidity_map.len()
                        );
                    }

                    // Store total TICS and BTC liquidity
                    let tics_key = crate::database::key_utils::total_liquidity_tics_key();
                    if let Err(e) = database.put_string(&tics_key, &total_tics.to_string()) {
                        warn!("⚠️ [SOLVER] Failed to store total tics liquidity: {}", e);
                    } else {
                        info!("💾 [SOLVER] Stored total tics liquidity: {}", total_tics);
                    }

                    let btc_key = crate::database::key_utils::total_liquidity_btc_key();
                    if let Err(e) = database.put_string(&btc_key, &total_btc.to_string()) {
                        warn!("⚠️ [SOLVER] Failed to store total btc liquidity: {}", e);
                    } else {
                        info!("💾 [SOLVER] Stored total btc liquidity: {}", total_btc);
                    }
                }
                Err(e) => {
                    warn!(
                        "⚠️ [SOLVER] Failed to recompute total liquidity from DB: {}",
                        e
                    );
                }
            }
        } else {
            warn!("⚠️ [SOLVER] No database available to store solver liquidity");
        }

        Ok(())
    }

    pub async fn calculate_reward_per_solver(&self, intent_hash: &str) -> Result<()> {
        let database = self
            .database
            .as_ref()
            .ok_or_else(|| anyhow!("Database not available"))?;
        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User registry not available"))?;

        if let Some(true) = user_intent_manager
            .get_intent_reward_status(intent_hash)
            .await
        {
            info!(
                "⏭️ [SOLVER] Rewards already calculated for intent {}",
                intent_hash
            );
            return Ok(());
        }

        let intent = user_intent_manager
            .get_intent(intent_hash)
            .await
            .ok_or_else(|| anyhow!("Intent not found: {}", intent_hash))?;

        let source_chain = intent.source_chain.to_lowercase();
        let intent_amount = EthereumU256::from(intent.amount);
        let base_reward = intent_amount / EthereumU256::from(10u8);

        let total_tics = user_intent_manager
            .get_total_liquidity_tics_u256()
            .await
            .unwrap_or_else(EthereumU256::zero);
        let total_btc = user_intent_manager
            .get_total_liquidity_btc_u256()
            .await
            .unwrap_or_else(EthereumU256::zero);

        info!("💰 [SOLVER] Total tics: {}", total_tics);
        info!("💰 [SOLVER] Total btc: {}", total_btc);

        let solver_liquidity_map: std::collections::HashMap<String, Vec<String>> = database
            .get_string("solver_liquidity:all")?
            .unwrap_or_default();

        for (solver, amounts) in solver_liquidity_map.iter() {
            let reward = if source_chain == "btc" || source_chain == "bitcoin" {
                let solver_btc = amounts
                    .first()
                    .and_then(|v| EthereumU256::from_dec_str(v).ok())
                    .unwrap_or_else(EthereumU256::zero);
                if solver_btc.is_zero() || total_btc.is_zero() {
                    info!(
                        "💰 [SOLVER] Solver {} has no BTC liquidity, reward = 0",
                        solver
                    );
                    EthereumU256::zero()
                } else {
                    solver_btc * base_reward / total_btc
                }
            } else {
                let solver_tics = amounts
                    .get(1)
                    .and_then(|v| EthereumU256::from_dec_str(v).ok())
                    .unwrap_or_else(EthereumU256::zero);
                if solver_tics.is_zero() || total_tics.is_zero() {
                    info!(
                        "💰 [SOLVER] Solver {} has no TICS liquidity, reward = 0",
                        solver
                    );
                    EthereumU256::zero()
                } else {
                    solver_tics * base_reward / total_tics
                }
            };

            info!("💰 [SOLVER] Reward for {}: {}", solver, reward);

            let current_currency_reward = if source_chain == "btc" || source_chain == "bitcoin" {
                user_intent_manager
                    .get_solver_reward_btc(solver)
                    .await
                    .unwrap_or_else(EthereumU256::zero)
            } else {
                user_intent_manager
                    .get_solver_reward_tics(solver)
                    .await
                    .unwrap_or_else(EthereumU256::zero)
            };

            let current_ethers = EthereumU256::from_dec_str(&current_currency_reward.to_string())
                .map_err(|e| anyhow!("Failed to convert current reward: {}", e))?;
            let reward_ethers = EthereumU256::from_dec_str(&reward.to_string())
                .map_err(|e| anyhow!("Failed to convert reward: {}", e))?;
            let updated_ethers = current_ethers + reward_ethers;

            let updated_ethereum_types = EthereumU256::from_dec_str(&updated_ethers.to_string())
                .map_err(|e| anyhow!("Failed to convert updated reward: {}", e))?;

            if source_chain == "btc" || source_chain == "bitcoin" {
                let _ = user_intent_manager
                    .set_solver_reward_btc(solver, updated_ethereum_types)
                    .await;
            } else {
                let _ = user_intent_manager
                    .set_solver_reward_tics(solver, updated_ethereum_types)
                    .await;
            }

            info!(
                "💰 [SOLVER] Reward for {} updated to {}",
                solver, updated_ethers
            );
        }

        info!(
            "✅ [SOLVER] Calculated rewards for {} solvers",
            solver_liquidity_map.len()
        );

        user_intent_manager
            .set_intent_reward_status(intent_hash, true)
            .await
            .map_err(|e| anyhow!("Failed to set intent reward status: {}", e))?;

        Ok(())
    }

    async fn contract_call_with_retry<F, Fut, T>(
        &self,
        description: &str,
        mut operation: F,
    ) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        const MAX_ATTEMPTS: usize = 3;
        let retry_delay = Duration::from_millis(750);

        for attempt in 1..=MAX_ATTEMPTS {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    let should_retry = self.is_retryable_contract_error(&err);
                    if attempt == MAX_ATTEMPTS || !should_retry {
                        return Err(anyhow!(
                            "{} failed after {} attempt(s): {}",
                            description,
                            attempt,
                            err
                        ));
                    }

                    warn!(
                        "⚠️ [SOLVER] {} attempt {} failed: {} — retrying in {}ms",
                        description,
                        attempt,
                        err,
                        retry_delay.as_millis()
                    );
                    sleep(retry_delay).await;
                }
            }
        }

        unreachable!("Retry loop should always return or error")
    }

    fn is_retryable_contract_error(&self, err: &Error) -> bool {
        let msg = err.to_string().to_lowercase();
        msg.contains("502")
            || msg.contains("503")
            || msg.contains("504")
            || msg.contains("timeout")
            || msg.contains("temporar")
            || msg.contains("connection reset")
            || msg.contains("connection refused")
            || msg.contains("deserialization error")
    }
}
