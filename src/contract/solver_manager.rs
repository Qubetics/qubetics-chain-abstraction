use anyhow::{anyhow, Result};
use ethers::{
    contract::abigen,
    providers::{Http, Middleware, Provider},
    types::{Address, Bytes, TransactionRequest},
};
use std::sync::Arc;
use tracing::info;

use super::ContractConfig;

abigen!(
    SolverManager,
    r#"[
        function getSolverAllChainAmounts(string solverId) view returns (uint256[] amounts)
        function getActiveSolvers() view returns (string[] solverIds)
        function get_solver_evm_address(string solverId) view returns (address)
        function getSolverId(address solver) view returns (string)
        function getMinimumLiquidities() view returns (uint256 btcMinimum, uint256 ticsMinimum, uint256 btcNodeMinimum, uint256 ticsNodeMinimum)
        function getSolversUnclaimedRewards(string[] solverIds) view returns ((string solverId, uint256 btcUnclaimed, uint256 ticsUnclaimed)[] rewards)
        function isSolverActive(string solverId) view returns (bool)
        function isSolverIdValidated(string solverId) view returns (bool)
        function isSolverOnboarded(string solverId) view returns (bool)
        function invalidateSolverIds(string[] solverIds)
        function getPlatformUnclaimedFee(uint256 chainId) view returns (uint256)
        function getSolverFeePercentage() view returns (uint256)
        function getPlatformFeePercentage() view returns (uint256)
    ]"#
);

#[derive(Clone)]
pub struct SolverManagerContract {
    inner: SolverManager<Provider<Http>>,
}

impl SolverManagerContract {
    pub fn new(config: &ContractConfig, provider: Arc<Provider<Http>>) -> Result<Self> {
        let addr: Address = config.contract_address;
        let inner = SolverManager::new(addr, provider);
        Ok(Self { inner })
    }

    pub async fn get_all_chain_amounts(&self, solver_id: &str) -> Result<Vec<ethers::types::U256>> {
        let call = self
            .inner
            .get_solver_all_chain_amounts(solver_id.to_string());
        let amounts = call
            .call()
            .await
            .map_err(|e| anyhow!("contract call failed: {}", e))?;
        Ok(amounts)
    }

    pub async fn get_active_solvers(&self) -> Result<Vec<String>> {
        let call = self.inner.get_active_solvers();
        let solver_ids = call
            .call()
            .await
            .map_err(|e| anyhow!("contract call failed: {}", e))?;
        Ok(solver_ids)
    }

    pub async fn get_solver_evm_address(&self, solver_id: &str) -> Result<Address> {
        let addr = self
            .inner
            .get_solver_evm_address(solver_id.to_owned())
            .call()
            .await
            .map_err(|e| anyhow!("contract call failed: {}", e))?;
        Ok(addr)
    }

    pub async fn get_solver_id(&self, solver: Address) -> Result<String> {
        let solver_id = self
            .inner
            .get_solver_id(solver)
            .call()
            .await
            .map_err(|e| anyhow!("contract call failed: {}", e))?;
        Ok(solver_id)
    }

    /// Returns (btcMinimum, ticsMinimum, btcNodeMinimum, ticsNodeMinimum).
    /// Use btcNodeMinimum/ticsNodeMinimum for validated (node-running) solvers,
    /// btcMinimum/ticsMinimum for non-node solvers.
    pub async fn get_minimum_liquidities(
        &self,
    ) -> Result<(
        ethers::types::U256,
        ethers::types::U256,
        ethers::types::U256,
        ethers::types::U256,
    )> {
        self.inner
            .get_minimum_liquidities()
            .call()
            .await
            .map_err(|e| anyhow!("getMinimumLiquidities call failed: {}", e))
    }

    /// Returns (solver_id, btc_unclaimed, tics_unclaimed) per solver.
    ///
    /// Uses manual eth_call + ethabi decoding instead of abigen because ethers-rs v2
    /// incorrectly decodes arrays of structs containing dynamic types (string),
    /// returning ABI offset values instead of the actual uint256 amounts.
    pub async fn get_solvers_unclaimed_rewards(
        &self,
        solver_ids: Vec<String>,
    ) -> Result<Vec<(String, ethers::types::U256, ethers::types::U256)>> {
        use ethabi::{Function, Param, ParamType, StateMutability, Token};

        if solver_ids.is_empty() {
            return Ok(vec![]);
        }

        // Build calldata: getSolversUnclaimedRewards(string[] solverIds)
        #[allow(deprecated)]
        let func = Function {
            name: "getSolversUnclaimedRewards".to_owned(),
            inputs: vec![Param {
                name: "solverIds".into(),
                kind: ParamType::Array(Box::new(ParamType::String)),
                internal_type: None,
            }],
            outputs: vec![Param {
                name: "rewards".into(),
                kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                    ParamType::String,    // solverId
                    ParamType::Uint(256), // btcUnclaimed
                    ParamType::Uint(256), // ticsUnclaimed
                ]))),
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::View,
        };

        let input_tokens: Vec<Token> = solver_ids
            .iter()
            .map(|s| Token::String(s.clone()))
            .collect();
        let calldata = func
            .encode_input(&[Token::Array(input_tokens)])
            .map_err(|e| {
                anyhow!(
                    "Failed to encode getSolversUnclaimedRewards calldata: {}",
                    e
                )
            })?;

        // Make raw eth_call via the provider
        let provider = self.inner.client();
        let contract_addr = self.inner.address();

        let tx = TransactionRequest::new()
            .to(contract_addr)
            .data(Bytes::from(calldata));

        let raw_output = provider
            .call(&tx.into(), None)
            .await
            .map_err(|e| anyhow!("getSolversUnclaimedRewards eth_call failed: {}", e))?;

        // Decode the raw output using ethabi
        let decoded = func
            .decode_output(&raw_output)
            .map_err(|e| anyhow!("Failed to decode getSolversUnclaimedRewards output: {}", e))?;

        // decoded[0] should be Token::Array of Token::Tuple
        let rewards_array = match decoded.into_iter().next() {
            Some(Token::Array(arr)) => arr,
            other => {
                return Err(anyhow!("Unexpected decoded output shape: {:?}", other));
            }
        };

        let mut results = Vec::with_capacity(rewards_array.len());
        for token in rewards_array {
            match token {
                Token::Tuple(fields) if fields.len() == 3 => {
                    let solver_id = match &fields[0] {
                        Token::String(s) => s.clone(),
                        _ => String::new(),
                    };
                    let btc_unclaimed = match &fields[1] {
                        Token::Uint(v) => {
                            let mut buf = [0u8; 32];
                            v.to_big_endian(&mut buf);
                            ethers::types::U256::from_big_endian(&buf)
                        }
                        _ => ethers::types::U256::zero(),
                    };
                    let tics_unclaimed = match &fields[2] {
                        Token::Uint(v) => {
                            let mut buf = [0u8; 32];
                            v.to_big_endian(&mut buf);
                            ethers::types::U256::from_big_endian(&buf)
                        }
                        _ => ethers::types::U256::zero(),
                    };

                    info!(
                        "📊 [CONTRACT] getSolversUnclaimedRewards: solver={}, btc_unclaimed={}, tics_unclaimed={}",
                        solver_id, btc_unclaimed, tics_unclaimed
                    );

                    results.push((solver_id, btc_unclaimed, tics_unclaimed));
                }
                _ => {
                    return Err(anyhow!("Unexpected tuple shape in rewards array"));
                }
            }
        }

        Ok(results)
    }

    /// Check if a solver is active by solver ID
    pub async fn is_solver_active(&self, solver_id: &str) -> Result<bool> {
        let is_active = self
            .inner
            .is_solver_active(solver_id.to_string())
            .call()
            .await
            .map_err(|e| anyhow!("isSolverActive call failed: {}", e))?;
        Ok(is_active)
    }

    /// Check if a solver ID is validated on-chain by solver ID string.
    pub async fn is_solver_id_validated(&self, solver_id: &str) -> Result<bool> {
        let validated = self
            .inner
            .is_solver_id_validated(solver_id.to_string())
            .call()
            .await
            .map_err(|e| anyhow!("isSolverIdValidated call failed: {}", e))?;
        Ok(validated)
    }

    /// Check if a solver is onboarded by solver ID (contract: isSolverOnboarded).
    pub async fn is_solver_onboarded(&self, solver_id: &str) -> Result<bool> {
        let onboarded = self
            .inner
            .is_solver_onboarded(solver_id.to_string())
            .call()
            .await
            .map_err(|e| anyhow!("isSolverOnboarded call failed: {}", e))?;
        Ok(onboarded)
    }

    /// Invalidate multiple solver IDs (marks them as inactive)
    /// This is a state-changing function that requires a transaction
    pub async fn invalidate_solver_ids(&self, solver_ids: Vec<String>) -> Result<()> {
        if solver_ids.is_empty() {
            return Ok(());
        }

        self.inner
            .invalidate_solver_ids(solver_ids)
            .send()
            .await
            .map_err(|e| anyhow!("invalidateSolverIds transaction failed: {}", e))?
            .await
            .map_err(|e| anyhow!("invalidateSolverIds receipt failed: {}", e))?;

        Ok(())
    }

    /// Encode call data for invalidateSolverIds function
    /// This can be used to create batch transactions
    pub fn encode_invalidate_call_data(&self, solver_ids: Vec<String>) -> Result<Vec<u8>> {
        let call = self.inner.invalidate_solver_ids(solver_ids);
        let calldata = call
            .calldata()
            .ok_or_else(|| anyhow!("Failed to encode calldata"))?;
        Ok(calldata.to_vec())
    }

    /// Query the unclaimed platform fee for a given chain.
    /// `chain_id`: 0 for BTC, TICS chain ID for TICS (matches contract constants; read from MPC_TICS_CHAIN_ID env var).
    pub async fn get_platform_unclaimed_fee(
        &self,
        chain_id: ethers::types::U256,
    ) -> Result<ethers::types::U256> {
        self.inner
            .get_platform_unclaimed_fee(chain_id)
            .call()
            .await
            .map_err(|e| anyhow!("getPlatformUnclaimedFee call failed: {}", e))
    }

    pub async fn get_solver_fee_percentage(&self) -> Result<ethers::types::U256> {
        self.inner
            .get_solver_fee_percentage()
            .call()
            .await
            .map_err(|e| anyhow!("getSolverFeePercentage call failed: {}", e))
    }

    pub async fn get_platform_fee_percentage(&self) -> Result<ethers::types::U256> {
        self.inner
            .get_platform_fee_percentage()
            .call()
            .await
            .map_err(|e| anyhow!("getPlatformFeePercentage call failed: {}", e))
    }
}
