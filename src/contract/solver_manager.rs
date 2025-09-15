use anyhow::{anyhow, Result};
use ethers::{
    contract::abigen,
    providers::{Http, Provider},
    types::Address,
};
use std::sync::Arc;

use super::ContractConfig;

abigen!(
    SolverManager,
    r#"[
        function getSolverAllChainAmounts(string solverId) view returns (uint256[] amounts)
        function getActiveSolvers() view returns (string[] solverIds)
        function get_solver_evm_address(string solverId) view returns (address)
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
        let addr = self.inner.get_solver_evm_address(solver_id.to_owned())
            .call().await
            .map_err(|e| anyhow!("contract call failed: {}", e))?;
        Ok(addr)
    }
    
}
