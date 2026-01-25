use super::*;
use crate::types::intent::TransactionNetwork;
use tracing::{error, info};

impl UserIntentManager {
    /// Store total liquidity in tics
    pub async fn set_total_liquidity_tics(&self, tics: u64) -> Result<(), String> {
        self.reward_storage
            .set_total_liquidity_tics(tics)
            .await
            .map_err(|e| e.to_string())?;
        info!("✅ [DB_USER_REGISTRY] Set total liquidity tics: {}", tics);
        Ok(())
    }

    /// Get total liquidity in tics (as u64 legacy)
    pub async fn get_total_liquidity_tics(&self) -> Option<u64> {
        match self.reward_storage.get_total_liquidity_tics().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to get total liquidity TICS: {}", e);
                None
            }
        }
    }

    /// Get total liquidity in TICS as U256 (string-backed)
    pub async fn get_total_liquidity_tics_u256(&self) -> Option<U256> {
        match self.reward_storage.get_total_liquidity_tics_u256().await {
            Ok(v) => v.and_then(|x| U256::from_dec_str(&x.to_string()).ok()),
            Err(e) => {
                tracing::error!("Failed to get total liquidity TICS (u256): {}", e);
                None
            }
        }
    }

    /// Get total liquidity in btc (legacy f64)
    pub async fn get_total_liquidity_btc(&self) -> Option<f64> {
        match self.reward_storage.get_total_liquidity_btc().await {
            Ok(btc) => btc,
            Err(e) => {
                tracing::error!("Failed to get total liquidity BTC: {}", e);
                None
            }
        }
    }

    /// Get total liquidity in BTC as U256 satoshis (string-backed)
    pub async fn get_total_liquidity_btc_u256(&self) -> Option<U256> {
        match self.reward_storage.get_total_liquidity_btc_u256().await {
            Ok(v) => v.and_then(|x| U256::from_dec_str(&x.to_string()).ok()),
            Err(e) => {
                tracing::error!("Failed to get total liquidity BTC (u256): {}", e);
                None
            }
        }
    }

    /// Delete total liquidity tics
    pub async fn delete_total_liquidity_tics(&self) -> Result<(), String> {
        self.reward_storage
            .delete_total_liquidity_tics()
            .await
            .map_err(|e| e.to_string())?;
        info!("✅ [DB_USER_REGISTRY] Deleted total liquidity tics");
        Ok(())
    }

    /// Delete total liquidity btc
    pub async fn delete_total_liquidity_btc(&self) -> Result<(), String> {
        self.reward_storage
            .delete_total_liquidity_btc()
            .await
            .map_err(|e| e.to_string())?;
        info!("✅ [DB_USER_REGISTRY] Deleted total liquidity BTC");
        Ok(())
    }

    /// Store TICS reward for a specific solver
    pub async fn set_solver_reward_tics(
        &self,
        solver_address: &str,
        reward_tics: U256,
    ) -> Result<(), String> {
        let reward_ethers =
            EthersU256::from_dec_str(&reward_tics.to_string()).map_err(|e| e.to_string())?;
        match self
            .reward_storage
            .set_solver_reward_tics(solver_address, reward_ethers)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Store BTC reward (satoshis) for a specific solver
    pub async fn set_solver_reward_btc(
        &self,
        solver_address: &str,
        reward_btc_sats: U256,
    ) -> Result<(), String> {
        let reward_ethers =
            EthersU256::from_dec_str(&reward_btc_sats.to_string()).map_err(|e| e.to_string())?;
        match self
            .reward_storage
            .set_solver_reward_btc(solver_address, reward_ethers)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Get TICS reward for a specific solver
    pub async fn get_solver_reward_tics(&self, solver_address: &str) -> Option<U256> {
        match self
            .reward_storage
            .get_solver_reward_tics(solver_address)
            .await
        {
            Ok(v) => v.and_then(|x| U256::from_dec_str(&x.to_string()).ok()),
            Err(e) => {
                tracing::error!("Failed to get TICS reward for {}: {}", solver_address, e);
                None
            }
        }
    }

    /// Get BTC reward (satoshis) for a specific solver
    pub async fn get_solver_reward_btc(&self, solver_address: &str) -> Option<U256> {
        match self
            .reward_storage
            .get_solver_reward_btc(solver_address)
            .await
        {
            Ok(v) => v.and_then(|x| U256::from_dec_str(&x.to_string()).ok()),
            Err(e) => {
                tracing::error!("Failed to get BTC reward for {}: {}", solver_address, e);
                None
            }
        }
    }

    /// Store claimed request amount for a specific solver
    pub async fn set_solver_claimed_request_amount(
        &self,
        solver_address: &str,
        amount: U256,
    ) -> Result<(), String> {
        info!("💰 [DB_USER_REGISTRY] Processing claimed request amount storage:");
        info!("  🤖 Solver address: {}", solver_address);
        info!("  💵 Claimed amount: {}", amount);

        match self
            .reward_storage
            .set_claimed_request_amount(solver_address, amount)
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored claimed request amount");
                info!("  🤖 Solver: {}", solver_address);
                info!("  💵 Amount: {}", amount);
                Ok(())
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store claimed request amount");
                error!("  🤖 Solver address: {}", solver_address);
                error!("  💵 Amount: {}", amount);
                error!("  💥 Error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Get claimed request amount for a specific solver
    pub async fn get_solver_claimed_request_amount(&self, solver_address: &str) -> Option<U256> {
        match self
            .reward_storage
            .get_claimed_request_amount(solver_address)
            .await
        {
            Ok(amount) => {
                if amount.is_some() {
                    info!(
                        "🔍 [DB_USER_REGISTRY] Retrieved claimed request amount for: {}",
                        solver_address
                    );
                }
                amount
            }
            Err(e) => {
                tracing::error!(
                    "Failed to get claimed request amount for {}: {}",
                    solver_address,
                    e
                );
                None
            }
        }
    }

    /// Set reward calculation status for a specific intent hash
    pub async fn set_intent_reward_status(
        &self,
        intent_hash: &str,
        status: bool,
    ) -> Result<(), String> {
        info!("🎯 [DB_USER_REGISTRY] Processing intent reward status storage:");
        info!("  🔗 Intent hash: {}", intent_hash);
        info!("  ✅ Status: {}", status);

        match self
            .reward_storage
            .set_intent_reward_status(intent_hash, status)
            .await
        {
            Ok(()) => {
                info!("✅ [DB_USER_REGISTRY] Successfully stored intent reward status");
                info!("  🎯 Intent: {}", intent_hash);
                info!("  ✅ Status: {}", status);
                Ok(())
            }
            Err(e) => {
                error!("❌ [DB_USER_REGISTRY] Failed to store intent reward status");
                error!("  🔗 Intent hash: {}", intent_hash);
                error!("  ✅ Status: {}", status);
                error!("  💥 Error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Get reward calculation status for a specific intent hash
    pub async fn get_intent_reward_status(&self, intent_hash: &str) -> Option<bool> {
        match self
            .reward_storage
            .get_intent_reward_status(intent_hash)
            .await
        {
            Ok(status) => {
                if status.is_some() {
                    info!(
                        "🔍 [DB_USER_REGISTRY] Retrieved intent reward status for: {}",
                        intent_hash
                    );
                }
                status
            }
            Err(e) => {
                tracing::error!(
                    "Failed to get intent reward status for {}: {}",
                    intent_hash,
                    e
                );
                None
            }
        }
    }

    /// Store the latest TICS transaction hash for a specific solver
    pub async fn set_solver_tics_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        info!(
            "🎯 [DB_USER_REGISTRY] Storing latest TICS txn hash for solver: {}",
            solver_address
        );
        info!("📝 [DB_USER_REGISTRY] Txn hash: {}", txn_hash);

        self.reward_storage
            .set_solver_tics_txn_hash(solver_address, txn_hash)
            .await
            .map(|_| {
                info!("✅ [DB_USER_REGISTRY] Successfully stored TICS txn hash");
            })
            .map_err(|e| {
                error!("❌ [DB_USER_REGISTRY] Failed to store TICS txn hash: {}", e);
                e
            })
    }

    /// Get the latest TICS transaction hash for a specific solver
    pub async fn get_solver_tics_txn_hash(&self, solver_address: &str) -> Option<String> {
        match self
            .reward_storage
            .get_solver_tics_txn_hash(solver_address)
            .await
        {
            Ok(hash) => {
                if let Some(ref hash) = hash {
                    info!(
                        "🔍 [DB_USER_REGISTRY] Retrieved latest TICS txn hash for solver {}: {}",
                        solver_address, hash
                    );
                }
                hash
            }
            Err(e) => {
                tracing::error!(
                    "Failed to get TICS txn hash for solver {}: {}",
                    solver_address,
                    e
                );
                None
            }
        }
    }

    /// Add a single TICS transaction hash (overwrites with the latest)
    pub async fn add_solver_tics_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        info!(
            "🎯 [DB_USER_REGISTRY] Adding TICS txn hash for solver: {}",
            solver_address
        );
        info!("📝 [DB_USER_REGISTRY] Txn hash: {}", txn_hash);

        self.reward_storage
            .add_solver_tics_txn_hash(solver_address, txn_hash)
            .await
            .map(|_| {
                info!("✅ [DB_USER_REGISTRY] Successfully stored latest TICS txn hash");
            })
            .map_err(|e| {
                error!("❌ [DB_USER_REGISTRY] Failed to add TICS txn hash: {}", e);
                e
            })
    }

    /// Store the latest BTC transaction hash for a specific solver
    pub async fn set_solver_btc_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        info!(
            "🎯 [DB_USER_REGISTRY] Storing latest BTC txn hash for solver: {}",
            solver_address
        );
        info!("📝 [DB_USER_REGISTRY] Txn hash: {}", txn_hash);

        self.reward_storage
            .set_solver_btc_txn_hash(solver_address, txn_hash)
            .await
            .map(|_| {
                info!("✅ [DB_USER_REGISTRY] Successfully stored BTC txn hash");
            })
            .map_err(|e| {
                error!("❌ [DB_USER_REGISTRY] Failed to store BTC txn hash: {}", e);
                e
            })
    }

    /// Get the latest BTC transaction hash for a specific solver
    pub async fn get_solver_btc_txn_hash(&self, solver_address: &str) -> Option<String> {
        match self
            .reward_storage
            .get_solver_btc_txn_hash(solver_address)
            .await
        {
            Ok(hash) => {
                if let Some(ref hash) = hash {
                    info!(
                        "🔍 [DB_USER_REGISTRY] Retrieved latest BTC txn hash for solver {}: {}",
                        solver_address, hash
                    );
                }
                hash
            }
            Err(e) => {
                tracing::error!(
                    "Failed to get BTC txn hash for solver {}: {}",
                    solver_address,
                    e
                );
                None
            }
        }
    }

    /// Add a single BTC transaction hash (overwrites with the latest)
    pub async fn add_solver_btc_txn_hash(
        &self,
        solver_address: &str,
        txn_hash: String,
    ) -> Result<()> {
        info!(
            "🎯 [DB_USER_REGISTRY] Adding BTC txn hash for solver: {}",
            solver_address
        );
        info!("📝 [DB_USER_REGISTRY] Txn hash: {}", txn_hash);

        self.reward_storage
            .add_solver_btc_txn_hash(solver_address, txn_hash)
            .await
            .map(|_| {
                info!("✅ [DB_USER_REGISTRY] Successfully stored latest BTC txn hash");
            })
            .map_err(|e| {
                error!("❌ [DB_USER_REGISTRY] Failed to add BTC txn hash: {}", e);
                e
            })
    }

    /// Clear TICS transaction hashes for a specific solver
    pub async fn clear_solver_tics_txn_hashes(&self, solver_address: &str) -> Result<()> {
        info!(
            "🎯 [DB_USER_REGISTRY] Clearing TICS txn hashes for solver: {}",
            solver_address
        );

        self.reward_storage
            .clear_solver_tics_txn_hashes(solver_address)
            .await
            .map(|_| {
                info!("✅ [DB_USER_REGISTRY] Successfully cleared TICS txn hashes");
            })
            .map_err(|e| {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to clear TICS txn hashes: {}",
                    e
                );
                e
            })
    }

    /// Clear BTC transaction hashes for a specific solver
    pub async fn clear_solver_btc_txn_hashes(&self, solver_address: &str) -> Result<()> {
        info!(
            "🎯 [DB_USER_REGISTRY] Clearing BTC txn hashes for solver: {}",
            solver_address
        );

        self.reward_storage
            .clear_solver_btc_txn_hashes(solver_address)
            .await
            .map(|_| {
                info!("✅ [DB_USER_REGISTRY] Successfully cleared BTC txn hashes");
            })
            .map_err(|e| {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to clear BTC txn hashes: {}",
                    e
                );
                e
            })
    }


    pub async fn get_solver_remove_liquidity_txn_hash(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
    ) -> Result<Option<String>, String> {
        self.liquidity_storage
            .get_remove_liquidity_tx_id(solver_address, network)
            .await
            .map_err(|e| {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to get remove-liquidity txn hash for solver {}: {}",
                    solver_address, e
                );
                e.to_string()
            })
    }

    pub async fn add_solver_remove_liquidity_txn_hash(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
        tx_id: String,
    ) -> Result<(), String> {
        self.liquidity_storage
            .set_remove_liquidity_tx_id(solver_address, network, tx_id)
            .await
            .map_err(|e| {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to store remove-liquidity txn hash for solver {}: {}",
                    solver_address, e
                );
                e.to_string()
            })
    }

    pub async fn set_pending_remove_liquidity_amount(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
        amount: String,
    ) -> Result<(), String> {
        self.liquidity_storage
            .set_pending_remove_liquidity_amount(solver_address, network, amount)
            .await
            .map_err(|e| {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to store pending remove-liquidity amount for solver {}: {}",
                    solver_address, e
                );
                e.to_string()
            })
    }

    pub async fn take_pending_remove_liquidity_amount(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
    ) -> Result<Option<String>, String> {
        self.liquidity_storage
            .take_pending_remove_liquidity_amount(solver_address, network)
            .await
            .map_err(|e| {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to read pending remove-liquidity amount for solver {}: {}",
                    solver_address, e
                );
                e.to_string()
            })
    }
}
