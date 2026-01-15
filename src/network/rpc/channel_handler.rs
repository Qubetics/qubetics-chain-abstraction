use libp2p::Multiaddr;
use std::sync::Arc;

impl MpcNetworkLayer {
    pub(crate) async fn record_pending_liquidity_contract_update(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
        amount: u128,
    ) {
        if amount == 0 {
            return;
        }

        if let Some(user_intent_manager) = &self.user_intent_manager {
            if let Err(e) = user_intent_manager
                .set_pending_remove_liquidity_amount(solver_address, network, amount.to_string())
                .await
            {
                warn!(
                    "⚠️ [NETWORK] Failed to persist pending liquidity amount for solver {} ({:?}): {}",
                    solver_address, network, e
                );
            } else {
                info!(
                    "💾 [NETWORK] Cached pending withdraw amount {} for solver {} ({:?}) awaiting tx_id",
                    amount, solver_address, network
                );
            }
        } else {
            warn!(
                "⚠️ [NETWORK] UserIntentManager unavailable; cannot persist pending liquidity amount for {}",
                solver_address
            );
        }
    }

    pub(crate) async fn take_pending_liquidity_contract_update_amount(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
    ) -> Option<u128> {
        if let Some(user_intent_manager) = &self.user_intent_manager {
            match user_intent_manager
                .take_pending_remove_liquidity_amount(solver_address, network)
                .await
            {
                Ok(Some(amount_str)) => match amount_str.parse::<u128>() {
                    Ok(value) => {
                        info!(
                            "💾 [NETWORK] Retrieved pending withdraw amount {} for solver {} ({:?})",
                            value, solver_address, network
                        );
                        Some(value)
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ [NETWORK] Failed to parse pending liquidity amount '{}' for solver {}: {}",
                            amount_str, solver_address, e
                        );
                        None
                    }
                },
                Ok(None) => {
                    info!(
                        "ℹ️ [NETWORK] No pending withdraw amount stored for solver {} ({:?})",
                        solver_address, network
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        "⚠️ [NETWORK] Failed to read pending liquidity amount for solver {}: {}",
                        solver_address, e
                    );
                    None
                }
            }
        } else {
            warn!(
                "⚠️ [NETWORK] UserIntentManager unavailable; cannot read pending liquidity amount for solver {}",
                solver_address
            );
            None
        }
    }

    async fn fetch_solver_id_for_address(&self, solver_address: &str) -> Result<String> {
        let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string());
        let contract_address_env = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
        let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "9029".to_string())
            .parse::<u64>()
            .unwrap_or(9029);

        if contract_address_env == "0x0000000000000000000000000000000000000000" {
            return Err(anyhow!(
                "solver contract address not configured; cannot fetch solver id"
            ));
        }

        let contract_address = contract_address_env
            .parse::<Address>()
            .map_err(|e| anyhow!("invalid solver contract address: {}", e))?;

        let config = ContractConfig {
            rpc_url: rpc_url.clone(),
            contract_address,
            chain_id,
        };

        let client = ContractClient::new(config.clone())
            .map_err(|e| anyhow!("failed to create contract client: {}", e))?;
        let contract = SolverManagerContract::new(&config, client.provider())
            .map_err(|e| anyhow!("failed to create solver contract handle: {}", e))?;

        let solver_addr = solver_address
            .parse::<Address>()
            .map_err(|e| anyhow!("invalid solver address {}: {}", solver_address, e))?;

        let solver_id = contract
            .get_solver_id(solver_addr)
            .await
            .map_err(|e| anyhow!("contract getSolverId failed for {}: {}", solver_address, e))?;

        if solver_id.trim().is_empty() {
            Err(anyhow!(
                "solver id not found on contract for address {}",
                solver_address
            ))
        } else {
            Ok(solver_id)
        }
    }

    fn get_transaction_type_from_context(context: &str) -> crate::types::TransactionType {
        match context {
            "withdraw_liquidity" => crate::types::TransactionType::WithdrawLiquidity,
            "claim_reward" | "reward_txn" => crate::types::TransactionType::RewardTxn,
            "add_liquidity" => crate::types::TransactionType::AddLiquidity,
            _ => crate::types::TransactionType::RewardTxn,
        }
    }

    async fn process_eth_payout(
        &mut self,
        context: &str,
        solver_address: &str,
        eth_address: &str,
        amount: u128,
    ) -> Result<bool> {
        let tx_type = Self::get_transaction_type_from_context(context);

        info!(
            "💧 [{}] Processing TICS payout: {} -> {} (amount: {})",
            context, solver_address, eth_address, amount
        );

        let dkg_node = match &self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [{}] DKG node not available for TICS payout", context);
                return Ok(false);
            }
        };

        let group_key = match dkg_node.get_final_public_key().await {
            Some(key) => key,
            None => {
                warn!("❌ [{}] No group key available for TICS payout", context);
                return Ok(false);
            }
        };

        let network_address = crate::utils::get_eth_address_from_group_key(group_key);
        let eth_tx = match crate::utils::transaction::create_ethereum_transaction(
            &network_address,
            eth_address,
            amount,
            "qubetics",
        )
        .await
        {
            Ok(tx) => tx,
            Err(e) => {
                error!(
                    "❌ [{}] Failed to create TICS payout transaction: {}",
                    context, e
                );
                return Ok(false);
            }
        };

        info!(
            "✅ [{}] Created TICS payout transaction: {:?}",
            context, eth_tx
        );

        let signing_node = match &mut self.signing_node {
            Some(node) => node,
            None => {
                warn!("❌ [{}] Signing node unavailable for TICS payout", context);
                return Ok(false);
            }
        };

        let available_nodes: Vec<PeerId> =
            self.node_manager.get_active_nodes().into_iter().collect();
        signing_node.set_available_nodes(available_nodes);
        signing_node.set_chain_handler(
            crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(eth_tx.chain_id)
                .into(),
        );

        let secret_share = match dkg_node.get_final_secret_share().await {
            Some(share) => share,
            None => {
                info!(
                    "⏳ [{}] DKG not completed yet, no secret share for TICS payout",
                    context
                );
                return Ok(false);
            }
        };

        if let Some(group_key) = dkg_node.get_final_public_key().await {
            signing_node.set_group_public_key(group_key);
        }

        let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&eth_tx);
        info!(
            "🔐 [{}] Starting TICS payout signing: 0x{}",
            context,
            hex::encode(tx_bytes.clone())
        );

        // For withdraw_liquidity and reward_txn, queue to network sequencer for coordinated signing
        if context == "withdraw_liquidity" {
            if let Err(e) = self
                .submit_withdraw_liquidity_to_sequencer(
                    solver_address,
                    eth_address,
                    amount,
                    tx_bytes,
                    eth_tx,
                )
                .await
            {
                error!(
                    "❌ [{}] Failed to submit withdraw liquidity to sequencer: {}",
                    context, e
                );
                return Err(e);
            }

            info!(
                "✅ [{}] Submitted withdraw liquidity to network sequencer",
                context
            );
            // Note: record_pending_liquidity_contract_update will be called after transaction is signed
            Ok(true)
        } else if context == "reward_txn" || context == "claim_reward" {
            if let Err(e) = self
                .submit_reward_payout_to_sequencer(
                    solver_address,
                    eth_address,
                    amount,
                    tx_bytes,
                    eth_tx,
                )
                .await
            {
                error!(
                    "❌ [{}] Failed to submit reward payout to sequencer: {}",
                    context, e
                );
                return Err(e);
            }

            info!(
                "✅ [{}] Submitted reward payout to network sequencer",
                context
            );
            Ok(true)
        } else {
            // For other contexts, sign directly
            let chain_handler: Arc<dyn crate::chain_abstraction::ChainHandler> =
                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                    eth_tx.chain_id,
                )
                .into();
            let mut eth_signer = EthereumSigner::new(signing_node);
            eth_signer
                .sign_transaction(
                    tx_bytes,
                    &chain_handler,
                    &eth_tx,
                    None,
                    None,
                    None,
                    Some(tx_type),
                    Some(solver_address.to_string()),
                    Some(secret_share),
                )
                .await?;

            info!("✅ [{}] TICS payout signing completed", context);
            Ok(true)
        }
    }

    async fn process_btc_payout(
        &mut self,
        context: &str,
        solver_address: &str,
        btc_address: &str,
        amount: u128,
    ) -> Result<bool> {
        let tx_type = Self::get_transaction_type_from_context(context);

        info!(
            "💧 [{}] Processing BTC payout: {} -> {} (amount: {})",
            context, solver_address, btc_address, amount
        );

        let dkg_node = match &self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [{}] DKG node not available for BTC payout", context);
                return Ok(false);
            }
        };

        let group_key = match dkg_node.get_final_public_key().await {
            Some(key) => key,
            None => {
                warn!("❌ [{}] No group key available for BTC payout", context);
                return Ok(false);
            }
        };

        let network_btc_address = crate::utils::get_btc_address_from_group_key(group_key);
        let btc_tx = match crate::utils::transaction::create_bitcoin_transaction(
            &network_btc_address,
            btc_address,
            amount,
        )
        .await
        {
            Ok(tx) => tx,
            Err(e) => {
                error!(
                    "❌ [{}] Failed to create BTC payout transaction: {}",
                    context, e
                );
                // Return error to propagate insufficient UTXO and other transaction creation errors
                return Err(anyhow::anyhow!(
                    "Failed to create BTC transaction: {}",
                    e
                ));
            }
        };

        info!(
            "✅ [{}] Created BTC payout transaction: {:?}",
            context, btc_tx
        );

        let signing_node = match &mut self.signing_node {
            Some(node) => node,
            None => {
                warn!("❌ [{}] Signing node unavailable for BTC payout", context);
                return Ok(false);
            }
        };

        let available_nodes: Vec<PeerId> =
            self.node_manager.get_active_nodes().into_iter().collect();
        signing_node.set_available_nodes(available_nodes);
        signing_node.set_chain_handler(
            crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                crate::types::network::network_type()
                    .bitcoin_network_label()
                    .to_string(),
            )
            .into(),
        );

        let secret_share = match dkg_node.get_final_secret_share().await {
            Some(share) => share,
            None => {
                info!(
                    "⏳ [{}] DKG not completed yet, no secret share for BTC payout",
                    context
                );
                return Ok(false);
            }
        };

        if let Some(group_key) = dkg_node.get_final_public_key().await {
            signing_node.set_group_public_key(group_key);
        }

        let chain_handler: Arc<dyn crate::chain_abstraction::ChainHandler> =
            crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                crate::types::network::network_type()
                    .bitcoin_network_label()
                    .to_string(),
            )
            .into();
        let chain_tx = crate::chain_abstraction::ChainTransaction::Bitcoin(btc_tx.clone());
        let tx_bytes = chain_handler.create_transaction_bytes(&chain_tx).unwrap();

        info!(
            "🔐 [{}] Starting BTC payout signing: 0x{}",
            context,
            hex::encode(tx_bytes.clone())
        );

        let mut btc_signer = BitcoinSigner::new(signing_node);
        btc_signer
            .sign_transaction(
                tx_bytes,
                &chain_handler,
                Some(btc_tx),
                None,
                None,
                Some(tx_type),
                None,
                Some(solver_address.to_string()),
                Some(secret_share),
            )
            .await?;

        info!("✅ [{}] BTC payout signing completed", context);
        if context == "withdraw_liquidity" {
            self.record_pending_liquidity_contract_update(
                solver_address,
                TransactionNetwork::BTC,
                amount,
            )
            .await;
        }
        Ok(true)
    }

    pub(crate) async fn process_payout(
        &mut self,
        context: &str,
        solver_address: &str,
        btc_address: &Option<String>,
        eth_address: &Option<String>,
        amount_btc: &Option<String>,
        amount_tics: &Option<String>,
    ) -> Result<(bool, bool)> {
        let mut tics_payout_initiated = false;
        let mut btc_payout_initiated = false;
        if amount_btc.is_none() && amount_tics.is_none() {
            warn!(
                "❌ [{}] No BTC or TICS amount specified for solver {}",
                context, solver_address
            );
            return Ok((tics_payout_initiated, btc_payout_initiated));
        }

        if let Some(amount_str) = amount_tics {
            if let Some(eth_addr) = eth_address {
                match amount_str.parse::<u128>() {
                    Ok(tics_amount) => {
                        tics_payout_initiated = self
                            .process_eth_payout(context, solver_address, eth_addr, tics_amount)
                            .await?;
                    }
                    Err(_) => {
                        warn!(
                            "❌ [{}] Invalid TICS payout amount: {}",
                            context, amount_str
                        );
                    }
                }
            } else {
                warn!(
                    "❌ [{}] TICS payout requested but no ETH address provided",
                    context
                );
            }
        }

        if let Some(amount_str) = amount_btc {
            if let Some(btc_addr) = btc_address {
                match amount_str.parse::<u128>() {
                    Ok(btc_amount) => {
                        btc_payout_initiated = self
                            .process_btc_payout(context, solver_address, btc_addr, btc_amount)
                            .await?;
                    }
                    Err(_) => {
                        warn!("❌ [{}] Invalid BTC payout amount: {}", context, amount_str);
                    }
                }
            } else {
                warn!(
                    "❌ [{}] BTC payout requested but no BTC address provided",
                    context
                );
            }
        }

        info!(
            "✅ [{}] Payout processing complete for solver {}",
            context, solver_address
        );
        Ok((tics_payout_initiated, btc_payout_initiated))
    }

    pub(crate) async fn submit_solver_reward_contract_update(
        &mut self,
        solver_address: &str,
        reward_btc: Option<u128>,
        reward_tics: Option<u128>,
        payout_tx_hash: &str,
        request_id: Option<String>,
        original_request: Option<crate::network::ContractTransactionRequest>,
    ) -> Result<()> {
        let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
        if contract_address == "0x0000000000000000000000000000000000000000" {
            info!(
                "⏭️ [SOLVER] Skipping reward update for {} - solver contract address not configured",
                solver_address
            );
            return Ok(());
        }

        let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "9029".to_string())
            .parse::<u64>()
            .unwrap_or(9029);
        let chain_name = if chain_id == 9029 {
            "qubetics"
        } else {
            "ethereum"
        };

        let rewards_payload = vec![
            U256::from(reward_btc.unwrap_or(0)),
            U256::from(reward_tics.unwrap_or(0)),
        ];

        if rewards_payload.iter().all(|value| value.is_zero()) {
            info!(
                "⏭️ [SOLVER] Skipping reward update for {} - both payout values are zero",
                solver_address
            );
            return Ok(());
        }

        info!(
            "🧮 [SOLVER] Reward payload for {} -> btc: {}, tics: {} (contract: {}, chain_id: {})",
            solver_address, rewards_payload[0], rewards_payload[1], contract_address, chain_id
        );

        let dkg_node = if let Some(node) = &self.dkg_node {
            node
        } else {
            warn!(
                "❌ [SOLVER] Cannot update solver rewards for {} - DKG node unavailable",
                solver_address
            );
            return Ok(());
        };

        let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
            key
        } else {
            warn!(
                "❌ [SOLVER] Cannot update solver rewards for {} - vault group key unavailable",
                solver_address
            );
            return Ok(());
        };

        let vault_address = crate::utils::get_eth_address_from_group_key(group_public_key);
        info!(
            "🧾 [SOLVER] Submitting reward update for {} via vault address {}",
            solver_address, vault_address
        );

        let chain_tx = crate::utils::transaction::create_solver_rewards_update_transaction(
            &vault_address,
            solver_address,
            &rewards_payload,
            payout_tx_hash,
            &contract_address,
            chain_id,
            chain_name,
        )
        .await?;

        let eth_tx = match chain_tx {
            crate::chain_abstraction::ChainTransaction::Ethereum(tx) => tx,
            _ => {
                warn!(
                    "❌ [SOLVER] Reward update transaction for {} is not an Ethereum transaction",
                    solver_address
                );
                return Ok(());
            }
        };

        if let Some(signing_node) = &mut self.signing_node {
            let available_nodes: Vec<PeerId> =
                self.node_manager.get_active_nodes().into_iter().collect();
            signing_node.set_available_nodes(available_nodes);
            signing_node.set_chain_handler(
                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                    eth_tx.chain_id,
                )
                .into(),
            );

            let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

            if let Some(ref _secret_share) = vault_tweaked_share {
                // signing_node.set_group_public_key(group_public_key);
                signing_node.set_vault_group_key(group_public_key);

                let contract_tx = crate::types::intent::ContractTransaction {
                    to: eth_tx.to.clone(),
                    value: eth_tx.value.clone(),
                    nonce: eth_tx.nonce,
                    gas_limit: eth_tx.gas_limit,
                    gas_price: eth_tx.gas_price.clone(),
                    chain_id: eth_tx.chain_id,
                    data: eth_tx
                        .data
                        .as_ref()
                        .map(|d| format!("0x{}", hex::encode(d)))
                        .unwrap_or_else(|| "0x".to_string()),
                };
                info!(
                    "🔧 [CONTRACT] Contract transaction: {:?}",
                    contract_tx.clone()
                );
                info!(
                    "🔧 [CONTRACT] Contract transaction data: {:?}",
                    contract_tx.data
                );
                info!(
                    "🔧 [CONTRACT] Contract transaction data hex: {:?}",
                    hex::encode(contract_tx.data.clone())
                );
                // info!("🔧 [CONTRACT] Contract transaction data length: {:?}", contract_tx.data.len());
                // info!("🔧 [COONTRACT] Contract transaction data as ref: {:?}", contract_tx.data.as_ref());
                // info!("🔧 [CNTRACT] Contract transaction data as ref hex: {:?}", hex::encode(contract_tx.data.as_ref()));
                // info!("🔧 [CONTRACT] Contract transaction data as ref as ref: {:?}", contract_tx.data.as_ref().as_ref());
                // info!("🔧 [CONTRACT] Contract transaction data as ref as ref hex: {:?}", hex::encode(contract_tx.data.as_ref().as_ref()));
                let contract_tx_bytes =
                    crate::utils::transaction::create_transaction_for_signing_contract(
                        &contract_tx,
                    );
                info!(
                    "🔐 [SOLVER] Starting contract update signing for {}: 0x{}",
                    solver_address,
                    hex::encode(&contract_tx_bytes)
                );

                let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
                let mut eth_signer = EthereumSigner::new(signing_node);
                eth_signer
                    .sign_contract_message(
                        contract_tx_bytes,
                        &contract_chain_handler,
                        &contract_tx,
                        vault_tweaked_share,
                        None,
                        vault_tweaked_share,
                        request_id, // Pass request_id from sequencer
                        original_request, // Pass original_request for retry support
                    )
                    .await?;
                info!(
                    "✅ [SOLVER] Reward update transaction signed for solver {} (btc: {}, tics: {})",
                    solver_address,
                    rewards_payload[0],
                    rewards_payload[1]
                );
            } else {
                warn!(
                    "⚠️ [SOLVER] Skipping reward update for {} - missing vault secret share",
                    solver_address
                );
            }
        } else {
            warn!(
                "❌ [SOLVER] Signing node unavailable for reward update for {}",
                solver_address
            );
        }

        Ok(())
    }

    pub(crate) async fn submit_solver_liquidity_contract_update(
        &mut self,
        solver_address: &str,
        asset_chain_name: &str,
        amount: u128,
        payout_tx_hash: &str,
        request_id: Option<String>,
        original_request: Option<crate::network::ContractTransactionRequest>,
    ) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }

        let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
        if contract_address == "0x0000000000000000000000000000000000000000" {
            info!(
                "⏭️ [SOLVER] Skipping contract liquidity update for {} - solver contract address not configured",
                solver_address
            );
            return Ok(());
        }

        let contract_chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "9029".to_string())
            .parse::<u64>()
            .unwrap_or(9029);
        let contract_chain_name = if contract_chain_id == 9029 {
            "qubetics"
        } else {
            "ethereum"
        };

        let asset_chain_id_value =
            crate::utils::transaction::get_chain_id_from_name(asset_chain_name).unwrap_or(0);
        let asset_chain_id_u256 = U256::from(asset_chain_id_value);
        let amount_u256 = U256::from(amount);

        if amount_u256.is_zero() {
            return Ok(());
        }

        let solver_id = match self.fetch_solver_id_for_address(solver_address).await {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    "⚠️ [SOLVER] Unable to fetch solver ID for {}: {}; skipping contract update",
                    solver_address, e
                );
                return Ok(());
            }
        };

        let dkg_node = if let Some(node) = &self.dkg_node {
            node
        } else {
            warn!(
                "❌ [SOLVER] Cannot update contract liquidity for {} - DKG node unavailable",
                solver_address
            );
            return Ok(());
        };

        let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
            key
        } else {
            warn!(
                "❌ [SOLVER] Cannot update contract liquidity for {} - vault group key unavailable",
                solver_address
            );
            return Ok(());
        };

        let vault_address = crate::utils::get_eth_address_from_group_key(group_public_key);
        info!(
            "🧾 [SOLVER] Submitting removeLiquidity for solver {} (solver_id={}, chain_id={}, amount={}, contract={}, from={})",
            solver_address,
            solver_id,
            asset_chain_id_value,
            amount,
            contract_address,
            vault_address
        );

        let eth_tx = crate::utils::transaction::create_solver_remove_liquidity_transaction(
            &vault_address,
            &solver_id,
            asset_chain_id_u256,
            amount_u256,
            payout_tx_hash,
            &contract_address,
            contract_chain_id,
            contract_chain_name,
        )
        .await?;

        if let Some(signing_node) = &mut self.signing_node {
            let available_nodes: Vec<PeerId> =
                self.node_manager.get_active_nodes().into_iter().collect();
            signing_node.set_available_nodes(available_nodes);
            signing_node.set_chain_handler(
                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                    eth_tx.chain_id,
                )
                .into(),
            );

            let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

            if let Some(ref _secret_share) = vault_tweaked_share {
                // signing_node.set_group_public_key(group_public_key);
                signing_node.set_vault_group_key(group_public_key);

                let contract_tx = crate::types::intent::ContractTransaction {
                    to: eth_tx.to.clone(),
                    value: eth_tx.value.clone(),
                    nonce: eth_tx.nonce,
                    gas_limit: eth_tx.gas_limit,
                    gas_price: eth_tx.gas_price.clone(),
                    chain_id: eth_tx.chain_id,
                    data: eth_tx
                        .data
                        .as_ref()
                        .map(|d| format!("0x{}", hex::encode(d)))
                        .unwrap_or_else(|| "0x".to_string()),
                };

                let tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(
                    &contract_tx,
                );
                info!(
                    "🔐 [SOLVER] Starting contract liquidity update signing for {}: 0x{}",
                    solver_address,
                    hex::encode(&tx_bytes)
                );
                let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
                let mut eth_signer = EthereumSigner::new(signing_node);
                eth_signer
                    .sign_contract_message(
                        tx_bytes,
                        &contract_chain_handler,
                        &contract_tx,
                        vault_tweaked_share,
                        None,
                        vault_tweaked_share,
                        request_id, // Pass request_id from sequencer
                        original_request, // No original_request available in this context
                    )
                    .await?;
                info!(
                    "✅ [SOLVER] Contract liquidity update transaction signed for solver {} (chain_id: {}, amount: {})",
                    solver_address,
                    asset_chain_id_value,
                    amount
                );
            } else {
                warn!(
                    "⚠️ [SOLVER] Skipping contract liquidity update for {} - missing vault secret share",
                    solver_address
                );
            }
        } else {
            warn!(
                "❌ [SOLVER] Signing node unavailable for contract liquidity update for {}",
                solver_address
            );
        }

        Ok(())
    }

    pub(crate) async fn submit_solver_add_liquidity_contract_update(
        &mut self,
        solver_address: &str,
        solver_id: &str,
        asset_chain_name: &str,
        amount: u128,
        request_id: Option<String>,
        original_request: Option<crate::network::ContractTransactionRequest>,
    ) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }

        let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
        if contract_address == "0x0000000000000000000000000000000000000000" {
            info!(
                "⏭️ [SOLVER] Skipping contract add-liquidity for {} - solver contract address not configured",
                solver_address
            );
            return Ok(());
        }

        let contract_chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "9029".to_string())
            .parse::<u64>()
            .unwrap_or(9029);
        let contract_chain_name = if contract_chain_id == 9029 {
            "qubetics"
        } else {
            "ethereum"
        };

        let asset_chain_id_value =
            crate::utils::transaction::get_chain_id_from_name(asset_chain_name).unwrap_or(0);
        let asset_chain_id_u256 = U256::from(asset_chain_id_value);
        let amount_u256 = U256::from(amount);

        if amount_u256.is_zero() {
            return Ok(());
        }

        let dkg_node = if let Some(node) = &self.dkg_node {
            node
        } else {
            warn!(
                "❌ [SOLVER] Cannot add liquidity on contract for {} - DKG node unavailable",
                solver_address
            );
            return Ok(());
        };

        let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
            key
        } else {
            warn!(
                "❌ [SOLVER] Cannot add liquidity on contract for {} - vault group key unavailable",
                solver_address
            );
            return Ok(());
        };

        let vault_address = crate::utils::get_eth_address_from_group_key(group_public_key);
        info!(
            "🧾 [SOLVER] Submitting addLiquidity for solver {} (solver_id={}, chain_id={}, amount={}, contract={}, from={})",
            solver_address,
            solver_id,
            asset_chain_id_value,
            amount,
            contract_address,
            vault_address
        );

        let chain_tx = crate::utils::transaction::create_solver_add_liquidity_transaction(
            &vault_address,
            solver_id,
            asset_chain_id_u256,
            amount_u256,
            &contract_address,
            contract_chain_id,
            contract_chain_name,
        )
        .await?;

        let eth_tx = match chain_tx {
            ChainTransaction::Ethereum(tx) => tx,
            ChainTransaction::Bitcoin(_) => {
                warn!(
                    "⚠️ [SOLVER] addLiquidity contract call only supported on EVM chains; skipping solver {}",
                    solver_address
                );
                return Ok(());
            }
        };

        if let Some(signing_node) = &mut self.signing_node {
            let available_nodes: Vec<PeerId> =
                self.node_manager.get_active_nodes().into_iter().collect();
            signing_node.set_available_nodes(available_nodes);
            signing_node.set_chain_handler(
                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                    eth_tx.chain_id,
                )
                .into(),
            );

            let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

            if let Some(ref _secret_share) = vault_tweaked_share {
                // signing_node.set_group_public_key(group_public_key);
                signing_node.set_vault_group_key(group_public_key);

                let contract_tx = crate::types::intent::ContractTransaction {
                    to: eth_tx.to.clone(),
                    value: eth_tx.value.clone(),
                    nonce: eth_tx.nonce,
                    gas_limit: eth_tx.gas_limit,
                    gas_price: eth_tx.gas_price.clone(),
                    chain_id: eth_tx.chain_id,
                    data: eth_tx
                        .data
                        .as_ref()
                        .map(|d| format!("0x{}", hex::encode(d)))
                        .unwrap_or_else(|| "0x".to_string()),
                };

                let tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(
                    &contract_tx,
                );
                info!(
                    "🔐 [SOLVER] Starting contract add-liquidity signing for {} on {} (amount: {})",
                    solver_address, asset_chain_name, amount
                );
                let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
                let mut eth_signer = EthereumSigner::new(signing_node);
                eth_signer
                    .sign_contract_message(
                        tx_bytes,
                        &contract_chain_handler,
                        &contract_tx,
                        vault_tweaked_share,
                        None,
                        vault_tweaked_share,
                        request_id, // Pass request_id from sequencer
                        original_request, // Pass original_request for retry support
                    )
                    .await?;
                info!(
                    "✅ [SOLVER] Contract add-liquidity transaction signed for solver {} (chain: {}, amount: {})",
                    solver_address, asset_chain_id_value, amount
                );
            } else {
                warn!(
                    "⚠️ [SOLVER] Skipping contract add-liquidity for {} - missing vault secret share",
                    solver_address
                );
            }
        } else {
            warn!(
                "❌ [SOLVER] Signing node unavailable for contract add-liquidity for {}",
                solver_address
            );
        }

        Ok(())
    }

    fn parse_liquidity_amount_value(amount_str: &str, asset_label: &str) -> Option<u128> {
        match U256::from_dec_str(amount_str) {
            Ok(value) => {
                if value.is_zero() {
                    warn!(
                        "⚠️ [ADD-LIQ] {} add-liquidity amount is zero; skipping contract submission",
                        asset_label
                    );
                    None
                } else if value.bits() > 128 {
                    warn!(
                        "⚠️ [ADD-LIQ] {} add-liquidity amount {} exceeds u128 bounds; skipping",
                        asset_label, amount_str
                    );
                    None
                } else {
                    Some(value.low_u128())
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ [ADD-LIQ] Failed to parse {} add-liquidity amount '{}': {}",
                    asset_label, amount_str, e
                );
                None
            }
        }
    }

    pub(crate) async fn handle_add_liquidity_contract_calls(
        &mut self,
        solver_address: &str,
        solver_id: &str,
        amount_btc: &Option<String>,
        amount_tics: &Option<String>,
        request_id: &str,
    ) -> Result<()> {
        let mut dispatched = false;

        if let Some(amount_str) = amount_tics.as_ref() {
            if let Some(amount) = Self::parse_liquidity_amount_value(amount_str, "TICS") {
                info!(
                    "💧 [ADD-LIQ] Dispatching contract update for solver {} on qubetics (amount: {})",
                    solver_address, amount_str
                );
                // Submit to sequencer for synchronized execution
                self.submit_solver_add_liquidity_to_sequencer(
                    solver_address,
                    solver_id,
                    "qubetics",
                    amount,
                    request_id,
                )
                .await?;
                dispatched = true;
            }
        }

        if let Some(amount_str) = amount_btc.as_ref() {
            if let Some(amount) = Self::parse_liquidity_amount_value(amount_str, "BTC") {
                info!(
                    "💧 [ADD-LIQ] Dispatching contract update for solver {} on btc (amount: {})",
                    solver_address, amount_str
                );
                // Submit to sequencer for synchronized execution
                self.submit_solver_add_liquidity_to_sequencer(
                    solver_address,
                    solver_id,
                    "btc",
                    amount,
                    request_id,
                )
                .await?;
                dispatched = true;
            }
        }

        if !dispatched {
            info!(
                "ℹ️ [ADD-LIQ] No valid add-liquidity amounts provided for solver {}; skipping contract update",
                solver_address
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::chain_abstraction::{ChainHandler, ChainHandlerFactory};
    use std::sync::Arc;

    #[tokio::test]
    async fn parallel_deposit_chain_handlers_remain_isolated() {
        let evm_handler = tokio::spawn(async {
            let chain_id =
                crate::utils::transaction::get_chain_id_from_name("ethereum").expect("chain id");
            let handler: Arc<dyn ChainHandler> =
                ChainHandlerFactory::create_ethereum_handler(chain_id).into();
            handler
        });

        let btc_handler = tokio::spawn(async {
            let handler: Arc<dyn ChainHandler> = ChainHandlerFactory::create_bitcoin_handler(
                crate::types::network::network_type()
                    .bitcoin_network_label()
                    .to_string(),
            )
            .into();
            handler
        });

        let (evm_handler, btc_handler) = tokio::join!(evm_handler, btc_handler);
        let evm_handler = evm_handler.expect("evm task");
        let btc_handler = btc_handler.expect("btc task");

        assert_eq!(evm_handler.chain_type(), "ethereum");
        assert_eq!(btc_handler.chain_type(), "bitcoin");
        assert!(!Arc::ptr_eq(&evm_handler, &btc_handler));
    }
}
/// Channel message handler
/// Handles all internal channel messages: Broadcast, Unicast, DepositIntent, etc.
///
/// NOTE: This module contains the channel message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~3561-5042 of the original file
use anyhow::{anyhow, Result};
use ethers::types::{Address, U256};
use ff::PrimeField;
use libp2p::{gossipsub, PeerId};
use tracing::{debug, error, info, warn};

use crate::{
    chain_abstraction::transactions::ChainTransaction,
    contract::{ContractClient, ContractConfig, SolverManagerContract},
    signing::{BitcoinSigner, EthereumSigner},
    types::{
        intent::TransactionNetwork, rpc::RPCRequest, rpc_server::NodeStatus, ChannelMessage,
        GossipsubMessage,
    },
};

use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer};
use crate::protocols::DKGStatus;

impl MpcNetworkLayer {
    // ChannelMessage is related to the MPSC channel only
    pub(crate) async fn handle_channel_message(
        &mut self,
        message: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match message {
            ChannelMessage::PeerDiscoveryRetry { attempt } => {
                if !self.peer_discovery.pending_peer_discovery_retry {
                    return Ok(());
                }

                self.peer_discovery.pending_peer_discovery_retry = false;

                if self.has_additional_peers() {
                    self.broadcast_local_presence().await?;
                } else if attempt >= Self::MAX_PEER_DISCOVERY_RETRIES {
                    warn!(
                        "⚠️ Peer discovery retry attempt {} reached limit {}; not broadcasting yet",
                        attempt,
                        Self::MAX_PEER_DISCOVERY_RETRIES
                    );
                } else {
                    self.schedule_peer_discovery_retry(attempt + 1);
                }
            }
            ChannelMessage::StatusRequest { responder } => {
                let peer_id = self.local_peer_id.to_string();
                let connected_peers = swarm.connected_peers().count();

                let (dkg_status, has_final_share) = if let Some(dkg_node) = &self.dkg_node {
                    let status = dkg_node.get_status();
                    let has_share = dkg_node.get_final_secret_share().await.is_some();
                    (status, has_share)
                } else {
                    (DKGStatus::New, false)
                };

                let is_ready = has_final_share && matches!(dkg_status, DKGStatus::Completed);
                let dkg_status_str = format!("{:?}", dkg_status);

                let status = NodeStatus {
                    peer_id,
                    connected_peers,
                    dkg_status: dkg_status_str,
                    is_ready,
                };

                if responder.send(status).is_err() {
                    warn!("❌ [STATUS] Failed to send node status response to requester");
                }
            }
            // this is used in the dkg code
            ChannelMessage::Broadcast { topic, data } => {
                // dkg.s.1
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());

                // Production: Check channel capacity and log warnings for monitoring
                let channel_capacity_warning_threshold = 0.8; // Warn at 80% full
                // Note: We can't directly check channel capacity, but we can monitor via try_send failures
                
                // Check if this is a critical message that needs retry tracking
                // Only register if retry manager is available and message deserializes correctly
                // Skip registration if message is already being tracked (e.g., from a retry)
                if let Some(retry_mgr) = &self.retry_manager {
                    match serde_json::from_slice::<crate::types::GossipsubMessage>(&data) {
                        Ok(gossip_msg) => {
                            if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_msg) {
                                // Generate message ID to check if already tracked
                                if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_msg) {
                                    // Check if already being tracked (this is a retry, skip registration)
                                    if retry_mgr.is_message_tracked(&message_id).await {
                                        info!("🔄 [RETRY] Message {:?} already tracked, skipping registration (this is a retry)", message_id);
                                    } else {
                                        // Get expected nodes (all active nodes except ourselves)
                                        let expected_nodes: std::collections::HashSet<PeerId> = self
                                            .node_manager
                                            .get_active_nodes()
                                            .into_iter()
                                            .filter(|&pid| pid != self.local_peer_id)
                                            .collect();

                                        if !expected_nodes.is_empty() {
                                            // Check if already tracked (retry case)
                                            if retry_mgr.is_message_tracked(&message_id).await {
                                                info!("🔄 [RETRY] Message {:?} already tracked, skipping registration (this is a retry)", message_id);
                                            } else {
                                                // Log expected nodes for debugging
                                                let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
                                                info!(
                                                    "📋 [RETRY] Registering message {:?} - expecting ACKs from {} nodes: {:?}",
                                                    message_id, expected_nodes.len(), expected_list
                                                );
                                                
                                                // Register with retry manager (first time only)
                                                if let Err(e) = retry_mgr.register_message(
                                                    message_id.clone(),
                                                    topic.clone(),
                                                    data.clone(),
                                                    expected_nodes.clone(),
                                                ).await {
                                                    error!("❌ [RETRY] Failed to register critical message for retry: {}", e);
                                                }
                                            }
                                        } else {
                                            warn!("⚠️ [RETRY] No expected nodes - skipping retry registration for {:?}", message_id);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Message deserialization failed - this is expected for some message types
                            // Only log at debug level to avoid noise
                            debug!("[BROADCAST] Message deserialization failed (may not be a GossipsubMessage): {}", e);
                        }
                    }
                }

                // Check if this is a retry by checking if message is already tracked
                let is_retry = if let Some(retry_mgr) = &self.retry_manager {
                    match serde_json::from_slice::<crate::types::GossipsubMessage>(&data) {
                        Ok(gossip_msg) => {
                            if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_msg) {
                                if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_msg) {
                                    retry_mgr.is_message_tracked(&message_id).await
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                };

                // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                // if peer(s) have already subscribed to this topic, they will recieve this
                // msg (check subscribe_to_default_topics())
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    let publish_result = swarm_mut.gossipsub.publish(topic_hash, data);
                    match publish_result {
                        Ok(_) => {}
                        Err(e) => {
                            if is_retry {
                                error!(
                                    "❌ [RETRY] CRITICAL: Failed to publish retry message to topic {}: {:?}",
                                    topic, e
                                );
                                // For retries, this is critical - log as error
                            } else {
                                warn!(
                                    "❌ [BROADCAST] Failed to publish message to topic {}: {:?}",
                                    topic, e
                                );
                                // Initial publish failure - retry mechanism will handle it if message was registered
                            }
                        }
                    }
                } else {
                    if is_retry {
                        error!(
                            "❌ [RETRY] No peers available for retry broadcast to topic: {}",
                            topic
                        );
                    } else {
                        warn!(
                            "⚠️ [BROADCAST] No peers available for broadcasting to topic: {}",
                            topic
                        );
                    }
                }
            }
            // SECURE DKG SHARE DISTRIBUTION - sends share to specific peer via P2P RPC
            ChannelMessage::UnicastShareDKG {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;


                // Parse the target peer ID
                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [DKG-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                // Attempt to dial if not connected and we have a listen address
                let mut is_connected = swarm.is_connected(&peer_id);
                let connected_peers = swarm.connected_peers().collect::<Vec<_>>();
                info!("🔐 [DKG-SECURE]  Connected peers: {:?}", connected_peers);

                info!(
                    "🔐 [DKG-SECURE]  Peer discovery {} address: {:?}",
                    target_peer_id,
                    self.peer_discovery.peer_multiaddresses.get(&peer_id)
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [DKG-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!("⚠️ [DKG-SECURE] Dial to {} failed: {}", target_peer_id, e);
                        } else {
                            // allow a brief window for connection to establish
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            info!(
                                "🔐 [DKG-SECURE] Dial to connect to {} successful {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [DKG-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    // Not connected - schedule retry with exponential backoff
                    let delay_ms = 1000 * (1 << retry_count.min(5)); // 1s, 2s, 4s, 8s, 16s, 32s max
                    info!(
                        "🔄 [DKG-SECURE] Peer send {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastShareDKG {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        share_index,
                        share_value,
                        commitments,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [DKG-SECURE] Failed to schedule retry for share {}: {}",
                                share_index,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [DKG-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                // Create the RPC request
                let request = RPCRequest::SendDKGShare {
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                    round,
                };

                // Send via request-response protocol (unicast, not broadcast)
                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request.clone());

                // Track request for reliability
                self.pending_share_requests.insert(
                    request_id,
                    crate::network::transport::types::PendingShareRequest {
                        peer: peer_id,
                        request,
                        retry_count,
                        timestamp: std::time::Instant::now(),
                    },
                );

                info!(
                    "✅ [DKG-SECURE] Share index {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    share_index, target_peer_id, request_id, is_connected
                );
            }
            ChannelMessage::RequestDKGShare {
                target_peer_id,
                requester_id,
            } => {
                 let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [DKG-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };
                
                let request = RPCRequest::RequestDKGShare {
                    requester_id,
                };
                
                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);
                    
                info!(
                    "📤 [DKG-SECURE] Sent RequestDKGShare to {} (request_id: {:?})",
                    target_peer_id, request_id
                );
            }
            // SECURE REFRESH SHARE DISTRIBUTION - sends refresh share to specific peer via P2P RPC
            ChannelMessage::UnicastRefreshShare {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                info!(
                    "🔐 [REFRESH-SECURE] Sending refresh share index {} via UNICAST to peer {} (attempt {})",
                    share_index, target_peer_id, retry_count + 1
                );

                // Parse the target peer ID
                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [REFRESH-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                // Attempt to dial if not connected
                let mut is_connected = swarm.is_connected(&peer_id);
                info!(
                    "🔐 [REFRESH-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [REFRESH-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [REFRESH-SECURE] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            info!(
                                "🔐 [REFRESH-SECURE] Dial to {} successful: {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [REFRESH-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let delay_ms = 1000 * (1 << retry_count.min(5));
                    info!(
                        "🔄 [REFRESH-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastRefreshShare {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        share_index,
                        share_value,
                        commitments,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [REFRESH-SECURE] Failed to schedule retry for refresh share {}: {}",
                                share_index, e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [REFRESH-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                // Create the RPC request
                let request = RPCRequest::SendRefreshShare {
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                };

                // Send via request-response protocol (unicast, not broadcast)
                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request.clone());

                // Track request for reliability
                self.pending_share_requests.insert(
                    request_id,
                    crate::network::transport::types::PendingShareRequest {
                        peer: peer_id,
                        request,
                        retry_count,
                        timestamp: std::time::Instant::now(),
                    },
                );

                info!(
                    "✅ [REFRESH-SECURE] Refresh share index {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    share_index, target_peer_id, request_id, is_connected
                );
            }
            // CRITICAL GOSSIP DELIVERY - sends critical gossip bytes to specific peer via P2P RPC
            ChannelMessage::UnicastCritical {
                target_peer_id,
                topic,
                data,
                message_type,
                message_id,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 1;
                const RETRY_DELAY_MS: u64 = 200;

                info!(
                    "📨 [CRITICAL-UNICAST] Sending critical message {}:{} to peer {} (attempt {})",
                    message_type,
                    message_id,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [CRITICAL-UNICAST] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                info!(
                    "📨 [CRITICAL-UNICAST] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [CRITICAL-UNICAST] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [CRITICAL-UNICAST] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            info!(
                                "📨 [CRITICAL-UNICAST] Dial to {} successful: {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [CRITICAL-UNICAST] No known address to dial peer {}; will rely on retry manager",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    info!(
                        "🔄 [CRITICAL-UNICAST] Peer {} not connected - scheduling quick retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        RETRY_DELAY_MS
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastCritical {
                        target_peer_id: target_peer_id.clone(),
                        topic: topic.clone(),
                        data: data.clone(),
                        message_type: message_type.clone(),
                        message_id: message_id.clone(),
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [CRITICAL-UNICAST] Failed to schedule retry for {}:{}: {}",
                                message_type,
                                message_id,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [CRITICAL-UNICAST] Peer {} still not connected after quick retry - giving up",
                        target_peer_id
                    );
                    return Ok(());
                }

                let request = RPCRequest::DeliverCriticalGossip {
                    topic,
                    data,
                    message_type,
                    message_id,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                info!(
                    "✅ [CRITICAL-UNICAST] Critical message sent to {} (request_id: {:?}, connected: {})",
                    target_peer_id, request_id, is_connected
                );
            }
            // SECURE SIGNATURE DISTRIBUTION - sends ECDSA signature to final node via P2P RPC
            ChannelMessage::UnicastECDSASignature {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                info!(
                    "🔐 [SIGNING-SECURE] Sending ECDSA signature for round {} via UNICAST to peer {} (attempt {})",
                    round,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                info!(
                    "🔐 [SIGNING-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [SIGNING-SECURE] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            info!(
                                "🔐 [SIGNING-SECURE] Dial to connect to {} successful {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let delay_ms = 1000 * (1 << retry_count.min(5));
                    info!(
                        "🔄 [SIGNING-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastECDSASignature {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        signature_data,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [SIGNING-SECURE] Failed to schedule retry for round {} signature: {}",
                                round,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                let request = RPCRequest::SendECDSASignature {
                    from_node_id,
                    signature_data,
                    round,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                info!(
                    "✅ [SIGNING-SECURE] ECDSA signature for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    round, target_peer_id, request_id, is_connected
                );
            }

            // SECURE SIGNATURE DISTRIBUTION - sends BTC signatures to final node via P2P RPC
            ChannelMessage::UnicastBtcSignatures {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                info!(
                    "🔐 [SIGNING-SECURE] Sending BTC signatures for round {} via UNICAST to peer {} (attempt {})",
                    round,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                info!(
                    "🔐 [SIGNING-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [SIGNING-SECURE] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            info!(
                                "🔐 [SIGNING-SECURE] Dial to connect to {} successful {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let delay_ms = 1000 * (1 << retry_count.min(5));
                    info!(
                        "🔄 [SIGNING-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastBtcSignatures {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        signature_data,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [SIGNING-SECURE] Failed to schedule retry for round {} BTC signatures: {}",
                                round,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                let request = RPCRequest::SendBtcSignatures {
                    from_node_id,
                    signature_data,
                    round,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                info!(
                    "✅ [SIGNING-SECURE] BTC signatures for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    round, target_peer_id, request_id, is_connected
                );
            }
            ChannelMessage::UnicastTransactionData {
                target_peer_id,
                from_node_id,
                transaction_data,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                info!(
                    "📦 [SIGNING-SECURE] Sending transaction data for round {} via UNICAST to peer {} (attempt {})",
                    round,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                info!(
                    "📦 [SIGNING-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "❌ [SIGNING-SECURE] Failed to dial {}: {}",
                                target_peer_id, e
                            );
                        } else {
                            info!("✅ [SIGNING-SECURE] Dialing {}", target_peer_id);
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        }
                        is_connected = swarm.is_connected(&peer_id);
                    } else {
                        warn!(
                            "❌ [SIGNING-SECURE] No known address for peer {}",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let tx = self.message_tx.clone();
                    let delay_ms = 2000 + (retry_count as u64 * 1000);
                    warn!(
                        "⏰ [SIGNING-SECURE] Peer {} not connected, will retry transaction data for round {} in {}ms (attempt {}/{})",
                        target_peer_id,
                        round,
                        delay_ms,
                        retry_count + 1,
                        MAX_RETRIES
                    );

                    let retry_msg = ChannelMessage::UnicastTransactionData {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        transaction_data,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [SIGNING-SECURE] Failed to schedule retry for round {} transaction data: {}",
                                round,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                let request = RPCRequest::SendTransactionData {
                    from_node_id,
                    transaction_data,
                    round,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                info!(
                    "✅ [SIGNING-SECURE] Transaction data for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    round, target_peer_id, request_id, is_connected
                );
            }
            ChannelMessage::IntentHash {
                intent_hash,
                signer,
                intent,
            } => {
                info!("📝 [NETWORK] Storing intent hash from signer {}", signer);

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_intent_hash(intent_hash.clone(), &signer, &intent)
                        .await
                    {
                        warn!("❌ [NETWORK] Failed to store intent hash: {}", e);
                    } else {
                        info!("✅ [NETWORK] Intent hash stored locally");
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store intent hash");
                }

                let intent_hash_hex = hex::encode(&intent_hash);
                let gossip_msg = GossipsubMessage::IntentHash {
                    intent_hash: intent_hash_hex.clone(),
                    signer: signer.clone(),
                    intent: intent.clone(),
                };
                let msg_bytes = serde_json::to_vec(&gossip_msg).map_err(|e| {
                    anyhow::anyhow!("Failed to serialize intent hash message: {}", e)
                })?;
                let topic = gossipsub::IdentTopic::new("intent-hashes");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted intent hash {}", intent_hash_hex);
            }
            ChannelMessage::DepositIntent {
                intent,
                intent_id,
                user_eth_address,
                transaction_type,
                amount,
            } => {
                info!(
                    "📝 [NETWORK] Processing deposit intent locally: {:?}",
                    intent
                );

                // Only broadcast to other nodes via gossipsub when using network share (no user_eth_address)
                info!("🌐 [NETWORK] Using network share - broadcasting to P2P network");
                let deposit_intent_msg = GossipsubMessage::DepositIntent {
                    intent: intent.clone(),
                    intent_id: intent_id.clone(),
                    user_eth_address: user_eth_address.clone(),
                    transaction_type: transaction_type.clone(),
                    amount,
                };
                let msg_bytes = serde_json::to_vec(&deposit_intent_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize deposit intent: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("deposit-intents");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted deposit intent to P2P network");

                // CRITICAL FIX: For refund transactions, use the ORIGINAL intent_hash from intent_id
                // Refund intents have modified target_address/target_chain, so calculating hash from
                // the modified intent would produce a different hash than the original intent
                let intent_hash = if matches!(transaction_type, crate::types::TransactionType::Refund) 
                    && intent_id.starts_with("refund-") 
                {
                    // Extract original intent_hash from "refund-{original_intent_hash}"
                    let original_intent_hash = intent_id.strip_prefix("refund-").unwrap_or(&intent_id);
                    info!("🔐 [LOCAL] Refund transaction detected - using ORIGINAL intent hash: {} (from intent_id: {})", original_intent_hash, intent_id);
                    original_intent_hash.to_string()
                } else {
                    // For non-refund transactions, calculate hash from the intent
                    let calculated_hash = crate::utils::calculate_intent_hash(&intent)
                        .map_err(|e| anyhow::anyhow!("Failed to calculate intent hash: {}", e))?;
                    info!("🔐 [LOCAL] Calculated intent hash: {}", calculated_hash);
                    calculated_hash
                };

                // Prepare unsigned transaction for on-chain deposit intent recording
                // self.prepare_deposit_intent_tx(&intent, &intent_hash).await;

                // Determine chain type based on transaction type:
                // - UserToVault: use source_chain (user is depositing FROM this chain)
                // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
                // - VaultToNetwork: use source_chain (vault is sending back to network on source chain)
                let chain_to_use = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        &intent.source_chain.to_lowercase()
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        &intent.target_chain.to_lowercase()
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        &intent.source_chain.to_lowercase()
                    }
                    crate::types::TransactionType::Refund => {
                        &intent.source_chain.to_lowercase() // Refund goes back to source chain
                    }
                    crate::types::TransactionType::RewardTxn => {
                        // RewardTxn is not valid for intent flow
                        warn!("❌ [LOCAL] RewardTxn is not valid for deposit intent flow");
                        return Ok(());
                    }
                    crate::types::TransactionType::WithdrawLiquidity => {
                        warn!(
                            "❌ [LOCAL] WithdrawLiquidity is not supported in deposit intent flow"
                        );
                        return Ok(());
                    }
                    crate::types::TransactionType::AddLiquidity => {
                        warn!("❌ [LOCAL] AddLiquidity is not supported in deposit intent flow");
                        return Ok(());
                    }
                };
                info!(
                    "🔗 [LOCAL] Processing deposit intent for chain: {} (transaction_type: {:?})",
                    chain_to_use, transaction_type
                );

                // Get the appropriate signing key based on transaction type
                let signing_key: Option<k256::Scalar> = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        // For user deposits, use user's tweaked secret share
                        self.get_signing_key_for_user(user_eth_address.as_ref())
                            .await
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        // For network withdrawals, use network's DKG secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        // For vault-to-network, use vault's tweaked secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_vault_tweaked_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::Refund => {
                        // For refund transactions, use network's DKG secret share (same as NetworkToTarget)
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::RewardTxn => {
                        // RewardTxn is not valid for intent flow
                        None
                    }
                    crate::types::TransactionType::WithdrawLiquidity => {
                        warn!(
                            "❌ [LOCAL] WithdrawLiquidity is not supported for deposit intent signing"
                        );
                        None
                    }
                    crate::types::TransactionType::AddLiquidity => {
                        warn!(
                            "❌ [LOCAL] AddLiquidity is not supported for deposit intent signing"
                        );
                        None
                    }
                };

                if signing_key.is_some() {
                    info!(
                        "🔐 [LOCAL] Successfully retrieved signing key for transaction type: {:?}",
                        transaction_type
                    );
                } else {
                    warn!(
                        "❌ [LOCAL] Failed to retrieve signing key for transaction type: {:?}",
                        transaction_type
                    );
                }

                // Process locally first (this node will sign it)
                if let Some(signing_node) = &mut self.signing_node {
                    let chain_handler: Option<Arc<dyn crate::chain_abstraction::ChainHandler>> =
                        if crate::utils::transaction::is_evm_chain(chain_to_use) {
                            crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                                .map(|chain_id| {
                                    info!(
                                        "🔗 [LOCAL] Using Ethereum chain handler for chain: {} (ID: {})",
                                        chain_to_use, chain_id
                                    );
                                    let handler =
                                        crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                                            chain_id,
                                        );
                                    Arc::from(handler)
                                        as Arc<dyn crate::chain_abstraction::ChainHandler>
                                })
                        } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                            let mut handler =
                                crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                                    crate::types::network::network_type()
                                        .bitcoin_network_label()
                                        .to_string(),
                                );

                            // Set appropriate group public key in Bitcoin chain handler based on transaction type
                            match transaction_type {
                                crate::types::TransactionType::UserToVault => {
                                    // For user deposits, use user's specific group key
                                    if let Some(eth_addr) = &user_eth_address {
                                        if let Some(user_intent_manager) = &self.user_intent_manager
                                        {
                                            if let Some(user) = user_intent_manager
                                                .get_user_by_address(eth_addr)
                                                .await
                                            {
                                                if let Some(user_group_key) = &user.user_group_key {
                                                    let affine_point = user_group_key.0; // user_group_key is SerializablePoint(AffinePoint)
                                                    let encoded_point =
                                                        k256::EncodedPoint::from(affine_point);
                                                    let compressed_bytes = encoded_point
                                                        .compress()
                                                        .to_bytes()
                                                        .to_vec();

                                                    if let Some(btc_handler) = handler
                                                        .as_any_mut()
                                                        .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>()
                                                    {
                                                        btc_handler
                                                            .set_group_public_key(compressed_bytes);
                                                        info!("🔑 [LOCAL] Set user-specific group public key in Bitcoin chain handler for user: {}", eth_addr);
                                                    }
                                                } else {
                                                    warn!(
                                                        "❌ [LOCAL] User {} has no group key for Bitcoin transaction",
                                                        eth_addr
                                                    );
                                                }
                                            } else {
                                                warn!(
                                                    "❌ [LOCAL] User {} not found for Bitcoin transaction",
                                                    eth_addr
                                                );
                                            }
                                        } else {
                                            warn!(
                                                "❌ [LOCAL] User registry not available for Bitcoin transaction"
                                            );
                                        }
                                    } else {
                                        warn!("❌ [LOCAL] UserToVault transaction requires user_eth_address");
                                    }
                                }
                                crate::types::TransactionType::NetworkToTarget
                                | crate::types::TransactionType::Refund => {
                                    // For network withdrawals and refunds, use network's DKG group key
                                    if let Some(dkg_node) = &self.dkg_node {
                                        if let Some(group_key) =
                                            dkg_node.get_final_public_key().await
                                        {
                                            let affine_point = group_key.to_affine();
                                            let encoded_point =
                                                k256::EncodedPoint::from(affine_point);
                                            let compressed_bytes =
                                                encoded_point.compress().to_bytes().to_vec();

                                            if let Some(btc_handler) = handler
                                                .as_any_mut()
                                                .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>()
                                            {
                                                btc_handler.set_group_public_key(compressed_bytes);
                                                info!("🔑 [LOCAL] Set network DKG group public key in Bitcoin chain handler");
                                            }
                                        }
                                    }
                                }
                                crate::types::TransactionType::VaultToNetwork => {
                                    // For vault-to-network, use vault's group key
                                    if let Some(dkg_node) = &self.dkg_node {
                                        if let Some(vault_group_key) =
                                            dkg_node.get_vault_group_key().await
                                        {
                                            let affine_point = vault_group_key.to_affine();
                                            let encoded_point =
                                                k256::EncodedPoint::from(affine_point);
                                            let compressed_bytes =
                                                encoded_point.compress().to_bytes().to_vec();

                                            if let Some(btc_handler) = handler
                                                .as_any_mut()
                                                .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>()
                                            {
                                                btc_handler.set_group_public_key(compressed_bytes);
                                                info!("🔑 [LOCAL] Set vault group public key in Bitcoin chain handler");
                                            }
                                        }
                                    }
                                }
                                crate::types::TransactionType::RewardTxn => {
                                    // RewardTxn is not valid for intent flow
                                }
                                crate::types::TransactionType::WithdrawLiquidity => {
                                    warn!(
                                        "❌ [LOCAL] WithdrawLiquidity is not supported for Bitcoin group key selection"
                                    );
                                }
                                crate::types::TransactionType::AddLiquidity => {
                                    warn!(
                                        "❌ [LOCAL] AddLiquidity is not supported for Bitcoin group key selection"
                                    );
                                }
                            }

                            Some(Arc::from(handler)
                                as Arc<dyn crate::chain_abstraction::ChainHandler>)
                        } else {
                            warn!(
                                "❌ [LOCAL] Unsupported chain: {}, using default Ethereum handler",
                                chain_to_use
                            );
                            None
                        };

                    let Some(chain_handler) = chain_handler else {
                        return Ok(());
                    };
                    // Get derived addresses based on transaction type
                    let (derived_eth_addr, derived_btc_addr) = match transaction_type {
                        crate::types::TransactionType::UserToVault => {
                            // For user deposits, use user's derived addresses
                            if let Some(eth_addr) = &user_eth_address {
                                if let Some(user_intent_manager) = &self.user_intent_manager {
                                    if let Some(user) =
                                        user_intent_manager.get_user_by_address(eth_addr).await
                                    {
                                        (
                                            user.derived_eth_address.clone(),
                                            user.derived_btc_address.clone(),
                                        )
                                    } else {
                                        warn!("❌ [LOCAL] User {} not found in registry", eth_addr);
                                        (None, None)
                                    }
                                } else {
                                    warn!("❌ [LOCAL] User registry not available");
                                    (None, None)
                                }
                            } else {
                                warn!(
                                    "❌ [LOCAL] UserToVault transaction requires user_eth_address"
                                );
                                (None, None)
                            }
                        }
                        crate::types::TransactionType::NetworkToTarget
                        | crate::types::TransactionType::VaultToNetwork
                        | crate::types::TransactionType::Refund => {
                            // For network withdrawals, vault-to-network, and refunds, no derived addresses needed
                            (None, None)
                        }
                        crate::types::TransactionType::RewardTxn => {
                            // RewardTxn is not valid for intent flow
                            (None, None)
                        }
                        crate::types::TransactionType::WithdrawLiquidity => {
                            warn!(
                                "❌ [LOCAL] WithdrawLiquidity transaction type not supported for derived addresses"
                            );
                            (None, None)
                        }
                        crate::types::TransactionType::AddLiquidity => {
                            warn!(
                                "❌ [LOCAL] AddLiquidity is not supported for derived address lookup"
                            );
                            (None, None)
                        }
                    };

                    let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_public_key().await
                    } else {
                        None
                    };

                    // Get vault addresses from database
                    let (vault_eth_addr, vault_btc_addr) =
                        if let Some(registry) = &self.user_intent_manager {
                            let database = registry.get_database();
                            let vault_eth = database
                                .get_string(crate::database::keys::DKG_VAULT_ETH_ADDRESS)
                                .ok()
                                .flatten();
                            let vault_btc = database
                                .get_string(crate::database::keys::DKG_VAULT_BTC_ADDRESS)
                                .ok()
                                .flatten();
                            (vault_eth, vault_btc)
                        } else {
                            return Err(anyhow::anyhow!("User registry not available"));
                        };

                    let chain_transaction_result =
                        crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                            &intent,
                            group_public_key,
                            derived_eth_addr.as_ref(),
                            derived_btc_addr.as_ref(),
                            transaction_type.clone(),
                            vault_eth_addr.as_ref(),
                            vault_btc_addr.as_ref(),
                            amount,
                        )
                        .await;

                    match chain_transaction_result {
                        Ok(chain_transaction) => {
                            info!(
                                "📝 [LOCAL] Created {} transaction from deposit intent",
                                chain_handler.chain_type()
                            );

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> =
                                self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if let Some(_key) = signing_key {
                                info!("🔐 [LOCAL] Got signing key for deposit intent");
                            } else {
                                info!("❌ [LOCAL] Could not get signing key for deposit intent");
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = chain_handler
                                .create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!(
                                "🔐 [LOCAL] Starting {} signing process for deposit intent: 0x{}",
                                chain_handler.chain_type(),
                                hex::encode(tx_bytes.clone())
                            );

                            // Handle Bitcoin and EVM differently - DummyTransaction is only for EVM!
                            match chain_transaction {
                                crate::chain_abstraction::ChainTransaction::Bitcoin(ref btc_tx) => {
                                    // For Bitcoin, use direct signing with tx_bytes and original transaction
                                    {
                                        let mut btc_signer = BitcoinSigner::new(signing_node);
                                        btc_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                &chain_handler,
                                                Some(btc_tx.clone()),
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                signing_key,
                                                None,
                                                signing_key,
                                            )
                                            .await?;
                                    }
                                }
                                crate::chain_abstraction::ChainTransaction::Ethereum(
                                    ref eth_tx,
                                ) => {
                                    let tx_bytes =
                                        crate::utils::transaction::create_transaction_for_signing(
                                            eth_tx,
                                        );
                                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                                    // Use the signing_key that was already fetched earlier to avoid redundant fetching
                                    let user_tweaked_share = signing_key;

                                    // For NetworkToTarget, queue to sequencer for coordinated signing
                                    if matches!(
                                        transaction_type,
                                        crate::types::TransactionType::NetworkToTarget
                                    ) {
                                        info!(
                                            "📝 [LOCAL] NetworkToTarget (EVM) detected - queuing via network transaction sequencer (intent_hash={})",
                                            intent_hash
                                        );
                                        match self.submit_network_to_target_to_sequencer(
                                            &intent,
                                            &intent_hash,
                                            amount,
                                            tx_bytes.clone(),
                                            eth_tx.clone(),
                                            user_tweaked_share,
                                            user_eth_address.clone(),
                                        )
                                        .await
                                        {
                                            Ok(()) => {
                                                return Ok(());
                                            }
                                            Err(e) => {
                                                let error_message = format!(
                                                    "Failed to submit NetworkToTarget transaction to sequencer: {}",
                                                    e
                                                );
                                                error!("❌ [LOCAL] {}", error_message);
                                                
                                                // Store transaction error and trigger refund
                                                if let Some(user_intent_manager) = &self.user_intent_manager {
                                                    // Store the error
                                                    if let Err(store_err) = user_intent_manager
                                                        .store_transaction_error(&intent_hash, &error_message, None)
                                                        .await
                                                    {
                                                        warn!(
                                                            "❌ [LOCAL] Failed to store transaction error for intent {}: {}",
                                                            intent_hash, store_err
                                                        );
                                                    } else {
                                                        info!(
                                                            "💥 [LOCAL] Stored transaction error for intent {}: {}",
                                                            intent_hash, error_message
                                                        );
                                                    }
                                                    
                                                    // Broadcast the error
                                                    if let Some(signing_node) = &self.signing_node {
                                                        signing_node.broadcast_transaction_error(
                                                            Some(&intent_hash),
                                                            &error_message,
                                                            "network_to_target",
                                                            None,
                                                        )
                                                        .await;
                                                    }
                                                    
                                                    // Trigger refund for NetworkToTarget transactions
                                                    info!(
                                                        "💸 [LOCAL] Network-to-target transaction failed, initiating refund for intent: {}",
                                                        intent_hash
                                                    );
                                                    
                                                    // Get the intent for refund calculation
                                                    if let Some(intent) = user_intent_manager.get_intent(&intent_hash).await {
                                                        let refund_amount = self.calculate_refund_amount(
                                                            user_intent_manager,
                                                            &intent_hash,
                                                            &intent,
                                                        )
                                                        .await;
                                                        
                                                        // Broadcast refund initiation directly through message channel
                                                        let refund_msg = serde_json::json!({
                                                            "type": "refund_initiation",
                                                            "intent_hash": intent_hash,
                                                            "source_address": intent.source_address,
                                                            "source_chain": intent.source_chain,
                                                            "original_amount": intent.amount.to_string(),
                                                            "refund_amount": refund_amount.to_string(),
                                                            "timestamp": std::time::SystemTime::now()
                                                                .duration_since(std::time::UNIX_EPOCH)
                                                                .unwrap()
                                                                .as_millis()
                                                        });
                                                        
                                                        let msg_bytes = match serde_json::to_vec(&refund_msg) {
                                                            Ok(bytes) => bytes,
                                                            Err(serialize_err) => {
                                                                error!(
                                                                    "❌ [LOCAL] Failed to serialize refund initiation message: {}",
                                                                    serialize_err
                                                                );
                                                                return Ok(());
                                                            }
                                                        };
                                                        
                                                        let channel_msg = ChannelMessage::RefundInitiation {
                                                            intent_hash: intent_hash.clone(),
                                                            data: msg_bytes,
                                                        };
                                                        
                                                        if let Err(send_err) = self.message_tx.send(channel_msg).await {
                                                            error!(
                                                                "❌ [LOCAL] Failed to send refund initiation message: {}",
                                                                send_err
                                                            );
                                                        } else {
                                                            info!(
                                                                "✅ [LOCAL] Successfully sent refund initiation for intent: {}",
                                                                intent_hash
                                                            );
                                                        }
                                                    } else {
                                                        warn!(
                                                            "❌ [LOCAL] Could not retrieve intent {} for refund initiation",
                                                            intent_hash
                                                        );
                                                    }
                                                } else {
                                                    warn!("❌ [LOCAL] User intent manager not available to handle transaction error");
                                                }
                                                
                                                return Ok(());
                                            }
                                        }
                                    }

                                    {
                                        let mut eth_signer = EthereumSigner::new(signing_node);
                                        eth_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                &chain_handler,
                                                eth_tx,
                                                user_tweaked_share,
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                None,
                                                signing_key,
                                            )
                                            .await?;
                                    }
                                    // // Only execute contract transaction for UserToVault transaction type
                                    // if matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                                    //     info!("📝 [LOCAL] UserToVault transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [LOCAL] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);

                                    //             match contract_transaction {
                                    //                 crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::types::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [LOCAL] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [LOCAL] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // } else if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget){
                                    //     info!("📝 [GOSSIPSUB] networkToTarget transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);

                                    //             match contract_transaction {
                                    //                 crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::types::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // }
                                }
                            }
                        }
                        Err(e) => {
                            let error_message = format!("Failed to create chain transaction from deposit intent: {}", e);
                            error!("❌ [LOCAL] {}", error_message);
                            
                            // Store transaction error and trigger refund for NetworkToTarget transactions
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                // Store the error
                                if let Err(store_err) = user_intent_manager
                                    .store_transaction_error(&intent_hash, &error_message, None)
                                    .await
                                {
                                    warn!(
                                        "❌ [LOCAL] Failed to store transaction error for intent {}: {}",
                                        intent_hash, store_err
                                    );
                                } else {
                                    info!(
                                        "💥 [LOCAL] Stored transaction error for intent {}: {}",
                                        intent_hash, error_message
                                    );
                                }
                                
                                // Broadcast the error
                                if let Some(signing_node) = &self.signing_node {
                                    let transaction_type_str = match transaction_type {
                                        crate::types::TransactionType::UserToVault => "user_to_vault",
                                        crate::types::TransactionType::NetworkToTarget => "network_to_target",
                                        crate::types::TransactionType::VaultToNetwork => "vault_to_network",
                                        crate::types::TransactionType::Refund => "refund",
                                        crate::types::TransactionType::RewardTxn => "reward_txn",
                                        crate::types::TransactionType::WithdrawLiquidity => "withdraw_liquidity",
                                        crate::types::TransactionType::AddLiquidity => "add_liquidity",
                                    };
                                    
                                    signing_node.broadcast_transaction_error(
                                        Some(&intent_hash),
                                        &error_message,
                                        transaction_type_str,
                                        None,
                                    )
                                    .await;
                                }
                                
                                // Trigger refund for NetworkToTarget transactions
                                if matches!(
                                    transaction_type,
                                    crate::types::TransactionType::NetworkToTarget
                                ) {
                                    info!(
                                        "💸 [LOCAL] Network-to-target transaction failed, initiating refund for intent: {}",
                                        intent_hash
                                    );
                                    
                                    // Get the intent for refund calculation
                                    if let Some(intent) = user_intent_manager.get_intent(&intent_hash).await {
                                        let refund_amount = self.calculate_refund_amount(
                                            user_intent_manager,
                                            &intent_hash,
                                            &intent,
                                        )
                                        .await;
                                        
                                        // Broadcast refund initiation directly through message channel
                                        let refund_msg = serde_json::json!({
                                            "type": "refund_initiation",
                                            "intent_hash": intent_hash,
                                            "source_address": intent.source_address,
                                            "source_chain": intent.source_chain,
                                            "original_amount": intent.amount.to_string(),
                                            "refund_amount": refund_amount.to_string(),
                                            "timestamp": std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_millis()
                                        });
                                        
                                        let msg_bytes = match serde_json::to_vec(&refund_msg) {
                                            Ok(bytes) => bytes,
                                            Err(e) => {
                                                error!(
                                                    "❌ [LOCAL] Failed to serialize refund initiation message: {}",
                                                    e
                                                );
                                                return Ok(());
                                            }
                                        };
                                        
                                        let channel_msg = ChannelMessage::RefundInitiation {
                                            intent_hash: intent_hash.clone(),
                                            data: msg_bytes,
                                        };
                                        
                                        if let Err(e) = self.message_tx.send(channel_msg).await {
                                            error!(
                                                "❌ [LOCAL] Failed to send refund initiation message: {}",
                                                e
                                            );
                                        } else {
                                            info!(
                                                "✅ [LOCAL] Successfully sent refund initiation for intent: {}",
                                                intent_hash
                                            );
                                        }
                                    } else {
                                        warn!(
                                            "❌ [LOCAL] Could not retrieve intent {} for refund initiation",
                                            intent_hash
                                        );
                                    }
                                }
                            } else {
                                warn!("❌ [LOCAL] User intent manager not available to handle transaction error");
                            }
                        }
                    }
                } else {
                    warn!("❌ [LOCAL] Signing node not available for deposit intent");
                }
            }
            ChannelMessage::TransactionFailure {
                sequencer_request_id,
                blockchain_tx_hash,
                error,
                original_request,
            } => {
                info!(
                    "📝 [NETWORK] Processing transaction failure locally: request_id={}, error={}",
                    sequencer_request_id, error
                );

                // Check if error message indicates transaction is already in mempool
                // If so, skip failure handling - transaction will succeed later
                if error.contains("tx already in mempool") {
                    info!(
                        "✅ [TX_FAILURE] Transaction {} is already in mempool (error: {}). Will succeed later. Skipping failure handling.",
                        sequencer_request_id, error
                    );
                    // Don't re-insert or broadcast failure - transaction is pending and will succeed
                    return Ok(());
                }

                // Process locally first - re-insert to sequencer
                if let Some(sequencer) = &self.contract_sequencer {
                    if let Some(request) = original_request.clone() {
                        // Check if already in queue to avoid duplicates
                        let already_in_queue = {
                            let pending = sequencer.pending_requests.read().await;
                            pending.contains_key(&sequencer_request_id)
                        };

                        if !already_in_queue {
                            // Use submit to properly add the request (handles sequence, notifies waiters, etc.)
                            match sequencer.submit(request).await {
                                Ok(()) => {
                                    info!(
                                        "✅ [TX_FAILURE] [LOCAL] Re-inserted failed transaction locally: {}",
                                        sequencer_request_id
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        "❌ [TX_FAILURE] [LOCAL] Failed to re-insert transaction {} locally: {}",
                                        sequencer_request_id, e
                                    );
                                }
                            }
                        } else {
                            info!(
                                "ℹ️ [TX_FAILURE] [LOCAL] Transaction {} already in queue, skipping re-insert",
                                sequencer_request_id
                            );
                        }
                    } else {
                        // Fallback to reinsert (for backwards compatibility)
                        match sequencer.reinsert(&sequencer_request_id).await {
                            Ok(()) => {
                                info!(
                                    "✅ [TX_FAILURE] [LOCAL] Re-inserted via cache: {}",
                                    sequencer_request_id
                                );
                            }
                            Err(e) => {
                                error!(
                                    "❌ [TX_FAILURE] [LOCAL] Failed to re-insert transaction {} via cache: {}",
                                    sequencer_request_id, e
                                );
                            }
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [TX_FAILURE] [LOCAL] Cannot retry transaction {} - sequencer not available",
                        sequencer_request_id
                    );
                }

                // Then broadcast to other nodes via gossipsub
                let failure_msg = GossipsubMessage::TransactionFailure {
                    sequencer_request_id: sequencer_request_id.clone(),
                    blockchain_tx_hash: blockchain_tx_hash.clone(),
                    error: error.clone(),
                    original_request,
                };
                let msg_bytes = serde_json::to_vec(&failure_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize transaction failure: {}", e))?;
                
                let topic = gossipsub::IdentTopic::new("transaction-failure");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted transaction failure to P2P network");
            }

            ChannelMessage::TransactionIdBroadcast {
                intent_hash,
                transaction_id,
                transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction ID broadcast from node {}",
                    node_id
                );
                info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);
                if let Some(hash) = &intent_hash {
                    info!("🔗 [NETWORK] Intent hash: {}", hash);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hash or solver address supplied with transaction ID broadcast");
                }

                // Gossip the transaction ID broadcast to other peers immediately so everyone can contribute their share in parallel
                let gossip_message = GossipsubMessage::TransactionIdBroadcast {
                    intent_hash: intent_hash.clone(),
                    transaction_id: transaction_id.clone(),
                    transaction_type: transaction_type.clone(),
                    solver_address: solver_address.clone(),
                    node_id: node_id.clone(),
                };

                let msg_bytes = match serde_json::to_vec(&gossip_message) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("❌ [NETWORK] Failed to serialize transaction ID broadcast for gossiping: {}", e);
                        return Ok(());
                    }
                };

                let topic_str = "transaction-id-sync";
                let topic = gossipsub::IdentTopic::new(topic_str);

                // CRITICAL FIX: Register TransactionIdBroadcast for retry tracking
                // This ensures all nodes receive transaction IDs even if initial broadcast fails
                if let Some(retry_mgr) = &self.retry_manager {
                    if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_message) {
                        if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_message) {
                            // Check if already being tracked (this is a retry, skip registration)
                            if !retry_mgr.is_message_tracked(&message_id).await {
                                // Get expected nodes (all active nodes except ourselves)
                                let expected_nodes: std::collections::HashSet<PeerId> = self
                                    .node_manager
                                    .get_active_nodes()
                                    .into_iter()
                                    .filter(|&pid| pid != self.local_peer_id)
                                    .collect();

                                if !expected_nodes.is_empty() {
                                    let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
                                    info!(
                                        "📋 [RETRY] Registering TransactionIdBroadcast {:?} - expecting ACKs from {} nodes: {:?}",
                                        message_id, expected_nodes.len(), expected_list
                                    );
                                    
                                    // Register with retry manager (first time only)
                                    if let Err(e) = retry_mgr.register_message(
                                        message_id.clone(),
                                        topic_str.to_string(),
                                        msg_bytes.clone(),
                                        expected_nodes.clone(),
                                    ).await {
                                        error!("❌ [RETRY] Failed to register TransactionIdBroadcast for retry: {}", e);
                                    } else {
                                        info!("✅ [RETRY] Successfully registered TransactionIdBroadcast {:?} for retry tracking", message_id);
                                    }
                                } else {
                                    warn!("⚠️ [RETRY] No expected nodes - skipping retry registration for TransactionIdBroadcast {:?}", message_id);
                                }
                            } else {
                                info!("🔄 [RETRY] TransactionIdBroadcast {:?} already tracked, skipping registration (this is a retry)", message_id);
                            }
                        }
                    }
                }

                if let Err(e) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), msg_bytes)
                {
                    error!(
                        "❌ [NETWORK] Failed to gossip transaction ID broadcast to other peers: {}",
                        e
                    );
                } else {
                    match (intent_hash.as_ref(), solver_address.as_ref()) {
                        (Some(hash), _) => {
                            info!("📡 [NETWORK] Gossiped transaction ID {} for intent {} (type: {}) to other peers", transaction_id, hash, transaction_type);
                        }
                        (None, Some(solver)) => {
                            info!("📡 [NETWORK] Gossiped reward transaction ID {} for solver {} (type: {}) to other peers", transaction_id, solver, transaction_type);
                        }
                        _ => {
                            info!(
                                "📡 [NETWORK] Gossiped transaction ID {} (type: {}) to other peers",
                                transaction_id, transaction_type
                            );
                        }
                    }
                }

                // Now process locally using shared handler
                match (intent_hash.as_ref(), solver_address.as_ref()) {
                    (Some(intent_hash), _) => {
                        // Parse node_id to get PeerId for security check
                        let sender_peer_id = node_id
                            .parse::<libp2p::PeerId>()
                            .unwrap_or_else(|_| libp2p::PeerId::random());

                        if let Err(e) = self
                            .handle_transaction_id_storage(
                                intent_hash,
                                &transaction_id,
                                &transaction_type,
                                &node_id,
                                &sender_peer_id,
                            )
                            .await
                        {
                            error!(
                                "❌ [NETWORK] Failed to handle transaction ID storage: {}",
                                e
                            );
                        }
                    }
                    (None, Some(solver_addr)) => {
                        // Handle reward or withdraw liquidity transaction IDs
                        let storage_result = match transaction_type.as_str() {
                            "reward_txn" => {
                                self.handle_reward_transaction_id_storage(
                                    solver_addr,
                                    &transaction_id,
                                    &transaction_type,
                                )
                                .await
                            }
                            "withdraw_liquidity" | "withdrawLiquidity" => {
                                self.handle_withdraw_liquidity_transaction_id_storage(
                                    solver_addr,
                                    &transaction_id,
                                    &transaction_type,
                                )
                                .await
                            }
                            _ => {
                                warn!(
                                    "❌ [NETWORK] Unknown transaction type: {}",
                                    transaction_type
                                );
                                return Err(anyhow!(
                                    "Unknown transaction type: {}",
                                    transaction_type
                                ));
                            }
                        };

                        if let Err(e) = storage_result {
                            error!(
                                "❌ [NETWORK] Failed to handle transaction ID storage: {}",
                                e
                            );
                        }
                    }
                    _ => {
                        warn!("⚠️ [NETWORK] Transaction ID broadcast missing both intent hash and solver address");
                    }
                }
            }
            ChannelMessage::IntentHashBroadcast {
                intent_hash,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Broadcasting intent hash {} from node {}",
                    intent_hash, node_id
                );
                let broadcast_msg = GossipsubMessage::IntentHashBroadcast {
                    intent_hash: intent_hash.clone(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&broadcast_msg).map_err(|e| {
                    anyhow::anyhow!("Failed to serialize intent hash broadcast: {}", e)
                })?;
                let topic = gossipsub::IdentTopic::new("intent-hashes");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted intent hash to P2P network");
            }
            ChannelMessage::UserRegistration {
                ethereum_address,
                node_id,
            } => {
                info!(
                    "👤 [NETWORK] Broadcasting user registration: {} from node {}",
                    ethereum_address, node_id
                );

                // Directly update commitments locally using the stored HMAC constant
                if let (Some(user_intent_manager), Some(dkg_node)) =
                    (&self.user_intent_manager, &self.dkg_node)
                {
                    if let Some(reg) = user_intent_manager
                        .get_user_by_address(&ethereum_address)
                        .await
                    {
                        if let Some(tweak_scalar) =
                            k256::Scalar::from_repr_vartime(reg.hmac_constant.into())
                        {
                            // Derive and store user-specific group key from updated commitments
                            match dkg_node
                                .derive_user_specific_group_key_from_commitments(tweak_scalar)
                                .await
                            {
                                Ok(group_key) => {
                                    if let Err(e) = user_intent_manager
                                        .set_user_group_key(&ethereum_address, group_key)
                                        .await
                                    {
                                        warn!("❌ [NETWORK] Failed to store user group key for {}: {}", ethereum_address, e);
                                    } else {
                                        info!("🔑 [NETWORK] Stored user-specific group key and derived addresses for {}", ethereum_address);
                                        // Log the derived addresses
                                        if let Some(user) = user_intent_manager
                                            .get_user_by_address(&ethereum_address)
                                            .await
                                        {
                                            if let Some(eth_addr) = &user.derived_eth_address {
                                                info!(
                                                    "📬 [NETWORK] Derived ETH address for {}: {}",
                                                    ethereum_address, eth_addr
                                                );
                                            }
                                            if let Some(btc_addr) = &user.derived_btc_address {
                                                info!(
                                                    "📬 [NETWORK] Derived BTC address for {}: {}",
                                                    ethereum_address, btc_addr
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("❌ [NETWORK] Failed to derive user-specific group key for {}: {}", ethereum_address, e);
                                }
                            }
                        }
                    } else {
                        warn!(
                            "❌ [NETWORK] Invalid HMAC tweak scalar for {}",
                            ethereum_address
                        );
                    }
                } else {
                    warn!("❌ [NETWORK] Missing user_intent_manager or dkg_node; cannot update commitments locally for {}", ethereum_address);
                }

                // Create and broadcast user registration message via gossipsub (same pattern as deposit intent)
                let user_reg_msg = GossipsubMessage::UserRegistration {
                    ethereum_address: ethereum_address.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&user_reg_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("user-registrations");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted user registration to P2P network");
            }
            ChannelMessage::RefundInitiation { intent_hash, data } => {
                info!(
                    "💸 [NETWORK] Received refund initiation for intent: {}",
                    intent_hash
                );

                // Deserialize refund message to get details
                match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(refund_data) => {
                        info!("📋 [NETWORK] Refund details: {:?}", refund_data);

                        // Get the intent to create the refund transaction
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            if let Some(mut intent) =
                                user_intent_manager.get_intent(&intent_hash).await
                            {
                                // Calculate refund amount: prefer refund_amount from message, otherwise calculate it
                                let refund_amount = if let Some(refund_amount_str) = refund_data
                                    .get("refund_amount")
                                    .and_then(|v| v.as_str())
                                {
                                    // Use refund amount from message (already includes 5% extra if applicable)
                                    if let Ok(amount) = refund_amount_str.parse::<u128>() {
                                        info!(
                                            "💰 [NETWORK-REFUND] Using refund amount from message: {}",
                                            amount
                                        );
                                        amount
                                    } else {
                                        warn!(
                                            "⚠️ [NETWORK-REFUND] Failed to parse refund_amount from message, calculating..."
                                        );
                                        // Fall back to calculation
                                        self.calculate_refund_amount(user_intent_manager, &intent_hash, &intent).await
                                    }
                                } else {
                                    // No refund_amount in message, calculate it
                                    info!("💰 [NETWORK-REFUND] No refund_amount in message, calculating...");
                                    self.calculate_refund_amount(user_intent_manager, &intent_hash, &intent).await
                                };

                                info!("🔄 [NETWORK-REFUND] Creating refund transaction from network to user's source address");
                                info!(
                                    "💰 [NETWORK-REFUND] Refunding {} from network to source address: {} on {}",
                                    intent.amount, intent.source_address, intent.source_chain
                                );

                                // Modify the intent to create a refund transaction:
                                // - From: Network address (DKG group key)
                                // - To: User's source address
                                // - Chain: Source chain (where user originally sent from)
                                let original_target = intent.target_address.clone();
                                let original_target_chain = intent.target_chain.clone();

                                // Set target to user's source address on source chain for the refund
                                intent.target_address = intent.source_address.clone();
                                intent.target_chain = intent.source_chain.clone();

                                info!(
                                    "🔄 [NETWORK-REFUND] Refund routing: Network → {} ({})",
                                    intent.target_address, intent.target_chain
                                );
                                info!("🔄 [NETWORK-REFUND] Original failed transaction was to: {} ({})", 
                                      original_target, original_target_chain);

                                // Create a refund transaction from network to user's source address
                                // Use Refund type specifically for refund transactions
                                let refund_intent_id = format!("refund-{intent_hash}");
                                // Parse amount for refund ChannelMessage
                                let refund_amount = match refund_amount {
                                    amount if amount > 0 => amount,
                                    _ => {
                                        // Fallback to intent amount if refund_amount is 0
                                        match intent.amount.parse::<u128>() {
                                            Ok(v) => v,
                                            Err(e) => {
                                                warn!(
                                                    "❌ [NETWORK-REFUND] Invalid intent amount '{}' for refund {}: {}. Skipping refund.",
                                                    intent.amount, intent_hash, e
                                                );
                                                return Ok(());
                                            }
                                        }
                                    }
                                };

                                let refund_message = ChannelMessage::DepositIntent {
                                    intent: intent.clone(),
                                    intent_id: refund_intent_id,
                                    user_eth_address: None, // Use network's DKG key for refund
                                    transaction_type: crate::types::TransactionType::Refund,
                                    amount: refund_amount,
                                };

                                // Send the refund message through the channel to be processed
                                if let Err(e) = self.message_tx.send(refund_message).await {
                                    error!("❌ [NETWORK-REFUND] Failed to send refund transaction message: {}", e);
                                } else {
                                    info!("✅ [NETWORK-REFUND] Successfully initiated refund transaction for intent: {}", intent_hash);
                                }
                            } else {
                                warn!("❌ [NETWORK-REFUND] Intent not found: {}", intent_hash);
                            }
                        } else {
                            warn!("❌ [NETWORK-REFUND] User registry not available");
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [NETWORK-REFUND] Failed to deserialize refund data: {}",
                            e
                        );
                    }
                }
            }
            ChannelMessage::ScheduledDKGStart => {
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();

                if let Some(dkg) = &mut self.dkg_node {
                    // This should only be called for initial DKG with 3 nodes
                    let initial_dkg_complete = dkg.is_initial_dkg_complete().await;

                    if initial_dkg_complete {
                        warn!("⚠️ [DKG] ScheduledDKGStart called but initial DKG already complete. This should not happen.");
                        return Ok(());
                    }

                    // Start the initial DKG with 3 nodes
                    info!("🚀 [DKG] Starting initial DKG with {} nodes", total);

                    if total != 3 {
                        warn!(
                            "⚠️ [DKG] Expected 4 nodes for initial DKG, but have {}",
                            total
                        );
                    }

                    if let Err(e) = dkg.update_node_params(total, threshold) {
                        warn!("❌ [DKG] Invalid params for scheduled start: {}", e);
                        return Ok(());
                    }
                    if let Err(e) = dkg.reset().await {
                        warn!("❌ [DKG] Failed to reset before scheduled start: {}", e);
                        return Ok(());
                    }
                    if let Some(signing_node) = &mut self.signing_node {
                        // Align signing threshold with the node manager's configured threshold
                        signing_node.set_threshold(threshold);
                    }
                    info!(
                        "🔄 DKG parameters updated: total_nodes={}, threshold={}",
                        total, threshold
                    );
                    if let Err(e) = dkg.start_dkg(self.node_manager.clone()).await {
                        warn!("❌ Scheduled DKG start failed: {:?}", e);
                    }
                } else {
                    warn!("❌ DKG node not initialized at scheduled start!");
                }
            }
            ChannelMessage::ClaimReward {
                solver_address,
                btc_address,
                eth_address,
                reward_btc,
                reward_tics,
                transaction_type,
            } => {
                info!("🎁 [NETWORK] Processing reward claim for solver: {}, ETH address: {:?}, BTC address: {:?}", 
                  solver_address, eth_address, btc_address);
                info!(
                    "💰 [NETWORK] Reward details - BTC: {:?}, TICS: {:?}",
                    reward_btc, reward_tics
                );

                // Validate transaction type for reward flow
                // Note: If TransactionType is added to ClaimReward message in the future,
                // use: Self::validate_transaction_type_for_reward(&transaction_type)?;
                let claim_reward_msg = GossipsubMessage::Rewards(
                    crate::types::messaging::RewardMessage::Claim {
                        solver_address: solver_address.clone(),
                        btc_address: btc_address.clone(),
                        eth_address: eth_address.clone(),
                        reward_btc: reward_btc.clone(),
                        reward_tics: reward_tics.clone(),
                        transaction_type: transaction_type.clone(),
                    }
                );
                let msg_bytes = serde_json::to_vec(&claim_reward_msg).map_err(|e| {
                    anyhow::anyhow!("Failed to serialize claim reward message: {}", e)
                })?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("claim-rewards");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!(
                    "📡 [NETWORK] Broadcasted claim reward to P2P network for solver: {}",
                    solver_address
                );

                let _ = self
                    .process_payout(
                        "claim_reward",
                        &solver_address,
                        &btc_address,
                        &eth_address,
                        &reward_btc,
                        &reward_tics,
                    )
                    .await?;
            }
            ChannelMessage::AddLiquidity {
                solver_address,
                solver_id,
                amount_btc,
                amount_tics,
                request_id,
            } => {
                let add_msg = GossipsubMessage::Liquidity(
                    crate::types::messaging::LiquidityMessage::Add {
                        solver_address: solver_address.clone(),
                        solver_id: solver_id.clone(),
                        amount_btc: amount_btc.clone(),
                        amount_tics: amount_tics.clone(),
                        request_id: request_id.clone(),
                    }
                );
                let msg_bytes = serde_json::to_vec(&add_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize add-liquidity msg: {}", e))?;
                let topic = gossipsub::IdentTopic::new("add-liquidity");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!(
                    "📡 [NETWORK] Broadcasted add liquidity request for solver {}",
                    solver_address
                );
                // 1) Dispatch contract calls from this local node (if applicable)
                self.handle_add_liquidity_contract_calls(
                    &solver_address,
                    &solver_id,
                    &amount_btc,
                    &amount_tics,
                    &request_id,
                )
                .await?;

                // 2) Apply the liquidity delta locally based on the requested amount (avoid waiting
                //    for on-chain confirmation to keep DB in sync).
                if let Some(signing_node) = &self.signing_node {
                    let delta_btc = amount_btc.as_ref().and_then(|v| U256::from_dec_str(v).ok());
                    let delta_tics = amount_tics
                        .as_ref()
                        .and_then(|v| U256::from_dec_str(v).ok());
                    match signing_node
                        .apply_liquidity_delta(
                            &solver_address,
                            Some(&solver_id),
                            delta_btc,
                            delta_tics,
                            true,
                        )
                        .await
                    {
                        Ok(()) => {
                            info!(
                                "✅ [NETWORK] Applied local liquidity add for {}",
                                solver_address
                            );
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ [NETWORK] Failed to apply local liquidity add for {}: {}",
                                solver_address, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [NETWORK] Signing node unavailable; cannot apply local liquidity add for {}",
                        solver_address
                    );
                }
            }
            ChannelMessage::WithdrawLiquidity {
                solver_address,
                btc_address,
                eth_address,
                amount_btc,
                amount_tics,
                transaction_type,
            } => {
                let withdraw_msg = GossipsubMessage::Liquidity(
                    crate::types::messaging::LiquidityMessage::Withdraw {
                        solver_address: solver_address.clone(),
                        btc_address: btc_address.clone(),
                        eth_address: eth_address.clone(),
                        amount_btc: amount_btc.clone(),
                        amount_tics: amount_tics.clone(),
                        transaction_type: transaction_type.clone(),
                    }
                );
                let msg_bytes = serde_json::to_vec(&withdraw_msg)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let topic = gossipsub::IdentTopic::new("withdraw-liquidity");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!(
                    "📡 [NETWORK] Broadcasted withdraw liquidity request for solver {}",
                    solver_address
                );

                let (tics_payout_initiated, btc_payout_initiated) = self
                    .process_payout(
                        "withdraw_liquidity",
                        &solver_address,
                        &btc_address,
                        &eth_address,
                        &amount_btc,
                        &amount_tics,
                    )
                    .await?;

                // Apply the liquidity decrease locally only when the payout was actually initiated
                // to avoid reducing liquidity for transactions that never reach storage (e.g., BTC dust).
                if let Some(signing_node) = &self.signing_node {
                    let delta_btc = if btc_payout_initiated {
                        amount_btc.as_ref().and_then(|v| U256::from_dec_str(v).ok())
                    } else {
                        None
                    };
                    let delta_tics = if tics_payout_initiated {
                        amount_tics
                            .as_ref()
                            .and_then(|v| U256::from_dec_str(v).ok())
                    } else {
                        None
                    };

                    if delta_btc.is_some() || delta_tics.is_some() {
                        match signing_node
                            .apply_liquidity_delta(
                                &solver_address,
                                None,
                                delta_btc,
                                delta_tics,
                                false,
                            )
                            .await
                        {
                            Ok(()) => {
                                info!(
                                    "✅ [NETWORK] Applied local liquidity withdraw for {}",
                                    solver_address
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "⚠️ [NETWORK] Failed to apply local liquidity withdraw for {}: {}",
                                    solver_address, e
                                );
                            }
                        }
                    } else {
                        info!(
                            "⏭️ [NETWORK] Skipping local liquidity withdraw for {} because payout was not initiated",
                            solver_address
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [NETWORK] Signing node unavailable; cannot apply local liquidity withdraw for {}",
                        solver_address
                    );
                }
            }
        }
        Ok(())
    }

    /// Calculate refund amount: if UserToVault transaction exists, include 5% extra
    async fn calculate_refund_amount(
        &self,
        user_intent_manager: &crate::user_intent_manager::UserIntentManager,
        intent_hash: &str,
        intent: &crate::types::intent::DepositIntent,
    ) -> u128 {
        // Parse intent amount from string
        let intent_amount = intent.amount.parse::<u128>().unwrap_or(0);
        
        if let Some(tx_ids) = user_intent_manager
            .get_intent_transaction_ids(intent_hash)
            .await
        {
            if tx_ids.user_to_network_tx_id.is_some() {
                // UserToVault transaction exists, refund original amount + 5% extra
                let full_amount = intent_amount + (intent_amount / 20);
                info!(
                    "💰 [NETWORK-REFUND] UserToVault transaction found, refunding full amount: {} (original: {} + 5% extra: {})",
                    full_amount, intent_amount, intent_amount / 20
                );
                full_amount
            } else {
                // No UserToVault transaction, refund original amount
                info!(
                    "💰 [NETWORK-REFUND] No UserToVault transaction found, refunding original amount: {}",
                    intent_amount
                );
                intent_amount
            }
        } else {
            // Couldn't check transaction IDs, refund original amount
            warn!(
                "⚠️ [NETWORK-REFUND] Could not check transaction IDs, refunding original amount: {}",
                intent_amount
            );
            intent_amount
        }
    }
}
