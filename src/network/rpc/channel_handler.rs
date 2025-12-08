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
    ) -> Result<()> {
        let tx_type = Self::get_transaction_type_from_context(context);

        info!(
            "💧 [{}] Processing TICS payout: {} -> {} (amount: {})",
            context, solver_address, eth_address, amount
        );

        let dkg_node = match &self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [{}] DKG node not available for TICS payout", context);
                return Ok(());
            }
        };

        let group_key = match dkg_node.get_final_public_key().await {
            Some(key) => key,
            None => {
                warn!("❌ [{}] No group key available for TICS payout", context);
                return Ok(());
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
                return Ok(());
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
                return Ok(());
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
                return Ok(());
            }
        };

        signing_node.set_private_key_from_scalar(secret_share);
        if let Some(group_key) = dkg_node.get_final_public_key().await {
            signing_node.set_group_public_key(group_key);
        }

        let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&eth_tx);
        info!(
            "🔐 [{}] Starting TICS payout signing: 0x{}",
            context,
            hex::encode(tx_bytes.clone())
        );

        let mut eth_signer = EthereumSigner::new(signing_node);
        eth_signer
            .sign_transaction(
                tx_bytes,
                &eth_tx,
                None,
                None,
                None,
                Some(tx_type),
                Some(solver_address.to_string()),
            )
            .await?;

        info!("✅ [{}] TICS payout signing completed", context);
        if context == "withdraw_liquidity" {
            self.record_pending_liquidity_contract_update(
                solver_address,
                TransactionNetwork::TICS,
                amount,
            )
            .await;
        }
        Ok(())
    }

    async fn process_btc_payout(
        &mut self,
        context: &str,
        solver_address: &str,
        btc_address: &str,
        amount: u128,
    ) -> Result<()> {
        let tx_type = Self::get_transaction_type_from_context(context);

        info!(
            "💧 [{}] Processing BTC payout: {} -> {} (amount: {})",
            context, solver_address, btc_address, amount
        );

        let dkg_node = match &self.dkg_node {
            Some(node) => node,
            None => {
                warn!("❌ [{}] DKG node not available for BTC payout", context);
                return Ok(());
            }
        };

        let group_key = match dkg_node.get_final_public_key().await {
            Some(key) => key,
            None => {
                warn!("❌ [{}] No group key available for BTC payout", context);
                return Ok(());
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
                return Ok(());
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
                return Ok(());
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
                return Ok(());
            }
        };

        signing_node.set_private_key_from_scalar(secret_share);
        if let Some(group_key) = dkg_node.get_final_public_key().await {
            signing_node.set_group_public_key(group_key);
        }

        let chain_tx = crate::chain_abstraction::ChainTransaction::Bitcoin(btc_tx.clone());
        let tx_bytes = signing_node
            .get_chain_handler()
            .create_transaction_bytes(&chain_tx)
            .unwrap();

        info!(
            "🔐 [{}] Starting BTC payout signing: 0x{}",
            context,
            hex::encode(tx_bytes.clone())
        );

        let mut btc_signer = BitcoinSigner::new(signing_node);
        btc_signer
            .sign_transaction(
                tx_bytes,
                Some(btc_tx),
                None,
                None,
                Some(tx_type),
                None,
                Some(solver_address.to_string()),
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
        Ok(())
    }

    pub(crate) async fn process_payout(
        &mut self,
        context: &str,
        solver_address: &str,
        btc_address: &Option<String>,
        eth_address: &Option<String>,
        amount_btc: &Option<String>,
        amount_tics: &Option<String>,
    ) -> Result<()> {
        if amount_btc.is_none() && amount_tics.is_none() {
            warn!(
                "❌ [{}] No BTC or TICS amount specified for solver {}",
                context, solver_address
            );
            return Ok(());
        }

        if let Some(amount_str) = amount_tics {
            if let Some(eth_addr) = eth_address {
                match amount_str.parse::<u128>() {
                    Ok(tics_amount) => {
                        self.process_eth_payout(context, solver_address, eth_addr, tics_amount)
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
                        self.process_btc_payout(context, solver_address, btc_addr, btc_amount)
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
        Ok(())
    }

    pub(crate) async fn submit_solver_reward_contract_update(
        &mut self,
        solver_address: &str,
        reward_btc: Option<u128>,
        reward_tics: Option<u128>,
        transaction_hash: &str,
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
            transaction_hash,
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

            if let Some(ref secret_share) = vault_tweaked_share {
                signing_node.set_private_key_from_scalar(*secret_share);
                signing_node.set_group_public_key(group_public_key);
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
                // info!("🔧 [CONTRACT] Contract transaction data as ref length: {:?}", contract_tx.data.as_ref().len());
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

                let mut eth_signer = EthereumSigner::new(signing_node);
                eth_signer
                    .sign_contract_message(
                        contract_tx_bytes,
                        &contract_tx,
                        vault_tweaked_share,
                        None,
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
        transaction_hash: &str,
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
            transaction_hash,
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

            if let Some(ref secret_share) = vault_tweaked_share {
                signing_node.set_private_key_from_scalar(*secret_share);
                signing_node.set_group_public_key(group_public_key);
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
                let mut eth_signer = EthereumSigner::new(signing_node);
                eth_signer
                    .sign_contract_message(tx_bytes, &contract_tx, vault_tweaked_share, None)
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

            if let Some(ref secret_share) = vault_tweaked_share {
                signing_node.set_private_key_from_scalar(*secret_share);
                signing_node.set_group_public_key(group_public_key);
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
                let mut eth_signer = EthereumSigner::new(signing_node);
                eth_signer
                    .sign_contract_message(tx_bytes, &contract_tx, vault_tweaked_share, None)
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
    ) -> Result<()> {
        let mut dispatched = false;

        if let Some(amount_str) = amount_tics.as_ref() {
            if let Some(amount) = Self::parse_liquidity_amount_value(amount_str, "TICS") {
                info!(
                    "💧 [ADD-LIQ] Dispatching contract update for solver {} on qubetics (amount: {})",
                    solver_address, amount_str
                );
                self.submit_solver_add_liquidity_contract_update(
                    solver_address,
                    solver_id,
                    "qubetics",
                    amount,
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
                self.submit_solver_add_liquidity_contract_update(
                    solver_address,
                    solver_id,
                    "btc",
                    amount,
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
    types::{intent::TransactionNetwork, rpc::RPCRequest, ChannelMessage, GossipsubMessage},
};

use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer};

impl MpcNetworkLayer {
    // ChannelMessage is related to the MPSC channel only
    pub(crate) async fn handle_channel_message(
        &mut self,
        message: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        info!("[handle_channel_message()] {:?}", message);
        match message {
            ChannelMessage::PeerDiscoveryRetry { attempt } => {
                info!(
                    "Received peer discovery retry notification (attempt {})",
                    attempt
                );
                if !self.peer_discovery.pending_peer_discovery_retry {
                    info!(
                        "Received stale peer discovery retry notification (attempt {}), ignoring",
                        attempt
                    );
                    return Ok(());
                }

                self.peer_discovery.pending_peer_discovery_retry = false;

                if self.has_additional_peers() {
                    info!(
                        "✅ Additional peers detected (attempt {}); broadcasting local presence",
                        attempt
                    );
                    self.broadcast_local_presence().await?;
                } else if attempt >= Self::MAX_PEER_DISCOVERY_RETRIES {
                    warn!(
                        "⚠️ Peer discovery retry attempt {} reached limit {}; not broadcasting yet",
                        attempt,
                        Self::MAX_PEER_DISCOVERY_RETRIES
                    );
                } else {
                    info!(
                        "⏳ Peer discovery retry attempt {} found no additional peers; rescheduling",
                        attempt
                    );
                    self.schedule_peer_discovery_retry(attempt + 1);
                }
            }
            // this is used in the dkg code
            ChannelMessage::Broadcast { topic, data } => {
                // dkg.s.1
                info!("📢 [BROADCAST] Attempting to broadcast to topic: {}", topic);
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());
                info!("🏷️ [BROADCAST] Topic hash: {:?}", topic_hash.hash());

                // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                // if peer(s) have already subscribed to this topic, they will recieve this
                // msg (check subscribe_to_default_topics())
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();
                info!(
                    "📊 [BROADCAST] Available peers for topic {}: {}",
                    topic, peer_count
                );

                if peer_count > 0 {
                    info!("👥 [BROADCAST] Connected peers:");
                    for (peer_id, _peer_info) in swarm_mut.gossipsub.all_peers() {
                        info!("   - Peer: {:?}", peer_id);
                    }

                    match swarm_mut.gossipsub.publish(topic_hash, data) {
                        Ok(_) => {
                            info!(
                                "✅ [BROADCAST] Successfully published message to topic: {}",
                                topic
                            );
                        }
                        Err(e) => {
                            warn!(
                                "❌ [BROADCAST] Failed to publish message to topic {}: {:?}",
                                topic, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [BROADCAST] No peers available for broadcasting to topic: {}",
                        topic
                    );
                }
            }
            // this is not used anywhere yet
            ChannelMessage::Unicast { peer_id, data } => {
                // Implement direct message sending using request-response protocol
                let peer_id = PeerId::from_bytes(&hex::decode(peer_id)?)
                    .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
                let request = RPCRequest::Custom {
                    id: "custom".to_string(),
                    data,
                };
                // this will send the channel msg as
                // NetworkEvent::RequestResponse under ReqRespMessage::Request type
                // to just single peer
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);
            }
            // SECURE DKG SHARE DISTRIBUTION - sends share to specific peer via P2P RPC
            ChannelMessage::SendDKGShareRPC {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;
                
                info!(
                    "🔐 [DKG-SECURE] Sending share index {} via UNICAST to peer {} (attempt {})",
                    share_index, target_peer_id, retry_count + 1
                );
                
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
                
                // Check if we're connected to the peer
                let is_connected = swarm.is_connected(&peer_id);
                
                if !is_connected && retry_count < MAX_RETRIES {
                    // Not connected - schedule retry with exponential backoff
                    let delay_ms = 1000 * (1 << retry_count.min(5)); // 1s, 2s, 4s, 8s, 16s, 32s max
                    info!(
                        "🔄 [DKG-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                        target_peer_id, retry_count + 1, delay_ms
                    );
                    
                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::SendDKGShareRPC {
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
                                share_index, e
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
                    .send_request(&peer_id, request);
                
                info!(
                    "✅ [DKG-SECURE] Share index {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    share_index, target_peer_id, request_id, is_connected
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

                // Calculate intent hash for transaction ID storage
                let intent_hash = crate::utils::calculate_intent_hash(&intent)
                    .map_err(|e| anyhow::anyhow!("Failed to calculate intent hash: {}", e))?;
                info!("🔐 [LOCAL] Calculated intent hash: {}", intent_hash);

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

                // Process locally first (this node will sign it)
                if let Some(signing_node) = &mut self.signing_node {
                    // Set appropriate chain handler based on the determined chain
                    if crate::utils::transaction::is_evm_chain(chain_to_use) {
                        if let Some(chain_id) =
                            crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                        {
                            let chain_handler =
                                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                                    chain_id,
                                );
                            signing_node.set_chain_handler(chain_handler.into());
                            info!(
                                "🔗 [LOCAL] Set Ethereum chain handler for chain: {} (ID: {})",
                                chain_to_use, chain_id
                            );
                        }
                    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                        let mut chain_handler =
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
                                    if let Some(user_intent_manager) = &self.user_intent_manager {
                                        if let Some(user) =
                                            user_intent_manager.get_user_by_address(eth_addr).await
                                        {
                                            if let Some(user_group_key) = &user.user_group_key {
                                                let affine_point = user_group_key.0; // user_group_key is SerializablePoint(AffinePoint)
                                                let encoded_point =
                                                    k256::EncodedPoint::from(affine_point);
                                                let compressed_bytes =
                                                    encoded_point.compress().to_bytes().to_vec();

                                                if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                                    btc_handler.set_group_public_key(compressed_bytes);
                                                    info!("🔑 [LOCAL] Set user-specific group public key in Bitcoin chain handler for user: {}", eth_addr);
                                                }
                                            } else {
                                                warn!("❌ [LOCAL] User {} has no group key for Bitcoin transaction", eth_addr);
                                            }
                                        } else {
                                            warn!("❌ [LOCAL] User {} not found for Bitcoin transaction", eth_addr);
                                        }
                                    } else {
                                        warn!("❌ [LOCAL] User registry not available for Bitcoin transaction");
                                    }
                                } else {
                                    warn!("❌ [LOCAL] UserToVault transaction requires user_eth_address");
                                }
                            }
                            crate::types::TransactionType::NetworkToTarget => {
                                // For network withdrawals, use network's DKG group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                                        let affine_point = group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler
                                            .as_any_mut()
                                            .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                                        ) {
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
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler
                                            .as_any_mut()
                                            .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                                        ) {
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

                        signing_node.set_chain_handler(chain_handler.into());
                        info!("🔗 [LOCAL] Set Bitcoin chain handler");
                    } else {
                        warn!(
                            "❌ [LOCAL] Unsupported chain: {}, using default Ethereum handler",
                            chain_to_use
                        );
                    }

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
                        | crate::types::TransactionType::VaultToNetwork => {
                            // For network withdrawals and vault-to-network, no derived addresses needed
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
                                signing_node.get_chain_type()
                            );

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> =
                                self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if let Some(key) = signing_key {
                                info!("🔐 [LOCAL] Got signing key for deposit intent");
                                signing_node.set_private_key_from_scalar(key);

                                // Set the appropriate group public key based on transaction type
                                match transaction_type {
                                    crate::types::TransactionType::UserToVault => {
                                        // For user deposits, use user-specific group key
                                        if let Some(eth_address) = &user_eth_address {
                                            if let Some(user_intent_manager) =
                                                &self.user_intent_manager
                                            {
                                                if let Some(user) = user_intent_manager
                                                    .get_user_by_address(eth_address)
                                                    .await
                                                {
                                                    if let Some(user_group_key) =
                                                        &user.user_group_key
                                                    {
                                                        signing_node.set_group_public_key(
                                                            user_group_key.0.into(),
                                                        ); // Convert AffinePoint to ProjectivePoint
                                                        info!("🔑 [LOCAL] Set user-specific group public key for: {}", eth_address);
                                                    } else {
                                                        warn!("❌ [LOCAL] User {} has no group key available", eth_address);
                                                        return Ok(());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::NetworkToTarget => {
                                        // For network withdrawals, use the original DKG group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(group_key) =
                                                dkg_node.get_final_public_key().await
                                            {
                                                signing_node.set_group_public_key(group_key);
                                                info!(
                                                    "🔑 [LOCAL] Set network DKG group public key"
                                                );
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::VaultToNetwork => {
                                        // For vault-to-network, use the vault group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(vault_group_key) =
                                                dkg_node.get_vault_group_key().await
                                            {
                                                signing_node.set_vault_group_key(vault_group_key);
                                                info!("🔑 [LOCAL] Set vault group public key");
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::RewardTxn => {
                                        // RewardTxn is not valid for intent flow
                                    }
                                    crate::types::TransactionType::WithdrawLiquidity => {
                                        warn!(
                                            "❌ [LOCAL] WithdrawLiquidity transaction type not supported for group public key assignment"
                                        );
                                    }
                                    crate::types::TransactionType::AddLiquidity => {
                                        warn!(
                                            "❌ [LOCAL] AddLiquidity transaction type not supported for group public key assignment"
                                        );
                                    }
                                }
                            } else {
                                info!("❌ [LOCAL] Could not get signing key for deposit intent");
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = signing_node
                                .get_chain_handler()
                                .create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!(
                                "🔐 [LOCAL] Starting {} signing process for deposit intent: 0x{}",
                                signing_node.get_chain_type(),
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
                                                Some(btc_tx.clone()),
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                signing_key,
                                                None,
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

                                    // Get signing key based on transaction type
                                    let user_tweaked_share = match transaction_type {
                                        crate::types::TransactionType::UserToVault => {
                                            // For user deposits, use user's tweaked secret share
                                            if let Some(eth_addr) = &user_eth_address {
                                                if let Some(user_intent_manager) =
                                                    &self.user_intent_manager
                                                {
                                                    if let Some(user) = user_intent_manager
                                                        .get_user_by_address(eth_addr)
                                                        .await
                                                    {
                                                        user.tweaked_secret_share.map(|s| s.0)
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
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
                                        crate::types::TransactionType::RewardTxn => {
                                            // RewardTxn is not valid for intent flow
                                            None
                                        }
                                        crate::types::TransactionType::WithdrawLiquidity => {
                                            warn!(
                                                "❌ [LOCAL] WithdrawLiquidity transaction type not supported for deposit signing"
                                            );
                                            None
                                        }
                                        crate::types::TransactionType::AddLiquidity => {
                                            warn!(
                                                "❌ [LOCAL] AddLiquidity transaction type not supported for deposit signing"
                                            );
                                            None
                                        }
                                    };
                                    {
                                        let mut eth_signer = EthereumSigner::new(signing_node);
                                        eth_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                eth_tx,
                                                user_tweaked_share,
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                None,
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
                            warn!("❌ [LOCAL] Failed to create chain transaction from deposit intent: {}", e);
                        }
                    }
                } else {
                    warn!("❌ [LOCAL] Signing node not available for deposit intent");
                }
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

                let topic = gossipsub::IdentTopic::new("transaction-id-sync");
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
                        if let Err(e) = self
                            .handle_transaction_id_storage(
                                intent_hash,
                                &transaction_id,
                                &transaction_type,
                                &node_id,
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
                        if transaction_type == "reward_txn" {
                            if let Err(e) = self
                                .handle_reward_transaction_id_storage(
                                    solver_addr,
                                    &transaction_id,
                                    &transaction_type,
                                )
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to handle reward transaction ID storage: {}",
                                    e
                                );
                            }
                        } else if transaction_type == "withdraw_liquidity"
                            || transaction_type == "withdrawLiquidity"
                        {
                            if let Err(e) = self
                                .handle_withdraw_liquidity_transaction_id_storage(
                                    solver_addr,
                                    &transaction_id,
                                    &transaction_type,
                                )
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to handle withdraw liquidity transaction ID storage: {}",
                                    e
                                );
                            }
                        } else {
                            warn!(
                                "⚠️ [NETWORK] Unknown transaction type '{}' for solver-based transaction",
                                transaction_type
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
                                info!("🔄 [NETWORK-REFUND] Creating refund transaction from network to user's source address");
                                info!("💰 [NETWORK-REFUND] Refunding {} from network to source address: {} on {}", 
                                      intent.amount, intent.source_address, intent.source_chain);

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
                                // Use NetworkToTarget type since we're sending from network address to a target
                                let refund_intent_id = format!("refund-{intent_hash}");
                                let refund_message = ChannelMessage::DepositIntent {
                                    intent: intent.clone(),
                                    intent_id: refund_intent_id,
                                    user_eth_address: None, // Use network's DKG key for refund
                                    transaction_type:
                                        crate::types::TransactionType::NetworkToTarget,
                                    amount: intent.amount,
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
                    // This should only be called for initial DKG with 4 nodes
                    let initial_dkg_complete = dkg.is_initial_dkg_complete().await;

                    if initial_dkg_complete {
                        warn!("⚠️ [DKG] ScheduledDKGStart called but initial DKG already complete. This should not happen.");
                        return Ok(());
                    }

                    // Start the initial DKG with 4 nodes
                    info!("🚀 [DKG] Starting initial DKG with {} nodes", total);

                    if total != 4 {
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
                // For now, reward flow only processes RewardTxn type transactions

                // Broadcast the reward claim to other nodes via gossipsub immediately
                let claim_reward_msg = GossipsubMessage::ClaimReward {
                    solver_address: solver_address.clone(),
                    btc_address: btc_address.clone(),
                    eth_address: eth_address.clone(),
                    reward_btc: reward_btc.clone(),
                    reward_tics: reward_tics.clone(),
                    transaction_type: transaction_type.clone(),
                };
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

                self.process_payout(
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
            } => {
                info!(
                    "💧 [NETWORK] Processing add liquidity for solver {} (solver_id: {})",
                    solver_address, solver_id
                );

                let add_msg = GossipsubMessage::AddLiquidity {
                    solver_address: solver_address.clone(),
                    solver_id: solver_id.clone(),
                    amount_btc: amount_btc.clone(),
                    amount_tics: amount_tics.clone(),
                };
                let msg_bytes = serde_json::to_vec(&add_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize add-liquidity msg: {}", e))?;
                let topic = gossipsub::IdentTopic::new("add-liquidity");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!(
                    "📡 [NETWORK] Broadcasted add liquidity request for solver {}",
                    solver_address
                );
                self.handle_add_liquidity_contract_calls(
                    &solver_address,
                    &solver_id,
                    &amount_btc,
                    &amount_tics,
                )
                .await?;
            }
            ChannelMessage::WithdrawLiquidity {
                solver_address,
                btc_address,
                eth_address,
                amount_btc,
                amount_tics,
                transaction_type,
            } => {
                info!(
                    "💧 [NETWORK] Processing withdraw liquidity for solver {}",
                    solver_address
                );

                let withdraw_msg = GossipsubMessage::WithdrawLiquidity {
                    solver_address: solver_address.clone(),
                    btc_address: btc_address.clone(),
                    eth_address: eth_address.clone(),
                    amount_btc: amount_btc.clone(),
                    amount_tics: amount_tics.clone(),
                    transaction_type: transaction_type.clone(),
                };
                let msg_bytes = serde_json::to_vec(&withdraw_msg)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let topic = gossipsub::IdentTopic::new("withdraw-liquidity");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!(
                    "📡 [NETWORK] Broadcasted withdraw liquidity request for solver {}",
                    solver_address
                );

                self.process_payout(
                    "withdraw_liquidity",
                    &solver_address,
                    &btc_address,
                    &eth_address,
                    &amount_btc,
                    &amount_tics,
                )
                .await?;
            }
        }
        Ok(())
    }
}
