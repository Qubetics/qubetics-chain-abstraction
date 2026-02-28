pub mod peer_lifecycle;
pub mod intent_processing;
pub mod chain_events;
pub mod p2p_messaging;

use crate::network::transport::types::{MpcNetworkLayer, MpcNetworkBehaviour};
use crate::types::ChannelMessage;
use anyhow::{Result, anyhow};
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use ethers::prelude::Address;
use ethers::types::U256;
use libp2p::PeerId;
use crate::contract::*;
use crate::types::rpc::RPCRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingAddLiquidityRecord {
    pub(crate) request_id: String,
    pub(crate) solver_id: String,
    pub(crate) solver_address: String,
    pub(crate) amount: String,
    pub(crate) chain_id: u64,
    pub(crate) signature: String,
    pub(crate) signed_payload: String,
    pub(crate) timestamp_ms: i64,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) tx_id: Option<String>,
}

pub(crate) const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";

impl MpcNetworkLayer {
    pub(crate) async fn handle_channel_message(
        &mut self,
        message: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match message {
            ChannelMessage::PeerDiscoveryRetry { .. } => {
                self.handle_ch_peerdiscoveryretry(message, swarm).await?
            }
            ChannelMessage::StatusRequest { .. } => {
                self.handle_ch_statusrequest(message, swarm).await?
            }
            ChannelMessage::NodeMultiaddrRequest { .. } => {
                self.handle_ch_nodemultiaddrrequest(message, swarm).await?
            }
            ChannelMessage::PeerConnectionCheck { .. } => {
                self.handle_ch_peerconnectioncheck(message, swarm).await?
            }
            ChannelMessage::PeerInvalidationBatch { .. } => {
                self.handle_ch_peerinvalidationbatch(message, swarm).await?
            }
            ChannelMessage::PeerInvalidationDeleted { .. } => {
                self.handle_ch_peerinvalidationdeleted(message, swarm).await?
            }
            ChannelMessage::IntentBatchBroadcast { .. } => {
                self.handle_ch_intentbatchbroadcast(message, swarm).await?
            }
            ChannelMessage::TicsUserToVaultIntentBatch { .. } => {
                self.handle_ch_ticsusertovaultintentbatch(message, swarm).await?
            }
            ChannelMessage::BtcUserToVaultIntentBatch { .. } => {
                self.handle_ch_btcusertovaultintentbatch(message, swarm).await?
            }
            ChannelMessage::DepositIntent { .. } => {
                self.handle_ch_depositintent(message, swarm).await?
            }
            ChannelMessage::UserRegistration { .. } => {
                self.handle_ch_userregistration(message, swarm).await?
            }
            ChannelMessage::AdminRegistration { .. } => {
                self.handle_ch_adminregistration(message, swarm).await?
            }
            ChannelMessage::BtcIntentManagerTxUpdate { .. } => {
                self.handle_ch_btcintentmanagertxupdate(message, swarm).await?
            }
            ChannelMessage::BtcWithdrawBatch { .. } => {
                self.handle_ch_btcwithdrawbatch(message, swarm).await?
            }
            ChannelMessage::BtcClaimRewardBatch { .. } => {
                self.handle_ch_btcclaimrewardbatch(message, swarm).await?
            }
            ChannelMessage::BtcClaimPlatformFeeBatch { .. } => {
                self.handle_ch_btcclaimplatformfeebatch(message, swarm).await?
            }
            ChannelMessage::ClaimPlatformFeeTxIdBroadcast { .. } => {
                self.handle_ch_claimplatformfeetxidbroadcast(message, swarm).await?
            }
            ChannelMessage::TicsClaimPlatformFeeBatch { .. } => {
                self.handle_ch_ticsclaimplatformfeebatch(message, swarm).await?
            }
            ChannelMessage::TicsWithdrawBatch { .. } => {
                self.handle_ch_ticswithdrawbatch(message, swarm).await?
            }
            ChannelMessage::TicsClaimRewardBatch { .. } => {
                self.handle_ch_ticsclaimrewardbatch(message, swarm).await?
            }
            ChannelMessage::ClaimRewardTxIdBroadcast { .. } => {
                self.handle_ch_claimrewardtxidbroadcast(message, swarm).await?
            }
            ChannelMessage::WithdrawTxIdBroadcast { .. } => {
                self.handle_ch_withdrawtxidbroadcast(message, swarm).await?
            }
            ChannelMessage::PendingWithdrawRequestBroadcast { .. } => {
                self.handle_ch_pendingwithdrawrequestbroadcast(message, swarm).await?
            }
            ChannelMessage::PendingClaimPlatformFeeRequestBroadcast { .. } => {
                self.handle_ch_pendingclaimplatformfeerequestbroadcast(message, swarm).await?
            }
            ChannelMessage::PendingClaimRewardRequestBroadcast { .. } => {
                self.handle_ch_pendingclaimrewardrequestbroadcast(message, swarm).await?
            }
            ChannelMessage::SolverAddLiquidityBatch { .. } => {
                self.handle_ch_solveraddliquiditybatch(message, swarm).await?
            }
            ChannelMessage::SolverAddLiquidity { .. } => {
                self.handle_ch_solveraddliquidity(message, swarm).await?
            }
            ChannelMessage::Broadcast { .. } => {
                self.handle_ch_broadcast(message, swarm).await?
            }
            ChannelMessage::UnicastShareDKG { .. } => {
                self.handle_ch_unicastsharedkg(message, swarm).await?
            }
            ChannelMessage::UnicastCritical { .. } => {
                self.handle_ch_unicastcritical(message, swarm).await?
            }
            ChannelMessage::UnicastECDSASignature { .. } => {
                self.handle_ch_unicastecdsasignature(message, swarm).await?
            }
            ChannelMessage::UnicastBtcSignatures { .. } => {
                self.handle_ch_unicastbtcsignatures(message, swarm).await?
            }
            ChannelMessage::UnicastTransactionData { .. } => {
                self.handle_ch_unicasttransactiondata(message, swarm).await?
            }
            ChannelMessage::TransactionFailure { .. } => {
                self.handle_ch_transactionfailure(message, swarm).await?
            }
            ChannelMessage::TransactionIdBroadcast { .. } => {
                self.handle_ch_transactionidbroadcast(message, swarm).await?
            }
            ChannelMessage::FinalNodeIdBroadcast { .. } => {
                self.handle_ch_finalnodeidbroadcast(message, swarm).await?
            }
            ChannelMessage::ScheduledDKGStart { .. } => {
                self.handle_ch_scheduleddkgstart(message, swarm).await?
            }
        }
        Ok(())
    }

    pub(crate) async fn fetch_solver_id_for_address(&self, solver_address: &str) -> Result<String> {
        let rpc_url = crate::env_defaults::solver_contract_rpc_url();
        let contract_address_env = crate::env_defaults::solver_contract_address();
        let chain_id = crate::env_defaults::solver_contract_chain_id()
            .parse::<u64>()
            .unwrap_or_else(|_| crate::env_defaults::mpc_tics_chain_id());

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

    pub(crate) async fn handle_btc_intent_manager_update_batch(
        &mut self,
        intent_hashes: Vec<String>,
        btc_txid: String,
        _btc_batch_round: u64,
        update_round: u64,
        timestamp: String,
        _node_id: String,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        info!(
            "🔄 [BTC_INTENT_MANAGER] Processing contract update batch: {} intents, BTC txid: {}",
            intent_hashes.len(),
            btc_txid
        );

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Fetch intent details from database
        let mut batch_intents = Vec::new();
        let mut batch_intent_inputs = Vec::new();

        for intent_hash in &intent_hashes {
            if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                let tx_ids = user_intent_manager
                    .get_intent_transaction_ids(intent_hash)
                    .await;

                // Must have network_to_target_tx_id
                if let Some(ref tx_ids) = tx_ids {
                    if tx_ids.network_to_target_tx_id.is_none() {
                        warn!(
                            "⚠️ [BTC_INTENT_MANAGER] Intent {} missing network_to_target_tx_id, skipping",
                            intent_hash
                        );
                        continue;
                    }
                } else {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Intent {} has no transaction IDs, skipping",
                        intent_hash
                    );
                    continue;
                }

                batch_intents.push((intent_hash.clone(), intent.clone()));
            } else {
                warn!("⚠️ [BTC_INTENT_MANAGER] Intent {} not found in database", intent_hash);
            }
        }

        if batch_intents.is_empty() {
            warn!("⚠️ [BTC_INTENT_MANAGER] No valid intents found for contract update batch");
            return Ok(());
        }

        info!(
            "✅ [BTC_INTENT_MANAGER] Fetched {} intents for contract update batch",
            batch_intents.len()
        );

        // Prepare BatchIntentInput array for processBatchIntents contract call
        for (intent_hash, intent) in &batch_intents {
            let source_amount = match intent.amount.parse::<u128>() {
                Ok(amt) => amt,
                Err(e) => {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Invalid amount for intent {}: {}",
                        intent_hash, e
                    );
                    continue;
                }
            };
            // Use stored target_amount (pre-computed at intent submission).
            // For cross-chain intents source and target use different units
            // (e.g. wei vs sats), so falling back to source_amount is wrong.
            let target_amount = match user_intent_manager
                .get_intent_target_amount(intent_hash)
                .await
            {
                Some(amt) => amt,
                None => {
                    if intent.source_chain.eq_ignore_ascii_case(&intent.target_chain) {
                        source_amount
                    } else {
                        // Cross-chain: re-compute via price feed
                        warn!(
                            "⚠️ [BTC_INTENT_MANAGER] No stored target_amount for cross-chain intent {}; computing fallback",
                            intent_hash
                        );
                        match crate::rpc_server::utils::fetch_crypto_prices(Some(intent.timestamp)).await {
                            Ok(prices) => {
                                match crate::rpc_server::utils::convert_src_smallest_to_dst_smallest(
                                    source_amount,
                                    &intent.source_chain,
                                    &intent.target_chain,
                                    &prices,
                                ) {
                                    Ok(amt) => amt,
                                    Err(e) => {
                                        error!("❌ [BTC_INTENT_MANAGER] Fallback conversion failed for intent {}: {:?}", intent_hash, e);
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("❌ [BTC_INTENT_MANAGER] Failed to fetch prices for fallback on intent {}: {}", intent_hash, e);
                                continue;
                            }
                        }
                    }
                }
            };

            // Get transaction IDs
            let tx_ids = user_intent_manager
                .get_intent_transaction_ids(intent_hash)
                .await;

            // For BTC contract update:
            // - withdraw_tx_hash = user_to_network_tx_id (the UserToVault / user deposit tx)
            // - deposit_tx_hash = btc_txid (the BTC batch transaction ID, if available, otherwise use network_to_target_tx_id)
            let user_to_network_tx_id = tx_ids
                .as_ref()
                .and_then(|ids| ids.user_to_network_tx_id.clone())
                .unwrap_or_else(|| {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Intent {} missing user_to_network_tx_id",
                        intent_hash
                    );
                    "N/A".to_string()
                });

            let network_to_target_tx_id = tx_ids
                .as_ref()
                .and_then(|ids| ids.network_to_target_tx_id.clone())
                .unwrap_or_else(|| {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Intent {} missing network_to_target_tx_id",
                        intent_hash
                    );
                    "N/A".to_string()
                });

            // Use BTC batch txid if available and not "pending", otherwise use network_to_target_tx_id
            let deposit_tx_hash = if btc_txid != "pending" && !btc_txid.is_empty() {
                Some(btc_txid.clone())
            } else {
                Some(network_to_target_tx_id.clone())
            };

            // Create BatchIntentInput for this intent
            let batch_input = crate::types::BatchIntentInput {
                source_address: intent.source_address.clone(),
                target_address: intent.target_address.clone(),
                source_chain: intent.source_chain.clone(),
                target_chain: intent.target_chain.clone(),
                source_amount,
                target_amount,
                source_token: intent.source_token.clone(),
                target_token: intent.target_token.clone(),
                intent_id: intent_hash.clone(),
                withdraw_tx_hash: user_to_network_tx_id, // UserToVault / user-to-network tx ID
                deposit_tx_hash, // The BTC batch transaction ID (or network_to_target_tx_id if batch not finalized yet)
            };

            batch_intent_inputs.push(batch_input);
        }

        if batch_intent_inputs.is_empty() {
            warn!("⚠️ [BTC_INTENT_MANAGER] No valid BatchIntentInput entries after filtering");
            return Ok(());
        }

        info!(
            "📤 [BTC_INTENT_MANAGER] Prepared {} BatchIntentInput entries",
            batch_intent_inputs.len()
        );

        // Create processBatchIntents calldata with batchType = BTC (0)
        if let Some(calldata) = crate::utils::transaction::encode_process_batch_intents_calldata(
            &batch_intent_inputs,
            crate::types::BatchType::BTC, // batchType = 0 for BTC
            &timestamp,
        ) {
            info!(
                "✅ [BTC_INTENT_MANAGER] Created processBatchIntents calldata ({} bytes) for BTC batch",
                calldata.len()
            );

            // Create and submit an MPC-signed contract call transaction for processBatchIntents
            // Use MAIN DKG group key (not vault key) for processBatchIntents
            let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                dkg_node.get_final_public_key().await
            } else {
                None
            };

            let Some(group_public_key) = group_public_key else {
                warn!("❌ [BTC_INTENT_MANAGER] Main DKG group key not available; cannot create contract call");
                return Ok(());
            };

            // Contract address for IntentManager (processBatchIntents)
            let contract_address_env = crate::env_defaults::intent_manager_contract_address();
            if contract_address_env == "0x0000000000000000000000000000000000000000" {
                warn!("❌ [BTC_INTENT_MANAGER] INTENT_MANAGER_CONTRACT_ADDRESS not configured");
                return Ok(());
            }

            // Use the MAIN group-derived EVM address as sender
            let from_address =
                crate::utils::get_eth_address_from_group_key(group_public_key);
            let chain_id =
                crate::utils::transaction::get_chain_id_from_name("qubetics").unwrap_or_else(|| crate::env_defaults::mpc_tics_chain_id());

            // Estimate gas; abort if it would revert
            let calldata_hex = format!("0x{}", hex::encode(&calldata));
            let estimated_gas =
                crate::utils::transaction::estimate_gas_for_deposit_intent(
                    &from_address,
                    &contract_address_env,
                    &calldata_hex,
                    chain_id,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("BTC contract update batch gas estimation failed: {}", e)
                })?;
            let gas_limit = estimated_gas + (estimated_gas / 10);

            let nonce = crate::utils::transaction::fetch_tics_nonce(&from_address, chain_id)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to fetch nonce for {}: {}", from_address, e)
                })?;

            let gas_price =
                crate::utils::transaction::get_gas_price_for_chain("qubetics", chain_id)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(
                            "⚠️ [BTC_INTENT_MANAGER] Failed to get dynamic gas price: {}, using fallback",
                            e
                        );
                        crate::utils::transaction::get_default_gas_price_for_chain("qubetics")
                    });

            let contract_tx = crate::types::ContractTransaction {
                to: contract_address_env.clone(),
                value: "0x0".to_string(),
                nonce,
                gas_limit,
                gas_price,
                chain_id,
                data: calldata_hex,
            };

            // Start MPC signing
            if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                let available_nodes: Vec<PeerId> =
                    self.node_manager.get_active_nodes().into_iter().collect();
                signing_node.set_available_nodes(available_nodes);

                // Ensure MAIN group key is available on signing node
                signing_node.set_group_public_key(group_public_key);

                // Use MAIN final secret share for signing (network group key path)
                // Observer nodes will have None here — sign_contract_message() handles
                // the observer path internally (builds TX, skips ECDSA, stores for aggregation).
                let secret_share = if let Some(dkg_node) = &self.dkg_node {
                    dkg_node.get_final_secret_share().await
                } else {
                    None
                };

                let contract_tx_bytes =
                    crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                let contract_chain_handler =
                    signing_node.get_contract_chain_handler().clone();
                let mut eth_signer = crate::signing::TicsSigner::new(&mut signing_node);
                eth_signer
                    .sign_contract_message(
                        contract_tx_bytes,
                        &contract_chain_handler,
                        &contract_tx,
                        None,
                        None, // user_tics_address (not applicable)
                        intent_hashes.clone(),
                        // Use the main DKG share as an explicit signing key override.
                        secret_share,
                        None,
                        None,
                        None, // tics_withdraw_identifiers (not applicable)
                        None, // tics_claim_reward_identifiers (not applicable)
                        None, // tics_claim_platform_fee_identifiers (not applicable)
                        nonce_tuple_id.clone(), // Coordinated nonce from batch broadcast
                    )
                    .await?;

                info!(
                    "✅ [BTC_INTENT_MANAGER] Submitted processBatchIntents contract transaction into MPC signing flow ({} intents, batchType=BTC)",
                    intent_hashes.len()
                );
                info!(
                    "ℹ️  [BTC_INTENT_MANAGER] Signatures will be sent to final node for round {}",
                    update_round
                );
            } else {
                warn!(
                    "❌ [BTC_INTENT_MANAGER] Signing node not available; cannot start MPC signing for batch contract call"
                );
            }
        } else {
            warn!("❌ [BTC_INTENT_MANAGER] Failed to encode processBatchIntents calldata");
        }

        Ok(())
    }

    pub(crate) async fn handle_solver_add_liquidity_batch(
        &mut self,
        request_ids: Vec<String>,
        round: u64,
        _timestamp: String,
        node_id: String,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        info!(
            "💧 [ADD_LIQUIDITY_BATCH] Processing batch: {} requests, round {}, from node {}, nonce: {:?}",
            request_ids.len(),
            round,
            node_id,
            nonce_tuple_id
        );

        if request_ids.is_empty() {
            warn!("⚠️ [ADD_LIQUIDITY_BATCH] Empty batch received");
            return Ok(());
        }

        // Look up all records from RocksDB and extract data
        const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";
        
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct PendingAddLiquidityRecord {
            request_id: String,
            solver_id: String,
            solver_address: String,
            amount: String,
            chain_id: u64,
            signature: String,
            signed_payload: String,
            timestamp_ms: i64,
            status: String,
            #[serde(default)]
            tx_id: Option<String>,
        }

        let mut solver_ids: Vec<String> = Vec::new();
        let mut amounts: Vec<String> = Vec::new();
        let mut chain_ids: Vec<u64> = Vec::new();
        let mut chain_types: Vec<u8> = Vec::new();
        let mut tx_ids: Vec<String> = Vec::new();

        for request_id in &request_ids {
            let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, request_id);
            if let Ok(Some(record)) =
                self.db
                    .get_string_async::<PendingAddLiquidityRecord>(&key)
                    .await
            {
                // Extract data for transaction
                solver_ids.push(record.solver_id.clone());
                amounts.push(record.amount.clone());
                chain_ids.push(record.chain_id);
                
                // Map chain_id to ChainType enum:
                // 0 (BTC) -> ChainType::BTC (0)
                // TICS chain ID (EVM/Qubetics) -> ChainType::EVM (1)
                let tics_cid = crate::env_defaults::mpc_tics_chain_id();
                let chain_type = if record.chain_id == 0 {
                    0u8 // BTC
                } else if record.chain_id == tics_cid {
                    1u8 // EVM
                } else {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY_BATCH] Unsupported chain_id {} for request {}, defaulting to EVM",
                        record.chain_id, request_id
                    );
                    1u8 // Default to EVM
                };
                chain_types.push(chain_type);
                tx_ids.push(record.tx_id.clone().unwrap_or_default());

                // Keep status as "Pending" - it will be marked "Completed" on success
                info!("📦 [ADD_LIQUIDITY_BATCH] Processing request {} (status: {}, tx_id: {:?})", request_id, record.status, record.tx_id);
            } else {
                warn!("⚠️ [ADD_LIQUIDITY_BATCH] Request {} not found in RocksDB, skipping", request_id);
            }
        }

        // Verify we found all requests
        if solver_ids.len() != request_ids.len() {
            error!("❌ [ADD_LIQUIDITY_BATCH] Some requests not found in RocksDB");
            return Err(anyhow!("Some requests not found in RocksDB"));
        }

        // Safety check: ensure we have at least one request with chain_id
        if chain_ids.is_empty() {
            error!("❌ [ADD_LIQUIDITY_BATCH] No chain_ids found in batch");
            return Err(anyhow!("No chain_ids found in batch"));
        }

        // The addLiquidityBatch smart contract lives on Qubetics (TICS chain ID from MPC_TICS_CHAIN_ID env var).
        // chain_ids[] holds the *asset* chain (e.g. 0 for BTC), not the target chain.
        let chain_id: u64 = crate::env_defaults::mpc_tics_chain_id();
        info!("💧 [ADD_LIQUIDITY_BATCH] Contract chain_id: {}, first asset chain_id: {}, chain_type: {}", chain_id, chain_ids[0], chain_types[0]);

        // Parse amounts to U256
        let amounts_u256: Vec<U256> = amounts
            .iter()
            .filter_map(|a| U256::from_dec_str(a).ok())
            .collect();

        if amounts_u256.len() != amounts.len() {
            error!("❌ [ADD_LIQUIDITY_BATCH] Failed to parse some amounts");
            return Err(anyhow!("Failed to parse amounts"));
        }

        // Get solver contract address from ENV
        let solver_contract_address = crate::env_defaults::solver_contract_address();
        if solver_contract_address.is_empty() {
            error!("❌ [ADD_LIQUIDITY_BATCH] SOLVER_CONTRACT_ADDRESS not configured");
            return Err(anyhow!("SOLVER_CONTRACT_ADDRESS not configured"));
        }

        // Derive liquidity operator address from vault group key (same as rewards/remove_liquidity)
        let dkg_node = if let Some(node) = &self.dkg_node {
            node
        } else {
            warn!(
                "❌ [ADD_LIQUIDITY_BATCH] Cannot process batch - DKG node unavailable"
            );
            return Ok(());
        };

        let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
            key
        } else {
            warn!(
                "❌ [ADD_LIQUIDITY_BATCH] Liquidity operator group key unavailable; cannot derive liquidity operator address"
            );
            return Ok(());
        };

        let liquidity_operator_address =
            crate::utils::get_eth_address_from_group_key(group_public_key);

        info!(
            "💧 [ADD_LIQUIDITY_BATCH] Building addLiquidityBatch tx: from={}, to={}, {} deposits",
            liquidity_operator_address,
            solver_contract_address,
            solver_ids.len()
        );

        // Build the addLiquidityBatch transaction using helper from utils/transaction.rs
        let chain_tx = crate::utils::transaction::create_solver_add_liquidity_batch_transaction(
            &liquidity_operator_address,
            &solver_ids,
            &amounts_u256,
            &chain_types,
            &tx_ids,
            &solver_contract_address,
            chain_id,
        )
        .await?;

        // Expect a TICS transaction
        let eth_tx = match chain_tx {
            crate::chain_abstraction::ChainTransaction::Tics(tx) => tx,
            _ => {
                warn!(
                    "❌ [ADD_LIQUIDITY_BATCH] Batch transaction is not a TICS transaction"
                );
                return Ok(());
            }
        };

        info!(
            "✅ [ADD_LIQUIDITY_BATCH] Built batchTransfer TICS transaction: nonce={}, gas_limit={}",
            eth_tx.nonce, eth_tx.gas_limit
        );

        // Start MPC signing using vault (liquidity operator) DKG key
        if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
            let available_nodes: Vec<PeerId> =
                self.node_manager.get_active_nodes().into_iter().collect();
            signing_node.set_available_nodes(available_nodes);
            signing_node.set_chain_handler(
                crate::chain_abstraction::ChainHandlerFactory::create_tics_handler(
                    eth_tx.chain_id,
                )
                .into(),
            );

            let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

            // All nodes (DKG + observer) proceed through sign_contract_message().
            // sign_contract_message() internally checks has_dkg_share() and handles
            // the observer path (builds TX, skips signing, stores for aggregation).
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

            let contract_tx_bytes =
                crate::utils::transaction::create_transaction_for_signing_contract(
                    &contract_tx,
                );
            let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
            let mut eth_signer = crate::signing::TicsSigner::new(&mut signing_node);

            // Pass request_ids as intent_hashes for tracking through signing flow
            // When transaction succeeds/fails, these IDs will be used to update status
            eth_signer
                .sign_contract_message(
                    contract_tx_bytes,
                    &contract_chain_handler,
                    &contract_tx,
                    vault_tweaked_share.clone(),
                    None,     // user_tics_address (not applicable)
                    request_ids.clone(),   // Pass request_ids for tracking
                    vault_tweaked_share,
                    None,     // request_id
                    None,     // original_request
                    None,     // tics_withdraw_identifiers (not applicable)
                    None,     // tics_claim_reward_identifiers (not applicable)
                    None,     // tics_claim_platform_fee_identifiers (not applicable)
                    nonce_tuple_id.clone(), // Coordinated nonce from batch broadcast
                )
                .await?;

            info!(
                "✅ [ADD_LIQUIDITY_BATCH] Submitted addLiquidityBatch transaction into MPC signing flow ({} deposits)",
                request_ids.len()
            );
            info!(
                "ℹ️  [ADD_LIQUIDITY_BATCH] Request IDs tracked: {:?}",
                request_ids
            );
            info!(
                "ℹ️  [ADD_LIQUIDITY_BATCH] Signatures will be sent to final node for round {}",
                round
            );
        } else {
            warn!(
                "❌ [ADD_LIQUIDITY_BATCH] Signing node not available; cannot start MPC signing for batch"
            );
            // Don't mark as Failed - this is a temporary condition, can be retried
        }

        Ok(())
    }
}
