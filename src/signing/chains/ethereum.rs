use crate::signing::SigningNode;
use crate::{
    chain_abstraction::{ChainTransaction, EthereumTransaction},
    types::{
        intent::{ContractTransaction, DummyTransaction},
        signing::ECDSASignature,
        TransactionType,
    },
    utils::{get_eth_address_from_group_key, transaction::create_signed_transaction},
};
use anyhow::{anyhow, Result};
use hex;
use k256::Scalar;
use reqwest::Client;
use secp256k1::{ecdsa::RecoverableSignature, Message, SecretKey};
use sha3::Digest;
use std::collections::{HashMap, HashSet};
use tracing::{error, info, warn};

/// Convenience wrapper for Ethereum-focused signing flows.
pub struct EthereumSigner<'a> {
    node: &'a mut SigningNode,
}

impl<'a> EthereumSigner<'a> {
    pub fn new(node: &'a mut SigningNode) -> Self {
        Self { node }
    }

    pub fn node(&self) -> &SigningNode {
        self.node
    }

    pub fn node_mut(&mut self) -> &mut SigningNode {
        self.node
    }

    pub async fn sign_transaction(
        &mut self,
        message: Vec<u8>,
        transaction: &EthereumTransaction,
        user_tweaked_share: Option<Scalar>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<TransactionType>,
        solver_address: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_message(
                message,
                transaction,
                user_tweaked_share,
                user_eth_address,
                intent_hash,
                transaction_type,
                solver_address,
            )
            .await
    }

    pub async fn sign_contract_message(
        &mut self,
        message: Vec<u8>,
        contract_tx: &ContractTransaction,
        user_tweaked_share: Option<Scalar>,
        user_eth_address: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_contract_message(message, contract_tx, user_tweaked_share, user_eth_address)
            .await
    }
}

impl SigningNode {
    pub async fn fetch_ethereum_nonce(address: &str, chain_id: u64) -> Result<u64> {
        let rpc_url = match chain_id {
            9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
                .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
            1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
            _ => {
                return Err(anyhow!(
                    "Unsupported chain ID for nonce fetching: {}",
                    chain_id
                ))
            }
        };

        let client = Client::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "pending"],
            "id": 1
        });

        info!(
            "Fetching nonce for address {} on chain {} (pending)",
            address, chain_id
        );

        let response = client
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            if let Some(error) = result.get("error") {
                error!("❌ Failed to fetch nonce: {}", error);
                return Err(anyhow!("Nonce fetch failed: {}", error));
            }
            if let Some(nonce_hex) = result.get("result") {
                let nonce_str = nonce_hex.as_str().unwrap_or("0x0");
                let nonce =
                    u64::from_str_radix(nonce_str.strip_prefix("0x").unwrap_or(nonce_str), 16)?;
                info!("✅ Fetched nonce {} for address {}", nonce, address);
                Ok(nonce)
            } else {
                Err(anyhow!("No nonce result in response"))
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to fetch nonce: {}", error_text);
            Err(anyhow!("Nonce fetch failed: {}", error_text))
        }
    }

    pub(crate) async fn broadcast_ethereum_transaction(
        raw_tx_hex: &str,
        chain_id: u64,
    ) -> Result<Option<String>> {
        let rpc_url = match chain_id {
            9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
                .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
            1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
            _ => {
                return Err(anyhow!(
                    "Unsupported chain ID for broadcasting: {}",
                    chain_id
                ))
            }
        };

        let client = Client::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex],
            "id": 1
        });

        info!(
            "Broadcasting Ethereum transaction to chain {}: {}",
            chain_id, rpc_url
        );

        let response = client
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            if let Some(error) = result.get("error") {
                error!("❌ Failed to broadcast transaction: {}", error);
                return Err(anyhow!("Broadcast failed: {}", error));
            }
            if let Some(tx_hash) = result.get("result") {
                info!("✅ Qubetics transaction broadcasted successfully!");
                info!("TX Hash: {}", tx_hash);
                if let Some(tx_hash_str) = tx_hash.as_str() {
                    return Ok(Some(tx_hash_str.to_string()));
                }
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to broadcast transaction: {}", error_text);
            return Err(anyhow!("Broadcast failed: {}", error_text));
        }
        Ok(None)
    }
    pub async fn sign_message(
        &mut self,
        _message: Vec<u8>,
        transaction: &EthereumTransaction,
        user_tweaked_share: Option<Scalar>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<TransactionType>,
        solver_address: Option<String>,
    ) -> Result<()> {
        // Validate parameters: if transaction_type is RewardTxn, solver_address must be provided
        if let Some(TransactionType::RewardTxn) = transaction_type {
            if solver_address.is_none() {
                error!("❌ [SIGNING] Invalid parameters: solver_address is required when transaction_type is RewardTxn");
                return Err(anyhow!(
                    "Solver address is required when transaction_type is RewardTxn"
                ));
            }
        }

        // Determine which key to use for signing
        // Redacted user_tweaked_share from logs
        let signing_key = if let Some(tweaked_share) = user_tweaked_share {
            // Use user's tweaked share for user deposits
            info!("🔑 [SIGNING] Using user-specific tweaked share for signing");
            Self::derive_secp_secret(&tweaked_share)?
        } else {
            // Use network DKG share for network withdrawals
            info!("🔑 [SIGNING] Using network DKG share for signing");
            match self.key_store.clone_private_key() {
                Some(key) => key,
                None => {
                    error!(
                        "❌ [SIGNING] Node {} cannot sign: no private key available",
                        self.id
                    );
                    return Err(anyhow!("No private key available"));
                }
            }
        };

        // Log signing key for testing/debugging
        let signing_key_hex = hex::encode(signing_key.secret_bytes());
        info!(
            "🔐 [SIGNING-DEBUG] Node {} signing key (hex): 0x{}",
            self.id, signing_key_hex
        );

        // Calculate and log DKG index for this node
        let dkg_index = self.calculate_dkg_index_for_peer(&self.id).await;
        info!(
            "🔢 [SIGNING-DEBUG] Node {} DKG index: {}",
            self.id, dkg_index
        );

        info!("📝 [SIGNING] Node {} starting to sign transaction", self.id);

        // Convert DummyTransaction to ChainTransaction for chain-agnostic handling with UTXO error handling
        let chain_transaction =
            ChainTransaction::Ethereum(crate::chain_abstraction::EthereumTransaction {
                to: transaction.to.clone(),
                value: transaction.value.clone(),
                gas_limit: transaction.gas_limit,
                gas_price: transaction.gas_price.clone(),
                nonce: transaction.nonce,
                data: None,
                chain_id: transaction.chain_id,
            });

        // Create transaction bytes using chain handler
        let tx_bytes = self
            .chain_handler
            .create_transaction_bytes(&chain_transaction)?;

        // Hash the transaction bytes
        let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> =
            sha3::Keccak256::new();
        hasher.update(&tx_bytes);
        let tx_hash = hasher.finalize();
        info!("Tx hash: 0x{}", hex::encode(&tx_hash));

        // Get available nodes and perform VRF selection
        let available_nodes = self.coordination.get_available_nodes_from_manager().await;

        // Use VrfService for node selection (chain-agnostic)
        if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = vrf_service.get_current_round().await;
            let _selection_result = vrf_service
                .perform_node_selection(&available_nodes, 1, round, self.chain_handler.chain_type())
                .await?;

            info!(
                "🎯 [VRF] Node {} completed VRF selection for {} signing round {}",
                self.id,
                self.chain_handler.chain_type(),
                round
            );
        }

        // Create ECDSA signature using secp256k1
        let msg = Message::from_digest_slice(&tx_hash)?;
        let signature = self.create_ecdsa_signature_with_key(&msg, transaction, &signing_key)?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();

        info!(
            "✍️ [SIGNING] Node {} created {} signature",
            self.id,
            self.chain_handler.chain_type()
        );

        // Convert to legacy ECDSASignature for compatibility
        let ecdsa_signature = ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_eth_address: user_eth_address.clone(), // Clone to avoid borrow checker issues
        };

        // Get current round from VRF service
        let round = if let Some(vrf_service) = self.coordination.vrf_service() {
            vrf_service.get_next_round().await
        } else {
            0
        };

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(self.id.clone(), ecdsa_signature.clone());

            // Calculate and log this node's DKG index
            let my_dkg_index = self.calculate_dkg_index_for_peer(&self.id).await;

            info!(
                "💾 [SIGNING] Node {} stored signature for {} round {}",
                self.id,
                self.chain_handler.chain_type(),
                round
            );
            info!(
                "💾 [SIGNING-DEBUG] Stored signature details - r: 0x{}, s: 0x{}, recovery_id: {}",
                hex::encode(&signature_bytes[0..32]),
                hex::encode(&signature_bytes[32..64]),
                recovery_id.to_i32()
            );
            info!(
                "💾 [INDEX-PEER-DEBUG] Stored signature for Index {} => PeerId {} (s-share: 0x{})",
                my_dkg_index,
                self.id,
                hex::encode(&signature_bytes[32..64])
            );
        }

        // Store original transaction for reconstruction after aggregation
        // Use reward pending transactions if transaction_type is RewardTxn, otherwise use regular pending transactions
        if let Some(TransactionType::RewardTxn) = transaction_type {
            // This is a reward transaction - store in reward pending transactions
            // solver_address is guaranteed to be Some due to validation above
            let solver_addr = solver_address.expect("Solver address should be validated above");
            let chain_tx =
                ChainTransaction::Ethereum(crate::chain_abstraction::EthereumTransaction {
                    to: transaction.to.clone(),
                    value: transaction.value.clone(),
                    gas_limit: transaction.gas_limit,
                    gas_price: transaction.gas_price.clone(),
                    nonce: transaction.nonce,
                    data: None,
                    chain_id: transaction.chain_id,
                });

            // Store in TICS reward pending transactions (assuming TICS for now)
            // TODO: Determine network type based on transaction context
            self.store_reward_transaction_tics(
                round,
                chain_tx,
                tx_bytes.clone(),
                solver_addr.clone(),
            )
            .await;

            // Insert round number into reward_rounds for reward transactions
            {
                let mut reward_rounds: tokio::sync::RwLockWriteGuard<'_, HashSet<u64>> =
                    self.pending.reward_rounds.write().await;
                reward_rounds.insert(round);
                info!(
                    "🎁 [SIGNING] Node {} added round {} to reward_rounds",
                    self.id, round
                );
            }

            info!(
                "💾 [SIGNING] Node {} stored reward transaction for round {} with solver address: {}",
                self.id, round, solver_addr
            );
        } else if let Some(TransactionType::WithdrawLiquidity) = transaction_type {
            let solver_addr = solver_address.expect("Solver address should be validated above");
            let chain_tx =
                ChainTransaction::Ethereum(crate::chain_abstraction::EthereumTransaction {
                    to: transaction.to.clone(),
                    value: transaction.value.clone(),
                    gas_limit: transaction.gas_limit,
                    gas_price: transaction.gas_price.clone(),
                    nonce: transaction.nonce,
                    data: None,
                    chain_id: transaction.chain_id,
                });

            self.store_withdraw_transaction_tics(
                round,
                chain_tx,
                tx_bytes.clone(),
                solver_addr.clone(),
            )
            .await;

            {
                let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                withdraw_rounds.insert(round);
                info!(
                    "💧 [SIGNING] Node {} added round {} to withdraw_rounds",
                    self.id, round
                );
            }

            info!(
                "💾 [SIGNING] Node {} stored withdraw-liquidity transaction for round {} with solver address: {}",
                self.id, round, solver_addr
            );
        } else {
            // This is an intent-based transaction - store in regular pending transactions
            let mut pending_transactions = self.pending.pending_transactions.write().await;
            let chain_tx =
                ChainTransaction::Ethereum(crate::chain_abstraction::EthereumTransaction {
                    to: transaction.to.clone(),
                    value: transaction.value.clone(),
                    gas_limit: transaction.gas_limit,
                    gas_price: transaction.gas_price.clone(),
                    nonce: transaction.nonce,
                    data: None,
                    chain_id: transaction.chain_id,
                });
            pending_transactions.insert(
                round,
                (
                    chain_tx,
                    tx_bytes.clone(),
                    intent_hash.clone(),
                    transaction_type,
                ),
            );
            info!(
                "💾 [SIGNING] Node {} stored intent-based transaction for round {} reconstruction (intent_hash: {:?})",
                self.id, round, intent_hash
            );
        }

        info!("📤 [SIGNING] Node {} broadcasted ECDSA signature", self.id);
        Ok(())
    }

    /// Sign a contract transaction message (overload for ContractTransaction)
    pub async fn sign_contract_message(
        &mut self,
        _message: Vec<u8>,
        transaction: &ContractTransaction,
        user_tweaked_share: Option<Scalar>,
        user_eth_address: Option<String>,
    ) -> Result<()> {
        // Determine which key to use for signing
        // Redacted user_tweaked_share from logs
        let signing_key = if let Some(tweaked_share) = user_tweaked_share {
            // Use user's tweaked share for user deposits
            info!("🔑 [SIGNING] Using user-specific tweaked share for signing");
            Self::derive_secp_secret(&tweaked_share)?
        } else {
            // Use network DKG share for network withdrawals
            info!("🔑 [SIGNING] Using network DKG share for signing");
            match self.key_store.clone_private_key() {
                Some(key) => key,
                None => {
                    error!(
                        "❌ [SIGNING] Node {} cannot sign: no private key available",
                        self.id
                    );
                    return Err(anyhow!("No private key available"));
                }
            }
        };

        // Log signing key for testing/debugging
        let signing_key_hex = hex::encode(signing_key.secret_bytes());
        info!(
            "🔐 [SIGNING-DEBUG] Node {} signing key (hex): 0x{}",
            self.id, signing_key_hex
        );

        // Calculate and log DKG index for this node
        let dkg_index = self.calculate_dkg_index_for_peer(&self.id).await;
        info!(
            "🔢 [SIGNING-DEBUG] Node {} DKG index: {}",
            self.id, dkg_index
        );

        info!(
            "📝 [SIGNING] Node {} starting to sign contract transaction",
            self.id
        );

        // Create chain transaction from contract transaction
        // Convert hex string data to actual bytes
        let data_bytes = if transaction.data.is_empty() || transaction.data == "0x" {
            vec![]
        } else {
            hex::decode(
                transaction
                    .data
                    .strip_prefix("0x")
                    .unwrap_or(&transaction.data),
            )
            .map_err(|e| anyhow!("Invalid hex data in contract transaction: {}", e))?
        };

        info!(
            "🔍 [SIGNING] Contract transaction data: '{}' -> {} bytes",
            transaction.data,
            data_bytes.len()
        );

        let chain_transaction =
            ChainTransaction::Ethereum(crate::chain_abstraction::EthereumTransaction {
                to: transaction.to.clone(),
                value: transaction.value.clone(),
                gas_limit: transaction.gas_limit,
                gas_price: transaction.gas_price.clone(),
                nonce: transaction.nonce,
                data: Some(data_bytes.clone()),
                chain_id: transaction.chain_id,
            });

        // Create transaction bytes using contract chain handler
        let tx_bytes = self
            .contract_chain_handler
            .create_transaction_bytes_contract(&chain_transaction)?;
        info!(
            "🔐 [SIGNING] Contract transaction bytes: 0x{}",
            hex::encode(&tx_bytes)
        );

        // Hash the transaction bytes
        let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> =
            sha3::Keccak256::new();
        hasher.update(&tx_bytes);
        let tx_hash = hasher.finalize();
        info!("Tx hash: 0x{}", hex::encode(&tx_hash));
        // Get available nodes and perform VRF selection
        let available_nodes = self.get_available_nodes_from_manager().await;

        // Use VrfService for node selection (chain-agnostic)
        if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = vrf_service.get_current_round().await;
            let _selection_result = vrf_service
                .perform_node_selection(&available_nodes, 1, round, "ethereum")
                .await?;

            info!(
                "🎯 [VRF] Node {} completed VRF selection for ethereum signing round {}",
                self.id, round
            );
        }

        // Create ECDSA signature using secp256k1
        let msg = Message::from_digest_slice(&tx_hash)?;
        let signature =
            self.create_ecdsa_signature_with_key_contract(&msg, transaction, &signing_key)?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();

        info!(
            "✍️ [SIGNING] Node {} created Ethereum contract signature",
            self.id
        );

        // Convert to legacy ECDSASignature for compatibility
        let ecdsa_signature = ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_eth_address: user_eth_address.clone(), // Clone to avoid borrow checker issues
        };

        // Get current round from VRF service
        let round = if let Some(vrf_service) = self.coordination.vrf_service() {
            vrf_service.get_next_round().await
        } else {
            0
        };

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(self.id.clone(), ecdsa_signature.clone());

            // Calculate and log this node's DKG index
            let my_dkg_index = self.calculate_dkg_index_for_peer(&self.id).await;

            info!(
                "💾 [SIGNING] Node {} stored contract signature for round {}",
                self.id, round
            );
            info!(
                "💾 [SIGNING-DEBUG] Stored contract signature details - r: 0x{}, s: 0x{}, recovery_id: {}",
                hex::encode(&signature_bytes[0..32]),
                hex::encode(&signature_bytes[32..64]),
                recovery_id.to_i32()
            );
            info!(
                "💾 [INDEX-PEER-DEBUG] Stored contract signature for Index {} => PeerId {} (s-share: 0x{})",
                my_dkg_index,
                self.id,
                hex::encode(&signature_bytes[32..64])
            );
        }

        // Store original transaction for reconstruction after aggregation (contract-specific path)
        let mut pending_transactions = self.pending.pending_transactions.write().await;
        pending_transactions.insert(
            round,
            (
                chain_transaction,
                tx_bytes.clone(),
                None, // No intent hash for direct contract calls
                None,
            ),
        );
        info!(
            "💾 [SIGNING] Node {} stored contract transaction for round {} reconstruction",
            self.id, round
        );

        info!(
            "📤 [SIGNING] Node {} broadcasted Ethereum contract signature",
            self.id
        );
        Ok(())
    }

    pub async fn reconstruct_signed_ethereum_transaction(
        &self,
        round: u64,
        aggregated_signature: &[u8],
        recovery_id: u8,
    ) -> Result<Option<String>> {
        let is_reward_round = {
            let reward_rounds = self.pending.reward_rounds.read().await;
            reward_rounds.contains(&round)
        };
        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        let (chain_tx, transaction_type) = if is_reward_round {
            let reward_pending_transactions =
                self.pending.reward_pending_transactions_tics.read().await;
            if let Some((chain_tx, _tx_bytes, _solver_address, transaction_type)) =
                reward_pending_transactions.get(&round)
            {
                (Some(chain_tx.clone()), transaction_type.clone())
            } else {
                (None, None)
            }
        } else if is_withdraw_round {
            let withdraw_pending_transactions =
                self.pending.withdraw_pending_transactions_tics.read().await;
            if let Some((chain_tx, _tx_bytes, _solver_address, transaction_type)) =
                withdraw_pending_transactions.get(&round)
            {
                (Some(chain_tx.clone()), transaction_type.clone())
            } else {
                (None, None)
            }
        } else {
            let pending_transactions = self.pending.pending_transactions.read().await;
            if let Some((chain_tx, _tx_bytes, _intent_hash, transaction_type)) =
                pending_transactions.get(&round)
            {
                (Some(chain_tx.clone()), transaction_type.clone())
            } else {
                (None, None)
            }
        };

        if let Some(chain_tx) = chain_tx {
            if let ChainTransaction::Ethereum(original_tx) = chain_tx {
                let is_contract_tx =
                    original_tx.data.is_some() && !original_tx.data.as_ref().unwrap().is_empty();

                info!(
                    "🔧 [SIGNING] Node {} reconstructing signed Ethereum transaction for round {} (contract: {})",
                    self.id, round, is_contract_tx
                );

                if is_contract_tx {
                    info!(
                        "📄 [SIGNING] Contract transaction detected - using contract chain handler"
                    );
                    info!(
                        "📄 [SIGNING] Contract data length: {} bytes",
                        original_tx.data.as_ref().unwrap().len()
                    );
                }

                let r = &aggregated_signature[0..32];
                let s = &aggregated_signature[32..64];

                let chain_handler = if is_contract_tx {
                    &self.contract_chain_handler
                } else {
                    &self.chain_handler
                };
                let chain_id = chain_handler
                    .get_chain_params()
                    .get("chain_id")
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(9029);

                let v = recovery_id as u64 + 35 + chain_id * 2;

                let user_eth_address = {
                    let signatures_by_round = self.signatures.signatures_by_round.read().await;
                    if let Some(round_signatures) = signatures_by_round.get(&round) {
                        round_signatures
                            .values()
                            .next()
                            .and_then(|sig| sig.user_eth_address.clone())
                    } else {
                        None
                    }
                };

                let nonce_address = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        if let Some(user_addr) = &user_eth_address {
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                if let Some(user) =
                                    user_intent_manager.get_user_by_address(user_addr).await
                                {
                                    if let Some(derived_eth_addr) = &user.derived_eth_address {
                                        let nonce =
                                            Self::fetch_ethereum_nonce(derived_eth_addr, chain_id)
                                                .await?;
                                        info!("🔢 [SIGNING] UserToVault transaction: fetching nonce {} from user's derived address {}", nonce, derived_eth_addr);
                                        derived_eth_addr.clone()
                                    } else {
                                        return Err(anyhow!(
                                            "User {} has no derived Ethereum address",
                                            user_addr
                                        ));
                                    }
                                } else {
                                    return Err(anyhow!(
                                        "User {} not found in registry",
                                        user_addr
                                    ));
                                }
                            } else {
                                return Err(anyhow!(
                                    "User registry not available for user transaction"
                                ));
                            }
                        } else {
                            return Err(anyhow!(
                                "UserToVault transaction requires user_eth_address"
                            ));
                        }
                    }
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        let group_address =
                            if let Some(group_key) = self.key_store.get_group_public_key() {
                                get_eth_address_from_group_key(group_key)
                            } else {
                                return Err(anyhow!(
                                    "No group public key available for network transaction"
                                ));
                            };

                        let nonce = Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
                        info!("🔢 [SIGNING] NetworkToTarget transaction: fetching nonce {} from network group address {}", nonce, group_address);
                        group_address
                    }
                    Some(crate::types::TransactionType::VaultToNetwork) => {
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            let database = user_intent_manager.get_database();
                            let vault_eth_address: String = database
                                .get_string(&crate::database::keys::DKG_VAULT_ETH_ADDRESS)
                                .ok()
                                .flatten()
                                .ok_or_else(|| {
                                    anyhow!("Vault ETH address not found in database")
                                })?;

                            let nonce =
                                Self::fetch_ethereum_nonce(&vault_eth_address, chain_id).await?;
                            info!("🔢 [SIGNING] VaultToNetwork transaction: fetching nonce {} from vault address {}", nonce, vault_eth_address);
                            vault_eth_address
                        } else {
                            return Err(anyhow!(
                                "User registry not available for vault transaction"
                            ));
                        }
                    }
                    Some(crate::types::TransactionType::RewardTxn) => {
                        // For reward transactions, use network group address
                        let group_address =
                            if let Some(group_key) = self.key_store.get_group_public_key() {
                                get_eth_address_from_group_key(group_key)
                            } else {
                                return Err(anyhow!(
                                    "No group public key available for reward transaction"
                                ));
                            };
                        let nonce =
                            Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
                        info!("🔢 [SIGNING] RewardTxn transaction: fetching nonce {} from network group address {}", nonce, group_address);
                        group_address
                    }
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        // Withdraw liquidity payouts reuse the network group key path (same as rewards)
                        let group_address =
                            if let Some(group_key) = self.key_store.get_group_public_key() {
                                get_eth_address_from_group_key(group_key)
                            } else {
                                return Err(anyhow!(
                                    "No group public key available for withdraw-liquidity transaction"
                                ));
                            };
                        let nonce =
                            Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
                        info!("🔢 [SIGNING] WithdrawLiquidity transaction: fetching nonce {} from network group address {}", nonce, group_address);
                        group_address
                    }
                    None => {
                        if let Some(user_addr) = &user_eth_address {
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                if let Some(user) =
                                    user_intent_manager.get_user_by_address(user_addr).await
                                {
                                    if let Some(derived_eth_addr) = &user.derived_eth_address {
                                        let nonce =
                                            Self::fetch_ethereum_nonce(derived_eth_addr, chain_id)
                                                .await?;
                                        info!("🔢 [SIGNING] User transaction (fallback): fetching nonce {} from user's derived address {}", nonce, derived_eth_addr);
                                        derived_eth_addr.clone()
                                    } else {
                                        return Err(anyhow!(
                                            "User {} has no derived Ethereum address",
                                            user_addr
                                        ));
                                    }
                                } else {
                                    return Err(anyhow!(
                                        "User {} not found in registry",
                                        user_addr
                                    ));
                                }
                            } else {
                                return Err(anyhow!(
                                    "User registry not available for user transaction"
                                ));
                            }
                        } else {
                            let group_address =
                                if let Some(group_key) = self.key_store.get_group_public_key() {
                                    get_eth_address_from_group_key(group_key)
                                } else {
                                    return Err(anyhow!(
                                        "No group public key available for nonce fetching"
                                    ));
                                };

                            let nonce =
                                Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
                            info!("🔢 [SIGNING] Network/Vault transaction (fallback): fetching nonce {} from group address {}", nonce, group_address);
                            group_address
                        }
                    }
                };

                info!("💰 [SIGNING] Transaction cost: {} wei", original_tx.value);
                info!(
                    "🔍 [SIGNING] Please ensure the address {} has sufficient balance",
                    nonce_address
                );
                info!(
                    "🔍 [SIGNING] Data present: {} bytes",
                    original_tx.data.as_deref().unwrap_or(&[]).len()
                );
                info!("🔍 [SIGNING] Original Nonce: {}", original_tx.nonce);

                let signed_tx = create_signed_transaction(
                    &DummyTransaction {
                        to: original_tx.to.clone(),
                        value: original_tx.value.clone(),
                        nonce: original_tx.nonce,
                        gas_limit: original_tx.gas_limit,
                        gas_price: original_tx.gas_price.clone(),
                        chain_id: original_tx.chain_id,
                    },
                    original_tx.data.as_deref(),
                    r,
                    s,
                    v,
                );

                let signed_tx_hex = format!("0x{}", hex::encode(&signed_tx));

                info!(
                    "✅ [SIGNING] Node {} successfully reconstructed signed Ethereum transaction for round {}",
                    self.id, round
                );
                info!("📄 [SIGNING] Signed transaction prepared");
                info!("📏 [SIGNING] Transaction size: {} bytes", signed_tx.len());
                info!("🔗 [SIGNING] Chain ID: {}", chain_id);

                Ok(Some(signed_tx_hex))
            } else {
                warn!(
                    "❌ [SIGNING] Node {} expected Ethereum transaction for round {} but got different type",
                    self.id, round
                );
                Ok(None)
            }
        } else {
            warn!(
                "❌ [SIGNING] Node {} cannot reconstruct Ethereum transaction for round {} - original transaction not found",
                self.id, round
            );
            Ok(None)
        }
    }

    pub fn create_ecdsa_signature_with_key(
        &self,
        message: &Message,
        _transaction: &EthereumTransaction,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        self.create_ecdsa_signature_with_signing_key(message, signing_key)
    }

    pub fn create_ecdsa_signature_with_key_contract(
        &self,
        message: &Message,
        _transaction: &ContractTransaction,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        self.create_ecdsa_signature_with_signing_key(message, signing_key)
    }

    async fn store_reward_transaction_tics(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        solver_address: String,
    ) {
        let mut pending = self.pending.reward_pending_transactions_tics.write().await;
        pending.insert(round, (chain_tx, tx_bytes, Some(solver_address), None));
        info!(
            "🎁 [SIGNING] Stored TICS reward transaction for round {} with solver address",
            round
        );
    }
}
