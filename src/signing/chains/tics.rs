use crate::signing::SigningNode;
use crate::types::signing::SigningMessage;
use crate::{
    chain_abstraction::{ChainTransaction, TicsTransaction},
    types::{
        intent::{ContractTransaction, DummyTransaction},
        signing::ECDSASignature,
        TransactionType,
    },
    utils::{
        get_eth_address_from_group_key,
        transaction::{create_signed_transaction, get_evm_rpc_url},
    },
};
use anyhow::{anyhow, Result};
use hex;
use k256::Scalar;
use reqwest::Client;
use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use sha3::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Convenience wrapper for TICS-focused signing flows.
pub struct TicsSigner<'a> {
    node: &'a mut SigningNode,
}

impl<'a> TicsSigner<'a> {
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
        chain_handler: &Arc<dyn crate::chain_abstraction::ChainHandler>,
        transaction: &TicsTransaction,
        user_tweaked_share: Option<Scalar>,
        user_tics_address: Option<String>,
        intent_hashes: Vec<String>,
        transaction_type: Option<TransactionType>,
        solver_address: Option<String>,
        signing_key_override: Option<Scalar>,
    ) -> Result<()> {
        self.node
            .sign_message(
                message,
                chain_handler,
                transaction,
                user_tweaked_share,
                user_tics_address,
                intent_hashes,
                transaction_type,
                solver_address,
                signing_key_override,
            )
            .await
    }

    pub async fn sign_contract_message(
        &mut self,
        message: Vec<u8>,
        chain_handler: &Arc<dyn crate::chain_abstraction::ChainHandler>,
        contract_tx: &ContractTransaction,
        user_tweaked_share: Option<Scalar>,
        user_tics_address: Option<String>,
        intent_hashes: Vec<String>,
        signing_key_override: Option<Scalar>,
        request_id: Option<String>,
        original_request: Option<()>,
        tics_withdraw_identifiers: Option<Vec<String>>,
        tics_claim_reward_identifiers: Option<Vec<String>>,
        tics_claim_platform_fee_identifiers: Option<Vec<String>>,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_contract_message(
                message,
                chain_handler,
                contract_tx,
                user_tweaked_share,
                user_tics_address,
                intent_hashes,
                signing_key_override,
                request_id,
                original_request,
                tics_withdraw_identifiers,
                tics_claim_reward_identifiers,
                tics_claim_platform_fee_identifiers,
                nonce_tuple_id,
            )
            .await
    }

    /// TICS UserToVault batch: one round, one VRF; sign each slot and send partials to final node.
    pub async fn sign_tics_user_to_vault_batch(
        &mut self,
        round: u64,
        batch: Vec<(
            String,
            String,
            crate::chain_abstraction::ChainTransaction,
            Vec<u8>,
            Option<Scalar>,
        )>,
    ) -> Result<()> {
        // DEPRECATED: Empty nonce assignments will cause all intents to be SKIPPED
        // Use sign_tics_user_to_vault_batch_with_nonces with proper nonce assignments
        warn!("⚠️ [TICS_UTV_BATCH] sign_tics_user_to_vault_batch called without nonce assignments - all intents will be SKIPPED");
        self.node
            .sign_tics_user_to_vault_batch_with_nonces(round, batch, std::collections::HashMap::new())
            .await
    }

    /// TICS UserToVault batch with nonce assignments for coordinated signing.
    pub async fn sign_tics_user_to_vault_batch_with_nonces(
        &mut self,
        round: u64,
        batch: Vec<(
            String,
            String,
            crate::chain_abstraction::ChainTransaction,
            Vec<u8>,
            Option<Scalar>,
        )>,
        nonce_assignments: std::collections::HashMap<String, Vec<String>>,
    ) -> Result<()> {
        self.node
            .sign_tics_user_to_vault_batch_with_nonces(round, batch, nonce_assignments)
            .await
    }
}

impl SigningNode {
    pub async fn fetch_tics_nonce(address: &str, chain_id: u64) -> Result<u64> {
        let rpc_url = get_evm_rpc_url(chain_id)?;

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

    /// Helper: Fetch nonce for address and log with description
    async fn fetch_nonce_and_log(
        address: &str,
        chain_id: u64,
        description: &str,
    ) -> Result<String> {
        let nonce = Self::fetch_tics_nonce(address, chain_id).await?;
        info!(
            "🔢 [SIGNING] {}: fetching nonce {} from address {}",
            description, nonce, address
        );
        Ok(address.to_string())
    }

    /// Wait for transaction receipt with timeout
    async fn wait_for_transaction_receipt(
        tx_hash: &str,
        chain_id: u64,
        timeout_secs: u64,
    ) -> Result<serde_json::Value> {
        let rpc_url = get_evm_rpc_url(chain_id)?;
        let client = Client::new();
        let start = std::time::Instant::now();
        let timeout_duration = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(2);

        info!(
            "⏳ Waiting for transaction receipt: {} (timeout: {}s)",
            tx_hash, timeout_secs
        );

        loop {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            });

            let response = client
                .post(&rpc_url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(error) = result.get("error") {
                    error!("❌ Failed to get transaction receipt: {}", error);
                    return Err(anyhow!("Receipt fetch failed: {}", error));
                }
                if let Some(receipt) = result.get("result") {
                    if !receipt.is_null() {
                        info!("✅ Transaction receipt received for {}", tx_hash);
                        return Ok(receipt.clone());
                    }
                }
            }

            // Check timeout
            if start.elapsed() >= timeout_duration {
                error!(
                    "❌ Timeout waiting for transaction receipt: {} (waited {}s)",
                    tx_hash, timeout_secs
                );
                return Err(anyhow!(
                    "Transaction confirmation timeout after {}s. TX may still be pending: {}",
                    timeout_secs,
                    tx_hash
                ));
            }

            // Wait before next poll
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Check transaction receipt status
    fn check_receipt_status(receipt: &serde_json::Value, tx_hash: &str) -> Result<()> {
        // Check status field (0x0 = failure, 0x1 = success)
        let status = receipt
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("0x0");

        // Check gas used
        let gas_used = receipt
            .get("gasUsed")
            .and_then(|g| g.as_str())
            .unwrap_or("0x0");

        info!("📊 Transaction receipt for {}:", tx_hash);
        info!("   Status: {}", status);
        info!("   Gas Used: {}", gas_used);

        // If status is 0x0, transaction failed
        if status == "0x0" {
            // Try to get more error details from the receipt
            let mut error_details = String::from("Transaction execution failed");

            // Check if there's an error field
            if let Some(error) = receipt.get("error") {
                error_details = format!("Transaction failed: {}", error);
            }

            // Check if gas used is 0x0 (out of gas scenario)
            if gas_used == "0x0" {
                error_details = format!(
                    "{} (gas used: 0x0 - likely out of gas or immediate revert)",
                    error_details
                );
            }

            error!("❌ {}", error_details);
            return Err(anyhow!("{}", error_details));
        }

        // Additional check: if gas used is 0x0 but status is 0x1, something is wrong
        if gas_used == "0x0" && status == "0x1" {
            warn!("⚠️ Transaction shows success but no gas used - this is unusual");
        }

        info!("✅ Transaction executed successfully: {}", tx_hash);
        Ok(())
    }

    pub(crate) async fn broadcast_tics_transaction(
        raw_tx_hex: &str,
        chain_id: u64,
    ) -> Result<Option<String>> {
        let rpc_url = get_evm_rpc_url(chain_id)?;

        let client = Client::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex],
            "id": 1
        });

        info!(
            "Broadcasting TICS transaction to chain {}: {}",
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
                info!("✅ Qubetics transaction broadcasted to mempool!");
                info!("TX Hash: {}", tx_hash);
                if let Some(tx_hash_str) = tx_hash.as_str() {
                    // Wait for transaction receipt and verify execution status
                    info!("⏳ Waiting for transaction confirmation...");
                    match Self::wait_for_transaction_receipt(tx_hash_str, chain_id, 60).await {
                        Ok(receipt) => {
                            // Check if transaction execution was successful
                            Self::check_receipt_status(&receipt, tx_hash_str)?;
                            info!("✅ Transaction confirmed and executed successfully!");
                            return Ok(Some(tx_hash_str.to_string()));
                        }
                        Err(e) => {
                            error!("❌ Transaction confirmation failed: {}", e);
                            return Err(anyhow!("Transaction confirmation failed: {}", e));
                        }
                    }
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
        chain_handler: &Arc<dyn crate::chain_abstraction::ChainHandler>,
        transaction: &TicsTransaction,
        user_tweaked_share: Option<Scalar>,
        user_tics_address: Option<String>,
        intent_hashes: Vec<String>,
        transaction_type: Option<TransactionType>,
        solver_address: Option<String>,
        signing_key_override: Option<Scalar>,
    ) -> Result<()> {
        info!(
            "🔗 [SIGNING] Using {} chain handler for EVM signing",
            chain_handler.chain_type()
        );

        // Determine which key to use for signing
        // Redacted user_tweaked_share from logs
        let signing_key = if let Some(tweaked_share) = user_tweaked_share {
            // Use user's tweaked share for user deposits
            info!("🔑 [SIGNING] Using user-specific tweaked share for signing");
            Self::derive_secp_secret(&tweaked_share)?
        } else if let Some(explicit_key) = signing_key_override {
            info!("🔑 [SIGNING] Using provided signing key override for signing");
            Self::derive_secp_secret(&explicit_key)?
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

        debug!(
            "[SIGNING] Node {} signing ETH transaction: to={}, value={}, nonce={}",
            self.id, transaction.to, transaction.value, transaction.nonce
        );

        // Convert DummyTransaction to ChainTransaction for chain-agnostic handling with UTXO error handling
        let chain_transaction =
            ChainTransaction::Tics(crate::chain_abstraction::TicsTransaction {
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
        debug!("[SIGNING] Transaction hash: 0x{}", hex::encode(&tx_hash));

        // Get available nodes and perform HRW selection
        let available_nodes = self.coordination.get_available_nodes_from_manager().await;

        // Use VrfService for node selection (chain-agnostic)
        if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = vrf_service.get_current_round().await;
            let _selection_result = vrf_service
                .perform_node_selection(
                    &available_nodes,
                    crate::vrf::VRF_NODE_SELECTION_COUNT,
                    round,
                    self.chain_handler.chain_type(),
                )
                .await?;

            info!(
                "🎯 [SIGNING] Node {} completed selection for {} signing round {}",
                self.id,
                self.chain_handler.chain_type(),
                round
            );
        }

        // Create ECDSA signature using secp256k1 (with random nonce if available)
        let msg = Message::from_digest_slice(&tx_hash)?;
        let signature = self.create_ecdsa_signature_with_key_async(&msg, transaction, &signing_key).await?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();

        info!(
            "✍️ [SIGNING] Node {} created {} signature",
            self.id,
            self.chain_handler.chain_type()
        );

        // --- SELF-VERIFICATION ---
        // Verify the signature against our own public key before sending
        {
            let secp = Secp256k1::new();
            let public_key = PublicKey::from_secret_key(&secp, &signing_key);
            let public_key_hex = hex::encode(public_key.serialize());
            let digest_hex = hex::encode(tx_hash);

            info!("🔍 [SELF-VERIFY] Verifying generated signature...");
            info!("    - Digest: 0x{}", digest_hex);
            info!(
                "    - Expected PubKey (Derived from Secret): 0x{}",
                public_key_hex
            );

            // Attempt to recover public key from signature to show 'Found PubKey'
            let rec_sig_result = RecoverableSignature::from_compact(&signature_bytes, recovery_id);
            match rec_sig_result {
                Ok(rec_sig) => match secp.recover_ecdsa(&msg, &rec_sig) {
                    Ok(recovered_pk) => {
                        let recovered_pk_hex = hex::encode(recovered_pk.serialize());
                        info!(
                            "    - Found PubKey (Recovered from Sig): 0x{}",
                            recovered_pk_hex
                        );

                        if recovered_pk == public_key {
                            info!("✅ [SELF-VERIFY] Signature verified successfully! Found PubKey matches Expected PubKey.");
                        } else {
                            error!(
                                "❌ [SELF-VERIFY] PubKey Mismatch! Found 0x{} != Expected 0x{}",
                                recovered_pk_hex, public_key_hex
                            );
                        }
                    }
                    Err(e) => {
                        error!("❌ [SELF-VERIFY] Failed to recover ECDSA public key: {}", e);
                    }
                },
                Err(e) => {
                    error!(
                        "❌ [SELF-VERIFY] Failed to construct recoverable signature: {}",
                        e
                    );
                }
            }
        }
        // --- END SELF-VERIFICATION ---

        // Convert to legacy ECDSASignature for compatibility
        let ecdsa_signature = ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_tics_address: user_tics_address.clone(), // Clone to avoid borrow checker issues
        };

        // Synchronize rounds before advancing and acquiring the signing round
        let round = if let Some(vrf_service) = self.coordination.vrf_service() {
            vrf_service.sync_rounds_before_signing().await?;
            let r = vrf_service.get_next_round().await;
            self.coordination.replicate_vrf_round_to_consensus(r);
            r
        } else {
            0
        };

        // Store signature by round before touching any pending transaction locks to maintain
        // a consistent lock acquisition order across signing and reconstruction paths
        {
            let mut signatures_by_round = self.signatures.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(self.id.clone(), ecdsa_signature.clone());
        }

        // Store original transaction for reconstruction after aggregation
        if let Some(TransactionType::WithdrawLiquidity) = transaction_type {
            let solver_addr = solver_address.expect("Solver address should be validated above");
            let chain_tx =
                ChainTransaction::Tics(crate::chain_abstraction::TicsTransaction {
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
                ChainTransaction::Tics(crate::chain_abstraction::TicsTransaction {
                    to: transaction.to.clone(),
                    value: transaction.value.clone(),
                    gas_limit: transaction.gas_limit,
                    gas_price: transaction.gas_price.clone(),
                    nonce: transaction.nonce,
                    data: None,
                    chain_id: transaction.chain_id,
                });
            let primary_intent_hash = intent_hashes.first().cloned();
            pending_transactions.insert(
                round,
                (
                    chain_tx,
                    tx_bytes.clone(),
                    primary_intent_hash.clone(),
                    transaction_type,
                    None, // No request_id for this path
                    None, // No original_request for this path
                ),
            );
            // Track intent hash scope (single intent = vec![hash], none = empty)
            {
                let mut intent_map = self.pending.intent_hashes_by_round.write().await;
                intent_map.insert(round, intent_hashes.clone());
            }
            info!(
                "💾 [SIGNING] Node {} stored intent-based transaction for round {} reconstruction (intent_hash: {:?})",
                self.id, round, primary_intent_hash
            );
        }

        info!("📤 [SIGNING] Node {} broadcasted ECDSA signature", self.id);
        Ok(())
    }

    /// Sign a contract transaction message (overload for ContractTransaction)
    /// When tics_withdraw_identifiers is Some(non-empty), stores in withdraw_pending_transactions_tics for batch TICS withdraw.
    /// When nonce_tuple_id is Some, uses coordinated nonce from the pool (required for threshold signing).
    pub async fn sign_contract_message(
        &mut self,
        _message: Vec<u8>,
        _chain_handler: &Arc<dyn crate::chain_abstraction::ChainHandler>,
        transaction: &ContractTransaction,
        user_tweaked_share: Option<Scalar>,
        user_tics_address: Option<String>,
        intent_hashes: Vec<String>,
        signing_key_override: Option<Scalar>,
        request_id: Option<String>,
        original_request: Option<()>,
        tics_withdraw_identifiers: Option<Vec<String>>,
        tics_claim_reward_identifiers: Option<Vec<String>>,
        tics_claim_platform_fee_identifiers: Option<Vec<String>>,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        let has_dkg = self.has_dkg_share().await;

        debug!(
            "[SIGNING] Node {} {} contract tx: to={}, value={}, data_len={}",
            self.id,
            if has_dkg { "signing" } else { "preparing (observer)" },
            transaction.to, transaction.value, transaction.data.len()
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

        let chain_transaction =
            ChainTransaction::Tics(crate::chain_abstraction::TicsTransaction {
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

        debug!("[SIGNING] Contract tx bytes length: {}", tx_bytes.len());

        // Hash the transaction bytes
        let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> =
            sha3::Keccak256::new();
        hasher.update(&tx_bytes);
        let tx_hash = hasher.finalize();
        // Get available nodes and perform HRW selection
        let available_nodes = self.get_available_nodes_from_manager().await;

        // Use VrfService for node selection (chain-agnostic)
        if let Some(vrf_service) = self.coordination.vrf_service() {
            let round = vrf_service.get_current_round().await;
            let _selection_result = vrf_service
                .perform_node_selection(
                    &available_nodes,
                    crate::vrf::VRF_NODE_SELECTION_COUNT,
                    round,
                    "tics",
                )
                .await?;

            info!(
                "🎯 [SIGNING] Node {} completed selection for TICS signing round {}",
                self.id, round
            );
        }

        // DKG nodes create ECDSA signature; non-DKG nodes skip signing
        if has_dkg {
            // Determine which key to use for signing
            let signing_key = if let Some(tweaked_share) = user_tweaked_share {
                info!("🔑 [SIGNING] Using user-specific tweaked share for signing");
                Self::derive_secp_secret(&tweaked_share)?
            } else if let Some(explicit_key) = signing_key_override {
                info!("🔑 [SIGNING] Using provided signing key override for signing");
                Self::derive_secp_secret(&explicit_key)?
            } else {
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

            // Create ECDSA signature using secp256k1 with COORDINATED nonce
            let msg = Message::from_digest_slice(&tx_hash)?;
            let signature = if let Some(ref tuple_id) = nonce_tuple_id {
                // Use coordinated nonce - all nodes will use the same k value
                info!(
                    "🔐 [SIGNING] Using coordinated nonce {} for contract signing",
                    tuple_id
                );

                // Acquire the specific nonce from the pool
                if let Some(nm) = &self.nonce_manager {
                    let nm_guard = nm.lock().await;
                    match nm_guard.acquire_specific_nonce(tuple_id).await {
                        Ok(Some(nonce_tuple)) => {
                            info!(
                                "🔐 [CONTRACT_SIGN] Acquired coordinated nonce {} (r_scalar: 0x{}...)",
                                tuple_id,
                                hex::encode(&nonce_tuple.r_scalar.0.to_bytes()[..4])
                            );
                            drop(nm_guard); // Release lock before signing
                            self.create_ecdsa_signature_with_nonce(&msg, &signing_key, &nonce_tuple)?
                        }
                        Ok(None) => {
                            error!(
                                "🔴 [CONTRACT_SIGN] Nonce {} not found or already consumed",
                                tuple_id
                            );
                            return Err(anyhow!("Nonce {} not found or already consumed", tuple_id));
                        }
                        Err(e) => {
                            error!(
                                "🔴 [CONTRACT_SIGN] Failed to acquire nonce {}: {}",
                                tuple_id, e
                            );
                            return Err(anyhow!("Failed to acquire nonce {}: {}", tuple_id, e));
                        }
                    }
                } else {
                    error!("🔴 [CONTRACT_SIGN] Nonce manager not available");
                    return Err(anyhow!("Nonce manager not available for coordinated signing"));
                }
            } else {
                // No nonce_tuple_id provided - this is a BUG in the caller
                error!(
                    "🔴 [SIGNING] No nonce_tuple_id provided for contract signing - this is a coordination bug!"
                );
                return Err(anyhow!(
                    "No nonce_tuple_id provided. All signing operations must use coordinated nonces. \
                    The coordinator must reserve a nonce and include the tuple_id in the broadcast message."
                ));
            };
            let (recovery_id, signature_bytes) = signature.serialize_compact();

            info!(
                "✍️ [SIGNING] Node {} created TICS contract signature",
                self.id
            );

            // Convert to legacy ECDSASignature for compatibility
            let ecdsa_signature = ECDSASignature {
                signature: signature_bytes.to_vec(),
                signer_id: self.id.clone(),
                recovery_id: recovery_id.to_i32() as u8,
                user_tics_address: user_tics_address.clone(),
            };

            // Synchronize rounds before advancing and acquiring the signing round
            let round = if let Some(vrf_service) = self.coordination.vrf_service() {
                vrf_service.sync_rounds_before_signing().await?;
                let r = vrf_service.get_next_round().await;
                self.coordination.replicate_vrf_round_to_consensus(r);
                r
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
            }

            // Store original transaction and broadcast signature (DKG path continues below)
            self.store_contract_tx_and_broadcast(
                round, chain_transaction, tx_bytes, intent_hashes,
                tics_withdraw_identifiers, tics_claim_reward_identifiers,
                tics_claim_platform_fee_identifiers,
                request_id, original_request,
            ).await
        } else {
            // Non-DKG node: skip signing, just advance round and store TX

            // Synchronize rounds and advance to keep in sync with DKG nodes
            let round = if let Some(vrf_service) = self.coordination.vrf_service() {
                vrf_service.sync_rounds_before_signing().await?;
                let r = vrf_service.get_next_round().await;
                self.coordination.replicate_vrf_round_to_consensus(r);
                r
            } else {
                0
            };

            debug!(
                "💾 [SIGNING] Stored contract TX for round {} (ready for final-node reconstruction)",
                round
            );

            // Store original transaction (same as DKG path, without signature broadcast)
            self.store_contract_tx_and_broadcast(
                round, chain_transaction, tx_bytes, intent_hashes,
                tics_withdraw_identifiers, tics_claim_reward_identifiers,
                tics_claim_platform_fee_identifiers,
                request_id, original_request,
            ).await
        }
    }

    /// Store contract transaction in the appropriate pending store and populate intent_hashes_by_round.
    /// Shared by both DKG nodes (after signing) and observer nodes (without signing).
    async fn store_contract_tx_and_broadcast(
        &self,
        round: u64,
        chain_transaction: ChainTransaction,
        tx_bytes: Vec<u8>,
        intent_hashes: Vec<String>,
        tics_withdraw_identifiers: Option<Vec<String>>,
        tics_claim_reward_identifiers: Option<Vec<String>>,
        tics_claim_platform_fee_identifiers: Option<Vec<String>>,
        request_id: Option<String>,
        original_request: Option<()>,
    ) -> Result<()> {

        // Store original transaction for reconstruction after aggregation (contract-specific path)
        // TICS withdraw batch: store in withdraw_pending_transactions_tics with identifiers for tx-id broadcast
        if let Some(ref identifiers) = tics_withdraw_identifiers {
            if !identifiers.is_empty() {
                self.store_withdraw_transaction_tics_batch(
                    round,
                    chain_transaction.clone(),
                    tx_bytes.clone(),
                    identifiers.clone(),
                )
                .await;
                {
                    let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
                    withdraw_rounds.insert(round);
                    info!(
                        "💧 [SIGNING] Node {} added round {} to withdraw_rounds (TICS batch, {} request(s))",
                        self.id, round, identifiers.len()
                    );
                }
                info!(
                    "💾 [SIGNING] Node {} stored TICS withdraw batch contract transaction for round {} ({} request(s))",
                    self.id, round, identifiers.len()
                );
                info!(
                    "📤 [SIGNING] Node {} broadcasted TICS contract signature",
                    self.id
                );
                return Ok(());
            }
        }

        // TICS claim-reward batch: store in claim_reward_pending_transactions_tics with identifiers for tx-id broadcast
        if let Some(ref identifiers) = tics_claim_reward_identifiers {
            if !identifiers.is_empty() {
                self.store_claim_reward_transaction_tics_batch(
                    round,
                    chain_transaction.clone(),
                    tx_bytes.clone(),
                    identifiers.clone(),
                )
                .await;
                {
                    let mut claim_reward_rounds = self.pending.claim_reward_rounds.write().await;
                    claim_reward_rounds.insert(round);
                    info!(
                        "🎁 [SIGNING] Node {} added round {} to claim_reward_rounds (TICS batch, {} request(s))",
                        self.id, round, identifiers.len()
                    );
                }
                info!(
                    "💾 [SIGNING] Node {} stored TICS claim-reward batch contract transaction for round {} ({} request(s))",
                    self.id, round, identifiers.len()
                );
                info!(
                    "📤 [SIGNING] Node {} broadcasted TICS contract signature",
                    self.id
                );
                return Ok(());
            }
        }

        // TICS claim-platform-fee batch: store in claim_platform_fee_pending_transactions_tics with identifiers for tx-id broadcast
        if let Some(ref identifiers) = tics_claim_platform_fee_identifiers {
            if !identifiers.is_empty() {
                self.store_claim_platform_fee_transaction_tics_batch(
                    round,
                    chain_transaction.clone(),
                    tx_bytes.clone(),
                    identifiers.clone(),
                )
                .await;
                {
                    let mut claim_pf_rounds = self.pending.claim_platform_fee_rounds.write().await;
                    claim_pf_rounds.insert(round);
                    info!(
                        "💰 [SIGNING] Node {} added round {} to claim_platform_fee_rounds (TICS batch, {} request(s))",
                        self.id, round, identifiers.len()
                    );
                }
                info!(
                    "💾 [SIGNING] Node {} stored TICS claim-platform-fee batch contract transaction for round {} ({} request(s))",
                    self.id, round, identifiers.len()
                );
                info!(
                    "📤 [SIGNING] Node {} broadcasted TICS contract signature",
                    self.id
                );
                return Ok(());
            }
        }

        let mut pending_transactions = self.pending.pending_transactions.write().await;
        let primary_intent_hash = intent_hashes.first().cloned();

        // Prefix-based tx type (like add_liquidity "addliq:"): "peerinv:" => PeerInvalidation
        let tx_type_for_round = if intent_hashes.iter().any(|h| h.starts_with("peerinv:")) {
            Some(TransactionType::PeerInvalidation)
        } else if !intent_hashes.is_empty() {
            // Check if this is an add_liquidity transaction (request_id starts with "addliq:")
            let is_add_liquidity = intent_hashes.iter().any(|h| h.starts_with("addliq:"));

            if is_add_liquidity {
                // add_liquidity uses vault key - don't set transaction type
                // This prevents the verification from using the wrong pubkey
                None
            } else {
                // Check if this round is for BTC intent manager update (marks intents as Solved only).
                let is_btc_intent_manager_update =
                    if let Some(consensus_node) = self.coordination.consensus_node() {
                        consensus_node
                            .get_operation_type_for_round(round)
                            .map(|op| op == "btc_intent_manager_update")
                            .unwrap_or(false)
                    } else {
                        false
                    };

                if is_btc_intent_manager_update {
                    Some(TransactionType::IntentStatusUpdate)
                } else {
                    // Fallback: contract rounds with intent_hashes (not addliq) that have no
                    // operation_type set (e.g. timing/race) use IntentStatusUpdate so intents get
                    // marked Solved and are not picked again. Prevents "intents not marked Solved"
                    // loop when consensus operation_type was not yet stored.
                    if let Some(consensus_node) = self.coordination.consensus_node() {
                        if consensus_node.get_operation_type_for_round(round).is_none() {
                            warn!(
                                "⚠️ [SIGNING] Operation type missing for contract round {}, using IntentStatusUpdate so intents are marked Solved",
                                round
                            );
                            Some(TransactionType::IntentStatusUpdate)
                        } else {
                            Some(TransactionType::NetworkToTarget)
                        }
                    } else {
                        Some(TransactionType::NetworkToTarget)
                    }
                }
            }
        } else {
            None
        };
        pending_transactions.insert(
            round,
            (
                chain_transaction,
                tx_bytes.clone(),
                primary_intent_hash.clone(),
                tx_type_for_round,
                request_id,       // Store request_id for retry tracking
                original_request, // Store original_request for guaranteed retry
            ),
        );
        {
            let mut intent_map = self.pending.intent_hashes_by_round.write().await;
            intent_map.insert(round, intent_hashes.clone());
        }
        info!(
            "💾 [SIGNING] Node {} stored contract transaction for round {} reconstruction",
            self.id, round
        );

        info!(
            "📤 [SIGNING] Node {} broadcasted TICS contract signature",
            self.id
        );
        Ok(())
    }

    pub async fn reconstruct_signed_tics_transaction(
        &self,
        round: u64,
        aggregated_signature: &[u8],
        recovery_id: u8,
    ) -> Result<Option<String>> {
        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };

        let is_claim_platform_fee_round = {
            let r = self.pending.claim_platform_fee_rounds.read().await;
            r.contains(&round)
        };

        let user_tics_address = {
            let signatures_by_round = self.signatures.signatures_by_round.read().await;
            if let Some(round_signatures) = signatures_by_round.get(&round) {
                round_signatures
                    .values()
                    .next()
                    .and_then(|sig| sig.user_tics_address.clone())
            } else {
                None
            }
        };

        // Observer nodes (no DKG share) may not have TX data yet because it arrives
        // via TransactionDataForFinalNode messages which need threshold verification.
        // We poll briefly to let the TX data arrive before giving up.
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 }; // observer: poll up to ~5s

        let (chain_tx, transaction_type) = {
            let mut result = (None, None);
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let found = if is_withdraw_round {
                    let store = self.pending.withdraw_pending_transactions_tics.read().await;
                    store.get(&round).map(|(chain_tx, _tx_bytes, _solver_address, transaction_type, _request_id, _original_request)| {
                        (Some(chain_tx.clone()), transaction_type.clone())
                    })
                } else if is_claim_reward_round {
                    let store = self.pending.claim_reward_pending_transactions_tics.read().await;
                    store.get(&round).map(|(chain_tx, _tx_bytes, _identifiers, transaction_type, _request_id, _original_request)| {
                        (Some(chain_tx.clone()), transaction_type.clone())
                    })
                } else if is_claim_platform_fee_round {
                    let store = self.pending.claim_platform_fee_pending_transactions_tics.read().await;
                    store.get(&round).map(|(chain_tx, _tx_bytes, _identifiers, transaction_type, _request_id, _original_request)| {
                        (Some(chain_tx.clone()), transaction_type.clone())
                    })
                } else {
                    let store = self.pending.pending_transactions.read().await;
                    store.get(&round).map(|(chain_tx, _tx_bytes, _intent_hash, transaction_type, _request_id, _original_request)| {
                        (Some(chain_tx.clone()), transaction_type.clone())
                    })
                };
                if let Some(val) = found {
                    result = val;
                    if attempt > 0 {
                        debug!(
                            "✅ [SIGNING] Found TX data for reconstruction of round {} after {} attempts (~{}ms)",
                            round, attempt + 1, attempt * 100
                        );
                    }
                    break;
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [SIGNING] Could not find TX data for reconstruction of round {} after {}ms",
                        round, max_attempts * 100
                    );
                }
            }
            result
        };

        if let Some(chain_tx) = chain_tx {
            if let ChainTransaction::Tics(original_tx) = chain_tx {
                let is_contract_tx =
                    original_tx.data.is_some() && !original_tx.data.as_ref().unwrap().is_empty();

                info!(
                    "🔧 [SIGNING] Node {} reconstructing signed TICS transaction for round {} (contract: {})",
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

                let chain_id = original_tx.chain_id;

                let v = recovery_id as u64 + 35 + chain_id * 2;

                let nonce_address = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        if let Some(user_addr) = &user_tics_address {
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                if let Some(user) =
                                    user_intent_manager.get_user_by_address(user_addr).await
                                {
                                    if let Some(derived_eth_addr) = &user.derived_eth_address {
                                        Self::fetch_nonce_and_log(
                                            derived_eth_addr,
                                            chain_id,
                                            "UserToVault transaction",
                                        )
                                        .await?
                                    } else {
                                        return Err(anyhow!(
                                            "User {} has no derived TICS address",
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
                                "UserToVault transaction requires user_tics_address"
                            ));
                        }
                    }
                    Some(crate::types::TransactionType::NetworkToTarget)
                    | Some(crate::types::TransactionType::IntentStatusUpdate) => {
                        let group_key = self.get_network_group_public_key().await?;
                        let group_address = get_eth_address_from_group_key(group_key);
                        Self::fetch_nonce_and_log(
                            &group_address,
                            chain_id,
                            "NetworkToTarget/IntentStatusUpdate transaction",
                        )
                        .await?
                    }
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        let group_key = self.get_vault_group_public_key().await?;
                        let group_address = get_eth_address_from_group_key(group_key);
                        Self::fetch_nonce_and_log(
                            &group_address,
                            chain_id,
                            "WithdrawLiquidity (TICS) transaction",
                        )
                        .await?
                    }
                    Some(crate::types::TransactionType::ClaimReward) => {
                        let group_key = self.get_vault_group_public_key().await?;
                        let group_address = get_eth_address_from_group_key(group_key);
                        Self::fetch_nonce_and_log(
                            &group_address,
                            chain_id,
                            "ClaimReward (TICS) transaction",
                        )
                        .await?
                    }
                    Some(crate::types::TransactionType::ClaimPlatformFee) => {
                        let group_key = self.get_vault_group_public_key().await?;
                        let group_address = get_eth_address_from_group_key(group_key);
                        Self::fetch_nonce_and_log(
                            &group_address,
                            chain_id,
                            "ClaimPlatformFee (TICS) transaction",
                        )
                        .await?
                    }
                    Some(crate::types::TransactionType::PeerInvalidation) => {
                        let group_key = self.get_vault_group_public_key().await?;
                        let group_address = get_eth_address_from_group_key(group_key);
                        Self::fetch_nonce_and_log(
                            &group_address,
                            chain_id,
                            "PeerInvalidation (invalidateSolverIds) transaction",
                        )
                        .await?
                    }
                    None => {
                        if let Some(user_addr) = &user_tics_address {
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                if let Some(user) =
                                    user_intent_manager.get_user_by_address(user_addr).await
                                {
                                    if let Some(derived_eth_addr) = &user.derived_eth_address {
                                        Self::fetch_nonce_and_log(
                                            derived_eth_addr,
                                            chain_id,
                                            "User transaction (fallback)",
                                        )
                                        .await?
                                    } else {
                                        return Err(anyhow!(
                                            "User {} has no derived TICS address",
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
                            let group_address = get_eth_address_from_group_key(
                                self.get_network_group_public_key().await?,
                            );
                            Self::fetch_nonce_and_log(
                                &group_address,
                                chain_id,
                                "Network/Vault transaction (fallback)",
                            )
                            .await?
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
                        nonce: original_tx.nonce, // Use original nonce that was signed
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
                    "✅ [SIGNING] Node {} successfully reconstructed signed TICS transaction for round {}",
                    self.id, round
                );
                info!("📄 [SIGNING] Signed transaction prepared");
                info!("📏 [SIGNING] Transaction size: {} bytes", signed_tx.len());
                info!("🔗 [SIGNING] Chain ID: {}", chain_id);
                info!(
                    "🔍 [SIGNING] Raw signed tx hex for round {}: {}",
                    round, signed_tx_hex
                );
                // Recover sender address from the signed transaction for debugging
                {
                    let unsigned_tx_bytes = if is_contract_tx {
                        // Contract transactions must use the contract-aware encoder
                        // that includes calldata in the RLP, matching what was actually signed.
                        let data_hex = hex::encode(original_tx.data.as_ref().unwrap());
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &crate::types::ContractTransaction {
                                to: original_tx.to.clone(),
                                value: original_tx.value.clone(),
                                nonce: original_tx.nonce,
                                gas_limit: original_tx.gas_limit,
                                gas_price: original_tx.gas_price.clone(),
                                chain_id: original_tx.chain_id,
                                data: data_hex,
                            },
                        )
                    } else {
                        crate::utils::transaction::create_transaction_for_signing(
                            &crate::chain_abstraction::TicsTransaction {
                                to: original_tx.to.clone(),
                                value: original_tx.value.clone(),
                                nonce: original_tx.nonce,
                                gas_limit: original_tx.gas_limit,
                                gas_price: original_tx.gas_price.clone(),
                                chain_id: original_tx.chain_id,
                                data: original_tx.data.clone(),
                            },
                        )
                    };
                    let mut hasher = sha3::Keccak256::new();
                    hasher.update(&unsigned_tx_bytes);
                    let tx_hash = hasher.finalize();
                    info!(
                        "🔍 [SIGNING] Unsigned tx hash for round {}: 0x{}",
                        round, hex::encode(&tx_hash)
                    );
                    info!(
                        "🔍 [SIGNING] Signature r: 0x{}, s: 0x{}, v: {} (recovery_id: {})",
                        hex::encode(r), hex::encode(s), v, recovery_id
                    );
                    if let Ok(msg) = Message::from_digest_slice(&tx_hash) {
                        let secp = Secp256k1::new();
                        let recid_for_recover = (v - 35 - chain_id * 2) as u8;
                        if let Ok(rid) = secp256k1::ecdsa::RecoveryId::from_i32(recid_for_recover as i32) {
                            let mut sig_bytes_64 = [0u8; 64];
                            sig_bytes_64[0..32].copy_from_slice(r);
                            sig_bytes_64[32..64].copy_from_slice(s);
                            if let Ok(rec_sig) = RecoverableSignature::from_compact(&sig_bytes_64, rid) {
                                match secp.recover_ecdsa(&msg, &rec_sig) {
                                    Ok(pubkey) => {
                                        let pub_bytes = pubkey.serialize_uncompressed();
                                        let mut keccak = sha3::Keccak256::new();
                                        keccak.update(&pub_bytes[1..]);
                                        let hash = keccak.finalize();
                                        let recovered_addr = format!("0x{}", hex::encode(&hash[12..]));
                                        info!(
                                            "🔍 [SIGNING] Recovered sender address for round {}: {}",
                                            round, recovered_addr
                                        );
                                        info!(
                                            "🔍 [SIGNING] Expected sender (nonce_address) for round {}: {}",
                                            round, nonce_address
                                        );
                                        if recovered_addr.to_lowercase() != nonce_address.to_lowercase() {
                                            error!(
                                                "❌ [SIGNING] ADDRESS MISMATCH for round {}! Recovered: {} vs Expected: {}",
                                                round, recovered_addr, nonce_address
                                            );
                                        } else {
                                            info!(
                                                "✅ [SIGNING] Address match confirmed for round {}",
                                                round
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!("❌ [SIGNING] Failed to recover sender from signature for round {}: {}", round, e);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(Some(signed_tx_hex))
            } else {
                warn!(
                    "❌ [SIGNING] Node {} expected TICS transaction for round {} but got different type",
                    self.id, round
                );
                Ok(None)
            }
        } else {
            warn!(
                "❌ [SIGNING] Node {} cannot reconstruct TICS transaction for round {} - original transaction not found",
                self.id, round
            );
            Ok(None)
        }
    }

    /// Reconstruct signed TICS tx for one TICS UserToVault batch slot (round, intent_hash).
    pub async fn reconstruct_signed_tics_transaction_for_batch_slot(
        &self,
        round: u64,
        slot_id: &str,
        aggregated_signature: &[u8],
        recovery_id: u8,
    ) -> Result<Option<String>> {
        // Nodes without a DKG share may not have batch data yet — poll up to ~5s
        let has_dkg = self.has_dkg_share().await;
        let max_attempts = if has_dkg { 1 } else { 50 };

        let (_intent_hash, user_eth, chain_tx, _tx_bytes) = {
            let mut result = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                let batch = self.pending.user_to_vault_tics_batch.read().await;
                if let Some(entries) = batch.get(&round) {
                    if let Some(entry) = entries.iter().find(|(h, ..)| h == slot_id) {
                        if attempt > 0 {
                            debug!(
                                "✅ [SIGNING] Found TICS batch data for round {} slot {} after {} attempts (~{}ms)",
                                round, slot_id, attempt + 1, attempt * 100
                            );
                        }
                        result = Some((entry.0.clone(), entry.1.clone(), entry.2.clone(), entry.3.clone()));
                        break;
                    }
                }
                if attempt == max_attempts - 1 && !has_dkg {
                    warn!(
                        "⚠️ [SIGNING] Could not find TICS batch data for round {} slot {} after {}ms",
                        round, slot_id, max_attempts * 100
                    );
                }
            }
            result.ok_or_else(|| anyhow!("No TICS UserToVault batch for round {} slot {}", round, slot_id))?
        };
        let ChainTransaction::Tics(original_tx) = &chain_tx else {
            return Ok(None);
        };
        let r = &aggregated_signature[0..32];
        let s = &aggregated_signature[32..64];
        let chain_id = original_tx.chain_id;
        let v = recovery_id as u64 + 35 + chain_id * 2;
        let user_derived_address = if let Some(user_intent_manager) = &self.user_intent_manager {
            if let Some(user) = user_intent_manager.get_user_by_address(&user_eth).await {
                if let Some(derived_eth_addr) = &user.derived_eth_address {
                    Self::fetch_nonce_and_log(
                        derived_eth_addr,
                        chain_id,
                        "UserToVault batch slot",
                    )
                    .await?
                } else {
                    return Err(anyhow!(
                        "User {} has no derived TICS address",
                        user_eth
                    ));
                }
            } else {
                return Err(anyhow!("User {} not found in registry", user_eth));
            }
        } else {
            return Err(anyhow!("User intent manager not available"));
        };
        let user_derived_address = Some(user_derived_address);
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
            "✅ [SIGNING] Reconstructed signed tx for batch slot {} (round {})",
            slot_id, round
        );
        info!(
            "🔍 [SIGNING] Raw signed tx hex for batch slot {}: {}",
            slot_id, signed_tx_hex
        );
        // Recover sender address from the signed transaction for debugging
        {
            // Re-create the unsigned tx bytes (EIP-155 signing hash)
            let unsigned_tx_bytes = crate::utils::transaction::create_transaction_for_signing(
                &crate::chain_abstraction::TicsTransaction {
                    to: original_tx.to.clone(),
                    value: original_tx.value.clone(),
                    nonce: original_tx.nonce,
                    gas_limit: original_tx.gas_limit,
                    gas_price: original_tx.gas_price.clone(),
                    chain_id: original_tx.chain_id,
                    data: original_tx.data.clone(),
                },
            );
            let mut hasher = sha3::Keccak256::new();
            hasher.update(&unsigned_tx_bytes);
            let tx_hash = hasher.finalize();
            info!(
                "🔍 [SIGNING] Unsigned tx hash for batch slot {}: 0x{}",
                slot_id, hex::encode(&tx_hash)
            );
            info!(
                "🔍 [SIGNING] Signature r: 0x{}, s: 0x{}, v: {} (recovery_id: {})",
                hex::encode(r), hex::encode(s), v, recovery_id
            );
            if let Ok(msg) = Message::from_digest_slice(&tx_hash) {
                let secp = Secp256k1::new();
                let recid_for_recover = (v - 35 - chain_id * 2) as u8;
                if let Ok(rid) = secp256k1::ecdsa::RecoveryId::from_i32(recid_for_recover as i32) {
                    let mut sig_bytes_64 = [0u8; 64];
                    sig_bytes_64[0..32].copy_from_slice(r);
                    sig_bytes_64[32..64].copy_from_slice(s);
                    if let Ok(rec_sig) = RecoverableSignature::from_compact(&sig_bytes_64, rid) {
                        match secp.recover_ecdsa(&msg, &rec_sig) {
                            Ok(pubkey) => {
                                let pub_bytes = pubkey.serialize_uncompressed();
                                let mut keccak = sha3::Keccak256::new();
                                keccak.update(&pub_bytes[1..]);
                                let hash = keccak.finalize();
                                let recovered_addr = format!("0x{}", hex::encode(&hash[12..]));
                                info!(
                                    "🔍 [SIGNING] Recovered sender address for batch slot {}: {}",
                                    slot_id, recovered_addr
                                );
                                if let Some(derived) = &user_derived_address {
                                    if recovered_addr.to_lowercase() != derived.to_lowercase() {
                                        error!(
                                            "❌ [SIGNING] ADDRESS MISMATCH for batch slot {}! Recovered: {} vs Expected derived: {}",
                                            slot_id, recovered_addr, derived
                                        );
                                    } else {
                                        info!(
                                            "✅ [SIGNING] Address match confirmed for batch slot {}",
                                            slot_id
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!("❌ [SIGNING] Failed to recover sender from signature for batch slot {}: {}", slot_id, e);
                            }
                        }
                    }
                }
            }
        }
        Ok(Some(signed_tx_hex))
    }

    #[deprecated(
        since = "0.1.0",
        note = "Synchronous signing without an explicit nonce is disabled. Use create_ecdsa_signature_with_key_async."
    )]
    pub fn create_ecdsa_signature_with_key(
        &self,
        message: &Message,
        _transaction: &TicsTransaction,
        _signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        let _ = message;
        Err(anyhow!(
            "Synchronous signing API is disabled: use create_ecdsa_signature_with_key_async with coordinator-reserved nonces"
        ))
    }

    /// DEPRECATED: Synchronous version uses fixed k which is a SECURITY VULNERABILITY.
    /// Use create_ecdsa_signature_with_key_contract_async instead.
    #[deprecated(
        since = "0.1.0",
        note = "Fixed k is insecure. Use create_ecdsa_signature_with_key_contract_async instead."
    )]
    pub fn create_ecdsa_signature_with_key_contract(
        &self,
        message: &Message,
        _transaction: &ContractTransaction,
        _signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        let _ = message;
        // SECURITY: This function now returns an error - nonces are mandatory
        error!("🔴 [SIGNING] create_ecdsa_signature_with_key_contract called - this uses fixed k which is INSECURE");
        Err(anyhow!(
            "Synchronous contract signing API is disabled: use create_ecdsa_signature_with_key_contract_async"
        ))
    }

    /// Async version of create_ecdsa_signature_with_key that acquires a random nonce.
    ///
    /// Acquires a nonce from the pool for secure random signing.
    /// SECURITY: Fixed k fallback has been removed.
    pub async fn create_ecdsa_signature_with_key_async(
        &self,
        message: &Message,
        _transaction: &TicsTransaction,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        // Acquire nonce from pool
        let nonce_tuple = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.acquire_nonce().await {
                Ok(Some(tuple)) => {
                    info!(
                        "🔐 [SIGNING] Acquired nonce {} for contract signing",
                        tuple.tuple_id
                    );
                    tuple
                }
                Ok(None) => {
                    error!("🔴 [SIGNING] No nonce available - CANNOT SIGN (fixed k removed for security)");
                    return Err(anyhow!("Nonce is required for signing - fixed k fallback has been removed for security"));
                }
                Err(e) => {
                    error!("🔴 [SIGNING] Failed to acquire nonce: {} - CANNOT SIGN (fixed k removed for security)", e);
                    return Err(anyhow!("Failed to acquire nonce: {} - fixed k fallback has been removed for security", e));
                }
            }
        } else {
            error!("🔴 [SIGNING] NonceManager not available - CANNOT SIGN (fixed k removed for security)");
            return Err(anyhow!("NonceManager not available - fixed k fallback has been removed for security"));
        };

        self.create_ecdsa_signature_with_nonce(message, signing_key, &nonce_tuple)
    }

    /// Async version of create_ecdsa_signature_with_key_contract that acquires a random nonce.
    ///
    /// Acquires a nonce from the pool for secure random signing.
    /// SECURITY: Fixed k fallback has been removed.
    pub async fn create_ecdsa_signature_with_key_contract_async(
        &self,
        message: &Message,
        _transaction: &ContractTransaction,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        // Acquire nonce from pool
        let nonce_tuple = if let Some(nm) = &self.nonce_manager {
            let nm_guard = nm.lock().await;
            match nm_guard.acquire_nonce().await {
                Ok(Some(tuple)) => {
                    info!(
                        "🔐 [SIGNING] Acquired nonce {} for contract signing",
                        tuple.tuple_id
                    );
                    tuple
                }
                Ok(None) => {
                    error!("🔴 [SIGNING] No nonce available - CANNOT SIGN (fixed k removed for security)");
                    return Err(anyhow!("Nonce is required for signing - fixed k fallback has been removed for security"));
                }
                Err(e) => {
                    error!("🔴 [SIGNING] Failed to acquire nonce: {} - CANNOT SIGN (fixed k removed for security)", e);
                    return Err(anyhow!("Failed to acquire nonce: {} - fixed k fallback has been removed for security", e));
                }
            }
        } else {
            error!("🔴 [SIGNING] NonceManager not available - CANNOT SIGN (fixed k removed for security)");
            return Err(anyhow!("NonceManager not available - fixed k fallback has been removed for security"));
        };

        self.create_ecdsa_signature_with_nonce(message, signing_key, &nonce_tuple)
    }

    /// DEPRECATED: Synchronous version uses fixed k which is insecure.
    /// Use create_partial_ecdsa_for_tics_slot_with_nonce instead.
    #[deprecated(
        since = "0.1.0",
        note = "Fixed k is insecure. Use create_partial_ecdsa_for_tics_slot_with_nonce instead."
    )]
    #[allow(dead_code)]
    fn create_partial_ecdsa_for_tics_slot_deprecated(
        &self,
        tx_bytes: &[u8],
        transaction: &TicsTransaction,
        signing_key: &SecretKey,
        user_tics_address: Option<String>,
    ) -> Result<ECDSASignature> {
        // SECURITY: This function is deprecated - uses fixed k
        error!("🔴 [SIGNING] create_partial_ecdsa_for_tics_slot_DEPRECATED called - this uses fixed k which is INSECURE");
        let mut hasher = sha3::Keccak256::new();
        hasher.update(tx_bytes);
        let tx_hash = hasher.finalize();
        let msg = Message::from_digest_slice(tx_hash.as_slice())?;
        let signature = self.create_ecdsa_signature_with_key(&msg, transaction, signing_key)?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        Ok(ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_tics_address,
        })
    }

    /// Async version of create_partial_ecdsa_for_tics_slot that acquires a random nonce
    pub async fn create_partial_ecdsa_for_tics_slot_async(
        &self,
        tx_bytes: &[u8],
        transaction: &TicsTransaction,
        signing_key: &SecretKey,
        user_tics_address: Option<String>,
    ) -> Result<ECDSASignature> {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(tx_bytes);
        let tx_hash = hasher.finalize();
        let msg = Message::from_digest_slice(tx_hash.as_slice())?;
        let signature = self.create_ecdsa_signature_with_key_async(&msg, transaction, signing_key).await?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        Ok(ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_tics_address,
        })
    }

    /// TICS UserToVault batch: one round, multiple slots. Store batch, create partial per slot, store in
    /// signatures_by_round_slot, and send each partial to the final node with slot_id.
    pub async fn sign_tics_user_to_vault_batch(
        &mut self,
        round: u64,
        batch: Vec<(
            String,
            String,
            ChainTransaction,
            Vec<u8>,
            Option<Scalar>,
        )>,
    ) -> Result<()> {
        use crate::signing::state::RoundSlotKey;
        if batch.is_empty() {
            return Ok(());
        }
        let final_node_id = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .cloned()
                .ok_or_else(|| anyhow!("No final node for TICS UserToVault batch round {}", round))?
        };

        let batch_storage: Vec<(String, String, ChainTransaction, Vec<u8>)> = batch
            .iter()
            .map(|(h, u, tx, bytes, _key)| (h.clone(), u.clone(), tx.clone(), bytes.clone()))
            .collect();
        {
            let mut store = self.pending.user_to_vault_tics_batch.write().await;
            store.insert(round, batch_storage);
        }

        info!(
            "📦 [TICS_UTV_BATCH] Node {} signing {} slots for round {} (final node: {})",
            self.id,
            batch.len(),
            round,
            final_node_id
        );

        for (intent_hash, user_eth, chain_tx, tx_bytes, key_opt) in batch {
            let signing_key = match key_opt {
                Some(scalar) => {
                    let scalar_bytes = scalar.to_bytes();
                    info!(
                        "🔑 [TICS_UTV_BATCH] Intent {} (user {}): tweaked_share scalar_fingerprint=0x{} (no-nonce path)",
                        intent_hash, user_eth, hex::encode(&scalar_bytes[..8])
                    );
                    let secp_key = Self::derive_secp_secret(&scalar)?;
                    {
                        let secp = Secp256k1::new();
                        let pk = PublicKey::from_secret_key(&secp, &secp_key);
                        let pk_uncompressed = pk.serialize_uncompressed();
                        let mut keccak = sha3::Keccak256::new();
                        keccak.update(&pk_uncompressed[1..]);
                        let hash = keccak.finalize();
                        let signing_addr = format!("0x{}", hex::encode(&hash[12..]));
                        info!(
                            "🔑 [TICS_UTV_BATCH] Intent {} (user {}): signing_key derives ETH address: {} (no-nonce path)",
                            intent_hash, user_eth, signing_addr
                        );
                    }
                    secp_key
                }
                None => {
                    warn!(
                        "⚠️ [TICS_UTV_BATCH] No signing key for intent {} (user {}), skipping",
                        intent_hash, user_eth
                    );
                    continue;
                }
            };
            let eth_tx = match &chain_tx {
                ChainTransaction::Tics(t) => t,
                _ => {
                    warn!(
                        "⚠️ [TICS_UTV_BATCH] Intent {} is not TICS, skipping",
                        intent_hash
                    );
                    continue;
                }
            };
            let ecdsa_sig = self.create_partial_ecdsa_for_tics_slot_async(
                &tx_bytes,
                eth_tx,
                &signing_key,
                Some(user_eth.clone()),
            ).await?;

            let slot_key: RoundSlotKey = (round, intent_hash.clone());
            {
                let mut by_slot = self.signatures.signatures_by_round_slot.write().await;
                let entry = by_slot.entry(slot_key).or_default();
                entry.insert(self.id.clone(), ecdsa_sig.clone());
            }

            let user_eth_clone = user_eth.clone();
            let signature_msg = SigningMessage::ECDSASignature {
                from: self.id.clone(),
                signature: ecdsa_sig,
                round,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                user_tics_address: Some(user_eth_clone),
                slot_id: Some(intent_hash.clone()),
            };
            let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
            let signature_data = serde_json::to_vec(&gossipsub_msg)?;
            self.broadcast("signing", &signature_data).await?;
            info!(
                "✅ [TICS_UTV_BATCH] Broadcasting partial for slot {} (round {}): final node {} will aggregate",
                intent_hash, round, final_node_id
            );

            // Send TX data for this slot to the final node for threshold verification.
            {
                let chain_tx_json = serde_json::to_string(&chain_tx).ok();
                let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                    from: self.id.clone(),
                    round,
                    tx_bytes: tx_bytes.clone(),
                    intent_hash: Some(intent_hash.clone()),
                    transaction_type: Some("UserToVault".to_string()),
                    request_id: None,
                    chain_tx_json,
                    user_tics_address: Some(user_eth),
                    batch_identifiers: None,
                };
                let tx_data_gossip = crate::types::GossipsubMessage::Signing(tx_data_msg);
                let tx_data_bytes = serde_json::to_vec(&tx_data_gossip)?;
                self.broadcast("signing", &tx_data_bytes).await?;
            }
        }
        Ok(())
    }

    /// TICS UserToVault batch with nonce assignments for coordinated signing.
    ///
    /// When nonce_assignments contains an entry for an intent_hash, all nodes will use
    /// the same nonce tuple, enabling proper threshold signature aggregation with random k.
    pub async fn sign_tics_user_to_vault_batch_with_nonces(
        &mut self,
        round: u64,
        batch: Vec<(
            String,
            String,
            ChainTransaction,
            Vec<u8>,
            Option<Scalar>,
        )>,
        nonce_assignments: std::collections::HashMap<String, Vec<String>>,
    ) -> Result<()> {
        use crate::signing::state::RoundSlotKey;
        if batch.is_empty() {
            return Ok(());
        }

        let has_nonce_assignments = !nonce_assignments.is_empty();
        if has_nonce_assignments {
            info!(
                "🔐 [TICS_UTV_BATCH] Using coordinated nonces for {} intents",
                nonce_assignments.len()
            );
        }

        let final_node_id = {
            let final_nodes = self.signatures.final_nodes_by_round.read().await;
            final_nodes
                .get(&round)
                .cloned()
                .ok_or_else(|| anyhow!("No final node for TICS UserToVault batch round {}", round))?
        };

        let batch_storage: Vec<(String, String, ChainTransaction, Vec<u8>)> = batch
            .iter()
            .map(|(h, u, tx, bytes, _key)| (h.clone(), u.clone(), tx.clone(), bytes.clone()))
            .collect();
        let batch_slot_count = batch_storage.len();
        {
            let mut store = self.pending.user_to_vault_tics_batch.write().await;
            store.insert(round, batch_storage);
        }

        // Check if this node has a DKG share (needed for signing, not for TX building/storage)
        let has_dkg = self.has_dkg_share().await;

        info!(
            "📦 [TICS_UTV_BATCH] Node {} {} {} slots for round {} (final node: {}, coordinated: {})",
            self.id,
            if has_dkg { "signing" } else { "preparing (observer)" },
            batch.len(),
            round,
            final_node_id,
            has_nonce_assignments
        );

        // DKG nodes: sign each slot and broadcast signatures + TX data
        // Non-DKG nodes: batch data is already stored above — skip signing
        if has_dkg {
            for (intent_hash, user_eth, chain_tx, tx_bytes, key_opt) in batch {
                let signing_key = match key_opt {
                    Some(scalar) => {
                        let scalar_bytes = scalar.to_bytes();
                        info!(
                            "🔑 [TICS_UTV_BATCH] Intent {} (user {}): tweaked_share scalar_fingerprint=0x{}",
                            intent_hash, user_eth, hex::encode(&scalar_bytes[..8])
                        );
                        let secp_key = Self::derive_secp_secret(&scalar)?;
                        // Derive the ETH address this signing key corresponds to
                        {
                            let secp = Secp256k1::new();
                            let pk = PublicKey::from_secret_key(&secp, &secp_key);
                            let pk_uncompressed = pk.serialize_uncompressed();
                            let mut keccak = sha3::Keccak256::new();
                            keccak.update(&pk_uncompressed[1..]);
                            let hash = keccak.finalize();
                            let signing_addr = format!("0x{}", hex::encode(&hash[12..]));
                            info!(
                                "🔑 [TICS_UTV_BATCH] Intent {} (user {}): signing_key derives ETH address: {}",
                                intent_hash, user_eth, signing_addr
                            );
                        }
                        secp_key
                    }
                    None => {
                        warn!(
                            "⚠️ [TICS_UTV_BATCH] No signing key for intent {} (user {}), skipping",
                            intent_hash, user_eth
                        );
                        continue;
                    }
                };
                let eth_tx = match &chain_tx {
                    ChainTransaction::Tics(t) => t,
                    _ => {
                        warn!(
                            "⚠️ [TICS_UTV_BATCH] Intent {} is not TICS, skipping",
                            intent_hash
                        );
                        continue;
                    }
                };

                // Get the assigned nonce for this intent - REQUIRED for security
                let nonce_tuple = if let Some(tuple_ids) = nonce_assignments.get(&intent_hash) {
                    let Some(tuple_id) = tuple_ids.first() else {
                        error!("🔴 [TICS_UTV_BATCH] Empty nonce assignment list for intent {}, SKIPPING", intent_hash);
                        continue;
                    };
                    info!(
                        "🔍 [TICS_UTV_BATCH] Intent {} has nonce assignment: {}",
                        intent_hash, tuple_id
                    );
                    // Acquire the specific nonce assigned by coordinator
                    if let Some(nm) = &self.nonce_manager {
                        let nm_guard = nm.lock().await;
                        match nm_guard.acquire_specific_nonce(tuple_id).await {
                            Ok(Some(tuple)) => {
                                info!(
                                    "🔐 [TICS_UTV_BATCH] Using coordinated nonce {} for intent {} (r_scalar: 0x{})",
                                    tuple.tuple_id, intent_hash, hex::encode(tuple.r_scalar.0.to_bytes())
                                );
                                tuple
                            }
                            Ok(None) => {
                                error!(
                                    "🔴 [TICS_UTV_BATCH] Nonce {} not found in local pool for intent {}, SKIPPING (fixed k removed for security)",
                                    tuple_id, intent_hash
                                );
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "🔴 [TICS_UTV_BATCH] Failed to acquire nonce {} for intent {}: {}, SKIPPING (fixed k removed for security)",
                                    tuple_id, intent_hash, e
                                );
                                continue;
                            }
                        }
                    } else {
                        error!(
                            "🔴 [TICS_UTV_BATCH] NonceManager not available for intent {}, SKIPPING (fixed k removed for security)",
                            intent_hash
                        );
                        continue;
                    }
                } else {
                    error!(
                        "🔴 [TICS_UTV_BATCH] No nonce assignment for intent {}, SKIPPING (fixed k removed for security)",
                        intent_hash
                    );
                    continue;
                };

                // Sign with coordinated nonce (fixed k fallback removed for security)
                let ecdsa_sig = self.create_partial_ecdsa_for_tics_slot_with_nonce(
                    &tx_bytes,
                    eth_tx,
                    &signing_key,
                    Some(user_eth.clone()),
                    &nonce_tuple,
                ).await?;

                let slot_key: RoundSlotKey = (round, intent_hash.clone());
                {
                    let mut by_slot = self.signatures.signatures_by_round_slot.write().await;
                    let entry = by_slot.entry(slot_key).or_default();
                    entry.insert(self.id.clone(), ecdsa_sig.clone());
                }

                let user_eth_clone = user_eth.clone();
                let signature_msg = SigningMessage::ECDSASignature {
                    from: self.id.clone(),
                    signature: ecdsa_sig,
                    round,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                    user_tics_address: Some(user_eth_clone),
                    slot_id: Some(intent_hash.clone()),
                };
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;
                self.broadcast("signing", &signature_data).await?;
                info!(
                    "✅ [TICS_UTV_BATCH] Broadcasting partial for slot {} (round {}): final node {} will aggregate",
                    intent_hash, round, final_node_id
                );

                // Send TX data for this slot to the final node for threshold verification.
                // All DKG nodes broadcast their TX data; the final node accepts it once
                // threshold matching copies arrive. This enables observer final nodes to
                // reconstruct signed transactions without building TXs locally.
                {
                    let chain_tx_json = serde_json::to_string(&chain_tx).ok();
                    let tx_data_msg = SigningMessage::TransactionDataForFinalNode {
                        from: self.id.clone(),
                        round,
                        tx_bytes: tx_bytes.clone(),
                        intent_hash: Some(intent_hash.clone()),
                        transaction_type: Some("UserToVault".to_string()),
                        request_id: None,
                        chain_tx_json,
                        user_tics_address: Some(user_eth),
                        batch_identifiers: None,
                    };
                    let tx_data_gossip = crate::types::GossipsubMessage::Signing(tx_data_msg);
                    let tx_data_bytes = serde_json::to_vec(&tx_data_gossip)?;
                    self.broadcast("signing", &tx_data_bytes).await?;
                }
            }
        } else {
            debug!(
                "ℹ️ [TICS_UTV_BATCH] Stored batch data for round {} ({} slots) — signing skipped (no DKG share)",
                round, batch_slot_count
            );
        }
        Ok(())
    }

    /// Create partial ECDSA signature for a TICS UserToVault slot using a specific nonce tuple.
    /// Uses an explicit, coordinator-provided nonce tuple.
    async fn create_partial_ecdsa_for_tics_slot_with_nonce(
        &self,
        tx_bytes: &[u8],
        _transaction: &TicsTransaction,
        signing_key: &SecretKey,
        user_tics_address: Option<String>,
        nonce_tuple: &crate::types::nonce::NonceTuple,
    ) -> Result<ECDSASignature> {
        use sha3::Digest;

        let mut hasher = sha3::Keccak256::new();
        hasher.update(tx_bytes);
        let tx_hash = hasher.finalize();
        let msg = Message::from_digest_slice(tx_hash.as_slice())?;

        let signature = self.create_ecdsa_signature_with_nonce(&msg, signing_key, nonce_tuple)?;

        let (recovery_id, signature_bytes) = signature.serialize_compact();
        Ok(ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_tics_address,
        })
    }
}
