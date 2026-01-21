/// MPC Chain Executor Service
/// Handles contract execution logic, separating it from networking concerns.
use anyhow::Result;
use k256::ProjectivePoint;
use libp2p::PeerId;
use tracing::{debug, info, warn};

use crate::node_selection::NodeMembership;
use crate::protocols::DKGNode;
use crate::signing::{EthereumSigner, SigningNode};
use crate::types::{ContractTransaction, DepositIntent, TransactionType};

/// Service for executing contract calls on blockchain networks
/// This service handles contract ABI assembly and signing node coordination,
/// keeping these concerns separate from the network transport layer.
pub struct MpcChainExecutor;

impl MpcChainExecutor {
    /// Execute a contract call for a given transaction type and intent.
    ///
    /// This method handles:
    /// - Contract ABI assembly (via create_chain_transaction_from_contract_call)
    /// - Signing node coordination (setting available nodes, getting vault shares)
    /// - Transaction signing
    ///
    /// It does NOT handle networking concerns - those should be handled by the caller.
    pub async fn execute_contract_call(
        signing_node: &mut SigningNode,
        node_manager: &dyn NodeMembership,
        dkg_node: Option<&DKGNode>,
        intent: &DepositIntent,
        intent_hash: &str,
        transaction_type: TransactionType,
        vault_group_key: Option<ProjectivePoint>,
        amount: u128,
        tx_hash: &str,
        request_id: Option<String>,
        _original_request: Option<()>,
    ) -> Result<()> {
        info!(
            "📝 [CHAIN_EXECUTOR] Executing contract call for transaction type: {:?}",
            transaction_type
        );

        // Small delay to allow transaction to be fully processed
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Create the chain transaction from contract call parameters
        let contract_call_result =
            crate::utils::transaction::create_chain_transaction_from_contract_call(
                vault_group_key,
                amount,
                intent,
                intent_hash,
                tx_hash,
                transaction_type.clone(),
            )
            .await;

        match contract_call_result {
            Ok(contract_transaction) => {
                info!("📝 [CHAIN_EXECUTOR] Created contract call transaction");

                // Update signing node with available nodes from network
                let available_nodes: Vec<PeerId> =
                    node_manager.get_active_nodes().into_iter().collect();
                signing_node.set_available_nodes(available_nodes);

                // Handle Ethereum transactions
                match contract_transaction {
                    crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                        let contract_tx = ContractTransaction {
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
                        debug!(
                            "→ RLP payload contract call: 0x{}",
                            hex::encode(&contract_tx_bytes)
                        );

                        // Get vault tweaked share from DKG node if available
                        let vault_tweaked_share = if let Some(dkg_node) = dkg_node {
                            dkg_node.get_vault_tweaked_secret_share().await
                        } else {
                            None
                        };

                        // Execute the signing operation (retry metadata no longer used)
                        let contract_chain_handler =
                            signing_node.get_contract_chain_handler().clone();
                        let mut eth_signer = EthereumSigner::new(signing_node);
                        eth_signer
                            .sign_contract_message(
                                contract_tx_bytes,
                                &contract_chain_handler,
                                &contract_tx,
                                vault_tweaked_share,
                                None,
                                vec![],
                                vault_tweaked_share,
                                request_id,
                                None,
                            )
                            .await?;
                    }
                    _ => {
                        info!(
                            "📝 [CHAIN_EXECUTOR] Contract call transaction is not Ethereum type, skipping"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    "❌ [CHAIN_EXECUTOR] Failed to create contract call transaction: {}",
                    e
                );
            }
        }

        Ok(())
    }
}
