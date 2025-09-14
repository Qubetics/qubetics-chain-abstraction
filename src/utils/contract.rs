use anyhow::Result;
use k256::ProjectivePoint;
use crate::rpc_server::DepositIntent;
use crate::types::TransactionType;
use crate::signing::SigningNode;
use crate::node_management::NodeMembership;
use crate::adkg_secp256k1::DKGNode;
use libp2p::PeerId;
use tracing::{info, warn, debug};

/// Global function to execute contract call for a given transaction type and intent
/// This function can be accessed from anywhere in the codebase
pub async fn execute_contract_call_for_transaction(
    signing_node: &mut SigningNode,
    node_manager: &dyn NodeMembership,
    dkg_node: Option<&DKGNode>,
    intent: &DepositIntent,
    intent_hash: &str,
    transaction_type: TransactionType,
    vault_group_key: Option<ProjectivePoint>,
    amount: u128,
    tx_hash: &[u8],
) -> Result<()> {
    info!("📝 [CONTRACT] Executing contract call for transaction type: {:?}", transaction_type);

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(
        vault_group_key, 
        amount, 
        intent, 
        intent_hash, 
        tx_hash.to_vec(), 
        transaction_type.clone()
    ).await;

    match contract_call_result {
        Ok(contract_transaction) => {
            info!("📝 [CONTRACT] Created contract call transaction");   
            let available_nodes: Vec<PeerId> = node_manager.get_active_nodes().into_iter().collect();
            signing_node.set_available_nodes(available_nodes);
                                    
            match contract_transaction {
                crate::chain::ChainTransaction::Ethereum(ref eth_tx) => {
                    let contract_tx = crate::rpc_server::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        nonce: eth_tx.nonce,
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        chain_id: eth_tx.chain_id,
                        data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                    };
                    let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                    debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                    let vault_tweaked_share = if let Some(dkg_node) = dkg_node {
                        dkg_node.get_vault_tweaked_secret_share().await
                    } else {
                        None
                    };
                    signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                }
                _ => {
                    info!("📝 [CONTRACT] Contract call transaction is not Ethereum type, skipping");
                }
            }
        }
        Err(e) => {
            warn!("❌ [CONTRACT] Failed to create contract call transaction: {}", e);
        }
    }
    
    Ok(())
}
