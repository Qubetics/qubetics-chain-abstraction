use anyhow::Result;
use k256::ProjectivePoint;
use crate::signing::SigningNode;
use crate::node_selection::NodeMembership;
use crate::threshold_dkg::DKGNode;
use crate::types::{DepositIntent, TransactionType};

/// Global function to execute contract call for a given transaction type and intent
/// This function delegates to MpcChainExecutor to keep contract execution
/// logic separate from networking concerns.
/// 
/// This is a convenience wrapper that can be accessed from anywhere in the codebase.
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
    // Convert tx_hash from bytes to hex string for the executor
    let tx_hash_str = hex::encode(tx_hash);
    
    crate::chain_abstraction::MpcChainExecutor::execute_contract_call(
        signing_node,
        node_manager,
        dkg_node,
        intent,
        intent_hash,
        transaction_type,
        vault_group_key,
        amount,
        &tx_hash_str,
    )
    .await
}
