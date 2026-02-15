use crate::node_selection::NodeMembership;
use crate::protocols::DKGNode;
use crate::signing::SigningNode;
use crate::types::{DepositIntent, TransactionType};
use anyhow::Result;
use k256::ProjectivePoint;

/// Global function to execute contract call for a given transaction type and intent
/// This function delegates to MpcChainExecutor to keep contract execution
/// logic separate from networking concerns.
///
/// This is a convenience wrapper that can be accessed from anywhere in the codebase.
///
/// NOTE: This is a legacy path. The nonce_tuple_id parameter is required for
/// coordinated threshold signing. For production use, callers should use the
/// batch flow which handles nonce coordination automatically.
pub async fn execute_contract_call_for_transaction(
    signing_node: &mut SigningNode,
    node_manager: &dyn NodeMembership,
    dkg_node: Option<&DKGNode>,
    intent: &DepositIntent,
    intent_hash: &str,
    transaction_type: TransactionType,
    vault_group_key: Option<ProjectivePoint>,
    amount: u128,
    target_amount: Option<u128>,
    tx_hash: &[u8],
    nonce_tuple_id: Option<String>,
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
        target_amount,
        &tx_hash_str,
        None, // No request_id for non-sequencer call
        None, // No original_request for non-sequencer call
        nonce_tuple_id, // Coordinated nonce (required for signing)
    )
    .await
}
