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
    )
    .await
}

/// Execute a refund intent contract call
/// This calls the refundIntent method on the IntentManager contract
///
/// # Arguments
/// * `signing_node` - The signing node to use for MPC signing
/// * `node_manager` - Node membership manager
/// * `dkg_node` - Optional DKG node for vault tweaked share
/// * `intent_id` - The intent ID to refund
/// * `transaction_hash` - The transaction hash associated with the refund
/// * `timestamp` - Timestamp as a string
/// * `reason` - Reason for the refund
/// * `vault_group_key` - Optional vault group public key
pub async fn execute_refund_intent_contract_call(
    signing_node: &mut SigningNode,
    node_manager: &dyn NodeMembership,
    dkg_node: Option<&DKGNode>,
    intent_id: &str,
    transaction_hash: &str,
    timestamp: &str,
    reason: &str,
    vault_group_key: Option<ProjectivePoint>,
    request_id: Option<String>,
    _original_request: Option<()>,
) -> Result<()> {
    use crate::signing::EthereumSigner;
    use crate::utils::get_eth_address_from_group_key;
    use crate::utils::transaction::{
        create_transaction_for_signing_contract, encode_refund_intent_calldata,
        estimate_gas_for_deposit_intent, fetch_ethereum_nonce, get_chain_id_from_name,
        get_gas_price_for_chain,
    };
    use tracing::{debug, info};

    info!(
        "📝 [REFUND_CONTRACT] Executing refund intent contract call for intent: {}",
        intent_id
    );

    // Group public key is required for contract call transactions
    let group_key = vault_group_key.ok_or_else(|| {
        anyhow::anyhow!("Group public key required for refund intent contract call")
    })?;
    let network_address = get_eth_address_from_group_key(group_key);
    let chain_id = get_chain_id_from_name("qubetics")
        .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: qubetics"))?;

    // Get contract address from environment variable
    let contract_address_env = std::env::var("INTENT_MANAGER_CONTRACT_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    info!(
        "[execute_refund_intent_contract_call] encode_refund_intent_calldata params:\n  intent_id: {}\n  transaction_hash: {}\n  timestamp: {}\n  reason: {}",
        intent_id, transaction_hash, timestamp, reason
    );

    info!("🔧 [REFUND_CONTRACT] Network address: {}", network_address);
    info!("🔧 [REFUND_CONTRACT] Chain ID: {}", chain_id);

    // Encode refund intent calldata
    let calldata = encode_refund_intent_calldata(intent_id, transaction_hash, timestamp, reason);

    let calldata_hex = calldata
        .as_ref()
        .map(|d| format!("0x{}", hex::encode(d)))
        .unwrap_or_else(|| "0x".to_string());

    let estimated_gas = estimate_gas_for_deposit_intent(
        &network_address,
        &contract_address_env,
        &calldata_hex,
        chain_id,
    )
    .await?;
    let gas_limit = estimated_gas + (estimated_gas / 10); // Add 10% buffer

    info!(
        "🔧 [REFUND_CONTRACT] Using gas_limit: {}",
        gas_limit
    );

    let nonce = fetch_ethereum_nonce(&network_address, chain_id).await?;
    let gas_price_str = get_gas_price_for_chain("qubetics", chain_id).await?;

    info!(
        "🔧 [REFUND_CONTRACT] Nonce: {}, Gas price: {}",
        nonce, gas_price_str
    );

    // Create contract transaction
    let contract_tx = crate::types::ContractTransaction {
        to: contract_address_env,
        value: "0x0".to_string(),
        nonce,
        gas_limit,
        gas_price: gas_price_str,
        chain_id,
        data: calldata_hex,
    };

    let contract_tx_bytes = create_transaction_for_signing_contract(&contract_tx);
    debug!(
        "→ RLP payload refund contract call: 0x{}",
        hex::encode(&contract_tx_bytes)
    );

    // Get vault tweaked share from DKG node if available
    let vault_tweaked_share = if let Some(dkg_node) = dkg_node {
        dkg_node.get_vault_tweaked_secret_share().await
    } else {
        None
    };

    // Update signing node with available nodes from network
    let available_nodes: Vec<libp2p::PeerId> =
        node_manager.get_active_nodes().into_iter().collect();
    signing_node.set_available_nodes(available_nodes);

    // Get contract chain handler from signing node
    let contract_chain_handler = signing_node.get_contract_chain_handler().clone();

        // Execute the signing operation (retry metadata no longer used)
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
            None, // tics_withdraw_identifiers (not applicable)
        )
        .await?;

    info!(
        "✅ [REFUND_CONTRACT] Successfully executed refund intent contract call for intent: {}",
        intent_id
    );

    Ok(())
}
