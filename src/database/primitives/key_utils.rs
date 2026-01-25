use super::keys;

/// Utility helpers for building typed database keys.
pub fn user_key(ethereum_address: &str) -> String {
    format!("{}{}", keys::USER_REGISTRATION, ethereum_address)
}

pub fn intent_key(intent_hash: &str) -> String {
    format!("{}{}", keys::INTENT_REGISTRY, intent_hash)
}

pub fn user_intent_key(ethereum_address: &str, intent_hash: &str) -> String {
    format!(
        "{}{}:{}",
        keys::USER_INTENT_HASH,
        ethereum_address,
        intent_hash
    )
}

/// Reverse index key: intent_hash -> ethereum_address. Enables O(1) get_user_by_intent_hash
/// instead of scanning all users, reducing races and signature verification failures under load.
pub fn intent_hash_to_user_key(intent_hash: &str) -> String {
    format!("{}{}", keys::INTENT_HASH_TO_USER, intent_hash)
}

pub fn intent_transaction_ids_key(intent_hash: &str) -> String {
    format!("{}{}", keys::INTENT_TRANSACTION_IDS, intent_hash)
}

pub fn transaction_status_key(tx_hash: &str) -> String {
    format!("{}{}", keys::TRANSACTION_STATUS, tx_hash)
}

pub fn public_key_key(node_id: &str) -> String {
    format!("{}{}", keys::PUBLIC_KEY, node_id)
}

pub fn signature_key(node_id: &str) -> String {
    format!("{}{}", keys::SIGNATURE, node_id)
}

pub fn signature_round_key(round: u64, node_id: &str) -> String {
    format!("{}{}:{}", keys::SIGNATURE_ROUND, round, node_id)
}

pub fn final_node_round_key(round: u64) -> String {
    format!("{}{}", keys::FINAL_NODE_ROUND, round)
}

pub fn pending_transaction_key(round: u64) -> String {
    format!("{}{}", keys::PENDING_TRANSACTION, round)
}

pub fn consensus_round_key(round: u64) -> String {
    format!("{}{}", keys::CONSENSUS_ROUND, round)
}

pub fn consensus_result_key(round: u64) -> String {
    format!("{}{}", keys::CONSENSUS_RESULT, round)
}

pub fn selected_nodes_key(round: u64) -> String {
    format!("{}{}", keys::SELECTED_NODES, round)
}

pub fn solver_amounts_key(node_id: &str, solver_id: &str) -> String {
    format!("{}{}:{}", keys::SOLVER_AMOUNTS, node_id, solver_id)
}

pub fn all_solver_amounts_key(node_id: &str) -> String {
    format!("{}all:{}", keys::SOLVER_AMOUNTS, node_id)
}

pub fn total_liquidity_tics_key() -> String {
    keys::TOTAL_LIQUIDITY_TICS.to_string()
}

pub fn total_liquidity_btc_key() -> String {
    keys::TOTAL_LIQUIDITY_BTC.to_string()
}

pub fn solver_reward_key(solver_address: &str) -> String {
    format!("{}{}", keys::SOLVER_REWARD, solver_address.to_lowercase())
}

pub fn solver_reward_tics_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::SOLVER_REWARD_TICS,
        solver_address.to_lowercase()
    )
}

pub fn solver_reward_btc_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::SOLVER_REWARD_BTC,
        solver_address.to_lowercase()
    )
}

pub fn claimed_request_amount_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::CLAIMED_REQUEST_AMOUNT,
        solver_address.to_lowercase()
    )
}

pub fn intent_reward_status_key(intent_hash: &str) -> String {
    format!(
        "{}{}",
        keys::INTENT_REWARD_STATUS,
        intent_hash.to_lowercase()
    )
}

pub fn solver_tics_txn_hashes_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::SOLVER_TICS_TXN_HASHES,
        solver_address.to_lowercase()
    )
}

pub fn solver_btc_txn_hashes_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::SOLVER_BTC_TXN_HASHES,
        solver_address.to_lowercase()
    )
}


pub fn solver_remove_liquidity_tics_txn_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::SOLVER_REMOVE_LIQ_TICS_TXN,
        solver_address.to_lowercase()
    )
}

pub fn solver_remove_liquidity_btc_txn_key(solver_address: &str) -> String {
    format!(
        "{}{}",
        keys::SOLVER_REMOVE_LIQ_BTC_TXN,
        solver_address.to_lowercase()
    )
}

pub fn peer_index_key(peer_id: &str) -> String {
    format!("{}{}", keys::PEER_INDEX, peer_id)
}

pub fn peer_addr_key(peer_id: &str) -> String {
    format!("{}{}", keys::PEER_ADDR, peer_id)
}

pub fn vrf_current_round_key() -> String {
    keys::VRF_CURRENT_ROUND.to_string()
}

pub fn vrf_peer_round_key(peer_id: &str) -> String {
    format!("{}{}", keys::VRF_PEER_ROUND, peer_id)
}

pub fn node_share_pubkey_network_key(peer_id: &str) -> String {
    format!("{}{}", keys::NODE_SHARE_PUBKEY_NETWORK, peer_id)
}

pub fn node_share_pubkey_vault_key(peer_id: &str) -> String {
    format!("{}{}", keys::NODE_SHARE_PUBKEY_VAULT, peer_id)
}

pub fn node_share_pubkey_user_key(peer_id: &str, user_eth_address: &str) -> String {
    format!("{}{}:{}", keys::NODE_SHARE_PUBKEY_USER, peer_id, user_eth_address.to_lowercase())
}
