pub const USER_REGISTRATION_PREFIX: &[u8] = b"user:";
pub const INTENT_REGISTRY_PREFIX: &[u8] = b"intent:";
pub const USER_INTENT_HASH_PREFIX: &[u8] = b"user_intent:";
pub const INTENT_TRANSACTION_IDS_PREFIX: &[u8] = b"intent_txids:";
pub const TRANSACTION_STATUS_PREFIX: &[u8] = b"tx_status:";
pub const PUBLIC_KEY_PREFIX: &[u8] = b"pubkey:";
pub const SIGNATURE_PREFIX: &[u8] = b"sig:";
pub const SIGNATURE_ROUND_PREFIX: &[u8] = b"sig_round:";
pub const FINAL_NODE_ROUND_PREFIX: &[u8] = b"final_node:";
pub const PENDING_TRANSACTION_PREFIX: &[u8] = b"pending_tx:";
pub const CONSENSUS_ROUND_PREFIX: &[u8] = b"consensus:";
pub const CONSENSUS_RESULT_PREFIX: &[u8] = b"consensus_result:";
pub const SELECTED_NODES_PREFIX: &[u8] = b"selected_nodes:";
pub const DKG_SHARE_PREFIX: &[u8] = b"dkg_share:";
pub const DKG_COMMITMENT_PREFIX: &[u8] = b"dkg_commitment:";
pub const DKG_VALIDATION_PREFIX: &[u8] = b"dkg_validation:";
pub const DKG_FINAL_SECRET_PREFIX: &[u8] = b"dkg_final_secret";
pub const DKG_FINAL_PUBLIC_PREFIX: &[u8] = b"dkg_final_public";
pub const DKG_VAULT_ETH_ADDRESS_PREFIX: &[u8] = b"dkg_vault_eth_address";
pub const DKG_VAULT_BTC_ADDRESS_PREFIX: &[u8] = b"dkg_vault_btc_address";
pub const DKG_VAULT_TWEAKED_SECRET_PREFIX: &[u8] = b"dkg_vault_tweaked_secret";
pub const DKG_VAULT_GROUP_KEY_PREFIX: &[u8] = b"dkg_vault_group_key";
pub const SOLVER_AMOUNTS_PREFIX: &[u8] = b"solver_amounts:";
pub const CURRENT_ROUND_PREFIX: &[u8] = b"current_round";
pub const AGGREGATED_ROUND_PREFIX: &[u8] = b"aggregated_round:";
pub const TOTAL_LIQUIDITY_TICS_PREFIX: &[u8] = b"total_liquidity_tics";
pub const TOTAL_LIQUIDITY_BTC_PREFIX: &[u8] = b"total_liquidity_btc";
pub const SOLVER_REWARD_PREFIX: &[u8] = b"solver_reward:";
pub const SOLVER_REWARD_TICS_PREFIX: &[u8] = b"solver_reward_tics:";
pub const SOLVER_REWARD_BTC_PREFIX: &[u8] = b"solver_reward_btc:";
pub const CLAIMED_REQUEST_AMOUNT_PREFIX: &[u8] = b"claimed_request_amount:";
pub const INTENT_REWARD_STATUS_PREFIX: &[u8] = b"intent_reward_status:";

pub const SOLVER_TICS_TXN_HASHES_PREFIX: &[u8] = b"solver_tics_txn_hashes:";
pub const SOLVER_BTC_TXN_HASHES_PREFIX: &[u8] = b"solver_btc_txn_hashes:";

pub const PEER_KEYPAIR_PREFIX: &[u8] = b"peer_keypair";

pub const ALL_SOLVER_AMOUNTS_PREFIX: &[u8] = b"solver_amounts:all";
pub const ALL_SOLVER_LIQUIDITY_PREFIX: &[u8] = b"solver_liquidity:all";
pub const SOLVER_LIQUIDITY_PREFIX: &[u8] = b"solver_liquidity:";
pub const LIQUIDITY_LAST_UPDATE_PREFIX: &[u8] = b"liquidity_last_update";

pub const DKG_POLYNOMIAL_PREFIX: &[u8] = b"dkg_polynomial";
pub const DKG_INITIAL_COMPLETE_PREFIX: &[u8] = b"dkg_initial_complete";
pub const DKG_MY_PERMANENT_INDEX_PREFIX: &[u8] = b"dkg_my_permanent_index";
pub const PEER_INDEX_PREFIX: &[u8] = b"peer_index:"; // key = peer_index:<peer_id_str>
pub const DKG_ORIGINAL_COMMITMENT_PREFIX: &[u8] = b"dkg_original_commitment:";
