/// Database key prefixes for different data types
pub const USER_REGISTRATION: &str = "user:";
pub const INTENT_REGISTRY: &str = "intent:";
pub const USER_INTENT_HASH: &str = "user_intent:";
pub const INTENT_TRANSACTION_IDS: &str = "intent_txids:";
pub const TRANSACTION_STATUS: &str = "tx_status:";
pub const PUBLIC_KEY: &str = "pubkey:";
pub const SIGNATURE: &str = "sig:";
pub const SIGNATURE_ROUND: &str = "sig_round:";
pub const FINAL_NODE_ROUND: &str = "final_node:";
pub const PENDING_TRANSACTION: &str = "pending_tx:";
pub const CONSENSUS_ROUND: &str = "consensus:";
pub const CONSENSUS_RESULT: &str = "consensus_result:";
pub const SELECTED_NODES: &str = "selected_nodes:";
pub const DKG_SHARE: &str = "dkg_share:";
pub const DKG_COMMITMENT: &str = "dkg_commitment:";
pub const DKG_ORIGINAL_COMMITMENT: &str = "dkg_original_commitment:";
pub const DKG_VALIDATION: &str = "dkg_validation:";
pub const DKG_FINAL_SECRET: &str = "dkg_final_secret";
pub const DKG_FINAL_PUBLIC: &str = "dkg_final_public";
pub const DKG_LIQUIDITY_OPERATOR_ETH_ADDRESS: &str = "dkg_liquidity_operator_eth_address";
pub const DKG_LIQUIDITY_OPERATOR_BTC_ADDRESS: &str = "dkg_liquidity_operator_btc_address";
pub const DKG_VAULT_TWEAKED_SECRET: &str = "dkg_vault_tweaked_secret";
pub const DKG_VAULT_GROUP_KEY: &str = "dkg_vault_group_key";
pub const DKG_VAULT_ETH_ADDRESS: &str = "dkg_vault_eth_address";
pub const DKG_VAULT_BTC_ADDRESS: &str = "dkg_vault_btc_address";
pub const DKG_POLYNOMIAL: &str = "dkg_polynomial";
pub const DKG_INITIAL_COMPLETE: &str = "dkg_initial_complete";
pub const DKG_SIGNER_COUNT: &str = "dkg_signer_count";
pub const DKG_INVULNERABLES: &str = "dkg_invulnerables";
pub const DKG_MY_PERMANENT_INDEX: &str = "dkg_my_permanent_index";
pub const DKG_RECEIVED_SHARE: &str = "dkg_received_share:";
pub const DKG_EXPECTED_SHARES: &str = "dkg_expected_shares";
pub const PEER_INDEX: &str = "peer_index:";
pub const SOLVER_AMOUNTS: &str = "solver_amounts:";
pub const PEER_KEYPAIR: &str = "peer_keypair";
pub const PEER_ADDR: &str = "peer_addr:";
pub const VRF_CURRENT_ROUND: &str = "vrf_current_round";
pub const VRF_PEER_ROUND: &str = "vrf_peer_round:";
pub const NODE_SHARE_PUBKEY_NETWORK: &str = "node_share_pubkey_network:";
pub const NODE_SHARE_PUBKEY_VAULT: &str = "node_share_pubkey_vault:";
pub const NODE_SHARE_PUBKEY_USER: &str = "node_share_pubkey_user:";
/// Reverse index: intent_hash -> tics_address for O(1) get_user_by_intent_hash
pub const INTENT_HASH_TO_USER: &str = "intent_to_user:";
/// Target chain amount (in smallest units) for an intent, computed from prices per node
pub const INTENT_TARGET_AMOUNT: &str = "intent_target_amount:";

// ============================================================
// Nonce Storage Keys (for random k with additive shares)
// ============================================================

/// Prefix for storing nonce tuples: nonce_tuple:<tuple_id>
pub const NONCE_TUPLE: &str = "nonce_tuple:";
/// Prefix for nonce generation batch state: nonce_batch:<batch_id>
pub const NONCE_BATCH: &str = "nonce_batch:";
/// Prefix for nonce commitments: nonce_commitment:<batch_id>:<peer_id>
pub const NONCE_COMMITMENT: &str = "nonce_commitment:";
/// Prefix for nonce R points: nonce_r_point:<batch_id>:<peer_id>
pub const NONCE_R_POINT: &str = "nonce_r_point:";
/// Current nonce pool metrics
pub const NONCE_POOL_METRICS: &str = "nonce_pool_metrics";
/// List of available (unconsumed) nonce tuple IDs for quick lookup
pub const NONCE_AVAILABLE_IDS: &str = "nonce_available_ids";
/// Staging area for peer disconnections — written immediately when a peer disconnects.
/// Key format: "disconnection_staging:{solver_id}" — one entry per solver.
/// Cleared immediately if the peer reconnects before epoch-2 (no invalidation).
/// At epoch-2 surviving entries are promoted to PENDING_DISCONNECTION for batch processing.
pub const DISCONNECTION_STAGING: &str = "disconnection_staging:";

/// Pending peer disconnections for batch invalidation.
/// Key format: "pending_disconnection:{solver_id}" — exactly one entry per solver.
/// Promoted from DISCONNECTION_STAGING at epoch-2 (only if peer did not rejoin).
/// Deleted after successful on-chain invalidateSolverIds tx.
pub const PENDING_DISCONNECTION: &str = "pending_disconnection:";

// ============================================================
// Contract-call / solver request state (safe to sync)
// ============================================================

/// Pending solver add_liquidity requests (batchTransfer contract call)
pub const SOLVER_ADD_LIQUIDITY: &str = "solver_add_liquidity:";
/// Pending withdraw liquidity requests (removeLiquidity contract call)
pub const PENDING_WITHDRAW_LIQUIDITY: &str = "pending_withdraw_liquidity:";
/// Pending claim reward requests (contract call)
pub const PENDING_CLAIM_REWARD: &str = "pending_claim_reward:";
/// Pending admin claim-platform-fee requests.
/// Key format: "pending_claim_platform_fee:{request_id}"
pub const PENDING_CLAIM_PLATFORM_FEE: &str = "pending_claim_platform_fee:";
