//! Central defaults for environment variables. When an env var is not set, these values are used.

/// Default RPC server port (used when RPC_PORT is unset).
pub const DEFAULT_RPC_PORT: u16 = 80;

/// Default SolverManager / TICS RPC URL.
pub const DEFAULT_SOLVER_CONTRACT_RPC_URL: &str = "https://rpc.qubetics.work";
/// Default SolverManager contract address.
pub const DEFAULT_SOLVER_CONTRACT_ADDRESS: &str = "0x28118Ef00aeFA859AC80C35E05335FbCa7167eC8";
/// Default IntentManager contract address.
pub const DEFAULT_INTENT_MANAGER_CONTRACT_ADDRESS: &str = "0xbC8b59348f397C3D6bFeFC0d864a79A568d868EF";
/// Default SolverManager chain ID.
pub const DEFAULT_SOLVER_CONTRACT_CHAIN_ID: &str = "9030";

/// Default MPC Ethereum RPC URL.
pub const DEFAULT_MPC_ETHEREUM_RPC_URL: &str = "https://rpc.qubetics.work";
/// Default MPC Bitcoin broadcast API URL.
pub const DEFAULT_MPC_BITCOIN_RPC_URL: &str = "https://prod-btc-sync.qubetics.work/api/v1/tx/broadcast";
/// Default backend API base URL.
pub const DEFAULT_BACKEND_API_URL: &str = "https://prod-crypto-api.qubetics.work";
/// Default BTC UTXO API base URL.
pub const DEFAULT_BTC_UTXO_API_BASE: &str = "https://prod-crypto-api.qubetics.work";
/// Default RPC API key (for auth).
pub const DEFAULT_RPC_API_KEY: &str = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";
/// Default chain code hex (BIP32 chain code).
pub const DEFAULT_CHAIN_CODE_HEX: &str = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194abe4";
/// Default network type.
pub const DEFAULT_NETWORK_TYPE: &str = "mainnet";
/// Default DB encryption key (32-byte hex).
pub const DEFAULT_QUBETICS_DB_ENCRYPTION_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// Default global clock interval in seconds.
pub const DEFAULT_GLOBAL_CLOCK_INTERVAL_SECONDS: &str = "30";
/// Default Treasury Vault contract address.
pub const DEFAULT_TREASURY_VAULT_CONTRACT_ADDRESS: &str = "0xaCA96ae39ad3B45A24D6E315c374DB8CEbeD87CD";
/// Default max BTC withdraw entries per cycle.
pub const DEFAULT_MAX_BTC_WITHDRAW_PER_CYCLE: &str = "10";
/// Default max intents per cycle.
pub const DEFAULT_MAX_INTENTS_PER_CYCLE: &str = "13";
/// Default verification address (solver add_liquidity verification).
pub const DEFAULT_VERIFICATION_ADDRESS: &str = "0xbac113cebd9CB2fBD2a01B5CBC43D0fC0EBed5e9";
/// Default admin Ethereum address (for register_admin / platform fee signing).
pub const DEFAULT_ADMIN_PUBLIC_ADDRESS: &str = "0x3317aDd512177663544374cBaCA25814A6C4957c";
/// Default max TICS UserToVault intents per signing batch.
pub const DEFAULT_MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH: &str = "10";
/// Default max BTC UserToVault intents per signing batch.
pub const DEFAULT_MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH: &str = "10";
/// Default max BTC claim-reward requests processed per cycle.
pub const DEFAULT_MAX_BTC_CLAIM_REWARD_PER_CYCLE: &str = "10";
/// Default max add-liquidity requests per batch.
pub const DEFAULT_MAX_ADD_LIQUIDITY_BATCH: &str = "10";
/// Chain ID used for TICS EVM signing (mainnet).
pub const DEFAULT_MPC_TICS_CHAIN_ID: &str = "9030";
/// RPC URL for the TICS chain (platform-fee & TICS-chain contract calls).
pub const DEFAULT_TICS_CHAIN_RPC_URL: &str = "https://rpc.qubetics.work";
/// Chain ID for TICS chain contract calls (platform fee, etc.) — mainnet.
pub const DEFAULT_TICS_CHAIN_ID: &str = "9030";
/// Bitcoin fee rate in satoshis per vByte.
pub const DEFAULT_BTC_FEE_RATE_SAT_VB: &str = "2";

// --- Getters: return env value or default (no allocation when env is set if caller uses &str where possible).

#[inline]
pub fn solver_contract_rpc_url() -> String {
    std::env::var("SOLVER_CONTRACT_RPC_URL").unwrap_or_else(|_| DEFAULT_SOLVER_CONTRACT_RPC_URL.to_string())
}

#[inline]
pub fn solver_contract_address() -> String {
    std::env::var("SOLVER_CONTRACT_ADDRESS").unwrap_or_else(|_| DEFAULT_SOLVER_CONTRACT_ADDRESS.to_string())
}

#[inline]
pub fn intent_manager_contract_address() -> String {
    std::env::var("INTENT_MANAGER_CONTRACT_ADDRESS").unwrap_or_else(|_| DEFAULT_INTENT_MANAGER_CONTRACT_ADDRESS.to_string())
}

#[inline]
pub fn solver_contract_chain_id() -> String {
    std::env::var("SOLVER_CONTRACT_CHAIN_ID").unwrap_or_else(|_| DEFAULT_SOLVER_CONTRACT_CHAIN_ID.to_string())
}

#[inline]
pub fn mpc_ethereum_rpc_url() -> String {
    std::env::var("MPC_ETHEREUM_RPC_URL").unwrap_or_else(|_| DEFAULT_MPC_ETHEREUM_RPC_URL.to_string())
}

#[inline]
pub fn mpc_bitcoin_rpc_url() -> String {
    std::env::var("MPC_BITCOIN_RPC_URL").unwrap_or_else(|_| DEFAULT_MPC_BITCOIN_RPC_URL.to_string())
}

#[inline]
pub fn backend_api_url() -> String {
    std::env::var("BACKEND_API_URL").unwrap_or_else(|_| DEFAULT_BACKEND_API_URL.to_string())
}

#[inline]
pub fn btc_utxo_api_base() -> String {
    std::env::var("BTC_UTXO_API_BASE").unwrap_or_else(|_| DEFAULT_BTC_UTXO_API_BASE.to_string())
}

#[inline]
pub fn rpc_api_key() -> String {
    std::env::var("RPC_API_KEY").unwrap_or_else(|_| DEFAULT_RPC_API_KEY.to_string())
}

#[inline]
pub fn chain_code_hex() -> String {
    std::env::var("CHAIN_CODE_HEX").unwrap_or_else(|_| DEFAULT_CHAIN_CODE_HEX.to_string())
}

#[inline]
pub fn global_clock_interval_seconds() -> String {
    std::env::var("GLOBAL_CLOCK_INTERVAL_SECONDS").unwrap_or_else(|_| DEFAULT_GLOBAL_CLOCK_INTERVAL_SECONDS.to_string())
}

#[inline]
pub fn treasury_vault_contract_address() -> String {
    std::env::var("TREASURY_VAULT_CONTRACT_ADDRESS").unwrap_or_else(|_| DEFAULT_TREASURY_VAULT_CONTRACT_ADDRESS.to_string())
}

#[inline]
pub fn max_btc_withdraw_per_cycle() -> String {
    std::env::var("MAX_BTC_WITHDRAW_PER_CYCLE").unwrap_or_else(|_| DEFAULT_MAX_BTC_WITHDRAW_PER_CYCLE.to_string())
}

#[inline]
pub fn max_intents_per_cycle() -> String {
    std::env::var("MAX_INTENTS_PER_CYCLE").unwrap_or_else(|_| DEFAULT_MAX_INTENTS_PER_CYCLE.to_string())
}

#[inline]
pub fn verification_address() -> String {
    std::env::var("VERIFICATION_ADDRESS").unwrap_or_else(|_| DEFAULT_VERIFICATION_ADDRESS.to_string())
}

#[inline]
pub fn qubetics_db_encryption_key() -> String {
    std::env::var("QUBETICS_DB_ENCRYPTION_KEY").unwrap_or_else(|_| DEFAULT_QUBETICS_DB_ENCRYPTION_KEY.to_string())
}

#[inline]
pub fn rpc_port() -> u16 {
    std::env::var("RPC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_RPC_PORT)
}

#[inline]
pub fn admin_public_address() -> String {
    std::env::var("ADMIN_PUBLIC_ADDRESS").unwrap_or_else(|_| DEFAULT_ADMIN_PUBLIC_ADDRESS.to_string())
}

#[inline]
pub fn max_tics_user_to_vault_intents_per_batch() -> usize {
    std::env::var("MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH.parse().unwrap())
}

#[inline]
pub fn max_btc_user_to_vault_intents_per_batch() -> usize {
    std::env::var("MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH.parse().unwrap())
}

#[inline]
pub fn max_btc_claim_reward_per_cycle() -> usize {
    std::env::var("MAX_BTC_CLAIM_REWARD_PER_CYCLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_MAX_BTC_CLAIM_REWARD_PER_CYCLE.parse().unwrap())
}

#[inline]
pub fn max_add_liquidity_batch() -> usize {
    std::env::var("MAX_ADD_LIQUIDITY_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_MAX_ADD_LIQUIDITY_BATCH.parse().unwrap())
}

#[inline]
pub fn mpc_tics_chain_id() -> u64 {
    std::env::var("MPC_TICS_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_MPC_TICS_CHAIN_ID.parse().unwrap())
}

#[inline]
pub fn tics_chain_rpc_url() -> String {
    std::env::var("TICS_CHAIN_RPC_URL").unwrap_or_else(|_| DEFAULT_TICS_CHAIN_RPC_URL.to_string())
}

#[inline]
pub fn tics_chain_id() -> u64 {
    std::env::var("TICS_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_TICS_CHAIN_ID.parse().unwrap())
}

#[inline]
pub fn btc_fee_rate_sat_vb() -> u64 {
    std::env::var("BTC_FEE_RATE_SAT_VB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| DEFAULT_BTC_FEE_RATE_SAT_VB.parse().unwrap())
}

/// Log all resolved env configuration at startup.
/// For each variable shows whether it came from the environment or fell back to the hardcoded default.
pub fn log_env_config() {
    fn src(var: &str) -> &'static str {
        if std::env::var(var).is_ok() { "ENV" } else { "DEFAULT" }
    }

    tracing::info!("╔══════════════════════════════════════════════════════════════╗");
    tracing::info!("║              NODE CONFIGURATION (startup)                    ║");
    tracing::info!("╠══════════════════════════════════════════════════════════════╣");
    tracing::info!("  RPC_PORT                        = {}  [{}]", rpc_port(), src("RPC_PORT"));
    tracing::info!("  NETWORK_TYPE                    = {}  [{}]", crate::types::network::network_type().as_str(), src("NETWORK_TYPE"));
    tracing::info!("  SOLVER_CONTRACT_RPC_URL         = {}  [{}]", solver_contract_rpc_url(), src("SOLVER_CONTRACT_RPC_URL"));
    tracing::info!("  SOLVER_CONTRACT_ADDRESS         = {}  [{}]", solver_contract_address(), src("SOLVER_CONTRACT_ADDRESS"));
    tracing::info!("  SOLVER_CONTRACT_CHAIN_ID        = {}  [{}]", solver_contract_chain_id(), src("SOLVER_CONTRACT_CHAIN_ID"));
    tracing::info!("  INTENT_MANAGER_CONTRACT_ADDRESS = {}  [{}]", intent_manager_contract_address(), src("INTENT_MANAGER_CONTRACT_ADDRESS"));
    tracing::info!("  TREASURY_VAULT_CONTRACT_ADDRESS = {}  [{}]", treasury_vault_contract_address(), src("TREASURY_VAULT_CONTRACT_ADDRESS"));
    tracing::info!("  MPC_ETHEREUM_RPC_URL            = {}  [{}]", mpc_ethereum_rpc_url(), src("MPC_ETHEREUM_RPC_URL"));
    tracing::info!("  MPC_BITCOIN_RPC_URL             = {}  [{}]", mpc_bitcoin_rpc_url(), src("MPC_BITCOIN_RPC_URL"));
    tracing::info!("  BACKEND_API_URL                 = {}  [{}]", backend_api_url(), src("BACKEND_API_URL"));
    tracing::info!("  BTC_UTXO_API_BASE               = {}  [{}]", btc_utxo_api_base(), src("BTC_UTXO_API_BASE"));
    tracing::info!("  CHAIN_CODE_HEX                  = {}  [{}]", chain_code_hex(), src("CHAIN_CODE_HEX"));
    tracing::info!("  GLOBAL_CLOCK_INTERVAL_SECONDS   = {}  [{}]", global_clock_interval_seconds(), src("GLOBAL_CLOCK_INTERVAL_SECONDS"));
    tracing::info!("  MAX_INTENTS_PER_CYCLE                    = {}  [{}]", max_intents_per_cycle(), src("MAX_INTENTS_PER_CYCLE"));
    tracing::info!("  MAX_BTC_WITHDRAW_PER_CYCLE               = {}  [{}]", max_btc_withdraw_per_cycle(), src("MAX_BTC_WITHDRAW_PER_CYCLE"));
    tracing::info!("  MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH = {}  [{}]", max_tics_user_to_vault_intents_per_batch(), src("MAX_TICS_USER_TO_VAULT_INTENTS_PER_BATCH"));
    tracing::info!("  MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH  = {}  [{}]", max_btc_user_to_vault_intents_per_batch(), src("MAX_BTC_USER_TO_VAULT_INTENTS_PER_BATCH"));
    tracing::info!("  MAX_BTC_CLAIM_REWARD_PER_CYCLE           = {}  [{}]", max_btc_claim_reward_per_cycle(), src("MAX_BTC_CLAIM_REWARD_PER_CYCLE"));
    tracing::info!("  MAX_ADD_LIQUIDITY_BATCH                  = {}  [{}]", max_add_liquidity_batch(), src("MAX_ADD_LIQUIDITY_BATCH"));
    tracing::info!("  MPC_TICS_CHAIN_ID                        = {}  [{}]", mpc_tics_chain_id(), src("MPC_TICS_CHAIN_ID"));
    tracing::info!("  TICS_CHAIN_RPC_URL                       = {}  [{}]", tics_chain_rpc_url(), src("TICS_CHAIN_RPC_URL"));
    tracing::info!("  TICS_CHAIN_ID                            = {}  [{}]", tics_chain_id(), src("TICS_CHAIN_ID"));
    tracing::info!("  BTC_FEE_RATE_SAT_VB                      = {}  [{}]", btc_fee_rate_sat_vb(), src("BTC_FEE_RATE_SAT_VB"));
    tracing::info!("  VERIFICATION_ADDRESS                     = {}  [{}]", verification_address(), src("VERIFICATION_ADDRESS"));
    tracing::info!("  ADMIN_PUBLIC_ADDRESS                     = {}  [{}]", admin_public_address(), src("ADMIN_PUBLIC_ADDRESS"));
    tracing::info!("  RPC_API_KEY                              = [{}]", src("RPC_API_KEY"));
    tracing::info!("  QUBETICS_DB_ENCRYPTION_KEY               = [{}]", src("QUBETICS_DB_ENCRYPTION_KEY"));
    tracing::info!("╚══════════════════════════════════════════════════════════════╝");
}
