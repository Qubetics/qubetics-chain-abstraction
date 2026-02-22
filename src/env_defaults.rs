//! Central defaults for environment variables. When an env var is not set, these values are used.

/// Default RPC server port (used when RPC_PORT is unset).
pub const DEFAULT_RPC_PORT: u16 = 80;

/// Default SolverManager / TICS RPC URL.
pub const DEFAULT_SOLVER_CONTRACT_RPC_URL: &str = "https://rpc-testnet.qubetics.work";
/// Default SolverManager contract address.
pub const DEFAULT_SOLVER_CONTRACT_ADDRESS: &str = "0x7A4710e8ae2e25416256720f75064Ec7A7B62C68";
/// Default IntentManager contract address.
pub const DEFAULT_INTENT_MANAGER_CONTRACT_ADDRESS: &str = "0xcf5746BC1b491210CbbFF7067d52B9B9e9723c27";
/// Default SolverManager chain ID.
pub const DEFAULT_SOLVER_CONTRACT_CHAIN_ID: &str = "9029";

/// Default MPC Ethereum RPC URL.
pub const DEFAULT_MPC_ETHEREUM_RPC_URL: &str = "https://rpc-testnet.qubetics.work";
/// Default MPC Bitcoin broadcast API URL.
pub const DEFAULT_MPC_BITCOIN_RPC_URL: &str = "https://stage-crypto-api.qubetics.work/api/v1/tx/broadcast";
/// Default backend API base URL.
pub const DEFAULT_BACKEND_API_URL: &str = "https://stage-crypto-api.qubetics.work";
/// Default BTC UTXO API base URL.
pub const DEFAULT_BTC_UTXO_API_BASE: &str = "https://stage-crypto-api.qubetics.work";
/// Default RPC API key (for auth).
pub const DEFAULT_RPC_API_KEY: &str = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";
/// Default chain code hex (BIP32 chain code).
pub const DEFAULT_CHAIN_CODE_HEX: &str = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194abe4";
/// Default network type.
pub const DEFAULT_NETWORK_TYPE: &str = "testnet";
/// Default DB encryption key (32-byte hex).
pub const DEFAULT_QUBETICS_DB_ENCRYPTION_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// Default global clock interval in seconds.
pub const DEFAULT_GLOBAL_CLOCK_INTERVAL_SECONDS: &str = "30";
/// Default Treasury Vault contract address.
pub const DEFAULT_TREASURY_VAULT_CONTRACT_ADDRESS: &str = "0x2De20Bf0acE8e031E7d3259953f9a4A490D9654B";
/// Default max BTC withdraw entries per cycle.
pub const DEFAULT_MAX_BTC_WITHDRAW_PER_CYCLE: &str = "15";
/// Default max intents per cycle.
pub const DEFAULT_MAX_INTENTS_PER_CYCLE: &str = "10";
/// Default verification address (solver add_liquidity verification).
pub const DEFAULT_VERIFICATION_ADDRESS: &str = "0xbac113cebd9CB2fBD2a01B5CBC43D0fC0EBed5e9";
/// Default: treat solver validation as always passing (1 = true).
pub const DEFAULT_SOLVER_VALIDATION_ALWAYS_TRUE: &str = "1";
/// Default admin Ethereum address (for register_admin / platform fee signing).
pub const DEFAULT_ADMIN_PUBLIC_ADDRESS: &str = "0x88c8045Fd96b88394B67fcA04FC92172CF7E6940";

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
pub fn solver_validation_always_true() -> bool {
    let v = std::env::var("SOLVER_VALIDATION_ALWAYS_TRUE").unwrap_or_else(|_| DEFAULT_SOLVER_VALIDATION_ALWAYS_TRUE.to_string());
    v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
}

#[inline]
pub fn admin_public_address() -> String {
    std::env::var("ADMIN_PUBLIC_ADDRESS").unwrap_or_else(|_| DEFAULT_ADMIN_PUBLIC_ADDRESS.to_string())
}
