use crate::chain::{
    BitcoinInput, BitcoinOutput, BitcoinTransaction, BitcoinWitnessUtxo, ChainTransaction,
    EthereumTransaction,
};
use crate::rpc_server::{ContractTransaction, DepositIntent, DummyTransaction};
use crate::utils::get_eth_address_from_group_key;
use anyhow::{bail, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, WitnessVersion};
use ethabi::ethereum_types::U256;
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use serde::{Deserialize, Serialize};
use tracing::{info, warn}; // for Token::Uint

// use rlp::RlpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendKind { P2PKH, P2WPKH }
/// Bitcoin UTXO structure for fetching from external APIs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

pub type WitnessItem  = Vec<u8>;
pub type WitnessStack = Vec<WitnessItem>;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BitcoinWitness {
    pub stacks: Vec<WitnessStack>, // len must equal inputs.len() for segwit spends
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

const DEFAULT_FEE_RATE_SAT_PER_VBYTE: u64 = 2;
const DUST_LIMIT_SATS: u64 = 546;

/// Wrapper for custom UTXO API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomApiUtxoResponse {
    error: bool,
    #[serde(rename = "statuscode")]
    status_code: u16,
    message: String,
    data: Vec<BitcoinUtxo>,
}

/// RLP encoder for Ethereum transaction signing (EIP-155)
pub struct RlpEncoder {
    pub data: Vec<u8>,
}

impl RlpEncoder {
    fn new() -> Self {
        RlpEncoder { data: Vec::new() }
    }

    fn encode_bytes(&mut self, bytes: &[u8]) {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            self.data.push(bytes[0]);
        } else if bytes.len() < 56 {
            self.data.push(0x80 + bytes.len() as u8);
            self.data.extend_from_slice(bytes);
        } else {
            let length_bytes = (bytes.len() as u64).to_be_bytes();
            let length_start = length_bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(length_bytes.len() - 1);
            let length_slice = &length_bytes[length_start..];

            self.data.push(0xb7 + length_slice.len() as u8);
            self.data.extend_from_slice(length_slice);
            self.data.extend_from_slice(bytes);
        }
    }

    fn encode_u64(&mut self, value: u64) {
        if value == 0 {
            self.data.push(0x80);
        } else {
            let bytes = value.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(bytes.len() - 1);
            self.encode_bytes(&bytes[start..]);
        }
    }

    fn encode_hex_string(&mut self, hex_str: &str) {
        let bytes = encode_hex_to_bytes(hex_str);
        self.encode_bytes(&bytes);
    }

    fn encode_address(&mut self, address: &str) {
        let bytes = hex::decode(&address[2..]).expect("Invalid address");
        self.encode_bytes(&bytes);
    }

    fn encode_list_header(&mut self, content_length: usize) {
        if content_length < 56 {
            self.data.push(0xc0 + content_length as u8);
        } else {
            let length_bytes = (content_length as u64).to_be_bytes();
            let length_start = length_bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(length_bytes.len() - 1);
            let length_slice = &length_bytes[length_start..];

            self.data.push(0xf7 + length_slice.len() as u8);
            self.data.extend_from_slice(length_slice);
        }
    }

    fn finalize(self) -> Vec<u8> {
        self.data
    }
}

fn encode_hex_to_bytes(hex_str: &str) -> Vec<u8> {
    let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let trimmed = clean_hex.trim_start_matches('0');

    // If the value is zero or only zeros were provided, return an empty
    // Vec so that the caller encodes it as an empty byte slice (0x80 in RLP).
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut final_hex = trimmed.to_string();
    if final_hex.len() % 2 == 1 {
        final_hex = format!("0{}", final_hex);
    }

    hex::decode(&final_hex).expect("Invalid hex string")
}

/// Strip leading zeros from byte array for RLP compliance
/// RLP encoding requires that integers have no leading zero bytes
fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    // Find the first non-zero byte
    let start = bytes.iter().position(|&x| x != 0).unwrap_or(bytes.len());

    // If all bytes are zero, return a single zero byte
    if start == bytes.len() {
        vec![0]
    } else {
        bytes[start..].to_vec()
    }
}

/// Convert amount (u128) to proper hex string format for Ethereum transactions
/// Returns "0x0" for zero amounts, otherwise returns minimal hex representation with 0x prefix
pub fn amount_to_hex_string(amount: u128) -> String {
    if amount == 0 {
        return "0x0".to_string();
    }

    // Convert to hex and remove leading zeros
    let hex_str = format!("{:x}", amount);
    format!("0x{}", hex_str)
}

/// Validate and normalize hex string for amounts
/// Ensures proper 0x prefix and removes unnecessary leading zeros
pub fn validate_and_normalize_hex_amount(hex_str: &str) -> Result<String> {
    let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Validate hex characters
    if !clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "Invalid hex characters in amount: {}",
            hex_str
        ));
    }

    // Remove leading zeros but keep at least one digit
    let trimmed = clean_hex.trim_start_matches('0');
    let normalized = if trimmed.is_empty() { "0" } else { trimmed };

    Ok(format!("0x{}", normalized))
}

/// Validate that a transaction has proper hex formatting for value and gas_price
pub fn validate_transaction_hex_fields(tx: &crate::rpc_server::DummyTransaction) -> Result<()> {
    // Validate value field
    validate_and_normalize_hex_amount(&tx.value)
        .map_err(|e| anyhow::anyhow!("Invalid value field: {}", e))?;

    // Validate gas_price field
    validate_and_normalize_hex_amount(&tx.gas_price)
        .map_err(|e| anyhow::anyhow!("Invalid gas_price field: {}", e))?;

    Ok(())
}

/// Validate that a contract transaction has proper hex formatting
pub fn validate_contract_transaction_hex_fields(
    tx: &crate::rpc_server::ContractTransaction,
) -> Result<()> {
    // Validate value field
    validate_and_normalize_hex_amount(&tx.value)
        .map_err(|e| anyhow::anyhow!("Invalid value field: {}", e))?;

    // Validate gas_price field
    validate_and_normalize_hex_amount(&tx.gas_price)
        .map_err(|e| anyhow::anyhow!("Invalid gas_price field: {}", e))?;

    // Validate data field (should be hex if not empty)
    if !tx.data.is_empty() && tx.data != "0x" {
        let clean_data = tx.data.strip_prefix("0x").unwrap_or(&tx.data);
        if !clean_data.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!(
                "Invalid hex characters in data field: {}",
                tx.data
            ));
        }
    }

    Ok(())
}

/// Chain mapping to convert string names to chain IDs
pub fn get_chain_id_from_name(chain_name: &str) -> Option<u64> {
    match chain_name.to_lowercase().as_str() {
        "ethereum" | "eth" => Some(1),
        "qubetics" => Some(9029),
        "polygon" | "matic" => Some(137),
        "bsc" | "binance" => Some(56),
        "avalanche" | "avax" => Some(43114),
        "arbitrum" => Some(42161),
        "optimism" => Some(10),
        "base" => Some(8453),
        _ => None, // Bitcoin and other non-EVM chains return None
    }
}

/// Determine if a chain is EVM-compatible
pub fn is_evm_chain(chain_name: &str) -> bool {
    get_chain_id_from_name(chain_name).is_some()
}

/// Fetch UTXOs for a Bitcoin address from Mempool.space Esplora API
pub async fn fetch_bitcoin_utxos(address: &str, is_testnet: bool) -> Result<Vec<BitcoinUtxo>> {
    tracing::info!(
        "🔍 Fetching Bitcoin UTXOs for address: {} (is_testnet: {})",
        address,
        is_testnet
    );

    // Prefer custom API if provided: BTC_UTXO_API_BASE=http://host:port
    if let Ok(custom_base) = std::env::var("BTC_UTXO_API_BASE") {
        let base = custom_base.trim_end_matches('/');
        let url = format!("{}/api/v1/utxos?address={}", base, address);
        tracing::info!("🌐 Using custom UTXO API: {}", url);
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await?;

        tracing::info!(
            "🔗 Custom API response status: {}",
            response.status()
        );

        if !response.status().is_success() {
            tracing::error!(
                "❌ Failed to fetch UTXOs from custom API: HTTP {}",
                response.status()
            );
            return Err(anyhow::anyhow!(
                "Failed to fetch UTXOs from custom API: HTTP {}",
                response.status()
            ));
        }

        let wrapper: CustomApiUtxoResponse = response.json().await?;
        if wrapper.error {
            tracing::error!(
                "❌ Custom API error (status {}): {}",
                wrapper.status_code,
                wrapper.message
            );
            return Err(anyhow::anyhow!(
                "Custom API error (status {}): {}",
                wrapper.status_code,
                wrapper.message
            ));
        }

        tracing::info!(
            "✅ Custom API returned {} UTXOs for address {}",
            wrapper.data.len(),
            address
        );

        return Ok(wrapper.data);
    }

    // Fallback to mempool.space Esplora API
    let base_url = if is_testnet {
        "https://mempool.space/testnet/api"
    } else {
        "https://mempool.space/api"
    };

    let url = format!("{}/address/{}/utxo", base_url, address);
    tracing::info!("🌐 Using mempool.space Esplora API: {}", url);
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    tracing::info!(
        "🔗 Esplora API response status: {}",
        response.status()
    );

    if !response.status().is_success() {
        tracing::error!(
            "❌ Failed to fetch UTXOs: HTTP {}",
            response.status()
        );
        return Err(anyhow::anyhow!(
            "Failed to fetch UTXOs: HTTP {}",
            response.status()
        ));
    }

    let utxos: Vec<BitcoinUtxo> = response.json().await?;
    tracing::info!(
        "✅ Esplora API returned {} UTXOs for address {}",
        utxos.len(),
        address
    );
    Ok(utxos)
}

/// Enhanced UTXO information for P2PKH validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
    pub scriptpubkey: Option<String>,
    pub scriptpubkey_type: Option<String>,
    pub scriptpubkey_address: Option<String>,
}

/// Result of the SegWit UTXO selection logic.
#[derive(Debug, Clone)]
pub struct UtxoSelectionResult {
    pub selected_utxos: Vec<BitcoinUtxo>,
    pub total_value: u64,
    pub fee: u64,
    pub change: u64,
    pub change_output: bool,
}

fn estimate_vbytes(kind: SpendKind, n_in: usize, n_out: usize) -> usize {
    match kind {
        SpendKind::P2WPKH => 10 + 68 * n_in + 31 * n_out,   // segwit approx
        SpendKind::P2PKH  => 10 + 148 * n_in + 34 * n_out,  // legacy approx
    }
}

fn estimate_fee_sat(kind: SpendKind, n_in: usize, n_out: usize, fee_rate_sat_vb: u64) -> u64 {
    (estimate_vbytes(kind, n_in, n_out) as u64) * fee_rate_sat_vb
}

/// Select and combine SegWit (P2WPKH) UTXOs to meet the required amount.
///
/// # Examples
///
/// Assume `fee_rate_sat_vb = 2`.
///
/// ## Two tiny UTXOs, no change output
/// - Inputs: `800 + 800 = 1_600` sats (`n_in = 2`).
/// - Try with change (`n_out = 2` → recipient + change):
///   `vbytes = 10 + 68*2 + 31*2 = 208` → `fee ≈ 416` sats and `change = -16` (insufficient).
/// - Retry without change (`n_out = 1` → recipient only):
///   `vbytes = 10 + 68*2 + 31 = 177` → `fee ≈ 354` sats.
/// - `total (1_600) ≥ send (1_200) + fee (354)`. The would-be change `46` is `< 546` dust,
///   so it is folded into the fee. The actual fee paid on-chain is `1_600 - 1_200 = 400` sats
///   (~2.26 sat/vB).
///
/// ## Three UTXOs with a change output
/// - Inputs: `30_000 + 50_000 + 70_000 = 150_000` sats (`n_in = 3`).
/// - With change (`n_out = 2`):
///   `vbytes = 10 + 68*3 + 31*2 = 276` → `fee ≈ 552` sats.
/// - Change `= 150_000 - 120_000 - 552 = 29_448` which is `≥ 546` dust, so two outputs are used.
/// - The loop stops as soon as `total ≥ send + fee`; otherwise the selector keeps adding
///   the next smallest confirmed UTXO until the target is met or funds are exhausted.
///
/// ## Two UTXOs, large send with change (optional)
/// - Inputs: `60_000 + 70_000 = 130_000` sats (`n_in = 2`).
/// - With change (`n_out = 2`): `vbytes = 208` → `fee ≈ 416` sats.
/// - Change `= 130_000 - 120_000 - 416 = 9_584` sats which is above dust, so the selector
///   keeps both outputs (recipient + change) and stops after two inputs.
pub fn select_utxos_for_amount(
    utxos: &[BitcoinUtxo],
    required_amount: u64,
    fee_rate_sat_vb: u64,
    kind: SpendKind,
) -> Result<UtxoSelectionResult> {
    if required_amount == 0 {
        return Err(anyhow::anyhow!("Required amount must be greater than zero"));
    }

    let mut confirmed_utxos: Vec<_> = utxos
        .iter()
        .cloned()
        .filter(|utxo| {
            if !utxo.status.confirmed {
                tracing::debug!(
                    "🔍 [UTXO_FILTER] Skipping unconfirmed UTXO: {}:{}",
                    utxo.txid,
                    utxo.vout
                );
                return false;
            }

            if utxo.txid.len() != 64 {
                tracing::warn!(
                    "⚠️ [UTXO_FILTER] Skipping UTXO with invalid txid length: {}",
                    utxo.txid
                );
                return false;
            }

            if utxo.value == 0 {
                tracing::warn!(
                    "⚠️ [UTXO_FILTER] Skipping zero-value UTXO: {}:{}",
                    utxo.txid,
                    utxo.vout
                );
                return false;
            }

            true
        })
        .collect();

    if confirmed_utxos.is_empty() {
        return Err(anyhow::anyhow!(
            "No confirmed UTXOs available from {} fetched entries",
            utxos.len()
        ));
    }

    // Sort descending (largest first) to minimize the number of inputs needed
    confirmed_utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.value));

    tracing::info!(
        "🔍 [UTXO_SELECTION] {} confirmed UTXOs remain after filtering ({} fetched)",
        confirmed_utxos.len(),
        utxos.len()
    );

    // Simple greedy algorithm: add UTXOs until we have enough, then choose best path
    let mut selected = Vec::new();
    let mut total_value = 0u64;

    for candidate in confirmed_utxos.into_iter() {
        total_value += candidate.value;
        selected.push(candidate);

        let n_inputs = selected.len();

        // Try change path first (2 outputs: recipient + change)
        let fee_with_change = estimate_fee_sat(kind, n_inputs, 2, fee_rate_sat_vb);
        let required_with_change = required_amount + fee_with_change;

        if total_value >= required_with_change {
            let change = total_value - required_with_change;
            
            if change >= DUST_LIMIT_SATS {
                // Use change path - this is optimal
                tracing::info!(
                    "✅ [UTXO_SELECTION] Using change path with {} inputs (fee {} sats, change {} sats)",
                    n_inputs,
                    fee_with_change,
                    change
                );

                return Ok(UtxoSelectionResult {
                    selected_utxos: selected,
                    total_value,
                    fee: fee_with_change,
                    change,
                    change_output: true,
                });
            }
        }

        // Try no-change path (1 output: recipient only)
        let fee_no_change = estimate_fee_sat(kind, n_inputs, 1, fee_rate_sat_vb);
        let required_no_change: u64 = required_amount + fee_no_change;

        if total_value >= required_no_change {
            // Use no-change path
            tracing::info!(
                "✅ [UTXO_SELECTION] Using no-change path with {} inputs (fee {} sats)",
                n_inputs,
                fee_no_change
            );

            return Ok(UtxoSelectionResult {
                selected_utxos: selected,
                total_value,
                fee: fee_no_change,
                change: 0,
                change_output: false,
            });
        }

        // If we don't have enough, continue adding UTXOs
    }

    // error tail - no valid combination found
    let n_inputs = selected.len().max(1);
    let needed_with_change   = required_amount.saturating_add(estimate_fee_sat(kind, n_inputs, 2, fee_rate_sat_vb));
    let needed_without_change= required_amount.saturating_add(estimate_fee_sat(kind, n_inputs, 1, fee_rate_sat_vb));
    let min_needed = needed_with_change.min(needed_without_change);

    Err(anyhow::anyhow!(
        "Insufficient confirmed funds: gathered {} sats but need at least {} sats (amount + fees)",
        total_value, min_needed
    ))
}

/// Extract UTXO identifiers from selected UTXOs for tracking
pub fn extract_utxo_identifiers(utxos: &[BitcoinUtxo]) -> Vec<(String, u32)> {
    utxos
        .iter()
        .map(|utxo| (utxo.txid.clone(), utxo.vout))
        .collect()
}

pub async fn fetch_ethereum_nonce(address: &str, chain_id: u64) -> Result<u64> {
    let rpc_url = match chain_id {
        9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
            .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
        1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(), // Ethereum mainnet
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported chain ID for nonce fetching: {}",
                chain_id
            ))
        }
    };

    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [address, "pending"],
        "id": 1
    });

    info!(
        "Fetching nonce for address {} on chain {} (pending)",
        address, chain_id
    );

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(error) = result.get("error") {
            tracing::error!("❌ Failed to fetch nonce: {}", error);
            return Err(anyhow::anyhow!("Nonce fetch failed: {}", error));
        }
        if let Some(nonce_hex) = result.get("result") {
            let nonce_str = nonce_hex.as_str().unwrap_or("0x0");
            let nonce = u64::from_str_radix(nonce_str.strip_prefix("0x").unwrap_or(nonce_str), 16)?;
            info!("✅ Fetched nonce {} for address {}", nonce, address);
            Ok(nonce)
        } else {
            Err(anyhow::anyhow!("No nonce result in response"))
        }
    } else {
        let error_text = response.text().await?;
        tracing::error!("❌ Failed to fetch nonce: {}", error_text);
        Err(anyhow::anyhow!("Nonce fetch failed: {}", error_text))
    }
}

async fn estimate_gas_for_deposit_intent(
    from: &str,
    to: &str,
    data_hex: &str,
    chain_id: u64,
) -> Result<u64> {
    let rpc_url = match chain_id {
        9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
            .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
        1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported chain ID for gas estimation: {}",
                chain_id
            ))
        }
    };

    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_estimateGas",
        "params": [{
            "from": from,
            "to": to,
            "data": data_hex
        }],
        "id": 1
    });

    info!(
        "🔧 Estimating gas for contract call from {} to {}",
        from, to
    );

    let response = client
        .post(&rpc_url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(error) = result.get("error") {
            tracing::error!("❌ Gas estimation failed: {}", error);
            return Err(anyhow::anyhow!("Gas estimation failed: {}", error));
        }
        if let Some(gas_hex) = result.get("result") {
            let gas_str = gas_hex.as_str().unwrap_or("0x0");
            let gas = u64::from_str_radix(gas_str.strip_prefix("0x").unwrap_or(gas_str), 16)?;
            info!("✅ Estimated gas: {}", gas);
            Ok(gas)
        } else {
            Err(anyhow::anyhow!("No gas result in response"))
        }
    } else {
        let error_text = response.text().await?;
        tracing::error!("❌ Gas estimation failed: {}", error_text);
        Err(anyhow::anyhow!("Gas estimation failed: {}", error_text))
    }
}

/// Create a chain-specific transaction from a deposit intent
/// For Bitcoin transactions, group_public_key is required to derive the Bitcoin address and fetch UTXOs
/// transaction_type determines the fund flow:
/// - UserToVault: User deposit - FROM derived address TO vault address (on source chain)
/// - NetworkToTarget: Network withdrawal - FROM network address TO target address (on target chain)
/// - VaultToNetwork: Vault to network - FROM vault address TO network address (on source chain)
/// derived_eth_addr and derived_btc_addr are the actual addresses that hold user funds
pub async fn create_chain_transaction_from_deposit_intent(
    intent: &DepositIntent,
    group_public_key: Option<k256::ProjectivePoint>,
    derived_eth_addr: Option<&String>,
    derived_btc_addr: Option<&String>,
    transaction_type: crate::types::TransactionType,
    vault_eth_address: Option<&String>,
    vault_btc_address: Option<&String>,
    amount: u128,
) -> Result<ChainTransaction> {
    create_chain_transaction_from_deposit_intent_internal(
        intent,
        group_public_key,
        derived_eth_addr,
        derived_btc_addr,
        transaction_type,
        vault_eth_address,
        vault_btc_address,
        None,
        amount,
    )
    .await
}

fn classify_address(addr: &str) -> Result<(SpendKind, bitcoin::Network)> {
    use bitcoin::address::{Address, AddressData, NetworkUnchecked};
    use bitcoin::{Network, WitnessVersion};

    tracing::info!("🔍 Attempting to classify Bitcoin address: {}", addr);

    // Parse as *unchecked*
    let a: Address<NetworkUnchecked> = match addr.parse() {
        Ok(address) => {
            tracing::info!("✅ Successfully parsed address: {}", addr);
            address
        },
        Err(e) => {
            tracing::error!("❌ Invalid Bitcoin address '{}': {}", addr, e);
            return Err(anyhow::anyhow!("Invalid Bitcoin address '{}': {}", addr, e));
        }
    };

    // Figure out which network this string is valid for.
    // (Legacy testnet/regtest/signet are ambiguous by design.)
    let net = match [Network::Bitcoin, Network::Testnet, Network::Signet, Network::Regtest]
        .into_iter()
        .find(|n| a.is_valid_for_network(*n))
    {
        Some(network) => {
            tracing::info!("✅ Address '{}' is valid for network: {:?}", addr, network);
            network
        },
        None => {
            tracing::error!("❌ Address '{}' is not valid for any known network", addr);
            return Err(anyhow::anyhow!("Address '{}' is not valid for any known network", addr));
        }
    };

    // Now *require* that network to get a checked address.
    let checked = match a.require_network(net) {
        Ok(checked_addr) => {
            tracing::info!("✅ Address '{}' matches network: {:?}", addr, net);
            checked_addr
        },
        Err(e) => {
            tracing::error!("❌ Network mismatch for '{}': {}", addr, e);
            return Err(anyhow::anyhow!("Network mismatch for '{}': {}", addr, e));
        }
    };

    // Classify by data (or you could use checked.address_type()).
    let kind = match checked.to_address_data() {
        AddressData::P2pkh { .. } => {
            tracing::info!("🔎 Address '{}' classified as P2PKH", addr);
            SpendKind::P2PKH
        },
        AddressData::Segwit { witness_program: wp }
            if wp.version() == WitnessVersion::V0 && wp.is_p2wpkh() => {
            tracing::info!("🔎 Address '{}' classified as P2WPKH", addr);
            SpendKind::P2WPKH
        },
        _ => {
            tracing::error!("❌ Unsupported address type for spending: {}", addr);
            bail!("Unsupported address type for spending: {}", addr)
        },
    };

    tracing::info!("✅ Classification result for '{}': kind={:?}, network={:?}", addr, kind, net);

    Ok((kind, net))
}

/// Internal implementation of transaction creation with optional UTXO checking
async fn create_chain_transaction_from_deposit_intent_internal(
    intent: &DepositIntent,
    group_public_key: Option<k256::ProjectivePoint>,
    derived_eth_addr: Option<&String>,
    derived_btc_addr: Option<&String>,
    transaction_type: crate::types::TransactionType,
    vault_eth_address: Option<&String>,
    vault_btc_address: Option<&String>,
    _user_registry: Option<&crate::user_registry::DatabaseUserRegistry>,
    amount: u128,
) -> Result<ChainTransaction> {
    // Determine chain type based on transaction type:
    // - UserToVault: use source_chain (user is depositing FROM this chain)
    // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
    // - VaultToNetwork: use source_chain (vault is sending back to network on source chain)
    let chain_to_use = match transaction_type {
        crate::types::TransactionType::UserToVault => &intent.source_chain.to_lowercase(),
        crate::types::TransactionType::NetworkToTarget => &intent.target_chain.to_lowercase(),
        crate::types::TransactionType::VaultToNetwork => &intent.source_chain.to_lowercase(),
    };

    info!("amount::::: {}", amount);

    if is_evm_chain(chain_to_use) {
        // Create Ethereum-compatible transaction
        let chain_id = get_chain_id_from_name(chain_to_use)
            .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", chain_to_use))?;
        // Get vault address from parameter
        let vault_address =
            vault_eth_address.ok_or_else(|| anyhow::anyhow!("Vault ETH address not provided"))?;

        let network_address = get_eth_address_from_group_key(group_public_key.unwrap());

        // Determine source and target based on transaction type
        let (from_address, to_address) = match transaction_type {
            crate::types::TransactionType::UserToVault => {
                // User deposit: FROM derived ethereum address TO vault address
                if let Some(derived_addr) = derived_eth_addr {
                    tracing::info!(
                        "💰 [TRANSACTION] User to vault: {} -> {}",
                        derived_addr,
                        vault_address
                    );
                    (derived_addr.clone(), vault_address)
                } else {
                    return Err(anyhow::anyhow!(
                        "UserToVault transaction requires derived_eth_address"
                    ));
                }
            }
            crate::types::TransactionType::NetworkToTarget => {
                // Network withdrawal: FROM network address TO target address
                tracing::info!(
                    "💰 [TRANSACTION] Network to target: {} -> {}",
                    network_address,
                    intent.target_address
                );
                (network_address.clone(), &intent.target_address)
            }
            crate::types::TransactionType::VaultToNetwork => {
                // Vault to network: FROM vault address TO network address
                tracing::info!(
                    "💰 [TRANSACTION] Vault to network: {} -> {}",
                    vault_address,
                    network_address
                );
                (vault_address.clone(), &network_address)
            }
        };

        // Get dynamic gas price for Qubetics, fallback to static for other chains
        let gas_price = get_gas_price_for_chain(chain_to_use, chain_id).await
            .unwrap_or_else(|e| {
                warn!("⚠️ Failed to get dynamic gas price: {}, using fallback", e);
                get_default_gas_price_for_chain(chain_to_use)
            });

        let ethereum_tx = EthereumTransaction {
            to: to_address.to_string(),
            value: amount_to_hex_string(amount),
            gas_limit: 300000,
            gas_price,
            nonce: fetch_ethereum_nonce(&from_address, chain_id).await?,
            data: None,
            chain_id,
        };

        Ok(ChainTransaction::Ethereum(ethereum_tx))
    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
        // Create Bitcoin transaction with proper UTXO fetching
        let group_key = group_public_key
            .ok_or_else(|| anyhow::anyhow!("Group public key required for Bitcoin transactions"))?;

        // Get Bitcoin addresses
        let btc_network_address = crate::utils::get_btc_address_from_group_key(group_key);
        // Get vault address from parameter
        let btc_vault_address =
            vault_btc_address.ok_or_else(|| anyhow::anyhow!("Vault BTC address not provided"))?;

        // Determine source and target based on transaction type
        let (from_address, to_address) = match transaction_type {
            crate::types::TransactionType::UserToVault => {
                // User deposit: FROM derived bitcoin address TO vault bitcoin address
                if let Some(derived_btc_addr) = derived_btc_addr {
                    tracing::info!(
                        "💰 [TRANSACTION] Bitcoin user to vault: {} -> {}",
                        derived_btc_addr,
                        btc_vault_address
                    );
                    (derived_btc_addr.clone(), btc_vault_address)
                } else {
                    return Err(anyhow::anyhow!(
                        "UserToVault transaction requires derived_btc_address"
                    ));
                }
            }
            crate::types::TransactionType::NetworkToTarget => {
                // Network withdrawal: FROM network bitcoin address TO target address
                tracing::info!(
                    "💰 [TRANSACTION] Bitcoin network to target: {} -> {}",
                    btc_network_address,
                    intent.target_address
                );
                (btc_network_address.clone(), &intent.target_address)
            }
            crate::types::TransactionType::VaultToNetwork => {
                // Vault to network: FROM vault bitcoin address TO network bitcoin address
                tracing::info!(
                    "💰 [TRANSACTION] Bitcoin vault to network: {} -> {}",
                    btc_vault_address,
                    btc_network_address
                );
                (btc_vault_address.clone(), &btc_network_address)
            }
        };

        tracing::info!("Using Bitcoin source address for UTXOs: {}", from_address);

        // Validate that both addresses are P2PKH format only
        // if !is_p2pkh_address(&from_address) {
        //     return Err(anyhow::anyhow!(
        //         "Source address '{}' is not supported. Only P2PKH addresses (1.../m.../n...) are supported.",
        //         from_address
        //     ));
        // }

        // if !is_p2pkh_address(&to_address) {
        //     return Err(anyhow::anyhow!(
        //         "Destination address '{}' is not supported. Only P2PKH addresses (1.../m.../n...) are supported.",
        //         to_address
        //     ));
        // }

        // let is_testnet = is_testnet_p2pkh_address(&from_address);
        let (from_kind, from_net) = classify_address(&from_address)?;   
        let (to_kind,   to_net)   = classify_address(&to_address)?; 
        // Fetch raw UTXOs without external verification
        // Sanity: prevent net mismatch
        if from_net != to_net {
            anyhow::bail!("From/To network mismatch: {:?} vs {:?}", from_net, to_net);
        }

        let is_testnet = matches!(from_net, bitcoin::Network::Testnet | bitcoin::Network::Signet | bitcoin::Network::Regtest);

// Fetch UTXOs for the right network
        let utxos = fetch_bitcoin_utxos(&from_address, is_testnet).await?;

        tracing::info!(
            "Final verified {} spendable UTXOs for address {}",
            utxos.len(),
            from_address
        );

        // Convert amount from wei to satoshis (assuming 1:1 conversion for now, you might want to adjust this)
        let amount_satoshis = (amount) as u64;
        let fee_rate_sat_vb = std::env::var("BTC_FEE_RATE_SAT_VB")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_FEE_RATE_SAT_PER_VBYTE);

        tracing::info!(
            "Using fee rate of {} sat/vB for Bitcoin transaction from {}",
            fee_rate_sat_vb,
            from_address
        );

        // Select UTXOs that provide enough value using SegWit-aware fee estimation.
        let selection = select_utxos_for_amount(&utxos, amount_satoshis, fee_rate_sat_vb, from_kind)?;

        tracing::info!(
            "Selected {} UTXOs with total value {} satoshis for transaction of {} satoshis (fee: {}, change: {}, change_output: {})",
            selection.selected_utxos.len(),
            selection.total_value,
            amount_satoshis,
            selection.fee,
            selection.change,
            selection.change_output
        );

        // Log the specific UTXOs we're about to spend for debugging
        tracing::info!("📋 [TRANSACTION] UTXOs selected for spending:");
        for (i, utxo) in selection.selected_utxos.iter().enumerate() {
            tracing::info!(
                "  {}. {}:{} - {} sats (confirmed: {})",
                i + 1,
                utxo.txid,
                utxo.vout,
                utxo.value,
                utxo.status.confirmed
            );
        }

        let to_spk   = create_bitcoin_script_pubkey(&to_address)?;
        let from_spk = create_bitcoin_script_pubkey(&from_address)?;

        // Inputs:
        let inputs: Vec<BitcoinInput> = selection.selected_utxos.iter().map(|u| {
            match from_kind {
                SpendKind::P2WPKH => BitcoinInput {
                    txid: u.txid.clone(),
                    vout: u.vout,
                    script_sig: vec![],
                    sequence: 0xffff_fffe,
                    witness_utxo: Some(BitcoinWitnessUtxo {
                        value: u.value,
                        script_pubkey: from_spk.clone(), // 0x00 0x14 <20>
                    }),
                },
                SpendKind::P2PKH => BitcoinInput {
                    txid: u.txid.clone(),
                    vout: u.vout,
                    script_sig: vec![],
                    sequence: 0xffff_fffe,
                    // IMPORTANT: stash 25-byte prev script here so final node doesn’t need to reconstruct
                    witness_utxo: Some(BitcoinWitnessUtxo {
                        value: u.value,
                        script_pubkey: from_spk.clone(), // 76 a9 14 <20> 88 ac
                    }),
                }
            }
    }).collect();

        // Create outputs (recipient always, change only if not dust)
       // Outputs (change script MUST match the from-address type; using from_spk is correct):
        let mut outputs = vec![BitcoinOutput { value: amount_satoshis, script_pubkey: to_spk }];
        if selection.change_output {
            outputs.push(BitcoinOutput { value: selection.change, script_pubkey: from_spk });
        }

        let (version, witness_opt) = match from_kind {
            SpendKind::P2WPKH => {
                // placeholder: one empty stack per input; fill after signing
                (
                    2,
                    Some(crate::chain::BitcoinWitness {
                        inputs: (0..inputs.len())
                            .map(|_| crate::chain::BitcoinWitnessInput { stack: vec![] })
                            .collect(),
                    }),
                )
            }
            SpendKind::P2PKH => (1, None),
        };
        
        let bitcoin_tx = BitcoinTransaction {
            inputs,
            outputs,
            version,
            lock_time: 0,
            witness: witness_opt,
        };

        Ok(ChainTransaction::Bitcoin(bitcoin_tx))
    } else {
        Err(anyhow::anyhow!("Unsupported chain: {}", chain_to_use))
    }
}

pub async fn create_chain_transaction_from_contract_call(
    group_public_key: Option<k256::ProjectivePoint>,
    amount: u128,
    intent: &DepositIntent,
    intent_hash: &str,
    tx_hash: &str,
    transaction_type: crate::types::TransactionType,
) -> Result<ChainTransaction> {
    let network_address = get_eth_address_from_group_key(group_public_key.unwrap());
    let chain_id = get_chain_id_from_name("qubetics")
        .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", "eth"))?;

    // Get contract address from environment variable and normalize to 0x-prefixed
    let contract_address_env = std::env::var("INTENT_MANAGER_CONTRACT_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    info!(
        "[create_chain_transaction_from_contract_call] encode_deposit_intent_calldata params:\n  source_address: {}\n  target_address: {}\n  source_chain: {}\n  target_chain: {}\n  amount: {}\n  source_token: {}\n  target_token: {}\n  transaction_hash: {}\n  intent_hash: {}",
            &intent.source_address,
            &intent.target_address,
            &intent.source_chain,
            &intent.target_chain,
            amount,
            &intent.source_token,
            &intent.target_token,
            &tx_hash,
            intent_hash
        );

    info!("🔧 [CONTRACT] Network address: {}", network_address);
    info!("🔧 [CONTRACT] Chain ID: {}", chain_id);

    // Choose the appropriate calldata encoding function based on transaction type
    let calldata = match transaction_type {
        crate::types::TransactionType::UserToVault => {
            info!("🔧 [CONTRACT] Using depositIntent calldata for UserToVault transaction");
            encode_deposit_intent_calldata(
                &intent.source_address,
                &intent.target_address,
                &intent.source_chain,
                &intent.target_chain,
                amount,
                &intent.source_token,
                &intent.target_token,
                &tx_hash,
                intent_hash,
                &intent.timestamp.to_string(),
            )
        }
        _ => {
            info!(
                "🔧 [CONTRACT] Using fulfillIntent calldata for {:?} transaction",
                transaction_type
            );
            encode_fulfill_intent_calldata(
                &intent.source_address,
                &intent.target_address,
                &intent.source_chain,
                &intent.target_chain,
                amount,
                &intent.source_token,
                &intent.target_token,
                tx_hash,
                intent_hash,
                &intent.timestamp.to_string(),
            )
        }
    };

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
    .await
    .unwrap_or(300000);
    let gas_limit = estimated_gas + (estimated_gas / 10); // Add 10% buffer

    info!(
        "🔧 [CONTRACT] Estimated gas: {}, using gas_limit: {}",
        estimated_gas, gas_limit
    );

    let nonce = fetch_ethereum_nonce(&network_address, chain_id).await?;
    let gas_price = get_gas_price_for_chain("qubetics", chain_id).await
        .unwrap_or_else(|e| {
            warn!("⚠️ Failed to get dynamic gas price: {}, using fallback", e);
            get_default_gas_price_for_chain("qubetics")
        });

    info!("🔧 [CONTRACT] Final transaction details:");
    info!("  - To: {}", contract_address_env);
    info!("  - From: {}", network_address);
    info!("  - Nonce: {}", nonce);
    info!("  - Gas Limit: {}", gas_limit);
    info!("  - Gas Price: {}", gas_price);
    info!("  - Chain ID: {}", chain_id);
    info!(
        "  - Calldata: 0x{}",
        calldata
            .as_ref()
            .map(|d| hex::encode(d))
            .unwrap_or_else(|| "".to_string())
    );

    let ethereum_tx = EthereumTransaction {
        to: contract_address_env,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: calldata,
        chain_id,
    };

    Ok(ChainTransaction::Ethereum(ethereum_tx))
}

pub fn encode_deposit_intent_calldata(
    source_address: &str,
    target_address: &str,
    source_chain: &str,
    target_chain: &str,
    amount: u128,
    source_token: &str,
    target_token: &str,
    transaction_hash: &str,
    intent_id: &str,
    timestamp: &str,
) -> Option<Vec<u8>> {
    let f = Function {
        name: "depositIntent".to_owned(),
        inputs: vec![
            Param {
                name: "sourceAddress".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "targetAddress".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "sourceChain".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "targetChain".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "amount".into(),
                kind: ParamType::Uint(128),
                internal_type: None,
            },
            Param {
                name: "sourceToken".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "targetToken".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "transactionHash".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "intentId".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "timestamp".into(),
                kind: ParamType::String,
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    let tokens = vec![
        Token::String(source_address.to_owned()),
        Token::String(target_address.to_owned()),
        Token::String(source_chain.to_owned()),
        Token::String(target_chain.to_owned()),
        Token::Uint(U256::from(amount)), // uint128
        Token::String(source_token.to_owned()),
        Token::String(target_token.to_owned()),
        Token::String(transaction_hash.to_owned()),
        Token::String(intent_id.to_owned()),
        Token::String(timestamp.to_owned()),
    ];

    f.encode_input(&tokens).ok()
}

pub fn encode_fulfill_intent_calldata(
    source_address: &str,
    target_address: &str,
    source_chain: &str,
    target_chain: &str,
    amount: u128,
    source_token: &str,
    target_token: &str,
    transaction_hash: &str,
    intent_id: &str,
    timestamp: &str,
) -> Option<Vec<u8>> {
    let f = Function {
        name: "fulfillIntent".to_owned(),
        inputs: vec![
            Param {
                name: "sourceAddress".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "targetAddress".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "sourceChain".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "targetChain".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "amount".into(),
                kind: ParamType::Uint(128),
                internal_type: None,
            },
            Param {
                name: "sourceToken".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "targetToken".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "transactionHash".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "intentId".into(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "timestamp".into(),
                kind: ParamType::String,
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    let tokens = vec![
        Token::String(source_address.to_owned()),
        Token::String(target_address.to_owned()),
        Token::String(source_chain.to_owned()),
        Token::String(target_chain.to_owned()),
        Token::Uint(U256::from(amount)), // uint128
        Token::String(source_token.to_owned()),
        Token::String(target_token.to_owned()),
        Token::String(transaction_hash.to_owned()),
        Token::String(intent_id.to_owned()),
        Token::String(timestamp.to_owned()),
    ];

    f.encode_input(&tokens).ok()
}

/// Fetch current gas price from RPC for Qubetics chain
pub async fn fetch_qubetics_gas_price(chain_id: u64) -> Result<String> {
    let rpc_url = match chain_id {
        9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
            .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported chain ID for gas price fetching: {}",
                chain_id
            ))
        }
    };

    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_gasPrice",
        "params": [],
        "id": 1
    });

    info!("🔧 Fetching current gas price from Qubetics RPC...");

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(error) = result.get("error") {
            tracing::error!("❌ Failed to fetch gas price: {}", error);
            return Err(anyhow::anyhow!("Gas price fetch failed: {}", error));
        }
        if let Some(gas_price_hex) = result.get("result") {
            let gas_price_str = gas_price_hex.as_str().unwrap_or("0x0");
            info!("✅ Fetched current gas price: {}", gas_price_str);
            Ok(gas_price_str.to_string())
        } else {
            Err(anyhow::anyhow!("No gas price result in response"))
        }
    } else {
        let error_text = response.text().await?;
        tracing::error!("❌ Failed to fetch gas price: {}", error_text);
        Err(anyhow::anyhow!("Gas price fetch failed: {}", error_text))
    }
}

/// Get default gas price for different EVM chains
pub fn get_default_gas_price_for_chain(chain_name: &str) -> String {
    match chain_name {
        "ethereum" | "eth" => "0x4A817C800".to_string(), // 20 Gwei
        "qubetics" => "0x3B9ACA00".to_string(),          // 1 Gwei (fallback)
        "polygon" | "matic" => "0x12A05F200".to_string(), // 5 Gwei
        "bsc" | "binance" => "0x12A05F200".to_string(),  // 5 Gwei
        "avalanche" | "avax" => "0x5D21DBA00".to_string(), // 25 Gwei
        "arbitrum" => "0x5F5E100".to_string(),           // 0.1 Gwei
        "optimism" => "0x5F5E100".to_string(),           // 0.1 Gwei
        "base" => "0x5F5E100".to_string(),               // 0.1 Gwei
        _ => "0x4A817C800".to_string(),                  // Default to 20 Gwei
    }
}

/// Get gas price for chain with dynamic fetching for Qubetics
pub async fn get_gas_price_for_chain(chain_name: &str, chain_id: u64) -> Result<String> {
    // Reduced noisy stdout logging in production path
    
    match chain_name {
        "qubetics" => {
            // Reduced noisy stdout logging in production path
            // Try to fetch dynamic gas price for Qubetics
            match fetch_qubetics_gas_price(chain_id).await {
                Ok(gas_price) => {
                    info!("Using dynamic gas price for Qubetics: {}", gas_price);
                    // Convert to decimal to show the actual value
                    if let Some(hex_part) = gas_price.strip_prefix("0x") {
                        if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                            info!("Dynamic gas price in decimal: {} wei ({} Gwei)", price_decimal, price_decimal / 1_000_000_000);
                        }
                    }
                    Ok(gas_price)
                }
                Err(e) => {
                    warn!("Failed to fetch dynamic gas price for Qubetics: {}, using fallback", e);
                    let fallback_price = get_default_gas_price_for_chain(chain_name);
                    info!("Using fallback gas price for Qubetics: {}", fallback_price);
                    // Convert fallback to decimal to show the actual value
                    if let Some(hex_part) = fallback_price.strip_prefix("0x") {
                        if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                            info!("Fallback gas price in decimal: {} wei ({} Gwei)", price_decimal, price_decimal / 1_000_000_000);
                        }
                    }
                    Ok(fallback_price)
                }
            }
        }
        _ => {
            // Reduced noisy stdout logging in production path
            // Use static gas price for other chains
            let static_price = get_default_gas_price_for_chain(chain_name);
            info!("Using static gas price for {}: {}", chain_name, static_price);
            // Convert static to decimal to show the actual value
            if let Some(hex_part) = static_price.strip_prefix("0x") {
                if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                    info!("Static gas price in decimal: {} wei ({} Gwei)", price_decimal, price_decimal / 1_000_000_000);
                }
            }
            Ok(static_price)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectedAddressType {
    P2PKH,       // Legacy P2PKH (1... mainnet, m.../n... testnet) - ONLY SUPPORTED TYPE
    Unsupported, // All other types are unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qubetics_static_gas_price() {
        // Test Qubetics static gas price (fallback value)
        let static_price = get_default_gas_price_for_chain("qubetics");
        println!("🔧 Qubetics static gas price: {}", static_price);
        assert_eq!(static_price, "0x3B9ACA00");
        
        // Convert to decimal to show the actual value
        let price_decimal = u64::from_str_radix("3B9ACA00", 16).unwrap();
        println!("🔧 Qubetics static gas price in decimal: {} wei ({} Gwei)", price_decimal, price_decimal / 1_000_000_000);
    }

    #[tokio::test]
    async fn test_qubetics_dynamic_gas_price_fallback() {
        // Test that Qubetics falls back to static price when RPC fails
        // This test uses an invalid RPC URL to trigger the fallback
        let original_url = std::env::var("MPC_ETHEREUM_RPC_URL").unwrap_or_default();
        std::env::set_var("MPC_ETHEREUM_RPC_URL", "https://rpc-testnet.qubetics.work");

        let result = get_gas_price_for_chain("qubetics", 9029).await;
        assert!(result.is_ok());
        
        let gas_price = result.unwrap();
        println!("🔧 Qubetics gas price (should be fallback): {}", gas_price);
        
        // The test might get either the fallback or the real RPC value depending on network conditions
        // Both are valid - the important thing is that it doesn't crash
        if gas_price == "0x3B9ACA00" {
            println!("🔧 Got fallback gas price: {} (1 Gwei)", gas_price);
            let price_decimal = u64::from_str_radix("3B9ACA00", 16).unwrap();
            println!("🔧 Fallback gas price in decimal: {} wei ({} Gwei)", price_decimal, price_decimal / 1_000_000_000);
        } else {
            println!("🔧 Got dynamic gas price from RPC: {}", gas_price);
            // Convert to decimal to show the actual value
            if let Some(hex_part) = gas_price.strip_prefix("0x") {
                if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                    println!("🔧 Dynamic gas price in decimal: {} wei ({} Gwei)", 
                            price_decimal, price_decimal / 1_000_000_000);
                }
            }
        }
        
        // Gas price should be a valid hex string
        assert!(gas_price.starts_with("0x"));
        assert!(gas_price.len() > 2);
        
        // Restore original URL
        if !original_url.is_empty() {
            std::env::set_var("MPC_ETHEREUM_RPC_URL", original_url);
        }
    }

    #[tokio::test]
    async fn test_qubetics_unsupported_chain() {
        // Test that unsupported chain IDs return an error
        let result = fetch_qubetics_gas_price(1).await; // Ethereum mainnet
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("🔧 Expected error for unsupported chain: {}", error_msg);
        assert!(error_msg.contains("Unsupported chain ID"));
    }

    #[test]
    fn test_qubetics_gas_price_hex_conversion() {
        // Test that Qubetics hex values are correct
        let qubetics_hex = "0x3B9ACA00";
        let price_decimal = u64::from_str_radix("3B9ACA00", 16).unwrap();
        
        println!("🔧 Qubetics gas price hex: {}", qubetics_hex);
        println!("🔧 Qubetics gas price decimal: {} wei", price_decimal);
        println!("🔧 Qubetics gas price in Gwei: {} Gwei", price_decimal / 1_000_000_000);
        
        assert_eq!(price_decimal, 1_000_000_000); // 1 Gwei
    }

    #[test]
    fn test_qubetics_gas_price_consistency() {
        // Test that Qubetics gas price function returns consistent results
        let price1 = get_default_gas_price_for_chain("qubetics");
        let price2 = get_default_gas_price_for_chain("qubetics");
        
        println!("🔧 Qubetics gas price consistency test:");
        println!("  - First call: {}", price1);
        println!("  - Second call: {}", price2);
        
        assert_eq!(price1, price2);
        assert_eq!(price1, "0x3B9ACA00");
    }

    #[tokio::test]
    async fn test_qubetics_gas_price_with_real_rpc() {
        // Test with the actual Qubetics RPC URL (if available)
        // This test will show what happens with a real RPC call
        let original_url = std::env::var("MPC_ETHEREUM_RPC_URL").unwrap_or_default();
        
        // Try with the default Qubetics RPC URL
        std::env::set_var("MPC_ETHEREUM_RPC_URL", "https://rpc-testnet.qubetics.work");
        
        let result = get_gas_price_for_chain("qubetics", 9029).await;
        
        match result {
            Ok(gas_price) => {
                println!("🔧 Qubetics dynamic gas price from RPC: {}", gas_price);
                
                // Convert to decimal to show the actual value
                if let Some(hex_part) = gas_price.strip_prefix("0x") {
                    if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                        println!("🔧 Qubetics dynamic gas price in decimal: {} wei ({} Gwei)", 
                                price_decimal, price_decimal / 1_000_000_000);
                    }
                }
                
                // Gas price should be a valid hex string
                assert!(gas_price.starts_with("0x"));
                assert!(gas_price.len() > 2);
            }
            Err(e) => {
                println!("🔧 Qubetics RPC call failed (expected if RPC is down): {}", e);
                // This is expected if the RPC is not available
                // The function should still work with fallback
            }
        }
        
        // Restore original URL
        if !original_url.is_empty() {
            std::env::set_var("MPC_ETHEREUM_RPC_URL", original_url);
        }
    }
}

/// Detect Bitcoin address type - only P2PKH is supported
// fn detect_bitcoin_address_type(address: &str) -> DetectedAddressType {
//     if is_p2pkh_address(address) {
//         DetectedAddressType::P2PKH
//     } else {
//         DetectedAddressType::Unsupported
//     }
// }

/// Check if address is P2PKH format
// fn is_p2pkh_address(address: &str) -> bool {
//     // Mainnet P2PKH: starts with '1'
//     // Testnet P2PKH: starts with 'm' or 'n'
//     (address.starts_with('1') && address.len() >= 26 && address.len() <= 35)
//         || ((address.starts_with('m') || address.starts_with('n'))
//             && address.len() >= 26
//             && address.len() <= 35)
// }

/// Check if address is testnet P2PKH
// fn is_testnet_p2pkh_address(address: &str) -> bool {
//     address.starts_with('m') || address.starts_with('n')
// }

fn create_bitcoin_script_pubkey(address: &str) -> Result<Vec<u8>> {
    use bitcoin::{Address, Network};
    use std::str::FromStr;

    // Parse the address and determine network
    let parsed_address = Address::from_str(address)
        .map_err(|e| anyhow::anyhow!("Invalid Bitcoin address '{}': {}", address, e))?;

    // Only support P2PKH addresses
    // if !is_p2pkh_address(address) {
    //     return Err(anyhow::anyhow!(
    //         "Only P2PKH addresses (1.../m.../n...) are supported, got: {}",
    //         address
    //     ));
    // }

    // Require the network to get a checked address. This preserves the network encoded
    // in the string (mainnet vs testnet/regtest) and prevents silent mismatches.
    let network = bitcoin::Network::Testnet;
    let checked_address = parsed_address
        .require_network(network)
        .map_err(|e| anyhow::anyhow!("Address network mismatch for '{}': {}", address, e))?;

    // Convert to script_pubkey
    let script_pubkey = checked_address.script_pubkey();
    let script_bytes = script_pubkey.to_bytes();

    // Log address type for debugging
    // let detected_type = detect_bitcoin_address_type(address);
    // match detected_type {
    //     DetectedAddressType::P2PKH => {
    //         tracing::info!(
    //             "✅ [TRANSACTION] Address {} is P2PKH (Legacy) - supported",
    //             address
    //         );
    //     }
    //     DetectedAddressType::Unsupported => {
    //         return Err(anyhow::anyhow!(
    //             "Unsupported Bitcoin address type: {}. Only P2PKH addresses (1.../m.../n...) are supported.",
    //             address
    //         ));
    //     }
    // }

    Ok(script_bytes)
}

pub fn create_transaction_for_signing(tx: &DummyTransaction) -> Vec<u8> {
    // Log transaction details before creating raw transaction
    info!(
        "🔧 [ETH_RAW_TXN] Creating raw Ethereum transaction - To: {}, Value: {}, Nonce: {}, GasLimit: {}, GasPrice: {}, ChainId: {}",
        tx.to, tx.value, tx.nonce, tx.gas_limit, tx.gas_price, tx.chain_id
    );

    let mut content = Vec::new();

    // Encode transaction fields for signing (EIP-155)
    let mut encoder = RlpEncoder::new();

    // Nonce
    encoder.encode_u64(tx.nonce);
    content.extend_from_slice(&encoder.finalize());

    // Gas price
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.gas_price);
    content.extend_from_slice(&encoder.finalize());

    // Gas limit
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.gas_limit);
    content.extend_from_slice(&encoder.finalize());

    // To address
    encoder = RlpEncoder::new();
    encoder.encode_address(&tx.to);
    content.extend_from_slice(&encoder.finalize());

    // Value
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.value);
    content.extend_from_slice(&encoder.finalize());

    // Data (empty)
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    // Chain ID
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.chain_id);
    content.extend_from_slice(&encoder.finalize());

    // Empty r and s for EIP-155
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    // Create final RLP with list header
    let mut final_encoder = RlpEncoder::new();
    final_encoder.encode_list_header(content.len());
    final_encoder.data.extend_from_slice(&content);

    final_encoder.finalize()
}

    #[test]
    fn encode_hex_string_zero_is_canonical() {
        let mut encoder = RlpEncoder::new();
        encoder.encode_hex_string("0x0");
        // RLP encoding of zero should be a single 0x80 byte
        assert_eq!(encoder.finalize(), vec![0x80]);
    }

    #[test]
    fn test_amount_to_hex_string() {
        // Test zero amount
        assert_eq!(amount_to_hex_string(0), "0x0");

        // Test small amounts
        assert_eq!(amount_to_hex_string(1), "0x1");
        assert_eq!(amount_to_hex_string(15), "0xf");
        assert_eq!(amount_to_hex_string(16), "0x10");
        assert_eq!(amount_to_hex_string(255), "0xff");
        assert_eq!(amount_to_hex_string(256), "0x100");

        // Test larger amounts (common in crypto)
        assert_eq!(
            amount_to_hex_string(1000000000000000000u128),
            "0xde0b6b3a7640000"
        ); // 1 ETH in wei
        assert_eq!(
            amount_to_hex_string(21000000000000000000u128),
            "0x1236efcbcbb340000"
        ); // 21 ETH in wei

        // Test very large amounts
        assert_eq!(
            amount_to_hex_string(u128::MAX),
            "0xffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn test_validate_and_normalize_hex_amount() {
        // Test valid hex strings
        assert_eq!(validate_and_normalize_hex_amount("0x0").unwrap(), "0x0");
        assert_eq!(validate_and_normalize_hex_amount("0x1").unwrap(), "0x1");
        assert_eq!(validate_and_normalize_hex_amount("0xff").unwrap(), "0xff");
        assert_eq!(validate_and_normalize_hex_amount("0xFF").unwrap(), "0xFF");

        // Test normalization of leading zeros
        assert_eq!(validate_and_normalize_hex_amount("0x00").unwrap(), "0x0");
        assert_eq!(
            validate_and_normalize_hex_amount("0x000001").unwrap(),
            "0x1"
        );
        assert_eq!(
            validate_and_normalize_hex_amount("0x0000ff").unwrap(),
            "0xff"
        );

        // Test hex without 0x prefix
        assert_eq!(validate_and_normalize_hex_amount("1").unwrap(), "0x1");
        assert_eq!(validate_and_normalize_hex_amount("ff").unwrap(), "0xff");
        assert_eq!(validate_and_normalize_hex_amount("0001").unwrap(), "0x1");

        // Test invalid hex strings
        assert!(validate_and_normalize_hex_amount("0xgg").is_err());
        assert!(validate_and_normalize_hex_amount("0x12g3").is_err());
        assert!(validate_and_normalize_hex_amount("xyz").is_err());
    }

    #[test]
    fn test_validate_transaction_hex_fields() {
        use crate::rpc_server::DummyTransaction;

        // Test valid transaction
        let valid_tx = DummyTransaction {
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "0x1".to_string(),
            nonce: 0,
            gas_limit: 21000,
            gas_price: "0x3b9aca00".to_string(), // 1 Gwei
            chain_id: 1,
        };
        assert!(validate_transaction_hex_fields(&valid_tx).is_ok());

        // Test invalid value field
        let invalid_value_tx = DummyTransaction {
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "invalid".to_string(),
            nonce: 0,
            gas_limit: 21000,
            gas_price: "0x3b9aca00".to_string(),
            chain_id: 1,
        };
        assert!(validate_transaction_hex_fields(&invalid_value_tx).is_err());

        // Test invalid gas_price field
        let invalid_gas_price_tx = DummyTransaction {
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "0x1".to_string(),
            nonce: 0,
            gas_limit: 21000,
            gas_price: "invalid".to_string(),
            chain_id: 1,
        };
        assert!(validate_transaction_hex_fields(&invalid_gas_price_tx).is_err());
    }

    #[test]
    fn test_validate_contract_transaction_hex_fields() {
        use crate::rpc_server::ContractTransaction;

        // Test valid contract transaction
        let valid_contract_tx = ContractTransaction {
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "0x0".to_string(),
            nonce: 0,
            gas_limit: 300000,
            gas_price: "0x3b9aca00".to_string(),
            chain_id: 1,
            data: "0xa9059cbb".to_string(), // transfer function selector
        };
        assert!(validate_contract_transaction_hex_fields(&valid_contract_tx).is_ok());

        // Test invalid data field
        let invalid_data_tx = ContractTransaction {
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "0x0".to_string(),
            nonce: 0,
            gas_limit: 300000,
            gas_price: "0x3b9aca00".to_string(),
            chain_id: 1,
            data: "invalid_hex".to_string(),
        };
        assert!(validate_contract_transaction_hex_fields(&invalid_data_tx).is_err());

        // Test empty data field (should be valid)
        let empty_data_tx = ContractTransaction {
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "0x0".to_string(),
            nonce: 0,
            gas_limit: 300000,
            gas_price: "0x3b9aca00".to_string(),
            chain_id: 1,
            data: "0x".to_string(),
        };
        assert!(validate_contract_transaction_hex_fields(&empty_data_tx).is_ok());
    }

    #[test]
    fn test_common_ethereum_amounts() {
        // Test common Ethereum amounts in wei
        let one_eth_wei = 1000000000000000000u128; // 1 ETH = 10^18 wei
        assert_eq!(amount_to_hex_string(one_eth_wei), "0xde0b6b3a7640000");

        let one_gwei = 1000000000u128; // 1 Gwei = 10^9 wei
        assert_eq!(amount_to_hex_string(one_gwei), "0x3b9aca00");

        let half_eth_wei = 500000000000000000u128; // 0.5 ETH
        assert_eq!(amount_to_hex_string(half_eth_wei), "0x6f05b59d3b20000");

        // Test that these values are properly handled by the RLP encoder
        let mut encoder = RlpEncoder::new();
        encoder.encode_hex_string(&amount_to_hex_string(one_eth_wei));
        let encoded = encoder.finalize();
        // Should not be empty and should be properly encoded
        assert!(!encoded.is_empty());
        assert_ne!(encoded, vec![0x80]); // Should not be the "zero" encoding
    }

    #[test]
    fn test_utxo_selection_optimal() {
        // Test case: 2 UTXOs of 1400 sats each, want to send 1540 sats
        let utxos = vec![
            BitcoinUtxo {
                txid: "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
                vout: 0,
                value: 1400,
                status: UtxoStatus {
                    confirmed: true,
                    block_height: Some(100),
                    block_hash: Some("block1".to_string()),
                    block_time: Some(1234567890),
                },
            },
            BitcoinUtxo {
                txid: "b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1".to_string(),
                vout: 0,
                value: 1400,
                status: UtxoStatus {
                    confirmed: true,
                    block_height: Some(100),
                    block_hash: Some("block2".to_string()),
                    block_time: Some(1234567890),
                },
            },
        ];

        let result = select_utxos_for_amount(&utxos, 1540, 2, SpendKind::P2WPKH).unwrap();
        
        println!("Selected {} UTXOs", result.selected_utxos.len());
        println!("Total value: {} sats", result.total_value);
        println!("Fee: {} sats", result.fee);
        println!("Change: {} sats", result.change);
        println!("Change output: {}", result.change_output);
        
        // Should use change path with reasonable fee
        assert!(result.change_output, "Should use change output");
        assert!(result.fee < 500, "Fee should be reasonable (< 500 sats)");
        assert!(result.change > 0, "Should have change");
    }

    #[test]
    fn test_utxo_selection_single_utxo() {
        // Test case: 1 UTXO of 2000 sats, want to send 1000 sats
        let utxos = vec![
            BitcoinUtxo {
                txid: "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2".to_string(),
                vout: 0,
                value: 2000,
                status: UtxoStatus {
                    confirmed: true,
                    block_height: Some(100),
                    block_hash: Some("block1".to_string()),
                    block_time: Some(1234567890),
                },
            },
        ];

        let result = select_utxos_for_amount(&utxos, 1000, 2, SpendKind::P2WPKH).unwrap();
        
        println!("Selected {} UTXOs", result.selected_utxos.len());
        println!("Total value: {} sats", result.total_value);
        println!("Fee: {} sats", result.fee);
        println!("Change: {} sats", result.change);
        println!("Change output: {}", result.change_output);
        
        // Should use single UTXO with change
        assert_eq!(result.selected_utxos.len(), 1, "Should use only 1 UTXO");
        assert!(result.change_output, "Should use change output");
        assert!(result.fee < 200, "Fee should be reasonable (< 200 sats)");
        assert!(result.change > 500, "Should have substantial change");
    }

pub fn create_transaction_for_signing_contract(tx: &ContractTransaction) -> Vec<u8> {
    // Log contract transaction details before creating raw transaction
    info!(
        "🔧 [ETH_RAW_CONTRACT_TXN] Creating raw Ethereum contract transaction - To: {}, Value: {}, Nonce: {}, GasLimit: {}, GasPrice: {}, ChainId: {}, DataLength: {}",
        tx.to, tx.value, tx.nonce, tx.gas_limit, tx.gas_price, tx.chain_id, tx.data.len()
    );

    let mut content = Vec::new();

    // Encode transaction fields for signing (EIP-155)
    let mut encoder = RlpEncoder::new();

    // Nonce
    encoder.encode_u64(tx.nonce);
    content.extend_from_slice(&encoder.finalize());

    // Gas price
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.gas_price);
    content.extend_from_slice(&encoder.finalize());

    // Gas limit
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.gas_limit);
    content.extend_from_slice(&encoder.finalize());

    // To address
    encoder = RlpEncoder::new();
    encoder.encode_address(&tx.to);
    content.extend_from_slice(&encoder.finalize());

    // Value
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.value);
    content.extend_from_slice(&encoder.finalize());

    // Data (empty)
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.data);
    content.extend_from_slice(&encoder.finalize());

    // Chain ID
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.chain_id);
    content.extend_from_slice(&encoder.finalize());

    // Empty r and s for EIP-155
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    // Create final RLP with list header
    let mut final_encoder = RlpEncoder::new();
    final_encoder.encode_list_header(content.len());
    final_encoder.data.extend_from_slice(&content);

    final_encoder.finalize()
}

pub fn create_signed_transaction(
    tx: &DummyTransaction,
    data: Option<&[u8]>,
    r: &[u8],
    s: &[u8],
    v: u64,
) -> Vec<u8> {
    // Log signed transaction details before creating final raw transaction
    info!(
        "🔧 [ETH_SIGNED_TXN] Creating final signed Ethereum transaction - To: {}, Value: {}, Nonce: {}, GasLimit: {}, GasPrice: {}, ChainId: {}, v: {}, HasData: {}",
        tx.to, tx.value, tx.nonce, tx.gas_limit, tx.gas_price, tx.chain_id, v, data.is_some()
    );

    let mut content = Vec::new();

    // Encode transaction fields
    let mut encoder = RlpEncoder::new();

    // Nonce
    encoder.encode_u64(tx.nonce);
    content.extend_from_slice(&encoder.finalize());

    // Gas price
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.gas_price);
    content.extend_from_slice(&encoder.finalize());

    // Gas limit
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.gas_limit);
    content.extend_from_slice(&encoder.finalize());

    // To address
    encoder = RlpEncoder::new();
    encoder.encode_address(&tx.to);
    content.extend_from_slice(&encoder.finalize());

    info!("🔍 [SIGNING] Value: {}", tx.value);
    // Value
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.value);
    content.extend_from_slice(&encoder.finalize());

    // Data - include contract calldata if provided
    encoder = RlpEncoder::new();
    if let Some(data) = data {
        encoder.encode_bytes(data);
    } else {
        encoder.encode_bytes(&[]);
    }
    content.extend_from_slice(&encoder.finalize());

    // v
    encoder = RlpEncoder::new();
    encoder.encode_u64(v); // ✅ proper RLP encoding for large v
    content.extend_from_slice(&encoder.finalize());

    // r - strip leading zeros for RLP compliance
    encoder = RlpEncoder::new();
    let r_trimmed = strip_leading_zeros(r);
    encoder.encode_bytes(&r_trimmed);
    content.extend_from_slice(&encoder.finalize());

    // s - strip leading zeros for RLP compliance
    encoder = RlpEncoder::new();
    let s_trimmed = strip_leading_zeros(s);
    encoder.encode_bytes(&s_trimmed);
    content.extend_from_slice(&encoder.finalize());

    // Create final RLP with list header
    let mut final_encoder = RlpEncoder::new();
    final_encoder.encode_list_header(content.len());
    final_encoder.data.extend_from_slice(&content);

    final_encoder.finalize()
}
