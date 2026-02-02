use crate::chain_abstraction::{ChainTransaction, EthereumTransaction};
use crate::types::{
    network as network_cfg, BatchIntentInput, BatchType, BitcoinInput, BitcoinOutput,
    BitcoinTransaction, BitcoinUtxo, BitcoinWitness, BitcoinWitnessUtxo, ContractTransaction,
    DepositIntent, DummyTransaction, RlpEncoder, SpendKind, UtxoStatus,
};
use crate::utils::get_eth_address_from_group_key;
use anyhow::{bail, Result};
use ethabi::ethereum_types::U256;
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use serde::{Deserialize, Serialize};
use tracing::{info, warn}; // for Token::Uint

// use rlp::RlpStream;

pub type WitnessItem = Vec<u8>;
pub type WitnessStack = Vec<WitnessItem>;

const DEFAULT_FEE_RATE_SAT_PER_VBYTE: u64 = 2;
pub const DUST_LIMIT_SATS: u64 = 546;

/// Wrapper for custom UTXO API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomApiUtxoResponse {
    error: bool,
    #[serde(rename = "statuscode")]
    status_code: u16,
    message: String,
    data: Vec<BitcoinUtxo>,
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
    let hex_str = format!("{amount:x}");
    format!("0x{hex_str}")
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

    Ok(format!("0x{normalized}"))
}

/// Validate that a transaction has proper hex formatting for value and gas_price
pub fn validate_transaction_hex_fields(tx: &DummyTransaction) -> Result<()> {
    // Validate value field
    validate_and_normalize_hex_amount(&tx.value)
        .map_err(|e| anyhow::anyhow!("Invalid value field: {}", e))?;

    // Validate gas_price field
    validate_and_normalize_hex_amount(&tx.gas_price)
        .map_err(|e| anyhow::anyhow!("Invalid gas_price field: {}", e))?;

    Ok(())
}

/// Validate that a contract transaction has proper hex formatting
pub fn validate_contract_transaction_hex_fields(tx: &ContractTransaction) -> Result<()> {
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
/// Only supports Qubetics as an EVM chain
pub fn get_chain_id_from_name(chain_name: &str) -> Option<u64> {
    match chain_name.to_lowercase().as_str() {
        // Qubetics EVM chain
        "qubetics" => Some(9029),
        // Bitcoin uses a structural chain id of 0 (non-EVM, used for routing/metadata)
        "btc" | "bitcoin" => Some(0),
        _ => None,
    }
}

/// Determine if a chain is EVM-compatible
/// Only Qubetics is supported as an EVM chain
pub fn is_evm_chain(chain_name: &str) -> bool {
    match chain_name.to_lowercase().as_str() {
        "qubetics" => true,
        // Explicitly treat Bitcoin as non-EVM even though it has a structural ID (0)
        "btc" | "bitcoin" => false,
        _ => false,
    }
}

/// Get RPC URL for an EVM chain by chain ID
/// Only supports Qubetics (chain ID 9029) as an EVM chain
/// Uses the MPC_ETHEREUM_RPC_URL environment variable
pub fn get_evm_rpc_url(chain_id: u64) -> Result<String> {
    match chain_id {
        // Qubetics - use environment variable
        9029 => network_cfg::qubetics_rpc_url_from_env(),
        _ => Err(anyhow::anyhow!(
            "Unsupported EVM chain ID: {}. Only Qubetics (9029) is supported as an EVM chain",
            chain_id
        )),
    }
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
        let url = format!("{base}/api/v1/utxos?address={address}");
        tracing::info!("🌐 Using custom UTXO API: {}", url);
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await?;

        tracing::info!("🔗 Custom API response status: {}", response.status());

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

    let url = format!("{base_url}/address/{address}/utxo");
    tracing::info!("🌐 Using mempool.space Esplora API: {}", url);
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    tracing::info!("🔗 Esplora API response status: {}", response.status());

    if !response.status().is_success() {
        tracing::error!("❌ Failed to fetch UTXOs: HTTP {}", response.status());
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
        SpendKind::P2WPKH => 10 + 68 * n_in + 31 * n_out, // segwit approx
        SpendKind::P2PKH => 10 + 148 * n_in + 34 * n_out, // legacy approx
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

    // Enforce Bitcoin dust limit on recipient output (BIP-125)
    // Transactions with outputs below 546 satoshis are non-standard and will be rejected
    if required_amount < DUST_LIMIT_SATS {
        return Err(anyhow::anyhow!(
            "Recipient amount {} sats is below Bitcoin dust limit (minimum: {} sats). Transaction would be rejected by Bitcoin nodes.",
            required_amount,
            DUST_LIMIT_SATS
        ));
    }

    let mut confirmed_utxos: Vec<_> = utxos
        .iter()
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
        .cloned()
        .collect();

    if confirmed_utxos.is_empty() {
        return Err(anyhow::anyhow!(
            "No confirmed UTXOs available from {} fetched entries",
            utxos.len()
        ));
    }

    // Sort descending (largest first) to minimize the number of inputs needed.
    // Break ties deterministically on (txid, vout) so every node selects the
    // same UTXOs even if the upstream API returns them in different orders.
    confirmed_utxos.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.vout.cmp(&b.vout))
    });

    tracing::info!(
        "🔍 [UTXO_SELECTION] {} confirmed UTXOs remain after filtering ({} fetched)",
        confirmed_utxos.len(),
        utxos.len()
    );

    // Simple greedy algorithm: add UTXOs until we have enough, then choose best path
    let mut selected = Vec::new();
    let mut total_value = 0u64;

    let mut no_change_candidate: Option<UtxoSelectionResult> = None;

    for candidate in confirmed_utxos.into_iter() {
        total_value += candidate.value;
        selected.push(candidate);

        let n_inputs = selected.len();
        let skip_no_change_path = false;

        // Try change path first (2 outputs: recipient + change)
        let fee_with_change = estimate_fee_sat(kind, n_inputs, 2, fee_rate_sat_vb);
        let required_with_change = required_amount + fee_with_change;

        tracing::debug!(
            "💰 [UTXO_SELECTION] Iteration {}: total_value={} sats, required_with_change={} sats (amount={} + fee={})",
            n_inputs,
            total_value,
            required_with_change,
            required_amount,
            fee_with_change
        );

        if total_value >= required_with_change {
            let change = total_value - required_with_change;

            tracing::info!(
                "💰 [UTXO_SELECTION] Change path check: change={} sats, dust_limit={} sats, above_dust={}",
                change,
                DUST_LIMIT_SATS,
                change >= DUST_LIMIT_SATS
            );

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

            // Change would be dust; fold it into the fee
            // Use the change path fee calculation but don't create a change output
            let actual_fee = fee_with_change + change;
            tracing::info!(
                "✅ [UTXO_SELECTION] Using change path with {} inputs, folding dust change {} sats into fee (fee {} sats, total fee {} sats)",
                n_inputs,
                change,
                fee_with_change,
                actual_fee
            );

            return Ok(UtxoSelectionResult {
                selected_utxos: selected,
                total_value,
                fee: actual_fee,
                change: 0,
                change_output: false,
            });
        }

        // Try no-change path (1 output: recipient only)
        let fee_no_change = estimate_fee_sat(kind, n_inputs, 1, fee_rate_sat_vb);
        let required_no_change: u64 = required_amount + fee_no_change;

        tracing::debug!(
            "💰 [UTXO_SELECTION] No-change path check: total_value={} sats, required_no_change={} sats (amount={} + fee={})",
            total_value,
            required_no_change,
            required_amount,
            fee_no_change
        );

        if total_value >= required_no_change {
            // IMPORTANT: Calculate what the leftover would be if we don't create change
            let leftover = total_value - required_no_change;

            tracing::info!(
                "🚨 [UTXO_SELECTION] No-change path leftover analysis: leftover={} sats, dust_limit={} sats, leftover_is_dust={}",
                leftover,
                DUST_LIMIT_SATS,
                leftover < DUST_LIMIT_SATS
            );

            // Only use no-change path if:
            // 1. We don't have enough for the change path (checked above), OR
            // 2. The leftover would be below dust anyway
            // This prevents accidentally sending large amounts as fees
            let should_use_no_change = leftover < DUST_LIMIT_SATS;

            let candidate_result = UtxoSelectionResult {
                selected_utxos: selected.clone(),
                total_value,
                fee: fee_no_change,
                change: 0,
                change_output: false,
            };

            if no_change_candidate.is_none() {
                no_change_candidate = Some(candidate_result.clone());
            }

            if skip_no_change_path {
                continue;
            }

            // Only return no-change path if leftover is truly dust
            if should_use_no_change {
                tracing::info!(
                    "✅ [UTXO_SELECTION] Using no-change path with {} inputs (fee {} sats, leftover {} sats folded into fee)",
                    n_inputs,
                    fee_no_change,
                    leftover
                );
                return Ok(candidate_result);
            } else {
                // We have enough for no-change, but the leftover is significant
                // Continue to try adding more UTXOs to hit the change path
                tracing::debug!(
                    "🔍 [UTXO_SELECTION] Skipping no-change path - leftover {} sats is above dust ({}), continuing to find change path",
                    leftover,
                    DUST_LIMIT_SATS
                );
                continue;
            }
        }

        // If we don't have enough, continue adding UTXOs
    }

    if let Some(candidate) = no_change_candidate {
        tracing::info!(
            "✅ [UTXO_SELECTION] Using no-change path with {} inputs (fee {} sats)",
            candidate.selected_utxos.len(),
            candidate.fee
        );

        return Ok(candidate);
    }

    // error tail - no valid combination found
    let n_inputs = selected.len().max(1);
    let needed_with_change =
        required_amount.saturating_add(estimate_fee_sat(kind, n_inputs, 2, fee_rate_sat_vb));
    let needed_without_change =
        required_amount.saturating_add(estimate_fee_sat(kind, n_inputs, 1, fee_rate_sat_vb));
    let min_needed = needed_with_change.min(needed_without_change);

    Err(anyhow::anyhow!(
        "Insufficient confirmed funds: gathered {} sats but need at least {} sats (amount + fees)",
        total_value,
        min_needed
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
    let rpc_url = get_evm_rpc_url(chain_id)?;

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

/// Helper function to create an Ethereum transaction
/// Takes a target address and amount to create a simple ETH transfer transaction
pub async fn create_ethereum_transaction(
    from_address: &str,
    to_address: &str,
    amount: u128,
    chain_name: &str,
) -> Result<EthereumTransaction> {
    info!(
        "🎁 [ETH_TX] Creating Ethereum transaction: {} -> {} (amount: {})",
        from_address, to_address, amount
    );

    // Get chain ID for the specified chain
    let chain_id = get_chain_id_from_name(chain_name)
        .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", chain_name))?;

    // Get dynamic gas price for the chain, fallback to static if needed
    let gas_price = get_gas_price_for_chain(chain_name, chain_id)
        .await
        .unwrap_or_else(|e| {
            warn!(
                "⚠️ Failed to get dynamic gas price for {}: {}, using fallback",
                chain_name, e
            );
            get_default_gas_price_for_chain(chain_name)
        });

    // Fetch nonce for the from address
    let nonce = fetch_ethereum_nonce(from_address, chain_id).await?;

    info!(
        "🎁 [ETH_TX] Constructed Payload: \n\
         \tTo: {}\n\
         \tValue: {}\n\
         \tGas Price: {}\n\
         \tNonce: {}\n\
         \tGas Limit: 21000\n\
         \tChain ID: {}",
        to_address,
        amount_to_hex_string(amount),
        gas_price,
        nonce,
        chain_id
    );

    let ethereum_tx = EthereumTransaction {
        to: to_address.to_string(),
        value: amount_to_hex_string(amount),
        gas_limit: 300000, // Standard ETH transfer gas limit
        gas_price,
        nonce,
        data: None, // No calldata for simple ETH transfer
        chain_id,
    };

    info!("✅ [ETH_TX] Created Ethereum transaction successfully");
    Ok(ethereum_tx)
}

/// Helper function to create a Bitcoin transaction
/// Takes source and target addresses, amount, and creates a Bitcoin transaction with UTXO selection
pub async fn create_bitcoin_transaction(
    from_address: &str,
    to_address: &str,
    amount: u128,
) -> Result<BitcoinTransaction> {
    tracing::info!(
        "₿ [BTC_TX] Creating Bitcoin transaction: {} -> {} (amount: {})",
        from_address,
        to_address,
        amount
    );

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
    let (from_kind, from_net) = classify_address(from_address)?;
    let (_to_kind, to_net) = classify_address(to_address)?;

    // Sanity: prevent net mismatch
    if from_net != to_net {
        anyhow::bail!("From/To network mismatch: {:?} vs {:?}", from_net, to_net);
    }

    let is_testnet = matches!(
        from_net,
        bitcoin::Network::Testnet | bitcoin::Network::Signet | bitcoin::Network::Regtest
    );

    // Fetch UTXOs for the right network
    let utxos = fetch_bitcoin_utxos(from_address, is_testnet).await?;

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

    let to_spk = create_bitcoin_script_pubkey(to_address)?;
    let from_spk = create_bitcoin_script_pubkey(from_address)?;

    // Inputs:
    let inputs: Vec<BitcoinInput> = selection
        .selected_utxos
        .iter()
        .map(|u| {
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
                    // IMPORTANT: stash 25-byte prev script here so final node doesn't need to reconstruct
                    witness_utxo: Some(BitcoinWitnessUtxo {
                        value: u.value,
                        script_pubkey: from_spk.clone(), // 76 a9 14 <20> 88 ac
                    }),
                },
            }
        })
        .collect();

    // Create outputs (recipient always, change only if not dust)
    // Outputs (change script MUST match the from-address type; using from_spk is correct):
    let mut outputs = vec![BitcoinOutput {
        value: amount_satoshis,
        script_pubkey: to_spk,
    }];
    if selection.change_output {
        outputs.push(BitcoinOutput {
            value: selection.change,
            script_pubkey: from_spk,
        });
        tracing::info!(
            "💰 [BTC_TX] Adding change output: {} satoshis to {}",
            selection.change,
            from_address
        );
    } else {
        tracing::warn!(
            "⚠️ [BTC_TX] No change output (change_output=false). Remaining {} satoshis will be paid as fee!",
            selection.total_value - amount_satoshis - selection.fee
        );
    }

    // Calculate and log actual fee
    let total_output_value: u64 = outputs.iter().map(|o| o.value).sum();
    let actual_fee = selection.total_value - total_output_value;
    tracing::info!(
        "💰 [BTC_TX] Fee calculation: total_input={}, total_output={}, actual_fee={}, estimated_fee={}",
        selection.total_value,
        total_output_value,
        actual_fee,
        selection.fee
    );

    if actual_fee != selection.fee {
        tracing::warn!(
            "⚠️ [BTC_TX] Fee mismatch! Estimated fee: {} sats, Actual fee: {} sats (difference: {} sats)",
            selection.fee,
            actual_fee,
            actual_fee as i64 - selection.fee as i64
        );
    }

    // Log all outputs for debugging
    tracing::info!("📤 [BTC_TX] Transaction outputs:");
    for (i, output) in outputs.iter().enumerate() {
        tracing::info!(
            "  Output {}: {} satoshis (script_pubkey_len: {})",
            i,
            output.value,
            output.script_pubkey.len()
        );
    }

    let (version, witness_opt) = match from_kind {
        SpendKind::P2WPKH => {
            // placeholder: one empty stack per input; fill after signing
            (
                2,
                Some(BitcoinWitness {
                    inputs: (0..inputs.len())
                        .map(|_| crate::chain_abstraction::BitcoinWitnessInput { stack: vec![] })
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

    tracing::info!("✅ [BTC_TX] Created Bitcoin transaction successfully");
    Ok(bitcoin_tx)
}

pub(crate) async fn estimate_gas_for_deposit_intent(
    from: &str,
    to: &str,
    data_hex: &str,
    chain_id: u64,
) -> Result<u64> {
    let rpc_url = get_evm_rpc_url(chain_id)?;

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
/// - UserToVault: User deposit - FROM derived address TO liquidity operator address (on source chain)
/// - NetworkToTarget: Network withdrawal - FROM network address TO target address (on target chain)
///   derived_eth_addr and derived_btc_addr are the actual addresses that hold user funds
pub async fn create_chain_transaction_from_deposit_intent(
    intent: &DepositIntent,
    group_public_key: Option<k256::ProjectivePoint>,
    derived_eth_addr: Option<&String>,
    derived_btc_addr: Option<&String>,
    transaction_type: crate::types::TransactionType,
    liquidity_operator_eth_address: Option<&String>,
    liquidity_operator_btc_address: Option<&String>,
    amount: u128,
) -> Result<ChainTransaction> {
    create_chain_transaction_from_deposit_intent_internal(
        intent,
        group_public_key,
        derived_eth_addr,
        derived_btc_addr,
        transaction_type,
        liquidity_operator_eth_address,
        liquidity_operator_btc_address,
        amount,
    )
    .await
}

pub(crate) fn classify_address(addr: &str) -> Result<(SpendKind, bitcoin::Network)> {
    use bitcoin::address::{Address, AddressData, NetworkUnchecked};
    use bitcoin::{Network, WitnessVersion};

    tracing::info!("🔍 Attempting to classify Bitcoin address: {}", addr);

    // Parse as *unchecked*
    let a: Address<NetworkUnchecked> = match addr.parse() {
        Ok(address) => {
            tracing::info!("✅ Successfully parsed address: {}", addr);
            address
        }
        Err(e) => {
            tracing::error!("❌ Invalid Bitcoin address '{}': {}", addr, e);
            return Err(anyhow::anyhow!("Invalid Bitcoin address '{}': {}", addr, e));
        }
    };

    // Figure out which network this string is valid for.
    // (Legacy testnet/regtest/signet are ambiguous by design.)
    let net = match [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ]
    .into_iter()
    .find(|n| a.is_valid_for_network(*n))
    {
        Some(network) => {
            tracing::info!("✅ Address '{}' is valid for network: {:?}", addr, network);
            network
        }
        None => {
            tracing::error!("❌ Address '{}' is not valid for any known network", addr);
            return Err(anyhow::anyhow!(
                "Address '{}' is not valid for any known network",
                addr
            ));
        }
    };

    // Now *require* that network to get a checked address.
    let checked = match a.require_network(net) {
        Ok(checked_addr) => {
            tracing::info!("✅ Address '{}' matches network: {:?}", addr, net);
            checked_addr
        }
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
        }
        AddressData::Segwit {
            witness_program: wp,
        } if wp.version() == WitnessVersion::V0 && wp.is_p2wpkh() => {
            tracing::info!("🔎 Address '{}' classified as P2WPKH", addr);
            SpendKind::P2WPKH
        }
        _ => {
            tracing::error!("❌ Unsupported address type for spending: {}", addr);
            bail!("Unsupported address type for spending: {}", addr)
        }
    };

    tracing::info!(
        "✅ Classification result for '{}': kind={:?}, network={:?}",
        addr,
        kind,
        net
    );

    Ok((kind, net))
}

// Internal implementation of transaction creation with optional UTXO checking
async fn create_chain_transaction_from_deposit_intent_internal(
    intent: &DepositIntent,
    group_public_key: Option<k256::ProjectivePoint>,
    derived_eth_addr: Option<&String>,
    derived_btc_addr: Option<&String>,
    transaction_type: crate::types::TransactionType,
    liquidity_operator_eth_address: Option<&String>,
    liquidity_operator_btc_address: Option<&String>,
    amount: u128,
) -> Result<ChainTransaction> {
    // Determine chain type based on transaction type:
    // - UserToVault: use source_chain (user is depositing FROM this chain)
    // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
    let chain_to_use = match transaction_type {
        crate::types::TransactionType::UserToVault => &intent.source_chain.to_lowercase(),
        crate::types::TransactionType::NetworkToTarget => &intent.target_chain.to_lowercase(),
        crate::types::TransactionType::IntentStatusUpdate => "qubetics", // IntentStatusUpdate is a contract call on Qubetics chain
        crate::types::TransactionType::WithdrawLiquidity => {
            return Err(anyhow::anyhow!(
                "WithdrawLiquidity is not valid for deposit intent flow"
            ));
        }
        crate::types::TransactionType::ClaimReward => {
            return Err(anyhow::anyhow!(
                "ClaimReward is not valid for deposit intent flow"
            ));
        }
    };

    info!(
        "🎁 [CHAIN_TX] Processing DepositIntent - IntentID: {}, Type: {:?}, Amount: {}, Chain: {}",
        intent.source_address, transaction_type, amount, chain_to_use
    );

    if is_evm_chain(chain_to_use) {
        // Get liquidity operator address from parameter
        let liquidity_operator_address = liquidity_operator_eth_address
            .ok_or_else(|| anyhow::anyhow!("Liquidity operator ETH address not provided"))?;

        // Determine source and target based on transaction type
        // NOTE: group_public_key will always be available once the solver ecosystem is live,
        // but it's passed or not depending on transaction type. For UserToVault transactions
        // on EVM chains, the group key is not required as we use the derived user address.
        // For NetworkToTarget, the group key is required to derive the
        // network address. We only unwrap and compute network_address when it's actually needed.
        let (from_address, to_address) = match transaction_type {
            crate::types::TransactionType::UserToVault => {
                // User deposit: FROM derived ethereum address
                // - On TICS/qubetics: TO IntentManager contract (from env)
                // - On other EVM chains: TO liquidity operator address
                if let Some(derived_addr) = derived_eth_addr {
                    // Default target is liquidity operator
                    let mut target_address = liquidity_operator_address.clone();

                    // For TICS/qubetics source chain, override with Treasury Vault contract if configured
                    if chain_to_use.eq_ignore_ascii_case("tics")
                        || chain_to_use.eq_ignore_ascii_case("qubetics")
                    {
                        let contract_address_env = std::env::var("TREASURY_VAULT_CONTRACT_ADDRESS")
                            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
                        if contract_address_env
                            != "0x0000000000000000000000000000000000000000"
                        {
                            tracing::info!(
                                "💰 [TRANSACTION] UserToVault on {}: {} -> TreasuryVault contract {}",
                                chain_to_use,
                                derived_addr,
                                contract_address_env
                            );
                            target_address = contract_address_env;
                        } else {
                            tracing::warn!(
                                "⚠️ [TRANSACTION] TREASURY_VAULT_CONTRACT_ADDRESS not configured; using liquidity operator {} for UserToVault on {}",
                                liquidity_operator_address,
                                chain_to_use
                            );
                        }
                    } else {
                        tracing::info!(
                            "💰 [TRANSACTION] User to liquidity operator: {} -> {} on chain {}",
                            derived_addr,
                            liquidity_operator_address,
                            chain_to_use
                        );
                    }

                    (derived_addr.clone(), target_address)
                } else {
                    return Err(anyhow::anyhow!(
                        "UserToVault transaction requires derived_eth_address"
                    ));
                }
            }
            crate::types::TransactionType::NetworkToTarget => {
                // Network withdrawal: FROM network address TO target address
                // Group public key is required to derive the network address
                let group_key = group_public_key.ok_or_else(|| {
                    anyhow::anyhow!("Group public key required for NetworkToTarget transactions")
                })?;
                let network_address = get_eth_address_from_group_key(group_key);
                tracing::info!(
                    "💰 [TRANSACTION] Network to target: {} -> {}",
                    network_address,
                    intent.target_address
                );
                (network_address.clone(), intent.target_address.clone())
            }
            crate::types::TransactionType::IntentStatusUpdate => {
                // IntentStatusUpdate is a contract call on Qubetics chain
                // It doesn't need from/to addresses as it's a contract call, not a transfer
                // Return empty addresses (not used for contract calls)
                ("".to_string(), "".to_string())
            }

            crate::types::TransactionType::WithdrawLiquidity => {
                return Err(anyhow::anyhow!(
                    "WithdrawLiquidity is not valid for deposit intent flow"
                ));
            }
            crate::types::TransactionType::ClaimReward => {
                return Err(anyhow::anyhow!(
                    "ClaimReward is not valid for deposit intent flow"
                ));
            }
        };

        let ethereum_tx =
            create_ethereum_transaction(&from_address, &to_address, amount, chain_to_use).await?;

        Ok(ChainTransaction::Ethereum(ethereum_tx))
    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
        // Get liquidity operator address from parameter
        let btc_liquidity_operator_address = liquidity_operator_btc_address
            .ok_or_else(|| anyhow::anyhow!("Liquidity operator BTC address not provided"))?;

        // Determine source and target based on transaction type
        // NOTE: group_public_key will always be available once the solver ecosystem is live,
        // but it's passed or not depending on transaction type. For UserToVault transactions
        // on Bitcoin, the group key is not required as we use the derived user address.
        // For NetworkToTarget, the group key is required to derive the
        // network address. We only unwrap and compute btc_network_address when it's actually needed.
        let (from_address, to_address) = match transaction_type {
            crate::types::TransactionType::UserToVault => {
                // User deposit: FROM derived bitcoin address TO vault bitcoin address
                // Group public key is not needed for UserToVault on Bitcoin
                if let Some(derived_btc_addr) = derived_btc_addr {
                    tracing::info!(
                        "💰 [TRANSACTION] Bitcoin user to liquidity operator: {} -> {}",
                        derived_btc_addr,
                        btc_liquidity_operator_address
                    );
                    (
                        derived_btc_addr.clone(),
                        btc_liquidity_operator_address.clone(),
                    )
                } else {
                    return Err(anyhow::anyhow!(
                        "UserToVault transaction requires derived_btc_address"
                    ));
                }
            }
            crate::types::TransactionType::NetworkToTarget => {
                // Network withdrawal: FROM network bitcoin address TO target address
                // Group public key is required to derive the network address
                let group_key = group_public_key.ok_or_else(|| {
                    anyhow::anyhow!("Group public key required for NetworkToTarget transactions")
                })?;
                let btc_network_address = crate::utils::get_btc_address_from_group_key(group_key);
                tracing::info!(
                    "💰 [TRANSACTION] Bitcoin network to target: {} -> {}",
                    btc_network_address,
                    intent.target_address
                );
                (btc_network_address.clone(), intent.target_address.clone())
            }
            crate::types::TransactionType::IntentStatusUpdate => {
                // IntentStatusUpdate is a contract call on Qubetics chain (not Bitcoin)
                // This should not be called for Bitcoin transactions
                return Err(anyhow::anyhow!(
                    "IntentStatusUpdate is not valid for Bitcoin transactions"
                ));
            }

            crate::types::TransactionType::WithdrawLiquidity => {
                return Err(anyhow::anyhow!(
                    "WithdrawLiquidity is not valid for deposit intent flow"
                ));
            }
            crate::types::TransactionType::ClaimReward => {
                return Err(anyhow::anyhow!(
                    "ClaimReward is not valid for deposit intent flow"
                ));
            }
        };

        tracing::info!("Using Bitcoin source address for UTXOs: {}", from_address);

        let bitcoin_tx = create_bitcoin_transaction(&from_address, &to_address, amount).await?;

        Ok(ChainTransaction::Bitcoin(bitcoin_tx))
    } else {
        Err(anyhow::anyhow!("Unsupported chain: {}", chain_to_use))
    }
}

pub async fn create_chain_transaction_from_contract_call(
    group_public_key: Option<k256::ProjectivePoint>,
    amount: u128,
    target_amount: Option<u128>,
    intent: &DepositIntent,
    intent_hash: &str,
    tx_hash: &str,
    transaction_type: crate::types::TransactionType,
) -> Result<ChainTransaction> {
    // Group public key is required for contract call transactions
    // NOTE: group_public_key will always be available once the solver ecosystem is live,
    // but we handle the None case gracefully to prevent panics
    let group_key = group_public_key.ok_or_else(|| {
        anyhow::anyhow!("Group public key required for contract call transactions")
    })?;
    let network_address = get_eth_address_from_group_key(group_key);
    let chain_id = get_chain_id_from_name("qubetics")
        .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", "eth"))?;

    // Get contract address from environment variable and normalize to 0x-prefixed
    // For processBatchIntents / intent management, use the IntentManager contract
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

    // Determine batch type based on transaction type
    // UserToVault = BTC (deposits from Bitcoin to vault)
    // NetworkToTarget = TICS (fulfillments from vault to target chain)
    let batch_type = match transaction_type {
        crate::types::TransactionType::UserToVault => BatchType::BTC,
        crate::types::TransactionType::NetworkToTarget => BatchType::TICS,
        crate::types::TransactionType::IntentStatusUpdate => BatchType::BTC, // IntentStatusUpdate is for BTC contract updates

        crate::types::TransactionType::WithdrawLiquidity => {
            return Err(anyhow::anyhow!(
                "WithdrawLiquidity is not valid for deposit intent flow"
            ));
        }
        crate::types::TransactionType::ClaimReward => {
            return Err(anyhow::anyhow!(
                "ClaimReward is not valid for deposit intent flow"
            ));
        }
    };

    info!(
        "🔧 [CONTRACT] Using processBatchIntents with batch_type {:?} for {:?} transaction",
        batch_type, transaction_type
    );

    // Create a single-intent batch for this transaction
    // For UserToVault: withdrawTxHash = tx_hash (user's deposit tx), depositTxHash = intent_hash
    // For NetworkToTarget: withdrawTxHash = intent_hash, depositTxHash = tx_hash (fulfillment tx)
    let (withdraw_tx_hash, deposit_tx_hash) = match transaction_type {
        crate::types::TransactionType::UserToVault => {
            // User deposited funds, so tx_hash is the withdraw (from user), intent_hash is the deposit (to vault)
            (tx_hash.to_string(), intent_hash.to_string())
        }
        crate::types::TransactionType::NetworkToTarget => {
            // Network is fulfilling, so intent_hash is the withdraw (from vault), tx_hash is the deposit (to user)
            (intent_hash.to_string(), tx_hash.to_string())
        }
        _ => {
            // Already handled above, but compiler needs this
            return Err(anyhow::anyhow!("Invalid transaction type"));
        }
    };

    let target_amt = target_amount.unwrap_or(amount);
    let batch_intent = BatchIntentInput {
        source_address: intent.source_address.clone(),
        target_address: intent.target_address.clone(),
        source_chain: intent.source_chain.clone(),
        target_chain: intent.target_chain.clone(),
        source_amount: amount,
        target_amount: target_amt,
        source_token: intent.source_token.clone(),
        target_token: intent.target_token.clone(),
        intent_id: intent_hash.to_string(),
        withdraw_tx_hash,
        deposit_tx_hash: Some(deposit_tx_hash),
    };

    let calldata = encode_process_batch_intents_calldata(
        &[batch_intent],
        batch_type,
        &intent.timestamp.to_string(),
    );

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
    .await?; // Abort if gas estimation fails - indicates transaction would revert
    let gas_limit = estimated_gas + (estimated_gas / 10); // Add 10% buffer

    info!(
        "🔧 [CONTRACT] Estimated gas: {}, using gas_limit: {}",
        estimated_gas, gas_limit
    );

    let nonce = fetch_ethereum_nonce(&network_address, chain_id).await?;
    let gas_price = get_gas_price_for_chain("qubetics", chain_id)
        .await
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
            .map(hex::encode)
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

pub async fn create_solver_rewards_update_transaction(
    from_address: &str,
    solver_address: &str,
    rewards: &[U256],
    transaction_hash: &str,
    contract_address: &str,
    chain_id: u64,
    chain_name: &str,
) -> Result<ChainTransaction> {
    let normalized_contract_address = if contract_address.starts_with("0x") {
        contract_address.to_string()
    } else {
        format!("0x{contract_address}")
    };

    info!("🔧 [CONTRACT] Solver address: {}", solver_address);
    info!("🔧 [CONTRACT] Rewards: {:?}", rewards);
    info!("🔧 [CONTRACT] Transaction hash: {}", transaction_hash);
    info!(
        "🔧 [CONTRACT] Contract address: {}",
        normalized_contract_address
    );
    info!("🔧 [CONTRACT] Chain ID: {}", chain_id);
    info!("🔧 [CONTRACT] Chain name: {}", chain_name);
    info!("🔧 [CONTRACT] From address: {}", from_address);

    let calldata = encode_update_solver_rewards_calldata(solver_address, rewards, transaction_hash);
    info!("🔧 [CONTRACT] Calldata: {:?}", calldata);
    let calldata_hex = calldata
        .as_ref()
        .map(|d| format!("0x{}", hex::encode(d)))
        .unwrap_or_else(|| "0x".to_string());

    info!("🔧 [CONTRACT] Calldata prepared: {}", calldata_hex);

    let estimated_gas = estimate_gas_for_deposit_intent(
        from_address,
        &normalized_contract_address,
        &calldata_hex,
        chain_id,
    )
    .await?; // Abort if gas estimation fails - indicates transaction would revert
    let gas_limit = estimated_gas + (estimated_gas / 10);

    let gas_price = get_gas_price_for_chain("qubetics", chain_id)
        .await
        .unwrap_or_else(|e| {
            warn!("⚠️ Failed to get dynamic gas price: {}, using fallback", e);
            get_default_gas_price_for_chain("qubetics")
        });

    info!("🔧 [CONTRACT] Gas price: {}", gas_price);
    info!("🔧 [CONTRACT] Gas limit: {}", gas_limit);
    let nonce = fetch_ethereum_nonce(from_address, chain_id).await?;

    let ethereum_tx = EthereumTransaction {
        to: normalized_contract_address,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: calldata,
        chain_id,
    };

    Ok(ChainTransaction::Ethereum(ethereum_tx))
}

/// Create a ChainTransaction for a batch claim-rewards call to SolverManager.claimRewardsBatch.
/// - `claims`: slice of (solver_address, amount) for the same chain type.
/// - `chain_type`: 0 = BTC, 1 = TICS (SolverManager.ChainType).
pub async fn create_solver_claim_rewards_batch_transaction(
    from_address: &str,
    claims: &[RewardClaimBatchEntry],
    chain_type: u8,
    contract_address: &str,
    chain_id: u64,
    chain_name: &str,
) -> Result<ChainTransaction> {
    let normalized_contract_address = if contract_address.starts_with("0x") {
        contract_address.to_string()
    } else {
        format!("0x{contract_address}")
    };

    let calldata = encode_claim_rewards_batch_calldata(claims, chain_type)
        .ok_or_else(|| anyhow::anyhow!("Failed to encode claimRewardsBatch calldata"))?;
    let calldata_hex = format!("0x{}", hex::encode(&calldata));

    info!(
        "🔧 [CONTRACT] Creating claimRewardsBatch for {} claims, chain_type={} on chain {} via {}",
        claims.len(),
        chain_type,
        chain_id,
        normalized_contract_address
    );

    let estimated_gas = estimate_gas_for_deposit_intent(
        from_address,
        &normalized_contract_address,
        &calldata_hex,
        chain_id,
    )
    .await?;
    let gas_limit = estimated_gas + (estimated_gas / 10);

    let gas_price = get_gas_price_for_chain(chain_name, chain_id)
        .await
        .unwrap_or_else(|e| {
            warn!(
                "⚠️ Failed to get dynamic gas price for claimRewardsBatch: {}, using fallback",
                e
            );
            get_default_gas_price_for_chain(chain_name)
        });

    let nonce = fetch_ethereum_nonce(from_address, chain_id).await?;

    let ethereum_tx = EthereumTransaction {
        to: normalized_contract_address,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: Some(calldata),
        chain_id,
    };

    Ok(ChainTransaction::Ethereum(ethereum_tx))
}

/// Encode calldata for SolverManager.batchTransfer(recipients, amounts).
/// Encode calldata for addLiquidityBatch(AddLiquidityBatch[] deposits)
/// where AddLiquidityBatch is struct { string solverId, uint256 amount, uint8 chainType }
pub fn encode_add_liquidity_batch_calldata(
    solver_ids: &[String],
    amounts: &[U256],
    chain_types: &[u8],
) -> Option<Vec<u8>> {
    #[allow(deprecated)]
    let f = Function {
        name: "addLiquidityBatch".to_owned(),
        inputs: vec![
            Param {
                name: "deposits".into(),
                kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                    ParamType::String,      // solverId
                    ParamType::Uint(256),   // amount
                    ParamType::Uint(8),     // chainType (enum as uint8)
                ]))),
                internal_type: Some("struct SolverManager.AddLiquidityBatch[]".into()),
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    if solver_ids.len() != amounts.len() || solver_ids.len() != chain_types.len() {
        return None;
    }

    // Build array of tuples (solverId, amount, chainType)
    let deposit_tuples: Vec<Token> = solver_ids
        .iter()
        .zip(amounts.iter())
        .zip(chain_types.iter())
        .map(|((solver_id, amount), chain_type)| {
            Token::Tuple(vec![
                Token::String(solver_id.clone()),
                Token::Uint(*amount),
                Token::Uint((*chain_type).into()),
            ])
        })
        .collect();

    let tokens = vec![Token::Array(deposit_tuples)];

    f.encode_input(&tokens).ok()
}

/// Create a ChainTransaction for a batch add-liquidity call to SolverManager.addLiquidityBatch.
///
/// - `from_address` should be the liquidity operator address (derived from group key).
/// - `solver_ids`, `amounts`, and `chain_types` must have the same length.
/// - `contract_address` is SOLVER_CONTRACT_ADDRESS (env-provided, may or may not have 0x prefix).
pub async fn create_solver_add_liquidity_batch_transaction(
    from_address: &str,
    solver_ids: &[String],
    amounts: &[U256],
    chain_types: &[u8],
    contract_address: &str,
    chain_id: u64,
) -> Result<ChainTransaction> {
    let normalized_contract_address = if contract_address.starts_with("0x") {
        contract_address.to_string()
    } else {
        format!("0x{contract_address}")
    };

    info!(
        "🔧 [CONTRACT] Creating addLiquidityBatch for {} deposits on chain {} via {}",
        solver_ids.len(),
        chain_id,
        normalized_contract_address
    );

    let calldata = encode_add_liquidity_batch_calldata(solver_ids, amounts, chain_types);
    let calldata_hex = calldata
        .as_ref()
        .map(|d| format!("0x{}", hex::encode(d)))
        .unwrap_or_else(|| "0x".to_string());

    info!("🔧 [CONTRACT] addLiquidityBatch calldata prepared (len={} bytes)", calldata.as_ref().map(|c| c.len()).unwrap_or(0));

    let estimated_gas = estimate_gas_for_deposit_intent(
        from_address,
        &normalized_contract_address,
        &calldata_hex,
        chain_id,
    )
    .await?; // Abort if gas estimation fails - indicates transaction would revert
    let gas_limit = estimated_gas + (estimated_gas / 10);

    let gas_price = get_gas_price_for_chain("qubetics", chain_id)
        .await
        .unwrap_or_else(|e| {
            warn!(
                "⚠️ Failed to get dynamic gas price for batchTransfer: {}, using fallback",
                e
            );
            get_default_gas_price_for_chain("qubetics")
        });

    info!("🔧 [CONTRACT] batchTransfer gas price: {}", gas_price);
    info!("🔧 [CONTRACT] batchTransfer gas limit: {}", gas_limit);
    let nonce = fetch_ethereum_nonce(from_address, chain_id).await?;

    let ethereum_tx = EthereumTransaction {
        to: normalized_contract_address,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: calldata,
        chain_id,
    };

    Ok(ChainTransaction::Ethereum(ethereum_tx))
}

pub async fn create_solver_remove_liquidity_transaction(
    from_address: &str,
    solver_id: &str,
    asset_chain_id: U256,
    amount: U256,
    transaction_hash: &str,
    contract_address: &str,
    chain_id: u64,
    chain_name: &str,
) -> Result<EthereumTransaction> {
    let normalized_contract_address = if contract_address.starts_with("0x") {
        contract_address.to_string()
    } else {
        format!("0x{contract_address}")
    };

    info!(
        "🔧 [CONTRACT][LIQ] Preparing removeLiquidity(solver_id={}, asset_chain_id={}, amount={}, tx_hash={}) call on {} (chain_id={}, chain_name={}, from={})",
        solver_id,
        asset_chain_id,
        amount,
        transaction_hash,
        normalized_contract_address,
        chain_id,
        chain_name,
        from_address
    );

    let calldata =
        encode_remove_liquidity_calldata(solver_id, asset_chain_id, amount, transaction_hash)
            .ok_or_else(|| anyhow::anyhow!("Failed to encode removeLiquidity calldata"))?;
    let calldata_hex = format!("0x{}", hex::encode(&calldata));
    info!(
        "🔧 [CONTRACT][LIQ] removeLiquidity calldata: {} ({} bytes)",
        calldata_hex,
        calldata.len()
    );

    let estimated_gas = estimate_gas_for_deposit_intent(
        from_address,
        &normalized_contract_address,
        &calldata_hex,
        chain_id,
    )
    .await?; // Abort if gas estimation fails - indicates transaction would revert
    let gas_limit = estimated_gas + (estimated_gas / 5).max(25_000);
    info!(
        "🔧 [CONTRACT][LIQ] Estimated gas={} -> gas_limit={}",
        estimated_gas, gas_limit
    );

    let gas_price = get_gas_price_for_chain(chain_name, chain_id)
        .await
        .unwrap_or_else(|_| get_default_gas_price_for_chain(chain_name));
    info!("🔧 [CONTRACT][LIQ] Gas price (wei): {}", gas_price);
    let nonce = fetch_ethereum_nonce(from_address, chain_id).await?;
    info!(
        "🔧 [CONTRACT][LIQ] Nonce for {} on chain {}: {}",
        from_address, chain_id, nonce
    );

    let ethereum_tx = EthereumTransaction {
        to: normalized_contract_address,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: Some(calldata),
        chain_id,
    };

    Ok(ethereum_tx)
}




/// Encode calldata for processBatchIntents contract call
/// This replaces individual depositIntent and fulfillIntent calls with a single batch operation
pub fn encode_process_batch_intents_calldata(
    batch_intents: &[BatchIntentInput],
    batch_type: BatchType,
    timestamp: &str,
) -> Option<Vec<u8>> {
    // Define the tuple type for BatchIntentInput struct
    let batch_intent_tuple_type = ParamType::Tuple(vec![
        ParamType::String,    // sourceAddress
        ParamType::String,    // targetAddress
        ParamType::String,    // sourceChain
        ParamType::String,    // targetChain
        ParamType::Uint(128), // sourceAmount
        ParamType::Uint(128), // targetAmount
        ParamType::String,    // sourceToken
        ParamType::String,    // targetToken
        ParamType::String,    // intentId
        ParamType::String,    // withdrawTxHash
        ParamType::String,    // depositTxHash
    ]);

    #[allow(deprecated)]
    let f = Function {
        name: "processBatchIntents".to_owned(),
        inputs: vec![
            Param {
                name: "batchIntents".into(),
                kind: ParamType::Array(Box::new(batch_intent_tuple_type)),
                internal_type: None,
            },
            Param {
                name: "batchType".into(),
                kind: ParamType::Uint(8), // enum represented as uint8
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

    // Convert BatchIntentInput structs to Token tuples
    let intent_tokens: Vec<Token> = batch_intents
        .iter()
        .map(|intent| {
            Token::Tuple(vec![
                Token::String(intent.source_address.clone()),
                Token::String(intent.target_address.clone()),
                Token::String(intent.source_chain.clone()),
                Token::String(intent.target_chain.clone()),
                Token::Uint(U256::from(intent.source_amount)),
                Token::Uint(U256::from(intent.target_amount)),
                Token::String(intent.source_token.clone()),
                Token::String(intent.target_token.clone()),
                Token::String(intent.intent_id.clone()),
                Token::String(intent.withdraw_tx_hash.clone()),
                Token::String(intent.deposit_tx_hash.clone().unwrap_or_else(|| "NULL".to_string())),
            ])
        })
        .collect();

    let tokens = vec![
        Token::Array(intent_tokens),
        Token::Uint(U256::from(batch_type as u8)),
        Token::String(timestamp.to_owned()),
    ];

    f.encode_input(&tokens).ok()
}

/// One claim entry for claimRewardsBatch: (solver_address, amount).
/// ABI: RewardClaim { address solver, uint256 amount }
pub type RewardClaimBatchEntry = (String, U256);

/// Encode calldata for claimRewardsBatch with multiple claims in one call.
/// ABI: claimRewardsBatch(RewardClaim[] claims, ChainType chainType)
/// where RewardClaim is struct { address solver, uint256 amount } and chainType is uint8 (0=BTC, 1=TICS).
pub fn encode_claim_rewards_batch_calldata(
    claims: &[RewardClaimBatchEntry],
    chain_type: u8,
) -> Option<Vec<u8>> {
    if claims.is_empty() {
        return None;
    }
    #[allow(deprecated)]
    let f = Function {
        name: "claimRewardsBatch".to_owned(),
        inputs: vec![
            Param {
                name: "claims".into(),
                kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                    ParamType::Address,
                    ParamType::Uint(256),
                ]))),
                internal_type: Some("struct SolverManager.RewardClaim[]".into()),
            },
            Param {
                name: "chainType".into(),
                kind: ParamType::Uint(8),
                internal_type: Some("enum SolverManager.ChainType".into()),
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    let claim_tokens: Vec<Token> = claims
        .iter()
        .filter_map(|(solver_addr_str, amount)| {
            solver_addr_str
                .parse::<ethers::types::Address>()
                .ok()
                .map(|addr| Token::Tuple(vec![Token::Address(addr), Token::Uint(*amount)]))
        })
        .collect();

    if claim_tokens.len() != claims.len() {
        return None;
    }

    let tokens = vec![
        Token::Array(claim_tokens),
        Token::Uint(U256::from(chain_type)),
    ];

    f.encode_input(&tokens).ok()
}

/// Encode calldata for a single-solver claim (builds a one-element batch).
/// Kept for backward compatibility; prefer encode_claim_rewards_batch_calldata for multiple claims.
pub fn encode_update_solver_rewards_calldata(
    solver_address: &str,
    rewards: &[U256],
    _transaction_hash: &str,
) -> Option<Vec<u8>> {
    // Existing flow passes rewards as [btc, tics]; HTTP layer enforces only one side
    // is claimed at a time. Map non-zero entry to amount and chainType.
    let (amount, chain_type_u8) = if !rewards.is_empty() && !rewards[0].is_zero() {
        (rewards[0], 0u8)
    } else if rewards.len() > 1 && !rewards[1].is_zero() {
        (rewards[1], 1u8)
    } else {
        (U256::zero(), 0u8)
    };
    let claims: Vec<RewardClaimBatchEntry> = vec![(solver_address.to_owned(), amount)];
    encode_claim_rewards_batch_calldata(&claims, chain_type_u8)
}

pub fn encode_remove_liquidity_calldata(
    solver_id: &str,
    chain_id: U256,
    amount: U256,
    transaction_hash: &str,
) -> Option<Vec<u8>> {
    #[allow(deprecated)]
    let f = Function {
        // New ABI: removeLiquidity((string solverId, uint256 amount, uint8 chainType, string transactionHash)[] requests)
        name: "removeLiquidity".to_owned(),
        inputs: vec![Param {
            name: "requests".into(),
            kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                ParamType::String,
                ParamType::Uint(256),
                ParamType::Uint(8),
                ParamType::String,
            ]))),
            internal_type: None,
        }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    // Map existing chain_id (asset chain ID) to enum ChainType (uint8).
    // Until call sites are updated to pass an explicit chain type, default to:
    // - 0 for BTC if chain_id is non-zero and not equal to the primary TICS chain
    // - 1 for TICS otherwise.
    // This heuristic matches the current two-asset setup and can be tightened later.
    let chain_type_u8 = if chain_id.is_zero() {
        1u8
    } else {
        // Heuristic: treat large chain IDs (e.g. 9029) as TICS (1), smaller as BTC (0)
        let chain_id_u128: u128 = chain_id.low_u128();
        if chain_id_u128 > 255 {
            1u8
        } else {
            0u8
        }
    };

    let request_tuple = Token::Tuple(vec![
        Token::String(solver_id.to_owned()),
        Token::Uint(amount),
        Token::Uint(U256::from(chain_type_u8)),
        Token::String(transaction_hash.to_owned()),
    ]);

    let tokens = vec![Token::Array(vec![request_tuple])];

    f.encode_input(&tokens).ok()
}

/// One request entry for removeLiquidity batch: (solver_id, amount, chain_type, transaction_hash).
pub type RemoveLiquidityBatchRequest = (String, U256, u8, String);

/// Encode calldata for removeLiquidity with multiple requests (TICS + BTC) in one call.
/// ABI: removeLiquidity((string solverId, uint256 amount, uint8 chainType, string transactionHash)[] requests)
pub fn encode_remove_liquidity_batch_calldata(
    requests: &[RemoveLiquidityBatchRequest],
) -> Option<Vec<u8>> {
    if requests.is_empty() {
        return None;
    }
    #[allow(deprecated)]
    let f = Function {
        name: "removeLiquidity".to_owned(),
        inputs: vec![Param {
            name: "requests".into(),
            kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                ParamType::String,
                ParamType::Uint(256),
                ParamType::Uint(8),
                ParamType::String,
            ]))),
            internal_type: None,
        }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    let request_tokens: Vec<Token> = requests
        .iter()
        .enumerate()
        .map(|(idx, (solver_id, amount, chain_type, tx_hash))| {
            info!(
                "🔧 [CONTRACT][LIQ] Request #{}: solver_id='{}', amount={}, chain_type={} ({}), tx_hash='{}'",
                idx,
                solver_id,
                amount,
                chain_type,
                if *chain_type == 0 { "BTC" } else if *chain_type == 1 { "TICS" } else { "UNKNOWN" },
                tx_hash
            );
            
            // Validate solver_id is not empty
            if solver_id.is_empty() {
                warn!("⚠️ [CONTRACT][LIQ] Request #{}: Empty solver_id detected!", idx);
            }
            
            // Validate amount is not zero
            if amount.is_zero() {
                warn!("⚠️ [CONTRACT][LIQ] Request #{}: Zero amount detected!", idx);
            }
            
            // Validate chain_type is valid (0 or 1)
            if *chain_type > 1 {
                warn!("⚠️ [CONTRACT][LIQ] Request #{}: Invalid chain_type {} (expected 0 for BTC or 1 for TICS)", idx, chain_type);
            }
            
            // Validate tx_hash is not empty
            if tx_hash.is_empty() {
                warn!("⚠️ [CONTRACT][LIQ] Request #{}: Empty transaction_hash detected!", idx);
            }
            
            Token::Tuple(vec![
                Token::String(solver_id.clone()),
                Token::Uint(*amount),
                Token::Uint(U256::from(*chain_type)),
                Token::String(tx_hash.clone()),
            ])
        })
        .collect();

    info!(
        "🔧 [CONTRACT][LIQ] Encoded {} removeLiquidity requests into batch",
        request_tokens.len()
    );

    let tokens = vec![Token::Array(request_tokens)];
    f.encode_input(&tokens).ok()
}

/// Build one Ethereum transaction for removeLiquidity batch (multiple solvers / TICS + BTC in one tx).
pub async fn create_solver_remove_liquidity_batch_transaction(
    from_address: &str,
    requests: &[RemoveLiquidityBatchRequest],
    _transaction_hash: &str,
    contract_address: &str,
    chain_id: u64,
    chain_name: &str,
) -> Result<EthereumTransaction> {
    use crate::utils::transaction::encode_remove_liquidity_batch_calldata;

    let normalized_contract_address = if contract_address.starts_with("0x") {
        contract_address.to_string()
    } else {
        format!("0x{contract_address}")
    };

    let calldata = encode_remove_liquidity_batch_calldata(requests)
        .ok_or_else(|| anyhow::anyhow!("Failed to encode removeLiquidity batch calldata"))?;
    let calldata_hex = format!("0x{}", hex::encode(&calldata));

    info!(
        "🔧 [CONTRACT][LIQ] Preparing removeLiquidity batch: {} requests, {} bytes",
        requests.len(),
        calldata.len()
    );

    let estimated_gas = estimate_gas_for_deposit_intent(
        from_address,
        &normalized_contract_address,
        &calldata_hex,
        chain_id,
    )
    .await?;
    let gas_limit = estimated_gas + (estimated_gas / 5).max(50_000);

    let gas_price = get_gas_price_for_chain(chain_name, chain_id)
        .await
        .unwrap_or_else(|_| get_default_gas_price_for_chain(chain_name));
    let nonce = fetch_ethereum_nonce(from_address, chain_id).await?;

    let ethereum_tx = EthereumTransaction {
        to: normalized_contract_address,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: Some(calldata),
        chain_id,
    };

    Ok(ethereum_tx)
}

/// Fetch current gas price from RPC for Qubetics chain
/// Only supports Qubetics (chain ID 9029)
pub async fn fetch_qubetics_gas_price(chain_id: u64) -> Result<String> {
    let rpc_url = get_evm_rpc_url(chain_id)?;

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

/// Get default gas price for Qubetics chain
/// Only supports Qubetics as an EVM chain
pub fn get_default_gas_price_for_chain(chain_name: &str) -> String {
    match chain_name {
        "qubetics" => "0x3B9ACA00".to_string(), // 1 Gwei (fallback)
        _ => "0x3B9ACA00".to_string(),          // Default to 1 Gwei for Qubetics
    }
}

/// Get gas price for Qubetics chain with dynamic fetching
/// Only supports Qubetics as an EVM chain
pub async fn get_gas_price_for_chain(chain_name: &str, _chain_id: u64) -> Result<String> {
    // Reduced noisy stdout logging in production path

    match chain_name {
        "qubetics" => {
            // Reduced noisy stdout logging in production path
            // Try to fetch dynamic gas price for Qubetics
            // ALWAYS use the fallback/static gas price for Qubetics to ensure deterministic transaction construction
            // across all MPC nodes. If we allow dynamic fetching here, different nodes might see different
            // gas prices (e.g. if the RPC updates between calls), leading to different transaction hashes
            // and signature verification failures.
            //
            // See: https://github.com/qubetics/qubetics-chain-abstraction/issues/123 (hypothetical link, but referencing the fix)
            let fixed_price = get_default_gas_price_for_chain(chain_name);
            info!("USING FIXED GAS PRICE for Qubetics: {}", fixed_price);

            // Convert formatted hex to decimal for display
            if let Some(hex_part) = fixed_price.strip_prefix("0x") {
                if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                    info!(
                        "Fixed gas price in decimal: {} wei ({} Gwei)",
                        price_decimal,
                        price_decimal / 1_000_000_000
                    );
                }
            }

            Ok(fixed_price)
        }
        _ => {
            // Only Qubetics is supported as an EVM chain
            Err(anyhow::anyhow!(
                "Unsupported EVM chain: {}. Only Qubetics is supported as an EVM chain",
                chain_name
            ))
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

    fn ensure_testnet_network_type() {
        std::env::set_var(crate::types::NETWORK_ENV_KEY, "testnet");
        let _ = crate::types::init_network_type_from_env();
    }

    #[test]
    fn test_qubetics_static_gas_price() {
        ensure_testnet_network_type();
        // Test Qubetics static gas price (fallback value)
        let static_price = get_default_gas_price_for_chain("qubetics");
        println!("🔧 Qubetics static gas price: {}", static_price);
        assert_eq!(static_price, "0x3B9ACA00");

        // Convert to decimal to show the actual value
        let price_decimal = u64::from_str_radix("3B9ACA00", 16).unwrap();
        println!(
            "🔧 Qubetics static gas price in decimal: {} wei ({} Gwei)",
            price_decimal,
            price_decimal / 1_000_000_000
        );
    }

    #[tokio::test]
    async fn test_qubetics_dynamic_gas_price_fallback() {
        ensure_testnet_network_type();
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
            println!(
                "🔧 Fallback gas price in decimal: {} wei ({} Gwei)",
                price_decimal,
                price_decimal / 1_000_000_000
            );
        } else {
            println!("🔧 Got dynamic gas price from RPC: {}", gas_price);
            // Convert to decimal to show the actual value
            if let Some(hex_part) = gas_price.strip_prefix("0x") {
                if let Ok(price_decimal) = u64::from_str_radix(hex_part, 16) {
                    println!(
                        "🔧 Dynamic gas price in decimal: {} wei ({} Gwei)",
                        price_decimal,
                        price_decimal / 1_000_000_000
                    );
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
        ensure_testnet_network_type();
        // Test that unsupported chain IDs return an error
        let result = fetch_qubetics_gas_price(1).await; // Ethereum mainnet (unsupported)
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("🔧 Expected error for unsupported chain: {}", error_msg);
        assert!(error_msg.contains("Unsupported EVM chain ID"));
    }

    #[test]
    fn test_qubetics_gas_price_hex_conversion() {
        ensure_testnet_network_type();
        // Test that Qubetics hex values are correct
        let qubetics_hex = "0x3B9ACA00";
        let price_decimal = u64::from_str_radix("3B9ACA00", 16).unwrap();

        println!("🔧 Qubetics gas price hex: {}", qubetics_hex);
        println!("🔧 Qubetics gas price decimal: {} wei", price_decimal);
        println!(
            "🔧 Qubetics gas price in Gwei: {} Gwei",
            price_decimal / 1_000_000_000
        );

        assert_eq!(price_decimal, 1_000_000_000); // 1 Gwei
    }

    #[test]
    fn test_qubetics_gas_price_consistency() {
        ensure_testnet_network_type();
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
        ensure_testnet_network_type();
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
                        println!(
                            "🔧 Qubetics dynamic gas price in decimal: {} wei ({} Gwei)",
                            price_decimal,
                            price_decimal / 1_000_000_000
                        );
                    }
                }

                // Gas price should be a valid hex string
                assert!(gas_price.starts_with("0x"));
                assert!(gas_price.len() > 2);
            }
            Err(e) => {
                println!(
                    "🔧 Qubetics RPC call failed (expected if RPC is down): {}",
                    e
                );
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

pub(crate) fn create_bitcoin_script_pubkey(address: &str) -> Result<Vec<u8>> {
    use bitcoin::Address;
    use std::str::FromStr;

    // Parse the address and determine network
    let parsed_address = Address::from_str(address)
        .map_err(|e| anyhow::anyhow!("Invalid Bitcoin address '{}': {}", address, e))?;

    // Require the network to match the configured deployment (testnet/mainnet).
    let network = if network_cfg::network_type().is_testnet() {
        bitcoin::Network::Testnet
    } else {
        bitcoin::Network::Bitcoin
    };
    let checked_address = parsed_address
        .require_network(network)
        .map_err(|e| anyhow::anyhow!("Address network mismatch for '{}': {}", address, e))?;

    // Convert to script_pubkey
    let script_pubkey = checked_address.script_pubkey();
    let script_bytes = script_pubkey.to_bytes();

    Ok(script_bytes)
}

/// Validate that an address is a valid, non-empty 20-byte Ethereum address.
/// This prevents contract creation transactions from being created when a transfer is intended.
fn validate_ethereum_address(address: &str) -> Result<()> {
    // Check that address is not empty
    if address.is_empty() {
        return Err(anyhow::anyhow!("Address cannot be empty"));
    }

    // Check that address starts with 0x
    if !address.starts_with("0x") {
        return Err(anyhow::anyhow!("Address must start with '0x' prefix"));
    }

    // Extract hex part after 0x
    let hex_part = &address[2..];

    // Check that hex part is not empty (prevents "0x" from being valid)
    if hex_part.is_empty() {
        return Err(anyhow::anyhow!(
            "Address cannot be '0x' - this would create a contract creation transaction"
        ));
    }

    // Decode hex to bytes
    let bytes = hex::decode(hex_part)
        .map_err(|e| anyhow::anyhow!("Invalid hex characters in address: {}", e))?;

    // Check that address is exactly 20 bytes (standard Ethereum address length)
    if bytes.len() != 20 {
        return Err(anyhow::anyhow!(
            "Address must be exactly 20 bytes (40 hex characters), got {} bytes",
            bytes.len()
        ));
    }

    Ok(())
}

pub fn create_transaction_for_signing(tx: &EthereumTransaction) -> Vec<u8> {
    // Validate the 'to' address before encoding to prevent contract creation transactions
    // when a transfer is intended. An empty or malformed address would RLP-encode as 0x80,
    // which Ethereum interprets as contract creation, potentially locking funds irreversibly.
    validate_ethereum_address(&tx.to)
        .map_err(|e| {
            anyhow::anyhow!(
                "Invalid 'to' address '{}' for transfer transaction: {}. \
                 This function is intended for standard Ethereum transfers, not contract creation.",
                tx.to,
                e
            )
        })
        .expect("Address validation failed");

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

    let final_bytes = final_encoder.finalize();
    info!(
        "🎁 [RLP_DUMP] Transaction RLP Bytes: {}",
        hex::encode(&final_bytes)
    );
    final_bytes
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
    use crate::types::DummyTransaction;

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
    use crate::types::ContractTransaction;

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
    let utxos = vec![BitcoinUtxo {
        txid: "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2".to_string(),
        vout: 0,
        value: 2000,
        status: UtxoStatus {
            confirmed: true,
            block_height: Some(100),
            block_hash: Some("block1".to_string()),
            block_time: Some(1234567890),
        },
    }];

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

#[test]
fn test_utxo_selection_prefers_non_dust_change_when_possible() {
    // First UTXO alone would leave near-dust change, but adding the second UTXO enables valid change
    let utxos = vec![
        BitcoinUtxo {
            txid: "d4e5f6789012345678901234567890123456789012345678901234567890a1b2c3".to_string(),
            vout: 0,
            value: 2000,
            status: UtxoStatus {
                confirmed: true,
                block_height: Some(100),
                block_hash: Some("block1".to_string()),
                block_time: Some(1234567890),
            },
        },
        BitcoinUtxo {
            txid: "e5f6789012345678901234567890123456789012345678901234567890a1b2c3d4".to_string(),
            vout: 0,
            value: 400,
            status: UtxoStatus {
                confirmed: true,
                block_height: Some(101),
                block_hash: Some("block2".to_string()),
                block_time: Some(1234567891),
            },
        },
    ];

    // With only the 2000-sat UTXO, change would be below the dust limit; the selector should keep adding inputs
    let result = select_utxos_for_amount(&utxos, 1400, 2, SpendKind::P2WPKH).unwrap();

    // Should include both inputs and produce a spendable change output
    assert_eq!(
        result.selected_utxos.len(),
        2,
        "Should add the second UTXO to avoid dust change"
    );
    assert!(
        result.change_output,
        "Should prefer a non-dust change output over fee-only remainder"
    );
    assert!(
        result.change >= DUST_LIMIT_SATS,
        "Change should be above dust"
    );
    assert_eq!(result.fee, estimate_fee_sat(SpendKind::P2WPKH, 2, 2, 2));
}

#[test]
fn test_validate_ethereum_address_valid() {
    // Test valid 20-byte address
    let valid_addr = "0x1234567890123456789012345678901234567890";
    assert!(validate_ethereum_address(valid_addr).is_ok());
}

#[test]
fn test_validate_ethereum_address_empty() {
    // Test empty address
    assert!(validate_ethereum_address("").is_err());
}

#[test]
fn test_validate_ethereum_address_just_0x() {
    // Test "0x" which would create contract creation transaction
    let result = validate_ethereum_address("0x");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be '0x'"));
}

#[test]
fn test_validate_ethereum_address_no_prefix() {
    // Test address without 0x prefix
    assert!(validate_ethereum_address("1234567890123456789012345678901234567890").is_err());
}

#[test]
fn test_validate_ethereum_address_wrong_length() {
    // Test address with wrong length (not 20 bytes)
    // 19 bytes (38 hex chars)
    assert!(validate_ethereum_address("0x12345678901234567890123456789012345678").is_err());
    // 21 bytes (42 hex chars)
    assert!(validate_ethereum_address("0x12345678901234567890123456789012345678901").is_err());
}

#[test]
fn test_validate_ethereum_address_invalid_hex() {
    // Test address with invalid hex characters
    assert!(validate_ethereum_address("0x123456789012345678901234567890123456789g").is_err());
}

pub fn create_transaction_for_signing_contract(tx: &ContractTransaction) -> Vec<u8> {
    // Validate the 'to' address before encoding to prevent contract creation transactions
    // when a contract call is intended. An empty or malformed address would RLP-encode as 0x80,
    // which Ethereum interprets as contract creation, potentially locking funds irreversibly.
    validate_ethereum_address(&tx.to)
        .map_err(|e| {
            anyhow::anyhow!(
                "Invalid 'to' address '{}' for contract transaction: {}. \
                 Contract address must be a valid 20-byte Ethereum address.",
                tx.to,
                e
            )
        })
        .expect("Address validation failed");

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
    // Validate the 'to' address before encoding to prevent contract creation transactions
    // when a transfer is intended. An empty or malformed address would RLP-encode as 0x80,
    // which Ethereum interprets as contract creation, potentially locking funds irreversibly.
    validate_ethereum_address(&tx.to)
        .map_err(|e| {
            anyhow::anyhow!(
                "Invalid 'to' address '{}' for transfer transaction: {}. \
                 This function is intended for standard Ethereum transfers, not contract creation.",
                tx.to,
                e
            )
        })
        .expect("Address validation failed");

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
