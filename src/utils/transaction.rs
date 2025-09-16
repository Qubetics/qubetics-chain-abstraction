use crate::chain::{
    BitcoinInput, BitcoinOutput, BitcoinTransaction, BitcoinWitnessUtxo, ChainTransaction,
    EthereumTransaction,
};
use crate::rpc_server::{ContractTransaction, DepositIntent, DummyTransaction};
use crate::utils::get_eth_address_from_group_key;
use anyhow::Result;
use ethabi::ethereum_types::U256;
use ethabi::{Function, Param, ParamType, StateMutability, Token};
use serde::{Deserialize, Serialize};
use tracing::info; // for Token::Uint

// use rlp::RlpStream;

/// Bitcoin UTXO structure for fetching from external APIs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
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
        return Err(anyhow::anyhow!("Invalid hex characters in amount: {}", hex_str));
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
pub fn validate_contract_transaction_hex_fields(tx: &crate::rpc_server::ContractTransaction) -> Result<()> {
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
            return Err(anyhow::anyhow!("Invalid hex characters in data field: {}", tx.data));
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

/// Fetch UTXOs for a Bitcoin address from BlockCypher API
pub async fn fetch_bitcoin_utxos(address: &str, is_testnet: bool) -> Result<Vec<BitcoinUtxo>> {
    let base_url = if is_testnet {
        "https://api.blockcypher.com/v1/btc/test3"
    } else {
        "https://api.blockcypher.com/v1/btc/main"
    };

    let url = format!("{}/addrs/{}", base_url, address);
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch UTXOs: HTTP {}",
            response.status()
        ));
    }

    let addr_data: serde_json::Value = response.json().await?;
    
    // BlockCypher returns UTXOs in the "txrefs" array for unconfirmed and "unconfirmed_txrefs" for unconfirmed
    let mut utxos = Vec::new();
    
    // Add confirmed UTXOs
    if let Some(txrefs) = addr_data["txrefs"].as_array() {
        for txref in txrefs {
            if txref["spent"].as_bool().unwrap_or(false) {
                continue; // Skip spent UTXOs
            }
            
            utxos.push(BitcoinUtxo {
                txid: txref["tx_hash"].as_str().unwrap_or_default().to_string(),
                vout: txref["tx_output_n"].as_u64().unwrap_or_default() as u32,
                value: txref["value"].as_u64().unwrap_or_default(),
                status: UtxoStatus {
                    confirmed: txref["confirmations"].as_u64().unwrap_or(0) > 0,
                    block_height: txref["block_height"].as_u64(),
                    block_hash: txref["block_hash"].as_str().map(|s| s.to_string()),
                    block_time: None, // BlockCypher doesn't provide block_time in this endpoint
                },
            });
        }
    }
    
    // Add unconfirmed UTXOs
    if let Some(unconfirmed_txrefs) = addr_data["unconfirmed_txrefs"].as_array() {
        for txref in unconfirmed_txrefs {
            if txref["spent"].as_bool().unwrap_or(false) {
                continue; // Skip spent UTXOs
            }
            
            utxos.push(BitcoinUtxo {
                txid: txref["tx_hash"].as_str().unwrap_or_default().to_string(),
                vout: txref["tx_output_n"].as_u64().unwrap_or_default() as u32,
                value: txref["value"].as_u64().unwrap_or_default(),
                status: UtxoStatus {
                    confirmed: false,
                    block_height: None,
                    block_hash: None,
                    block_time: None,
                },
            });
        }
    }
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

/// Fetch detailed UTXO information including script details
pub async fn fetch_detailed_bitcoin_utxo(
    txid: &str,
    vout: u32,
    is_testnet: bool,
) -> Result<EnhancedUtxo> {
    let base_url = if is_testnet {
        "https://api.blockcypher.com/v1/btc/test3"
    } else {
        "https://api.blockcypher.com/v1/btc/main"
    };

    let url = format!("{}/txs/{}", base_url, txid);
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch transaction details: HTTP {}",
            response.status()
        ));
    }

    let tx_data: serde_json::Value = response.json().await?;
    let outputs = tx_data["outputs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid transaction format"))?;

    if vout as usize >= outputs.len() {
        return Err(anyhow::anyhow!(
            "VOUT {} not found in transaction {}",
            vout,
            txid
        ));
    }

    let output_data = &outputs[vout as usize];

    Ok(EnhancedUtxo {
        txid: txid.to_string(),
        vout,
        value: output_data["value"].as_u64().unwrap_or(0),
        status: UtxoStatus {
            confirmed: tx_data["confirmations"].as_u64().unwrap_or(0) > 0,
            block_height: tx_data["block_height"].as_u64(),
            block_hash: tx_data["block_hash"].as_str().map(|s| s.to_string()),
            block_time: tx_data["confirmed"].as_str().map(|s| s.to_string()).and_then(|s| {
                // BlockCypher returns ISO 8601 timestamp, we'll just store as string for now
                Some(s)
            }).map(|_| 0u64), // Placeholder - would need proper timestamp parsing
        },
        scriptpubkey: output_data["script"].as_str().map(|s| s.to_string()),
        scriptpubkey_type: output_data["script_type"]
            .as_str()
            .map(|s| s.to_string()),
        scriptpubkey_address: {
            // BlockCypher stores addresses in the "addresses" array
            if let Some(addresses) = output_data["addresses"].as_array() {
                addresses.first().and_then(|addr| addr.as_str()).map(|s| s.to_string())
            } else {
                None
            }
        },
    })
}

/// Validate P2PKH prevout ownership and log comprehensive details
pub async fn validate_p2pkh_prevout(
    utxo: &BitcoinUtxo,
    expected_address: &str,
    signing_pubkey: &[u8], // 33-byte compressed pubkey
    is_testnet: bool,
    vin: usize,
) -> Result<()> {
    // Fetch detailed prevout information
    let enhanced_utxo = fetch_detailed_bitcoin_utxo(&utxo.txid, utxo.vout, is_testnet).await?;

    // Log prevout checkpoint
    tracing::info!(
        "🔍 [PREVOUT_CHECKPOINT] vin={}, prevout={}:{}, scriptpubkey_type={:?}, scriptpubkey={:?}, value={} sats",
        vin,
        enhanced_utxo.txid,
        enhanced_utxo.vout,
        enhanced_utxo.scriptpubkey_type,
        enhanced_utxo.scriptpubkey,
        enhanced_utxo.value
    );

    // Validate script type is P2PKH
    if enhanced_utxo.scriptpubkey_type.as_deref() != Some("p2pkh") {
        return Err(anyhow::anyhow!(
            "Input vin={} is {:?}; this path supports only P2PKH.",
            vin,
            enhanced_utxo.scriptpubkey_type
        ));
    }

    // Derive P2PKH address from our signing pubkey
    let derived_address = derive_p2pkh_address_from_pubkey(signing_pubkey, is_testnet)?;

    tracing::info!(
        "🔍 [PREVOUT_CHECKPOINT] derived_p2pkh_from_pubkey={}, prevout_address={:?}",
        derived_address,
        enhanced_utxo.scriptpubkey_address
    );

    // Check if prevout belongs to our key
    let matches_prevout = enhanced_utxo.scriptpubkey_address.as_deref() == Some(&derived_address);

    tracing::info!(
        "🔍 [PREVOUT_CHECKPOINT] matches_prevout_address={}",
        matches_prevout
    );

    if !matches_prevout {
        return Err(anyhow::anyhow!(
            "Prevout doesn't belong to our key. Expected: {}, Got: {:?}",
            derived_address,
            enhanced_utxo.scriptpubkey_address
        ));
    }

    // Also validate against the expected address parameter
    if derived_address != expected_address {
        return Err(anyhow::anyhow!(
            "Derived address {} doesn't match expected address {}",
            derived_address,
            expected_address
        ));
    }

    Ok(())
}

/// Derive P2PKH address from compressed public key
fn derive_p2pkh_address_from_pubkey(pubkey: &[u8], is_testnet: bool) -> Result<String> {
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::{Address, Network};

    if pubkey.len() != 33 {
        return Err(anyhow::anyhow!("Public key must be 33 bytes (compressed)"));
    }

    // Hash160 = RIPEMD160(SHA256(pubkey))
    let hash160_result = hash160::Hash::hash(pubkey);

    let network = if is_testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    };

    // Create P2PKH address from hash160
    let pubkey_hash = bitcoin::PubkeyHash::from(hash160_result);
    let address = Address::p2pkh(pubkey_hash, network);
    Ok(address.to_string())
}

/// Verify that a UTXO actually exists and is spendable
pub async fn verify_utxo_exists(txid: &str, vout: u32, is_testnet: bool) -> Result<bool> {
    let base_url = if is_testnet {
        "https://api.blockcypher.com/v1/btc/test3"
    } else {
        "https://api.blockcypher.com/v1/btc/main"
    };

    let url = format!("{}/txs/{}", base_url, txid);

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    match response.status().as_u16() {
        200 => {
            let tx_data: serde_json::Value = response.json().await?;
            
            // Check if the transaction has the specified output
            if let Some(outputs) = tx_data["outputs"].as_array() {
                if vout as usize >= outputs.len() {
                    tracing::warn!("⚠️ [UTXO_VERIFY] UTXO {}:{} output index out of range", txid, vout);
                    return Ok(false);
                }
                
                let output = &outputs[vout as usize];
                
                // Check if this output has been spent
                let is_spent = output["spent_by"].is_string(); // If spent_by exists, it's spent
                
                if is_spent {
                    tracing::info!("ℹ️ [UTXO_VERIFY] UTXO {}:{} is already spent", txid, vout);
                    Ok(false)
                } else {
                    tracing::info!("✅ [UTXO_VERIFY] UTXO {}:{} is unspent and available", txid, vout);
                    Ok(true)
                }
            } else {
                tracing::warn!("⚠️ [UTXO_VERIFY] Transaction {} has no outputs", txid);
                Ok(false)
            }
        }
        404 => {
            // Transaction doesn't exist
            tracing::warn!("⚠️ [UTXO_VERIFY] Transaction {} does not exist", txid);
            Ok(false)
        }
        _ => {
            tracing::error!(
                "❌ [UTXO_VERIFY] Failed to verify UTXO {}:{}: HTTP {}",
                txid,
                vout,
                response.status()
            );
            Err(anyhow::anyhow!(
                "Failed to verify UTXO: HTTP {}",
                response.status()
            ))
        }
    }
}

/// Verify multiple UTXOs in parallel
pub async fn verify_utxos_exist(
    utxos: &[BitcoinUtxo],
    is_testnet: bool,
) -> Result<Vec<BitcoinUtxo>> {
    use futures::future::join_all;

    let verification_futures: Vec<_> = utxos
        .iter()
        .map(|utxo| verify_utxo_exists(&utxo.txid, utxo.vout, is_testnet))
        .collect();

    let results = join_all(verification_futures).await;

    let mut verified_utxos = Vec::new();
    for (utxo, result) in utxos.iter().zip(results.iter()) {
        match result {
            Ok(true) => {
                tracing::debug!(
                    "✅ [UTXO_VERIFY] UTXO {}:{} is spendable",
                    utxo.txid,
                    utxo.vout
                );
                verified_utxos.push(utxo.clone());
            }
            Ok(false) => {
                tracing::warn!(
                    "⚠️ [UTXO_VERIFY] UTXO {}:{} is spent or doesn't exist",
                    utxo.txid,
                    utxo.vout
                );
            }
            Err(e) => {
                tracing::error!(
                    "❌ [UTXO_VERIFY] Failed to verify UTXO {}:{}: {}",
                    utxo.txid,
                    utxo.vout,
                    e
                );
            }
        }
    }

    tracing::info!(
        "🔍 [UTXO_VERIFY] Verified {} spendable UTXOs out of {} checked",
        verified_utxos.len(),
        utxos.len()
    );

    Ok(verified_utxos)
}

/// Fetch and verify UTXOs with retry logic
pub async fn fetch_and_verify_utxos_with_retry(
    address: &str,
    is_testnet: bool,
    max_retries: u32,
) -> Result<Vec<BitcoinUtxo>> {
    let mut last_error = None;

    for attempt in 1..=max_retries {
        tracing::info!(
            "🔄 [UTXO_RETRY] Attempt {}/{} to fetch spendable UTXOs for {}",
            attempt,
            max_retries,
            address
        );

        match fetch_and_verify_utxos_once(address, is_testnet).await {
            Ok(utxos) if !utxos.is_empty() => {
                tracing::info!(
                    "✅ [UTXO_RETRY] Successfully found {} spendable UTXOs on attempt {}",
                    utxos.len(),
                    attempt
                );
                return Ok(utxos);
            }
            Ok(_) => {
                let error_msg = format!(
                    "No spendable UTXOs available for address {} on attempt {}",
                    address, attempt
                );
                tracing::warn!("⚠️ [UTXO_RETRY] {}", error_msg);
                last_error = Some(anyhow::anyhow!(error_msg));
            }
            Err(e) => {
                tracing::error!("❌ [UTXO_RETRY] Error on attempt {}: {}", attempt, e);
                last_error = Some(e);
            }
        }

        if attempt < max_retries {
            let delay_seconds = attempt * 2; // Exponential backoff: 2s, 4s, 6s
            tracing::info!(
                "⏳ [UTXO_RETRY] Waiting {} seconds before retry...",
                delay_seconds
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(delay_seconds as u64)).await;
        }
    }

    // All retries failed
    let final_error =
        last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error during UTXO fetch"));
    tracing::error!(
        "❌ [UTXO_RETRY] All {} attempts failed for address {}. Final error: {}",
        max_retries,
        address,
        final_error
    );

    Err(anyhow::anyhow!(
        "Failed to fetch spendable UTXOs for address {} after {} attempts. Last error: {}",
        address,
        max_retries,
        final_error
    ))
}

/// Single attempt to fetch and verify UTXOs
async fn fetch_and_verify_utxos_once(address: &str, is_testnet: bool) -> Result<Vec<BitcoinUtxo>> {
    // Fetch UTXOs from API
    let raw_utxos = fetch_bitcoin_utxos(address, is_testnet).await?;
    tracing::debug!("🔍 [UTXO_FETCH] Fetched {} raw UTXOs", raw_utxos.len());

    if raw_utxos.is_empty() {
        return Ok(vec![]); // No UTXOs available
    }

    // Verify UTXOs exist and are spendable
    let verified_utxos = verify_utxos_exist(&raw_utxos, is_testnet).await?;
    tracing::debug!(
        "🔍 [UTXO_VERIFY] Verified {} spendable UTXOs out of {} raw",
        verified_utxos.len(),
        raw_utxos.len()
    );

    Ok(verified_utxos)
}

/// Select and combine UTXOs to meet the required amount
pub fn select_utxos_for_amount(
    utxos: &[BitcoinUtxo],
    required_amount: u64,
    fee_estimate: u64,
) -> Result<(Vec<BitcoinUtxo>, u64)> {
    let total_needed = required_amount + fee_estimate;
    let mut selected_utxos = Vec::new();
    let mut total_value = 0u64;

    // Sort UTXOs by value (largest first) for efficient selection
    let mut sorted_utxos = utxos.to_vec();
    sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));

    // Filter UTXOs: only confirmed and valid
    let available_utxos: Vec<_> = sorted_utxos
        .into_iter()
        .filter(|utxo| {
            // Must be confirmed
            if !utxo.status.confirmed {
                tracing::debug!(
                    "🔍 [UTXO_FILTER] Skipping unconfirmed UTXO: {}:{}",
                    utxo.txid,
                    utxo.vout
                );
                return false;
            }

            // Must have valid txid (64 hex characters)
            if utxo.txid.len() != 64 {
                tracing::warn!(
                    "⚠️ [UTXO_FILTER] Skipping UTXO with invalid txid length: <==> {}",
                    utxo.txid
                );
                return false;
            }

            // Must have non-zero value
            if utxo.value == 0 {
                tracing::warn!(
                    "⚠️ [UTXO_FILTER] Skipping UTXO with zero value: {}:{}",
                    utxo.txid,
                    utxo.vout
                );
                return false;
            }

            tracing::debug!(
                "✅ [UTXO_FILTER] Valid UTXO: {}:{} ({} sats)",
                utxo.txid,
                utxo.vout,
                utxo.value
            );
            true
        })
        .collect();

    if available_utxos.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid confirmed UTXOs available from {} total UTXOs",
            utxos.len()
        ));
    }

    tracing::info!(
        "🔍 [UTXO_SELECTION] Filtered to {} valid confirmed UTXOs from {} total",
        available_utxos.len(),
        utxos.len()
    );

    // Select UTXOs until we have enough value
    for utxo in available_utxos {
        selected_utxos.push(utxo);
        total_value += selected_utxos.last().unwrap().value;

        if total_value >= total_needed {
            break;
        }
    }

    if total_value < total_needed {
        return Err(anyhow::anyhow!(
            "Insufficient funds: have {} satoshis, need {} satoshis",
            total_value,
            total_needed
        ));
    }

    tracing::info!(
        "✅ [UTXO_SELECTION] Selected {} UTXOs with total value {} satoshis",
        selected_utxos.len(),
        total_value
    );

    Ok((selected_utxos, total_value))
}

/// Extract UTXO identifiers from selected UTXOs for tracking
pub fn extract_utxo_identifiers(utxos: &[BitcoinUtxo]) -> Vec<(String, u32)> {
    utxos
        .iter()
        .map(|utxo| (utxo.txid.clone(), utxo.vout))
        .collect()
}

/// Create a UTXO consolidation transaction to merge small UTXOs
pub async fn create_utxo_consolidation_transaction(
    from_address: &str,
    _group_public_key: Option<k256::ProjectivePoint>,
    max_inputs: usize,
    min_utxo_value: u64,
) -> Result<ChainTransaction> {
    tracing::info!(
        "🔄 [CONSOLIDATION] Creating UTXO consolidation transaction for {}",
        from_address
    );

    // Validate address format
    if !is_p2pkh_address(from_address) {
        return Err(anyhow::anyhow!(
            "Only P2PKH addresses (1.../m.../n...) are supported for consolidation, got: {}",
            from_address
        ));
    }

    let is_testnet = is_testnet_p2pkh_address(from_address);

    // Fetch UTXOs for the address
    let raw_utxos = fetch_bitcoin_utxos(from_address, is_testnet).await?;
    let utxos = verify_utxos_exist(&raw_utxos, is_testnet).await?;

    if utxos.is_empty() {
        return Err(anyhow::anyhow!(
            "No spendable UTXOs available for consolidation"
        ));
    }

    // Filter for small UTXOs that should be consolidated
    let mut small_utxos: Vec<_> = utxos
        .into_iter()
        .filter(|utxo| utxo.value <= min_utxo_value && utxo.status.confirmed)
        .collect();

    if small_utxos.is_empty() {
        return Err(anyhow::anyhow!("No small UTXOs found for consolidation"));
    }

    // Sort by value (smallest first) and limit to max_inputs
    small_utxos.sort_by_key(|utxo| utxo.value);
    if small_utxos.len() > max_inputs {
        small_utxos.truncate(max_inputs);
    }

    let total_input_value: u64 = small_utxos.iter().map(|utxo| utxo.value).sum();
    let estimated_fee = calculate_bitcoin_fee(small_utxos.len(), 1); // 1 output (consolidation)

    if total_input_value <= estimated_fee {
        return Err(anyhow::anyhow!(
            "Total input value ({} sats) is less than estimated fee ({} sats)",
            total_input_value,
            estimated_fee
        ));
    }

    let consolidation_amount = total_input_value - estimated_fee;

    tracing::info!(
        "🔄 [CONSOLIDATION] Consolidating {} UTXOs: {} sats -> {} sats (fee: {} sats)",
        small_utxos.len(),
        total_input_value,
        consolidation_amount,
        estimated_fee
    );

    // Create inputs from small UTXOs
    let inputs: Vec<BitcoinInput> = small_utxos
        .iter()
        .map(|utxo| {
            BitcoinInput {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                script_sig: vec![], // Will be filled during signing with <signature> <pubkey>
                sequence: 0xFFFFFFFD, // Enable RBF
                witness_utxo: None, // No witness data for P2PKH
            }
        })
        .collect();

    // Create single consolidation output (back to same address)
    let outputs = vec![BitcoinOutput {
        value: consolidation_amount,
        script_pubkey: create_bitcoin_script_pubkey(from_address)?,
    }];

    let bitcoin_tx = BitcoinTransaction {
        inputs,
        outputs,
        version: 1, // Use version 1 for legacy transactions
        lock_time: 0,
        witness: None, // No witness data for P2PKH
    };

    tracing::info!(
        "✅ [CONSOLIDATION] Created consolidation transaction with {} inputs -> 1 output",
        small_utxos.len()
    );
    Ok(ChainTransaction::Bitcoin(bitcoin_tx))
}

/// Calculate estimated Bitcoin transaction fee based on inputs and outputs
pub fn calculate_bitcoin_fee(num_inputs: usize, num_outputs: usize) -> u64 {
    // Simple fee calculation:
    // - Each input ~= 148 bytes (can vary with different script types)
    // - Each output ~= 34 bytes
    // - Base transaction ~= 10 bytes
    let estimated_size = 10 + (num_inputs * 148) + (num_outputs * 34);

    // Use 1 sat/byte as default (you might want to make this configurable or fetch from API)
    let fee_rate = 1usize; // satoshis per byte

    let calculated_fee = estimated_size * fee_rate;

    // Minimum fee of 1000 satoshis
    std::cmp::max(calculated_fee as u64, 1000)
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

/// Create a chain-specific transaction from a deposit intent with optional UTXO conflict prevention
// pub async fn create_chain_transaction_from_deposit_intent_with_utxo_check(
//     intent: &DepositIntent,
//     group_public_key: Option<k256::ProjectivePoint>,
//     derived_eth_addr: Option<&String>,
//     derived_btc_addr: Option<&String>,
//     transaction_type: crate::types::TransactionType,
//     vault_eth_address: Option<&String>,
//     vault_btc_address: Option<&String>,
//     user_registry: Option<&crate::user_registry::DatabaseUserRegistry>,
// ) -> Result<ChainTransaction> {
//     create_chain_transaction_from_deposit_intent_internal(
//         intent,
//         group_public_key,
//         derived_eth_addr,
//         derived_btc_addr,
//         transaction_type,
//         vault_eth_address,
//         vault_btc_address,
//         user_registry,
//     ).await
// }

/// Create a chain-specific transaction from a deposit intent (legacy function for backward compatibility)
/// Estimate gas for a call using eth_estimateGas
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

        let ethereum_tx = EthereumTransaction {
            to: to_address.to_string(),
            value: amount_to_hex_string(amount),
            gas_limit: 300000,
            gas_price: get_default_gas_price_for_chain(chain_to_use),
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
        if !is_p2pkh_address(&from_address) {
            return Err(anyhow::anyhow!(
                "Source address '{}' is not supported. Only P2PKH addresses (1.../m.../n...) are supported.", 
                from_address
            ));
        }

        if !is_p2pkh_address(&to_address) {
            return Err(anyhow::anyhow!(
                "Destination address '{}' is not supported. Only P2PKH addresses (1.../m.../n...) are supported.", 
                to_address
            ));
        }

        let is_testnet = is_testnet_p2pkh_address(&from_address);

        // Fetch UTXOs for the source address
        let raw_utxos = fetch_bitcoin_utxos(&from_address, is_testnet).await?;
        tracing::info!(
            "Fetched {} UTXOs for address {}",
            raw_utxos.len(),
            from_address
        );

        // Verify UTXOs actually exist and are spendable to prevent -25 errors with retry logic
        let utxos = fetch_and_verify_utxos_with_retry(&from_address, is_testnet, 3).await?;
        tracing::info!(
            "Final verified {} spendable UTXOs for address {}",
            utxos.len(),
            from_address
        );

        // Convert amount from wei to satoshis (assuming 1:1 conversion for now, you might want to adjust this)
        let amount_satoshis = (amount) as u64;
        let estimated_fee = calculate_bitcoin_fee(utxos.len(), 2); // 2 outputs (recipient + change)

        // Select UTXOs that provide enough value, excluding any that are pending
        // Select UTXOs for the transaction
        let (selected_utxos, total_input_value) =
            select_utxos_for_amount(&utxos, amount_satoshis, estimated_fee)?;

        tracing::info!(
            "Selected {} UTXOs with total value {} satoshis for transaction of {} satoshis (fee: {})",
            selected_utxos.len(),
            total_input_value,
            amount_satoshis,
            estimated_fee
        );

        // Log the specific UTXOs we're about to spend for debugging
        tracing::info!("📋 [TRANSACTION] UTXOs selected for spending:");
        for (i, utxo) in selected_utxos.iter().enumerate() {
            tracing::info!(
                "  {}. {}:{} - {} sats (confirmed: {})",
                i + 1,
                utxo.txid,
                utxo.vout,
                utxo.value,
                utxo.status.confirmed
            );
        }

        // Create inputs from selected UTXOs (P2PKH only)
        let inputs: Vec<BitcoinInput> = selected_utxos
            .iter()
            .map(|utxo| {
                // For P2PKH (legacy) transactions, we don't need witness_utxo
                // The witness_utxo field should be None for legacy P2PKH inputs
                BitcoinInput {
                    txid: utxo.txid.clone(),
                    vout: utxo.vout,
                    script_sig: vec![], // Will be filled during signing with <signature> <pubkey>
                    sequence: 0xfffffffe, // Enable RBF (Replace-By-Fee)
                    witness_utxo: None, // No witness data for P2PKH legacy transactions
                }
            })
            .collect();

        // Create outputs
        let mut outputs = vec![BitcoinOutput {
            value: amount_satoshis,
            script_pubkey: create_bitcoin_script_pubkey(&to_address)?,
        }];

        // Add change output if necessary
        let change_amount = total_input_value - amount_satoshis - estimated_fee;
        if change_amount > 546 {
            // Bitcoin dust limit
            outputs.push(BitcoinOutput {
                value: change_amount,
                script_pubkey: create_bitcoin_script_pubkey(&from_address)?, // Send change back to source address
            });
        }

        // P2PKH transactions don't use witness data
        //         // Determine if we need witness data based on input address types
        //         let needs_witness = inputs.iter().any(|input| input.witness_utxo.is_some());
        //         let witness = if needs_witness {
        //             Some(BitcoinWitness {
        //                 inputs: inputs
        //                     .iter()
        //                     .map(|_| BitcoinWitnessInput {
        //                         stack: vec![], // Will be filled during signing
        //                     })
        //                     .collect(),
        //             })
        //         } else {
        //             None
        //         };

        let bitcoin_tx = BitcoinTransaction {
            inputs,
            outputs,
            version: 1, // Use version 1 for legacy transactions
            lock_time: 0,
            witness: None, // No witness data for P2PKH
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
    let gas_price = get_default_gas_price_for_chain("qubetics");

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

/// Get default gas price for different EVM chains
pub fn get_default_gas_price_for_chain(chain_name: &str) -> String {
    match chain_name {
        "ethereum" | "eth" => "0x4A817C800".to_string(), // 20 Gwei
        "qubetics" => "0x3B9ACA00".to_string(),          // 1 Gwei
        "polygon" | "matic" => "0x12A05F200".to_string(), // 5 Gwei
        "bsc" | "binance" => "0x12A05F200".to_string(),  // 5 Gwei
        "avalanche" | "avax" => "0x5D21DBA00".to_string(), // 25 Gwei
        "arbitrum" => "0x5F5E100".to_string(),           // 0.1 Gwei
        "optimism" => "0x5F5E100".to_string(),           // 0.1 Gwei
        "base" => "0x5F5E100".to_string(),               // 0.1 Gwei
        _ => "0x4A817C800".to_string(),                  // Default to 20 Gwei
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectedAddressType {
    P2PKH,       // Legacy P2PKH (1... mainnet, m.../n... testnet) - ONLY SUPPORTED TYPE
    Unsupported, // All other types are unsupported
}

/// Detect Bitcoin address type - only P2PKH is supported
fn detect_bitcoin_address_type(address: &str) -> DetectedAddressType {
    if is_p2pkh_address(address) {
        DetectedAddressType::P2PKH
    } else {
        DetectedAddressType::Unsupported
    }
}

/// Check if address is P2PKH format
fn is_p2pkh_address(address: &str) -> bool {
    // Mainnet P2PKH: starts with '1'
    // Testnet P2PKH: starts with 'm' or 'n'
    (address.starts_with('1') && address.len() >= 26 && address.len() <= 35)
        || ((address.starts_with('m') || address.starts_with('n'))
            && address.len() >= 26
            && address.len() <= 35)
}

/// Check if address is testnet P2PKH
fn is_testnet_p2pkh_address(address: &str) -> bool {
    address.starts_with('m') || address.starts_with('n')
}

fn create_bitcoin_script_pubkey(address: &str) -> Result<Vec<u8>> {
    use bitcoin::{Address, Network};
    use std::str::FromStr;

    // Parse the address and determine network
    let parsed_address = Address::from_str(address)
        .map_err(|e| anyhow::anyhow!("Invalid Bitcoin address '{}': {}", address, e))?;

    // Only support P2PKH addresses
    if !is_p2pkh_address(address) {
        return Err(anyhow::anyhow!(
            "Only P2PKH addresses (1.../m.../n...) are supported, got: {}",
            address
        ));
    }

    // Determine network from P2PKH address prefix
    let network = if is_testnet_p2pkh_address(address) {
        Network::Testnet
    } else {
        Network::Bitcoin
    };

    // Require the network to get a checked address
    let checked_address = parsed_address
        .require_network(network)
        .map_err(|e| anyhow::anyhow!("Address network mismatch for '{}': {}", address, e))?;

    // Convert to script_pubkey
    let script_pubkey = checked_address.script_pubkey();
    let script_bytes = script_pubkey.to_bytes();

    // Log address type for debugging
    let detected_type = detect_bitcoin_address_type(address);
    match detected_type {
        DetectedAddressType::P2PKH => {
            tracing::info!(
                "✅ [TRANSACTION] Address {} is P2PKH (Legacy) - supported",
                address
            );
        }
        DetectedAddressType::Unsupported => {
            return Err(anyhow::anyhow!(
                "Unsupported Bitcoin address type: {}. Only P2PKH addresses (1.../m.../n...) are supported.",
                address
            ));
        }
    }

    Ok(script_bytes)
}

/// Create legacy Bitcoin sighash for P2PKH inputs (pre-SegWit)
pub fn create_legacy_bitcoin_sighash(
    tx: &BitcoinTransaction,
    input_index: usize,
    script_code: &[u8], // The prevout's scriptPubKey for P2PKH
    sighash_type: u8,   // Usually 0x01 for SIGHASH_ALL
) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    if input_index >= tx.inputs.len() {
        return Err(anyhow::anyhow!("Input index {} out of bounds", input_index));
    }

    let mut preimage = Vec::new();

    // Version (4 bytes, little-endian)
    preimage.extend_from_slice(&tx.version.to_le_bytes());

    // Number of inputs (varint)
    preimage.push(tx.inputs.len() as u8);

    // Inputs
    for (i, input) in tx.inputs.iter().enumerate() {
        // Previous output hash (32 bytes, little-endian)
        let txid_bytes =
            hex::decode(&input.txid).map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
        if txid_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid txid length: {}", txid_bytes.len()));
        }
        preimage.extend_from_slice(&txid_bytes);

        // Previous output index (4 bytes, little-endian)
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        // Script
        if i == input_index {
            // For the input being signed, use the scriptCode (prevout's scriptPubKey)
            preimage.push(script_code.len() as u8); // Script length
            preimage.extend_from_slice(script_code);
        } else {
            // For other inputs, use empty script
            preimage.push(0); // Empty script length
        }

        // Sequence (4 bytes, little-endian)
        preimage.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Number of outputs (varint)
    preimage.push(tx.outputs.len() as u8);

    // Outputs
    for output in &tx.outputs {
        // Value (8 bytes, little-endian)
        preimage.extend_from_slice(&output.value.to_le_bytes());

        // Script length and script
        preimage.push(output.script_pubkey.len() as u8);
        preimage.extend_from_slice(&output.script_pubkey);
    }

    // Lock time (4 bytes, little-endian)
    preimage.extend_from_slice(&tx.lock_time.to_le_bytes());

    // Sighash type (4 bytes, little-endian)
    preimage.extend_from_slice(&(sighash_type as u32).to_le_bytes());

    // Log sighash checkpoint
    tracing::info!(
        "🔍 [SIGHASH_CHECKPOINT] vin={}, scriptCode={}, sighash_type=0x{:02x}, sequence=0x{:08x}, locktime={}",
        input_index,
        hex::encode(script_code),
        sighash_type,
        tx.inputs[input_index].sequence,
        tx.lock_time
    );

    // Double SHA256
    let first_hash = Sha256::digest(&preimage);
    let second_hash = Sha256::digest(&first_hash);
    let digest: [u8; 32] = second_hash.into();

    tracing::info!("🔍 [SIGHASH_CHECKPOINT] digest32={}", hex::encode(&digest));

    Ok(digest)
}

/// Normalize signature to low-S and create minimal DER encoding
pub fn normalize_and_encode_signature(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    use k256::elliptic_curve::group::ff::PrimeField;
    use k256::Scalar;

    if r.len() != 32 || s.len() != 32 {
        return Err(anyhow::anyhow!("r and s must be 32 bytes each"));
    }

    // Parse s as scalar
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(s);
    let s_scalar = Scalar::from_repr(s_bytes.into()).unwrap();

    // Get curve order n (secp256k1 order)
    let n_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let n = Scalar::from_repr(n_bytes.into()).unwrap();

    // Calculate n/2
    let n_half = n * Scalar::from(2u32).invert().unwrap();

    // Check if s > n/2 (high-S)
    let s_bytes = s_scalar.to_bytes();
    let n_half_bytes = n_half.to_bytes();
    let is_high_s = s_bytes.as_slice() > n_half_bytes.as_slice();

    let (final_s, low_s_applied) = if is_high_s {
        // Normalize to low-S: s = n - s
        let low_s = n - s_scalar;
        (low_s.to_bytes(), true)
    } else {
        (s_bytes, false)
    };

    tracing::info!(
        "🔍 [SIGNATURE_CHECKPOINT] r={}, s_original={}, s_low={}, lowS_applied={}",
        hex::encode(r),
        hex::encode(s),
        hex::encode(&final_s),
        low_s_applied
    );

    // Create minimal DER encoding
    let der_encoded = create_minimal_der_signature(r, &final_s)?;

    tracing::info!(
        "🔍 [SIGNATURE_CHECKPOINT] DER_total_len={}, sighash_byte=0x01",
        der_encoded.len()
    );

    Ok(der_encoded)
}

/// Create minimal DER encoding for ECDSA signature (BIP-66 compliant)
fn create_minimal_der_signature(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    // Remove leading zeros but keep one if MSB would be set
    let trim_leading_zeros = |bytes: &[u8]| -> Vec<u8> {
        let mut start = 0;
        while start < bytes.len() - 1 && bytes[start] == 0 {
            start += 1;
        }
        // If MSB is set, we need a leading zero
        if bytes[start] & 0x80 != 0 && start > 0 {
            start -= 1;
        }
        bytes[start..].to_vec()
    };

    let r_trimmed = trim_leading_zeros(r);
    let s_trimmed = trim_leading_zeros(s);

    let mut der = Vec::new();

    // SEQUENCE tag
    der.push(0x30);

    // Calculate total length
    let r_len = r_trimmed.len();
    let s_len = s_trimmed.len();
    let total_len = 2 + r_len + 2 + s_len; // 2 bytes for each INTEGER header

    if total_len > 255 {
        return Err(anyhow::anyhow!("DER signature too long: {}", total_len));
    }

    der.push(total_len as u8);

    // R INTEGER
    der.push(0x02); // INTEGER tag
    der.push(r_len as u8);
    der.extend_from_slice(&r_trimmed);

    // S INTEGER
    der.push(0x02); // INTEGER tag
    der.push(s_len as u8);
    der.extend_from_slice(&s_trimmed);

    tracing::info!("🔍 [SIGNATURE_CHECKPOINT] R_len={}, S_len={}", r_len, s_len);

    Ok(der)
}

/// Log comprehensive pre-broadcast transaction details
pub fn log_pre_broadcast_details(tx: &BitcoinTransaction, tx_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    // Calculate txid (double SHA256 of raw transaction)
    let first_hash = Sha256::digest(tx_bytes);
    let second_hash = Sha256::digest(&first_hash);
    let mut txid_bytes = second_hash.to_vec();
    txid_bytes.reverse(); // Convert to big-endian for display
    let txid = hex::encode(&txid_bytes);

    // Calculate total fee (assuming we have input values available)
    let total_output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();

    tracing::info!(
        "🚀 [PRE_BROADCAST] txid={}, raw_tx_byte_length={}, num_inputs={}, num_outputs={}, total_output_value={}",
        txid,
        tx_bytes.len(),
        tx.inputs.len(),
        tx.outputs.len(),
        total_output_value
    );

    txid
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(amount_to_hex_string(1000000000000000000u128), "0xde0b6b3a7640000"); // 1 ETH in wei
        assert_eq!(amount_to_hex_string(21000000000000000000u128), "0x1236efcbcbb340000"); // 21 ETH in wei
        
        // Test very large amounts
        assert_eq!(amount_to_hex_string(u128::MAX), "0xffffffffffffffffffffffffffffffff");
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
        assert_eq!(validate_and_normalize_hex_amount("0x000001").unwrap(), "0x1");
        assert_eq!(validate_and_normalize_hex_amount("0x0000ff").unwrap(), "0xff");
        
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
