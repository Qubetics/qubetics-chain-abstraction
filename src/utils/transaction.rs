use crate::chain::{
    BitcoinInput, BitcoinOutput, BitcoinTransaction, BitcoinWitness, BitcoinWitnessInput, BitcoinWitnessUtxo, ChainTransaction, EthereumTransaction,
};
use crate::rpc_server::{DepositIntent, DummyTransaction};
use crate::utils::get_eth_address_from_group_key;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;
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
    let mut final_hex = if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    };

    if final_hex.len() % 2 == 1 {
        final_hex = format!("0{}", final_hex);
    }

    hex::decode(&final_hex).expect("Invalid hex string")
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

/// Fetch UTXOs for a Bitcoin address from Blockstream API
pub async fn fetch_bitcoin_utxos(address: &str, is_testnet: bool) -> Result<Vec<BitcoinUtxo>> {
    let base_url = if is_testnet {
        "https://blockstream.info/testnet/api"
    } else {
        "https://blockstream.info/api"
    };

    let url = format!("{}/address/{}/utxo", base_url, address);

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch UTXOs: HTTP {}",
            response.status()
        ));
    }

    let utxos: Vec<BitcoinUtxo> = response.json().await?;
    Ok(utxos)
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

    // Only use confirmed UTXOs
    let confirmed_utxos: Vec<_> = sorted_utxos
        .into_iter()
        .filter(|utxo| utxo.status.confirmed)
        .collect();

    if confirmed_utxos.is_empty() {
        return Err(anyhow::anyhow!("No confirmed UTXOs available"));
    }

    // Select UTXOs until we have enough value
    for utxo in confirmed_utxos {
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

    Ok((selected_utxos, total_value))
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

async fn fetch_ethereum_nonce(address: &str, chain_id: u64) -> Result<u64> {
    let rpc_url = match chain_id {
        9029 => "https://rpc-testnet.qubetics.work", // Qubetics RPC URL
        1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID", // Ethereum mainnet
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
        "params": [address, "latest"],
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

/// Create a chain-specific transaction from a deposit intent
/// For Bitcoin transactions, group_public_key is required to derive the Bitcoin address and fetch UTXOs
pub async fn create_chain_transaction_from_deposit_intent(
    intent: &DepositIntent,
    group_public_key: Option<k256::ProjectivePoint>,
) -> Result<ChainTransaction> {
    let target_chain = &intent.target_chain.to_lowercase();

    if is_evm_chain(target_chain) {
        // Create Ethereum-compatible transaction
        let chain_id = get_chain_id_from_name(target_chain)
            .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", target_chain))?;
        let group_address: String = get_eth_address_from_group_key(group_public_key.unwrap());

        let ethereum_tx = EthereumTransaction {
            to: intent.target_address.clone(),
            value: format!("0x{:x}", intent.amount),
            gas_limit: 21000, 
            gas_price: get_default_gas_price_for_chain(target_chain),
            nonce: fetch_ethereum_nonce(&group_address, chain_id).await?,
            data: None, 
            chain_id,
        };

        Ok(ChainTransaction::Ethereum(ethereum_tx))
    } else if target_chain == "bitcoin" || target_chain == "btc" {
        // Create Bitcoin transaction with proper UTXO fetching
        let group_key = group_public_key
            .ok_or_else(|| anyhow::anyhow!("Group public key required for Bitcoin transactions"))?;

        // Get Bitcoin address from group key
        let btc_address = crate::utils::get_btc_address_from_group_key(group_key);
        tracing::info!("Using Bitcoin address for UTXOs: {}", btc_address);

        // Determine if we're using testnet (you might want to make this configurable)
        let is_testnet = btc_address.starts_with("tb1")
            || btc_address.starts_with("2")
            || btc_address.starts_with("m")
            || btc_address.starts_with("n");

        // Fetch UTXOs for the address
        let utxos = fetch_bitcoin_utxos(&btc_address, is_testnet).await?;
        tracing::info!("Fetched {} UTXOs for address {}", utxos.len(), btc_address);

        if utxos.is_empty() {
            return Err(anyhow::anyhow!(
                "No UTXOs found for Bitcoin address: {}",
                btc_address
            ));
        }

        // Convert amount from wei to satoshis (assuming 1:1 conversion for now, you might want to adjust this)
        let amount_satoshis = (intent.amount) as u64;
        let estimated_fee = calculate_bitcoin_fee(utxos.len(), 2); // 2 outputs (recipient + change)

        // Select UTXOs that provide enough value
        let (selected_utxos, total_input_value) =
            select_utxos_for_amount(&utxos, amount_satoshis, estimated_fee)?;

        tracing::info!(
            "Selected {} UTXOs with total value {} satoshis for transaction of {} satoshis (fee: {})",
            selected_utxos.len(),
            total_input_value,
            amount_satoshis,
            estimated_fee
        );

        // Create inputs from selected UTXOs with proper witness support
        let inputs: Vec<BitcoinInput> = selected_utxos
            .iter()
            .map(|utxo| {
                let address_type = detect_bitcoin_address_type(&btc_address);
                let witness_utxo = match address_type {
                    DetectedAddressType::P2WPKH | DetectedAddressType::P2WSH | DetectedAddressType::P2TR => {
                        // For SegWit inputs, we need witness UTXO information
                        Some(BitcoinWitnessUtxo {
                            value: utxo.value,
                            script_pubkey: create_bitcoin_script_pubkey(&btc_address).unwrap_or_default(),
                        })
                    },
                    _ => None, // Legacy inputs don't need witness UTXO
                };

                BitcoinInput {
                    txid: utxo.txid.clone(),
                    vout: utxo.vout,
                    script_sig: vec![],   // Will be filled during signing
                    sequence: 0xfffffffe, // Enable RBF (Replace-By-Fee)
                    witness_utxo,
                }
            })
            .collect();

        // Create outputs
        let mut outputs = vec![BitcoinOutput {
            value: amount_satoshis,
            script_pubkey: create_bitcoin_script_pubkey(&intent.target_address)?,
        }];

        // Add change output if necessary
        let change_amount = total_input_value - amount_satoshis - estimated_fee;
        if change_amount > 546 {
            // Bitcoin dust limit
            outputs.push(BitcoinOutput {
                value: change_amount,
                script_pubkey: create_bitcoin_script_pubkey(&btc_address)?, // Send change back to source address
            });
        }

        // Determine if we need witness data based on input address types
        let needs_witness = inputs.iter().any(|input| input.witness_utxo.is_some());
        let witness = if needs_witness {
            Some(BitcoinWitness {
                inputs: inputs.iter().map(|_| BitcoinWitnessInput {
                    stack: vec![], // Will be filled during signing
                }).collect(),
            })
        } else {
            None
        };

        let bitcoin_tx = BitcoinTransaction {
            inputs,
            outputs,
            version: 2,
            lock_time: 0,
            witness,
        };

        Ok(ChainTransaction::Bitcoin(bitcoin_tx))
    } else {
        Err(anyhow::anyhow!(
            "Unsupported target chain: {}",
            target_chain
        ))
    }
}

/// Get default gas price for different EVM chains
fn get_default_gas_price_for_chain(chain_name: &str) -> String {
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

/// Bitcoin address type detection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectedAddressType {
    P2PKH,  // Legacy (1...)
    P2SH,   // Script Hash (3...)
    P2WPKH, // Native SegWit v0 (bc1...)
    P2WSH,  // Native SegWit v0 script hash (bc1...)
    P2TR,   // Taproot (bc1p...)
    Unknown,
}

/// Detect Bitcoin address type from address string
fn detect_bitcoin_address_type(address: &str) -> DetectedAddressType {
    if address.starts_with("bc1p") || address.starts_with("tb1p") {
        DetectedAddressType::P2TR
    } else if address.starts_with("bc1") || address.starts_with("tb1") {
        // Differentiate between P2WPKH and P2WSH based on address length
        // P2WPKH: 42 characters (bc1q... or tb1q...)
        // P2WSH: 62 characters (bc1q... or tb1q... but longer)
        if address.len() == 42 {
            DetectedAddressType::P2WPKH
        } else if address.len() == 62 {
            DetectedAddressType::P2WSH
        } else {
            // Fallback to P2WPKH for unknown lengths
            DetectedAddressType::P2WPKH
        }
    } else if address.starts_with("3") || address.starts_with("2") {
        DetectedAddressType::P2SH
    } else if address.starts_with("1") || address.starts_with("m") || address.starts_with("n") {
        DetectedAddressType::P2PKH
    } else {
        DetectedAddressType::Unknown
    }
}

/// Create a Bitcoin script_pubkey for an address (supports all address types)
fn create_bitcoin_script_pubkey(address: &str) -> Result<Vec<u8>> {
    use bitcoin::{Address, Network};
    use std::str::FromStr;

    // Parse the address and determine network
    let parsed_address = Address::from_str(address)
        .map_err(|e| anyhow::anyhow!("Invalid Bitcoin address '{}': {}", address, e))?;

    // Assume the correct network based on address format and require it
    let network =
        if address.starts_with("bc1") || address.starts_with("1") || address.starts_with("3") {
            Network::Bitcoin
        } else if address.starts_with("tb1")
            || address.starts_with("m")
            || address.starts_with("n")
            || address.starts_with("2")
        {
            Network::Testnet
        } else {
            return Err(anyhow::anyhow!(
                "Cannot determine network for address: {}",
                address
            ));
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
                "✅ [TRANSACTION] Address {} is Legacy P2PKH - fully compatible",
                address
            );
        },
        DetectedAddressType::P2SH => {
            tracing::info!(
                "✅ [TRANSACTION] Address {} is P2SH - compatible with proper script handling",
                address
            );
        },
        DetectedAddressType::P2WPKH => {
            tracing::info!(
                "✅ [TRANSACTION] Address {} is P2WPKH (Native SegWit) - requires witness data",
                address
            );
        },
        DetectedAddressType::P2WSH => {
            tracing::info!(
                "✅ [TRANSACTION] Address {} is P2WSH (Native SegWit Script) - requires witness data",
                address
            );
        },
        DetectedAddressType::P2TR => {
            tracing::info!(
                "✅ [TRANSACTION] Address {} is P2TR (Taproot) - requires Schnorr signatures",
                address
            );
        },
        DetectedAddressType::Unknown => {
            tracing::warn!(
                "⚠️ [TRANSACTION] Address {} has unknown type - proceeding with caution",
                address
            );
        },
    }

    Ok(script_bytes)
}

pub fn create_transaction_for_signing(tx: &DummyTransaction) -> Vec<u8> {
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

pub fn create_signed_transaction(tx: &DummyTransaction, r: &[u8], s: &[u8], v: u64) -> Vec<u8> {
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

    // Value
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.value);
    content.extend_from_slice(&encoder.finalize());

    // Data (empty)
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    // v
    encoder = RlpEncoder::new();
    encoder.encode_u64(v); // ✅ proper RLP encoding for large v
    content.extend_from_slice(&encoder.finalize());

    // r
    encoder = RlpEncoder::new();
    encoder.encode_bytes(r);
    content.extend_from_slice(&encoder.finalize());

    // s
    encoder = RlpEncoder::new();
    encoder.encode_bytes(s);
    content.extend_from_slice(&encoder.finalize());

    // Create final RLP with list header
    let mut final_encoder = RlpEncoder::new();
    final_encoder.encode_list_header(content.len());
    final_encoder.data.extend_from_slice(&content);

    final_encoder.finalize()
}
