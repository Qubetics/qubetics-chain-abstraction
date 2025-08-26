use crate::rpc_server::{DepositIntent, DummyTransaction};
use crate::chain::{ChainTransaction, EthereumTransaction, BitcoinTransaction, BitcoinInput, BitcoinOutput};
use anyhow::Result;
// use rlp::RlpStream;

/// RLP encoder for Ethereum transaction signing (EIP-155)
pub struct RlpEncoder {
    pub data: Vec<u8>,
}

// impl RlpEncoder {
//     pub fn new() -> Self {
//         Self { data: Vec::new() }
//     }

//     pub fn encode_u64(&mut self, value: u64) {
//         if value == 0 {
//             self.data.push(0x80);
//         } else {
//             let bytes = value.to_be_bytes();
//             let start = bytes.iter().position(|&x| x != 0).unwrap_or(bytes.len() - 1);
//             self.encode_bytes(&bytes[start..]);
//         }
//     }

//     pub fn encode_hex_string(&mut self, hex_str: &str) {
//         // Remove "0x" prefix if present
//         let clean_hex = if hex_str.starts_with("0x") {
//             &hex_str[2..]
//         } else {
//             hex_str
//         };

//         // Convert hex string to bytes
//         let bytes = hex::decode(clean_hex).unwrap_or_else(|_| {
//             // If hex decoding fails, try to parse as decimal string
//             let value = clean_hex.parse::<u128>().unwrap_or(0);
//             value.to_be_bytes().to_vec()
//         });

//         let mut stream = RlpStream::new();
//         stream.append(&bytes);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn encode_address(&mut self, address: &str) {
//         // Remove "0x" prefix if present
//         let clean_address = if address.starts_with("0x") {
//             &address[2..]
//         } else {
//             address
//         };

//         // Convert hex address to bytes
//         let bytes = hex::decode(clean_address).unwrap_or_else(|_| vec![0u8; 20]);

//         let mut stream = RlpStream::new();
//         stream.append(&bytes);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn encode_bytes(&mut self, bytes: &[u8]) {
//         let mut stream = RlpStream::new();
//         stream.append(&bytes);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn encode_list_header(&mut self, content_len: usize) {
//         let mut stream = RlpStream::new();
//         stream.begin_list(content_len);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn finalize(self) -> Vec<u8> {
//         self.data
//     }
// }
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
        "qubetics" => Some(1043),
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

/// Create a chain-specific transaction from a deposit intent
pub fn create_chain_transaction_from_deposit_intent(intent: &DepositIntent) -> Result<ChainTransaction> {
    let target_chain = &intent.target_chain.to_lowercase();
    
    if is_evm_chain(target_chain) {
        // Create Ethereum-compatible transaction
        let chain_id = get_chain_id_from_name(target_chain)
            .ok_or_else(|| anyhow::anyhow!("Unknown EVM chain: {}", target_chain))?;
            
        let ethereum_tx = EthereumTransaction {
            to: intent.target_address.clone(),
            value: format!("0x{:x}", intent.amount),
            gas_limit: 21000, // Standard transfer gas limit
            gas_price: get_default_gas_price_for_chain(target_chain),
            nonce: 0, // This should be fetched from the network or maintained per sender
            data: None, // Simple transfer has no data
            chain_id,
        };
        
        Ok(ChainTransaction::Ethereum(ethereum_tx))
    } else if target_chain == "bitcoin" || target_chain == "btc" {
        // Create Bitcoin transaction (placeholder structure)
        let bitcoin_tx = BitcoinTransaction {
            inputs: vec![BitcoinInput {
                txid: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                vout: 0,
                script_sig: vec![],
                sequence: 0xfffffffe,
            }],
            outputs: vec![BitcoinOutput {
                value: intent.amount as u64, // Convert from u128 to u64 (satoshis)
                script_pubkey: create_bitcoin_script_pubkey(&intent.target_address)?,
            }],
            version: 2,
            lock_time: 0,
        };
        
        Ok(ChainTransaction::Bitcoin(bitcoin_tx))
    } else {
        Err(anyhow::anyhow!("Unsupported target chain: {}", target_chain))
    }
}

/// Get default gas price for different EVM chains
fn get_default_gas_price_for_chain(chain_name: &str) -> String {
    match chain_name {
        "ethereum" | "eth" => "0x4A817C800".to_string(), // 20 Gwei
        "qubetics" => "0x3B9ACA00".to_string(), // 1 Gwei
        "polygon" | "matic" => "0x12A05F200".to_string(), // 5 Gwei
        "bsc" | "binance" => "0x12A05F200".to_string(), // 5 Gwei
        "avalanche" | "avax" => "0x5D21DBA00".to_string(), // 25 Gwei
        "arbitrum" => "0x5F5E100".to_string(), // 0.1 Gwei
        "optimism" => "0x5F5E100".to_string(), // 0.1 Gwei
        "base" => "0x5F5E100".to_string(), // 0.1 Gwei
        _ => "0x4A817C800".to_string(), // Default to 20 Gwei
    }
}

/// Create a Bitcoin script_pubkey for an address (simplified)
fn create_bitcoin_script_pubkey(address: &str) -> Result<Vec<u8>> {
    // This is a placeholder implementation
    // In a real implementation, you would parse the Bitcoin address
    // and create the appropriate script_pubkey
    if address.starts_with("bc1") || address.starts_with("tb1") {
        // Bech32 address (P2WPKH or P2WSH)
        // For now, return a placeholder script
        Ok(vec![0x00, 0x14]) // OP_0 + 20 bytes (placeholder)
    } else if address.starts_with("1") || address.starts_with("m") || address.starts_with("n") {
        // Legacy P2PKH address
        Ok(vec![0x76, 0xa9, 0x14]) // OP_DUP OP_HASH160 OP_PUSHDATA(20) (placeholder)
    } else if address.starts_with("3") || address.starts_with("2") {
        // P2SH address
        Ok(vec![0xa9, 0x14]) // OP_HASH160 OP_PUSHDATA(20) (placeholder)
    } else {
        Err(anyhow::anyhow!("Invalid Bitcoin address format: {}", address))
    }
}

/// Create a transaction from a deposit intent (backward compatibility)
/// This function now delegates to the chain-specific version and converts to DummyTransaction for EVM chains
pub fn create_transaction_from_deposit_intent(intent: &DepositIntent) -> DummyTransaction {
    match create_chain_transaction_from_deposit_intent(intent) {
        Ok(ChainTransaction::Ethereum(eth_tx)) => {
            // Convert EthereumTransaction to DummyTransaction for backward compatibility
            DummyTransaction {
                to: eth_tx.to,
                value: eth_tx.value,
                nonce: eth_tx.nonce,
                gas_limit: eth_tx.gas_limit,
                gas_price: eth_tx.gas_price,
                chain_id: eth_tx.chain_id,
            }
        }
        Ok(ChainTransaction::Bitcoin(_)) => {
            // For Bitcoin, we can't convert to DummyTransaction since it's EVM-specific
            // Return a placeholder that will cause an error later
            tracing::warn!("Bitcoin transaction cannot be converted to DummyTransaction");
            DummyTransaction {
                to: "BITCOIN_NOT_COMPATIBLE_WITH_EVM".to_string(),
                value: "0".to_string(),
                nonce: 0,
                gas_limit: 0,
                gas_price: "0".to_string(),
                chain_id: 0,
            }
        }
        Err(e) => {
            tracing::warn!("Failed to create chain transaction: {}, falling back to default", e);
            // Fallback to the old behavior for unknown chains
            DummyTransaction {
                to: intent.target_address.clone(),
                value: format!("0x{:x}", intent.amount),
                nonce: 0,
                gas_limit: 21000,
                gas_price: "0x4A817C800".to_string(),
                chain_id: 1043, // Default to Qubetics
            }
        }
    }
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
