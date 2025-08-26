use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::rpc_server::DummyTransaction;
// use crate::signing::{ECDSASignature, SignedMessage}; // Removed unused imports

/// Generic transaction interface for different blockchain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainTransaction {
    Ethereum(EthereumTransaction),
    Bitcoin(BitcoinTransaction), // Future support
}

/// Ethereum transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumTransaction {
    pub to: String,
    pub value: String,
    pub gas_limit: u64,
    pub gas_price: String,
    pub nonce: u64,
    pub data: Option<Vec<u8>>,
    pub chain_id: u64,
}

/// Bitcoin transaction structure (placeholder for future implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub inputs: Vec<BitcoinInput>,
    pub outputs: Vec<BitcoinOutput>,
    pub version: u32,
    pub lock_time: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinInput {
    pub txid: String,
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Chain-specific signing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSigningResult {
    pub transaction: ChainTransaction,
    pub signature: ChainSignature,
    pub signer_id: String,
    pub timestamp: u64,
}

/// Chain-specific signature types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainSignature {
    Ethereum(EthereumSignature),
    Bitcoin(BitcoinSignature), // Future support
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumSignature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recovery_id: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinSignature {
    pub signature: Vec<u8>,
    pub sighash_type: u8,
}

/// Trait for chain-specific operations
pub trait ChainHandler: Send + Sync {
    /// Get the chain type identifier
    fn chain_type(&self) -> &'static str;
    
    /// Create transaction bytes for signing
    fn create_transaction_bytes(&self, transaction: &ChainTransaction) -> Result<Vec<u8>>;
    
    /// Create signature from raw signature data
    fn create_signature(&self, signature_data: &[u8], recovery_id: u8, transaction: &ChainTransaction) -> Result<ChainSignature>;
    
    /// Verify a signature against transaction
    fn verify_signature(&self, transaction: &ChainTransaction, signature: &ChainSignature, public_key: &[u8]) -> Result<bool>;
    
    /// Convert from legacy DummyTransaction (for backward compatibility)
    fn from_dummy_transaction(&self, dummy_tx: &DummyTransaction) -> Result<ChainTransaction>;
    
    /// Get chain-specific parameters (e.g., chain ID for Ethereum)
    fn get_chain_params(&self) -> HashMap<String, String>;
}

/// Ethereum chain handler implementation
pub struct EthereumChainHandler {
    chain_id: u64,
}

impl EthereumChainHandler {
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id }
    }
}

impl ChainHandler for EthereumChainHandler {
    fn chain_type(&self) -> &'static str {
        "ethereum"
    }
    
    fn create_transaction_bytes(&self, transaction: &ChainTransaction) -> Result<Vec<u8>> {
        match transaction {
            ChainTransaction::Ethereum(eth_tx) => {
                // Use the existing transaction utility function
                let dummy_tx = DummyTransaction {
                    to: eth_tx.to.clone(),
                    value: eth_tx.value.clone(),
                    gas_limit: eth_tx.gas_limit,
                    gas_price: eth_tx.gas_price.clone(),
                    nonce: eth_tx.nonce,
                    chain_id: eth_tx.chain_id,
                };
                Ok(crate::utils::transaction::create_transaction_for_signing(&dummy_tx))
            }
            _ => Err(anyhow::anyhow!("Invalid transaction type for Ethereum handler"))
        }
    }
    
    fn create_signature(&self, signature_data: &[u8], recovery_id: u8, transaction: &ChainTransaction) -> Result<ChainSignature> {
        if signature_data.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature length for Ethereum"));
        }
        
        let r = signature_data[0..32].to_vec();
        let s = signature_data[32..64].to_vec();
        
        // Calculate v value for Ethereum (EIP-155)
        let v = if let ChainTransaction::Ethereum(eth_tx) = transaction {
            recovery_id as u64 + 35 + eth_tx.chain_id * 2
        } else {
            recovery_id as u64 + 27 // Legacy format
        };
        
        Ok(ChainSignature::Ethereum(EthereumSignature {
            v,
            r,
            s,
            recovery_id,
        }))
    }
    
    fn verify_signature(&self, _transaction: &ChainTransaction, _signature: &ChainSignature, _public_key: &[u8]) -> Result<bool> {
        // TODO: Implement Ethereum signature verification
        Ok(true)
    }
    
    fn from_dummy_transaction(&self, dummy_tx: &DummyTransaction) -> Result<ChainTransaction> {
        Ok(ChainTransaction::Ethereum(EthereumTransaction {
            to: dummy_tx.to.clone(),
            value: dummy_tx.value.clone(),
            gas_limit: dummy_tx.gas_limit,
            gas_price: dummy_tx.gas_price.clone(),
            nonce: dummy_tx.nonce,
            data: None, // DummyTransaction doesn't have data field
            chain_id: dummy_tx.chain_id,
        }))
    }
    
    fn get_chain_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("chain_id".to_string(), self.chain_id.to_string());
        params.insert("signature_type".to_string(), "ECDSA".to_string());
        params
    }
}

/// Bitcoin chain handler implementation (placeholder for future development)
pub struct BitcoinChainHandler {
    network: String, // mainnet, testnet, regtest
}

impl BitcoinChainHandler {
    pub fn new(network: String) -> Self {
        Self { network }
    }
}

impl ChainHandler for BitcoinChainHandler {
    fn chain_type(&self) -> &'static str {
        "bitcoin"
    }
    
    fn create_transaction_bytes(&self, _transaction: &ChainTransaction) -> Result<Vec<u8>> {
        // TODO: Implement Bitcoin transaction serialization
        Err(anyhow::anyhow!("Bitcoin chain handler not yet implemented"))
    }
    
    fn create_signature(&self, _signature_data: &[u8], _recovery_id: u8, _transaction: &ChainTransaction) -> Result<ChainSignature> {
        // TODO: Implement Bitcoin signature creation
        Err(anyhow::anyhow!("Bitcoin chain handler not yet implemented"))
    }
    
    fn verify_signature(&self, _transaction: &ChainTransaction, _signature: &ChainSignature, _public_key: &[u8]) -> Result<bool> {
        // TODO: Implement Bitcoin signature verification
        Ok(false)
    }
    
    fn from_dummy_transaction(&self, _dummy_tx: &DummyTransaction) -> Result<ChainTransaction> {
        // TODO: Implement conversion from DummyTransaction to Bitcoin transaction
        Err(anyhow::anyhow!("Bitcoin chain handler not yet implemented"))
    }
    
    fn get_chain_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("network".to_string(), self.network.clone());
        params.insert("signature_type".to_string(), "ECDSA".to_string());
        params
    }
}

/// Chain handler factory
pub struct ChainHandlerFactory;

impl ChainHandlerFactory {
    pub fn create_ethereum_handler(chain_id: u64) -> Box<dyn ChainHandler> {
        Box::new(EthereumChainHandler::new(chain_id))
    }
    
    pub fn create_bitcoin_handler(network: String) -> Box<dyn ChainHandler> {
        Box::new(BitcoinChainHandler::new(network))
    }
    
    pub fn create_handler_by_type(chain_type: &str, params: HashMap<String, String>) -> Result<Box<dyn ChainHandler>> {
        match chain_type {
            "ethereum" => {
                let chain_id = params.get("chain_id")
                    .ok_or_else(|| anyhow::anyhow!("Missing chain_id parameter for Ethereum"))?
                    .parse::<u64>()?;
                Ok(Self::create_ethereum_handler(chain_id))
            }
            "bitcoin" => {
                let network = params.get("network")
                    .unwrap_or(&"mainnet".to_string())
                    .clone();
                Ok(Self::create_bitcoin_handler(network))
            }
            _ => Err(anyhow::anyhow!("Unsupported chain type: {}", chain_type))
        }
    }
}