use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::DummyTransaction;

pub mod bitcoin;
pub mod ethereum;

pub use crate::types::chain::bitcoin::{
    BitcoinInput, BitcoinOutput, BitcoinSignature, BitcoinTransaction, BitcoinWitness,
    BitcoinWitnessInput, BitcoinWitnessUtxo,
};
pub use bitcoin::BitcoinChainHandler;
pub use ethereum::{EthereumChainHandler, EthereumSignature, EthereumTransaction};

/// Generic transaction interface for different blockchain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainTransaction {
    Ethereum(EthereumTransaction),
    Bitcoin(BitcoinTransaction),
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
    Bitcoin(BitcoinSignature),
}

/// Trait for chain-specific operations
pub trait ChainHandler: Send + Sync {
    /// Get the chain type identifier
    fn chain_type(&self) -> &'static str;

    /// Create transaction bytes for signing
    fn create_transaction_bytes(&self, transaction: &ChainTransaction) -> Result<Vec<u8>>;
    fn create_transaction_bytes_contract(&self, transaction: &ChainTransaction) -> Result<Vec<u8>>;

    /// Create signature from raw signature data
    fn create_signature(
        &self,
        signature_data: &[u8],
        recovery_id: u8,
        transaction: &ChainTransaction,
    ) -> Result<ChainSignature>;

    /// Verify a signature against transaction
    fn verify_signature(
        &self,
        transaction: &ChainTransaction,
        signature: &ChainSignature,
        public_key: &[u8],
    ) -> Result<bool>;

    /// Convert from legacy DummyTransaction (for backward compatibility)
    fn from_dummy_transaction(&self, dummy_tx: &DummyTransaction) -> Result<ChainTransaction>;

    /// Get chain-specific parameters (e.g., chain ID for Ethereum)
    fn get_chain_params(&self) -> HashMap<String, String>;

    /// Downcast to concrete type for type-specific operations
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// Chain handler factory helpers
pub struct ChainHandlerFactory;

impl ChainHandlerFactory {
    pub fn create_ethereum_handler(chain_id: u64) -> Box<dyn ChainHandler> {
        Box::new(EthereumChainHandler::new(chain_id))
    }

    pub fn create_bitcoin_handler(network: String) -> Box<dyn ChainHandler> {
        Box::new(BitcoinChainHandler::new(network))
    }

    pub fn create_handler_by_type(
        chain_type: &str,
        params: HashMap<String, String>,
    ) -> Result<Box<dyn ChainHandler>> {
        match chain_type {
            "ethereum" => {
                let chain_id = params
                    .get("chain_id")
                    .ok_or_else(|| anyhow::anyhow!("Missing chain_id parameter for Ethereum"))?
                    .parse::<u64>()?;
                Ok(Self::create_ethereum_handler(chain_id))
            }
            "bitcoin" => {
                let network = params
                    .get("network")
                    .unwrap_or(&"mainnet".to_string())
                    .clone();
                Ok(Self::create_bitcoin_handler(network))
            }
            _ => Err(anyhow::anyhow!("Unsupported chain type: {}", chain_type)),
        }
    }
}
