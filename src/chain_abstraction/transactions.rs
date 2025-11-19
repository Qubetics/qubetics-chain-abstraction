use serde::{Deserialize, Serialize};

pub use crate::types::chain::bitcoin::{
    BitcoinInput, BitcoinOutput, BitcoinSignature, BitcoinTransaction, BitcoinWitness,
    BitcoinWitnessInput, BitcoinWitnessUtxo,
};

/// Ethereum transaction structure used across handlers and services
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumSignature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recovery_id: u8,
}

/// Generic transaction interface for different blockchain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainTransaction {
    Ethereum(EthereumTransaction),
    Bitcoin(BitcoinTransaction),
}

impl ChainTransaction {
    pub fn as_ethereum(&self) -> Option<&EthereumTransaction> {
        match self {
            ChainTransaction::Ethereum(tx) => Some(tx),
            _ => None,
        }
    }

    pub fn as_bitcoin(&self) -> Option<&BitcoinTransaction> {
        match self {
            ChainTransaction::Bitcoin(tx) => Some(tx),
            _ => None,
        }
    }
}

/// Chain-specific signature types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainSignature {
    Ethereum(EthereumSignature),
    Bitcoin(BitcoinSignature),
}

/// Chain-specific signing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSigningResult {
    pub transaction: ChainTransaction,
    pub signature: ChainSignature,
    pub signer_id: String,
    pub timestamp: u64,
}


