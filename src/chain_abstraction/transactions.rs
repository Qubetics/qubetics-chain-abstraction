use serde::{Deserialize, Serialize};

pub use crate::types::chain::bitcoin::{
    BitcoinInput, BitcoinOutput, BitcoinSignature, BitcoinTransaction, BitcoinWitness,
    BitcoinWitnessInput, BitcoinWitnessUtxo,
};

/// TICS transaction structure used across handlers and services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicsTransaction {
    pub to: String,
    pub value: String,
    pub gas_limit: u64,
    pub gas_price: String,
    pub nonce: u64,
    pub data: Option<Vec<u8>>,
    pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicsSignature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recovery_id: u8,
}

/// Generic transaction interface for different blockchain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainTransaction {
    Tics(TicsTransaction),
    Bitcoin(BitcoinTransaction),
}

impl ChainTransaction {
    pub fn as_tics(&self) -> Option<&TicsTransaction> {
        match self {
            ChainTransaction::Tics(tx) => Some(tx),
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
    Tics(TicsSignature),
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
