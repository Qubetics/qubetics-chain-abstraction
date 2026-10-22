use anyhow::Result;
use std::collections::HashMap;

use crate::types::DummyTransaction;

use crate::chain_abstraction::transactions::{ChainSignature, ChainTransaction};

pub mod bitcoin;
pub mod tics;

pub use bitcoin::BitcoinChainHandler;
pub use tics::TicsChainHandler;

/// Trait for chain-specific operations used by signing nodes
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

    /// Get chain-specific parameters (e.g., chain ID for TICS)
    fn get_chain_params(&self) -> HashMap<String, String>;

    /// Downcast to concrete type for type-specific operations
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}
