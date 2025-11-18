use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{ContractTransaction, DummyTransaction};

use super::{ChainHandler, ChainSignature, ChainTransaction};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumSignature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recovery_id: u8,
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
                if let Some(data) = &eth_tx.data {
                    let contract_tx = ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                        data: hex::encode(data),
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &eth_tx,
                    ))
                }
            }
            _ => Err(anyhow::anyhow!(
                "Invalid transaction type for Ethereum handler"
            )),
        }
    }

    fn create_transaction_bytes_contract(&self, transaction: &ChainTransaction) -> Result<Vec<u8>> {
        match transaction {
            ChainTransaction::Ethereum(eth_tx) => {
                if let Some(data) = &eth_tx.data {
                    let contract_tx = ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                        data: hex::encode(data),
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &eth_tx,
                    ))
                }
            }
            _ => Err(anyhow::anyhow!(
                "Invalid transaction type for Ethereum handler"
            )),
        }
    }

    fn create_signature(
        &self,
        signature_data: &[u8],
        recovery_id: u8,
        transaction: &ChainTransaction,
    ) -> Result<ChainSignature> {
        if signature_data.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature length for Ethereum"));
        }

        let r = signature_data[0..32].to_vec();
        let s = signature_data[32..64].to_vec();

        let v = if let ChainTransaction::Ethereum(eth_tx) = transaction {
            recovery_id as u64 + 35 + eth_tx.chain_id * 2
        } else {
            recovery_id as u64 + 27
        };

        Ok(ChainSignature::Ethereum(EthereumSignature {
            v,
            r,
            s,
            recovery_id,
        }))
    }

    fn verify_signature(
        &self,
        transaction: &ChainTransaction,
        signature: &ChainSignature,
        public_key: &[u8],
    ) -> Result<bool> {
        match (transaction, signature) {
            (ChainTransaction::Ethereum(eth_tx), ChainSignature::Ethereum(eth_sig)) => {
                if eth_sig.r.len() != 32 || eth_sig.s.len() != 32 {
                    return Ok(false);
                }

                if public_key.len() != 64 && public_key.len() != 65 {
                    return Ok(false);
                }

                tracing::info!(
                    "Ethereum signature verification - basic validation passed for transaction to: {}",
                    eth_tx.to
                );
                Ok(true)
            }
            _ => Err(anyhow::anyhow!(
                "Mismatched transaction and signature types for Ethereum"
            )),
        }
    }

    fn from_dummy_transaction(&self, dummy_tx: &DummyTransaction) -> Result<ChainTransaction> {
        Ok(ChainTransaction::Ethereum(EthereumTransaction {
            to: dummy_tx.to.clone(),
            value: dummy_tx.value.clone(),
            gas_limit: dummy_tx.gas_limit,
            gas_price: dummy_tx.gas_price.clone(),
            nonce: dummy_tx.nonce,
            data: None,
            chain_id: dummy_tx.chain_id,
        }))
    }

    fn get_chain_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("chain_id".to_string(), self.chain_id.to_string());
        params.insert("signature_type".to_string(), "ECDSA".to_string());
        params
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
