use anyhow::{anyhow, Result};
use std::collections::HashMap;

use crate::types::{ContractTransaction, DummyTransaction};

use super::ChainHandler;
use crate::chain_abstraction::transactions::{
    ChainSignature, ChainTransaction, EthereumSignature, EthereumTransaction,
};

/// Ethereum chain handler implementation
pub struct EthereumChainHandler {
    chain_id: u64,
}

impl EthereumChainHandler {
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id }
    }

    fn ensure_chain_id(&self, tx_chain_id: u64) -> Result<()> {
        if tx_chain_id != self.chain_id {
            Err(anyhow!(
                "Mismatched chain ID for Ethereum handler: expected {}, got {}",
                self.chain_id, tx_chain_id
            ))
        } else {
            Ok(())
        }
    }
}

impl ChainHandler for EthereumChainHandler {
    fn chain_type(&self) -> &'static str {
        "ethereum"
    }

    fn create_transaction_bytes(&self, transaction: &ChainTransaction) -> Result<Vec<u8>> {
        match transaction {
            ChainTransaction::Ethereum(eth_tx) => {
                self.ensure_chain_id(eth_tx.chain_id)?;

                if let Some(data) = &eth_tx.data {
                    let contract_tx = ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: self.chain_id,
                        data: hex::encode(data),
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    let sanitized_tx = EthereumTransaction {
                        chain_id: self.chain_id,
                        ..eth_tx.clone()
                    };
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &sanitized_tx,
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
                self.ensure_chain_id(eth_tx.chain_id)?;

                if let Some(data) = &eth_tx.data {
                    let contract_tx = ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: self.chain_id,
                        data: hex::encode(data),
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    let sanitized_tx = EthereumTransaction {
                        chain_id: self.chain_id,
                        ..eth_tx.clone()
                    };
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &sanitized_tx,
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
            self.ensure_chain_id(eth_tx.chain_id)?;
            recovery_id as u64 + 35 + self.chain_id * 2
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
        self.ensure_chain_id(dummy_tx.chain_id)?;

        Ok(ChainTransaction::Ethereum(EthereumTransaction {
            to: dummy_tx.to.clone(),
            value: dummy_tx.value.clone(),
            gas_limit: dummy_tx.gas_limit,
            gas_price: dummy_tx.gas_price.clone(),
            nonce: dummy_tx.nonce,
            data: None,
            chain_id: self.chain_id,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_eth_transaction(chain_id: u64) -> EthereumTransaction {
        EthereumTransaction {
            to: "0x0000000000000000000000000000000000000000".to_string(),
            value: "0x0".to_string(),
            gas_limit: 21_000,
            gas_price: "0x1".to_string(),
            nonce: 0,
            data: None,
            chain_id,
        }
    }

    #[test]
    fn rejects_transactions_with_mismatched_chain_id() {
        let handler = EthereumChainHandler::new(1);
        let tx = ChainTransaction::Ethereum(base_eth_transaction(2));

        assert!(handler.create_transaction_bytes(&tx).is_err());
        assert!(handler.create_transaction_bytes_contract(&tx).is_err());
    }

    #[test]
    fn rejects_signatures_for_wrong_chain_id() {
        let handler = EthereumChainHandler::new(1);
        let tx = ChainTransaction::Ethereum(base_eth_transaction(2));
        let sig = vec![0u8; 64];

        assert!(handler.create_signature(&sig, 0, &tx).is_err());
    }
}
