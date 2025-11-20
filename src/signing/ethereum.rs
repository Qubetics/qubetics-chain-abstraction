use super::SigningNode;
use crate::{
    chain_abstraction::EthereumTransaction,
    types::{intent::ContractTransaction, TransactionType},
};
use anyhow::Result;
use k256::Scalar;

/// Convenience wrapper for Ethereum-focused signing flows.
pub struct EthereumSigner<'a> {
    node: &'a mut SigningNode,
}

impl<'a> EthereumSigner<'a> {
    pub fn new(node: &'a mut SigningNode) -> Self {
        Self { node }
    }

    pub fn node(&self) -> &SigningNode {
        self.node
    }

    pub fn node_mut(&mut self) -> &mut SigningNode {
        self.node
    }

    pub async fn sign_transaction(
        &mut self,
        message: Vec<u8>,
        transaction: &EthereumTransaction,
        user_tweaked_share: Option<Scalar>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<TransactionType>,
        solver_address: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_message(
                message,
                transaction,
                user_tweaked_share,
                user_eth_address,
                intent_hash,
                transaction_type,
                solver_address,
            )
            .await
    }

    pub async fn sign_contract_message(
        &mut self,
        message: Vec<u8>,
        contract_tx: &ContractTransaction,
        user_tweaked_share: Option<Scalar>,
        user_eth_address: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_contract_message(message, contract_tx, user_tweaked_share, user_eth_address)
            .await
    }
}
