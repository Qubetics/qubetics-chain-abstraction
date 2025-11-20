use super::SigningNode;
use crate::{
    chain_abstraction::BitcoinTransaction,
    types::{signing::BtcIndexedSignature, SpendKind, TransactionType},
};
use anyhow::Result;
use k256::Scalar;
use secp256k1::ecdsa::RecoverableSignature;

/// Convenience wrapper that exposes Bitcoin-specific signing operations on a `SigningNode`.
pub struct BitcoinSigner<'a> {
    node: &'a mut SigningNode,
}

impl<'a> BitcoinSigner<'a> {
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
        tx_bytes: Vec<u8>,
        original_tx: Option<BitcoinTransaction>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<TransactionType>,
        user_tweaked_share: Option<Scalar>,
        solver_address: Option<String>,
    ) -> Result<()> {
        self.node
            .sign_bitcoin_transaction(
                tx_bytes,
                original_tx,
                user_eth_address,
                intent_hash,
                transaction_type,
                user_tweaked_share,
                solver_address,
            )
            .await
    }

    pub async fn send_signatures_to_final_node(
        &mut self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        self.node
            .send_btc_signatures_to_final_node(final_node_id, round)
            .await
    }

    pub async fn handle_signatures_from_peer(
        &mut self,
        from: String,
        signatures: Vec<BtcIndexedSignature>,
        round: u64,
    ) -> Result<()> {
        self.node
            .handle_btc_signatures_to_final_node(from, signatures, round)
            .await
    }

    pub fn finalize_transaction(
        &self,
        tx: BitcoinTransaction,
        from_kind: SpendKind,
        per_input_sigs: &[(usize, RecoverableSignature)],
        pubkey33: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32], Option<[u8; 32]>)> {
        SigningNode::finalize_and_serialize_tx(tx, from_kind, per_input_sigs, pubkey33)
    }
}
