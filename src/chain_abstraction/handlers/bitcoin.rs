use anyhow::Result;
use std::collections::HashMap;

use crate::types::{ContractTransaction, DummyTransaction};

use super::ChainHandler;
use crate::chain_abstraction::transactions::{
    BitcoinSignature, BitcoinTransaction, ChainSignature, ChainTransaction,
};

/// Encode a variable length integer for Bitcoin transaction serialization
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut bytes = vec![0xfd];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value <= 0xffffffff {
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}

fn sorted_inputs(
    inputs: &[crate::types::chain::bitcoin::BitcoinInput],
) -> Vec<crate::types::chain::bitcoin::BitcoinInput> {
    let mut sorted = inputs.to_vec();
    sorted.sort_by(|a, b| {
        a.txid
            .cmp(&b.txid)
            .then_with(|| a.vout.cmp(&b.vout))
            .then_with(|| a.sequence.cmp(&b.sequence))
            .then_with(|| a.script_sig.cmp(&b.script_sig))
    });
    sorted
}

fn sorted_outputs(
    outputs: &[crate::types::chain::bitcoin::BitcoinOutput],
) -> Vec<crate::types::chain::bitcoin::BitcoinOutput> {
    let mut sorted = outputs.to_vec();
    sorted.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
    });
    sorted
}

/// Create P2PKH script_pubkey for Bitcoin signing using the actual DKG group public key
fn create_p2pkh_script_for_signing(group_public_key: &[u8]) -> Result<Vec<u8>> {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    if group_public_key.len() != 33 {
        return Err(anyhow::anyhow!(
            "Invalid group public key length: expected 33 bytes, got {}",
            group_public_key.len()
        ));
    }

    let sha256_hash = Sha256::digest(group_public_key);
    let pubkey_hash = Ripemd160::new().chain_update(sha256_hash).finalize();

    let mut script = Vec::new();
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG

    Ok(script)
}

/// Bitcoin chain handler implementation
pub struct BitcoinChainHandler {
    network: String,
    group_public_key: Option<Vec<u8>>,
}

impl BitcoinChainHandler {
    pub fn new(network: String) -> Self {
        Self {
            network,
            group_public_key: None,
        }
    }

    pub fn set_group_public_key(&mut self, group_key: Vec<u8>) {
        self.group_public_key = Some(group_key);
    }
}

impl ChainHandler for BitcoinChainHandler {
    fn chain_type(&self) -> &'static str {
        "bitcoin"
    }

    fn create_transaction_bytes(&self, transaction: &ChainTransaction) -> Result<Vec<u8>> {
        match transaction {
            ChainTransaction::Bitcoin(btc_tx) => {
                let sorted_inputs = sorted_inputs(&btc_tx.inputs);
                let sorted_outputs = sorted_outputs(&btc_tx.outputs);

                let first_input = sorted_inputs
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("Bitcoin transaction has no inputs"))?;

                let sighash_all: u32 = 1;

                if let Some(witness_utxo) = &first_input.witness_utxo {
                    use sha2::{Digest, Sha256};

                    let dbl_sha256 = |data: &[u8]| -> Vec<u8> {
                        let hash1 = Sha256::digest(data);
                        let hash2 = Sha256::digest(hash1);
                        hash2.to_vec()
                    };

                    let mut prevouts = Vec::new();
                    for inp in &sorted_inputs {
                        let mut txid = hex::decode(&inp.txid)
                            .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
                        txid.reverse();
                        prevouts.extend_from_slice(&txid);
                        prevouts.extend_from_slice(&inp.vout.to_le_bytes());
                    }
                    let hash_prevouts = dbl_sha256(&prevouts);

                    let mut sequences = Vec::new();
                    for inp in &sorted_inputs {
                        sequences.extend_from_slice(&inp.sequence.to_le_bytes());
                    }
                    let hash_sequence = dbl_sha256(&sequences);

                    let mut outs = Vec::new();
                    for out in &sorted_outputs {
                        outs.extend_from_slice(&out.value.to_le_bytes());
                        outs.extend_from_slice(&encode_varint(out.script_pubkey.len() as u64));
                        outs.extend_from_slice(&out.script_pubkey);
                    }
                    let hash_outputs = dbl_sha256(&outs);

                    let script_code = if witness_utxo.script_pubkey.len() == 22
                        && witness_utxo.script_pubkey[0] == 0x00
                        && witness_utxo.script_pubkey[1] == 0x14
                    {
                        let pubkey_hash = &witness_utxo.script_pubkey[2..];
                        let mut script = Vec::new();
                        script.push(0x76);
                        script.push(0xa9);
                        script.push(0x14);
                        script.extend_from_slice(pubkey_hash);
                        script.push(0x88);
                        script.push(0xac);
                        script
                    } else {
                        witness_utxo.script_pubkey.clone()
                    };

                    let mut preimage = Vec::new();
                    preimage.extend_from_slice(&btc_tx.version.to_le_bytes());
                    preimage.extend_from_slice(&hash_prevouts);
                    preimage.extend_from_slice(&hash_sequence);

                    let mut txid = hex::decode(&first_input.txid)
                        .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
                    txid.reverse();
                    preimage.extend_from_slice(&txid);
                    preimage.extend_from_slice(&first_input.vout.to_le_bytes());

                    preimage.extend_from_slice(&encode_varint(script_code.len() as u64));
                    preimage.extend_from_slice(&script_code);
                    preimage.extend_from_slice(&witness_utxo.value.to_le_bytes());
                    preimage.extend_from_slice(&first_input.sequence.to_le_bytes());
                    preimage.extend_from_slice(&hash_outputs);
                    preimage.extend_from_slice(&btc_tx.lock_time.to_le_bytes());
                    preimage.extend_from_slice(&sighash_all.to_le_bytes());

                    Ok(preimage)
                } else {
                    let mut tx_bytes = Vec::new();
                    tx_bytes.extend_from_slice(&btc_tx.version.to_le_bytes());
                    tx_bytes.extend_from_slice(&encode_varint(sorted_inputs.len() as u64));

                    for (i, input) in sorted_inputs.iter().enumerate() {
                        let mut txid = hex::decode(&input.txid)
                            .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
                        txid.reverse();
                        tx_bytes.extend_from_slice(&txid);

                        tx_bytes.extend_from_slice(&input.vout.to_le_bytes());

                        if i == 0 {
                            if let Some(ref group_key) = self.group_public_key {
                                let script_pubkey = create_p2pkh_script_for_signing(group_key)?;
                                tx_bytes
                                    .extend_from_slice(&encode_varint(script_pubkey.len() as u64));
                                tx_bytes.extend_from_slice(&script_pubkey);
                            } else {
                                return Err(anyhow::anyhow!(
                                    "Group public key not set for Bitcoin signing"
                                ));
                            }
                        } else {
                            tx_bytes.push(0x00);
                        }

                        tx_bytes.extend_from_slice(&input.sequence.to_le_bytes());
                    }

                    tx_bytes.extend_from_slice(&encode_varint(sorted_outputs.len() as u64));
                    for out in &sorted_outputs {
                        tx_bytes.extend_from_slice(&out.value.to_le_bytes());
                        tx_bytes.extend_from_slice(&encode_varint(out.script_pubkey.len() as u64));
                        tx_bytes.extend_from_slice(&out.script_pubkey);
                    }

                    tx_bytes.extend_from_slice(&btc_tx.lock_time.to_le_bytes());
                    tx_bytes.extend_from_slice(&sighash_all.to_le_bytes());

                    Ok(tx_bytes)
                }
            }
            _ => Err(anyhow::anyhow!(
                "Invalid transaction type for Bitcoin handler"
            )),
        }
    }

    fn create_transaction_bytes_contract(&self, transaction: &ChainTransaction) -> Result<Vec<u8>> {
        match transaction {
            ChainTransaction::Tics(eth_tx) => {
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
                        eth_tx,
                    ))
                }
            }
            _ => Err(anyhow::anyhow!(
                "Invalid transaction type for Bitcoin handler"
            )),
        }
    }

    fn create_signature(
        &self,
        signature_data: &[u8],
        _recovery_id: u8,
        _transaction: &ChainTransaction,
    ) -> Result<ChainSignature> {
        if signature_data.len() != 64 {
            return Err(anyhow::anyhow!(
                "Invalid signature length for Bitcoin: expected 64 bytes, got {}",
                signature_data.len()
            ));
        }

        let r = &signature_data[0..32];
        let s = &signature_data[32..64];

        let mut der_sig = Vec::new();
        der_sig.push(0x30);

        let length_pos = der_sig.len();
        der_sig.push(0x00);

        der_sig.push(0x02);
        if r[0] & 0x80 != 0 {
            der_sig.push((r.len() + 1) as u8);
            der_sig.push(0x00);
        } else {
            der_sig.push(r.len() as u8);
        }
        der_sig.extend_from_slice(r);

        der_sig.push(0x02);
        if s[0] & 0x80 != 0 {
            der_sig.push((s.len() + 1) as u8);
            der_sig.push(0x00);
        } else {
            der_sig.push(s.len() as u8);
        }
        der_sig.extend_from_slice(s);

        let content_length = der_sig.len() - 2;
        der_sig[length_pos] = content_length as u8;

        der_sig.push(0x01);

        Ok(ChainSignature::Bitcoin(BitcoinSignature {
            signature: der_sig,
            sighash_type: 0x01,
        }))
    }

    fn verify_signature(
        &self,
        transaction: &ChainTransaction,
        signature: &ChainSignature,
        public_key: &[u8],
    ) -> Result<bool> {
        match (transaction, signature) {
            (ChainTransaction::Bitcoin(_), ChainSignature::Bitcoin(btc_sig)) => {
                if btc_sig.signature.len() < 8 {
                    return Ok(false);
                }

                if public_key.len() != 33 && public_key.len() != 65 {
                    return Ok(false);
                }

                tracing::warn!("Bitcoin signature verification not fully implemented - returning true for basic validation");
                Ok(true)
            }
            _ => Err(anyhow::anyhow!(
                "Mismatched transaction and signature types"
            )),
        }
    }

    fn from_dummy_transaction(&self, dummy_tx: &DummyTransaction) -> Result<ChainTransaction> {
        tracing::warn!(
            "Converting DummyTransaction to Bitcoin transaction - this creates an invalid placeholder"
        );

        let bitcoin_tx = BitcoinTransaction {
            inputs: vec![],
            outputs: vec![],
            version: 2,
            lock_time: 0,
            witness: None,
        };

        tracing::info!(
            "DummyTransaction details: to={}, value={}, chain_id={}",
            dummy_tx.to,
            dummy_tx.value,
            dummy_tx.chain_id
        );

        Ok(ChainTransaction::Bitcoin(bitcoin_tx))
    }

    fn get_chain_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("network".to_string(), self.network.clone());
        params.insert("signature_type".to_string(), "ECDSA".to_string());
        params
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
