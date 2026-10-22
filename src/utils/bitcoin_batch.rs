use crate::signing::SigningNode;
use crate::types::{
    BitcoinInput, BitcoinOutput, BitcoinTransaction, BitcoinUtxo, BitcoinWitness,
    BitcoinWitnessInput, BitcoinWitnessUtxo, SpendKind,
};
use crate::utils::transaction::{create_bitcoin_script_pubkey, DUST_LIMIT_SATS};
use secp256k1::ecdsa::RecoverableSignature;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum BatchTxError {
    #[error("no outputs provided for batch transaction")]
    NoOutputs,
    #[error("invalid recipient address: {0}")]
    InvalidAddress(String),
    #[error("unsupported address type: {0}")]
    UnsupportedAddressType(String),
    #[error("recipient amount {amount} sats is below dust limit {dust_limit}")]
    DustRecipient { amount: u64, dust_limit: u64 },
    #[error("insufficient funds: available={available}, required={required}")]
    InsufficientFunds { available: u64, required: u64 },
    #[error("missing script_pubkey for input {index}")]
    MissingScriptPubKey { index: usize },
    #[error("signature count mismatch: expected {expected}, got {actual}")]
    SignatureCountMismatch { expected: usize, actual: usize },
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("bitcoin hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type BatchResult<T> = Result<T, BatchTxError>;

#[derive(Debug, Clone)]
pub struct BatchPolicy {
    pub spend_kind: SpendKind,
    pub dust_limit: u64,
    pub base_vbytes: u64,
    pub input_vbytes: u64,
    pub output_vbytes: u64,
    pub rbf_sequence: u32,
}

impl Default for BatchPolicy {
    fn default() -> Self {
        Self {
            spend_kind: SpendKind::P2PKH,
            dust_limit: DUST_LIMIT_SATS,
            base_vbytes: 100,
            input_vbytes: 150,
            output_vbytes: 31,
            rbf_sequence: 0xffff_fffe,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchRecipient {
    pub address: String,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct BatchSelection {
    pub selected_utxos: Vec<BitcoinUtxo>,
    pub total_value: u64,
    pub fee: u64,
    pub change: u64,
    pub change_output: bool,
    pub vbytes: u64,
}

#[derive(Debug, Clone)]
pub struct BatchSigningInfo {
    pub prev_script_pubkeys: Vec<Vec<u8>>,
    pub input_values: Vec<u64>,
    pub pubkey33: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BatchFinalizedTx {
    pub raw_tx: Vec<u8>,
    pub txid: [u8; 32],
    pub wtxid: Option<[u8; 32]>,
}

pub trait BatchInputSigner {
    fn sign_digest(&self, digest: &[u8; 32]) -> BatchResult<RecoverableSignature>;
}

pub fn select_utxos_for_batch(
    available_utxos: &[BitcoinUtxo],
    target_outputs: &[BatchRecipient],
    fee_rate_sat_vb: u64,
    policy: &BatchPolicy,
) -> BatchResult<BatchSelection> {
    if target_outputs.is_empty() {
        return Err(BatchTxError::NoOutputs);
    }

    let mut total_output_amount = 0u64;
    for output in target_outputs {
        if output.value < policy.dust_limit {
            return Err(BatchTxError::DustRecipient {
                amount: output.value,
                dust_limit: policy.dust_limit,
            });
        }
        total_output_amount = total_output_amount.saturating_add(output.value);
    }

    let mut confirmed_utxos: Vec<_> = available_utxos
        .iter()
        .filter(|utxo| {
            if !utxo.status.confirmed {
                debug!(
                    "🔍 [BTC_BATCH] Skipping unconfirmed UTXO: {}:{}",
                    utxo.txid, utxo.vout
                );
                return false;
            }
            if utxo.txid.len() != 64 {
                warn!(
                    "⚠️ [BTC_BATCH] Skipping UTXO with invalid txid length: {}",
                    utxo.txid
                );
                return false;
            }
            if utxo.value == 0 {
                warn!(
                    "⚠️ [BTC_BATCH] Skipping zero-value UTXO: {}:{}",
                    utxo.txid, utxo.vout
                );
                return false;
            }
            true
        })
        .cloned()
        .collect();

    if confirmed_utxos.is_empty() {
        return Err(BatchTxError::InsufficientFunds {
            available: 0,
            required: total_output_amount,
        });
    }

    let outputs_with_change = target_outputs.len() + 1;
    let mut selected = Vec::new();
    let mut total_input_value = 0u64;
    let mut vbytes = policy.base_vbytes + policy.output_vbytes * outputs_with_change as u64;

    for utxo in confirmed_utxos.drain(..) {
        total_input_value = total_input_value.saturating_add(utxo.value);
        selected.push(utxo);
        vbytes = policy.base_vbytes
            + policy.output_vbytes * outputs_with_change as u64
            + policy.input_vbytes * selected.len() as u64;

        let fee = compute_batch_fee(vbytes, fee_rate_sat_vb, policy);
        if total_input_value >= total_output_amount.saturating_add(fee) {
            break;
        }
    }

    let fee = compute_batch_fee(vbytes, fee_rate_sat_vb, policy);
    let required = total_output_amount.saturating_add(fee);
    if total_input_value < required {
        return Err(BatchTxError::InsufficientFunds {
            available: total_input_value,
            required,
        });
    }

    let mut change = total_input_value.saturating_sub(required);
    let change_output = change > policy.dust_limit;
    if !change_output {
        change = 0;
    }

    let final_fee = if change_output {
        fee
    } else {
        total_input_value.saturating_sub(total_output_amount)
    };

    info!(
        "🔍 [BTC_BATCH] Selected {} UTXOs (total {} sats). outputs={}, fee={}, change={}, change_output={}",
        selected.len(),
        total_input_value,
        target_outputs.len(),
        final_fee,
        change,
        change_output
    );

    Ok(BatchSelection {
        selected_utxos: selected,
        total_value: total_input_value,
        fee: final_fee,
        change,
        change_output,
        vbytes,
    })
}

pub fn estimate_batch_vbytes(
    selected_utxos: &[BitcoinUtxo],
    outputs: usize,
    _address_type: SpendKind,
    policy: &BatchPolicy,
) -> u64 {
    policy.base_vbytes
        + policy.input_vbytes * selected_utxos.len() as u64
        + policy.output_vbytes * outputs as u64
}

pub fn compute_batch_fee(vbytes: u64, fee_rate_sat_vb: u64, _policy: &BatchPolicy) -> u64 {
    vbytes.saturating_mul(fee_rate_sat_vb)
}

pub fn build_batch_unsigned_tx(
    selection: &BatchSelection,
    outputs: &[BatchRecipient],
    change_address: &str,
    policy: &BatchPolicy,
) -> BatchResult<BitcoinTransaction> {
    // Build the change script-pubkey directly — create_bitcoin_script_pubkey enforces the runtime
    // network for any address type (P2PKH, P2WPKH, P2SH, P2WSH, P2TR, …), so no separate
    // classify_address / spend_kind check is needed here.
    let change_spk = create_bitcoin_script_pubkey(change_address)
        .map_err(|e| BatchTxError::InvalidAddress(e.to_string()))?;

    let inputs: Vec<BitcoinInput> = selection
        .selected_utxos
        .iter()
        .map(|utxo| BitcoinInput {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            script_sig: vec![],
            sequence: policy.rbf_sequence,
            witness_utxo: Some(BitcoinWitnessUtxo {
                value: utxo.value,
                script_pubkey: change_spk.clone(),
            }),
        })
        .collect();

    let mut tx_outputs = Vec::with_capacity(outputs.len() + 1);
    for output in outputs {
        let spk = create_bitcoin_script_pubkey(&output.address)
            .map_err(|e| BatchTxError::InvalidAddress(e.to_string()))?;
        tx_outputs.push(BitcoinOutput {
            value: output.value,
            script_pubkey: spk,
        });
    }

    if selection.change_output {
        tx_outputs.push(BitcoinOutput {
            value: selection.change,
            script_pubkey: change_spk.clone(),
        });
    }

    let (version, witness) = match policy.spend_kind {
        SpendKind::P2WPKH => (
            2,
            Some(BitcoinWitness {
                inputs: (0..inputs.len())
                    .map(|_| BitcoinWitnessInput { stack: vec![] })
                    .collect(),
            }),
        ),
        SpendKind::P2PKH => (1, None),
    };

    info!(
        "🧾 [BTC_BATCH] Built unsigned tx: inputs={}, outputs={}, change_output={}",
        inputs.len(),
        tx_outputs.len(),
        selection.change_output
    );

    Ok(BitcoinTransaction {
        inputs,
        outputs: tx_outputs,
        version,
        lock_time: 0,
        witness,
    })
}

pub fn create_sighashes_for_inputs(
    unsigned_tx: &BitcoinTransaction,
    input_info: &BatchSigningInfo,
    policy: &BatchPolicy,
) -> BatchResult<Vec<[u8; 32]>> {
    if policy.spend_kind != SpendKind::P2PKH {
        return Err(BatchTxError::UnsupportedAddressType(format!(
            "{:?}",
            policy.spend_kind
        )));
    }

    if input_info.prev_script_pubkeys.len() != unsigned_tx.inputs.len() {
        return Err(BatchTxError::MissingScriptPubKey {
            index: input_info.prev_script_pubkeys.len(),
        });
    }

    let mut digests = Vec::with_capacity(unsigned_tx.inputs.len());
    for (idx, prev_spk) in input_info.prev_script_pubkeys.iter().enumerate() {
        let digest = compute_legacy_sighash_all_p2pkh(unsigned_tx, idx, prev_spk)?;
        digests.push(digest);
    }

    info!(
        "🔐 [BTC_BATCH] Created {} sighashes for batch inputs",
        digests.len()
    );

    Ok(digests)
}

pub fn mpc_sign_batch_inputs<S: BatchInputSigner>(
    digests: &[[u8; 32]],
    signer: &S,
) -> BatchResult<Vec<RecoverableSignature>> {
    let mut signatures = Vec::with_capacity(digests.len());
    for digest in digests {
        let sig = signer.sign_digest(digest)?;
        signatures.push(sig);
    }

    Ok(signatures)
}

pub fn attach_signatures_and_finalize(
    unsigned_tx: BitcoinTransaction,
    signatures: &[RecoverableSignature],
    input_info: &BatchSigningInfo,
    policy: &BatchPolicy,
) -> BatchResult<BatchFinalizedTx> {
    if signatures.len() != unsigned_tx.inputs.len() {
        return Err(BatchTxError::SignatureCountMismatch {
            expected: unsigned_tx.inputs.len(),
            actual: signatures.len(),
        });
    }

    if input_info.pubkey33.len() != 33 {
        return Err(BatchTxError::UnsupportedAddressType(
            "pubkey must be 33 bytes".to_string(),
        ));
    }

    let per_input: Vec<(usize, RecoverableSignature)> =
        signatures.iter().cloned().enumerate().collect();

    let (raw_tx, txid, wtxid) = SigningNode::finalize_and_serialize_tx(
        unsigned_tx,
        policy.spend_kind,
        &per_input,
        &input_info.pubkey33,
    )
    .map_err(|e| BatchTxError::InvalidAddress(e.to_string()))?;

    info!(
        "✅ [BTC_BATCH] Finalized batch transaction: txid={}",
        hex::encode(txid)
    );

    Ok(BatchFinalizedTx {
        raw_tx,
        txid,
        wtxid,
    })
}

pub fn validate_batch_tx(
    final_tx: &BatchFinalizedTx,
    expected_outputs: &[BatchRecipient],
    expected_fee: u64,
    input_info: &BatchSigningInfo,
    policy: &BatchPolicy,
) -> BatchResult<()> {
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&final_tx.raw_tx)
        .map_err(|e| BatchTxError::InvalidAddress(e.to_string()))?;

    let total_input: u64 = input_info.input_values.iter().sum();
    let total_output: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let actual_fee = total_input.saturating_sub(total_output);

    if actual_fee != expected_fee {
        warn!(
            "⚠️ [BTC_BATCH] Fee mismatch: expected {}, actual {}",
            expected_fee, actual_fee
        );
        return Err(BatchTxError::InsufficientFunds {
            available: total_input,
            required: total_output.saturating_add(expected_fee),
        });
    }

    for output in expected_outputs {
        let expected_spk = create_bitcoin_script_pubkey(&output.address)
            .map_err(|e| BatchTxError::InvalidAddress(e.to_string()))?;
        let matched = tx.output.iter().any(|tx_out| {
            tx_out.value.to_sat() == output.value && tx_out.script_pubkey.to_bytes() == expected_spk
        });
        if !matched {
            return Err(BatchTxError::InvalidAddress(format!(
                "missing expected output {}:{}",
                output.address, output.value
            )));
        }
    }

    let change_value = total_input
        .saturating_sub(total_output)
        .saturating_sub(expected_fee);
    let expects_change = change_value > policy.dust_limit;
    let expected_total_outputs = expected_outputs.len() + usize::from(expects_change);
    if tx.output.len() != expected_total_outputs {
        return Err(BatchTxError::InvalidAddress(format!(
            "unexpected output count: got {}, expected {}",
            tx.output.len(),
            expected_total_outputs
        )));
    }

    Ok(())
}

pub fn build_and_sign_btc_batch_tx<S: BatchInputSigner>(
    available_utxos: &[BitcoinUtxo],
    outputs: &[BatchRecipient],
    change_address: &str,
    fee_rate_sat_vb: u64,
    signer_pubkey: &[u8],
    policy: &BatchPolicy,
    signer: &S,
) -> BatchResult<(BitcoinTransaction, BatchFinalizedTx)> {
    let selection = select_utxos_for_batch(available_utxos, outputs, fee_rate_sat_vb, policy)?;
    let unsigned_tx = build_batch_unsigned_tx(&selection, outputs, change_address, policy)?;

    // Construct input info for signing
    // For P2PKH, all inputs share the same script_pubkey derived from the signer's pubkey
    let pubkey_obj = bitcoin::key::CompressedPublicKey::from_slice(signer_pubkey)
        .map_err(|_| BatchTxError::UnsupportedAddressType("invalid pubkey".to_string()))?;
    let address = bitcoin::Address::p2pkh(pubkey_obj, bitcoin::Network::Bitcoin); // Network irrelevant for spk
    let signer_spk = address.script_pubkey().to_bytes();

    let input_info = BatchSigningInfo {
        prev_script_pubkeys: vec![signer_spk; unsigned_tx.inputs.len()],
        input_values: selection.selected_utxos.iter().map(|u| u.value).collect(),
        pubkey33: signer_pubkey.to_vec(),
    };

    let digests = create_sighashes_for_inputs(&unsigned_tx, &input_info, policy)?;
    let signatures = mpc_sign_batch_inputs(&digests, signer)?;
    let finalized =
        attach_signatures_and_finalize(unsigned_tx.clone(), &signatures, &input_info, policy)?;
    Ok((unsigned_tx, finalized))
}

fn compute_legacy_sighash_all_p2pkh(
    tx: &BitcoinTransaction,
    idx: usize,
    prev_script_pubkey: &[u8],
) -> BatchResult<[u8; 32]> {
    let mut pre = Vec::new();
    pre.extend_from_slice(&tx.version.to_le_bytes());

    SigningNode::push_varint(&mut pre, tx.inputs.len() as u64);
    for (j, inp) in tx.inputs.iter().enumerate() {
        let mut txid = hex::decode(&inp.txid)?;
        txid.reverse();
        pre.extend_from_slice(&txid);
        pre.extend_from_slice(&inp.vout.to_le_bytes());

        if j == idx {
            SigningNode::push_varint(&mut pre, prev_script_pubkey.len() as u64);
            pre.extend_from_slice(prev_script_pubkey);
        } else {
            SigningNode::push_varint(&mut pre, 0);
        }
        pre.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    SigningNode::push_varint(&mut pre, tx.outputs.len() as u64);
    for out in &tx.outputs {
        pre.extend_from_slice(&out.value.to_le_bytes());
        SigningNode::push_varint(&mut pre, out.script_pubkey.len() as u64);
        pre.extend_from_slice(&out.script_pubkey);
    }

    pre.extend_from_slice(&tx.lock_time.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes());

    Ok(SigningNode::dsha256(&pre))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::script::Instruction;
    use bitcoin::Address;
    use secp256k1::{Message, Secp256k1, SecretKey};

    fn ensure_testnet_network_type() {
        std::env::set_var(crate::types::NETWORK_ENV_KEY, "testnet");
        let _ = crate::types::init_network_type_from_env();
    }

    struct LocalSigner {
        secp: Secp256k1<secp256k1::All>,
        secret_key: SecretKey,
    }

    impl BatchInputSigner for LocalSigner {
        fn sign_digest(&self, digest: &[u8; 32]) -> BatchResult<RecoverableSignature> {
            let msg = Message::from_digest_slice(digest)?;
            Ok(self.secp.sign_ecdsa_recoverable(&msg, &self.secret_key))
        }
    }

    fn make_test_address(secret_key: &SecretKey) -> (String, Vec<u8>) {
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
        // Use bytes to bridge versions
        let compressed =
            CompressedPublicKey::from_slice(&pubkey.serialize()).expect("compressed pubkey");
        let address = Address::p2pkh(compressed, bitcoin::Network::Testnet);
        (address.to_string(), pubkey.serialize().to_vec())
    }

    fn sample_utxo(txid_suffix: u8, value: u64) -> BitcoinUtxo {
        let txid = format!("{:02x}", txid_suffix).repeat(32);
        BitcoinUtxo {
            txid,
            vout: 0,
            value,
            status: crate::types::UtxoStatus {
                confirmed: true,
                block_height: Some(1),
                block_hash: None,
                block_time: None,
            },
        }
    }

    fn assert_p2pkh_signatures(
        raw_tx: &[u8],
        digests: &[[u8; 32]],
        pubkey33: &[u8],
    ) -> BatchResult<()> {
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(raw_tx)
            .map_err(|e| BatchTxError::InvalidAddress(e.to_string()))?;
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_slice(pubkey33)?;

        for (idx, input) in tx.input.iter().enumerate() {
            let mut pushes = Vec::new();
            for instr in input.script_sig.instructions() {
                match instr.map_err(|e| BatchTxError::InvalidAddress(e.to_string()))? {
                    Instruction::PushBytes(bytes) => pushes.push(bytes.as_bytes().to_vec()),
                    _ => {}
                }
            }

            assert_eq!(pushes.len(), 2, "scriptSig should have sig + pubkey");
            assert_eq!(pushes[1], pubkey33);

            let sig_with_hashtype = &pushes[0];
            assert!(sig_with_hashtype.len() > 1);
            let sig_der = &sig_with_hashtype[..sig_with_hashtype.len() - 1];
            let sig = secp256k1::ecdsa::Signature::from_der(sig_der)?;
            let msg = Message::from_digest_slice(&digests[idx])?;
            secp.verify_ecdsa(&msg, &sig, &pubkey)?;
        }

        Ok(())
    }

    #[test]
    fn test_batch_many_inputs_single_recipient_with_change() {
        ensure_testnet_network_type();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[7u8; 32]).expect("secret key");
        let (from_address, pubkey33) = make_test_address(&secret_key);
        let (_, _) = make_test_address(&SecretKey::from_slice(&[9u8; 32]).unwrap());
        let (recipient_address, _) = make_test_address(&SecretKey::from_slice(&[9u8; 32]).unwrap());

        let utxos = vec![
            sample_utxo(1, 20_000),
            sample_utxo(2, 15_000),
            sample_utxo(3, 10_000),
        ];

        let outputs = vec![BatchRecipient {
            address: recipient_address,
            value: 35_000,
        }];

        let policy = BatchPolicy::default();
        let signer = LocalSigner { secp, secret_key };

        let (unsigned_tx, finalized) = build_and_sign_btc_batch_tx(
            &utxos,
            &outputs,
            &from_address,
            1,
            &pubkey33,
            &policy,
            &signer,
        )
        .expect("build and sign");

        assert_eq!(unsigned_tx.inputs.len(), 3);

        // Re-derive digests
        let signer_spk = bitcoin::Address::p2pkh(
            CompressedPublicKey::from_slice(&pubkey33).unwrap(),
            bitcoin::Network::Bitcoin,
        )
        .script_pubkey()
        .to_bytes();
        let input_info = BatchSigningInfo {
            prev_script_pubkeys: vec![signer_spk; 3],
            input_values: vec![],
            pubkey33: pubkey33.clone(),
        };
        let digests = create_sighashes_for_inputs(&unsigned_tx, &input_info, &policy).unwrap();
        assert_p2pkh_signatures(&finalized.raw_tx, &digests, &pubkey33).unwrap();
    }

    #[test]
    fn test_batch_many_inputs_multi_recipient_no_change() {
        ensure_testnet_network_type();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[11u8; 32]).expect("secret key");
        let (from_address, pubkey33) = make_test_address(&secret_key);
        let (recipient_one, _) = make_test_address(&SecretKey::from_slice(&[13u8; 32]).unwrap());
        let (recipient_two, _) = make_test_address(&SecretKey::from_slice(&[17u8; 32]).unwrap());

        let utxos = vec![sample_utxo(5, 25_000), sample_utxo(6, 25_000)];

        let outputs = vec![
            BatchRecipient {
                address: recipient_one,
                value: 20_000,
            },
            BatchRecipient {
                address: recipient_two,
                value: 28_880,
            },
        ];

        let policy = BatchPolicy::default();
        let signer = LocalSigner { secp, secret_key };

        let (unsigned_tx, finalized) = build_and_sign_btc_batch_tx(
            &utxos,
            &outputs,
            &from_address,
            1,
            &pubkey33, // New API
            &policy,
            &signer,
        )
        .expect("build and sign");

        assert_eq!(unsigned_tx.inputs.len(), 2);

        // Re-derive digests
        let signer_spk = bitcoin::Address::p2pkh(
            CompressedPublicKey::from_slice(&pubkey33).unwrap(),
            bitcoin::Network::Bitcoin,
        )
        .script_pubkey()
        .to_bytes();
        let input_info = BatchSigningInfo {
            prev_script_pubkeys: vec![signer_spk; 2],
            input_values: vec![],
            pubkey33: pubkey33.clone(),
        };
        let digests = create_sighashes_for_inputs(&unsigned_tx, &input_info, &policy).unwrap();

        assert_p2pkh_signatures(&finalized.raw_tx, &digests, &pubkey33).unwrap();
    }
}
