use anyhow::{anyhow, bail, Result};
use bitcoin::{
    hashes::msg_digest::Hash as _,
    hashes::Hash, // For as_byte_array
    secp256k1::{self, ecdsa::RecoverableSignature, Secp256k1},
    Address,
    Amount,
    OutPoint,
    PublicKey,
    ScriptBuf,
    Sequence,
    Transaction,
    TxIn,
    TxOut,
    Txid,
    Witness,
};
use std::str::FromStr;

/// UTXO representation for batch selection
#[derive(Debug, Clone)]
pub struct BatchUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>, // Needed for signing
}

/// Output target for batch transaction
#[derive(Debug, Clone)]
pub struct BatchOutput {
    pub address: String,
    pub amount: u64,
}

/// Policy for batch transaction construction (fee rates, dust, etc.)
#[derive(Debug, Clone)]
pub struct BatchPolicy {
    pub fee_rate: u64, // sats/vbyte (conceptually, though we might use fixed estimates like script)
    pub dust_threshold: u64,
    pub change_address: String,
}

impl Default for BatchPolicy {
    fn default() -> Self {
        Self {
            fee_rate: 1, // Default to 1 sat/byte if not specified
            dust_threshold: 546,
            change_address: "".to_string(), // Must be set
        }
    }
}

/// Result of UTXO selection
#[derive(Debug)]
pub struct SelectedUtxos {
    pub utxos: Vec<BatchUtxo>,
    pub total_input_value: u64,
    pub fee: u64,
    pub change: u64,
}

/// Select UTXOs using the strategy from the reference script:
/// "Iterate and accumulate until total_input >= total_output + current_fee_estimate"
///
/// Reference script fee math:
/// est_fee = base_overhead + (est_fee_per_output * count) + (est_fee_per_input * input_count)
///
/// Adjustments for P2PKH (Legacy):
/// Input (P2PKH): ~148 bytes (Script: 150) -> We'll use 150 to be safe/consistent with script.
/// Output (P2PKH): ~34 bytes (Script: 31) -> We'll use 34.
/// Base Overhead: ~10 bytes (Script: 100) -> We'll use 100 to be safe.
pub fn select_utxos_for_batch(
    available_utxos: &[BatchUtxo],
    target_outputs: &[BatchOutput],
    policy: &BatchPolicy,
) -> Result<SelectedUtxos> {
    let total_output_amount: u64 = target_outputs.iter().map(|o| o.amount).sum();
    let output_count = target_outputs.len();

    // Constants adapted from reference script but tuned for P2PKH if needed.
    // Script used: input=150, output=31, overhead=100.
    // We stick to 150 for input (conservative for P2PKH).
    // We bump output to 34 (P2PKH is 34).
    let estimated_fee_per_input = 150;
    let estimated_fee_per_output = 34;
    let base_overhead = 100;

    let mut selected = Vec::new();
    let mut total_input_value = 0;

    // Initial fee estimate with 0 inputs
    let initial_fee_overhead = base_overhead + (estimated_fee_per_output * output_count as u64);
    let mut current_fee_estimate = initial_fee_overhead;

    // Greedy/FIFO selection as per script
    for utxo in available_utxos {
        selected.push(utxo.clone());
        total_input_value += utxo.value;
        current_fee_estimate += estimated_fee_per_input;

        if total_input_value >= total_output_amount + current_fee_estimate {
            break;
        }
    }

    // Check sufficiency
    if total_input_value < total_output_amount + current_fee_estimate {
        bail!(
            "Insufficient funds. Have: {}, Need: {} (Amount: {} + Fee: {})",
            total_input_value,
            total_output_amount + current_fee_estimate,
            total_output_amount,
            current_fee_estimate
        );
    }

    // Calculate change
    let total_required = total_output_amount + current_fee_estimate;
    let change = total_input_value.saturating_sub(total_required);

    // If change is effectively dust, burn it to fee (script logic implicitly does this by not adding output)
    // The script says: if change > 546 { add_output }
    // If we don't add output, the fee increases by the change amount.
    // Also if we add change output, we increase the transaction size!
    // The reference script does NOT loop back to increase fee if change output is added.
    // It calculates fee based on inputs chosen and *then* adds change if > dust.
    // This implies `current_fee_estimate` assumes *no change output cost* initially?
    // Wait, script: `current_fee_estimate = base + outputs*31`. It does NOT include change output cost in estimate loop.
    // Then: `if change > 546 { tx_out.push(...) }`.
    // So the fee paid is `total_in - total_out - change_out`.
    // If change_out is added, `tx_size` increases.
    // If we want to be exact, we should account for change output cost.
    // BUT "Exact match behavior" request -> We follow the script.
    // Script logic:
    // 1. Select inputs covering (out + fee_no_change).
    // 2. Calc change = in - (out + fee_no_change).
    // 3. If change > dust, add change output.
    // This means the effective fee rate drops slightly if change is added (size increases, fee stays same),
    // or we might underpay?
    // Actually, if we add a change output, the transaction is bigger.
    // If the fee was calculated for N outputs, and we have N+1, we might be under the fee rate.
    // However, the script has `base_overhead = 100`. A P2PKH output is 34 bytes.
    // 100 bytes overhead covers the change output easily. Safe.

    let final_fee = if change > policy.dust_threshold {
        // We will output change, so fee is exactly what we estimated
        current_fee_estimate
    } else {
        // We will NOT output change, so the "change" amount is added to fee
        current_fee_estimate + change
    };

    let effective_change = if change > policy.dust_threshold {
        change
    } else {
        0
    };

    Ok(SelectedUtxos {
        utxos: selected,
        total_input_value,
        fee: final_fee,
        change: effective_change,
    })
}

/// Build the unsigned Bitcoin transaction
pub fn build_batch_unsigned_tx(
    selected: &SelectedUtxos,
    target_outputs: &[BatchOutput],
    policy: &BatchPolicy,
) -> Result<Transaction> {
    let mut inputs = Vec::with_capacity(selected.utxos.len());
    for utxo in &selected.utxos {
        inputs.push(TxIn {
            previous_output: OutPoint::new(
                Txid::from_str(&utxo.txid)
                    .map_err(|e| anyhow!("Invalid TxID {}: {}", utxo.txid, e))?,
                utxo.vout,
            ),
            script_sig: ScriptBuf::new(), // Empty for signing
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // Match script: ENABLE_RBF_NO_LOCKTIME
            witness: Witness::new(),      // Legacy P2PKH -> Empty witness
        });
    }

    let mut outputs = Vec::with_capacity(target_outputs.len() + 1);
    for out in target_outputs {
        let addr = Address::from_str(&out.address)
            .map_err(|e| anyhow!("Invalid address {}: {}", out.address, e))?
            .assume_checked(); // We rely on caller validation or parse failure
        outputs.push(TxOut {
            value: Amount::from_sat(out.amount),
            script_pubkey: addr.script_pubkey(),
        });
    }

    // Change output
    if selected.change > 0 {
        if policy.change_address.is_empty() {
            bail!("Change exists but no change address provided in policy");
        }
        let change_addr = Address::from_str(&policy.change_address)
            .map_err(|e| anyhow!("Invalid change address: {}", e))?
            .assume_checked();

        outputs.push(TxOut {
            value: Amount::from_sat(selected.change),
            script_pubkey: change_addr.script_pubkey(),
        });
    }

    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO, // Match script: Version::TWO
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO, // Match script: ZERO
        input: inputs,
        output: outputs,
    })
}

/// Create legacy SIGHASH_ALL digests for all inputs
pub fn create_sighashes_for_inputs(
    tx: &Transaction,
    selected_utxos: &[BatchUtxo],
) -> Result<Vec<[u8; 32]>> {
    if tx.input.len() != selected_utxos.len() {
        bail!(
            "Tx input count {} does not match selected utxo count {}",
            tx.input.len(),
            selected_utxos.len()
        );
    }

    let mut sighashes = Vec::with_capacity(tx.input.len());
    let sighash_type = 1u32; // SIGHASH_ALL

    for i in 0..tx.input.len() {
        let script_pubkey = &selected_utxos[i].script_pubkey;

        // Manual legacy sighash construction or use standard library ?
        // The codebase seems to do manual construction in `chains/bitcoin.rs` `compute_legacy_sighash_all_p2pkh`.
        // We can reuse that logic if accessible, or implement standard legacy sighash.
        // Let's implement standard legacy sighash logic here for self-containment
        // OR better yet, use `bitcoin::sighash::SighashCache::legacy_signature_hash`.

        let script = ScriptBuf::from(script_pubkey.clone());
        let sighash = bitcoin::sighash::SighashCache::new(tx)
            .legacy_signature_hash(i, &script, sighash_type)
            .map_err(|e| anyhow!("Failed to compute sighash for input {}: {}", i, e))?;

        sighashes.push(sighash.as_byte_array().clone());
    }

    Ok(sighashes)
}

/// Finalize transaction by attaching signatures (Legacy P2PKH)
pub fn attach_signatures_and_finalize(
    mut tx: Transaction,
    signatures: &[RecoverableSignature],
    public_key: &PublicKey,
) -> Result<Transaction> {
    if tx.input.len() != signatures.len() {
        bail!(
            "Signature count {} does not match input count {}",
            signatures.len(),
            tx.input.len()
        );
    }

    let secp = Secp256k1::new();
    let pubkey_bytes = public_key.inner.serialize(); // Compressed 33 bytes

    for (i, sig) in signatures.iter().enumerate() {
        // Convert recoverable sig to DER
        let mut standard_sig = sig.to_standard();
        standard_sig.normalize_s();
        let mut sig_der = standard_sig.serialize_der().to_vec();
        sig_der.push(0x01); // SIGHASH_ALL type byte

        // Build scriptSig: <sig> <pubkey>
        let mut script_sig = ScriptBuf::new();
        let sig_push = bitcoin::script::PushBytes::from_slice(&sig_der)
            .map_err(|e| anyhow!("Failed to create PushBytes for sig: {}", e))?;
        script_sig.push_slice(sig_push);

        let pk_push = bitcoin::script::PushBytes::from_slice(&pubkey_bytes)
            .map_err(|e| anyhow!("Failed to create PushBytes for pubkey: {}", e))?;
        script_sig.push_slice(pk_push);

        tx.input[i].script_sig = script_sig;
    }

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn mock_utxo(id: u8, val: u64) -> BatchUtxo {
        // Mock P2PKH script for testing sighash
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[id; 20]);
        script.extend_from_slice(&[0x88, 0xac]);

        BatchUtxo {
            txid: format!("{:064x}", id),
            vout: 0,
            value: val,
            script_pubkey: script,
        }
    }

    #[test]
    fn test_selection_exact_no_change() {
        // Need 1000, have 1000 + estimated fee.
        // Fee est: 100(base) + 34(out) + 150(in) = 284.
        // Total need: 1284.
        // Let's provide UTXO of 1284.
        let utxos = vec![mock_utxo(1, 1284)];
        let targets = vec![BatchOutput {
            address: "tb1qXY".to_string(),
            amount: 1000,
        }];
        let policy = BatchPolicy {
            change_address: "tb1qChange".to_string(),
            ..Default::default()
        };

        let res = select_utxos_for_batch(&utxos, &targets, &policy).expect("Selection failed");

        assert_eq!(res.utxos.len(), 1);
        assert_eq!(res.fee, 284);
        assert_eq!(res.change, 0);
    }

    #[test]
    fn test_selection_with_change() {
        // Need 1000. Fee est for 1 in 1 out = 284. Total 1284.
        // Provide 2000.
        // Change = 2000 - 1284 = 716.
        // 716 > 546 (dust), so change output expected.
        let utxos = vec![mock_utxo(1, 2000)];
        let targets = vec![BatchOutput {
            address: "tb1qXY".to_string(),
            amount: 1000,
        }];
        let policy = BatchPolicy {
            change_address: "tb1qChange".to_string(),
            ..Default::default()
        };

        let res = select_utxos_for_batch(&utxos, &targets, &policy).expect("Selection failed");

        assert_eq!(res.utxos.len(), 1);
        assert_eq!(res.fee, 284);
        assert_eq!(res.change, 716);
    }

    #[test]
    fn test_selection_dust_change_burned() {
        // Need 1000. Fee est 284. Total 1284.
        // Provide 1300.
        // Change = 1300 - 1284 = 16.
        // 16 < 546. Burned to fee.
        let utxos = vec![mock_utxo(1, 1300)];
        let targets = vec![BatchOutput {
            address: "tb1qXY".to_string(),
            amount: 1000,
        }];
        let policy = BatchPolicy {
            change_address: "tb1qChange".to_string(),
            ..Default::default()
        };

        let res = select_utxos_for_batch(&utxos, &targets, &policy).expect("Selection failed");

        assert_eq!(res.utxos.len(), 1);
        assert_eq!(res.fee, 284 + 16); // 300
        assert_eq!(res.change, 0);
    }

    #[test]
    fn test_selection_multiple_inputs() {
        // Need 5000.
        // 1 Output.
        // Input cost = 150.
        // Helper: Estimate = 100 + 34 = 134 + (150 * N).
        // Utxos: 1000, 1000, 1000, 1000, 1000, 1000.
        // N=1: Need 5000+284=5284. Have 1000.
        // N=2: Need 5000+434=5434. Have 2000.
        // ...
        // N=6: Need 5000+(134+900)=6034. Have 6000. -> FAIL.
        // Wait, 6 * 1000 = 6000.
        // Fee for 6 inputs = 100 + 34 + 6*150 = 1034.
        // Total need = 6034.
        // We have 6000.
        // Insufficient.

        let utxos = vec![
            mock_utxo(1, 1000),
            mock_utxo(2, 1000),
            mock_utxo(3, 1000),
            mock_utxo(4, 1000),
            mock_utxo(5, 1000),
            mock_utxo(6, 1000),
        ];
        let targets = vec![BatchOutput {
            address: "tb1qXY".to_string(),
            amount: 5000,
        }];
        let policy = BatchPolicy {
            change_address: "tb1qChange".to_string(),
            ..Default::default()
        };

        let res = select_utxos_for_batch(&utxos, &targets, &policy);
        assert!(res.is_err()); // Correctly failed.
    }
}
