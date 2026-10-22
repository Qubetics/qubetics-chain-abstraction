use serde::{Deserialize, Serialize};

/// Fully described Bitcoin transaction with optional SegWit witness data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub inputs: Vec<BitcoinInput>,
    pub outputs: Vec<BitcoinOutput>,
    pub version: u32,
    pub lock_time: u32,
    pub witness: Option<BitcoinWitness>,
}

impl BitcoinTransaction {
    pub fn new(
        inputs: Vec<BitcoinInput>,
        outputs: Vec<BitcoinOutput>,
        version: u32,
        lock_time: u32,
        witness: Option<BitcoinWitness>,
    ) -> Self {
        Self {
            inputs,
            outputs,
            version,
            lock_time,
            witness,
        }
    }
}

/// Bitcoin transaction input description including optional witness UTXO data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinInput {
    pub txid: String,
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness_utxo: Option<BitcoinWitnessUtxo>,
}

impl BitcoinInput {
    pub fn new(
        txid: String,
        vout: u32,
        script_sig: Vec<u8>,
        sequence: u32,
        witness_utxo: Option<BitcoinWitnessUtxo>,
    ) -> Self {
        Self {
            txid,
            vout,
            script_sig,
            sequence,
            witness_utxo,
        }
    }
}

/// Bitcoin transaction output data including the serialized script_pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinOutput {
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }
}

/// SegWit witness data for the entire transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinWitness {
    pub inputs: Vec<BitcoinWitnessInput>,
}

impl BitcoinWitness {
    pub fn new(inputs: Vec<BitcoinWitnessInput>) -> Self {
        Self { inputs }
    }
}

/// Individual witness stack for a single input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinWitnessInput {
    pub stack: Vec<Vec<u8>>,
}

impl BitcoinWitnessInput {
    pub fn new(stack: Vec<Vec<u8>>) -> Self {
        Self { stack }
    }
}

/// Additional UTXO information required for SegWit signature hashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinWitnessUtxo {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinWitnessUtxo {
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }
}

/// DER-encoded Bitcoin signature plus the sighash flag used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinSignature {
    pub signature: Vec<u8>,
    pub sighash_type: u8,
}

impl BitcoinSignature {
    pub fn new(signature: Vec<u8>, sighash_type: u8) -> Self {
        Self {
            signature,
            sighash_type,
        }
    }
}

/// Classification of spend paths supported by the transaction builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendKind {
    P2PKH,
    P2WPKH,
}

/// Bitcoin UTXO structure for use across external storage/query layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

impl BitcoinUtxo {
    pub fn new(txid: String, vout: u32, value: u64, status: UtxoStatus) -> Self {
        Self {
            txid,
            vout,
            value,
            status,
        }
    }
}

/// Status information for a Bitcoin UTXO (confirmation metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

impl UtxoStatus {
    pub fn new(
        confirmed: bool,
        block_height: Option<u64>,
        block_hash: Option<String>,
        block_time: Option<u64>,
    ) -> Self {
        Self {
            confirmed,
            block_height,
            block_hash,
            block_time,
        }
    }
}
