use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::rpc_server::DummyTransaction;

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

/// Create P2PKH script_pubkey for Bitcoin signing using the actual DKG group public key
/// This should match the script of the UTXO being spent
fn create_p2pkh_script_for_signing(group_public_key: &[u8]) -> Result<Vec<u8>> {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    if group_public_key.len() != 33 {
        return Err(anyhow::anyhow!(
            "Invalid group public key length: expected 33 bytes, got {}",
            group_public_key.len()
        ));
    }

    // ✅ Create actual pubkey hash from DKG group public key
    // Bitcoin address derivation: SHA256(pubkey) -> RIPEMD160(hash) = pubkey_hash
    let sha256_hash = Sha256::digest(group_public_key);
    let pubkey_hash = Ripemd160::new().chain_update(&sha256_hash).finalize();

    // Create standard P2PKH script: OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::new();
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG

    Ok(script)
}
// use crate::signing::{ECDSASignature, SignedMessage}; // Removed unused imports

/// Generic transaction interface for different blockchain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainTransaction {
    Ethereum(EthereumTransaction),
    Bitcoin(BitcoinTransaction), // Future support
}

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

/// Bitcoin transaction structure with full SegWit support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub inputs: Vec<BitcoinInput>,
    pub outputs: Vec<BitcoinOutput>,
    pub version: u32,
    pub lock_time: u32,
    pub witness: Option<BitcoinWitness>, // SegWit witness data
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinInput {
    pub txid: String,
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness_utxo: Option<BitcoinWitnessUtxo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// SegWit witness data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinWitness {
    pub inputs: Vec<BitcoinWitnessInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinWitnessInput {
    pub stack: Vec<Vec<u8>>, // Witness stack items
}

/// Witness UTXO information for SegWit inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinWitnessUtxo {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Chain-specific signing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSigningResult {
    pub transaction: ChainTransaction,
    pub signature: ChainSignature,
    pub signer_id: String,
    pub timestamp: u64,
}

/// Chain-specific signature types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainSignature {
    Ethereum(EthereumSignature),
    Bitcoin(BitcoinSignature), // Future support
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumSignature {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recovery_id: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinSignature {
    pub signature: Vec<u8>,
    pub sighash_type: u8,
}

/// Trait for chain-specific operations
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

    /// Get chain-specific parameters (e.g., chain ID for Ethereum)
    fn get_chain_params(&self) -> HashMap<String, String>;

    /// Downcast to concrete type for type-specific operations
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
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
                // Check if this is a contract transaction (has data)
                if let Some(data) = &eth_tx.data {
                    // Use contract transaction function for transactions with data
                    let contract_tx = crate::rpc_server::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                        data: hex::encode(data), // Convert bytes back to hex string
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    // Use regular transaction function for simple transfers (no data)
                    let dummy_tx = DummyTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                    };
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &dummy_tx,
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
                // Check if this is a contract transaction (has data)
                if let Some(data) = &eth_tx.data {
                    // Use contract transaction function for transactions with data
                    let contract_tx = crate::rpc_server::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                        data: hex::encode(data), // Convert bytes back to hex string
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    // Use regular transaction function for simple transfers (no data)
                    let dummy_tx = DummyTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                    };
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &dummy_tx,
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

        // Calculate v value for Ethereum (EIP-155)
        let v = if let ChainTransaction::Ethereum(eth_tx) = transaction {
            recovery_id as u64 + 35 + eth_tx.chain_id * 2
        } else {
            recovery_id as u64 + 27 // Legacy format
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
                // Basic validation
                if eth_sig.r.len() != 32 || eth_sig.s.len() != 32 {
                    return Ok(false);
                }

                if public_key.len() != 64 && public_key.len() != 65 {
                    return Ok(false);
                }

                // In a production implementation, you would:
                // 1. Recreate the transaction hash
                // 2. Recover the public key from the signature
                // 3. Compare with the expected public key

                // For now, we'll do basic validation and return true
                tracing::info!("Ethereum signature verification - basic validation passed for transaction to: {}", eth_tx.to);
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
            data: None, // DummyTransaction doesn't have data field
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

/// Bitcoin chain handler implementation
pub struct BitcoinChainHandler {
    network: String,                   // mainnet, testnet, regtest
    group_public_key: Option<Vec<u8>>, // DKG group public key for signing
}

impl BitcoinChainHandler {
    pub fn new(network: String) -> Self {
        Self {
            network,
            group_public_key: None,
        }
    }

    /// Set the DKG group public key for signing
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
                // Currently we only sign the first input
                let first_input = btc_tx
                    .inputs
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("Bitcoin transaction has no inputs"))?;

                let sighash_all: u32 = 1; // SIGHASH_ALL

                // If this is a SegWit input, we must use BIP143 transaction digest
                if let Some(witness_utxo) = &first_input.witness_utxo {
                    use sha2::{Digest, Sha256};

                    // Helper to compute double SHA256
                    let dbl_sha256 = |data: &[u8]| -> Vec<u8> {
                        let hash1 = Sha256::digest(data);
                        let hash2 = Sha256::digest(&hash1);
                        hash2.to_vec()
                    };

                    // hashPrevouts: hash of all input outpoints
                    let mut prevouts = Vec::new();
                    for inp in &btc_tx.inputs {
                        let mut txid = hex::decode(&inp.txid)
                            .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
                        txid.reverse();
                        prevouts.extend_from_slice(&txid);
                        prevouts.extend_from_slice(&inp.vout.to_le_bytes());
                    }
                    let hash_prevouts = dbl_sha256(&prevouts);

                    // hashSequence: hash of all input sequences
                    let mut sequences = Vec::new();
                    for inp in &btc_tx.inputs {
                        sequences.extend_from_slice(&inp.sequence.to_le_bytes());
                    }
                    let hash_sequence = dbl_sha256(&sequences);

                    // hashOutputs: hash of all outputs
                    let mut outs = Vec::new();
                    for out in &btc_tx.outputs {
                        outs.extend_from_slice(&out.value.to_le_bytes());
                        outs.extend_from_slice(&encode_varint(out.script_pubkey.len() as u64));
                        outs.extend_from_slice(&out.script_pubkey);
                    }
                    let hash_outputs = dbl_sha256(&outs);

                    // scriptCode: depends on witness_utxo type
                    let script_code = if witness_utxo.script_pubkey.len() == 22
                        && witness_utxo.script_pubkey[0] == 0x00
                        && witness_utxo.script_pubkey[1] == 0x14
                    {
                        // P2WPKH -> convert to P2PKH script
                        let pubkey_hash = &witness_utxo.script_pubkey[2..];
                        let mut script = Vec::new();
                        script.push(0x76); // OP_DUP
                        script.push(0xa9); // OP_HASH160
                        script.push(0x14); // push 20 bytes
                        script.extend_from_slice(pubkey_hash);
                        script.push(0x88); // OP_EQUALVERIFY
                        script.push(0xac); // OP_CHECKSIG
                        script
                    } else {
                        // For other SegWit types, use the witness UTXO's script_pubkey directly
                        witness_utxo.script_pubkey.clone()
                    };

                    // Build preimage according to BIP143
                    let mut preimage = Vec::new();
                    preimage.extend_from_slice(&btc_tx.version.to_le_bytes());
                    preimage.extend_from_slice(&hash_prevouts);
                    preimage.extend_from_slice(&hash_sequence);

                    // outpoint being signed
                    let mut txid = hex::decode(&first_input.txid)
                        .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
                    txid.reverse();
                    preimage.extend_from_slice(&txid);
                    preimage.extend_from_slice(&first_input.vout.to_le_bytes());

                    // scriptCode
                    preimage.extend_from_slice(&encode_varint(script_code.len() as u64));
                    preimage.extend_from_slice(&script_code);

                    // value of the previous output
                    preimage.extend_from_slice(&witness_utxo.value.to_le_bytes());

                    // sequence of this input
                    preimage.extend_from_slice(&first_input.sequence.to_le_bytes());

                    // hashOutputs
                    preimage.extend_from_slice(&hash_outputs);

                    // lock time
                    preimage.extend_from_slice(&btc_tx.lock_time.to_le_bytes());

                    // hash type
                    preimage.extend_from_slice(&sighash_all.to_le_bytes());

                    Ok(preimage)
                } else {
                    // Legacy signing format (non-SegWit)
                    let mut tx_bytes = Vec::new();

                    // Version
                    tx_bytes.extend_from_slice(&btc_tx.version.to_le_bytes());

                    // Input count
                    tx_bytes.extend_from_slice(&encode_varint(btc_tx.inputs.len() as u64));

                    for (i, input) in btc_tx.inputs.iter().enumerate() {
                        // Previous tx hash
                        let mut txid = hex::decode(&input.txid)
                            .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
                        txid.reverse();
                        tx_bytes.extend_from_slice(&txid);

                        // Vout
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

                        // Sequence
                        tx_bytes.extend_from_slice(&input.sequence.to_le_bytes());
                    }

                    // Outputs
                    tx_bytes.extend_from_slice(&encode_varint(btc_tx.outputs.len() as u64));
                    for out in &btc_tx.outputs {
                        tx_bytes.extend_from_slice(&out.value.to_le_bytes());
                        tx_bytes.extend_from_slice(&encode_varint(out.script_pubkey.len() as u64));
                        tx_bytes.extend_from_slice(&out.script_pubkey);
                    }

                    // Lock time
                    tx_bytes.extend_from_slice(&btc_tx.lock_time.to_le_bytes());

                    // Append SIGHASH_ALL
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
            ChainTransaction::Ethereum(eth_tx) => {
                // Check if this is a contract transaction (has data)
                if let Some(data) = &eth_tx.data {
                    // Use contract transaction function for transactions with data
                    let contract_tx = crate::rpc_server::ContractTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                        data: hex::encode(data), // Convert bytes back to hex string
                    };
                    Ok(
                        crate::utils::transaction::create_transaction_for_signing_contract(
                            &contract_tx,
                        ),
                    )
                } else {
                    // Use regular transaction function for simple transfers (no data)
                    let dummy_tx = DummyTransaction {
                        to: eth_tx.to.clone(),
                        value: eth_tx.value.clone(),
                        gas_limit: eth_tx.gas_limit,
                        gas_price: eth_tx.gas_price.clone(),
                        nonce: eth_tx.nonce,
                        chain_id: eth_tx.chain_id,
                    };
                    Ok(crate::utils::transaction::create_transaction_for_signing(
                        &dummy_tx,
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
        _recovery_id: u8,
        _transaction: &ChainTransaction,
    ) -> Result<ChainSignature> {
        if signature_data.len() != 64 {
            return Err(anyhow::anyhow!(
                "Invalid signature length for Bitcoin: expected 64 bytes, got {}",
                signature_data.len()
            ));
        }

        // For Bitcoin, we use DER encoding of ECDSA signature
        // signature_data should be [r (32 bytes) || s (32 bytes)]
        let r = &signature_data[0..32];
        let s = &signature_data[32..64];

        // Create DER-encoded signature
        let mut der_sig = Vec::new();
        der_sig.push(0x30); // SEQUENCE tag

        // We'll calculate the length later
        let length_pos = der_sig.len();
        der_sig.push(0x00); // Placeholder for length

        // Add r value
        der_sig.push(0x02); // INTEGER tag
        if r[0] & 0x80 != 0 {
            // If high bit is set, prepend 0x00 to make it positive
            der_sig.push((r.len() + 1) as u8);
            der_sig.push(0x00);
        } else {
            der_sig.push(r.len() as u8);
        }
        der_sig.extend_from_slice(r);

        // Add s value
        der_sig.push(0x02); // INTEGER tag
        if s[0] & 0x80 != 0 {
            // If high bit is set, prepend 0x00 to make it positive
            der_sig.push((s.len() + 1) as u8);
            der_sig.push(0x00);
        } else {
            der_sig.push(s.len() as u8);
        }
        der_sig.extend_from_slice(s);

        // Update the length
        let content_length = der_sig.len() - 2; // Exclude the SEQUENCE tag and length byte
        der_sig[length_pos] = content_length as u8;

        // Add SIGHASH_ALL flag
        der_sig.push(0x01); // SIGHASH_ALL

        Ok(ChainSignature::Bitcoin(BitcoinSignature {
            signature: der_sig,
            sighash_type: 0x01, // SIGHASH_ALL
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
                // For Bitcoin signature verification, we would need to:
                // 1. Create the signature hash from the transaction
                // 2. Verify the DER-encoded signature against the hash using the public key
                // This is a complex process involving SIGHASH computation

                // For now, we'll do basic validation
                if btc_sig.signature.len() < 8 {
                    return Ok(false);
                }

                if public_key.len() != 33 && public_key.len() != 65 {
                    return Ok(false);
                }

                // In a production implementation, you would use secp256k1 to verify:
                // let secp = secp256k1::Secp256k1::verification_only();
                // let pubkey = secp256k1::PublicKey::from_slice(public_key)?;
                // let sig = secp256k1::ecdsa::Signature::from_der(&btc_sig.signature[..btc_sig.signature.len()-1])?;
                // let message = secp256k1::Message::from_slice(&tx_hash)?;
                // Ok(secp.verify_ecdsa(&message, &sig, &pubkey).is_ok())

                // For now, return true to indicate basic validation passed
                tracing::warn!("Bitcoin signature verification not fully implemented - returning true for basic validation");
                Ok(true)
            }
            _ => Err(anyhow::anyhow!(
                "Mismatched transaction and signature types"
            )),
        }
    }

    fn from_dummy_transaction(&self, dummy_tx: &DummyTransaction) -> Result<ChainTransaction> {
        // DummyTransaction is EVM-specific, so we can't directly convert to Bitcoin
        // We'll create a placeholder Bitcoin transaction that indicates this limitation
        tracing::warn!("Converting DummyTransaction to Bitcoin transaction - this creates an invalid placeholder");

        let bitcoin_tx = BitcoinTransaction {
            inputs: vec![],
            outputs: vec![],
            version: 2,
            lock_time: 0,
            witness: None,
        };

        // Log the original dummy transaction details for debugging
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

/// Chain handler factory
pub struct ChainHandlerFactory;

impl ChainHandlerFactory {
    pub fn create_ethereum_handler(chain_id: u64) -> Box<dyn ChainHandler> {
        Box::new(EthereumChainHandler::new(chain_id))
    }

    pub fn create_bitcoin_handler(network: String) -> Box<dyn ChainHandler> {
        Box::new(BitcoinChainHandler::new(network))
    }

    pub fn create_handler_by_type(
        chain_type: &str,
        params: HashMap<String, String>,
    ) -> Result<Box<dyn ChainHandler>> {
        match chain_type {
            "ethereum" => {
                let chain_id = params
                    .get("chain_id")
                    .ok_or_else(|| anyhow::anyhow!("Missing chain_id parameter for Ethereum"))?
                    .parse::<u64>()?;
                Ok(Self::create_ethereum_handler(chain_id))
            }
            "bitcoin" => {
                let network = params
                    .get("network")
                    .unwrap_or(&"mainnet".to_string())
                    .clone();
                Ok(Self::create_bitcoin_handler(network))
            }
            _ => Err(anyhow::anyhow!("Unsupported chain type: {}", chain_type)),
        }
    }
}
