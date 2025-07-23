use anyhow::{anyhow, Result};
use bitcoin::{
    Address, Network,
    psbt::Psbt,
    util::key::PrivateKey,
    util::sighash::{SighashCache, EcdsaSighashType},
    util::ecdsa::EcdsaSig,
    secp256k1::{Secp256k1, Signing, Message},
    Transaction, TxIn, TxOut, OutPoint, Txid,
    PackedLockTime, Sequence, Witness,
    consensus::encode::serialize,
};
use bitcoin::secp256k1::ecdsa::Signature as RawSignature;
use reqwest::Client;
use serde::Deserialize;
use std::str::FromStr;
use secp256k1::SecretKey;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct BitcoinTransactionRequest {
    pub sender_address: String,
    pub recipient_address: String,
    pub amount: u64,
    pub fee: u64,
    pub private_key: SecretKey,
}

/// Convert secp256k1 SecretKey to bitcoin PrivateKey
pub fn secp_to_bitcoin_private_key(secp_key: &SecretKey) -> Result<PrivateKey> {
    let sk_bytes = secp_key.secret_bytes();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes)?;
    
    let private_key = PrivateKey {
        inner: sk,
        network: Network::Testnet,
        compressed: true,
    };
    
    Ok(private_key)
}

/// Create and broadcast Bitcoin transaction
pub async fn create_and_sign_bitcoin_transaction(
    request: &BitcoinTransactionRequest,
) -> Result<String> {
    let network = Network::Testnet;
    
    // Convert secp256k1 SecretKey to bitcoin PrivateKey
    let privkey = secp_to_bitcoin_private_key(&request.private_key)?;
    
    let secp = Secp256k1::new();
    let pubkey = privkey.public_key(&secp);

    // Derive the Bitcoin address from the public key (like in your code)
    let change_addr = Address::p2wpkh(&pubkey, network)
        .expect("compressed pubkey → P2WPKH");
    info!("₿ [BTC] Derived sender address from aggregated private key: {}", change_addr);

    let recipient = Address::from_str(&request.recipient_address)?;
    let amount = request.amount;
    let fee = request.fee;

    info!("₿ [BTC] Recipient: {}", recipient);
    info!("₿ [BTC] Amount: {} sats", amount);
    info!("₿ [BTC] Fee: {} sats", fee);

    send_bitcoin_transaction(&change_addr, &privkey, &secp, &recipient, amount, fee).await
}

async fn send_bitcoin_transaction(
    change_addr: &Address,
    privkey: &PrivateKey,
    secp: &Secp256k1<impl Signing>,
    recipient: &Address,
    amount: u64,
    fee: u64,
) -> Result<String> {
    let client = Client::new();
    let url = format!(
        "https://blockstream.info/testnet/api/address/{}/utxo",
        change_addr
    );
    let utxos: Vec<Utxo> = client.get(&url).send().await?.json().await?;

    if utxos.is_empty() {
        info!("❌ [BTC] No UTXOs found. Fund via https://testnet-faucet.mempool.co");
        return Err(anyhow!("No UTXOs found for address: {}", change_addr));
    }

    info!("₿ [BTC] Found {} UTXOs", utxos.len());

    // Build the unsigned transaction
    let mut total_in = 0;
    let mut tx = Transaction {
        version: 2,
        lock_time: PackedLockTime(0),
        input: vec![],
        output: vec![],
    };
    
    for utxo in &utxos {
        if total_in >= amount + fee {
            break;
        }
        tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&utxo.txid)?,
                vout: utxo.vout,
            },
            script_sig: Default::default(),
            sequence: Sequence(0xFFFFFFFF),
            witness: Witness::default(),
        });
        total_in += utxo.value;
    }
    
    if total_in < amount + fee {
        return Err(anyhow!(
            "Insufficient funds: have {} sats, need {}",
            total_in,
            amount + fee
        ));
    }
    
    tx.output.push(TxOut {
        value: amount,
        script_pubkey: recipient.script_pubkey(),
    });
    
    let change = total_in - amount - fee;
    if change > 0 {
        tx.output.push(TxOut {
            value: change,
            script_pubkey: change_addr.script_pubkey(),
        });
    }

    info!("₿ [BTC] Transaction built: {} inputs, {} outputs", tx.input.len(), tx.output.len());

    // Wrap as PSBT and fill UTXO info
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let utxo = &utxos[i];
        input.witness_utxo = Some(TxOut {
            value: utxo.value,
            script_pubkey: change_addr.script_pubkey(),
        });
    }

    // Sign each input using the correct BIP‑143 scriptCode
    let pubkey = privkey.public_key(secp);
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let witness_utxo = input.witness_utxo.as_ref()
            .ok_or_else(|| anyhow!("Missing witness UTXO for input {}", i))?;
        let script_code = witness_utxo
            .script_pubkey
            .p2wpkh_script_code()
            .ok_or_else(|| anyhow!("Not a P2WPKH UTXO for input {}", i))?;

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache.segwit_signature_hash(
            i,
            &script_code,
            witness_utxo.value,
            EcdsaSighashType::All,
        )?;
        let msg: Message = Message::from_slice(&sighash[..])?;
        let raw_sig: RawSignature = secp.sign_ecdsa(&msg, &privkey.inner);

        let ecdsa_sig = EcdsaSig {
            sig: raw_sig,
            hash_ty: EcdsaSighashType::All,
        };
        input.partial_sigs.insert(pubkey.clone(), ecdsa_sig);
    }

    // Manually assemble each input's witness
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        if let Some(sig) = input.partial_sigs.get(&pubkey) {
            let mut witness = Witness::new();
            witness.push(sig.to_vec());
            witness.push(pubkey.to_bytes());
            input.final_script_witness = Some(witness.clone());
            psbt.unsigned_tx.input[i].witness = witness;
        }
    }

    // Extract, serialize & broadcast
    let final_tx = psbt.extract_tx();
    let raw = hex::encode(serialize(&final_tx));
    
    info!("₿ [BTC] Broadcasting transaction...");
    let txid = client
        .post("https://blockstream.info/testnet/api/tx")
        .body(raw)
        .send()
        .await?
        .text()
        .await?;
    
    info!("✅ [BTC] Bitcoin transaction broadcasted! TXID = {}", txid);
    Ok(txid)
} 