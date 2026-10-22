use std::{str::FromStr, time::Duration};
use tokio::time::sleep;

use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Amount, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use mpc_node::utils::transaction::fetch_bitcoin_utxos;
use std::convert::TryFrom;

pub async fn send_btc(amount_sats: u64, to_address: &str) -> anyhow::Result<Txid> {
    // Load environment variables for test
    dotenv::dotenv().ok();

    let test_private_key_btc =
        std::env::var("TEST_PRIVATE_KEY_BTC").expect("TEST_PRIVATE_KEY_BTC not set");

    let secp = Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::from_str(&test_private_key_btc)?;
    let private_key = PrivateKey::new(secret_key, Network::Testnet); // Assuming Testnet
    let pk = private_key.public_key(&secp);
    // Use P2PKH address
    let source_address = bitcoin::Address::p2pkh(&pk, Network::Testnet);

    println!("BTC Source Address: {}", source_address);

    let utxos = fetch_bitcoin_utxos(&source_address.to_string(), true).await?;

    // Select UTXOs
    let mut selected_utxos = Vec::new();
    let mut input_amount = 0;
    let fee = 1000;
    let target_amount = amount_sats + fee;

    for utxo in utxos {
        input_amount += utxo.value;
        selected_utxos.push(utxo);
        if input_amount >= target_amount {
            break;
        }
    }

    if input_amount < target_amount {
        return Err(anyhow::anyhow!(
            "Insufficient BTC funds. Have {}, need {}",
            input_amount,
            target_amount
        ));
    }

    let change = input_amount - target_amount;

    let mut inputs = Vec::new();
    for utxo in &selected_utxos {
        inputs.push(TxIn {
            previous_output: OutPoint::new(Txid::from_str(&utxo.txid)?, utxo.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        });
    }

    let to_addr_parsed =
        bitcoin::Address::from_str(to_address)?.require_network(Network::Testnet)?;
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: to_addr_parsed.script_pubkey(),
    }];

    if change > 546 {
        // Dust limit
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: source_address.script_pubkey(),
        });
    }

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Sign inputs
    let mut sighash_cache = SighashCache::new(&mut tx);
    let mut signatures = Vec::new();

    for i in 0..selected_utxos.len() {
        let script_pubkey = source_address.script_pubkey();

        let sighash = sighash_cache.legacy_signature_hash(
            i,
            &script_pubkey,
            EcdsaSighashType::All.to_u32(),
        )?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&msg, &secret_key);

        let sig = bitcoin::ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };

        let script_sig = bitcoin::script::Builder::new()
            .push_slice(bitcoin::script::PushBytesBuf::try_from(sig.to_vec()).unwrap())
            .push_slice(bitcoin::script::PushBytesBuf::try_from(pk.to_bytes()).unwrap())
            .into_script();

        signatures.push(script_sig);
    }

    let tx = sighash_cache.into_transaction();
    for (i, script_sig) in signatures.into_iter().enumerate() {
        tx.input[i].script_sig = script_sig;
    }

    let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);

    // Broadcast
    let client = reqwest::Client::new();
    let resp = client
        .post("https://mempool.space/testnet/api/tx")
        .body(tx_hex)
        .send()
        .await?;

    if !resp.status().is_success() {
        let text = resp.text().await?;
        return Err(anyhow::anyhow!("Failed to broadcast BTC tx: {}", text));
    }

    let txid_str = resp.text().await?;
    println!("Broadcast BTC Tx: {}", txid_str);
    Ok(Txid::from_str(&txid_str)?)
}

pub async fn wait_for_btc_confirmation(txid: Txid) -> anyhow::Result<()> {
    println!("Waiting for BTC confirmation for {}...", txid);
    let client = reqwest::Client::new();
    let url = format!("https://mempool.space/testnet/api/tx/{}/status", txid);

    for _ in 0..6000 {
        let resp = client.get(&url).send().await?;
        if resp.status().is_success() {
            let status: serde_json::Value = resp.json().await?;
            if status["confirmed"].as_bool().unwrap_or(false) {
                println!("BTC Tx Confirmed!");
                return Ok(());
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
    println!("Warning: BTC Tx not confirmed yet.");
    Ok(())
}
