use anyhow::{anyhow, Result};
use ethers::{prelude::*, utils::parse_ether};
use k256::ProjectivePoint;
use mpc_node::{
    database::keys,
    types::{
        rpc_server::{
            DKGStatusResponse, UserInfoResponse, UserMpcDepositRequest, UserRegistrationResponse,
        },
        DepositIntent, SerializablePoint,
    },
    utils::{get_btc_address_from_group_key, get_eth_address_from_group_key},
};
use reqwest::Client;
use std::time::Duration;
use tokio::time::sleep;

use crate::utils::{
    get_local_wallet, get_pair_and_target_address, send_btc, send_eth, wait_for_btc_confirmation,
    SupportedNetwork,
};

const RPC_PORT: u16 = 8081;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn wait_for_dkg(client: &Client, port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/dkg_status", port);
    println!("Waiting for DKG on port {}...", port);

    for _i in 0..6000 {
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(status) = resp.json::<DKGStatusResponse>().await {
                    if status.status == "success"
                        && status.dkg_status.as_deref() == Some("Completed")
                    {
                        println!("DKG Completed on node {}!", port);
                        return true;
                    }
                }
            }
            Err(_) => {
                // Node might not be up yet
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    false
}

pub fn get_vault_addresses(peer_id: &str) -> Result<(String, String)> {
    println!("Getting Vault Address from DB...");
    let db_path = format!("data/rocksdb-{}", &peer_id[..8]);
    let db = rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), &db_path, false)
        .map_err(|e| anyhow!("Failed to open RocksDB at {}: {}", db_path, e))?;

    let vault_eth_address = match db.get(keys::DKG_VAULT_ETH_ADDRESS.as_bytes()) {
        Ok(Some(val)) => bincode::deserialize::<String>(&val)
            .map_err(|e| anyhow!("Failed to deserialize vault eth address: {}", e))?,
        Ok(None) => return Err(anyhow!("Vault ETH address not found in DB")),
        Err(e) => return Err(anyhow!("Failed to read from DB: {}", e)),
    };
    println!("Vault ETH Address: {}", vault_eth_address);

    let vault_btc_address = match db.get(keys::DKG_VAULT_BTC_ADDRESS.as_bytes()) {
        Ok(Some(val)) => bincode::deserialize::<String>(&val)
            .map_err(|e| anyhow!("Failed to deserialize vault btc address: {}", e))?,
        Ok(None) => return Err(anyhow!("Vault BTC address not found in DB")),
        Err(e) => return Err(anyhow!("Failed to read from DB: {}", e)),
    };
    println!("Vault BTC Address: {}", vault_btc_address);

    Ok((vault_eth_address, vault_btc_address))
}

pub async fn register_user_and_get_derived_addresses(
    client: &Client,
    rpc_port: u16,
    user_eth_address: String,
) -> Result<(String, String)> {
    println!("Registering User...");
    let reg_resp = client
        .post(format!("http://127.0.0.1:{}/register_user", rpc_port))
        .header(
            "X-API-KEY",
            std::env::var("RPC_API_KEY").unwrap_or_else(|_| "default_dev_key".to_string()),
        )
        .json(&serde_json::json!({
            "ethereum_address": user_eth_address
        }))
        .send()
        .await?
        .json::<UserRegistrationResponse>()
        .await?;

    println!("Registration Response: {:?}", reg_resp);
    if reg_resp.status != "success" {
        if reg_resp.message != "User is already registered" {
            return Err(anyhow!("User registration failed: {:?}", reg_resp));
        }
        println!("User already registered, continuing...");
    }

    // Get derived addresses
    println!("Getting Derived ETH Address...");
    let reg_resp = client
        .get(format!(
            "http://127.0.0.1:{}/user_info/{}",
            rpc_port, user_eth_address
        ))
        .send()
        .await?
        .json::<UserInfoResponse>()
        .await?;

    if reg_resp.status != "success" {
        return Err(anyhow!("Failed to get user info: {:?}", reg_resp));
    }

    let derived_eth_address = reg_resp
        .derived_eth_address
        .ok_or_else(|| anyhow!("Derived ETH address missing"))?;
    println!("Derived ETH Address: {}", derived_eth_address);

    let derived_btc_address = reg_resp
        .derived_btc_address
        .ok_or_else(|| anyhow!("Derived BTC address missing"))?;
    println!("Derived BTC Address: {}", derived_btc_address);

    Ok((derived_eth_address, derived_btc_address))
}

pub fn get_group_address_from_db(peer_id: &str) -> Result<(String, String)> {
    println!("Getting Group Key from Node DB...");
    let db_path = format!("data/rocksdb-{}", &peer_id[..8]);
    let db = rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), &db_path, false)
        .map_err(|e| anyhow!("Failed to open RocksDB at {}: {}", db_path, e))?;

    let key_str = keys::DKG_FINAL_PUBLIC;
    let value = match db.get(key_str.as_bytes()) {
        Ok(Some(val)) => val,
        Ok(None) => return Err(anyhow!("DKG Final Public Key not found in DB")),
        Err(e) => return Err(anyhow!("Failed to read from DB: {}", e)),
    };

    let serializable: SerializablePoint = bincode::deserialize(&value)
        .map_err(|e| anyhow!("Failed to deserialize DKG final public: {}", e))?;
    let pubkey = ProjectivePoint::from(serializable.0);
    let btc_address = get_btc_address_from_group_key(pubkey);
    let eth_address = get_eth_address_from_group_key(pubkey);

    if btc_address.is_empty() {
        return Err(anyhow!("Failed to generate address from group key"));
    }

    println!("BTC Address Group Key: {}", btc_address);
    println!("ETH Address Group Key: {}", eth_address);
    Ok((btc_address, eth_address))
}

pub async fn execute(
    vault_eth_address: String,
    derived_eth_address: String,
    derived_btc_address: String,
    address_group_key: String,
    client: Client,
    source_chain: SupportedNetwork,
    target_chain: SupportedNetwork,
    deposit_amount: u128,
) -> anyhow::Result<()> {
    let wallet = get_local_wallet().await?;

    let now = SystemTime::now();
    let timestamp = now
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_secs();

    let (source_token, target_token, target_address) = get_pair_and_target_address(source_chain, target_chain);

    let mut deposit_intent = DepositIntent {
        source_address: "".to_string(),
        target_address: "".to_string(),
        source_chain: "".to_string(),
        target_chain: "".to_string(),
        amount: 0,
        source_token: "".to_string(),
        target_token: "".to_string(),
        timestamp: timestamp as u128,
    };

    if source_chain == SupportedNetwork::Qubetics && target_chain == SupportedNetwork::Bitcoin {
        // Starting provide BTC liquidity -> backend side
        // Send 1500 sats to BTC Address Group Key
        println!(
            "Sending 1500 sats to BTC Address Group Key: {}",
            address_group_key
        );
        match send_btc(1500, &address_group_key).await {
            Ok(txid) => {
                println!("Sent 1500 sats. Txid: {}", txid);
                wait_for_btc_confirmation(txid).await?;
            }
            Err(e) => println!("Warning: Failed to send BTC: {}", e),
        }

        println!("Sending 2 ETH to Vault: {}", vault_eth_address);

        send_eth(&vault_eth_address, 2).await?;

        println!("Sending 40 ETH to Derived Address: {}", derived_eth_address);

        send_eth(&derived_eth_address, 40).await?;

        println!("Testing user_mpc_deposit...");
        let amount = parse_ether(deposit_amount)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Value too large for u128"))?; // 25 ETH

        deposit_intent = DepositIntent {
            source_address: derived_eth_address.clone(),
            target_address,
            source_chain: source_chain.to_string(),
            target_chain: target_chain.to_string(),
            amount,
            source_token,
            target_token,
            timestamp: timestamp as u128,
        };
    } else if source_chain == SupportedNetwork::Bitcoin && target_chain == SupportedNetwork::Qubetics {
        // Starting provide BTC liquidity -> backend side
        // Send 1500 sats to BTC Address Group Key
        println!(
            "Sending 1500 sats to Derived BTC Address: {}",
            derived_btc_address
        );
        match send_btc(1500, &derived_btc_address).await {
            Ok(txid) => {
                println!("Sent 1500 sats. Txid: {}", txid);
                wait_for_btc_confirmation(txid).await?;
            }
            Err(e) => println!("Warning: Failed to send BTC: {}", e),
        }

        println!("Sending 2 ETH to Vault: {}", vault_eth_address);

        send_eth(&vault_eth_address, 2).await?;

        deposit_intent = DepositIntent {
            source_address: derived_btc_address.clone(),
            target_address,
            source_chain: source_chain.to_string(),
            target_chain: target_chain.to_string(),
            amount: deposit_amount,
            source_token,
            target_token,
            timestamp: timestamp as u128,
        };
    }

    let msg = serde_json::to_string(&deposit_intent)?;
    let signature = wallet.sign_message(msg.as_bytes()).await?;
    let signature_hex = format!("0x{}", signature);

    let deposit_req = UserMpcDepositRequest {
        signature: Some(signature_hex),
        msg: deposit_intent.clone(),
        tx_id: None,
        status: None,
    };

    let deposit_resp = client
        .post(format!("http://127.0.0.1:{}/user_mpc_deposit", RPC_PORT))
        .header(
            "X-API-KEY",
            std::env::var("RPC_API_KEY").unwrap_or_else(|_| "default_dev_key".to_string()),
        )
        .json(&deposit_req)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("Deposit Response: {:?}", deposit_resp);

    if let Some(status) = deposit_resp.get("status") {
        assert!(
            status == "success" || status == "submitted" || status == "processing",
            "Deposit failed status: {}",
            status
        );
    } else {
        panic!("Invalid deposit response");
    }

    println!("User to Vault Deposit Completed Successfully!");

    // Backend will execute user_mpc_deposit again

    println!("Testing user_mpc_deposit...");
    let msg = serde_json::to_string(&deposit_intent)?;
    let signature = wallet.sign_message(msg.as_bytes()).await?;
    let signature_hex = format!("0x{}", signature);

    let deposit_req = UserMpcDepositRequest {
        signature: Some(signature_hex),
        msg: deposit_intent,
        tx_id: None,
        status: None,
    };

    let deposit_resp = client
        .post(format!("http://127.0.0.1:{}/user_mpc_deposit", RPC_PORT))
        .header(
            "X-API-KEY",
            std::env::var("RPC_API_KEY").unwrap_or_else(|_| "default_dev_key".to_string()),
        )
        .json(&deposit_req)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("Deposit Response: {:?}", deposit_resp);

    if let Some(status) = deposit_resp.get("status") {
        assert!(
            status == "success" || status == "submitted" || status == "processing",
            "Deposit failed status: {}",
            status
        );
    } else {
        panic!("Invalid deposit response");
    }

    println!("Network to Target Completed Successfully!");

    Ok(())
}
