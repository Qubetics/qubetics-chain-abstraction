use reqwest::Client;
use std::{
    io::BufRead,
    process::{Command, Stdio},
    time::Duration,
};
use tokio::time::sleep;

use crate::utils::{
    NodeProcess, SupportedNetwork, execute, get_current_address, get_group_address_from_db, get_vault_addresses, register_user_and_get_derived_addresses, run_fifth_node, run_nodes
};

mod utils;

const RPC_PORT: u16 = 8081;
// const ETH_PROVIDER_URL: &str = "https://rpc-testnet.qubetics.work";


#[tokio::test]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let test_private_key =
        std::env::var("TEST_PRIVATE_KEY_ETH_1").expect("TEST_PRIVATE_KEY_ETH_1 not set");

    let test_private_key_1 =
        std::env::var("TEST_PRIVATE_KEY_ETH_2").expect("TEST_PRIVATE_KEY_ETH_2 not set");
    
    let client = Client::new();

    println!("Starting first node...");
    let (mut nodes, node1_peer_id) =
        run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

    println!("Executing user_mpc_deposit from Qubetics to Bitcoin");
    user_deposit_intent_eth_to_btc(test_private_key, node1_peer_id.clone(), client.clone()).await?;
    println!("User mpc deposit from Qubetics to Bitcoin executed successfully");


    // Run the fifth node after both deposit intents
    println!("Starting fifth node...");
    let fifth_node = run_fifth_node(RPC_PORT, &node1_peer_id).await?;
    nodes.push(fifth_node);
    println!("Fifth node started successfully");

    println!("Executing user_mpc_deposit from Bitcoin to Qubetics");
    user_deposit_intent_btc_to_eth(test_private_key_1, node1_peer_id.clone(), client.clone()).await?;
    println!("User mpc deposit from Bitcoin to Qubetics executed successfully");


    Ok(())
}



async fn user_deposit_intent_eth_to_btc(test_private_key: String, node1_peer_id: String, client: Client) -> anyhow::Result<()> {


    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address(&test_private_key).await?;

    // Register user and get derived addresses
    let (derived_eth_address, derived_btc_address) =
        register_user_and_get_derived_addresses(&client, RPC_PORT, user_address).await?;

    // Get BTC group address from DB
    let (btc_address_group_key, _) = get_group_address_from_db(&node1_peer_id)?;

    println!("Executing user_mpc_deposit from Qubetics to Bitcoin");
    // execute(
    //     test_private_key,
    //     vault_eth_address.clone(),
    //     derived_eth_address.clone(),
    //     derived_btc_address.clone(),
    //     btc_address_group_key.clone(),
    //     client.clone(),
    //     SupportedNetwork::Qubetics,
    //     SupportedNetwork::Bitcoin,
    //     25, // 25 ETH
    // )
    // .await?;

    Ok(())
}
async fn user_deposit_intent_btc_to_eth(test_private_key: String, node1_peer_id: String, client: Client) -> anyhow::Result<()> {

    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address(&test_private_key).await?;

    // Register user and get derived addresses
    let (derived_eth_address, derived_btc_address) =
        register_user_and_get_derived_addresses(&client, RPC_PORT, user_address).await?;

    // Get ETH group address from DB
    let (_, eth_address_group_key) = get_group_address_from_db(&node1_peer_id)?;

    println!("Executing user_mpc_deposit from Bitcoin to Qubetics");
    execute(
        test_private_key,
        vault_eth_address.clone(),
        derived_eth_address.clone(),
        derived_btc_address.clone(),
        eth_address_group_key.clone(),
        client.clone(),
        SupportedNetwork::Bitcoin,
        SupportedNetwork::Qubetics,
        500,
    )
    .await?;

    Ok(())
}

