use reqwest::Client;

use crate::utils::{
    SupportedNetwork, execute, get_group_address_from_db, get_current_address, get_vault_addresses, register_user_and_get_derived_addresses, run_nodes
};

mod utils;

const RPC_PORT: u16 = 8081;
// const ETH_PROVIDER_URL: &str = "https://rpc-testnet.qubetics.work";

#[tokio::test]
async fn test_integration_with_user_deposit_intent_eth_to_btc() -> anyhow::Result<()> {
    let client = Client::new();

    println!("Starting first node...");
    let (_nodes, node1_peer_id) = run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address().await?;

    // Register user and get derived addresses
    let (derived_eth_address, derived_btc_address) =
        register_user_and_get_derived_addresses(&client, RPC_PORT, user_address).await?;

    // Get BTC group address from DB
    let (btc_address_group_key, _) = get_group_address_from_db(&node1_peer_id)?;

    println!("Executing user_mpc_deposit from Qubetics to Bitcoin");
    execute(
        vault_eth_address.clone(),
        derived_eth_address.clone(),
		derived_btc_address.clone(),
        btc_address_group_key.clone(),
        client.clone(),
		SupportedNetwork::Qubetics,
		SupportedNetwork::Bitcoin,
		25, // 25 ETH
    )
    .await?;

    Ok(())
}


#[tokio::test]
async fn test_integration_with_user_deposit_intent_btc_to_eth() -> anyhow::Result<()> {
    let client = Client::new();

    println!("Starting first node...");
    let (_nodes, node1_peer_id) = run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address().await?;

    // Register user and get derived addresses
    let (derived_eth_address, derived_btc_address) =
        register_user_and_get_derived_addresses(&client, RPC_PORT, user_address).await?;

    // Get ETH group address from DB
    let (_, eth_address_group_key) = get_group_address_from_db(&node1_peer_id)?;

    println!("Executing user_mpc_deposit from Bitcoin to Qubetics");
    execute(
        vault_eth_address.clone(),
        derived_eth_address.clone(),
		derived_btc_address.clone(),
        eth_address_group_key.clone(),
        client.clone(),
		SupportedNetwork::Bitcoin,
		SupportedNetwork::Qubetics,
		1000
    )
    .await?;

    Ok(())
}



