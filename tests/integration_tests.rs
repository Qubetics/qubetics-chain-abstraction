use reqwest::Client;

use crate::utils::{
    execute, get_current_address, get_group_address_from_db, get_vault_addresses,
    register_user_and_get_derived_addresses, run_nodes, SupportedNetwork,
};

mod utils;

const RPC_PORT: u16 = 8081;
// const ETH_PROVIDER_URL: &str = "https://rpc-testnet.qubetics.work";

#[tokio::test]
async fn test_integration_with_user_deposit_intent_eth_to_btc() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let test_private_key =
        std::env::var("TEST_PRIVATE_KEY_ETH_1").expect("TEST_PRIVATE_KEY_ETH_1 not set");

    let client = Client::new();

    println!("Starting first node...");
    let (_nodes, node1_peer_id) =
        run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

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
    execute(
        test_private_key,
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
    dotenv::dotenv().ok();

    let test_private_key =
        std::env::var("TEST_PRIVATE_KEY_ETH_1").expect("TEST_PRIVATE_KEY_ETH_1 not set");

    let client = Client::new();

    println!("Starting first node...");
    let (_nodes, node1_peer_id) =
        run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

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

#[tokio::test]
async fn test_integration_with_user_deposit_intent_eth_to_btc_with_multiples_transactions(
) -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let test_private_key_1 =
        std::env::var("TEST_PRIVATE_KEY_ETH_1").expect("TEST_PRIVATE_KEY_ETH_1 not set");

    let test_private_key_2 =
        std::env::var("TEST_PRIVATE_KEY_ETH_2").expect("TEST_PRIVATE_KEY_ETH_2 not set");

    let client = Client::new();

    println!("Starting first node...");
    let (_nodes, node1_peer_id) =
        run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address(&test_private_key_1).await?;

    // Register user and get derived addresses for first user
    let (derived_eth_address_1, derived_btc_address_1) =
        register_user_and_get_derived_addresses(&client, RPC_PORT, user_address).await?;

    // Get User ETH
    let user_address_2 = get_current_address(&test_private_key_2).await?;

    // Register user and get derived addresses for first user
    let (derived_eth_address_2, derived_btc_address_2) =
        register_user_and_get_derived_addresses(&client, RPC_PORT, user_address_2).await?;

    // Get BTC group address from DB
    let (btc_address_group_key, _) = get_group_address_from_db(&node1_peer_id)?;

    println!("Executing concurrent user_mpc_deposit requests to test race condition");

    let handle1 = {
        let vault_eth = vault_eth_address.clone();
        let derived_eth = derived_eth_address_1.clone();
        let derived_btc = derived_btc_address_1.clone();
        let btc_group = btc_address_group_key.clone();
        let client_clone = client.clone();

        tokio::spawn(async move {
            execute(
                test_private_key_1,
                vault_eth,
                derived_eth,
                derived_btc,
                btc_group,
                client_clone,
                SupportedNetwork::Qubetics,
                SupportedNetwork::Bitcoin,
                25, // 25 ETH
            )
            .await
        })
    };

    let handle2 = {
        let vault_eth = vault_eth_address.clone();
        let derived_eth = derived_eth_address_2.clone();
        let derived_btc = derived_btc_address_2.clone();
        let btc_group = btc_address_group_key.clone();
        let client_clone = client.clone();

        tokio::spawn(async move {
            execute(
                test_private_key_2,
                vault_eth,
                derived_eth,
                derived_btc,
                btc_group,
                client_clone,
                SupportedNetwork::Qubetics,
                SupportedNetwork::Bitcoin,
                26, // 25 ETH
            )
            .await
        })
    };

    // Wait for both tasks to complete
    let result1 = handle1.await??;
    let result2 = handle2.await??;
    
    println!("✅ Both concurrent executions completed");
    println!("   Thread 1 (User 1) result: {:?}", result1);
    println!("   Thread 2 (User 2) result: {:?}", result2);

    Ok(())
}
