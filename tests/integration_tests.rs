use crate::utils::{
    SupportedNetwork, execute, get_current_address, get_derived_addresses, get_group_address_from_db, get_vault_addresses, register_user, run_fifth_node, run_nodes, wait_for_dkg
};
use reqwest::Client;

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
    let (mut nodes, node1_peer_id, node1_p2p_port) =
        run_nodes(&client, RPC_PORT, &["node1", "node2", "node3"]).await?;

    println!("Executing user_mpc_deposit from Qubetics to Bitcoin");
    user_deposit_intent_eth_to_btc(test_private_key, node1_peer_id.clone(), client.clone()).await?;
    println!("User mpc deposit from Qubetics to Bitcoin executed successfully");

    let (vault_eth_address_before, vault_btc_address_before) = get_vault_addresses(&node1_peer_id)?;

    let user_address = get_current_address(&test_private_key_1).await?;

    register_user(&client, RPC_PORT, &user_address).await?;
    let (derived_eth_address_before, derived_btc_address_before) =
        get_derived_addresses(&client, RPC_PORT, &user_address).await?;
    let (eth_group_address_before, btc_group_address_before) =
        get_group_address_from_db(&node1_peer_id)?;

    // Run the fifth node after both deposit intents
    println!("Starting fifth node...");
    let fifth_node = run_fifth_node(RPC_PORT, node1_p2p_port, &node1_peer_id).await?;
    nodes.push(fifth_node);
    println!("Fifth node started successfully");

    // Ensure node 5 finishes syncing/DKG before shutting down node 1
    println!("Waiting for Node 5 to complete DKG sync...");
    let node5_port = RPC_PORT + 5;
    let node5_ready = wait_for_dkg(&client, node5_port).await;
    assert!(node5_ready, "Node 5 failed to complete DKG sync");
    println!("Node 5 DKG completed.");

    // After refresh share and new node join

    let (vault_eth_address_after, vault_btc_address_after) = get_vault_addresses(&node1_peer_id)?;

    register_user(&client, RPC_PORT, &user_address).await?;
    let (derived_eth_address_after, derived_btc_address_after) =
        get_derived_addresses(&client, RPC_PORT, &user_address).await?;
    let (eth_group_address_after, btc_group_address_after) =
        get_group_address_from_db(&node1_peer_id)?;

    assert_eq!(
        vault_eth_address_after, vault_eth_address_before,
        "Vault ETH address should have changed"
    );
    assert_eq!(
        vault_btc_address_after, vault_btc_address_before,
        "Vault BTC address should have changed"
    );
    assert_eq!(
        derived_eth_address_after, derived_eth_address_before,
        "Derived ETH address should have changed"
    );
    assert_eq!(
        derived_btc_address_after, derived_btc_address_before,
        "Derived BTC address should have changed"
    );
    assert_eq!(
        eth_group_address_after, eth_group_address_before,
        "ETH group address should have changed"
    );
    assert_eq!(
        btc_group_address_after, btc_group_address_before,
        "BTC group address should have changed"
    );

    println!("Executing user_mpc_deposit from Bitcoin to Qubetics");
    user_deposit_intent_btc_to_eth(test_private_key_1, node1_peer_id.clone(), client.clone())
        .await?;
    println!("User mpc deposit from Bitcoin to Qubetics executed successfully");

    Ok(())
}

async fn user_deposit_intent_eth_to_btc(
    test_private_key: String,
    node1_peer_id: String,
    client: Client,
) -> anyhow::Result<()> {
    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address(&test_private_key).await?;

    // Register user and get derived addresses
    register_user(&client, RPC_PORT, &user_address).await?;
    let (derived_eth_address, derived_btc_address) =
        get_derived_addresses(&client, RPC_PORT, &user_address).await?;

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
async fn user_deposit_intent_btc_to_eth(
    test_private_key: String,
    node1_peer_id: String,
    client: Client,
) -> anyhow::Result<()> {
    // Get Vault Addresses from DB
    let (vault_eth_address, _) = get_vault_addresses(&node1_peer_id)?;

    // Get User ETH
    let user_address = get_current_address(&test_private_key).await?;

    // Register user and get derived addresses
    register_user(&client, RPC_PORT, &user_address).await?;

    let (derived_eth_address, derived_btc_address) =
        get_derived_addresses(&client, RPC_PORT, &user_address).await?;

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
