use std::str::FromStr;
use ethers::{
	prelude::*,
	providers::{Http, Middleware, Provider},
	signers::{LocalWallet, Signer},
	utils::parse_ether,
};
use std::{convert::TryFrom, sync::Arc};

const ETH_PROVIDER_URL: &str = "http://114.119.189.4:8545";


async fn get_client_eth() -> anyhow::Result<Arc<SignerMiddleware<Provider<Http>, LocalWallet>>> {


	let provider = Provider::<Http>::try_from(ETH_PROVIDER_URL)?;
	let chain_id = provider.get_chainid().await?;
	let wallet = get_local_wallet().await?;
	let wallet = wallet.with_chain_id(chain_id.as_u64());
	let client_eth = SignerMiddleware::new(provider, wallet.clone());
	let client_eth = Arc::new(client_eth);
	return Ok(client_eth);
}

pub async fn get_eth_balance(address: &str) -> anyhow::Result<U256> {
	let client_eth = get_client_eth().await?;
	let balance = client_eth.get_balance(address.parse::<Address>()?, None).await?;
	Ok(balance)
}

pub async fn get_current_address() -> anyhow::Result<String> {
	let client_eth = get_client_eth().await?;
	let address = format!("{:?}", client_eth.address());
	Ok(address)
}

pub async fn get_local_wallet() -> anyhow::Result<LocalWallet> {
	dotenv::dotenv().ok();

	let test_private_key = std::env::var("TEST_PRIVATE_KEY_ETH").expect("TEST_PRIVATE_KEY_ETH not set");

	let wallet = LocalWallet::from_str(&test_private_key)?;
	Ok(wallet)
}

pub async fn send_eth(recipient_eth_address: &str, amount: u128) -> anyhow::Result<()> {

	let client_eth = get_client_eth().await?;
	let tx_request = TransactionRequest::new()
		.to(recipient_eth_address.parse::<Address>()?)
		.value(parse_ether(amount)?);

	let pending_tx = client_eth
		.send_transaction(tx_request, None)
		.await
		.map_err(|e| anyhow::anyhow!("Failed to submit ETH tx: {}", e))?;

	let receipt = pending_tx
		.await
		.map_err(|e| anyhow::anyhow!("Failed to confirm ETH tx: {}", e))?;

	println!(
		"Sent {} ETH to {}. Tx Hash: {:?}",
		amount,
		recipient_eth_address,
		receipt.map(|tx| tx.transaction_hash)
	);

	Ok(())

}
