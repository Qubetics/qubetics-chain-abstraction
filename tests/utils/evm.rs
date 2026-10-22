use std::str::FromStr;
use ethers::{
	prelude::*,
	providers::{Http, Middleware, Provider},
	signers::{LocalWallet, Signer},
	utils::parse_ether,
};
use std::{convert::TryFrom, sync::Arc};

const ETH_PROVIDER_URL: &str = "http://114.119.189.4:8545";


async fn get_client_eth(private_key: &str) -> anyhow::Result<Arc<SignerMiddleware<Provider<Http>, LocalWallet>>> {


	let provider = Provider::<Http>::try_from(ETH_PROVIDER_URL)?;
	let chain_id = provider.get_chainid().await?;
	let wallet = get_local_wallet(private_key).await?;
	let wallet = wallet.with_chain_id(chain_id.as_u64());
	let client_eth = SignerMiddleware::new(provider, wallet.clone());
	let client_eth = Arc::new(client_eth);
	return Ok(client_eth);
}

pub async fn get_eth_balance(private_key: &str, address: &str) -> anyhow::Result<U256> {
	let client_eth = get_client_eth(private_key).await?;
	let balance = client_eth.get_balance(address.parse::<Address>()?, None).await?;
	Ok(balance)
}

pub async fn get_current_address(private_key: &str) -> anyhow::Result<String> {
	let client_eth = get_client_eth(private_key).await?;
	let address = format!("{:?}", client_eth.address());
	Ok(address)
}

pub async fn get_local_wallet(test_private_key: &str) -> anyhow::Result<LocalWallet> {

	let wallet = LocalWallet::from_str(test_private_key)?;
	Ok(wallet)
}

pub async fn send_eth(private_key: &str, recipient_eth_address: &str, amount: u128) -> anyhow::Result<()> {

	let client_eth = get_client_eth(private_key).await?;
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
