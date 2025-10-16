use serde::{Deserialize, Serialize};


// Define the transaction types for the RPC server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyTransaction {
	pub to: String,
	pub value: String,
	pub nonce: u64,
	#[serde(rename = "gasLimit")]
	pub gas_limit: u64,
	#[serde(rename = "gasPrice")]
	pub gas_price: String,
	#[serde(rename = "chainId")]
	pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTransaction {
	pub to: String,
	pub value: String,
	pub nonce: u64,
	#[serde(rename = "gasLimit")]
	pub gas_limit: u64,
	#[serde(rename = "gasPrice")]
	pub gas_price: String,
	#[serde(rename = "chainId")]
	pub chain_id: u64,
	#[serde(default)]
	pub data: String,
}

// Define the deposit intent structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositIntent {
	pub source_address: String,
	pub target_address: String,
	pub source_chain: String,
	pub target_chain: String,
	pub amount: u128,
	pub source_token: String,
	pub target_token: String,
	pub timestamp: u128, // Unix timestamp in seconds
}

