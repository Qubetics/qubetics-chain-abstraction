use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    UserToVault,
    NetworkToTarget,
    VaultToNetwork,
    RewardTxn,
    WithdrawLiquidity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionNetwork {
    /// EVM/TICS transactions
    TICS,
    /// Bitcoin transactions
    BTC,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositIntent {
    pub source_address: String,
    pub target_address: String,
    pub source_chain: String,
    pub target_chain: String,
    pub amount: u128,
    pub source_token: String,
    pub target_token: String,
    pub timestamp: u128,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub tx_hash: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositIntentResponse {
    pub intent_id: String,
    pub status: String,
    pub message: String,
    pub raw_transaction: Option<String>,
}
