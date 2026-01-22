use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    UserToVault,
    NetworkToTarget,
    RewardTxn,
    WithdrawLiquidity,
    Refund,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    /// Deposit amount in smallest units, encoded as a decimal string
    pub amount: String,
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

/// Batch intent input structure for processBatchIntents contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchIntentInput {
    pub source_address: String,
    pub target_address: String,
    pub source_chain: String,
    pub target_chain: String,
    pub amount: u128,
    pub source_token: String,
    pub target_token: String,
    pub intent_id: String,
    pub withdraw_tx_hash: String,
    pub deposit_tx_hash: Option<String>,
}

/// Batch type for processBatchIntents: 0 = BTC, 1 = TICS
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum BatchType {
    BTC = 0,
    TICS = 1,
}
