use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    UserToVault,
    NetworkToTarget,
    RewardTxn,
    WithdrawLiquidity,
    Refund,
    IntentStatusUpdate,
}

impl TransactionType {
    /// Convert TransactionType to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionType::UserToVault => "user_to_vault",
            TransactionType::NetworkToTarget => "network_to_target",
            TransactionType::RewardTxn => "reward_txn",
            TransactionType::WithdrawLiquidity => "withdraw_liquidity",
            TransactionType::Refund => "refund",
            TransactionType::IntentStatusUpdate => "intent_status_update",
        }
    }

    /// Determine which chain to use for signing based on transaction type
    /// Returns the chain name from the intent, or None for non-intent transactions
    pub fn chain_for_signing<'a>(&self, intent: &'a DepositIntent) -> Option<&'a str> {
        match self {
            TransactionType::UserToVault => Some(&intent.source_chain),
            TransactionType::NetworkToTarget => Some(&intent.target_chain),
            TransactionType::Refund => Some(&intent.source_chain),
            TransactionType::IntentStatusUpdate => Some("qubetics"),
            TransactionType::RewardTxn | TransactionType::WithdrawLiquidity => None,
        }
    }

    /// Convert transaction type to batch type for contract calls
    pub fn to_batch_type(&self) -> Option<BatchType> {
        match self {
            TransactionType::UserToVault => Some(BatchType::BTC),
            TransactionType::NetworkToTarget => Some(BatchType::TICS),
            TransactionType::IntentStatusUpdate => Some(BatchType::BTC),
            _ => None,
        }
    }
}

impl std::str::FromStr for TransactionType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user_to_vault" => Ok(TransactionType::UserToVault),
            "network_to_target" => Ok(TransactionType::NetworkToTarget),
            "reward_txn" | "claim_reward" => Ok(TransactionType::RewardTxn),
            "withdraw_liquidity" | "withdrawLiquidity" => Ok(TransactionType::WithdrawLiquidity),
            "refund" => Ok(TransactionType::Refund),
            "intent_status_update" => Ok(TransactionType::IntentStatusUpdate),
            _ => Err(anyhow::anyhow!("Unknown transaction type: {}", s)),
        }
    }
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

impl BatchType {
    /// Convert BatchType to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            BatchType::BTC => "BTC",
            BatchType::TICS => "TICS",
        }
    }
}

impl std::str::FromStr for BatchType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BTC" => Ok(BatchType::BTC),
            "TICS" => Ok(BatchType::TICS),
            _ => Err(anyhow::anyhow!("Unknown batch type: {}", s)),
        }
    }
}
