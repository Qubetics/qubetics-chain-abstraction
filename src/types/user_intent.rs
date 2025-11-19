use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{intent::DepositIntent, SerializablePoint, SerializableScalar};

/// Intent status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntentStatus {
    Pending,
    Processing,
    Solved,
    Rejected,
}

/// Status of a blockchain transaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Rejected,
    Confirmed,
}

/// Transaction IDs associated with an intent hash
/// Each intent has up to three transactions:
/// 1. user_aggregated_address -> network_aggregated_address
/// 2. network_aggregated_address -> user_target_address
/// 3. vault_address -> network_aggregated_address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentTransactionIds {
    pub intent_hash: String,
    /// Transaction ID for user_aggregated_address -> network_aggregated_address
    pub user_to_network_tx_id: Option<String>,
    /// Transaction ID for network_aggregated_address -> user_target_address
    pub network_to_target_tx_id: Option<String>,
    /// Transaction ID for vault_address -> network_aggregated_address
    pub vault_to_network_tx_id: Option<String>,
    /// Final solver identifier responsible for the deposit
    pub final_solver_id: Option<String>,
    /// Error message from blockchain if transaction failed
    pub error_message: Option<String>,
    /// Timestamp when first transaction was recorded
    pub created_at: DateTime<Utc>,
    /// Timestamp when last transaction was updated
    pub updated_at: DateTime<Utc>,
}

impl IntentTransactionIds {
    /// Get the solver node ID that completed the final transaction
    pub fn get_final_solver(&self) -> Option<String> {
        self.final_solver_id.clone()
    }

    /// Set the solver node ID for the final transaction
    pub fn set_final_solver(&mut self, solver: Option<String>) {
        self.final_solver_id = solver;
        self.updated_at = Utc::now();
    }
}

/// User registration data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistration {
    pub user_id: String,
    pub ethereum_address: String,
    pub hmac_constant: [u8; 32],
    pub tweaked_secret_share: Option<SerializableScalar>,
    pub user_group_key: Option<SerializablePoint>,
    pub derived_eth_address: Option<String>,
    pub derived_btc_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub registered_by_node: String, // Track which node registered this user
    pub intent_hashes: HashMap<String, IntentStatus>, // intent_hash -> IntentStatus mapping
}

/// Global intent registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRegistry {
    pub intents: HashMap<String, DepositIntent>, // intent_hash -> DepositIntent mapping
}

