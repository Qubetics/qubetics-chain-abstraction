use chrono::{DateTime, Utc};
use ff::PrimeField;
use k256::ProjectivePoint;
use k256::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use sha3::Keccak256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::rpc_server::DepositIntent;
use crate::types::{SerializablePoint, SerializableScalar};
use crate::utils::hmac_helper::hmac256_from_addr;
use tracing::info;

pub mod db_registry;
pub use db_registry::DatabaseUserRegistry;

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
/// Each intent has two transactions:
/// 1. user_aggregated_address -> network_aggregated_address
/// 2. network_aggregated_address -> user_target_address
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
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Timestamp when last transaction was updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
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

/// User registry for managing user registrations and intent tracking
pub struct UserRegistry {
    users: Arc<RwLock<HashMap<String, UserRegistration>>>,
    chain_code: [u8; 32],
    intent_registry: Arc<RwLock<IntentRegistry>>, // Global intent registry
}

impl Clone for UserRegistry {
    fn clone(&self) -> Self {
        info!(
            "🔄 [USER_REGISTRY] Clone called - Original Users Arc: {:p}, Intents Arc: {:p}",
            Arc::as_ptr(&self.users),
            Arc::as_ptr(&self.intent_registry)
        );

        let cloned = Self {
            users: Arc::clone(&self.users),
            chain_code: self.chain_code,
            intent_registry: Arc::clone(&self.intent_registry),
        };

        info!("🔄 [USER_REGISTRY] Clone created - New Users Arc: {:p}, Intents Arc: {:p} (should be same as original)", 
              Arc::as_ptr(&cloned.users), Arc::as_ptr(&cloned.intent_registry));

        cloned
    }
}

impl UserRegistry {
    /// Create a new user registry
    pub fn new(chain_code: [u8; 32]) -> Self {
        let registry = Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            chain_code,
            intent_registry: Arc::new(RwLock::new(IntentRegistry {
                intents: HashMap::new(),
            })),
        };

        info!("🏗️ [USER_REGISTRY] Created new UserRegistry instance - Users Arc: {:p}, Intents Arc: {:p}", 
              Arc::as_ptr(&registry.users), Arc::as_ptr(&registry.intent_registry));

        registry
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        ethereum_address: &str,
        dkg_secret_share: Option<&Scalar>,
        node_id: &str,
    ) -> Result<UserRegistration, String> {
        info!("👤 [USER_REGISTRY] register_user called - Registry Users Arc: {:p}, Intents Arc: {:p}, Address: {}, Node: {}", 
              Arc::as_ptr(&self.users), Arc::as_ptr(&self.intent_registry), ethereum_address, node_id);

        // 1) Normalize to canonical EIP-55
        let addr_cs = match checksum_from_any(ethereum_address) {
            Ok(a) => a,
            Err(e) => {
                return Err(format!(
                    "Invalid ethereum_address '{}': {}",
                    ethereum_address, e
                ))
            }
        };

        // 2) Dedup on canonical key
        {
            let users = self.users.read().await;
            if users.contains_key(&addr_cs) {
                return Err("User already registered".to_string());
            }
        }

        // 3) Generate user ID and HMAC constant
        let user_id = Uuid::new_v4().to_string();
        let hmac_constant = self.generate_hmac_constant(&addr_cs);

        // 4) Create registration
        let mut registration = UserRegistration {
            user_id: user_id.clone(),
            ethereum_address: addr_cs.clone(),
            hmac_constant,
            tweaked_secret_share: None,
            user_group_key: None,
            derived_eth_address: None,
            derived_btc_address: None,
            created_at: Utc::now(),
            registered_by_node: node_id.to_string(),
            intent_hashes: HashMap::new(),
        };

        // 5) Process DKG share if provided
        if let Some(share) = dkg_secret_share {
            let tweaked_share = self.compute_tweaked_share(share, &registration.hmac_constant);
            registration.tweaked_secret_share = Some(tweaked_share);
        }

        // 6) Store in registry
        {
            let mut users = self.users.write().await;
            users.insert(addr_cs.clone(), registration.clone());
        }

        info!("✅ Registered user {} with ID {}", addr_cs, user_id);
        Ok(registration)
    }

    /// Get user registration by user ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Option<UserRegistration> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Get user registration by ethereum address
    pub async fn get_user_by_address(&self, ethereum_address: &str) -> Option<UserRegistration> {
        info!("🔍 [USER_REGISTRY] get_user_by_address called - Registry Users Arc: {:p}, Intents Arc: {:p}, Address: {}", 
              Arc::as_ptr(&self.users), Arc::as_ptr(&self.intent_registry), ethereum_address);

        let users = self.users.read().await;
        let result = users.get(ethereum_address).cloned();

        info!(
            "🔍 [USER_REGISTRY] get_user_by_address result - Address: {}, Found: {}",
            ethereum_address,
            result.is_some()
        );

        result
    }

    /// Get all registered users
    pub async fn get_all_users(&self) -> Vec<UserRegistration> {
        let users = self.users.read().await;
        users.values().cloned().collect()
    }

    /// Get the HMAC constant for a user
    pub async fn get_hmac_constant(&self, ethereum_address: &str) -> Option<[u8; 32]> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            Some(registration.hmac_constant)
        } else {
            None
        }
    }

    /// Set user group key and derived addresses
    pub async fn set_user_group_key(
        &self,
        ethereum_address: &str,
        group_key: ProjectivePoint,
    ) -> Result<(), String> {
        let affine = group_key.to_affine();
        let serial = SerializablePoint(affine);

        // Derive ETH and BTC addresses from the group key
        let derived_eth = crate::utils::get_eth_address_from_group_key(group_key);
        let derived_btc = crate::utils::get_btc_address_from_group_key(group_key);

        // Log the derived addresses
        info!(
            "📬 [USER_REGISTRY] Derived ETH address for {}: {}",
            ethereum_address, derived_eth
        );
        info!(
            "📬 [USER_REGISTRY] Derived BTC address for {}: {}",
            ethereum_address, derived_btc
        );

        let mut users = self.users.write().await;
        if let Some(user) = users
            .values_mut()
            .find(|u| u.ethereum_address == ethereum_address)
        {
            user.user_group_key = Some(serial);
            user.derived_eth_address = Some(derived_eth);
            user.derived_btc_address = Some(derived_btc);
            info!(
                "✅ Set user group key and derived addresses for {}",
                ethereum_address
            );
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    /// Set derived addresses for a user
    pub async fn set_derived_addresses(
        &self,
        ethereum_address: &str,
        eth_address: String,
        btc_address: String,
    ) -> Result<(), String> {
        let mut users = self.users.write().await;
        if let Some(user) = users
            .values_mut()
            .find(|u| u.ethereum_address == ethereum_address)
        {
            user.derived_eth_address = Some(eth_address);
            user.derived_btc_address = Some(btc_address);
            info!("✅ Set derived addresses for {}", ethereum_address);
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    /// Store intent hash mapping and the actual intent
    pub async fn store_intent_hash(
        &self,
        intent_hash: Vec<u8>,
        user_address: &str,
        deposit_intent: &DepositIntent,
    ) -> Result<(), String> {
        let intent_hash_hex = hex::encode(&intent_hash);
        info!("🔐 [USER_REGISTRY] store_intent_hash called - Registry Users Arc: {:p}, Intents Arc: {:p}, Hash: {}, User: {}", 
              Arc::as_ptr(&self.users), Arc::as_ptr(&self.intent_registry), intent_hash_hex, user_address);

        let mut users = self.users.write().await;
        if let Some(user) = users
            .values_mut()
            .find(|u| u.ethereum_address == user_address)
        {
            // Convert intent hash to hex string for storage

            // Store intent status in user registry
            user.intent_hashes
                .insert(intent_hash_hex.clone(), IntentStatus::Pending);

            // Store actual intent in global registry
            let mut intent_registry = self.intent_registry.write().await;
            intent_registry
                .intents
                .insert(intent_hash_hex.clone(), deposit_intent.clone());

            info!(
                "✅ Stored intent hash for user {}: {} -> Pending",
                user_address, intent_hash_hex
            );
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    /// Get the actual DepositIntent by hash
    pub async fn get_intent(&self, intent_hash: &str) -> Option<DepositIntent> {
        let intent_registry = self.intent_registry.read().await;
        intent_registry.intents.get(intent_hash).cloned()
    }

    /// Get all intents from global registry
    pub async fn get_all_intents(&self) -> HashMap<String, DepositIntent> {
        let intent_registry = self.intent_registry.read().await;
        intent_registry.intents.clone()
    }

    /// Get intents by status from global registry
    pub async fn get_intents_by_status_global(
        &self,
        status: IntentStatus,
    ) -> Vec<(String, DepositIntent)> {
        let intent_registry = self.intent_registry.read().await;
        let mut result = Vec::new();

        for (hash, intent) in &intent_registry.intents {
            // Check if this intent has the specified status for any user
            let users = self.users.read().await;
            for user in users.values() {
                if let Some(user_status) = user.intent_hashes.get(hash) {
                    if user_status == &status {
                        result.push((hash.clone(), intent.clone()));
                        break;
                    }
                }
            }
        }

        result
    }

    /// Get intent hash information for a user
    pub async fn get_intent_hashes(
        &self,
        ethereum_address: &str,
    ) -> Option<HashMap<String, IntentStatus>> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            Some(registration.intent_hashes.clone())
        } else {
            None
        }
    }

    /// Check if a specific intent hash exists for a user
    pub async fn has_intent_hash(&self, ethereum_address: &str, intent_hash: &str) -> bool {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            registration.intent_hashes.contains_key(intent_hash)
        } else {
            false
        }
    }

    /// Get amount for a specific intent hash
    pub async fn get_intent_amount(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
    ) -> Option<u128> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            registration
                .intent_hashes
                .get(intent_hash)
                .map(|info| match info {
                    IntentStatus::Pending => 0,
                    IntentStatus::Processing => 0,
                    IntentStatus::Solved => 0,
                    IntentStatus::Rejected => 0,
                })
        } else {
            None
        }
    }

    /// Update intent status
    pub async fn update_intent_status(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
        new_status: IntentStatus,
    ) -> Result<(), String> {
        let mut users = self.users.write().await;
        if let Some(user) = users
            .values_mut()
            .find(|u| u.ethereum_address == ethereum_address)
        {
            if let Some(intent_info) = user.intent_hashes.get_mut(intent_hash) {
                *intent_info = new_status.clone();
                info!(
                    "✅ Updated intent status for user {}: {} -> {:?}",
                    ethereum_address, intent_hash, new_status
                );
                Ok(())
            } else {
                Err("Intent hash not found".to_string())
            }
        } else {
            Err("User not found".to_string())
        }
    }

    /// Get intent status
    pub async fn get_intent_status(
        &self,
        ethereum_address: &str,
        intent_hash: &str,
    ) -> Option<IntentStatus> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            registration.intent_hashes.get(intent_hash).cloned()
        } else {
            None
        }
    }

    /// Get all intents with a specific status for a user
    pub async fn get_intents_by_status(
        &self,
        ethereum_address: &str,
        status: IntentStatus,
    ) -> Vec<(String, IntentStatus)> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            registration
                .intent_hashes
                .iter()
                .filter(|(_, info)| **info == status)
                .map(|(hash, info)| (hash.clone(), info.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Generate HMAC constant for an address
    fn generate_hmac_constant(&self, address: &str) -> [u8; 32] {
        hmac256_from_addr(address, &self.chain_code).unwrap_or_else(|_| [0u8; 32])
        // Fallback to zero array if HMAC fails
    }

    /// Compute tweaked share from DKG share and HMAC constant
    fn compute_tweaked_share(
        &self,
        share: &Scalar,
        hmac_constant: &[u8; 32],
    ) -> SerializableScalar {
        let hmac_scalar = Scalar::from_repr((*hmac_constant).into()).unwrap();
        let tweaked_scalar = *share + hmac_scalar;
        SerializableScalar(tweaked_scalar)
    }

    /// Get the chain code (for debugging/testing purposes)
    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }
}

pub fn to_checksum_address(addr20: &[u8]) -> String {
    let hex_lower = hex::encode(addr20); // 40 lowercase hex chars
    let hash = Keccak256::digest(hex_lower.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in hex_lower.chars().enumerate() {
        if ch.is_ascii_hexdigit() && ch.is_ascii_lowercase() && ch >= 'a' {
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 {
                (byte >> 4) & 0x0f
            } else {
                byte & 0x0f
            };
            out.push(if nibble >= 8 {
                ch.to_ascii_uppercase()
            } else {
                ch
            });
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn checksum_from_any(s: &str) -> anyhow::Result<String> {
    let no0x = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if no0x.len() != 40 {
        anyhow::bail!("bad address length");
    }
    let bytes = hex::decode(no0x)?;
    if bytes.len() != 20 {
        anyhow::bail!("bad address bytes");
    }
    Ok(to_checksum_address(&bytes))
}
