use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use k256::Scalar;
use ff::PrimeField;

use crate::types::SerializableScalar;
use crate::utils::hmac_helper::hmac256_from_addr;
use tracing::info;
use tracing::warn;

/// User registration data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistration {
    pub user_id: String,
    pub ethereum_address: String,
    pub hmac_constant: [u8; 32],
    pub tweaked_secret_share: Option<SerializableScalar>,
    pub created_at: DateTime<Utc>,
    pub registered_by_node: String,  // Track which node registered this user
}

/// Global user registry that stores mappings between registered addresses and HMAC constants
#[derive(Debug, Clone)]
pub struct UserRegistry {
    chain_code: [u8; 32],
    users: Arc<RwLock<HashMap<String, UserRegistration>>>,
    /// Mapping from ethereum_address to user_id for quick lookups
    address_to_user: Arc<RwLock<HashMap<String, String>>>,
}

impl UserRegistry {
    /// Create a new user registry with the given chain code
    pub fn new(chain_code: [u8; 32]) -> Self {
        Self {
            chain_code,
            users: Arc::new(RwLock::new(HashMap::new())),
            address_to_user: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new user and compute their HMAC constant
    pub async fn register_user(&self, ethereum_address: &str, dkg_secret_share: Option<&Scalar>, node_id: &str) -> Result<UserRegistration, String> {
        // Check if user already exists
        let address_lookup = self.address_to_user.read().await;
        if address_lookup.contains_key(ethereum_address) {
            return Err("User already registered".to_string());
        }
        drop(address_lookup);

        // Generate unique user ID
        let user_id = Uuid::new_v4().to_string();
        
        // Compute HMAC-SHA256 constant for this user's address
        let hmac_constant = hmac256_from_addr(ethereum_address, &self.chain_code)?;
        
        // Log HMAC computation details for verification
        info!("🔐 [USER_REGISTRY] Computing HMAC for address: {}", ethereum_address);
        info!("🔐 [USER_REGISTRY] Chain code: 0x{}", hex::encode(&self.chain_code));
        info!("🔐 [USER_REGISTRY] Raw HMAC constant (32 bytes): 0x{}", hex::encode(&hmac_constant));

        // Compute tweaked secret share if DKG secret share is available
        let mut tweaked_secret_share = None;
        if let Some(secret_share) = dkg_secret_share {
            // Convert HMAC constant to secp256k1 scalar
            let hmac_scalar = Scalar::from_repr(hmac_constant.into()).unwrap();
            
            // Log only the HMAC scalar conversion (not the DKG shares)
            info!("🔐 [USER_REGISTRY] HMAC constant converted to scalar: {:?}", hmac_scalar);
            
            // Compute tweaked secret share: s_i' = s_i + t mod n
            // where n is the secp256k1 curve order
            let tweaked_scalar = secret_share + hmac_scalar;
            
            // Convert to SerializableScalar for storage
            tweaked_secret_share = Some(SerializableScalar(tweaked_scalar));
        }

        // Create user registration with computed tweaked secret share
        let registration = UserRegistration {
            user_id: user_id.clone(),
            ethereum_address: ethereum_address.to_string(),
            hmac_constant,
            tweaked_secret_share,
            created_at: Utc::now(),
            registered_by_node: node_id.to_string(),
        };

        // Store the registration
        {
            let mut users = self.users.write().await;
            users.insert(user_id.clone(), registration.clone());
        }
        
        {
            let mut address_map = self.address_to_user.write().await;
            address_map.insert(ethereum_address.to_string(), user_id);
        }

        Ok(registration)
    }

    /// Handle incoming user registration from another node
    /// This method is called when a user registration message is received via P2P
    pub async fn handle_incoming_registration(&self, ethereum_address: &str, source_node_id: &str) -> Result<(), String> {
        // Check if user already exists locally
        let address_lookup = self.address_to_user.read().await;
        if address_lookup.contains_key(ethereum_address) {
            // User already exists, nothing to do
            info!("👤 User {} already registered locally, skipping duplicate", ethereum_address);
            return Ok(());
        }
        drop(address_lookup);

        // User doesn't exist locally, register them
        // Note: We don't have DKG secret share here, so tweaked share won't be computed
        // This is fine - the main purpose is to ensure all nodes know about the user
        match self.register_user(ethereum_address, None, source_node_id).await {
            Ok(_) => {
                info!("✅ Successfully registered user {} locally from P2P message", ethereum_address);
                Ok(())
            }
            Err(e) => {
                warn!("❌ Failed to register user {} locally from P2P message: {}", ethereum_address, e);
                Err(e)
            }
        }
    }

    /// Get user registration by user ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Option<UserRegistration> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Get user registration by ethereum address
    pub async fn get_user_by_address(&self, ethereum_address: &str) -> Option<UserRegistration> {
        let address_map = self.address_to_user.read().await;
        if let Some(user_id) = address_map.get(ethereum_address) {
            let user_id = user_id.clone(); // Clone before dropping the lock
            drop(address_map);
            let users = self.users.read().await;
            users.get(&user_id).cloned()
        } else {
            None
        }
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

    /// Get the chain code (for debugging/testing purposes)
    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;

    #[test]
    fn test_user_registry_creation() {
        let chain_code = [1u8; 32];
        let registry = UserRegistry::new(chain_code);
        
        assert_eq!(registry.get_chain_code(), [1u8; 32]);
    }

    #[tokio::test]
    async fn test_user_registration_without_dkg() {
        let chain_code = [1u8; 32];
        let registry = UserRegistry::new(chain_code);
        
        let eth_address = "0x1234567890123456789012345678901234567890";
        let registration = registry.register_user(eth_address, None, "test_node").await.unwrap();
        
        assert_eq!(registration.ethereum_address, eth_address);
        assert!(!registration.user_id.is_empty());
        assert_eq!(registration.hmac_constant.len(), 32);
        assert!(registration.tweaked_secret_share.is_none()); // No DKG share provided
        assert_eq!(registration.registered_by_node, "test_node");
    }

    #[tokio::test]
    async fn test_user_registration_with_dkg() {
        let chain_code = [1u8; 32];
        let registry = UserRegistry::new(chain_code);
        
        let eth_address = "0x1234567890123456789012345678901234567890";
        
        // Create a dummy DKG secret share
        let dkg_secret_share = Scalar::from_repr([1u8; 32].into()).unwrap();
        
        let registration = registry.register_user(eth_address, Some(&dkg_secret_share), "test_node").await.unwrap();
        
        assert_eq!(registration.ethereum_address, eth_address);
        assert!(!registration.user_id.is_empty());
        assert_eq!(registration.hmac_constant.len(), 32);
        assert!(registration.tweaked_secret_share.is_some()); // DKG share provided, so tweaked share computed
        assert_eq!(registration.registered_by_node, "test_node");
        
        // Verify the tweaked share is stored
        let user = registry.get_user_by_address(eth_address).await;
        assert!(user.is_some());
        assert!(user.unwrap().tweaked_secret_share.is_some());
    }

    #[tokio::test]
    async fn test_handle_incoming_registration() {
        let registry = UserRegistry::new([42u8; 32]);
        let eth_address = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6";
        let source_node_id = "remote_node";

        // Initially no user exists
        assert!(registry.get_user_by_address(eth_address).await.is_none());

        // Handle incoming registration
        let result = registry.handle_incoming_registration(eth_address, source_node_id).await;
        assert!(result.is_ok());

        // Check if the registration was processed
        assert!(registry.get_user_by_address(eth_address).await.is_some());

        // Try to register the same user again - should be skipped
        let result2 = registry.handle_incoming_registration(eth_address, source_node_id).await;
        assert!(result2.is_ok());

        // User should still exist
        assert!(registry.get_user_by_address(eth_address).await.is_some());
    }
} 