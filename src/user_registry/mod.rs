use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use k256::Scalar;
use ff::PrimeField;

use crate::types::SerializableScalar;
use crate::utils::hmac_helper;

/// User registration data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistration {
    pub user_id: String,
    pub ethereum_address: String,
    pub hmac_constant: [u8; 32],
    pub tweaked_secret_share: Option<SerializableScalar>,
    pub created_at: DateTime<Utc>,
}

/// Global user registry that stores mappings between registered addresses and HMAC constants
#[derive(Debug)]
pub struct UserRegistry {
    /// Chain code for HMAC derivation (should be kept secret)
    chain_code: [u8; 32],
    /// Mapping from user_id to UserRegistration
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
    pub async fn register_user(&self, ethereum_address: &str) -> Result<UserRegistration, String> {
        // Check if user already exists
        let address_lookup = self.address_to_user.read().await;
        if address_lookup.contains_key(ethereum_address) {
            return Err("User already registered".to_string());
        }
        drop(address_lookup);

        // Generate unique user ID
        let user_id = Uuid::new_v4().to_string();
        
        // Compute HMAC-SHA256 constant for this user's address
        let hmac_constant = hmac_helper::hmac256_from_addr(ethereum_address, &self.chain_code)?;

        // Create user registration (tweaked secret share will be set later)
        let registration = UserRegistration {
            user_id: user_id.clone(),
            ethereum_address: ethereum_address.to_string(),
            hmac_constant,
            tweaked_secret_share: None,
            created_at: Utc::now(),
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

    /// Compute and store the tweaked secret share for a user
    /// This adds the HMAC constant to the original DKG secret share
    pub async fn compute_tweaked_secret_share(
        &self,
        ethereum_address: &str,
        original_secret_share: &Scalar,
    ) -> Result<SerializableScalar, String> {
        // Get the user registration
        let mut users = self.users.write().await;
        
        if let Some(registration) = users.get_mut(ethereum_address) {
            // Get the HMAC constant for this user
            let hmac_constant = registration.hmac_constant;
            
            // Convert HMAC constant to secp256k1 scalar
            let hmac_scalar = Scalar::from_repr(hmac_constant.into()).unwrap();
            
            // Compute tweaked secret share: s_i' = s_i + t mod n
            // where n is the secp256k1 curve order
            let tweaked_scalar = original_secret_share + hmac_scalar;
            
            // Convert to SerializableScalar for storage
            let tweaked_secret_share = SerializableScalar(tweaked_scalar);
            
            // Store the tweaked secret share
            registration.tweaked_secret_share = Some(tweaked_secret_share.clone());
            
            Ok(tweaked_secret_share)
        } else {
            Err("User not found".to_string())
        }
    }

    /// Get the tweaked secret share for a user
    pub async fn get_tweaked_secret_share(&self, ethereum_address: &str) -> Option<SerializableScalar> {
        if let Some(registration) = self.get_user_by_address(ethereum_address).await {
            registration.tweaked_secret_share
        } else {
            None
        }
    }

    /// Get user registration by user ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Option<UserRegistration> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Get user registration by Ethereum address
    pub async fn get_user_by_address(&self, ethereum_address: &str) -> Option<UserRegistration> {
        let user_id = {
            let address_map = self.address_to_user.read().await;
            address_map.get(ethereum_address).cloned()
        };
        
        if let Some(user_id) = user_id {
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
    async fn test_user_registration() {
        let chain_code = [1u8; 32];
        let registry = UserRegistry::new(chain_code);
        
        let eth_address = "0x1234567890123456789012345678901234567890";
        let result = registry.register_user(eth_address).await;
        
        assert!(result.is_ok());
        let registration = result.unwrap();
        assert_eq!(registration.ethereum_address, eth_address);
        assert!(!registration.user_id.is_empty());
        assert_eq!(registration.hmac_constant.len(), 32);
        assert!(registration.tweaked_secret_share.is_none());
    }

    #[tokio::test]
    async fn test_tweaked_secret_share() {
        let chain_code = [1u8; 32];
        let registry = UserRegistry::new(chain_code);
        
        let eth_address = "0x1234567890123456789012345678901234567890";
        let _ = registry.register_user(eth_address).await.unwrap();
        
        // Create a dummy original secret share
        let original_share = Scalar::from_repr([1u8; 32].into()).unwrap();
        
        // Compute tweaked secret share
        let result = registry.compute_tweaked_secret_share(eth_address, &original_share).await;
        assert!(result.is_ok());
        
        // Verify the tweaked share is stored
        let tweaked_share = registry.get_tweaked_secret_share(eth_address).await;
        assert!(tweaked_share.is_some());
    }
} 