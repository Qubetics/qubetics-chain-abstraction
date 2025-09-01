use std::collections::HashMap;
use std::sync::Arc;
use sha2::Digest as _;
use sha3::Keccak256;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use k256::Scalar;
use ff::PrimeField;
use k256::ProjectivePoint;

use crate::types::{SerializableScalar, SerializablePoint};
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
    pub user_group_key: Option<SerializablePoint>,
    pub derived_eth_address: Option<String>,
    pub derived_btc_address: Option<String>,
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

    /// Register a new user and compute their HMAC constant (canonicalized to EIP-55)
    pub async fn register_user(
        &self,
        ethereum_address: &str,
        dkg_secret_share: Option<&Scalar>,
        node_id: &str,
    ) -> Result<UserRegistration, String> {
        // 1) Canonicalize to EIP-55 once
        let addr_cs = match checksum_from_any(ethereum_address) {
            Ok(a) => a,
            Err(e) => return Err(format!("invalid ethereum_address: {e}")),
        };

        // 2) Dedup on canonical key
        {
            let address_lookup = self.address_to_user.read().await;
            if address_lookup.contains_key(&addr_cs) {
                return Err("User already registered".to_string());
            }
        }

        // 3) New user id
        let user_id = Uuid::new_v4().to_string();

        // 4) HMAC over the canonical address (deterministic regardless of caller casing)
        let hmac_constant = hmac256_from_addr(&addr_cs, &self.chain_code)
            .map_err(|e| e.to_string())?;

        info!("🔐 [USER_REGISTRY] Computing HMAC for address (EIP-55): {}", addr_cs);
        info!("🔐 [USER_REGISTRY] Chain code: 0x{}", hex::encode(&self.chain_code));
        info!("🔐 [USER_REGISTRY] Raw HMAC constant (32 bytes): 0x{}", hex::encode(&hmac_constant));

        // 5) Optional tweaked share: s_i' = s_i + t   with t = Scalar(hmac) reduced mod n
        let mut tweaked_secret_share = None;
        if let Some(secret_share) = dkg_secret_share {
            // SAFER: reduce 32 bytes mod n; never panic
            let hmac_scalar = Scalar::from_repr(hmac_constant.into()).unwrap();
            info!("🔐 [USER_REGISTRY] HMAC constant converted to scalar (reduced): {:?}", hmac_scalar);

            let tweaked_scalar = *secret_share + hmac_scalar;
            info!("🔑 [USER_REGISTRY] Computed tweaked secret share for {}: s_i' = s_i + t (stored privately)", addr_cs);
            tweaked_secret_share = Some(SerializableScalar(tweaked_scalar));
        }

        // 6) Persist normalized address in the record
        let registration = UserRegistration {
            user_id: user_id.clone(),
            ethereum_address: addr_cs.clone(),   // store canonical EIP-55
            hmac_constant,
            tweaked_secret_share,
            user_group_key: None,
            derived_eth_address: None,
            derived_btc_address: None,
            created_at: Utc::now(),
            registered_by_node: node_id.to_string(),
        };

        // 7) Store user and canonical index
        {
            let mut users = self.users.write().await;
            users.insert(user_id.clone(), registration.clone());
        }
        {
            let mut address_map = self.address_to_user.write().await;
            address_map.insert(addr_cs, user_id);
            // OPTIONAL one-time migration aid:
            // address_map.insert(addr_cs.to_ascii_lowercase(), user_id.clone());
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

    pub async fn get_user_by_address(&self, ethereum_address: &str) -> Option<UserRegistration> {
        // normalize query to EIP-55
        let key = match checksum_from_any(ethereum_address) {
            Ok(cs) => cs,
            Err(_) => return None,
        };
    
        let address_map = self.address_to_user.read().await;
        if let Some(user_id) = address_map.get(&key) {
            let user_id = user_id.clone();
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

    /// Store the user-specific group public key derived from updated commitments
    pub async fn set_user_group_key(&self, ethereum_address: &str, group_key: ProjectivePoint) -> Result<(), String> {
        let affine = group_key.to_affine();
        let serial = SerializablePoint(affine);
        
        // Derive ETH and BTC addresses from the group key
        let derived_eth = crate::utils::get_eth_address_from_group_key(group_key);
        let derived_btc = crate::utils::get_btc_address_from_group_key(group_key);
        
        // Log the derived addresses
        info!("📬 [USER_REGISTRY] Derived ETH address for {}: {}", ethereum_address, derived_eth);
        info!("📬 [USER_REGISTRY] Derived BTC address for {}: {}", ethereum_address, derived_btc);

        // Lookup user id from address map for in-place mutation
        let address_map = self.address_to_user.read().await;
        if let Some(user_id) = address_map.get(ethereum_address) {
            let mut users = self.users.write().await;
            if let Some(user) = users.get_mut(user_id) {
                user.user_group_key = Some(serial);
                user.derived_eth_address = Some(derived_eth);
                user.derived_btc_address = Some(derived_btc);
                return Ok(());
            }
        }
        Err("User not found".to_string())
    }

    /// Set derived addresses for a user
    pub async fn set_derived_addresses(&self, ethereum_address: &str, eth_address: String, btc_address: String) -> Result<(), String> {
        let address_map = self.address_to_user.read().await;
        if let Some(user_id) = address_map.get(ethereum_address) {
            let mut users = self.users.write().await;
            if let Some(user) = users.get_mut(user_id) {
                user.derived_eth_address = Some(eth_address);
                user.derived_btc_address = Some(btc_address);
                return Ok(());
            }
        }
        Err("User not found".to_string())
    }

    /// Get the chain code (for debugging/testing purposes)
    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }
}

pub fn to_checksum_address(addr20: &[u8]) -> String {
    let hex_lower = hex::encode(addr20);                    // 40 lowercase hex chars
    let hash = Keccak256::digest(hex_lower.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in hex_lower.chars().enumerate() {
        if ch.is_ascii_hexdigit() && ch.is_ascii_lowercase() && ch >= 'a' {
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 { (byte >> 4) & 0x0f } else { byte & 0x0f };
            out.push(if nibble >= 8 { ch.to_ascii_uppercase() } else { ch });
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn checksum_from_any(s: &str) -> anyhow::Result<String> {
    let no0x = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if no0x.len() != 40 { anyhow::bail!("bad address length"); }
    let bytes = hex::decode(no0x)?;
    if bytes.len() != 20 { anyhow::bail!("bad address bytes"); }
    Ok(to_checksum_address(&bytes))
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
        assert!(registration.user_group_key.is_none()); // No group key provided
        assert!(registration.derived_eth_address.is_none());
        assert!(registration.derived_btc_address.is_none());
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
        assert!(registration.user_group_key.is_none()); // No group key provided
        assert!(registration.derived_eth_address.is_none());
        assert!(registration.derived_btc_address.is_none());
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