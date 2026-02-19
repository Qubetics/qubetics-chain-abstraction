use super::*;
use crate::utils::hmac_helper::{bytes_to_scalar_mod_n, hmac_scalar_mod_n};
use tracing::{error, info, warn};

impl UserIntentManager {
    /// Recompute and update tweaked secret shares for all users using the latest final secret
    pub async fn refresh_all_user_tweaked_shares(&self) -> Result<()> {
        info!("🔄 [DB_USER_REGISTRY] Starting refresh_all_user_tweaked_shares for all users");

        // Access latest final secret share from DKG storage
        let dkg_storage = self.database_module.dkg_storage();
        let final_secret_share = match dkg_storage.get_final_secret().await? {
            Some(s) => s,
            None => {
                return Err(anyhow::anyhow!(
                    "No final secret share found in DKG storage"
                ))
            }
        };

        // Fetch all users
        let users: HashMap<String, UserRegistration> = self.user_storage.get_all_users().await?;
        info!(
            "👥 [DB_USER_REGISTRY] Users loaded for refresh: {}",
            users.len()
        );

        let mut success_count: usize = 0;
        let mut failure_count: usize = 0;

        // Iterate and recompute tweaked share for each user based on their HMAC constant
        for (address, mut user) in users.into_iter() {
            info!(
                "🧮 [DB_USER_REGISTRY] Recomputing tweaked share for {} (user_id: {})",
                address, user.user_id
            );
            let new_tweaked = self.compute_tweaked_share(&final_secret_share, &user.hmac_constant);
            user.tweaked_secret_share = Some(new_tweaked);

            // Persist updated user
            if let Err(e) = self.user_storage.store_user(&address, &user).await {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to update tweaked share for {}: {}",
                    address, e
                );
                failure_count += 1;
            } else {
                info!(
                    "✅ [DB_USER_REGISTRY] Updated tweaked secret share for {}",
                    address
                );
                success_count += 1;
            }
        }

        info!(
            "🎉 [DB_USER_REGISTRY] Completed refresh_all_user_tweaked_shares: {} success, {} failed",
            success_count,
            failure_count
        );
        Ok(())
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        tics_address: &str,
        dkg_secret_share: Option<&Scalar>,
        node_id: &str,
    ) -> Result<UserRegistration, String> {
        info!(
            "👤 [DB_USER_REGISTRY] register_user called - Address: {}, Node: {}",
            tics_address, node_id
        );

        // 1) Normalize to canonical EIP-55
        let addr_cs = match checksum_from_any(tics_address) {
            Ok(a) => a,
            Err(e) => {
                return Err(format!(
                    "Invalid tics_address '{tics_address}': {e}"
                ))
            }
        };

        // 2) Dedup on canonical key
        if self
            .user_storage
            .contains_user(&addr_cs)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err("User already registered".to_string());
        }

        // 3) Generate user ID and HMAC constant
        let user_id = Uuid::new_v4().to_string();
        let hmac_constant = self.generate_hmac_constant(&addr_cs);

        // 4) Create registration
        let mut registration = UserRegistration {
            user_id: user_id.clone(),
            tics_address: addr_cs.clone(),
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

        // 6) Store in database
        info!("💾 [DB_USER_REGISTRY] Preparing to store user registration in database");
        info!("  📧 TICS address: {}", addr_cs);
        info!("  🆔 User ID: {}", user_id);
        info!(
            "  🔑 Has tweaked secret share: {:?}",
            registration.tweaked_secret_share.is_some()
        );
        info!(
            "  🔑 Has user group key: {}",
            registration.user_group_key.is_some()
        );

        match self.user_storage.store_user(&addr_cs, &registration).await {
            Ok(()) => {
                info!("🎉 [DB_USER_REGISTRY] User registration SUCCESSFULLY stored in database!");
                info!("  📧 Final address: {}", addr_cs);
                info!("  🆔 Final user ID: {}", user_id);
                info!("  📅 Registration timestamp: {}", registration.created_at);
                
                // Compute and store user share pubkeys for all peers
                let dkg_storage = self.database_module.dkg_storage();
                if let Err(e) = dkg_storage
                    .compute_and_store_user_share_pubkeys_for_user(&addr_cs, &registration.hmac_constant)
                    .await
                {
                    warn!(
                        "⚠️ [DB_USER_REGISTRY] Failed to compute user share pubkeys for {}: {}",
                        addr_cs, e
                    );
                } else {
                    info!(
                        "✅ [DB_USER_REGISTRY] Successfully computed and stored user share pubkeys for {}",
                        addr_cs
                    );
                    
                    // Log stored share pubkeys for this user for verification
                    if let Err(e) = dkg_storage.log_all_stored_share_pubkeys().await {
                        warn!(
                            "⚠️ [DB_USER_REGISTRY] Failed to log stored share pubkeys: {}",
                            e
                        );
                    }
                }
                
                info!("✅ User registration process COMPLETED for: {}", addr_cs);
                Ok(registration)
            }
            Err(e) => {
                error!("💥 [DB_USER_REGISTRY] FAILED to store user registration in database!");
                error!("  📧 Address: {}", addr_cs);
                error!("  🆔 User ID: {}", user_id);
                error!("  💥 Database error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Get user registration by user ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Option<UserRegistration> {
        // Since we store by tics_address, we need to search through all users
        match self.user_storage.get_all_users().await {
            Ok(users) => users
                .into_iter()
                .find(|(_, user)| user.user_id == user_id)
                .map(|(_, user)| user),
            Err(e) => {
                tracing::error!("Failed to search for user by ID {}: {}", user_id, e);
                None
            }
        }
    }

    /// Get user registration by TICS address
    pub async fn get_user_by_address(&self, tics_address: &str) -> Option<UserRegistration> {
        info!(
            "🔍 [DB_USER_REGISTRY] get_user_by_address called - Address: {}",
            tics_address
        );

        match self.user_storage.get_user(tics_address).await {
            Ok(user) => {
                info!(
                    "🔍 [DB_USER_REGISTRY] get_user_by_address result - Address: {}, Found: {}",
                    tics_address,
                    user.is_some()
                );
                user
            }
            Err(e) => {
                tracing::error!("Failed to get user by address {}: {}", tics_address, e);
                None
            }
        }
    }

    /// Get all registered users
    pub async fn get_all_users(&self) -> Vec<UserRegistration> {
        match self.user_storage.get_all_users().await {
            Ok(users) => users.into_values().collect(),
            Err(e) => {
                tracing::error!("Failed to get all users: {}", e);
                Vec::new()
            }
        }
    }

    /// Get the HMAC constant for a user
    pub async fn get_hmac_constant(&self, tics_address: &str) -> Option<[u8; 32]> {
        if let Some(registration) = self.get_user_by_address(tics_address).await {
            Some(registration.hmac_constant)
        } else {
            None
        }
    }

    /// Set user group key and derived addresses
    pub async fn set_user_group_key(
        &self,
        tics_address: &str,
        group_key: ProjectivePoint,
    ) -> Result<(), String> {
        let affine = group_key.to_affine();
        let serial = SerializablePoint(affine);

        // Derive ETH and BTC addresses from the group key
        let derived_eth = crate::utils::get_eth_address_from_group_key(group_key);
        let derived_btc = crate::utils::get_btc_address_from_group_key(group_key);

        // Log the derived addresses
        info!(
            "📬 [DB_USER_REGISTRY] Derived ETH address for {}: {}",
            tics_address, derived_eth
        );
        info!(
            "📬 [DB_USER_REGISTRY] Derived BTC address for {}: {}",
            tics_address, derived_btc
        );

        // Update user group key in database
        self.user_storage
            .update_user_group_key(tics_address, &serial)
            .await
            .map_err(|e| e.to_string())?;

        // Update derived addresses
        self.user_storage
            .update_derived_addresses(tics_address, Some(derived_eth), Some(derived_btc))
            .await
            .map_err(|e| e.to_string())?;

        info!(
            "✅ [DB_USER_REGISTRY] Set user group key and derived addresses for {}",
            tics_address
        );
        Ok(())
    }

    /// Generate HMAC constant for a user
    /// Uses hmac_scalar_mod_n to safely reduce modulo curve order
    fn generate_hmac_constant(&self, tics_address: &str) -> [u8; 32] {
        hmac_scalar_mod_n(tics_address, &self.chain_code)
            .expect("Failed to generate HMAC constant")
    }

    /// Compute tweaked share from DKG share and HMAC constant
    /// Safely reduces hmac_constant modulo curve order before converting to scalar
    fn compute_tweaked_share(
        &self,
        share: &Scalar,
        hmac_constant: &[u8; 32],
    ) -> SerializableScalar {
        // Reduce modulo curve order to ensure valid scalar (works with both old and new hmac_constants)
        let hmac_reduced = bytes_to_scalar_mod_n(hmac_constant);
        // from_repr will always succeed since hmac_reduced is already reduced mod curve order
        let hmac_scalar = Scalar::from_repr(hmac_reduced.into())
            .expect("Failed to create scalar from reduced HMAC (should never fail)");
        let tweaked_scalar = *share + hmac_scalar;
        SerializableScalar(tweaked_scalar)
    }

    /// Get the chain code
    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    /// Check if a user is registered
    pub async fn is_user_registered(&self, tics_address: &str) -> bool {
        match self.user_storage.contains_user(tics_address).await {
            Ok(exists) => exists,
            Err(e) => {
                tracing::error!(
                    "Failed to check if user is registered {}: {}",
                    tics_address,
                    e
                );
                false
            }
        }
    }

    /// Get users by registration node
    pub async fn get_users_by_node(&self, node_id: &str) -> Vec<UserRegistration> {
        match self.user_storage.get_all_users().await {
            Ok(users) => users
                .into_iter()
                .filter(|(_, user)| user.registered_by_node == node_id)
                .map(|(_, user)| user)
                .collect(),
            Err(e) => {
                tracing::error!("Failed to get users by node {}: {}", node_id, e);
                Vec::new()
            }
        }
    }
}
