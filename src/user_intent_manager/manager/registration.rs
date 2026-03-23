use super::*;
use crate::utils::hmac_helper::{bytes_to_scalar_mod_n, hmac_scalar_mod_n};
use tracing::{error, info, warn};

impl UserIntentManager {
    /// Compute tweaked secret shares ONLY for users that are missing them (tweaked_secret_share = None).
    /// This is used after state sync to compute shares for newly imported users without
    /// touching existing users that already have valid shares from the original DKG signing.
    /// Observer nodes (no DKG final secret) skip computation — they hold user data for RPC queries only.
    pub async fn refresh_missing_user_tweaked_shares(&self) -> Result<usize> {
        info!("🔄 [DB_USER_REGISTRY] Computing tweaked shares for users with missing shares only");

        let dkg_storage = self.database_module.dkg_storage();
        let final_secret_share = match dkg_storage.get_final_secret().await? {
            Some(s) => {
                info!(
                    "🔐 [DB_USER_REGISTRY] DKG final_secret available for new user share computation"
                );
                s
            }
            None => {
                // Observer node — no DKG secret, cannot compute tweaked shares.
                // This is expected: observer nodes store user data for RPC queries
                // but never participate in signing.
                info!(
                    "ℹ️ [DB_USER_REGISTRY] No DKG final secret — this is an observer node. \
                     User data imported for RPC queries; tweaked shares not computed."
                );
                return Ok(0);
            }
        };

        let users: HashMap<String, UserRegistration> = self.user_storage.get_all_users().await?;
        let total = users.len();
        let mut computed_count: usize = 0;
        let mut already_have: usize = 0;

        for (address, mut user) in users.into_iter() {
            if user.tweaked_secret_share.is_some() {
                // User already has a valid tweaked share — do NOT touch it
                already_have += 1;
                continue;
            }

            // User is missing tweaked share (newly synced) — compute it
            info!(
                "🧮 [DB_USER_REGISTRY] Computing tweaked share for new user {} (user_id: {})",
                address, user.user_id
            );
            let new_tweaked = self.compute_tweaked_share(&final_secret_share, &user.hmac_constant);
            info!(
                "🔐 [DB_USER_REGISTRY] Computed tweaked share for {}",
                address
            );
            user.tweaked_secret_share = Some(new_tweaked);

            if let Err(e) = self.user_storage.store_user(&address, &user).await {
                error!(
                    "❌ [DB_USER_REGISTRY] Failed to store tweaked share for {}: {}",
                    address, e
                );
            } else {
                computed_count += 1;
            }
        }

        info!(
            "🎉 [DB_USER_REGISTRY] Completed refresh_missing: {} total users, {} already had shares, {} newly computed",
            total, already_have, computed_count
        );
        Ok(computed_count)
    }

    /// Compute tweaked secret shares ONLY for admins that are missing them (tweaked_secret_share = None).
    /// This is used after state sync to compute shares for newly imported admins without
    /// touching existing admins that already have valid shares from the original DKG signing.
    /// Observer nodes (no DKG final secret) skip computation — they hold admin data for RPC queries only.
    pub async fn refresh_missing_admin_tweaked_shares(&self) -> Result<usize> {
        info!(
            "🔄 [DB_ADMIN_REGISTRY] Computing tweaked shares for admins with missing shares only"
        );

        let dkg_storage = self.database_module.dkg_storage();
        let final_secret_share = match dkg_storage.get_final_secret().await? {
            Some(s) => {
                info!(
                    "🔐 [DB_ADMIN_REGISTRY] DKG final_secret available for admin share computation"
                );
                s
            }
            None => {
                // Observer node — no DKG secret, cannot compute tweaked shares.
                info!(
                    "ℹ️ [DB_ADMIN_REGISTRY] No DKG final secret — this is an observer node. \
                     Admin data imported for RPC queries; tweaked shares not computed."
                );
                return Ok(0);
            }
        };

        let admins: HashMap<String, crate::types::AdminRegistration> =
            self.user_storage.get_all_admins().await?;
        let total = admins.len();
        let mut computed_count: usize = 0;
        let mut already_have: usize = 0;

        for (address, mut admin) in admins.into_iter() {
            if admin.tweaked_secret_share.is_some() {
                already_have += 1;
                continue;
            }

            // Admin is missing tweaked share (newly synced) — compute it
            info!(
                "🧮 [DB_ADMIN_REGISTRY] Computing tweaked share for admin {} (admin_id: {})",
                address, admin.admin_id
            );
            let new_tweaked = self.compute_tweaked_share(&final_secret_share, &admin.hmac_constant);
            admin.tweaked_secret_share = Some(new_tweaked);

            if let Err(e) = self.user_storage.store_admin(&address, &admin).await {
                error!(
                    "❌ [DB_ADMIN_REGISTRY] Failed to store tweaked share for admin {}: {}",
                    address, e
                );
            } else {
                // Compute and store admin share pubkeys for all peers
                if let Err(e) = dkg_storage
                    .compute_and_store_user_share_pubkeys_for_user(&address, &admin.hmac_constant)
                    .await
                {
                    warn!(
                        "⚠️ [DB_ADMIN_REGISTRY] Failed to compute admin share pubkeys for {}: {}",
                        address, e
                    );
                }
                computed_count += 1;
            }
        }

        info!(
            "🎉 [DB_ADMIN_REGISTRY] Completed refresh_missing_admin: {} total admins, {} already had shares, {} newly computed",
            total, already_have, computed_count
        );
        Ok(computed_count)
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
            Err(e) => return Err(format!("Invalid tics_address '{tics_address}': {e}")),
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
            info!(
                "🔐 [DB_USER_REGISTRY] Computing tweaked share for {} at registration",
                addr_cs
            );
            let tweaked_share = self.compute_tweaked_share(share, &registration.hmac_constant);
            info!(
                "🔐 [DB_USER_REGISTRY] Initial tweaked share computed for {}",
                addr_cs
            );
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
                    .compute_and_store_user_share_pubkeys_for_user(
                        &addr_cs,
                        &registration.hmac_constant,
                    )
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
        hmac_scalar_mod_n(tics_address, &self.chain_code).expect("Failed to generate HMAC constant")
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

    // ==================== Admin Registration ====================

    /// Register a new admin (stored separately under "admin:" prefix)
    pub async fn register_admin(
        &self,
        tics_address: &str,
        dkg_secret_share: Option<&Scalar>,
        node_id: &str,
    ) -> Result<crate::types::AdminRegistration, String> {
        info!(
            "👤 [DB_ADMIN_REGISTRY] register_admin called - Address: {}, Node: {}",
            tics_address, node_id
        );

        // 1) Normalize to canonical EIP-55
        let addr_cs = match checksum_from_any(tics_address) {
            Ok(a) => a,
            Err(e) => return Err(format!("Invalid tics_address '{tics_address}': {e}")),
        };

        // 2) Check if admin already registered
        if self
            .user_storage
            .contains_admin(&addr_cs)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err("Admin already registered".to_string());
        }

        // 3) Generate admin ID and HMAC constant
        let admin_id = Uuid::new_v4().to_string();
        let hmac_constant = self.generate_hmac_constant(&addr_cs);

        // 4) Create admin registration
        let mut registration = crate::types::AdminRegistration {
            admin_id: admin_id.clone(),
            tics_address: addr_cs.clone(),
            hmac_constant,
            tweaked_secret_share: None,
            user_group_key: None,
            derived_eth_address: None,
            derived_btc_address: None,
            created_at: Utc::now(),
            registered_by_node: node_id.to_string(),
        };

        // 5) Process DKG share if provided
        if let Some(share) = dkg_secret_share {
            info!(
                "🔐 [DB_ADMIN_REGISTRY] Computing tweaked share for admin {} at registration",
                addr_cs
            );
            let tweaked_share = self.compute_tweaked_share(share, &registration.hmac_constant);
            registration.tweaked_secret_share = Some(tweaked_share);
        }

        // 6) Store in database under "admin:" prefix
        match self.user_storage.store_admin(&addr_cs, &registration).await {
            Ok(()) => {
                info!("🎉 [DB_ADMIN_REGISTRY] Admin registration SUCCESSFULLY stored in database!");
                info!("  📧 Final address: {}", addr_cs);
                info!("  🆔 Final admin ID: {}", admin_id);

                // Compute and store admin share pubkeys for all peers
                let dkg_storage = self.database_module.dkg_storage();
                if let Err(e) = dkg_storage
                    .compute_and_store_user_share_pubkeys_for_user(
                        &addr_cs,
                        &registration.hmac_constant,
                    )
                    .await
                {
                    warn!(
                        "⚠️ [DB_ADMIN_REGISTRY] Failed to compute admin share pubkeys for {}: {}",
                        addr_cs, e
                    );
                } else {
                    info!(
                        "✅ [DB_ADMIN_REGISTRY] Successfully computed and stored admin share pubkeys for {}",
                        addr_cs
                    );
                }

                Ok(registration)
            }
            Err(e) => {
                error!("💥 [DB_ADMIN_REGISTRY] FAILED to store admin registration in database!");
                error!("  📧 Address: {}", addr_cs);
                error!("  💥 Database error: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Get admin registration by TICS address
    pub async fn get_admin_by_address(
        &self,
        tics_address: &str,
    ) -> Option<crate::types::AdminRegistration> {
        match self.user_storage.get_admin(tics_address).await {
            Ok(admin) => admin,
            Err(e) => {
                tracing::error!("Failed to get admin by address {}: {}", tics_address, e);
                None
            }
        }
    }

    /// Set admin group key and derived addresses
    pub async fn set_admin_group_key(
        &self,
        tics_address: &str,
        group_key: k256::ProjectivePoint,
    ) -> Result<(), String> {
        let affine = group_key.to_affine();
        let serial = SerializablePoint(affine);

        let derived_eth = crate::utils::get_eth_address_from_group_key(group_key);
        let derived_btc = crate::utils::get_btc_address_from_group_key(group_key);

        info!(
            "📬 [DB_ADMIN_REGISTRY] Derived ETH address for admin {}: {}",
            tics_address, derived_eth
        );
        info!(
            "📬 [DB_ADMIN_REGISTRY] Derived BTC address for admin {}: {}",
            tics_address, derived_btc
        );

        self.user_storage
            .update_admin_group_key_and_addresses(
                tics_address,
                &serial,
                Some(derived_eth),
                Some(derived_btc),
            )
            .await
            .map_err(|e| e.to_string())?;

        info!(
            "✅ [DB_ADMIN_REGISTRY] Set admin group key and derived addresses for {}",
            tics_address
        );
        Ok(())
    }
}
