use crate::types::TransactionType;
use crate::user_intent_manager::UserIntentManager;
use anyhow::{anyhow, Result};
use k256::{EncodedPoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct KeyStore {
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    group_public_key: Option<ProjectivePoint>,
    vault_group_key: Option<ProjectivePoint>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
            group_public_key: None,
            vault_group_key: None,
        }
    }

    pub fn generate_key_pair(&mut self, id: &str) -> Result<()> {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (private_key, public_key) = secp.generate_keypair(&mut rng);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        info!("🔐 [SIGNING] Node {} generated ECDSA key pair", id);
        info!("🔑 [SIGNING] Public key set");
        Ok(())
    }

    pub fn set_private_key(&mut self, private_key: SecretKey, id: &str) {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        info!("🔐 [SIGNING] Node {} private key set", id);
    }

    pub fn set_private_key_from_scalar(&mut self, scalar: Scalar, id: &str) -> Result<()> {
        let secret_key = match Self::derive_secp_secret(&scalar) {
            Ok(key) => key,
            Err(err) => {
                error!(
                    "❌ [SIGNING] Node {} failed to set private key from scalar: {}",
                    id, err
                );
                return Err(err);
            }
        };

        info!("🔐 [SIGNING] Node {} private key set from scalar", id);

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        info!("🔑 [SIGNING] Node {} public key set", id);

        self.private_key = Some(secret_key);
        self.public_key = Some(public_key);

        info!(
            "🔐 [SIGNING] Node {} private key set from scalar with proper Ethereum conversion",
            id
        );
        Ok(())
    }

    pub fn derive_secp_secret(scalar: &Scalar) -> Result<SecretKey> {
        SecretKey::from_slice(scalar.to_bytes().as_slice())
            .map_err(|e| anyhow!("Invalid secp256k1 scalar: {}", e))
    }

    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    pub fn private_key(&self) -> Option<&SecretKey> {
        self.private_key.as_ref()
    }

    pub fn clone_private_key(&self) -> Option<SecretKey> {
        self.private_key
    }

    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    pub fn set_group_public_key(&mut self, group_key: ProjectivePoint, id: &str) {
        info!("🔑 [SIGNING] Setting DKG group public key for node {}", id);
        self.group_public_key = Some(group_key);
    }

    pub fn set_vault_group_key(&mut self, vault_group_key: ProjectivePoint, id: &str) {
        info!(
            "🔑 [SIGNING] Setting vault group public key for node {}",
            id
        );
        self.vault_group_key = Some(vault_group_key);
    }

    pub fn get_group_public_key(&self) -> Option<ProjectivePoint> {
        self.group_public_key
    }

    pub fn get_vault_group_key(&self) -> Option<ProjectivePoint> {
        self.vault_group_key
    }

    pub async fn get_group_public_key_bytes(
        &self,
        transaction_type: Option<TransactionType>,
        user_eth_address: Option<String>,
        user_intent_manager: Option<&Arc<UserIntentManager>>,
    ) -> Result<Vec<u8>> {
        match transaction_type {
            Some(TransactionType::UserToVault) => {
                if let Some(user_addr) = &user_eth_address {
                    if let Some(user_intent_manager) = user_intent_manager {
                        if let Some(user) = user_intent_manager.get_user_by_address(user_addr).await
                        {
                            if let Some(user_group_key) = &user.user_group_key {
                                let affine_point = user_group_key.0;
                                let encoded_point = EncodedPoint::from(affine_point);
                                let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                                info!(
                                    "🔑 [SIGNING] UserToVault: Using user-specific group public key for {}",
                                    user_addr
                                );
                                Ok(compressed_bytes)
                            } else {
                                Err(anyhow!(
                                    "User {} has no group key available - ensure user registration and key derivation is completed",
                                    user_addr
                                ))
                            }
                        } else {
                            Err(anyhow!("User {} not found in registry", user_addr))
                        }
                    } else {
                        Err(anyhow!(
                            "User registry not available for UserToVault transaction"
                        ))
                    }
                } else {
                    Err(anyhow!("UserToVault transaction requires user_eth_address"))
                }
            }
            Some(TransactionType::NetworkToTarget) | Some(TransactionType::Refund) | Some(TransactionType::IntentStatusUpdate) => {
                // Refund and IntentStatusUpdate use network group key (same as NetworkToTarget)
                if let Some(group_key) = self.group_public_key {
                    let affine_point = group_key.to_affine();
                    let encoded_point = EncodedPoint::from(affine_point);
                    let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                    info!("🔑 [SIGNING] NetworkToTarget/Refund/IntentStatusUpdate: Using DKG group public key");
                    Ok(compressed_bytes)
                } else {
                    Err(anyhow!(
                        "DKG group public key not available for NetworkToTarget/Refund/IntentStatusUpdate transaction - ensure DKG process is completed"
                    ))
                }
            }
            Some(TransactionType::RewardTxn) => {
                // IMPORTANT: RewardTxn and WithdrawLiquidity must use the same network group public key
                // Both transactions are signed by the network group key (via network DKG secret share)
                // and verified against individual partial public keys (network share pubkeys)
                if let Some(group_key) = self.group_public_key {
                    let affine_point = group_key.to_affine();
                    let encoded_point = EncodedPoint::from(affine_point);
                    let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                    info!("🔑 [SIGNING] RewardTxn: Using DKG group public key");
                    Ok(compressed_bytes)
                } else {
                    Err(anyhow!(
                        "DKG group public key not available for RewardTxn transaction - ensure DKG process is completed"
                    ))
                }
            }
            Some(TransactionType::WithdrawLiquidity) => {
                // IMPORTANT: RewardTxn and WithdrawLiquidity must use the same network group public key
                // Both transactions are signed by the network group key (via network DKG secret share)
                // and verified against individual partial public keys (network share pubkeys)
                if let Some(group_key) = self.group_public_key {
                    let affine_point = group_key.to_affine();
                    let encoded_point = EncodedPoint::from(affine_point);
                    let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                    info!("🔑 [SIGNING] WithdrawLiquidity: Using DKG group public key");
                    Ok(compressed_bytes)
                } else {
                    Err(anyhow!(
                        "DKG group public key not available for WithdrawLiquidity transaction - ensure DKG process is completed"
                    ))
                }
            }
            None => {
                if let Some(group_key) = self.group_public_key {
                    let affine_point = group_key.to_affine();
                    let encoded_point = EncodedPoint::from(affine_point);
                    let compressed_bytes = encoded_point.compress().to_bytes().to_vec();

                    info!("🔑 [SIGNING] Fallback: Using DKG group public key");
                    Ok(compressed_bytes)
                } else {
                    Err(anyhow!(
                        "DKG group public key not available - ensure DKG process is completed"
                    ))
                }
            }
        }
    }
}
