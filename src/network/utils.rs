use anyhow::Result;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use std::sync::Arc;
use tracing::{info, warn};

use crate::database::{keys, KeyStore};

use crate::network::transport::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Load existing keypair from keystore or create a new one
    ///
    /// Accepts a KeyStore implementation (e.g., Database, remote KMS) to allow
    /// the MPC stack to control the identity lifecycle and swap storage backends
    /// without changing keypair management logic.
    pub async fn load_or_create_keypair(keystore: Arc<dyn KeyStore>) -> Result<(Keypair, PeerId)> {
        // Try to load existing keypair
        if let Some(keypair_bytes) = keystore.get_keypair(keys::PEER_KEYPAIR)? {
            match Keypair::from_protobuf_encoding(&keypair_bytes) {
                Ok(keypair) => {
                    let peer_id = PeerId::from(keypair.public());
                    info!("🔄 Loaded existing keypair - Peer ID: {}", peer_id);
                    return Ok((keypair, peer_id));
                }
                Err(e) => {
                    warn!(
                        "⚠️ Failed to decode existing keypair: {}. Generating new one.",
                        e
                    );
                }
            }
        } else {
            info!("🆕 No existing keypair found. Generating new one.");
        }

        // Generate new keypair
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        // Save keypair to keystore
        let keypair_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("Failed to encode keypair: {}", e))?;
        keystore.put_keypair(keys::PEER_KEYPAIR, &keypair_bytes)?;

        info!("✅ Generated and saved new keypair - Peer ID: {}", peer_id);
        Ok((keypair, peer_id))
    }

    /// Broadcast a user registration to all other nodes in the P2P network
    pub async fn broadcast_user_registration(
        &self,
        ethereum_address: &str,
        node_id: &str,
    ) -> Result<()> {
        use crate::types::{ChannelMessage, GossipsubMessage};

        let registration_msg = GossipsubMessage::UserRegistration {
            ethereum_address: ethereum_address.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            node_id: node_id.to_string(),
        };

        let msg_bytes = serde_json::to_vec(&registration_msg)
            .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

        // Send via the message channel to be broadcast by the swarm
        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "user-registrations".to_string(),
                data: msg_bytes,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send user registration broadcast: {}", e))?;

        info!(
            "📡 Broadcasted user registration for {} from node {} to P2P network",
            ethereum_address, node_id
        );
        Ok(())
    }

    /// Broadcast a message to a specific topic
    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        use crate::types::ChannelMessage;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;
        Ok(())
    }

    /// Get the appropriate signing key based on the user eth address
    pub(crate) async fn get_signing_key_for_user(
        &self,
        user_eth_address: Option<&String>,
    ) -> Option<k256::Scalar> {
        if let Some(eth_address) = user_eth_address {
            // Use user-specific tweaked share
            info!(
                "🔑 [NETWORK] Using user-specific tweaked share for signing - User: {}",
                eth_address
            );

            if let Some(user_intent_manager) = &self.user_intent_manager {
                match user_intent_manager.get_user_by_address(eth_address).await {
                    Some(user) => {
                        if let Some(tweaked_share) = &user.tweaked_secret_share {
                            let share_scalar = tweaked_share.0;
                            // Derive pubkey from this scalar for debug
                            let secp = secp256k1::Secp256k1::new();
                            let sk = secp256k1::SecretKey::from_slice(&share_scalar.to_bytes())
                                .unwrap_or_else(|_| {
                                    secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap()
                                });
                            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

                            info!(
                                "✅ [NETWORK] Found user's tweaked share for: {}\n\
                                 \tTweaked Share PubKey (Self-Calc): 0x{}",
                                eth_address,
                                hex::encode(pk.serialize())
                            );

                            Some(share_scalar)
                        } else {
                            warn!(
                                "❌ [NETWORK] User {} has no tweaked share available",
                                eth_address
                            );
                            None
                        }
                    }
                    None => {
                        warn!("❌ [NETWORK] User {} not found in registry", eth_address);
                        None
                    }
                }
            } else {
                warn!("❌ [NETWORK] User registry not available");
                None
            }
        } else {
            // Use network's original DKG share
            info!("🔑 [NETWORK] Using network's original DKG share for signing");

            if let Some(dkg_node) = &self.dkg_node {
                if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                    info!("✅ [NETWORK] Found network's DKG share");
                    Some(secret_share)
                } else {
                    warn!("❌ [NETWORK] DKG not completed yet, no secret share available");
                    None
                }
            } else {
                warn!("❌ [NETWORK] DKG node not available");
                None
            }
        }
    }

    // Contract call helpers for user-to-vault have been removed; contract execution is skipped for that flow.

    /// Execute solver add-liquidity operation directly (sequencer removed)
    pub(crate) async fn submit_solver_add_liquidity_to_sequencer(
        &mut self,
        solver_address: &str,
        solver_id: &str,
        asset_chain_name: &str,
        amount: u128,
        request_id: &str,
    ) -> Result<()> {
        // Execute directly - sequencer removed
        self.submit_solver_add_liquidity_contract_update(
            solver_address,
            solver_id,
            asset_chain_name,
            amount,
            None, // No request_id
            None, // No original_request
        )
        .await
    }

    // ----------------------------------------------------------------------------
    // Network transaction helper functions (sequencer removed, will be replaced with pool approach)
    // ----------------------------------------------------------------------------

    /// Submit a NetworkToTarget transaction (sequencer removed - stub for future pool implementation)
    pub(crate) async fn submit_network_to_target_to_sequencer(
        &mut self,
        _intent: &crate::types::DepositIntent,
        intent_hash: &str,
        _amount: u128,
        _tx_bytes: Vec<u8>,
        _eth_tx: crate::chain_abstraction::EthereumTransaction,
        _user_tweaked_share: Option<k256::Scalar>,
        _user_eth_address: Option<String>,
    ) -> Result<()> {
        // Sequencer removed - will be replaced with pool approach later
        info!(
            "📋 [NETWORK] NetworkToTarget transaction helper called (sequencer removed, pool approach pending): intent_hash={}",
            intent_hash
        );
        Ok(())
    }

    /// Submit a withdraw liquidity transaction (sequencer removed - stub for future pool implementation)
    pub(crate) async fn submit_withdraw_liquidity_to_sequencer(
        &mut self,
        solver_address: &str,
        eth_address: &str,
        amount: u128,
        _tx_bytes: Vec<u8>,
        _eth_tx: crate::chain_abstraction::EthereumTransaction,
    ) -> Result<()> {
        // Sequencer removed - will be replaced with pool approach later
        info!(
            "📋 [NETWORK] WithdrawLiquidity transaction helper called (sequencer removed, pool approach pending): solver={}, eth_address={}, amount={}",
            solver_address, eth_address, amount
        );
        Ok(())
    }

    /// Submit a reward payout transaction (sequencer removed - stub for future pool implementation)
    pub(crate) async fn submit_reward_payout_to_sequencer(
        &mut self,
        solver_address: &str,
        eth_address: &str,
        amount: u128,
        _tx_bytes: Vec<u8>,
        _eth_tx: crate::chain_abstraction::EthereumTransaction,
    ) -> Result<()> {
        // Sequencer removed - will be replaced with pool approach later
        info!(
            "📋 [NETWORK] RewardPayout transaction helper called (sequencer removed, pool approach pending): solver={}, eth_address={}, amount={}",
            solver_address, eth_address, amount
        );
        Ok(())
    }

    /// Submit a solver withdraw-liquidity contract update to the sequencer
    pub(crate) async fn submit_solver_withdraw_liquidity_to_sequencer(
        &mut self,
        solver_address: &str,
        asset_chain_name: &str,
        amount: u128,
        payout_tx_hash: &str,
    ) -> Result<()> {
        if amount == 0 {
            info!(
                "⏭️ [NETWORK] Skipping withdraw-liquidity sequencing for solver {} (amount=0)",
                solver_address
            );
            return Ok(());
        }

        // Execute directly - sequencer removed
        self.submit_solver_liquidity_contract_update(
            solver_address,
            asset_chain_name,
            amount,
            payout_tx_hash,
            None, // No request_id
            None, // No original_request
        )
        .await
    }

    /// Submit a solver claim-reward contract update to the sequencer
    pub(crate) async fn submit_solver_claim_reward_to_sequencer(
        &mut self,
        solver_address: &str,
        reward_btc: Option<u128>,
        reward_tics: Option<u128>,
        payout_tx_hash: &str,
    ) -> Result<()> {
        if reward_btc.is_none() && reward_tics.is_none() {
            info!(
                "⏭️ [NETWORK] Skipping claim-reward sequencing for solver {} (both rewards are None)",
                solver_address
            );
            return Ok(());
        }

        if reward_btc.unwrap_or(0) == 0 && reward_tics.unwrap_or(0) == 0 {
            info!(
                "⏭️ [NETWORK] Skipping claim-reward sequencing for solver {} (both rewards are zero)",
                solver_address
            );
            return Ok(());
        }

        // Execute directly - sequencer removed
        self.submit_solver_reward_contract_update(
            solver_address,
            reward_btc,
            reward_tics,
            payout_tx_hash,
            None, // No request_id
            None, // No original_request
        )
        .await
    }

    /// Execute refund intent contract call directly (sequencer removed)
    pub(crate) async fn submit_refund_intent_to_sequencer(
        &mut self,
        intent_id: &str,
        transaction_hash: &str,
        timestamp: &str,
        reason: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
    ) -> Result<()> {
        // Execute refund intent contract call directly - sequencer removed
        if let Some(signing_node) = &mut self.signing_node {
            crate::utils::contract::execute_refund_intent_contract_call(
                signing_node,
                self.node_manager.as_ref(),
                self.dkg_node.as_ref(),
                intent_id,
                transaction_hash,
                timestamp,
                reason,
                vault_group_key,
                None, // No request_id
                None, // No original_request
            )
            .await
        } else {
            warn!("❌ [NETWORK] Signing node not available for refund intent contract call execution");
            Ok(())
        }
    }


    /// Process a single contract transaction (sequencer removed - method kept for compatibility but unused)
    #[allow(dead_code)]
    /// Process a single contract transaction (sequencer removed - method kept for compatibility but unused)
    #[allow(dead_code)]
    pub(crate) async fn process_contract_transaction(
        &mut self,
        _request: (),
    ) -> Result<()> {
        // Contract sequencer removed - transactions are executed directly
        Ok(())
    }
}

/// Parse semantic version string into (major, minor, patch)
pub fn parse_semantic_version(version: &str) -> Result<(u32, u32, u32)> {
    use anyhow::anyhow;

    let parts: Vec<&str> = version.split('.').collect();

    if parts.len() != 3 {
        return Err(anyhow!("Invalid semantic version format: {}", version));
    }

    Ok((
        parts[0]
            .parse()
            .map_err(|e| anyhow!("Invalid major version: {}", e))?,
        parts[1]
            .parse()
            .map_err(|e| anyhow!("Invalid minor version: {}", e))?,
        parts[2]
            .parse()
            .map_err(|e| anyhow!("Invalid patch version: {}", e))?,
    ))
}
