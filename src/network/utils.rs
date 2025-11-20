use anyhow::Result;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use tracing::{info, warn};

use crate::database::{keys, Database, DatabaseConfig};

use super::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Load existing keypair from database or create a new one
    pub async fn load_or_create_keypair() -> Result<(Keypair, PeerId)> {
        // Create database connection
        let db_config = DatabaseConfig::default();
        let database = Database::new(db_config)?;

        // Try to load existing keypair
        if let Some(keypair_bytes) = database.get_keypair(keys::PEER_KEYPAIR)? {
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

        // Save keypair to database
        let keypair_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("Failed to encode keypair: {}", e))?;
        database.put_keypair(keys::PEER_KEYPAIR, &keypair_bytes)?;

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

    /// Send a direct message to a specific peer
    pub async fn send_direct_message(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        use crate::types::ChannelMessage;

        self.message_tx
            .send(ChannelMessage::Unicast {
                peer_id: peer_id.to_string(),
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
                            info!(
                                "✅ [NETWORK] Found user's tweaked share for: {}",
                                eth_address
                            );
                            Some(tweaked_share.0) // Convert SerializableScalar to Scalar
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

    /// Execute contract call for a given transaction type and intent
    /// 
    /// This method delegates to MpcChainExecutor to keep contract execution
    /// logic separate from networking concerns.
    pub(crate) async fn execute_contract_call_for_transaction(
        &mut self,
        intent: &crate::types::DepositIntent,
        intent_hash: &str,
        transaction_type: crate::types::TransactionType,
        tx_hash: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
        amount: u128,
    ) -> Result<()> {
        if let Some(signing_node) = &mut self.signing_node {
            crate::chain_abstraction::MpcChainExecutor::execute_contract_call(
                signing_node,
                self.node_manager.as_ref(),
                self.dkg_node.as_ref(),
                intent,
                intent_hash,
                transaction_type,
                vault_group_key,
                amount,
                tx_hash,
            )
            .await
        } else {
            warn!("❌ [NETWORK] Signing node not available for contract call execution");
            Ok(())
        }
    }
}

