use anyhow::Result;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use tracing::{info, warn};

use crate::database::{keys, Database, DatabaseConfig};

use super::types::NetworkLayer;

impl NetworkLayer {
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
    pub(crate) async fn execute_contract_call_for_transaction(
        &mut self,
        intent: &crate::types::DepositIntent,
        intent_hash: &str,
        transaction_type: crate::types::TransactionType,
        tx_hash: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
        amount: u128,
    ) -> Result<()> {
        use tracing::debug;

        if let Some(signing_node) = &mut self.signing_node {
            info!(
                "📝 [CONTRACT] Executing contract call for transaction type: {:?}",
                transaction_type
            );

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            let contract_call_result =
                crate::utils::transaction::create_chain_transaction_from_contract_call(
                    vault_group_key,
                    amount,
                    intent,
                    intent_hash,
                    tx_hash,
                    transaction_type.clone(),
                )
                .await;

            match contract_call_result {
                Ok(contract_transaction) => {
                    info!("📝 [CONTRACT] Created contract call transaction");
                    let available_nodes: Vec<PeerId> =
                        self.node_manager.get_active_nodes().into_iter().collect();
                    signing_node.set_available_nodes(available_nodes);

                    match contract_transaction {
                        crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                            let contract_tx = crate::types::ContractTransaction {
                                to: eth_tx.to.clone(),
                                value: eth_tx.value.clone(),
                                nonce: eth_tx.nonce,
                                gas_limit: eth_tx.gas_limit,
                                gas_price: eth_tx.gas_price.clone(),
                                chain_id: eth_tx.chain_id,
                                data: eth_tx
                                    .data
                                    .as_ref()
                                    .map(|d| format!("0x{}", hex::encode(d)))
                                    .unwrap_or_else(|| "0x".to_string()),
                            };
                            let contract_tx_bytes =
                                crate::utils::transaction::create_transaction_for_signing_contract(
                                    &contract_tx,
                                );
                            debug!(
                                "→ RLP payload contract call: 0x{}",
                                hex::encode(&contract_tx_bytes)
                            );

                            let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                dkg_node.get_vault_tweaked_secret_share().await
                            } else {
                                None
                            };
                            signing_node
                                .sign_contract_message(
                                    contract_tx_bytes,
                                    &contract_tx,
                                    vault_tweaked_share,
                                    None,
                                )
                                .await?;
                        }
                        _ => {
                            info!("📝 [CONTRACT] Contract call transaction is not Ethereum type, skipping");
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "❌ [CONTRACT] Failed to create contract call transaction: {}",
                        e
                    );
                }
            }
        } else {
            warn!("❌ [CONTRACT] Signing node not available for contract call execution");
        }

        Ok(())
    }
}

