use libp2p::Multiaddr;

impl MpcNetworkLayer {
   
    pub(crate) async fn fetch_solver_id_for_address(&self, solver_address: &str) -> Result<String> {
        let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
            .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string());
        let contract_address_env = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x390bBeE9A268f273f3F5AF09BB5aE59516dd8327".to_string());
        let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "9029".to_string())
            .parse::<u64>()
            .unwrap_or(9029);

        if contract_address_env == "0x0000000000000000000000000000000000000000" {
            return Err(anyhow!(
                "solver contract address not configured; cannot fetch solver id"
            ));
        }

        let contract_address = contract_address_env
            .parse::<Address>()
            .map_err(|e| anyhow!("invalid solver contract address: {}", e))?;

        let config = ContractConfig {
            rpc_url: rpc_url.clone(),
            contract_address,
            chain_id,
        };

        let client = ContractClient::new(config.clone())
            .map_err(|e| anyhow!("failed to create contract client: {}", e))?;
        let contract = SolverManagerContract::new(&config, client.provider())
            .map_err(|e| anyhow!("failed to create solver contract handle: {}", e))?;

        let solver_addr = solver_address
            .parse::<Address>()
            .map_err(|e| anyhow!("invalid solver address {}: {}", solver_address, e))?;

        let solver_id = contract
            .get_solver_id(solver_addr)
            .await
            .map_err(|e| anyhow!("contract getSolverId failed for {}: {}", solver_address, e))?;

        if solver_id.trim().is_empty() {
            Err(anyhow!(
                "solver id not found on contract for address {}",
                solver_address
            ))
        } else {
            Ok(solver_id)
        }
    }

}

#[cfg(test)]
mod tests {
    use crate::chain_abstraction::{ChainHandler, ChainHandlerFactory};
    use std::sync::Arc;

    #[tokio::test]
    async fn parallel_deposit_chain_handlers_remain_isolated() {
        let evm_handler = tokio::spawn(async {
            let chain_id =
                crate::utils::transaction::get_chain_id_from_name("ethereum").expect("chain id");
            let handler: Arc<dyn ChainHandler> =
                ChainHandlerFactory::create_ethereum_handler(chain_id).into();
            handler
        });

        let btc_handler = tokio::spawn(async {
            let handler: Arc<dyn ChainHandler> = ChainHandlerFactory::create_bitcoin_handler(
                crate::types::network::network_type()
                    .bitcoin_network_label()
                    .to_string(),
            )
            .into();
            handler
        });

        let (evm_handler, btc_handler) = tokio::join!(evm_handler, btc_handler);
        let evm_handler = evm_handler.expect("evm task");
        let btc_handler = btc_handler.expect("btc task");

        assert_eq!(evm_handler.chain_type(), "ethereum");
        assert_eq!(btc_handler.chain_type(), "bitcoin");
        assert!(!Arc::ptr_eq(&evm_handler, &btc_handler));
    }
}
/// Channel message handler
/// Handles all internal channel messages: Broadcast, Unicast, DepositIntent, etc.
///
/// NOTE: This module contains the channel message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~3561-5042 of the original file
use anyhow::{anyhow, Result};
use ethers::types::{Address, U256};
use ff::PrimeField;
use libp2p::{gossipsub, PeerId};
use tracing::{debug, error, info, warn};

use crate::{
    contract::{ContractClient, ContractConfig, SolverManagerContract},
    rpc_server::utils::{
        convert_src_smallest_to_dst_smallest, fetch_crypto_prices, fetch_network_balance,
    },
    types::{
        rpc::RPCRequest, rpc_server::NodeStatus, ChannelMessage,
        GossipsubMessage,
    },
};

use crate::network::transport::types::{
    MpcNetworkBehaviour, MpcNetworkLayer, TOPIC_CLAIM_REWARDS, TOPIC_WITHDRAW_LIQUIDITY,
};
use crate::protocols::DKGStatus;

impl MpcNetworkLayer {
    // ChannelMessage is related to the MPSC channel only
    pub(crate) async fn handle_channel_message(
        &mut self,
        message: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match message {
            ChannelMessage::PeerDiscoveryRetry { attempt } => {
                if !self.peer_discovery.pending_peer_discovery_retry {
                    return Ok(());
                }

                self.peer_discovery.pending_peer_discovery_retry = false;

                if self.has_additional_peers() {
                    self.broadcast_local_presence().await?;
                } else if attempt >= Self::MAX_PEER_DISCOVERY_RETRIES {
                    warn!(
                        "⚠️ Peer discovery retry attempt {} reached limit {}; not broadcasting yet",
                        attempt,
                        Self::MAX_PEER_DISCOVERY_RETRIES
                    );
                } else {
                    self.schedule_peer_discovery_retry(attempt + 1);
                }
            }
            ChannelMessage::StatusRequest { responder } => {
                let peer_id = self.local_peer_id.to_string();
                let connected_peers = swarm.connected_peers().count();

                let (dkg_status, has_final_share) = if let Some(dkg_node) = &self.dkg_node {
                    let status = dkg_node.get_status();
                    let has_share = dkg_node.get_final_secret_share().await.is_some();
                    (status, has_share)
                } else {
                    (DKGStatus::New, false)
                };

                let is_ready = has_final_share && matches!(dkg_status, DKGStatus::Completed);
                let dkg_status_str = format!("{:?}", dkg_status);

                let status = NodeStatus {
                    peer_id,
                    connected_peers,
                    dkg_status: dkg_status_str,
                    is_ready,
                };

                if responder.send(status).is_err() {
                    warn!("❌ [STATUS] Failed to send node status response to requester");
                }
            }

            // this is used in the dkg code
            ChannelMessage::Broadcast { topic, data } => {
                // dkg.s.1
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());

                // Production: Check channel capacity and log warnings for monitoring
                let _channel_capacity_warning_threshold = 0.8; // Warn at 80% full
                // Note: We can't directly check channel capacity, but we can monitor via try_send failures
                
                // Check if this is a critical message that needs retry tracking
                // Only register if retry manager is available and message deserializes correctly
                // Skip registration if message is already being tracked (e.g., from a retry)
                if let Some(retry_mgr) = &self.retry_manager {
                    match serde_json::from_slice::<crate::types::GossipsubMessage>(&data) {
                        Ok(gossip_msg) => {
                            if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_msg) {
                                // Generate message ID to check if already tracked
                                if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_msg) {
                                    // Check if already being tracked (this is a retry, skip registration)
                                    if retry_mgr.is_message_tracked(&message_id).await {
                                        debug!("🔄 [RETRY] Message {:?} already tracked, skipping registration (this is a retry)", message_id);
                                    } else {
                                        // Get expected nodes (all active nodes except ourselves)
                                        let expected_nodes: std::collections::HashSet<PeerId> = self
                                            .node_manager
                                            .get_active_nodes()
                                            .into_iter()
                                            .filter(|&pid| pid != self.local_peer_id)
                                            .collect();

                                        if !expected_nodes.is_empty() {
                                            // Check if already tracked (retry case)
                                            if retry_mgr.is_message_tracked(&message_id).await {
                                                debug!("🔄 [RETRY] Message {:?} already tracked, skipping registration (this is a retry)", message_id);
                                            } else {
                                                // Log expected nodes for debugging
                                                let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
                                                debug!(
                                                    "📋 [RETRY] Registering message {:?} - expecting ACKs from {} nodes: {:?}",
                                                    message_id, expected_nodes.len(), expected_list
                                                );
                                                
                                                // Register with retry manager (first time only)
                                                if let Err(e) = retry_mgr.register_message(
                                                    message_id.clone(),
                                                    topic.clone(),
                                                    data.clone(),
                                                    expected_nodes.clone(),
                                                ).await {
                                                    debug!("❌ [RETRY] Failed to register critical message for retry: {}", e);
                                                }
                                            }
                                        } else {
                                            debug!("⚠️ [RETRY] No expected nodes - skipping retry registration for {:?}", message_id);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Message deserialization failed - this is expected for some message types
                            // Only log at debug level to avoid noise
                            debug!("[BROADCAST] Message deserialization failed (may not be a GossipsubMessage): {}", e);
                        }
                    }
                }

                // Check if this is a retry by checking if message is already tracked
                let is_retry = if let Some(retry_mgr) = &self.retry_manager {
                    match serde_json::from_slice::<crate::types::GossipsubMessage>(&data) {
                        Ok(gossip_msg) => {
                            if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_msg) {
                                if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_msg) {
                                    retry_mgr.is_message_tracked(&message_id).await
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                };

                // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                // if peer(s) have already subscribed to this topic, they will recieve this
                // msg (check subscribe_to_default_topics())
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    let publish_result = swarm_mut.gossipsub.publish(topic_hash, data);
                    match publish_result {
                        Ok(_) => {}
                        Err(e) => {
                            if is_retry {
                                debug!(
                                    "❌ [RETRY] CRITICAL: Failed to publish retry message to topic {}: {:?}",
                                    topic, e
                                );
                                // For retries, this is critical - log as debug (retry path)
                            } else {
                                warn!(
                                    "❌ [BROADCAST] Failed to publish message to topic {}: {:?}",
                                    topic, e
                                );
                                // Initial publish failure - retry mechanism will handle it if message was registered
                            }
                        }
                    }
                } else {
                    if is_retry {
                        debug!(
                            "❌ [RETRY] No peers available for retry broadcast to topic: {}",
                            topic
                        );
                    } else {
                        warn!(
                            "⚠️ [BROADCAST] No peers available for broadcasting to topic: {}",
                            topic
                        );
                    }
                }
            }
            // Local + network handling for intent batches:
            // - Origin node sends ChannelMessage::IntentBatchBroadcast
            // - We:
            //   1) Build the corresponding GossipsubMessage::IntentBatchBroadcast
            //   2) Call handle_gossipsub_message locally so this node processes its own batch
            //   3) Publish the message over gossipsub so other peers process it too
            ChannelMessage::IntentBatchBroadcast {
                intent_hashes,
                batch_type,
                timestamp,
                round,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::IntentBatchBroadcast {
                    intent_hashes,
                    batch_type,
                    timestamp,
                    round,
                    node_id,
                    nonce_tuple_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [INTENT_BATCH] Failed to serialize IntentBatchBroadcast: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "intent-batch-broadcast".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [INTENT_BATCH] Failed to process local IntentBatchBroadcast: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [INTENT_BATCH] Failed to publish IntentBatchBroadcast to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [INTENT_BATCH] No peers available for broadcasting IntentBatchBroadcast"
                    );
                }
            }
            // TICS UserToVault intent batch: final node broadcasts pending TICS-source intents for signing
            ChannelMessage::TicsUserToVaultIntentBatch {
                intent_hashes,
                round,
                timestamp,
                node_id,
                nonce_assignments,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::TicsUserToVaultIntentBatch {
                    intent_hashes: intent_hashes.clone(),
                    round,
                    timestamp: timestamp.clone(),
                    node_id: node_id.clone(),
                    nonce_assignments: nonce_assignments.clone(),
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [TICS_UTV_BATCH] Failed to serialize TicsUserToVaultIntentBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic =
                    crate::network::transport::types::TOPIC_TICS_USER_TO_VAULT_BATCH.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [TICS_UTV_BATCH] Failed to process local TicsUserToVaultIntentBatch: {}",
                        e
                    );
                }

                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();
                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [TICS_UTV_BATCH] Failed to publish TicsUserToVaultIntentBatch to topic {}: {:?}",
                            topic, e
                        );
                    } else {
                        info!(
                            "📡 [TICS_UTV_BATCH] Published TicsUserToVaultIntentBatch (round {}, {} intents) to {} peers",
                            round, intent_hashes.len(), peer_count
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [TICS_UTV_BATCH] No peers available for broadcasting TicsUserToVaultIntentBatch"
                    );
                }
            }
            // BTC UserToVault intent batch: final node broadcasts pending BTC-source intents for signing
            ChannelMessage::BtcUserToVaultIntentBatch {
                intent_hashes,
                round,
                timestamp,
                node_id,
                nonce_assignments,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::BtcUserToVaultIntentBatch {
                    intent_hashes: intent_hashes.clone(),
                    round,
                    timestamp: timestamp.clone(),
                    node_id: node_id.clone(),
                    nonce_assignments: nonce_assignments.clone(),
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [BTC_UTV_BATCH] Failed to serialize BtcUserToVaultIntentBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic =
                    crate::network::transport::types::TOPIC_BTC_USER_TO_VAULT_BATCH.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [BTC_UTV_BATCH] Failed to process local BtcUserToVaultIntentBatch: {}",
                        e
                    );
                }

                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();
                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [BTC_UTV_BATCH] Failed to publish BtcUserToVaultIntentBatch to topic {}: {:?}",
                            topic, e
                        );
                    } else {
                        info!(
                            "📡 [BTC_UTV_BATCH] Published BtcUserToVaultIntentBatch (round {}, {} intents) to {} peers",
                            round, intent_hashes.len(), peer_count
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [BTC_UTV_BATCH] No peers available for broadcasting BtcUserToVaultIntentBatch"
                    );
                }
            }
            // BTC Intent Manager Contract Update Batch
            // - Origin node sends ChannelMessage::BtcIntentManagerTxUpdate
            //   1) Build the corresponding GossipsubMessage::BtcIntentManagerTxUpdate
            //   2) Process locally by calling the main gossipsub handler
            //   3) Publish to other peers via gossipsub
            ChannelMessage::BtcIntentManagerTxUpdate {
                intent_hashes,
                btc_txid,
                btc_batch_round,
                update_round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::BtcIntentManagerTxUpdate {
                    intent_hashes: intent_hashes.clone(),
                    btc_txid: btc_txid.clone(),
                    btc_batch_round,
                    update_round,
                    timestamp: timestamp.clone(),
                    node_id: node_id.clone(),
                    nonce_tuple_id: nonce_tuple_id.clone(),
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [BTC_INTENT_MANAGER] Failed to serialize BtcIntentManagerTxUpdate: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "btc-intent-manager-tx-update".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [BTC_INTENT_MANAGER] Failed to process local BtcIntentManagerTxUpdate: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [BTC_INTENT_MANAGER] Failed to publish BtcIntentManagerTxUpdate to topic {}: {:?}",
                            topic, e
                        );
                    } else {
                        info!(
                            "✅ [BTC_INTENT_MANAGER] Published BtcIntentManagerTxUpdate to {} peers ({} intents)",
                            peer_count,
                            intent_hashes.len()
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] No peers available for broadcasting BtcIntentManagerTxUpdate"
                    );
                }
            }
            ChannelMessage::BtcWithdrawBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::BtcWithdrawBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [BTC_WITHDRAW] Failed to serialize BtcWithdrawBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "withdraw-liquidity-batch".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [BTC_WITHDRAW] Failed to process local BtcWithdrawBatch: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [BTC_WITHDRAW] Failed to publish BtcWithdrawBatch to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [BTC_WITHDRAW] No peers available for broadcasting BtcWithdrawBatch"
                    );
                }
            }
            ChannelMessage::BtcClaimRewardBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::BtcClaimRewardBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [BTC_CLAIM_REWARD] Failed to serialize BtcClaimRewardBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic = TOPIC_CLAIM_REWARDS.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [BTC_CLAIM_REWARD] Failed to process local BtcClaimRewardBatch: {}",
                        e
                    );
                }


                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();
                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [BTC_CLAIM_REWARD] Failed to publish BtcClaimRewardBatch to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [BTC_CLAIM_REWARD] No peers available for broadcasting BtcClaimRewardBatch"
                    );
                }
            }
            ChannelMessage::PeerInvalidationBatch {
                solver_ids,
                round,
                timestamp,
                node_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::PeerInvalidationBatch {
                    solver_ids,
                    round,
                    timestamp,
                    node_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [PEER_INVALIDATION] Failed to serialize PeerInvalidationBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "peer-invalidation-batch".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [PEER_INVALIDATION] Failed to process local PeerInvalidationBatch: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [PEER_INVALIDATION] Failed to publish PeerInvalidationBatch to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [PEER_INVALIDATION] No peers available for broadcasting PeerInvalidationBatch"
                    );
                }
            }
            ChannelMessage::TicsWithdrawBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::TicsWithdrawBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [TICS_WITHDRAW] Failed to serialize TicsWithdrawBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "withdraw-liquidity-batch".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [TICS_WITHDRAW] Failed to process local TicsWithdrawBatch: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [TICS_WITHDRAW] Failed to publish TicsWithdrawBatch to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [TICS_WITHDRAW] No peers available for broadcasting TicsWithdrawBatch"
                    );
                }
            }
            ChannelMessage::TicsClaimRewardBatch {
                batch_id,
                requests,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::TicsClaimRewardBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [TICS_CLAIM_REWARD] Failed to serialize TicsClaimRewardBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic = TOPIC_CLAIM_REWARDS.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [TICS_CLAIM_REWARD] Failed to process local TicsClaimRewardBatch: {}",
                        e
                    );
                }

                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [TICS_CLAIM_REWARD] Failed to publish TicsClaimRewardBatch to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [TICS_CLAIM_REWARD] No peers available for broadcasting TicsClaimRewardBatch"
                    );
                }
            }
            ChannelMessage::ClaimRewardTxIdBroadcast {
                txid,
                network,
                batch_id,
                solver_address,
                requests,
                node_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                info!(
                    "📡 [CLAIM_REWARD_TXID] Received claim-reward txid broadcast: txid={}, network={}, batch_id={}, solver={:?}, requests={}",
                    txid, network, batch_id, solver_address, requests.len()
                );

                let gossip_msg = crate::types::GossipsubMessage::ClaimRewardTxIdBroadcast {
                    txid,
                    network,
                    batch_id,
                    solver_address,
                    requests,
                    node_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [CLAIM_REWARD_TXID] Failed to serialize ClaimRewardTxIdBroadcast: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic = TOPIC_CLAIM_REWARDS.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [CLAIM_REWARD_TXID] Failed to process local ClaimRewardTxIdBroadcast: {}",
                        e
                    );
                }

                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [CLAIM_REWARD_TXID] Failed to publish ClaimRewardTxIdBroadcast to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [CLAIM_REWARD_TXID] No peers available for broadcasting ClaimRewardTxIdBroadcast"
                    );
                }
            }
            ChannelMessage::WithdrawTxIdBroadcast {
                txid,
                network,
                batch_id,
                solver_address,
                requests,
                node_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                info!(
                    "📡 [WITHDRAW_TXID] Received withdraw-liquidity txid broadcast from node {}: txid={}, batch_id={}, network={}, solver={:?}, requests={}",
                    node_id,
                    txid,
                    batch_id,
                    network,
                    solver_address,
                    requests.len()
                );

                let gossip_msg = crate::types::GossipsubMessage::WithdrawTxIdBroadcast {
                    txid,
                    network,
                    batch_id,
                    solver_address,
                    requests,
                    node_id,
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [WITHDRAW_TXID] Failed to serialize WithdrawTxIdBroadcast: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "withdraw-liquidity-batch".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [WITHDRAW_TXID] Failed to process local WithdrawTxIdBroadcast: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [WITHDRAW_TXID] Failed to publish WithdrawTxIdBroadcast to topic {}: {:?}",
                            topic, e
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [WITHDRAW_TXID] No peers available for broadcasting WithdrawTxIdBroadcast"
                    );
                }
            }
            ChannelMessage::PendingWithdrawRequestBroadcast { request } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::PendingWithdrawRequestBroadcast {
                    request: request.clone(),
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [WITHDRAW_LIQUIDITY] Failed to serialize PendingWithdrawRequestBroadcast: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic = TOPIC_WITHDRAW_LIQUIDITY.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [WITHDRAW_LIQUIDITY] Failed to process local PendingWithdrawRequestBroadcast: {}",
                        e
                    );
                }

                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [WITHDRAW_LIQUIDITY] Failed to publish PendingWithdrawRequestBroadcast to topic {}: {:?}",
                            topic, e
                        );
                    } else {
                        info!(
                            "📡 [WITHDRAW_LIQUIDITY] Published PendingWithdrawRequestBroadcast (request_id={}) to {} peers",
                            request.request_id, peer_count
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [WITHDRAW_LIQUIDITY] No peers available for broadcasting PendingWithdrawRequestBroadcast"
                    );
                }
            }
            ChannelMessage::PendingClaimRewardRequestBroadcast { request } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::PendingClaimRewardRequestBroadcast {
                    request: request.clone(),
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [CLAIM_REWARD] Failed to serialize PendingClaimRewardRequestBroadcast: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                let topic = TOPIC_CLAIM_REWARDS.to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [CLAIM_REWARD] Failed to process local PendingClaimRewardRequestBroadcast: {}",
                        e
                    );
                }

                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [CLAIM_REWARD] Failed to publish PendingClaimRewardRequestBroadcast to topic {}: {:?}",
                            topic, e
                        );
                    } else {
                        info!(
                            "📡 [CLAIM_REWARD] Published PendingClaimRewardRequestBroadcast (request_id={}) to {} peers",
                            request.request_id, peer_count
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [CLAIM_REWARD] No peers available for broadcasting PendingClaimRewardRequestBroadcast"
                    );
                }
            }
            // Solver Add Liquidity Batch
            // - Final node sends ChannelMessage::SolverAddLiquidityBatch (only request_ids)
            //   1) Build the corresponding GossipsubMessage::SolverAddLiquidityBatch
            //   2) Process locally by calling the main gossipsub handler
            //   3) Publish to other peers via gossipsub
            // All nodes already have full records in RocksDB, so we only send request_ids
            ChannelMessage::SolverAddLiquidityBatch {
                request_ids,
                round,
                timestamp,
                node_id,
                nonce_tuple_id,
            } => {
                use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};

                let gossip_msg = crate::types::GossipsubMessage::SolverAddLiquidityBatch {
                    request_ids: request_ids.clone(),
                    round,
                    timestamp: timestamp.clone(),
                    node_id: node_id.clone(),
                    nonce_tuple_id: nonce_tuple_id.clone(),
                };

                let data = match serde_json::to_vec(&gossip_msg) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "❌ [ADD_LIQUIDITY_BATCH] Failed to serialize SolverAddLiquidityBatch: {}",
                            e
                        );
                        return Ok(());
                    }
                };

                // 1) Process locally by calling the main gossipsub handler
                let topic = "solver-add-liquidity-batch".to_string();
                let topic_hash = IdentTopic::new(topic.clone());
                let local_msg = GossipMessage {
                    source: Some(self.local_peer_id),
                    data: data.clone(),
                    sequence_number: None,
                    topic: topic_hash.hash(),
                };

                if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                    warn!(
                        "❌ [ADD_LIQUIDITY_BATCH] Failed to process local SolverAddLiquidityBatch: {}",
                        e
                    );
                }

                // 2) Publish to other peers via gossipsub
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();

                if peer_count > 0 {
                    if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                        warn!(
                            "❌ [ADD_LIQUIDITY_BATCH] Failed to publish SolverAddLiquidityBatch to topic {}: {:?}",
                            topic, e
                        );
                    } else {
                        info!(
                            "✅ [ADD_LIQUIDITY_BATCH] Published SolverAddLiquidityBatch to {} peers ({} requests)",
                            peer_count,
                            request_ids.len()
                        );
                    }
                } else {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY_BATCH] No peers available for broadcasting SolverAddLiquidityBatch"
                    );
                }
            }
            // SECURE DKG SHARE DISTRIBUTION - sends share to specific peer via P2P RPC
            ChannelMessage::UnicastShareDKG {
                target_peer_id,
                from_node_id,
                share_index,
                share_value,
                commitments,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;


                // Parse the target peer ID
                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [DKG-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                // Attempt to dial if not connected and we have a listen address
                let mut is_connected = swarm.is_connected(&peer_id);
                let connected_peers = swarm.connected_peers().collect::<Vec<_>>();
                debug!("🔐 [DKG-SECURE] Connected peers: {:?}", connected_peers);

                info!(
                    "🔐 [DKG-SECURE]  Peer discovery {} address: {:?}",
                    target_peer_id,
                    self.peer_discovery.peer_multiaddresses.get(&peer_id)
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [DKG-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!("⚠️ [DKG-SECURE] Dial to {} failed: {}", target_peer_id, e);
                        } else {
                            // allow a brief window for connection to establish
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            info!(
                                "🔐 [DKG-SECURE] Dial to connect to {} successful {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [DKG-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    // Not connected - schedule retry with exponential backoff
                    let delay_ms = 1000 * (1 << retry_count.min(5)); // 1s, 2s, 4s, 8s, 16s, 32s max
                    debug!(
                        "🔄 [DKG-SECURE] Peer send {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastShareDKG {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        share_index,
                        share_value,
                        commitments,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [DKG-SECURE] Failed to schedule retry for share {}: {}",
                                share_index,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [DKG-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                // PACING: Check per-peer in-flight count before sending
                {
                    use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                    let mut inflight = self.outbound_inflight.lock().await;
                    let count = inflight.get(&peer_id).copied().unwrap_or(0);
                    
                    if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                        // At capacity - re-queue with delay
                        debug!(
                            "⏸️ [DKG-SECURE] Peer {} at capacity ({}/{}), re-queuing share {}",
                            target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, share_index
                        );
                        let tx = self.message_tx.clone();
                        let msg = ChannelMessage::UnicastShareDKG {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id: from_node_id.clone(),
                            share_index,
                            share_value: share_value.clone(),
                            commitments: commitments.clone(),
                            round,
                            retry_count,
                        };
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                            let _ = tx.send(msg).await;
                        });
                        return Ok(());
                    }
                    
                    // Increment in-flight count
                    *inflight.entry(peer_id).or_insert(0) += 1;
                }

                // Clone values for retry registry before creating RPC request
                let from_node_id_clone = from_node_id.clone();
                let share_value_clone = share_value.clone();
                let commitments_clone = commitments.clone();

                // Create the RPC request
                let request = RPCRequest::SendDKGShare {
                    from_node_id,
                    share_index,
                    share_value,
                    commitments,
                    round,
                };

                // Send via request-response protocol (unicast, not broadcast)
                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                // RETRY: Insert into outbound_retry registry
                {
                    use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                    let retry_msg = RetryableUnicast::UnicastShareDKG {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id: from_node_id_clone,
                        share_index,
                        share_value: share_value_clone,
                        commitments: commitments_clone,
                        round,
                    };
                    let entry = OutboundRetryEntry {
                        peer: peer_id,
                        retry_count,
                        msg: retry_msg,
                    };
                    self.outbound_retry.lock().await.insert(request_id, entry);
                }

                info!(
                    "✅ [DKG-SECURE] Share index {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    share_index, target_peer_id, request_id, is_connected
                );
            }
            // CRITICAL GOSSIP DELIVERY - sends critical gossip bytes to specific peer via P2P RPC
            ChannelMessage::UnicastCritical {
                target_peer_id,
                topic,
                data,
                message_type,
                message_id,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 1;
                const RETRY_DELAY_MS: u64 = 200;

                // info!(
                //     "📨 [CRITICAL-UNICAST] Sending critical message {}:{} to peer {} (attempt {})",
                //     message_type,
                //     message_id,
                //     target_peer_id,
                //     retry_count + 1
                // );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [CRITICAL-UNICAST] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                // info!(
                //     "📨 [CRITICAL-UNICAST] Target Peer {} connected: {}",
                //     target_peer_id, is_connected
                // );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        info!(
                            "📞 [CRITICAL-UNICAST] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [CRITICAL-UNICAST] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            // info!(
                            //     "📨 [CRITICAL-UNICAST] Dial to {} successful: {}",
                            //     target_peer_id, is_connected
                            // );
                        }
                    } else {
                        warn!(
                            "⚠️ [CRITICAL-UNICAST] No known address to dial peer {}; will rely on retry manager",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    info!(
                        "🔄 [CRITICAL-UNICAST] Peer {} not connected - scheduling quick retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        RETRY_DELAY_MS
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastCritical {
                        target_peer_id: target_peer_id.clone(),
                        topic: topic.clone(),
                        data: data.clone(),
                        message_type: message_type.clone(),
                        message_id: message_id.clone(),
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [CRITICAL-UNICAST] Failed to schedule retry for {}:{}: {}",
                                message_type,
                                message_id,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [CRITICAL-UNICAST] Peer {} still not connected after quick retry - giving up",
                        target_peer_id
                    );
                    return Ok(());
                }

                // PACING: Check per-peer in-flight count before sending
                {
                    use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                    let mut inflight = self.outbound_inflight.lock().await;
                    let count = inflight.get(&peer_id).copied().unwrap_or(0);
                    
                    if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                        // At capacity - re-queue with delay
                        // info!(
                        //     "⏸️ [CRITICAL-UNICAST] Peer {} at capacity ({}/{}), re-queuing message",
                        //     target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER
                        // );
                        let tx = self.message_tx.clone();
                        let msg = ChannelMessage::UnicastCritical {
                            target_peer_id: target_peer_id.clone(),
                            topic,
                            data,
                            message_type,
                            message_id,
                            retry_count,
                        };
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                            let _ = tx.send(msg).await;
                        });
                        return Ok(());
                    }
                    
                    // Increment in-flight count
                    *inflight.entry(peer_id).or_insert(0) += 1;
                }

                let request = RPCRequest::DeliverCriticalGossip {
                    topic: topic.clone(),
                    data: data.clone(),
                    message_type: message_type.clone(),
                    message_id: message_id.clone(),
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                // RETRY: Insert into outbound_retry registry
                {
                    use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                    let retry_msg = RetryableUnicast::UnicastCritical {
                        target_peer_id: target_peer_id.clone(),
                        topic,
                        data,
                        message_type,
                        message_id,
                    };
                    let entry = OutboundRetryEntry {
                        peer: peer_id,
                        retry_count,
                        msg: retry_msg,
                    };
                    self.outbound_retry.lock().await.insert(request_id, entry);
                }

                info!(
                    "✅ [CRITICAL-UNICAST] Critical message sent to {} (request_id: {:?}, connected: {})",
                    target_peer_id, request_id, is_connected
                );
            }
            // SECURE SIGNATURE DISTRIBUTION - sends ECDSA signature to final node via P2P RPC
            ChannelMessage::UnicastECDSASignature {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                debug!(
                    "🔐 [SIGNING-SECURE] Sending ECDSA signature for round {} via UNICAST to peer {} (attempt {})",
                    round,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                debug!(
                    "🔐 [SIGNING-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        debug!(
                            "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [SIGNING-SECURE] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            debug!(
                                "🔐 [SIGNING-SECURE] Dial to connect to {} successful {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let delay_ms = 1000 * (1 << retry_count.min(5));
                    debug!(
                        "🔄 [SIGNING-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastECDSASignature {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        signature_data,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [SIGNING-SECURE] Failed to schedule retry for round {} signature: {}",
                                round,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                // PACING: Check per-peer in-flight count before sending
                {
                    use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                    let mut inflight = self.outbound_inflight.lock().await;
                    let count = inflight.get(&peer_id).copied().unwrap_or(0);
                    
                    if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                        // At capacity - re-queue with delay
                        debug!(
                            "⏸️ [SIGNING-SECURE] Peer {} at capacity ({}/{}), re-queuing ECDSA signature for round {}",
                            target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, round
                        );
                        let tx = self.message_tx.clone();
                        let msg = ChannelMessage::UnicastECDSASignature {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            signature_data,
                            round,
                            retry_count,
                        };
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                            let _ = tx.send(msg).await;
                        });
                        return Ok(());
                    }
                    
                    // Increment in-flight count
                    *inflight.entry(peer_id).or_insert(0) += 1;
                }

                let request = RPCRequest::SendECDSASignature {
                    from_node_id: from_node_id.clone(),
                    signature_data: signature_data.clone(),
                    round,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                // RETRY: Insert into outbound_retry registry
                {
                    use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                    let retry_msg = RetryableUnicast::UnicastECDSASignature {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        signature_data,
                        round,
                    };
                    let entry = OutboundRetryEntry {
                        peer: peer_id,
                        retry_count,
                        msg: retry_msg,
                    };
                    self.outbound_retry.lock().await.insert(request_id, entry);
                }

                debug!(
                    "✅ [SIGNING-SECURE] ECDSA signature for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    round, target_peer_id, request_id, is_connected
                );
            }

            // SECURE SIGNATURE DISTRIBUTION - sends BTC signatures to final node via P2P RPC
            ChannelMessage::UnicastBtcSignatures {
                target_peer_id,
                from_node_id,
                signature_data,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                debug!(
                    "🔐 [SIGNING-SECURE] Sending BTC signatures for round {} via UNICAST to peer {} (attempt {})",
                    round,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                debug!(
                    "🔐 [SIGNING-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        debug!(
                            "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "⚠️ [SIGNING-SECURE] Dial to {} failed: {}",
                                target_peer_id, e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                            is_connected = swarm.is_connected(&peer_id);
                            debug!(
                                "🔐 [SIGNING-SECURE] Dial to connect to {} successful {}",
                                target_peer_id, is_connected
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING-SECURE] No known address to dial peer {}; will rely on retries",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let delay_ms = 1000 * (1 << retry_count.min(5));
                    debug!(
                        "🔄 [SIGNING-SECURE] Peer {} not connected - scheduling retry {} in {}ms",
                        target_peer_id,
                        retry_count + 1,
                        delay_ms
                    );

                    let tx = self.message_tx.clone();
                    let retry_msg = ChannelMessage::UnicastBtcSignatures {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        signature_data,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [SIGNING-SECURE] Failed to schedule retry for round {} BTC signatures: {}",
                                round,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                // PACING: Check per-peer in-flight count before sending
                {
                    use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                    let mut inflight = self.outbound_inflight.lock().await;
                    let count = inflight.get(&peer_id).copied().unwrap_or(0);
                    
                    if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                        // At capacity - re-queue with delay
                        debug!(
                            "⏸️ [SIGNING-SECURE] Peer {} at capacity ({}/{}), re-queuing BTC signatures for round {}",
                            target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, round
                        );
                        let tx = self.message_tx.clone();
                        let msg = ChannelMessage::UnicastBtcSignatures {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            signature_data,
                            round,
                            retry_count,
                        };
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                            let _ = tx.send(msg).await;
                        });
                        return Ok(());
                    }
                    
                    // Increment in-flight count
                    *inflight.entry(peer_id).or_insert(0) += 1;
                }

                let request = RPCRequest::SendBtcSignatures {
                    from_node_id: from_node_id.clone(),
                    signature_data: signature_data.clone(),
                    round,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                // RETRY: Insert into outbound_retry registry
                {
                    use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                    let retry_msg = RetryableUnicast::UnicastBtcSignatures {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        signature_data,
                        round,
                    };
                    let entry = OutboundRetryEntry {
                        peer: peer_id,
                        retry_count,
                        msg: retry_msg,
                    };
                    self.outbound_retry.lock().await.insert(request_id, entry);
                }

                debug!(
                    "✅ [SIGNING-SECURE] BTC signatures for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    round, target_peer_id, request_id, is_connected
                );
            }
            ChannelMessage::UnicastTransactionData {
                target_peer_id,
                from_node_id,
                transaction_data,
                round,
                retry_count,
            } => {
                const MAX_RETRIES: u8 = 10;

                debug!(
                    "📦 [SIGNING-SECURE] Sending transaction data for round {} via UNICAST to peer {} (attempt {})",
                    round,
                    target_peer_id,
                    retry_count + 1
                );

                let peer_id = match target_peer_id.parse::<PeerId>() {
                    Ok(pid) => pid,
                    Err(e) => {
                        warn!(
                            "❌ [SIGNING-SECURE] Invalid peer ID '{}': {}",
                            target_peer_id, e
                        );
                        return Err(anyhow!("Invalid peer ID: {}", e));
                    }
                };

                let mut is_connected = swarm.is_connected(&peer_id);
                debug!(
                    "📦 [SIGNING-SECURE] Target Peer {} connected: {}",
                    target_peer_id, is_connected
                );

                if !is_connected {
                    if let Some(addr) = self
                        .peer_discovery
                        .peer_multiaddresses
                        .get(&peer_id)
                        .cloned()
                    {
                        debug!(
                            "📞 [SIGNING-SECURE] Not connected to {}, dialing before send: {}",
                            target_peer_id, addr
                        );
                        let address: Multiaddr = if addr
                            .to_string()
                            .contains(&format!("/p2p/{}", target_peer_id))
                        {
                            addr.clone()
                        } else {
                            format!("{}/p2p/{}", addr, target_peer_id)
                                .parse()
                                .expect("valid multiaddr")
                        };
                        if let Err(e) = swarm.dial(address.clone()) {
                            warn!(
                                "❌ [SIGNING-SECURE] Failed to dial {}: {}",
                                target_peer_id, e
                            );
                        } else {
                            debug!("✅ [SIGNING-SECURE] Dialing {}", target_peer_id);
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        }
                        is_connected = swarm.is_connected(&peer_id);
                    } else {
                        warn!(
                            "❌ [SIGNING-SECURE] No known address for peer {}",
                            target_peer_id
                        );
                    }
                }

                if !is_connected && retry_count < MAX_RETRIES {
                    let tx = self.message_tx.clone();
                    let delay_ms = 2000 + (retry_count as u64 * 1000);
                    debug!(
                        "⏰ [SIGNING-SECURE] Peer {} not connected, will retry transaction data for round {} in {}ms (attempt {}/{})",
                        target_peer_id,
                        round,
                        delay_ms,
                        retry_count + 1,
                        MAX_RETRIES
                    );

                    let retry_msg = ChannelMessage::UnicastTransactionData {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        transaction_data,
                        round,
                        retry_count: retry_count + 1,
                    };

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = tx.send(retry_msg).await {
                            tracing::warn!(
                                "❌ [SIGNING-SECURE] Failed to schedule retry for round {} transaction data: {}",
                                round,
                                e
                            );
                        }
                    });

                    return Ok(());
                }

                if !is_connected {
                    warn!(
                        "❌ [SIGNING-SECURE] Peer {} still not connected after {} retries - giving up",
                        target_peer_id, MAX_RETRIES
                    );
                }

                // PACING: Check per-peer in-flight count before sending
                {
                    use crate::network::rpc::MAX_OUTBOUND_INFLIGHT_PER_PEER;
                    let mut inflight = self.outbound_inflight.lock().await;
                    let count = inflight.get(&peer_id).copied().unwrap_or(0);
                    
                    if count >= MAX_OUTBOUND_INFLIGHT_PER_PEER {
                        // At capacity - re-queue with delay
                        debug!(
                            "⏸️ [SIGNING-SECURE] Peer {} at capacity ({}/{}), re-queuing transaction data for round {}",
                            target_peer_id, count, MAX_OUTBOUND_INFLIGHT_PER_PEER, round
                        );
                        let tx = self.message_tx.clone();
                        let msg = ChannelMessage::UnicastTransactionData {
                            target_peer_id: target_peer_id.clone(),
                            from_node_id,
                            transaction_data,
                            round,
                            retry_count,
                        };
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                            let _ = tx.send(msg).await;
                        });
                        return Ok(());
                    }
                    
                    // Increment in-flight count
                    *inflight.entry(peer_id).or_insert(0) += 1;
                }

                let request = RPCRequest::SendTransactionData {
                    from_node_id: from_node_id.clone(),
                    transaction_data: transaction_data.clone(),
                    round,
                };

                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);

                // RETRY: Insert into outbound_retry registry
                {
                    use crate::network::rpc::{OutboundRetryEntry, RetryableUnicast};
                    let retry_msg = RetryableUnicast::UnicastTransactionData {
                        target_peer_id: target_peer_id.clone(),
                        from_node_id,
                        transaction_data,
                        round,
                    };
                    let entry = OutboundRetryEntry {
                        peer: peer_id,
                        retry_count,
                        msg: retry_msg,
                    };
                    self.outbound_retry.lock().await.insert(request_id, entry);
                }

                debug!(
                    "✅ [SIGNING-SECURE] Transaction data for round {} sent via P2P RPC to {} (request_id: {:?}, connected: {})",
                    round, target_peer_id, request_id, is_connected
                );
            }
            ChannelMessage::DepositIntent {
                intent,
                intent_id,
                user_eth_address,
                transaction_type,
                amount,
                signature,
            } => {
                // Log key fields explicitly so timestamp is clearly a number (used in intent hash)
                info!(
                    "📝 [NETWORK] Processing deposit intent locally: source={} target={} source_chain={} target_chain={} amount={} timestamp={}",
                    intent.source_address,
                    intent.target_address,
                    intent.source_chain,
                    intent.target_chain,
                    intent.amount,
                    intent.timestamp
                );

                // Only broadcast UserToVault deposits via gossipsub
                // Note: Gossiped DepositIntent is always processed as UserToVault
                if !matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                    info!("⏭️ [NETWORK] Skipping gossip broadcast - only UserToVault deposits are gossiped");
                    return Ok(());
                }
                info!("🌐 [NETWORK] Broadcasting UserToVault deposit to P2P network");
                let deposit_intent_msg = GossipsubMessage::DepositIntent {
                    intent: intent.clone(),
                    intent_id: intent_id.clone(),
                    user_eth_address: user_eth_address.clone(),
                    amount,
                    signature: signature.clone(),
                };
                let msg_bytes = serde_json::to_vec(&deposit_intent_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize deposit intent: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("deposit-intents");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted deposit intent to P2P network");

                // Calculate intent hash from the intent
                let intent_hash = {
                    let calculated_hash = crate::utils::calculate_intent_hash(&intent)
                        .map_err(|e| anyhow::anyhow!("Failed to calculate intent hash: {}", e))?;
                    info!("🔐 [LOCAL] Calculated intent hash: {}", calculated_hash);
                    calculated_hash
                };

                // Each node: fetch prices, compute target amount; store only when network has sufficient funds
                const MIN_BTC_INTENT_SATS: u128 = 550;
                let parsed_amount = match intent.amount.parse::<u128>() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("❌ [CHANNEL] Invalid intent amount for {}: {}", intent_hash, e);
                        return Ok(());
                    }
                };
                // Same-chain (TICS->TICS or BTC->BTC): use original RPC amount as target and store it by intent hash
                let is_same_chain = {
                    let src_tics = intent.source_chain.eq_ignore_ascii_case("tics")
                        || intent.source_chain.eq_ignore_ascii_case("qubetics");
                    let dst_tics = intent.target_chain.eq_ignore_ascii_case("tics")
                        || intent.target_chain.eq_ignore_ascii_case("qubetics");
                    let src_btc = intent.source_chain.eq_ignore_ascii_case("btc")
                        || intent.source_chain.eq_ignore_ascii_case("bitcoin");
                    let dst_btc = intent.target_chain.eq_ignore_ascii_case("btc")
                        || intent.target_chain.eq_ignore_ascii_case("bitcoin");
                    (src_tics && dst_tics) || (src_btc && dst_btc)
                };
                let (target_amount, has_sufficient_funds) = if is_same_chain {
                    let target_amount = intent.amount.parse::<u128>().unwrap();
                    let network_address = if let Some(dkg_node) = &self.dkg_node {
                        match dkg_node.get_final_public_key().await {
                            Some(final_public) => {
                                if intent.target_chain.eq_ignore_ascii_case("btc")
                                    || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                                {
                                    crate::utils::get_btc_address_from_group_key(final_public)
                                } else {
                                    crate::utils::get_eth_address_from_group_key(final_public)
                                }
                            }
                            None => String::new(),
                        }
                    } else {
                        String::new()
                    };
                    let sufficient = if !network_address.is_empty() {
                        let blockchain = if intent.target_chain.eq_ignore_ascii_case("btc")
                            || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                        {
                            "btc"
                        } else {
                            "eth"
                        };
                        match fetch_network_balance(&network_address, blockchain).await {
                            Ok(network_balance) => {
                                if network_balance < target_amount {
                                    warn!(
                                        "⚠️ [CHANNEL] Insufficient network balance for same-chain intent {}: have {}, need {}",
                                        intent_hash, network_balance, target_amount
                                    );
                                    false
                                } else {
                                    true
                                }
                            }
                            Err(_) => false,
                        }
                    } else {
                        false
                    };
                    (target_amount, sufficient)
                } else {
                    match fetch_crypto_prices().await {
                        Ok(prices) => {
                            let target_amount = match convert_src_smallest_to_dst_smallest(
                                parsed_amount,
                                &intent.source_chain,
                                &intent.target_chain,
                                &prices,
                            ) {
                                Ok(a) => a,
                                Err(_) => {
                                    return Ok(());
                                }
                            };
                            let is_tics_to_btc = (intent.source_chain.eq_ignore_ascii_case("tics")
                            || intent.source_chain.eq_ignore_ascii_case("qubetics"))
                            && (intent.target_chain.eq_ignore_ascii_case("btc")
                                || intent.target_chain.eq_ignore_ascii_case("bitcoin"));
                        if is_tics_to_btc && target_amount < MIN_BTC_INTENT_SATS {
                            warn!(
                                "⚠️ [CHANNEL] TICS->BTC intent {} below minimum: {} satoshis (min {})",
                                intent_hash, target_amount, MIN_BTC_INTENT_SATS
                            );
                            return Ok(());
                        }
                        let network_address = if let Some(dkg_node) = &self.dkg_node {
                            match dkg_node.get_final_public_key().await {
                                Some(final_public) => {
                                    if intent.target_chain.eq_ignore_ascii_case("btc")
                                        || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                                    {
                                        crate::utils::get_btc_address_from_group_key(final_public)
                                    } else {
                                        crate::utils::get_eth_address_from_group_key(final_public)
                                    }
                                }
                                None => String::new(),
                            }
                        } else {
                            String::new()
                        };
                        let sufficient = if !network_address.is_empty() {
                            let blockchain = if intent.target_chain.eq_ignore_ascii_case("btc")
                                || intent.target_chain.eq_ignore_ascii_case("bitcoin")
                            {
                                "btc"
                            } else {
                                "eth"
                            };
                            match fetch_network_balance(&network_address, blockchain).await {
                                Ok(network_balance) => {
                                    if network_balance < target_amount {
                                        warn!(
                                            "⚠️ [CHANNEL] Insufficient network balance for intent {}: have {}, need {}",
                                            intent_hash, network_balance, target_amount
                                        );
                                        false
                                    } else {
                                        true
                                    }
                                }
                                Err(_) => false,
                            }
                        } else {
                            false
                        };
                        (target_amount, sufficient)
                    }
                    Err(_) => return Ok(()),
                }
                };

                if has_sufficient_funds {
                    if let Some(user_intent_manager) = &self.user_intent_manager {
                        let _ = user_intent_manager
                            .store_intent_target_amount(&intent_hash, target_amount)
                            .await;
                        info!(
                            "💾 [CHANNEL] Stored target amount {} for intent {} (network has sufficient funds)",
                            target_amount, intent_hash
                        );
                    }
                } else {
                    return Ok(());
                }

                // Intent is broadcast and stored as Pending; skip immediate UserToVault processing.
                info!(
                    "⏸️ [LOCAL] Deposit intent {} stored as Pending; skipping immediate UserToVault processing",
                    intent_hash
                );
            }
            ChannelMessage::TransactionFailure {
                sequencer_request_id,
                blockchain_tx_hash,
                error,
                original_request,
            } => {
                info!(
                    "📝 [NETWORK] Processing transaction failure locally: request_id={}, error={}",
                    sequencer_request_id, error
                );

                // Check if error message indicates transaction is already in mempool
                // If so, skip failure handling - transaction will succeed later
                if error.contains("tx already in mempool") {
                    info!(
                        "✅ [TX_FAILURE] Transaction {} is already in mempool (error: {}). Will succeed later. Skipping failure handling.",
                        sequencer_request_id, error
                    );
                    // Don't re-insert or broadcast failure - transaction is pending and will succeed
                    return Ok(());
                }

                // Contract sequencer removed - transaction failures are logged but not retried via sequencer
                warn!(
                    "⚠️ [TX_FAILURE] [LOCAL] Contract transaction {} failed: {}. Sequencer removed, no automatic retry.",
                    sequencer_request_id, error
                );

                // Then broadcast to other nodes via gossipsub
                let failure_msg = GossipsubMessage::TransactionFailure {
                    sequencer_request_id: sequencer_request_id.clone(),
                    blockchain_tx_hash: blockchain_tx_hash.clone(),
                    error: error.clone(),
                    original_request,
                };
                let msg_bytes = serde_json::to_vec(&failure_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize transaction failure: {}", e))?;
                
                let topic = gossipsub::IdentTopic::new("transaction-failure");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted transaction failure to P2P network");
            }

            ChannelMessage::TransactionIdBroadcast {
                intent_hashes,
                transaction_id,
                transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction ID broadcast from node {}",
                    node_id
                );
                info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);
                if !intent_hashes.is_empty() {
                    info!("🔗 [NETWORK] Intent hashes: {:?}", intent_hashes);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hashes or solver address supplied with transaction ID broadcast");
                }

                // Process locally first (like add_liquidity / peerinv:) so this node updates DB too
                {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
                    let topic_hash = IdentTopic::new("transaction-id-sync");
                    let gossip_message = crate::types::GossipsubMessage::TransactionIdBroadcast {
                        intent_hashes: intent_hashes.clone(),
                        transaction_id: transaction_id.clone(),
                        transaction_type: transaction_type.clone(),
                        solver_address: solver_address.clone(),
                        node_id: node_id.clone(),
                    };
                    let data = serde_json::to_vec(&gossip_message).unwrap_or_default();
                    let local_msg = GossipMessage {
                        source: Some(self.local_peer_id),
                        data,
                        sequence_number: None,
                        topic: topic_hash.hash(),
                    };
                    if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                        warn!("❌ [NETWORK] Failed to process TransactionIdBroadcast locally: {}", e);
                    }
                }

                // Gossip the transaction ID broadcast to other peers immediately so everyone can contribute their share in parallel
                let gossip_message = GossipsubMessage::TransactionIdBroadcast {
                    intent_hashes: intent_hashes.clone(),
                    transaction_id: transaction_id.clone(),
                    transaction_type: transaction_type.clone(),
                    solver_address: solver_address.clone(),
                    node_id: node_id.clone(),
                };

                let msg_bytes = match serde_json::to_vec(&gossip_message) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("❌ [NETWORK] Failed to serialize transaction ID broadcast for gossiping: {}", e);
                        return Ok(());
                    }
                };

                let topic_str = "transaction-id-sync";
                let topic = gossipsub::IdentTopic::new(topic_str);

                // CRITICAL FIX: Register TransactionIdBroadcast for retry tracking
                // This ensures all nodes receive transaction IDs even if initial broadcast fails
                if let Some(retry_mgr) = &self.retry_manager {
                    if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&gossip_message) {
                        if let Ok(message_id) = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type, &gossip_message) {
                            // Check if already being tracked (this is a retry, skip registration)
                            if !retry_mgr.is_message_tracked(&message_id).await {
                                // Get expected nodes (all active nodes except ourselves)
                                let expected_nodes: std::collections::HashSet<PeerId> = self
                                    .node_manager
                                    .get_active_nodes()
                                    .into_iter()
                                    .filter(|&pid| pid != self.local_peer_id)
                                    .collect();

                                if !expected_nodes.is_empty() {
                                    let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
                                    debug!(
                                        "📋 [RETRY] Registering TransactionIdBroadcast {:?} - expecting ACKs from {} nodes: {:?}",
                                        message_id, expected_nodes.len(), expected_list
                                    );
                                    
                                    // Register with retry manager (first time only)
                                    if let Err(e) = retry_mgr.register_message(
                                        message_id.clone(),
                                        topic_str.to_string(),
                                        msg_bytes.clone(),
                                        expected_nodes.clone(),
                                    ).await {
                                        debug!("❌ [RETRY] Failed to register TransactionIdBroadcast for retry: {}", e);
                                    } else {
                                        debug!("✅ [RETRY] Successfully registered TransactionIdBroadcast {:?} for retry tracking", message_id);
                                    }
                                } else {
                                    debug!("⚠️ [RETRY] No expected nodes - skipping retry registration for TransactionIdBroadcast {:?}", message_id);
                                }
                            } else {
                                debug!("🔄 [RETRY] TransactionIdBroadcast {:?} already tracked, skipping registration (this is a retry)", message_id);
                            }
                        }
                    }
                }

                if let Err(e) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), msg_bytes)
                {
                    error!(
                        "❌ [NETWORK] Failed to gossip transaction ID broadcast to other peers: {}",
                        e
                    );
                } else {
                    if !intent_hashes.is_empty() {
                        info!(
                            "📡 [NETWORK] Gossiped transaction ID {} for intents {:?} (type: {}) to other peers",
                            transaction_id, intent_hashes, transaction_type
                        );
                    } else if let Some(solver) = &solver_address {
                        info!(
                            "📡 [NETWORK] Gossiped reward transaction ID {} for solver {} (type: {}) to other peers",
                            transaction_id, solver, transaction_type
                        );
                    } else {
                        info!(
                            "📡 [NETWORK] Gossiped transaction ID {} (type: {}) to other peers",
                            transaction_id, transaction_type
                        );
                    }
                }

                // Define add_liquidity record structure and DB prefix
                #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
                struct PendingAddLiquidityRecord {
                    request_id: String,
                    solver_id: String,
                    solver_address: String,
                    amount: String,
                    chain_id: u64,
                    signature: String,
                    signed_payload: String,
                    timestamp_ms: i64,
                    status: String,
                }
                const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";

                // Now process locally using shared handler
                if !intent_hashes.is_empty() {
                    // Parse node_id to get PeerId for security check
                    let sender_peer_id = node_id
                        .parse::<libp2p::PeerId>()
                        .unwrap_or_else(|_| libp2p::PeerId::random());

                    for intent_hash in intent_hashes.iter() {
                        // Check if this is an add_liquidity request_id (starts with "addliq:")
                        if intent_hash.starts_with("addliq:") {
                            // This is an add_liquidity request, mark as Completed
                            let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, intent_hash);
                            if let Ok(Some(mut record)) =
                                self.db
                                    .get_string_async::<PendingAddLiquidityRecord>(&key)
                                    .await
                            {
                                record.status = "Completed".to_string();
                                let _ = self.db.put_string_async(&key, &record).await;
                                info!("✅ [ADD_LIQUIDITY] Marked request {} as Completed (tx: {})", intent_hash, transaction_id);
                            }
                        } else {
                            // Regular intent, use existing handler
                            if let Err(e) = self
                                .handle_transaction_id_storage(
                                    intent_hash,
                                    &transaction_id,
                                    &transaction_type,
                                    &node_id,
                                    &sender_peer_id,
                                )
                                .await
                            {
                                error!(
                                    "❌ [NETWORK] Failed to handle transaction ID storage for intent {}: {}",
                                    intent_hash, e
                                );
                            }
                        }
                    }
                } else {
                    warn!("⚠️ [NETWORK] Transaction ID broadcast missing both intent hashes and solver address");
                }
            }
            
            ChannelMessage::UserRegistration {
                ethereum_address,
                node_id,
            } => {
                info!(
                    "👤 [NETWORK] Broadcasting user registration: {} from node {}",
                    ethereum_address, node_id
                );

                // Directly update commitments locally using the stored HMAC constant
                if let (Some(user_intent_manager), Some(dkg_node)) =
                    (&self.user_intent_manager, &self.dkg_node)
                {
                    if let Some(reg) = user_intent_manager
                        .get_user_by_address(&ethereum_address)
                        .await
                    {
                        if let Some(tweak_scalar) =
                            k256::Scalar::from_repr_vartime(reg.hmac_constant.into())
                        {
                            // Derive and store user-specific group key from updated commitments
                            match dkg_node
                                .derive_user_specific_group_key_from_commitments(tweak_scalar)
                                .await
                            {
                                Ok(group_key) => {
                                    if let Err(e) = user_intent_manager
                                        .set_user_group_key(&ethereum_address, group_key)
                                        .await
                                    {
                                        warn!("❌ [NETWORK] Failed to store user group key for {}: {}", ethereum_address, e);
                                    } else {
                                        info!("🔑 [NETWORK] Stored user-specific group key and derived addresses for {}", ethereum_address);
                                        // Log the derived addresses
                                        if let Some(user) = user_intent_manager
                                            .get_user_by_address(&ethereum_address)
                                            .await
                                        {
                                            if let Some(eth_addr) = &user.derived_eth_address {
                                                info!(
                                                    "📬 [NETWORK] Derived ETH address for {}: {}",
                                                    ethereum_address, eth_addr
                                                );
                                            }
                                            if let Some(btc_addr) = &user.derived_btc_address {
                                                info!(
                                                    "📬 [NETWORK] Derived BTC address for {}: {}",
                                                    ethereum_address, btc_addr
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("❌ [NETWORK] Failed to derive user-specific group key for {}: {}", ethereum_address, e);
                                }
                            }
                        }
                    } else {
                        warn!(
                            "❌ [NETWORK] Invalid HMAC tweak scalar for {}",
                            ethereum_address
                        );
                    }
                } else {
                    warn!("❌ [NETWORK] Missing user_intent_manager or dkg_node; cannot update commitments locally for {}", ethereum_address);
                }

                // Create and broadcast user registration message via gossipsub (same pattern as deposit intent)
                let user_reg_msg = GossipsubMessage::UserRegistration {
                    ethereum_address: ethereum_address.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&user_reg_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("user-registrations");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted user registration to P2P network");
            }

            ChannelMessage::ScheduledDKGStart => {
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();

                if let Some(dkg) = &mut self.dkg_node {
                    // This should only be called for initial DKG with 3 nodes
                    let initial_dkg_complete = dkg.is_initial_dkg_complete().await;

                    if initial_dkg_complete {
                        warn!("⚠️ [DKG] ScheduledDKGStart called but initial DKG already complete. This should not happen.");
                        return Ok(());
                    }

                    // Start the initial DKG with 3 nodes
                    info!("🚀 [DKG] Starting initial DKG with {} nodes", total);

                    if total != 3 {
                        warn!(
                            "⚠️ [DKG] Expected 4 nodes for initial DKG, but have {}",
                            total
                        );
                    }

                    if let Err(e) = dkg.update_node_params(total, threshold) {
                        warn!("❌ [DKG] Invalid params for scheduled start: {}", e);
                        return Ok(());
                    }
                    if let Err(e) = dkg.reset().await {
                        warn!("❌ [DKG] Failed to reset before scheduled start: {}", e);
                        return Ok(());
                    }
                    if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                        // Align signing threshold with the node manager's configured threshold
                        signing_node.set_threshold(threshold);
                    }
                    info!(
                        "🔄 DKG parameters updated: total_nodes={}, threshold={}",
                        total, threshold
                    );
                    if let Err(e) = dkg.start_dkg(self.node_manager.clone()).await {
                        warn!("❌ Scheduled DKG start failed: {:?}", e);
                    }
                } else {
                    warn!("❌ DKG node not initialized at scheduled start!");
                }
            }
            ChannelMessage::SolverAddLiquidity {
                request_id,
                solver_id,
                solver_address,
                amount,
                chain_id,
                signature,
                signed_payload,
                timestamp_ms,
                status,
            } => {
                use libp2p::gossipsub::IdentTopic;

                info!(
                    "💧 [ADD_LIQUIDITY] Processing solver_add_liquidity request for request_id={} solver_id={} solver_address={} amount={} chain_id={}",
                    request_id, solver_id, solver_address, amount, chain_id
                );

                // Validate chainId before persisting (must match RPC rules: 0 = BTC, 9029 = EVM).
                if chain_id != 0 && chain_id != 9029 {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Unsupported chain_id {} for request_id={}, dropping (allowed: 0=BTC, 9029=EVM)",
                        chain_id, request_id
                    );
                    return Ok(());
                }

                // Also persist locally to RocksDB so the origin node has the same pending view.
                #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
                struct PendingAddLiquidityRecord {
                    request_id: String,
                    solver_id: String,
                    solver_address: String,
                    amount: String,
                    chain_id: u64,
                    signature: String,
                    signed_payload: String,
                    timestamp_ms: i64,
                    status: String,
                }

                const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";

                let record = PendingAddLiquidityRecord {
                    request_id: request_id.clone(),
                    solver_id: solver_id.clone(),
                    solver_address: solver_address.clone(),
                    amount: amount.clone(),
                    chain_id,
                    signature: signature.clone(),
                    signed_payload: signed_payload.clone(),
                    timestamp_ms,
                    status: status.clone(),
                };

                // Use request_id as the unique key identifier
                let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, request_id);

                if let Err(e) = self.db.put_string_async(&key, &record).await {
                    warn!(
                        "⚠️ [ADD_LIQUIDITY] Failed to persist pending record for request_id={} at origin: {}",
                        request_id, e
                    );
                }

                // Broadcast to peers via gossipsub so everyone keeps a consistent pending view.
                let gossip_msg = crate::types::GossipsubMessage::SolverAddLiquidity {
                    request_id: request_id.clone(),
                    solver_id: solver_id.clone(),
                    solver_address: solver_address.clone(),
                    amount: amount.clone(),
                    chain_id,
                    signature: signature.clone(),
                    signed_payload: signed_payload.clone(),
                    timestamp_ms,
                    status: status.clone(),
                };

                let msg_bytes =
                    serde_json::to_vec(&gossip_msg).map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let topic =
                    IdentTopic::new(crate::network::transport::types::TOPIC_SOLVER_ADD_LIQUIDITY);
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic, msg_bytes)?;

                info!(
                    "📡 [ADD_LIQUIDITY] Broadcasted solver_add_liquidity request for request_id={} solver_id={} solver_address={}",
                    request_id, solver_id, solver_address
                );
            }
        }
        Ok(())
    }

    /// Handle BTC intent manager contract update batch
    /// Processes intents with network_to_target_tx_id and makes contract call to update tx-id
    pub(crate) async fn handle_btc_intent_manager_update_batch(
        &mut self,
        intent_hashes: Vec<String>,
        btc_txid: String,
        _btc_batch_round: u64,
        update_round: u64,
        timestamp: String,
        _node_id: String,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        info!(
            "🔄 [BTC_INTENT_MANAGER] Processing contract update batch: {} intents, BTC txid: {}",
            intent_hashes.len(),
            btc_txid
        );

        let user_intent_manager = self
            .user_intent_manager
            .as_ref()
            .ok_or_else(|| anyhow!("User intent manager not available"))?;

        // Fetch intent details from database
        let mut batch_intents = Vec::new();
        let mut batch_intent_inputs = Vec::new();

        for intent_hash in &intent_hashes {
            if let Some(intent) = user_intent_manager.get_intent(intent_hash).await {
                let tx_ids = user_intent_manager
                    .get_intent_transaction_ids(intent_hash)
                    .await;

                // Must have network_to_target_tx_id
                if let Some(ref tx_ids) = tx_ids {
                    if tx_ids.network_to_target_tx_id.is_none() {
                        warn!(
                            "⚠️ [BTC_INTENT_MANAGER] Intent {} missing network_to_target_tx_id, skipping",
                            intent_hash
                        );
                        continue;
                    }
                } else {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Intent {} has no transaction IDs, skipping",
                        intent_hash
                    );
                    continue;
                }

                batch_intents.push((intent_hash.clone(), intent.clone()));
            } else {
                warn!("⚠️ [BTC_INTENT_MANAGER] Intent {} not found in database", intent_hash);
            }
        }

        if batch_intents.is_empty() {
            warn!("⚠️ [BTC_INTENT_MANAGER] No valid intents found for contract update batch");
            return Ok(());
        }

        info!(
            "✅ [BTC_INTENT_MANAGER] Fetched {} intents for contract update batch",
            batch_intents.len()
        );

        // Prepare BatchIntentInput array for processBatchIntents contract call
        for (intent_hash, intent) in &batch_intents {
            let source_amount = match intent.amount.parse::<u128>() {
                Ok(amt) => amt,
                Err(e) => {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Invalid amount for intent {}: {}",
                        intent_hash, e
                    );
                    continue;
                }
            };
            let target_amount = user_intent_manager
                .get_intent_target_amount(intent_hash)
                .await
                .unwrap_or(source_amount);

            // Get transaction IDs
            let tx_ids = user_intent_manager
                .get_intent_transaction_ids(intent_hash)
                .await;

            // For BTC contract update:
            // - withdraw_tx_hash = user_to_network_tx_id (the UserToVault / user deposit tx)
            // - deposit_tx_hash = btc_txid (the BTC batch transaction ID, if available, otherwise use network_to_target_tx_id)
            let user_to_network_tx_id = tx_ids
                .as_ref()
                .and_then(|ids| ids.user_to_network_tx_id.clone())
                .unwrap_or_else(|| {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Intent {} missing user_to_network_tx_id",
                        intent_hash
                    );
                    "N/A".to_string()
                });

            let network_to_target_tx_id = tx_ids
                .as_ref()
                .and_then(|ids| ids.network_to_target_tx_id.clone())
                .unwrap_or_else(|| {
                    warn!(
                        "⚠️ [BTC_INTENT_MANAGER] Intent {} missing network_to_target_tx_id",
                        intent_hash
                    );
                    "N/A".to_string()
                });

            // Use BTC batch txid if available and not "pending", otherwise use network_to_target_tx_id
            let deposit_tx_hash = if btc_txid != "pending" && !btc_txid.is_empty() {
                Some(btc_txid.clone())
            } else {
                Some(network_to_target_tx_id.clone())
            };

            // Create BatchIntentInput for this intent
            let batch_input = crate::types::BatchIntentInput {
                source_address: intent.source_address.clone(),
                target_address: intent.target_address.clone(),
                source_chain: intent.source_chain.clone(),
                target_chain: intent.target_chain.clone(),
                source_amount,
                target_amount,
                source_token: intent.source_token.clone(),
                target_token: intent.target_token.clone(),
                intent_id: intent_hash.clone(),
                withdraw_tx_hash: user_to_network_tx_id, // UserToVault / user-to-network tx ID
                deposit_tx_hash, // The BTC batch transaction ID (or network_to_target_tx_id if batch not finalized yet)
            };

            batch_intent_inputs.push(batch_input);
        }

        if batch_intent_inputs.is_empty() {
            warn!("⚠️ [BTC_INTENT_MANAGER] No valid BatchIntentInput entries after filtering");
            return Ok(());
        }

        info!(
            "📤 [BTC_INTENT_MANAGER] Prepared {} BatchIntentInput entries",
            batch_intent_inputs.len()
        );

        // Create processBatchIntents calldata with batchType = BTC (0)
        if let Some(calldata) = crate::utils::transaction::encode_process_batch_intents_calldata(
            &batch_intent_inputs,
            crate::types::BatchType::BTC, // batchType = 0 for BTC
            &timestamp,
        ) {
            info!(
                "✅ [BTC_INTENT_MANAGER] Created processBatchIntents calldata ({} bytes) for BTC batch",
                calldata.len()
            );

            // Create and submit an MPC-signed contract call transaction for processBatchIntents
            // Use MAIN DKG group key (not vault key) for processBatchIntents
            let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                dkg_node.get_final_public_key().await
            } else {
                None
            };

            let Some(group_public_key) = group_public_key else {
                warn!("❌ [BTC_INTENT_MANAGER] Main DKG group key not available; cannot create contract call");
                return Ok(());
            };

            // Contract address for IntentManager (processBatchIntents)
            let contract_address_env =
                std::env::var("INTENT_MANAGER_CONTRACT_ADDRESS").unwrap_or_else(|_| {
                    "0x0055Ca34A66D962d68A07a3e1BA6d75b9e4cD383".to_string()
                });
            if contract_address_env == "0x0000000000000000000000000000000000000000" {
                warn!("❌ [BTC_INTENT_MANAGER] INTENT_MANAGER_CONTRACT_ADDRESS not configured");
                return Ok(());
            }

            // Use the MAIN group-derived EVM address as sender
            let from_address =
                crate::utils::get_eth_address_from_group_key(group_public_key);
            let chain_id =
                crate::utils::transaction::get_chain_id_from_name("qubetics").unwrap_or(9029);

            // Estimate gas; abort if it would revert
            let calldata_hex = format!("0x{}", hex::encode(&calldata));
            let estimated_gas =
                crate::utils::transaction::estimate_gas_for_deposit_intent(
                    &from_address,
                    &contract_address_env,
                    &calldata_hex,
                    chain_id,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("BTC contract update batch gas estimation failed: {}", e)
                })?;
            let gas_limit = estimated_gas + (estimated_gas / 10);

            let nonce = crate::utils::transaction::fetch_ethereum_nonce(&from_address, chain_id)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to fetch nonce for {}: {}", from_address, e)
                })?;

            let gas_price =
                crate::utils::transaction::get_gas_price_for_chain("qubetics", chain_id)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(
                            "⚠️ [BTC_INTENT_MANAGER] Failed to get dynamic gas price: {}, using fallback",
                            e
                        );
                        crate::utils::transaction::get_default_gas_price_for_chain("qubetics")
                    });

            let contract_tx = crate::types::ContractTransaction {
                to: contract_address_env.clone(),
                value: "0x0".to_string(),
                nonce,
                gas_limit,
                gas_price,
                chain_id,
                data: calldata_hex,
            };

            // Start MPC signing
            if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
                let available_nodes: Vec<PeerId> =
                    self.node_manager.get_active_nodes().into_iter().collect();
                signing_node.set_available_nodes(available_nodes);

                // Ensure MAIN group key is available on signing node
                signing_node.set_group_public_key(group_public_key);

                // Use MAIN final secret share for signing (network group key path)
                // Observer nodes will have None here — sign_contract_message() handles
                // the observer path internally (builds TX, skips ECDSA, stores for aggregation).
                let secret_share = if let Some(dkg_node) = &self.dkg_node {
                    dkg_node.get_final_secret_share().await
                } else {
                    None
                };

                let contract_tx_bytes =
                    crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                let contract_chain_handler =
                    signing_node.get_contract_chain_handler().clone();
                let mut eth_signer = crate::signing::EthereumSigner::new(&mut signing_node);
                eth_signer
                    .sign_contract_message(
                        contract_tx_bytes,
                        &contract_chain_handler,
                        &contract_tx,
                        None,
                        None, // user_eth_address (not applicable)
                        intent_hashes.clone(),
                        // Use the main DKG share as an explicit signing key override.
                        secret_share,
                        None,
                        None,
                        None, // tics_withdraw_identifiers (not applicable)
                        None, // tics_claim_reward_identifiers (not applicable)
                        nonce_tuple_id.clone(), // Coordinated nonce from batch broadcast
                    )
                    .await?;

                info!(
                    "✅ [BTC_INTENT_MANAGER] Submitted processBatchIntents contract transaction into MPC signing flow ({} intents, batchType=BTC)",
                    intent_hashes.len()
                );
                info!(
                    "ℹ️  [BTC_INTENT_MANAGER] Signatures will be sent to final node for round {}",
                    update_round
                );
            } else {
                warn!(
                    "❌ [BTC_INTENT_MANAGER] Signing node not available; cannot start MPC signing for batch contract call"
                );
            }
        } else {
            warn!("❌ [BTC_INTENT_MANAGER] Failed to encode processBatchIntents calldata");
        }

        Ok(())
    }

    /// Handle solver add_liquidity batch
    /// All nodes verify the batch and participate in distributed signing of batchTransfer tx
    /// All nodes already have the full records in RocksDB, so we only need request_ids
    pub(crate) async fn handle_solver_add_liquidity_batch(
        &mut self,
        request_ids: Vec<String>,
        round: u64,
        _timestamp: String,
        node_id: String,
        nonce_tuple_id: Option<String>,
    ) -> Result<()> {
        info!(
            "💧 [ADD_LIQUIDITY_BATCH] Processing batch: {} requests, round {}, from node {}, nonce: {:?}",
            request_ids.len(),
            round,
            node_id,
            nonce_tuple_id
        );

        if request_ids.is_empty() {
            warn!("⚠️ [ADD_LIQUIDITY_BATCH] Empty batch received");
            return Ok(());
        }

        // Look up all records from RocksDB and extract data
        const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";
        
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct PendingAddLiquidityRecord {
            request_id: String,
            solver_id: String,
            solver_address: String,
            amount: String,
            chain_id: u64,
            signature: String,
            signed_payload: String,
            timestamp_ms: i64,
            status: String,
        }

        let mut solver_ids: Vec<String> = Vec::new();
        let mut amounts: Vec<String> = Vec::new();
        let mut chain_ids: Vec<u64> = Vec::new();
        let mut chain_types: Vec<u8> = Vec::new();

        for request_id in &request_ids {
            let key = format!("{}{}", ADD_LIQUIDITY_DB_PREFIX, request_id);
            if let Ok(Some(record)) =
                self.db
                    .get_string_async::<PendingAddLiquidityRecord>(&key)
                    .await
            {
                // Extract data for transaction
                solver_ids.push(record.solver_id.clone());
                amounts.push(record.amount.clone());
                chain_ids.push(record.chain_id);
                
                // Map chain_id to ChainType enum:
                // 0 (BTC) -> ChainType::BTC (0)
                // 9029 (EVM/Qubetics) -> ChainType::EVM (1)
                let chain_type = match record.chain_id {
                    0 => 0u8,     // BTC
                    9029 => 1u8,  // EVM
                    _ => {
                        warn!(
                            "⚠️ [ADD_LIQUIDITY_BATCH] Unsupported chain_id {} for request {}, defaulting to EVM",
                            record.chain_id, request_id
                        );
                        1u8 // Default to EVM
                    }
                };
                chain_types.push(chain_type);

                // Keep status as "Pending" - it will be marked "Completed" on success
                info!("📦 [ADD_LIQUIDITY_BATCH] Processing request {} (status: {})", request_id, record.status);
            } else {
                warn!("⚠️ [ADD_LIQUIDITY_BATCH] Request {} not found in RocksDB, skipping", request_id);
            }
        }

        // Verify we found all requests
        if solver_ids.len() != request_ids.len() {
            error!("❌ [ADD_LIQUIDITY_BATCH] Some requests not found in RocksDB");
            return Err(anyhow!("Some requests not found in RocksDB"));
        }

        // Safety check: ensure we have at least one request with chain_id
        if chain_ids.is_empty() {
            error!("❌ [ADD_LIQUIDITY_BATCH] No chain_ids found in batch");
            return Err(anyhow!("No chain_ids found in batch"));
        }

        // For now, assume all requests in a batch are for the same chain
        // (can be extended to process per-chain sub-batches later)
        let chain_id = chain_ids[0];
        info!("💧 [ADD_LIQUIDITY_BATCH] Target chain_id: {}, chain_type: {}", chain_id, chain_types[0]);

        // Parse amounts to U256
        let amounts_u256: Vec<U256> = amounts
            .iter()
            .filter_map(|a| U256::from_dec_str(a).ok())
            .collect();

        if amounts_u256.len() != amounts.len() {
            error!("❌ [ADD_LIQUIDITY_BATCH] Failed to parse some amounts");
            return Err(anyhow!("Failed to parse amounts"));
        }

        // Get solver contract address from ENV
        let solver_contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x390bBeE9A268f273f3F5AF09BB5aE59516dd8327".to_string());
        if solver_contract_address.is_empty() {
            error!("❌ [ADD_LIQUIDITY_BATCH] SOLVER_CONTRACT_ADDRESS not configured");
            return Err(anyhow!("SOLVER_CONTRACT_ADDRESS not configured"));
        }

        // Derive liquidity operator address from vault group key (same as rewards/remove_liquidity)
        let dkg_node = if let Some(node) = &self.dkg_node {
            node
        } else {
            warn!(
                "❌ [ADD_LIQUIDITY_BATCH] Cannot process batch - DKG node unavailable"
            );
            return Ok(());
        };

        let group_public_key = if let Some(key) = dkg_node.get_vault_group_key().await {
            key
        } else {
            warn!(
                "❌ [ADD_LIQUIDITY_BATCH] Liquidity operator group key unavailable; cannot derive liquidity operator address"
            );
            return Ok(());
        };

        let liquidity_operator_address =
            crate::utils::get_eth_address_from_group_key(group_public_key);

        info!(
            "💧 [ADD_LIQUIDITY_BATCH] Building addLiquidityBatch tx: from={}, to={}, {} deposits",
            liquidity_operator_address,
            solver_contract_address,
            solver_ids.len()
        );

        // Build the addLiquidityBatch transaction using helper from utils/transaction.rs
        let chain_tx = crate::utils::transaction::create_solver_add_liquidity_batch_transaction(
            &liquidity_operator_address,
            &solver_ids,
            &amounts_u256,
            &chain_types,
            &solver_contract_address,
            chain_id,
        )
        .await?;

        // Expect an Ethereum transaction
        let eth_tx = match chain_tx {
            crate::chain_abstraction::ChainTransaction::Ethereum(tx) => tx,
            _ => {
                warn!(
                    "❌ [ADD_LIQUIDITY_BATCH] Batch transaction is not an Ethereum transaction"
                );
                return Ok(());
            }
        };

        info!(
            "✅ [ADD_LIQUIDITY_BATCH] Built batchTransfer Ethereum transaction: nonce={}, gas_limit={}",
            eth_tx.nonce, eth_tx.gas_limit
        );

        // Start MPC signing using vault (liquidity operator) DKG key
        if let Some(arc) = &self.signing_node {
                    let mut signing_node = arc.lock().await;
            let available_nodes: Vec<PeerId> =
                self.node_manager.get_active_nodes().into_iter().collect();
            signing_node.set_available_nodes(available_nodes);
            signing_node.set_chain_handler(
                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                    eth_tx.chain_id,
                )
                .into(),
            );

            let vault_tweaked_share = dkg_node.get_vault_tweaked_secret_share().await;

            // All nodes (DKG + observer) proceed through sign_contract_message().
            // sign_contract_message() internally checks has_dkg_share() and handles
            // the observer path (builds TX, skips signing, stores for aggregation).
            signing_node.set_vault_group_key(group_public_key);

            let contract_tx = crate::types::intent::ContractTransaction {
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
            let contract_chain_handler = signing_node.get_contract_chain_handler().clone();
            let mut eth_signer = crate::signing::EthereumSigner::new(&mut signing_node);

            // Pass request_ids as intent_hashes for tracking through signing flow
            // When transaction succeeds/fails, these IDs will be used to update status
            eth_signer
                .sign_contract_message(
                    contract_tx_bytes,
                    &contract_chain_handler,
                    &contract_tx,
                    vault_tweaked_share.clone(),
                    None,     // user_eth_address (not applicable)
                    request_ids.clone(),   // Pass request_ids for tracking
                    vault_tweaked_share,
                    None,     // request_id
                    None,     // original_request
                    None,     // tics_withdraw_identifiers (not applicable)
                    None,     // tics_claim_reward_identifiers (not applicable)
                    nonce_tuple_id.clone(), // Coordinated nonce from batch broadcast
                )
                .await?;

            info!(
                "✅ [ADD_LIQUIDITY_BATCH] Submitted addLiquidityBatch transaction into MPC signing flow ({} deposits)",
                request_ids.len()
            );
            info!(
                "ℹ️  [ADD_LIQUIDITY_BATCH] Request IDs tracked: {:?}",
                request_ids
            );
            info!(
                "ℹ️  [ADD_LIQUIDITY_BATCH] Signatures will be sent to final node for round {}",
                round
            );
        } else {
            warn!(
                "❌ [ADD_LIQUIDITY_BATCH] Signing node not available; cannot start MPC signing for batch"
            );
            // Don't mark as Failed - this is a temporary condition, can be retried
        }

        Ok(())
    }



}

