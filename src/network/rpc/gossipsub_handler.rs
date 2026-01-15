/// Gossipsub message handler
/// Handles all gossipsub message types: DKG, Signing, Command, Consensus, VRF, etc.
///
/// NOTE: This module contains the gossipsub message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~2038-3559 of the original file
use anyhow::{anyhow, Result};
use ff::PrimeField;
use libp2p::{gossipsub::Message, PeerId};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::{
    signing::{BitcoinSigner, EthereumSigner},
    types::{
        messaging::{SequencerConsensusMessage, SequencerDomain, LiquidityMessage, RewardMessage, SyncMessage},
        p2p::SerializablePeerId, vrf::VrfRoundSyncResponse,
        ChannelMessage, GossipsubMessage,
    },
};

use crate::network::transport::types::{
    MpcNetworkLayer, VrfDomain, TOPIC_CONSENSUS,
};

impl MpcNetworkLayer {
    /// Main gossipsub message handler - delegates to specific message type handlers
    pub(crate) async fn handle_gossipsub_message(&mut self, message: &Message) -> Result<()> {
        // Better error handling for message deserialization
        let msg = match serde_json::from_slice::<GossipsubMessage>(&message.data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to deserialize gossipsub message: {:?}", e);
                return Ok(()); // Continue processing other messages
            }
        };

        match msg {
            GossipsubMessage::DKG(dkg_msg) => {
                // Send ACK if it's a critical message
                // We need to wrap it back into GossipsubMessage to use the check
                let wrapper = GossipsubMessage::DKG(dkg_msg.clone());
                if let Some(msg_type) = crate::network::rpc::retry_manager::RetryManager::is_critical_message(&wrapper) {
                    self.send_critical_message_ack(msg_type, &wrapper).await;
                }

                if let crate::protocols::DKGMessage::NodeDisconnected {
                    ref disconnected_node_id,
                    broadcaster_node_id: _,
                } = dkg_msg
                {
                     // Parse the disconnected node ID
                    if let Ok(peer_id) = disconnected_node_id.parse::<PeerId>() {
                        // Check if we haven't already processed this disconnect
                        if self.node_manager.get_active_nodes().contains(&peer_id) {
                            info!("📢 [DISCONNECT] Processing disconnect for node {}", peer_id);
                            self.handle_node_disconnect_internal(peer_id).await;
                        } else {
                            info!("📢 [DISCONNECT] Node {} already removed, skipping", peer_id);
                        }
                    }
                }
                if let Some(dkg_node) = &mut self.dkg_node {
                    dkg_node
                        .handle_message(dkg_msg, self.node_manager.clone())
                        .await?;
                }
            }
            GossipsubMessage::Signing(signing_msg) => {
                if let Some(signing_node) = &mut self.signing_node {
                     if let Err(e) = signing_node.handle_message(signing_msg).await {
                         error!("❌ [NETWORK] Signing message processing failed: {}", e);
                     }
                } else {
                    warn!("❌ [NETWORK] Signing node not available to handle signing message");
                }
            }
            GossipsubMessage::Command(cmd) => {
                if let Some(cmd_processor) = self.command_processor.as_ref() {
                    cmd_processor.handle_message(cmd).await?;
                }
            }
            GossipsubMessage::Consensus(consensus_msg) => {
                if let Some(signing_node) = &mut self.signing_node {
                    signing_node.handle_consensus_message(consensus_msg.clone()).await?;
                }
                if let Some(sequencer) = &self.contract_sequencer {
                     let _ = sequencer.handle_consensus_message(consensus_msg.clone()).await;
                }
                if let Some(sequencer) = &self.network_transaction_sequencer {
                     let _ = sequencer.handle_consensus_message(consensus_msg.clone()).await;
                }
            }

            // Consolidated Topics
            GossipsubMessage::SequencerConsensus(inner) => self.handle_sequencer_consensus_message(inner, message.source).await?,
            GossipsubMessage::Liquidity(inner) => self.handle_liquidity_message(inner).await?,
            GossipsubMessage::Rewards(inner) => self.handle_reward_message(inner).await?,
            GossipsubMessage::Sync(inner) => self.handle_sync_message(inner).await?,
            GossipsubMessage::PeerDiscovered { peer, sequence, index } => self.handle_peer_discovery(peer, sequence, index).await?,
            GossipsubMessage::CriticalMessageAck { message_type, message_id, node_id } => self.handle_retry_ack(message_type, message_id, node_id).await?,

            // Core / Legacy / Generic
            GossipsubMessage::VrfSelection(vrf_msg) => {
                 if self.node_manager.as_any().downcast_ref::<crate::node_selection::VrfNodeManager>().is_some() {
                     // Log?
                 } else {
                     info!("Received VRF selection message but node manager is not VRF-based: {:?}", vrf_msg);
                 }
            }
            GossipsubMessage::VrfSelectedNodes(broadcast_msg) => {
                 let round = broadcast_msg.round;
                 let selector_node_id = broadcast_msg.selector_node_id.0;
                 let sender = match message.source {
                    Some(pid) => pid,
                    None => {
                        warn!("🚫 [SECURITY] Rejecting VrfSelectedNodes broadcast: message has no source");
                        return Ok(());
                    }
                 };

                 self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
                    &GossipsubMessage::VrfSelectedNodes(broadcast_msg.clone()),
                ).await;
                 
                 if let Some(signing_node) = &mut self.signing_node {
                     signing_node.handle_vrf_selected_nodes_broadcast(self.node_manager.get_total_nodes(), broadcast_msg, sender);
                     info!("💾 [VRF] Stored VRF selected nodes from node {} for round {}", selector_node_id, round);
                 }
            }
            GossipsubMessage::VrfRoundSyncRequest(req) => {
                 let peer = req.from.0;
                 let vrf_domain = VrfDomain::Signing;
                 let reference_round = self.get_local_vrf_round_for_domain(vrf_domain, Some(&req.context)).await;
                 if self.store_peer_round_if_valid(vrf_domain, &req.context, peer, reference_round, req.current_round) {
                     info!("💾 [VRF_SYNC] Stored round {:?} for peer {}", req.current_round, peer);
                 }
                 let response_round = self.get_local_vrf_round_for_domain(vrf_domain, Some(&req.context)).await;
                 let response = GossipsubMessage::VrfRoundSyncResponse(VrfRoundSyncResponse {
                    from: SerializablePeerId(self.local_peer_id),
                    current_round: response_round,
                    context: req.context.clone(),
                 });
                 if let Ok(data) = serde_json::to_vec(&response) {
                     let _ = self.message_tx.send(ChannelMessage::Broadcast { topic: TOPIC_CONSENSUS.to_string(), data }).await;
                 }
            }
            GossipsubMessage::VrfRoundSyncResponse(resp) => {
                 let peer = resp.from.0;
                 let vrf_domain = VrfDomain::Signing;
                 let reference_round = self.get_local_vrf_round_for_domain(vrf_domain, Some(&resp.context)).await;
                 if self.store_peer_round_if_valid(vrf_domain, &resp.context, peer, reference_round, resp.current_round) {
                     info!("💾 [VRF_SYNC] Stored round {:?} for peer {}", resp.current_round, peer);
                 }
            }

            // Preserved Handlers (Delegated)
            GossipsubMessage::DepositIntent { intent, intent_id, user_eth_address, transaction_type, amount } => {
                self.handle_deposit_intent(intent, intent_id, user_eth_address, transaction_type, amount).await?;
            }
            GossipsubMessage::TransactionIdBroadcast { intent_hash, transaction_id, transaction_type, solver_address, node_id } => {
                self.handle_transaction_id_broadcast(intent_hash, transaction_id, transaction_type, solver_address, node_id).await?;
            }
            GossipsubMessage::TransactionErrorBroadcast { intent_hash, error_message, transaction_type, solver_address, node_id } => {
                self.handle_transaction_error_broadcast(intent_hash, error_message, transaction_type, solver_address, node_id).await?;
            }
            GossipsubMessage::IntentHashBroadcast { intent_hash, node_id } => {
                self.handle_intent_hash_broadcast(intent_hash, node_id).await?;
            }
            GossipsubMessage::IntentHash { intent_hash, signer, intent } => {
                self.handle_intent_hash(intent_hash, signer, intent).await?;
            }
            GossipsubMessage::UserRegistration { ethereum_address, timestamp, node_id } => {
                self.handle_user_registration(ethereum_address, timestamp, node_id).await?;
            }

            // Transaction Broadcast
             GossipsubMessage::TransactionBroadcast { sequencer_request_id, blockchain_tx_hash, chain_id: _ } => {
                 if let Some(req_id) = sequencer_request_id {
                     info!("✅ [SEQUENCER] Transaction broadcast success for req {}: {}", req_id, blockchain_tx_hash);
                     if let Some(sequencer) = &self.contract_sequencer {
                         if let Err(e) = sequencer.handle_transaction_submitted(req_id.clone(), blockchain_tx_hash.clone()).await {
                             warn!("⚠️ [VAULT_SEQUENCER] Failed to mark transaction submitted: {}", e);
                         }
                     }
                     if let Some(sequencer) = &self.network_transaction_sequencer {
                         if let Err(e) = sequencer.handle_transaction_submitted(req_id.clone(), blockchain_tx_hash.clone()).await {
                             warn!("⚠️ [MAIN_SEQUENCER] Failed to mark transaction submitted: {}", e);
                         }
                     }
                 }
            }
            GossipsubMessage::TransactionFailure { sequencer_request_id, blockchain_tx_hash, error, original_request } => {
                error!("❌ [SEQUENCER] Transaction failure broadcast for req {}: {} (hash: {})", sequencer_request_id, error, blockchain_tx_hash);
                if let Some(sequencer) = &self.contract_sequencer {
                    if let Some(_request) = &original_request {
                         if let Err(e) = sequencer.handle_transaction_failure(sequencer_request_id.clone(), blockchain_tx_hash.clone(), error.clone()).await {
                             error!("❌ [VAULT_SEQUENCER] Failed to handle transaction failure: {}", e);
                         }
                    }
                }
                if let Some(sequencer) = &self.network_transaction_sequencer {
                    if let Err(e) = sequencer.handle_transaction_failure(sequencer_request_id.clone(), blockchain_tx_hash.clone(), error.clone()).await {
                        error!("❌ [MAIN_SEQUENCER] Failed to handle transaction failure: {}", e);
                    }
                }
            }

            GossipsubMessage::VersionAnnouncement { .. } => {}
            GossipsubMessage::UpgradeAnnouncement { .. } => {}
        }
        Ok(())
    }

    async fn send_critical_message_ack(
        &mut self,
        msg_type: crate::network::rpc::retry_manager::CriticalMessageType,
        msg: &GossipsubMessage,
    ) {
        let msg_id_result = crate::network::rpc::retry_manager::RetryManager::generate_message_id(msg_type.clone(), msg);
        if let Ok(message_id) = msg_id_result {
            let unique_id = message_id.unique_id;
            info!("📤 [RETRY] Sending ACK for {} (id: {})", unique_id, unique_id);
            
            let type_str = match msg_type {
                crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast => "TransactionIdBroadcast",
                crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes => "VrfSelectedNodes",
                crate::network::rpc::retry_manager::CriticalMessageType::SequencerConsensusVrf => "SequencerConsensusVrf",
                crate::network::rpc::retry_manager::CriticalMessageType::SequencerSync => "SequencerSync",
                crate::network::rpc::retry_manager::CriticalMessageType::DKGShareValidation => "DKGShareValidation",
                crate::network::rpc::retry_manager::CriticalMessageType::DKGNewNodeShare => "DKGNewNodeShare",
                crate::network::rpc::retry_manager::CriticalMessageType::DKGCommitmentBroadcast => "DKGCommitmentBroadcast",
            };

            let ack_msg = GossipsubMessage::CriticalMessageAck {
                message_type: type_str.to_string(),
                message_id: unique_id.clone(),
                node_id: self.local_peer_id,
            };

            let topic = match msg_type {
                 crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast => crate::network::transport::types::TOPIC_TRANSACTION_BROADCAST,
                 crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes => crate::network::transport::types::TOPIC_VRF_SELECTION,
                 crate::network::rpc::retry_manager::CriticalMessageType::SequencerConsensusVrf => crate::network::transport::types::TOPIC_SEQUENCER_CONSENSUS,
                 crate::network::rpc::retry_manager::CriticalMessageType::SequencerSync => crate::network::transport::types::TOPIC_TX_SYNC,
                 crate::network::rpc::retry_manager::CriticalMessageType::DKGShareValidation |
                 crate::network::rpc::retry_manager::CriticalMessageType::DKGNewNodeShare |
                 crate::network::rpc::retry_manager::CriticalMessageType::DKGCommitmentBroadcast => crate::types::dkg::MSG_TOPIC_DKG,
            };

            if let Ok(data) = serde_json::to_vec(&ack_msg) {
                if let Err(e) = self.message_tx.send(ChannelMessage::Broadcast { topic: topic.to_string(), data }).await {
                     warn!("❌ [RETRY] Failed to broadcast ACK: {}", e);
                }
            }
        }
    }

    // --- Consolidated Topic Handlers ---

    async fn handle_peer_discovery(&mut self, peer: PeerId, sequence: Option<u64>, index: Option<usize>) -> Result<()> {
        info!("🎯 Peer discovered via gossipsub: {:?} (seq: {:?}, idx: {:?})", peer, sequence, index);

        // Check duplicates
        if self.node_manager.get_active_nodes().contains(&peer) {
            return Ok(());
        }

        // Store index
        if let Some(idx) = index {
            self.peer_discovery.peer_indices.insert(peer, idx);
            let key = crate::database::key_utils::peer_index_key(&peer.to_string());
            if let Err(e) = self.db.put_string_async(&key, &idx.to_string()).await { // Fixed: Convert idx to string
                 warn!("Failed to persist peer index: {:?}", e);
            }
        }

        match self.node_manager.add_node(peer) {
            Ok(_) => {
                info!("✅ Successfully added peer {} to node manager", peer);
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();
                info!("📊 Updated node count: {}, threshold: {}", total, threshold);

                if let Some(sequencer) = &self.contract_sequencer {
                    sequencer.update_total_nodes(total).await;
                }

                if let Some(signing_node) = &mut self.signing_node {
                    signing_node.set_threshold(threshold);
                    info!("🔄 [THRESHOLD] Updated signing node threshold to {} (total nodes: {})", threshold, total);
                }

                if let Some(dkg_node) = &mut self.dkg_node {
                    if dkg_node.is_initial_dkg_complete().await {
                         info!("🔄 [EXISTING_NODE] New peer {} joined network, will respond to share requests", peer);
                    } else {
                         info!("ℹ️ [NEW_NODE] Initial DKG not yet completed");
                    }
                }
            }
            Err(e) => {
                warn!("❌ Failed to add peer {} to node manager: {:?}", peer, e);
            }
        }
        Ok(())
    }

    async fn handle_retry_ack(&mut self, message_type: String, message_id: String, node_id: PeerId) -> Result<()> {
        info!("✅ [RETRY] Received ACK for message type {} (id: {}) from {}", message_type, message_id, node_id);
        
        let msg_type = match message_type.as_str() {
             "TransactionIdBroadcast" => crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
             "VrfSelectedNodes" => crate::network::rpc::retry_manager::CriticalMessageType::VrfSelectedNodes,
             "SequencerConsensusVrf" => crate::network::rpc::retry_manager::CriticalMessageType::SequencerConsensusVrf,
             "SequencerSync" => crate::network::rpc::retry_manager::CriticalMessageType::SequencerSync,
             "DKGShareValidation" => crate::network::rpc::retry_manager::CriticalMessageType::DKGShareValidation,
             "DKGNewNodeShare" => crate::network::rpc::retry_manager::CriticalMessageType::DKGNewNodeShare,
             "DKGCommitmentBroadcast" => crate::network::rpc::retry_manager::CriticalMessageType::DKGCommitmentBroadcast,
             // Mappings for backward compatibility if needed, or just ignore unknown
             _ => {
                 warn!("⚠️ [RETRY] Unknown message type in ACK: {}", message_type);
                 return Ok(());
             }
        };

        let message_id_obj = crate::network::rpc::retry_manager::MessageId {
            message_type: msg_type.clone(),
            unique_id: message_id.clone(),
        };

        if let Some(retry_mgr) = &self.retry_manager {
             match retry_mgr.record_acknowledgment(&message_id_obj, node_id).await {
                 Ok(complete) => {
                     if complete { info!("🎉 [RETRY] ACK recorded - all nodes have acknowledged!"); }
                     else { info!("📝 [RETRY] ACK recorded - still waiting for more nodes"); }
                 }
                 Err(e) => error!("❌ [RETRY] Failed to record acknowledgment: {}", e),
             }
        } else {
            warn!("⚠️ [RETRY] Retry manager not available - ACK not recorded");
        }
        Ok(())
    }

    async fn handle_sequencer_consensus_message(&mut self, msg: SequencerConsensusMessage, source: Option<PeerId>) -> Result<()> {
        match msg {
            SequencerConsensusMessage::Select { domain, round, request_id, final_node_id, signature: _ } => {
                match domain {
                    SequencerDomain::Vault => {
                        info!("📨 [VAULT_SEQUENCER] Received SELECT: round={}, request_id={}, from={}", round, request_id, final_node_id);
                        if let Some(sequencer) = &self.contract_sequencer {
                            if let Err(e) = sequencer.handle_select_message(round, request_id, final_node_id).await {
                                error!("❌ [VAULT_SEQUENCER] Failed to handle SELECT: {}", e);
                            }
                        }
                    }
                    SequencerDomain::Main => {
                        info!("📨 [MAIN_SEQUENCER] Received SELECT: round={}, request_id={}, from={}", round, request_id, final_node_id);
                        if let Some(sequencer) = &self.network_transaction_sequencer {
                            if let Err(e) = sequencer.handle_select_message(round, request_id, final_node_id).await {
                                error!("❌ [MAIN_SEQUENCER] Failed to handle SELECT: {}", e);
                            }
                        }
                    }
                    _ => {}
                }
            }
            SequencerConsensusMessage::Ack { domain, round, request_id, node_id } => {
                match domain {
                    SequencerDomain::Vault => {
                        info!("✅ [VAULT_SEQUENCER] Received ACK: round={}, request_id={}, from={}", round, request_id, node_id);
                        if let Some(sequencer) = &self.contract_sequencer {
                            sequencer.handle_select_ack(round, &request_id, node_id).await;
                        }
                    }
                    SequencerDomain::Main => {
                        info!("✅ [MAIN_SEQUENCER] Received ACK: round={}, request_id={}, from={}", round, request_id, node_id);
                        if let Some(sequencer) = &self.network_transaction_sequencer {
                            sequencer.handle_select_ack(round, &request_id, node_id).await;
                        }
                    }
                    _ => {}
                }
            }
            SequencerConsensusMessage::Missing { domain, round, request_id, node_id } => {
                match domain {
                    SequencerDomain::Vault => warn!("⚠️ [VAULT_SEQUENCER] Received MISSING: round={}, request_id={}, from={}", round, request_id, node_id),
                    SequencerDomain::Main => warn!("⚠️ [MAIN_SEQUENCER] Received MISSING: round={}, request_id={}, from={}", round, request_id, node_id),
                    _ => {}
                }
            }
            SequencerConsensusMessage::VrfSelectedNodes { domain, broadcast } => {
                // Send ACK
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::SequencerConsensusVrf,
                    &GossipsubMessage::SequencerConsensus(SequencerConsensusMessage::VrfSelectedNodes {
                        domain: domain.clone(),
                        broadcast: broadcast.clone()
                    }),
                ).await;

                let sender_peer_id = match source {
                    Some(pid) => pid,
                    None => {
                        warn!("🚫 [SECURITY] Rejecting VrfSelectedNodes broadcast: message has no source");
                        return Ok(());
                    }
                };

                match domain {
                    SequencerDomain::Vault => {
                        info!("📥 [VAULT_SEQUENCER] Received VRF broadcast: round={}, from={}", broadcast.round, broadcast.selector_node_id.0);
                        if let Some(sequencer) = &self.contract_sequencer {
                            let sequencer_clone = sequencer.clone();
                            let broadcast_msg_clone = broadcast.clone();
                            let total_nodes = self.node_manager.get_total_nodes();
                            let min_selections = total_nodes;
                            // Spawn async task
                            tokio::spawn(async move {
                                if let Err(e) = sequencer_clone.handle_vrf_broadcast(broadcast_msg_clone, sender_peer_id, total_nodes).await {
                                    error!("❌ [VAULT_SEQUENCER] Failed to handle VRF broadcast: {}", e);
                                    return;
                                }
                                if sequencer_clone.can_start_consensus(broadcast.round, min_selections).await {
                                    info!("🎯 [VAULT_SEQUENCER] Enough selections, waiting 2s for retries");
                                    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
                                    if let Err(e) = sequencer_clone.check_and_trigger_consensus(broadcast.round, min_selections).await {
                                        error!("❌ [VAULT_SEQUENCER] Failed to trigger consensus: {}", e);
                                    }
                                }
                            });
                        }
                    }
                    SequencerDomain::Main => {
                         info!("📥 [MAIN_SEQUENCER] Received VRF broadcast: round={}, from={}", broadcast.round, broadcast.selector_node_id.0);
                         if let Some(sequencer) = &self.network_transaction_sequencer {
                            let sequencer_clone = sequencer.clone();
                            let broadcast_msg_clone = broadcast.clone();
                            let total_nodes = self.node_manager.get_total_nodes();
                            let min_selections = total_nodes;
                            tokio::spawn(async move {
                                if let Err(e) = sequencer_clone.handle_vrf_broadcast(broadcast_msg_clone, sender_peer_id, total_nodes).await {
                                    error!("❌ [MAIN_SEQUENCER] Failed to handle VRF broadcast: {}", e);
                                    return;
                                }
                                if sequencer_clone.can_start_consensus(broadcast.round, min_selections).await {
                                    info!("🎯 [MAIN_SEQUENCER] Enough selections, waiting 2s for retries");
                                    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
                                    if let Err(e) = sequencer_clone.check_and_trigger_consensus(broadcast.round, min_selections).await {
                                        error!("❌ [MAIN_SEQUENCER] Failed to trigger consensus: {}", e);
                                    }
                                }
                            });
                         }
                    }
                    _ => {}
                }
            }
             SequencerConsensusMessage::VrfRoundSyncRequest { domain, req } => {
                let vrf_domain = match domain {
                    SequencerDomain::Vault => VrfDomain::VaultSequencer,
                    SequencerDomain::Main => VrfDomain::MainSequencer,
                    _ => return Ok(()),
                };
                let peer = req.from.0;
                let reference_round = self.get_local_vrf_round_for_domain(vrf_domain, Some(&req.context)).await;
                if self.store_peer_round_if_valid(vrf_domain, &req.context, peer, reference_round, req.current_round) {
                    info!("💾 [{:?}_VRF_SYNC] Stored round {:?} for peer {}", vrf_domain, req.current_round, peer);
                }
                let response_round = self.get_local_vrf_round_for_domain(vrf_domain, Some(&req.context)).await;
                
                let response = GossipsubMessage::SequencerConsensus(SequencerConsensusMessage::VrfRoundSyncResponse {
                    domain: domain.clone(),
                    resp: VrfRoundSyncResponse {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round: response_round,
                        context: req.context.clone(),
                    }
                });

                let topic = match domain {
                    SequencerDomain::Vault => crate::network::transport::types::TOPIC_SEQUENCER_CONSENSUS,
                    SequencerDomain::Main => crate::network::transport::types::TOPIC_SEQUENCER_CONSENSUS, // Use shared topic now
                     _ => return Ok(()),
                };

                if let Ok(data) = serde_json::to_vec(&response) {
                    let _ = self.message_tx.send(ChannelMessage::Broadcast { topic: topic.to_string(), data }).await;
                }
            }
            SequencerConsensusMessage::VrfRoundSyncResponse { domain, resp } => {
                let vrf_domain = match domain {
                    SequencerDomain::Vault => VrfDomain::VaultSequencer,
                    SequencerDomain::Main => VrfDomain::MainSequencer,
                    _ => return Ok(()),
                };
                 let peer = resp.from.0;
                 let reference_round = self.get_local_vrf_round_for_domain(vrf_domain, Some(&resp.context)).await;
                 if self.store_peer_round_if_valid(vrf_domain, &resp.context, peer, reference_round, resp.current_round) {
                     info!("💾 [{:?}_VRF_SYNC] Stored round {:?} for peer {}", vrf_domain, resp.current_round, peer);
                 }
            }
        }
        Ok(())
    }

    async fn handle_sync_message(&mut self, msg: SyncMessage) -> Result<()> {
        match msg {
            SyncMessage::Sequencer { transaction_id, sequence, node_id, state } => {
                info!("🔄 [SEQUENCER] Sync: tx_id={}, seq={}, node={}, state={}", transaction_id, sequence, node_id, state);
                self.send_critical_message_ack(
                    crate::network::rpc::retry_manager::CriticalMessageType::SequencerSync,
                    &GossipsubMessage::Sync(SyncMessage::Sequencer {
                        transaction_id: transaction_id.clone(),
                        sequence,
                        node_id: node_id.clone(),
                        state: state.clone(),
                    }),
                ).await;

                if let Some(sequencer) = &self.contract_sequencer {
                    sequencer.handle_sync_message(transaction_id, sequence, node_id, state).await;
                }
            }
            SyncMessage::NetworkSequencer { transaction_id, sequence, node_id, state } => {
                 info!("🔄 [NETWORK_SEQUENCER] Sync: tx_id={}, seq={}, node={}, state={}", transaction_id, sequence, node_id, state);
                 
                 // Initialize sequencer if needed (same logic as before)
                 if self.network_transaction_sequencer.is_none() {
                     warn!("⚠️ [NETWORK_SEQUENCER] Auto-init logic skipped in refactor - verify if needed");
                 }

                 if let Some(sequencer) = &self.network_transaction_sequencer {
                     sequencer.handle_sync_message(transaction_id, sequence, node_id, state).await;
                 }
            }
        }
        Ok(())
    }

    async fn handle_liquidity_message(&mut self, msg: LiquidityMessage) -> Result<()> {
        match msg {
            LiquidityMessage::Add { solver_address, solver_id, amount_btc, amount_tics, request_id } => {
                info!("💧 [LIQUIDITY] Add: {} (id: {})", solver_address, solver_id);
                self.handle_add_liquidity_contract_calls(&solver_address, &solver_id, &amount_btc, &amount_tics, &request_id).await?;
                
                if let Some(signing_node) = &self.signing_node {
                    let delta_btc = amount_btc.as_ref().and_then(|v| ethers::types::U256::from_dec_str(v).ok());
                    let delta_tics = amount_tics.as_ref().and_then(|v| ethers::types::U256::from_dec_str(v).ok());
                    let _ = signing_node.apply_liquidity_delta(&solver_address, Some(&solver_id), delta_btc, delta_tics, true).await;
                }
            }
            LiquidityMessage::Withdraw { solver_address, btc_address, eth_address, amount_btc, amount_tics, transaction_type: _ } => {
                info!("💧 [LIQUIDITY] Withdraw: {}", solver_address);
                let (tics_initiated, btc_initiated) = self.process_payout("withdraw_liquidity", &solver_address, &btc_address, &eth_address, &amount_btc, &amount_tics).await?;
                
                 if let Some(signing_node) = &self.signing_node {
                    let delta_btc = if btc_initiated { amount_btc.as_ref().and_then(|v| ethers::types::U256::from_dec_str(v).ok()) } else { None };
                    let delta_tics = if tics_initiated { amount_tics.as_ref().and_then(|v| ethers::types::U256::from_dec_str(v).ok()) } else { None };
                    if delta_btc.is_some() || delta_tics.is_some() {
                        let _ = signing_node.apply_liquidity_delta(&solver_address, None, delta_btc, delta_tics, false).await;
                    }
                 }
            }
        }
        Ok(())
    }

    async fn handle_reward_message(&mut self, msg: RewardMessage) -> Result<()> {
        match msg {
            RewardMessage::Claim { solver_address, btc_address, eth_address, reward_btc, reward_tics, .. } => {
                info!("🎁 [REWARD] Claim: {}", solver_address);
                let _ = self.process_payout("claim_reward", &solver_address, &btc_address, &eth_address, &reward_btc, &reward_tics).await?;
            }
        }
        Ok(())
    }
    async fn handle_deposit_intent(&mut self, intent: crate::types::intent::DepositIntent, intent_id: String, user_eth_address: Option<String>, transaction_type: crate::types::intent::TransactionType, amount: u128) -> Result<()> {
        let intent_hash = if matches!(transaction_type, crate::types::TransactionType::Refund) 
            && intent_id.starts_with("refund-") 
        {
            let original_intent_hash = intent_id.strip_prefix("refund-").unwrap_or(&intent_id);
            info!("🔐 [GOSSIPSUB] Refund transaction detected - using ORIGINAL intent hash: {} (from intent_id: {})", original_intent_hash, intent_id);
            original_intent_hash.to_string()
        } else {
            let calculated_hash = crate::utils::calculate_intent_hash(&intent)
                .map_err(|e| anyhow::anyhow!("Failed to calculate intent hash: {}", e))?;
            info!("🔐 [GOSSIPSUB] Calculated intent hash: {}", calculated_hash);
            calculated_hash
        };

        if let Some(user_intent_manager) = &self.user_intent_manager {
            if user_intent_manager.get_intent(&intent_hash).await.is_none() {
                if let Ok(intent_hash_bytes) = hex::decode(&intent_hash) {
                    let signer = user_eth_address.as_ref().map(|addr| addr.clone()).unwrap_or_else(|| "network".to_string());
                    if let Err(e) = user_intent_manager.store_intent_hash(intent_hash_bytes, &signer, &intent).await {
                        warn!("❌ [GOSSIPSUB] Failed to store intent hash {}: {}", intent_hash, e);
                    }
                } else {
                    warn!("❌ [GOSSIPSUB] Invalid intent hash format: {}", intent_hash);
                }
            } else {
                debug!("✅ [GOSSIPSUB] Intent {} already exists in database", intent_hash);
            }
        } else {
            warn!("❌ [GOSSIPSUB] User intent manager not available to store intent");
        }

        let chain_to_use = match transaction_type {
            crate::types::TransactionType::UserToVault => &intent.source_chain.to_lowercase(),
            crate::types::TransactionType::NetworkToTarget => &intent.target_chain.to_lowercase(),
            crate::types::TransactionType::VaultToNetwork => &intent.source_chain.to_lowercase(),
            crate::types::TransactionType::Refund => &intent.source_chain.to_lowercase(),
            crate::types::TransactionType::RewardTxn => {
                warn!("❌ [GOSSIPSUB] RewardTxn is not valid for deposit intent flow");
                return Ok(());
            }
             crate::types::TransactionType::WithdrawLiquidity => {
                warn!("❌ [GOSSIPSUB] WithdrawLiquidity is not valid for deposit intent flow");
                return Ok(());
            }
            crate::types::TransactionType::AddLiquidity => {
                warn!("❌ [GOSSIPSUB] AddLiquidity is not valid for deposit intent flow");
                return Ok(());
            }
        };

        let signing_key: Option<k256::Scalar> = match transaction_type {
            crate::types::TransactionType::UserToVault => self.get_signing_key_for_user(user_eth_address.as_ref()).await,
            crate::types::TransactionType::NetworkToTarget => if let Some(dkg_node) = &self.dkg_node { dkg_node.get_final_secret_share().await } else { None },
            crate::types::TransactionType::VaultToNetwork => if let Some(dkg_node) = &self.dkg_node { dkg_node.get_vault_tweaked_secret_share().await } else { None },
            crate::types::TransactionType::Refund => if let Some(dkg_node) = &self.dkg_node { dkg_node.get_final_secret_share().await } else { None },
            _ => None,
        };

        if let Some(signing_node) = &mut self.signing_node {
            let chain_handler: Option<Arc<dyn crate::chain_abstraction::ChainHandler>> = if crate::utils::transaction::is_evm_chain(chain_to_use) {
                 crate::utils::transaction::get_chain_id_from_name(chain_to_use).map(|chain_id| {
                    let handler = crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(chain_id);
                    Arc::from(handler) as Arc<dyn crate::chain_abstraction::ChainHandler>
                 })
            } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                 let mut handler = crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(crate::types::network::network_type().bitcoin_network_label().to_string());
                 match transaction_type {
                     crate::types::TransactionType::UserToVault => {
                         if let Some(eth_addr) = &user_eth_address {
                             if let Some(user_intent_manager) = &self.user_intent_manager {
                                 if let Some(user) = user_intent_manager.get_user_by_address(eth_addr).await {
                                     if let Some(user_group_key) = &user.user_group_key {
                                         if let Some(btc_handler) = handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                             let encoded = k256::EncodedPoint::from(user_group_key.0);
                                             btc_handler.set_group_public_key(encoded.compress().to_bytes().to_vec());
                                         }
                                     }
                                 }
                             }
                         }
                     }
                     crate::types::TransactionType::NetworkToTarget | crate::types::TransactionType::Refund => {
                          if let Some(dkg_node) = &self.dkg_node {
                             if let Some(group_key) = dkg_node.get_final_public_key().await {
                                 if let Some(btc_handler) = handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                      let encoded = k256::EncodedPoint::from(group_key.to_affine());
                                      btc_handler.set_group_public_key(encoded.compress().to_bytes().to_vec());
                                 }
                             }
                          }
                     }
                     crate::types::TransactionType::VaultToNetwork => {
                          if let Some(dkg_node) = &self.dkg_node {
                               if let Some(vault_key) = dkg_node.get_vault_group_key().await {
                                   if let Some(btc_handler) = handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                        let encoded = k256::EncodedPoint::from(vault_key.to_affine());
                                        btc_handler.set_group_public_key(encoded.compress().to_bytes().to_vec());
                                   }
                               }
                          }
                     }
                     _ => {}
                 }
                 Some(Arc::from(handler))
            } else {
                 None
            };
            
            let Some(chain_handler) = chain_handler else { return Err(anyhow!("Unsupported chain: {}", chain_to_use)); };

            let (derived_eth, derived_btc) = match transaction_type {
                crate::types::TransactionType::UserToVault => {
                     if let Some(eth_addr) = &user_eth_address {
                          if let Some(mgr) = &self.user_intent_manager {
                               if let Some(user) = mgr.get_user_by_address(eth_addr).await {
                                   (user.derived_eth_address.clone(), user.derived_btc_address.clone())
                               } else { (None, None) }
                          } else { (None, None) }
                     } else { (None, None) }
                }
                _ => (None, None)
            };

            let group_public_key = if let Some(dkg) = &self.dkg_node { dkg.get_final_public_key().await } else { None };
            let (vault_eth, vault_btc) = if let Some(registry) = &self.user_intent_manager {
                let db = registry.get_database();
                (db.get_string(crate::database::keys::DKG_VAULT_ETH_ADDRESS).ok().flatten(),
                 db.get_string(crate::database::keys::DKG_VAULT_BTC_ADDRESS).ok().flatten())
            } else { return Err(anyhow!("Registry not available")); };

             let chain_transaction_result = crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                 &intent, group_public_key, derived_eth.as_ref(), derived_btc.as_ref(), transaction_type.clone(),
                 vault_eth.as_ref(), vault_btc.as_ref(), amount
             ).await;

             match chain_transaction_result {
                 Ok(chain_transaction) => {
                     let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                     signing_node.set_available_nodes(available_nodes);
                     
                     if signing_key.is_none() { warn!("❌ [GOSSIPSUB] No signing key for deposit intent"); return Ok(()); }
                     
                     let tx_bytes = chain_handler.create_transaction_bytes(&chain_transaction).unwrap_or_default();
                     info!("🔐 [GOSSIPSUB] Starting {} signing for intent: 0x{}", chain_handler.chain_type(), hex::encode(&tx_bytes));

                     match chain_transaction {
                         crate::chain_abstraction::ChainTransaction::Bitcoin(btc_tx) => {
                             let mut btc_signer = BitcoinSigner::new(signing_node);
                             btc_signer.sign_transaction(tx_bytes, &chain_handler, Some(btc_tx), user_eth_address, Some(intent_hash), Some(transaction_type), signing_key, None, signing_key).await?;
                         }
                         crate::chain_abstraction::ChainTransaction::Ethereum(eth_tx) => {
                             let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&eth_tx);
                             if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget) {
                                 info!("📝 [GOSSIPSUB] NetworkToTarget (EVM) - queuing via sequencer (hash={})", intent_hash);
                                 self.submit_network_to_target_to_sequencer(&intent, &intent_hash, amount, tx_bytes, eth_tx, signing_key, user_eth_address).await?;
                                 return Ok(());
                             }
                             let mut eth_signer = EthereumSigner::new(signing_node);
                             eth_signer.sign_transaction(tx_bytes, &chain_handler, &eth_tx, signing_key, user_eth_address, Some(intent_hash), Some(transaction_type), None, signing_key).await?;
                         }
                     }
                 }
                 Err(e) => warn!("❌ [GOSSIPSUB] Failed to create chain transaction: {}", e)
             }
        }
        Ok(())
    }

    async fn handle_transaction_id_broadcast(&mut self, intent_hash: Option<String>, transaction_id: String, transaction_type: String, solver_address: Option<String>, node_id: String) -> Result<()> {
         // Verify sender
         let sender_peer_id = node_id.parse::<PeerId>().map_err(|e| anyhow!("Invalid node_id: {}", e))?;
         if !self.node_manager.get_active_nodes().contains(&sender_peer_id) {
             warn!("🚫 [SECURITY] Rejecting TransactionIdBroadcast from non-trusted node {}", node_id);
             return Ok(());
         }
         
         self.send_critical_message_ack(
             crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast,
             &GossipsubMessage::TransactionIdBroadcast {
                 intent_hash: intent_hash.clone(), transaction_id: transaction_id.clone(),
                 transaction_type: transaction_type.clone(), solver_address: solver_address.clone(), node_id: node_id.clone()
             }
         ).await;

         match (intent_hash, solver_address) {
             (Some(hash), _) => {
                 self.handle_transaction_id_storage(&hash, &transaction_id, &transaction_type, &node_id, &sender_peer_id).await?;
             }
             (None, Some(solver)) => {
                 if transaction_type == "reward_txn" {
                     self.handle_reward_transaction_id_storage(&solver, &transaction_id, &transaction_type).await?;
                 } else if transaction_type == "withdraw_liquidity" || transaction_type == "withdrawLiquidity" {
                      self.handle_withdraw_liquidity_transaction_id_storage(&solver, &transaction_id, &transaction_type).await?;
                 }
             }
             _ => {}
         }
         Ok(())
    }
    
    async fn handle_transaction_error_broadcast(&mut self, intent_hash: Option<String>, error_message: String, transaction_type: String, solver_address: Option<String>, node_id: String) -> Result<()> {
        if let Some(mgr) = &self.user_intent_manager {
            match (intent_hash, solver_address) {
                (Some(hash), _) => {
                    let _ = mgr.store_transaction_error(&hash, &error_message, Some(&node_id)).await;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_intent_hash_broadcast(&mut self, intent_hash: String, node_id: String) -> Result<()> {
        info!("📨 [GOSSIPSUB] Received intent hash broadcast {} from node {}", intent_hash, node_id);
        Ok(())
    }
    
    async fn handle_intent_hash(&mut self, intent_hash: String, signer: String, intent: crate::types::intent::DepositIntent) -> Result<()> {
        info!("📝 [GOSSIPSUB] Received intent hash {} from {}", intent_hash, signer);
        if let Some(mgr) = &self.user_intent_manager {
            if let Ok(bytes) = hex::decode(&intent_hash) {
                let _ = mgr.store_intent_hash(bytes, &signer, &intent).await;
            }
        }
        Ok(())
    }

    async fn handle_user_registration(&mut self, ethereum_address: String, timestamp: i64, node_id: String) -> Result<()> {
        info!("👤 Received user registration: {} from {} at {}", ethereum_address, node_id, timestamp);
        if let Some(mgr) = &mut self.user_intent_manager {
             let dkg_share = if let Some(dkg) = &self.dkg_node { dkg.get_final_secret_share().await } else { None };
             if let Ok(reg) = mgr.register_user(&ethereum_address, dkg_share.as_ref(), &node_id).await {
                 info!("✅ [GOSSIPSUB] Registered user {} locally", ethereum_address);
                 if let Some(dkg) = &self.dkg_node {
                      if let Some(scalar) = k256::Scalar::from_repr_vartime(reg.hmac_constant.into()) {
                          if let Ok(group_key) = dkg.derive_user_specific_group_key_from_commitments(scalar).await {
                              let _ = mgr.set_user_group_key(&ethereum_address, group_key).await;
                          }
                      }
                 }
             }
        }
        Ok(())
    }
}
