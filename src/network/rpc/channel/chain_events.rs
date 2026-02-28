use anyhow::{Result, anyhow};
use tracing::{debug, error, info, warn};
use crate::network::transport::types::{MpcNetworkLayer, MpcNetworkBehaviour};
use crate::types::*;
use crate::protocols::*;
use crate::rpc_server::utils::*;
use crate::utils::transaction::*;
use crate::signing::TicsSigner;
use crate::database::key_utils;
use crate::types::p2p::SerializablePeerId;
use libp2p::gossipsub;
use libp2p::{Multiaddr, PeerId};
use crate::types::rpc_server::NodeStatus;
use ff::PrimeField;
use k256::Scalar;
use std::time::Duration;
use ethers::prelude::Address;
use crate::contract::*;
use crate::network::transport::types::{
    TOPIC_CLAIM_REWARDS, TOPIC_PLATFORM_FEE, TOPIC_WITHDRAW_LIQUIDITY,
};
use super::*;

impl MpcNetworkLayer {
    pub(crate) async fn handle_ch_btcintentmanagertxupdate(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::BtcIntentManagerTxUpdate {
                    intent_hashes,
                    btc_txid,
                    btc_batch_round,
                    update_round,
                    timestamp,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::BtcIntentManagerTxUpdate {
                        intent_hashes: intent_hashes.clone(),
                        btc_txid: btc_txid.clone(),
                        btc_batch_round,
                        update_round,
                        timestamp: timestamp.clone(),
                        node_id: node_id.clone(),
                        nonce_tuple_ids: nonce_tuple_ids.clone(),
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
                    let topic = "intent-batches";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_btcwithdrawbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::BtcWithdrawBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::BtcWithdrawBatch {
                        batch_id,
                        requests,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids,
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
                    let topic = "withdraw-liquidity";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_btcclaimrewardbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::BtcClaimRewardBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::BtcClaimRewardBatch {
                        batch_id,
                        requests,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids,
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
    
                    let topic = TOPIC_CLAIM_REWARDS;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_btcclaimplatformfeebatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::BtcClaimPlatformFeeBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::BtcClaimPlatformFeeBatch {
                        batch_id,
                        requests,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids,
                    };
    
                    let data = match serde_json::to_vec(&gossip_msg) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                "❌ [BTC_CLAIM_PLATFORM_FEE] Failed to serialize BtcClaimPlatformFeeBatch: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
    
                    let topic = TOPIC_PLATFORM_FEE;
                    let topic_hash = IdentTopic::new(topic);
                    let local_msg = GossipMessage {
                        source: Some(self.local_peer_id),
                        data: data.clone(),
                        sequence_number: None,
                        topic: topic_hash.hash(),
                    };
    
                    if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                        warn!(
                            "❌ [BTC_CLAIM_PLATFORM_FEE] Failed to process local BtcClaimPlatformFeeBatch: {}",
                            e
                        );
                    }
    
                    let swarm_mut = swarm.behaviour_mut();
                    let peer_count = swarm_mut.gossipsub.all_peers().count();
                    if peer_count > 0 {
                        if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                            warn!(
                                "❌ [BTC_CLAIM_PLATFORM_FEE] Failed to publish BtcClaimPlatformFeeBatch to topic {}: {:?}",
                                topic, e
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [BTC_CLAIM_PLATFORM_FEE] No peers available for broadcasting BtcClaimPlatformFeeBatch"
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_claimplatformfeetxidbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::ClaimPlatformFeeTxIdBroadcast {
                    txid,
                    network,
                    batch_id,
                    requests,
                    node_id,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    info!(
                        "📡 [CLAIM_PLATFORM_FEE_TXID] Received claim-platform-fee txid broadcast: txid={}, network={}, batch_id={}, requests={}",
                        txid, network, batch_id, requests.len()
                    );
    
                    let gossip_msg = crate::types::GossipsubMessage::ClaimPlatformFeeTxIdBroadcast {
                        txid,
                        network,
                        batch_id,
                        requests,
                        node_id,
                    };
    
                    let data = match serde_json::to_vec(&gossip_msg) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                "❌ [CLAIM_PLATFORM_FEE_TXID] Failed to serialize ClaimPlatformFeeTxIdBroadcast: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
    
                    let topic = TOPIC_PLATFORM_FEE;
                    let topic_hash = IdentTopic::new(topic);
                    let local_msg = GossipMessage {
                        source: Some(self.local_peer_id),
                        data: data.clone(),
                        sequence_number: None,
                        topic: topic_hash.hash(),
                    };
    
                    if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                        warn!(
                            "❌ [CLAIM_PLATFORM_FEE_TXID] Failed to process local ClaimPlatformFeeTxIdBroadcast: {}",
                            e
                        );
                    }
    
                    let swarm_mut = swarm.behaviour_mut();
                    let peer_count = swarm_mut.gossipsub.all_peers().count();
    
                    if peer_count > 0 {
                        if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                            warn!(
                                "❌ [CLAIM_PLATFORM_FEE_TXID] Failed to publish ClaimPlatformFeeTxIdBroadcast to topic {}: {:?}",
                                topic, e
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [CLAIM_PLATFORM_FEE_TXID] No peers available for broadcasting ClaimPlatformFeeTxIdBroadcast"
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_ticsclaimplatformfeebatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::TicsClaimPlatformFeeBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::TicsClaimPlatformFeeBatch {
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
                                "❌ [TICS_CLAIM_PLATFORM_FEE] Failed to serialize TicsClaimPlatformFeeBatch: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
    
                    let topic = TOPIC_PLATFORM_FEE;
                    let topic_hash = IdentTopic::new(topic);
                    let local_msg = GossipMessage {
                        source: Some(self.local_peer_id),
                        data: data.clone(),
                        sequence_number: None,
                        topic: topic_hash.hash(),
                    };
    
                    if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                        warn!(
                            "❌ [TICS_CLAIM_PLATFORM_FEE] Failed to process local TicsClaimPlatformFeeBatch: {}",
                            e
                        );
                    }
    
                    let swarm_mut = swarm.behaviour_mut();
                    let peer_count = swarm_mut.gossipsub.all_peers().count();
    
                    if peer_count > 0 {
                        if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                            warn!(
                                "❌ [TICS_CLAIM_PLATFORM_FEE] Failed to publish TicsClaimPlatformFeeBatch to topic {}: {:?}",
                                topic, e
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [TICS_CLAIM_PLATFORM_FEE] No peers available for broadcasting TicsClaimPlatformFeeBatch"
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_ticswithdrawbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::TicsWithdrawBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::TicsWithdrawBatch {
                        batch_id,
                        requests,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids,
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
                    let topic = "withdraw-liquidity";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_ticsclaimrewardbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::TicsClaimRewardBatch {
                    batch_id,
                    requests,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::TicsClaimRewardBatch {
                        batch_id,
                        requests,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids,
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
    
                    let topic = TOPIC_CLAIM_REWARDS;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_claimrewardtxidbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
    
                    let topic = TOPIC_CLAIM_REWARDS;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_withdrawtxidbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
                    let topic = "withdraw-liquidity";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_pendingwithdrawrequestbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
    
                    let topic = TOPIC_WITHDRAW_LIQUIDITY;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_pendingclaimplatformfeerequestbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::PendingClaimPlatformFeeRequestBroadcast { request } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg =
                        crate::types::GossipsubMessage::PendingClaimPlatformFeeRequestBroadcast {
                            request: request.clone(),
                        };
    
                    let data = match serde_json::to_vec(&gossip_msg) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                "❌ [PLATFORM_FEE] Failed to serialize PendingClaimPlatformFeeRequestBroadcast: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
    
                    let topic = TOPIC_PLATFORM_FEE;
                    let topic_hash = IdentTopic::new(topic);
                    let local_msg = GossipMessage {
                        source: Some(self.local_peer_id),
                        data: data.clone(),
                        sequence_number: None,
                        topic: topic_hash.hash(),
                    };
    
                    if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                        warn!(
                            "❌ [PLATFORM_FEE] Failed to process local PendingClaimPlatformFeeRequestBroadcast: {}",
                            e
                        );
                    }
    
                    let swarm_mut = swarm.behaviour_mut();
                    let peer_count = swarm_mut.gossipsub.all_peers().count();
    
                    if peer_count > 0 {
                        if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                            warn!(
                                "❌ [PLATFORM_FEE] Failed to publish PendingClaimPlatformFeeRequestBroadcast to topic {}: {:?}",
                                topic, e
                            );
                        } else {
                            info!(
                                "📡 [PLATFORM_FEE] Published PendingClaimPlatformFeeRequestBroadcast (request_id={}) to {} peers",
                                request.request_id, peer_count
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [PLATFORM_FEE] No peers available for broadcasting PendingClaimPlatformFeeRequestBroadcast"
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_pendingclaimrewardrequestbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
    
                    let topic = TOPIC_CLAIM_REWARDS;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_solveraddliquiditybatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::SolverAddLiquidityBatch {
                    request_ids,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id: nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::SolverAddLiquidityBatch {
                        request_ids: request_ids.clone(),
                        round,
                        timestamp: timestamp.clone(),
                        node_id: node_id.clone(),
                        nonce_tuple_ids: nonce_tuple_ids.clone().map(|id| vec![id]),
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
                    let topic = "solver-add-liquidity";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_solveraddliquidity(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::SolverAddLiquidityBatch {
                    request_ids,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id: nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::SolverAddLiquidityBatch {
                        request_ids: request_ids.clone(),
                        round,
                        timestamp: timestamp.clone(),
                        node_id: node_id.clone(),
                        nonce_tuple_ids: nonce_tuple_ids.clone().map(|id| vec![id]),
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
                    let topic = "solver-add-liquidity";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

}
