use anyhow::Result;
use tracing::{info, warn};
use crate::network::transport::types::{MpcNetworkLayer, MpcNetworkBehaviour};
use crate::types::*;
use libp2p::gossipsub;
use ff::PrimeField;

impl MpcNetworkLayer {
    pub(crate) async fn handle_ch_intentbatchbroadcast(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::IntentBatchBroadcast {
                    intent_hashes,
                    batch_type,
                    timestamp,
                    round,
                    node_id,
                    nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::IntentBatchBroadcast {
                        intent_hashes,
                        batch_type,
                        timestamp,
                        round,
                        node_id,
                        nonce_tuple_ids,
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_ticsusertovaultintentbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
                        crate::network::transport::types::TOPIC_INTENT_BATCHES;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_btcusertovaultintentbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
                        crate::network::transport::types::TOPIC_INTENT_BATCHES;
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_depositintent(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::DepositIntent {
                    intent,
                    intent_id,
                    user_tics_address,
                    transaction_type,
                    amount,
                    target_amount,
                    signature,
                } => {
                    // Log key fields explicitly so timestamp is clearly a number (used in intent hash)
                    info!(
                        "📝 [NETWORK] Processing deposit intent locally: source={} target={} source_chain={} target_chain={} amount={} target_amount={} timestamp={}",
                        intent.source_address,
                        intent.target_address,
                        intent.source_chain,
                        intent.target_chain,
                        intent.amount,
                        target_amount,
                        intent.timestamp
                    );
    
                    // Only broadcast UserToVault deposits via gossipsub
                    if !matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                        info!("⏭️ [NETWORK] Skipping gossip broadcast - only UserToVault deposits are gossiped");
                        return Ok(());
                    }
    
                    // Calculate intent hash from the intent (used both for logging and DB keys)
                    let intent_hash = {
                        let calculated_hash = crate::utils::calculate_intent_hash(&intent)
                            .map_err(|e| anyhow::anyhow!("Failed to calculate intent hash: {}", e))?;
                        info!("🔐 [LOCAL] Calculated intent hash: {}", calculated_hash);
                        calculated_hash
                    };
    
                    // Never accept/broadcast an intent hash that is already in storage (duplicate).
                    if let Some(ref uim) = self.user_intent_manager {
                        if uim.get_intent(&intent_hash).await.is_some() {
                            warn!(
                                "⚠️ [CHANNEL] Rejecting DepositIntent - intent hash {} already in storage (duplicate); no broadcast",
                                intent_hash
                            );
                            return Ok(());
                        }
                    }
    
                    // Store the intent locally BEFORE broadcasting to gossipsub.
                    // The originating node does NOT receive its own gossipsub message (libp2p default),
                    // so we must store here. Peers will store via their gossipsub handler.
                    // Note: All validations (address, balance, amount, network liquidity) were already
                    // performed at the RPC handler level. target_amount was pre-computed there.
                    if let Some(ref uim) = self.user_intent_manager {
                        // Store target_amount first (invariant: if intent stored, target_amount must exist)
                        if let Err(e) = uim.store_intent_target_amount(&intent_hash, target_amount).await {
                            warn!(
                                "❌ [CHANNEL] Failed to store target amount for {}: {}. Rejecting intent.",
                                intent_hash, e
                            );
                            return Ok(());
                        }
    
                        // Store the intent itself
                        if let Ok(intent_hash_bytes) = hex::decode(&intent_hash) {
                            if let Err(e) = uim
                                .store_intent_hash(intent_hash_bytes, &user_tics_address, &intent)
                                .await
                            {
                                warn!(
                                    "❌ [CHANNEL] Failed to store intent hash {}: {}",
                                    intent_hash, e
                                );
                                return Ok(());
                            }
                        } else {
                            warn!("❌ [CHANNEL] Invalid intent hash format: {}", intent_hash);
                            return Ok(());
                        }
                        info!(
                            "💾 [CHANNEL] Stored target amount {} and intent {} locally (originating node)",
                            target_amount, intent_hash
                        );
                    }
    
                    // Broadcast to all peers via gossipsub so they validate and store independently.
                    info!("🌐 [NETWORK] Broadcasting UserToVault deposit to P2P network");
                    let deposit_intent_msg = GossipsubMessage::DepositIntent {
                        intent: intent.clone(),
                        intent_id: intent_id.clone(),
                        user_tics_address: user_tics_address.clone(),
                        amount,
                        signature: signature.clone(),
                    };
                    let msg_bytes = serde_json::to_vec(&deposit_intent_msg)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize deposit intent: {}", e))?;
    
                    // Broadcast to all peers via gossipsub
                    let topic = gossipsub::IdentTopic::new("user-operations");
                    swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                    info!("📡 [NETWORK] Broadcasted deposit intent to P2P network");
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_userregistration(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::UserRegistration {
                    tics_address,
                    node_id,
                } => {
                    info!(
                        "👤 [NETWORK] Broadcasting user registration: {} from node {}",
                        tics_address, node_id
                    );
    
                    // Directly update commitments locally using the stored HMAC constant
                    if let (Some(user_intent_manager), Some(dkg_node)) =
                        (&self.user_intent_manager, &self.dkg_node)
                    {
                        if let Some(reg) = user_intent_manager
                            .get_user_by_address(&tics_address)
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
                                            .set_user_group_key(&tics_address, group_key)
                                            .await
                                        {
                                            warn!("❌ [NETWORK] Failed to store user group key for {}: {}", tics_address, e);
                                        } else {
                                            info!("🔑 [NETWORK] Stored user-specific group key and derived addresses for {}", tics_address);
                                            // Log the derived addresses
                                            if let Some(user) = user_intent_manager
                                                .get_user_by_address(&tics_address)
                                                .await
                                            {
                                                if let Some(eth_addr) = &user.derived_eth_address {
                                                    info!(
                                                        "📬 [NETWORK] Derived ETH address for {}: {}",
                                                        tics_address, eth_addr
                                                    );
                                                }
                                                if let Some(btc_addr) = &user.derived_btc_address {
                                                    info!(
                                                        "📬 [NETWORK] Derived BTC address for {}: {}",
                                                        tics_address, btc_addr
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("❌ [NETWORK] Failed to derive user-specific group key for {}: {}", tics_address, e);
                                    }
                                }
                            }
                        } else {
                            warn!(
                                "❌ [NETWORK] Invalid HMAC tweak scalar for {}",
                                tics_address
                            );
                        }
                    } else {
                        warn!("❌ [NETWORK] Missing user_intent_manager or dkg_node; cannot update commitments locally for {}", tics_address);
                    }
    
                    // Create and broadcast user registration message via gossipsub (same pattern as deposit intent)
                    let user_reg_msg = GossipsubMessage::UserRegistration {
                        tics_address: tics_address.clone(),
                        timestamp: chrono::Utc::now().timestamp(),
                        node_id: node_id.clone(),
                    };
                    let msg_bytes = serde_json::to_vec(&user_reg_msg)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;
    
                    // Broadcast to all peers via gossipsub
                    let topic = gossipsub::IdentTopic::new("user-operations");
                    swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                    info!("📡 [NETWORK] Broadcasted user registration to P2P network");
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_adminregistration(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::AdminRegistration {
                    tics_address,
                    node_id,
                } => {
                    info!(
                        "👤 [NETWORK] Broadcasting admin registration: {} from node {}",
                        tics_address, node_id
                    );
    
                    // Derive admin group key and store derived addresses locally
                    if let (Some(user_intent_manager), Some(dkg_node)) =
                        (&self.user_intent_manager, &self.dkg_node)
                    {
                        if let Some(reg) = user_intent_manager
                            .get_admin_by_address(&tics_address)
                            .await
                        {
                            if let Some(tweak_scalar) =
                                k256::Scalar::from_repr_vartime(reg.hmac_constant.into())
                            {
                                match dkg_node
                                    .derive_user_specific_group_key_from_commitments(tweak_scalar)
                                    .await
                                {
                                    Ok(group_key) => {
                                        if let Err(e) = user_intent_manager
                                            .set_admin_group_key(&tics_address, group_key)
                                            .await
                                        {
                                            warn!("❌ [NETWORK] Failed to store admin group key for {}: {}", tics_address, e);
                                        } else {
                                            info!("🔑 [NETWORK] Stored admin-specific group key and derived addresses for {}", tics_address);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("❌ [NETWORK] Failed to derive admin-specific group key for {}: {}", tics_address, e);
                                    }
                                }
                            }
                        } else {
                            warn!(
                                "❌ [NETWORK] Admin not found for HMAC tweak: {}",
                                tics_address
                            );
                        }
                    } else {
                        warn!("❌ [NETWORK] Missing user_intent_manager or dkg_node; cannot update commitments locally for admin {}", tics_address);
                    }
    
                    // Broadcast admin registration via gossipsub
                    let admin_reg_msg = GossipsubMessage::AdminRegistration {
                        tics_address: tics_address.clone(),
                        timestamp: chrono::Utc::now().timestamp(),
                        node_id: node_id.clone(),
                    };
                    let msg_bytes = serde_json::to_vec(&admin_reg_msg)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize admin registration: {}", e))?;
    
                    let topic = gossipsub::IdentTopic::new("user-operations");
                    swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                    info!("📡 [NETWORK] Broadcasted admin registration to P2P network");
            }
            _ => {},
        }
        Ok(())
    }

}
