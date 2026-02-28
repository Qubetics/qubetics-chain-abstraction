use anyhow::Result;
use tracing::warn;
use crate::network::transport::types::{MpcNetworkLayer, MpcNetworkBehaviour};
use crate::types::*;
use crate::protocols::*;
use libp2p::{Multiaddr, PeerId};
use crate::types::rpc_server::NodeStatus;

impl MpcNetworkLayer {
    pub(crate) async fn handle_ch_peerdiscoveryretry(
        &mut self,
        msg_enum: ChannelMessage,
        _swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_statusrequest(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_nodemultiaddrrequest(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::NodeMultiaddrRequest { responder } => {
                    let listen_addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
                    let multiaddr = listen_addrs.first().map(|a| {
                        format!("{}/p2p/{}", a, self.local_peer_id)
                    });
                    if responder.send(multiaddr).is_err() {
                        warn!("❌ [NODE_MULTIADDR] Failed to send multiaddr response to requester");
                    }
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_peerconnectioncheck(
        &mut self,
        msg_enum: ChannelMessage,
        _swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::PeerConnectionCheck { peer_id, responder } => {
                    let connected = if let Ok(pid) = peer_id.parse::<PeerId>() {
                        self.node_manager.get_active_nodes().contains(&pid)
                    } else {
                        false
                    };
                    let _ = responder.send(connected);
            }
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_peerinvalidationbatch(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::PeerInvalidationBatch {
                    solver_ids,
                    round,
                    timestamp,
                    node_id,
                    nonce_tuple_id: nonce_tuple_ids,
                } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::PeerInvalidationBatch {
                        solver_ids,
                        round,
                        timestamp,
                        node_id,
                        nonce_tuple_ids: nonce_tuple_ids.clone().map(|id| vec![id]),
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
                    let topic = "peer-status";
                    let topic_hash = IdentTopic::new(topic);
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
            _ => {},
        }
        Ok(())
    }

    pub(crate) async fn handle_ch_peerinvalidationdeleted(
        &mut self,
        msg_enum: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        match msg_enum {
            ChannelMessage::PeerInvalidationDeleted { solver_id, node_id } => {
                    use libp2p::gossipsub::{IdentTopic, Message as GossipMessage};
    
                    let gossip_msg = crate::types::GossipsubMessage::PeerInvalidationDeleted {
                        solver_id: solver_id.clone(),
                        node_id: node_id.clone(),
                    };
    
                    let data = match serde_json::to_vec(&gossip_msg) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                "❌ [PEER_INVALIDATION] Failed to serialize PeerInvalidationDeleted: {}",
                                e
                            );
                            return Ok(());
                        }
                    };
    
                    // 1) Process locally by calling the main gossipsub handler
                    let topic = "peer-status";
                    let topic_hash = IdentTopic::new(topic);
                    let local_msg = GossipMessage {
                        source: Some(self.local_peer_id),
                        data: data.clone(),
                        sequence_number: None,
                        topic: topic_hash.hash(),
                    };
    
                    if let Err(e) = self.handle_gossipsub_message(&local_msg).await {
                        warn!(
                            "❌ [PEER_INVALIDATION] Failed to process local PeerInvalidationDeleted: {}",
                            e
                        );
                    }
    
                    // 2) Publish to other peers via gossipsub
                    let swarm_mut = swarm.behaviour_mut();
                    let peer_count = swarm_mut.gossipsub.all_peers().count();
    
                    if peer_count > 0 {
                        if let Err(e) = swarm_mut.gossipsub.publish(topic_hash, data) {
                            warn!(
                                "❌ [PEER_INVALIDATION] Failed to publish PeerInvalidationDeleted to topic {}: {:?}",
                                topic, e
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [PEER_INVALIDATION] No peers available for broadcasting PeerInvalidationDeleted"
                        );
                    }
            }
            _ => {},
        }
        Ok(())
    }

}
