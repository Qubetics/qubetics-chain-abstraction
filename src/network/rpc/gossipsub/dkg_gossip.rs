use anyhow::Result;
use libp2p::{gossipsub::Message, PeerId};
use tracing::{debug, info, warn};
use crate::network::transport::types::MpcNetworkLayer;
use crate::types::*;

impl MpcNetworkLayer {
    pub(crate) async fn handle_dkg(&mut self, _message: &Message, msg_enum: GossipsubMessage) -> Result<()> {
        match msg_enum {
            GossipsubMessage::DKG(dkg_msg) => {
                    // Check if this is a NodeDisconnected message - handle it specially
                    if let crate::protocols::DKGMessage::NodeDisconnected {
                        ref disconnected_node_id,
                        ref broadcaster_node_id,
                    } = dkg_msg
                    {
                        info!(
                            "📢 [DISCONNECT] Received disconnect broadcast: {} disconnected (from {})",
                            disconnected_node_id, broadcaster_node_id
                        );
    
                        // Parse the disconnected node ID
                        if let Ok(peer_id) = disconnected_node_id.parse::<PeerId>() {
                            // A node must never remove itself from its own active list.
                            // During reconnection, connection flapping + REJOIN_BLOCKED can
                            // cause a fresh disconnect broadcast about us while we are still alive.
                            if peer_id == self.local_peer_id {
                                warn!(
                                    "📢 [DISCONNECT] Ignoring disconnect broadcast about ourselves ({}) from {} — we are still alive",
                                    peer_id, broadcaster_node_id
                                );
                                return Ok(());
                            }
    
                            // Check if we haven't already processed this disconnect
                            if self.node_manager.get_active_nodes().contains(&peer_id) {
                                debug!("📢 [DISCONNECT] Processing disconnect for node {}", peer_id);
                                self.handle_node_disconnect_internal(peer_id).await;
                            } else {
                                debug!("📢 [DISCONNECT] Node {} already removed, skipping", peer_id);
                            }
                        }
                    } else {
                        // dkg.r.2.1
                        // here we unwrapped the outer gossipmsg wrap from
                        // the msg bytes (check broadcast_shares() in dkg module)
                        if let Some(dkg_node) = &mut self.dkg_node {
                            let was_complete = dkg_node.is_initial_dkg_complete().await;
    
                            // now we can unwrap the internal dkg wrap to get the DKG related things
                            dkg_node
                                .handle_message(dkg_msg, self.node_manager.clone())
                                .await?;
    
                            // If DKG just completed, update NonceManager's dkg_signer_count
                            // so the stale-nonce filter works correctly from the start.
                            if !was_complete && dkg_node.is_initial_dkg_complete().await {
                                if let Some(count) = dkg_node.get_dkg_signer_count() {
                                    if let Some(arc) = &self.signing_node {
                                        let signing_node = arc.lock().await;
                                        if let Some(nm) = signing_node.nonce_manager() {
                                            let nm_guard = nm.lock().await;
                                            nm_guard.update_dkg_signer_count(count);
                                            // This node completed DKG — it holds a secret share and
                                            // can participate in the commit-reveal nonce protocol.
                                            nm_guard.set_is_dkg_signer(true);
                                            info!("🔢 [DKG] Updated NonceManager dkg_signer_count={} and is_dkg_signer=true after DKG completion", count);
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
            _ => {},
        }
        Ok(())
    }

}
