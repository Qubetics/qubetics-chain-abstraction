/// Main event loop for network layer
/// Handles swarm events, channel messages, and periodic tasks
use anyhow::Result;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::protocols::DKGStatus;

use super::types::{MpcNetworkBehaviour, MpcNetworkLayer};

impl MpcNetworkLayer {
    /// Start the network event loop
    pub async fn start(&mut self) -> Result<()> {
        let mut swarm = self.build_swarm()?;

        // Check if this is an existing node with DKG data - if so, subscribe to topics immediately
        self.subscribe_to_default_topics(&mut swarm)?;

        info!("Starting Kademlia bootstrap...");

        // Node manager will determine if this is the first node
        self.node_manager
            .add_node(self.local_peer_id.clone())
            .map_err(|e| anyhow::anyhow!(e))?;

        // Bootstrap with the configured nodes
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("Failed to start bootstrap: {:?}", e);
        }

        // Start a task to check if this is the first node after bootstrap attempts
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(300));
        let mut discovery_timer = tokio::time::interval(Duration::from_secs(300));
        let mut dkg_status_timer = tokio::time::interval(Duration::from_secs(300));
        let mut peerlist_logger = tokio::time::interval(Duration::from_secs(300));

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

        self.dial_seed_addresses(&mut swarm);
        // Dial command-line provided addresses
        self.dial_command_line_addresses(&mut swarm);

        info!("Local Peer ID: {}", self.local_peer_id);

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    info!("[SWARM] some");
                    // 🛡️ Error recovery for swarm events - prevent node crashes
                    if let Err(e) = self.handle_swarm_event(event, &mut swarm).await {
                        error!("❌ [NETWORK] Swarm event handling failed: {}", e);
                        error!("🛡️ [NETWORK] Node continues operating despite swarm event failure");
                        error!("🔍 [NETWORK] Error details: {:?}", e);
                        // Continue processing other events
                    }
                }

                // only hit when there is anything on the mpsc channel
                msg = self.message_rx.recv() => {
                    if let Some(msg) = msg {
                        // 🛡️ Error recovery for channel messages - prevent node crashes
                        if let Err(e) = self.handle_channel_message(msg, &mut swarm).await {
                            error!("❌ [NETWORK] Channel message handling failed: {}", e);
                            error!("🛡️ [NETWORK] Node continues operating despite message handling failure");
                            error!("🔍 [NETWORK] Error details: {:?}", e);
                            // Continue processing other messages
                        }
                    }
                }

                _ = peerlist_logger.tick() => {
                    self.log_peer_list_snapshot();
                }

                _ = bootstrap_timer.tick() => {
                    // Periodic bootstrap to discover new peers
                    info!("Performing periodic bootstrap...");
                    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                        warn!("Periodic bootstrap failed: {:?}", e);
                    }
                }

                _ = discovery_timer.tick() => {
                    self.perform_periodic_peer_discovery(&mut swarm);
                }

                _ = dkg_status_timer.tick() => {
                    self.log_periodic_dkg_status().await;
                }
            };
        }
    }

    /// Dial addresses provided via command line arguments
    fn dial_command_line_addresses(&self, swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>) {
        let args: Vec<String> = std::env::args().collect();
        if args.len() >= 2 {
            // Parse all addresses from command line arguments
            let addresses: Vec<Multiaddr> = args[1..]
                .iter()
                .filter_map(|arg| match arg.parse::<Multiaddr>() {
                    Ok(addr) => {
                        info!("Parsed address: {}", addr);
                        Some(addr)
                    }
                    Err(e) => {
                        error!("Failed to parse address '{}': {}", arg, e);
                        None
                    }
                })
                .collect();

            if addresses.is_empty() {
                warn!("No valid addresses provided to dial");
            } else {
                info!("Dialing {} addresses:", addresses.len());
                for (i, addr) in addresses.iter().enumerate() {
                    info!("  {}. {}", i + 1, addr);
                    if let Err(e) = swarm.dial(addr.clone()) {
                        error!("Failed to dial address {}: {}", addr, e);
                    } else {
                        info!("Successfully initiated dial to: {}", addr);
                    }
                }
            }
        }
    }

    /// Dial any configured seed addresses to accelerate mesh convergence
    fn dial_seed_addresses(&self, swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>) {
        let mut dialed = std::collections::HashSet::new();

        for addr in self
            .bootstrap_addresses
            .iter()
            .chain(self.discovery_seeds.iter())
        {
            if !dialed.insert(addr.clone()) {
                continue;
            }

            info!("Dialing configured seed: {}", addr);
            if let Err(e) = swarm.dial(addr.clone()) {
                warn!("Failed to dial seed {}: {}", addr, e);
            }
        }
    }

    /// Log peer list snapshot periodically
    fn log_peer_list_snapshot(&self) {
        let peers = self.node_manager.get_active_nodes();
        let mut entries: Vec<String> = Vec::new();
        for p in &peers {
            let idx = match self.peer_discovery.peer_indices.get(p).cloned() {
                Some(i) => Some(i),
                None => {
                    let key = crate::database::key_utils::peer_index_key(&p.to_string());
                    match self.db.get_string::<usize>(&key) {
                        Ok(Some(i)) => Some(i),
                        _ => None,
                    }
                }
            };
            match idx {
                Some(i) => entries.push(format!("{}=>{}", p, i)),
                None => entries.push(format!("{}=>?", p)),
            }
        }
        let display_str = entries.join(", ");
        info!(
            "🕒 PeerList snapshot ({} peers): {}",
            peers.len(),
            display_str
        );
    }

    /// Perform periodic peer discovery
    fn perform_periodic_peer_discovery(&mut self, swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>) {
        info!("🔄 Performing periodic peer discovery...");

        // Debug: Show current state before discovery
        let current_total = self.node_manager.get_total_nodes();
        let active_nodes = self.node_manager.get_active_nodes();
        info!(
            "📊 Current node manager state - Total: {}, Active nodes: {:?}",
            current_total, active_nodes
        );

        // Log gossipsub state
        let gossipsub_peers = swarm.behaviour_mut().gossipsub.all_peers().count();
        info!("📡 Gossipsub connected peers: {}", gossipsub_peers);

        // Log Kademlia state
        let kbucket_count: usize = swarm
            .behaviour_mut()
            .kademlia
            .kbuckets()
            .map(|bucket| bucket.num_entries())
            .sum();
        info!("🌐 Kademlia routing table entries: {}", kbucket_count);

        swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(self.local_peer_id);

        // Also search for random peers to populate routing table
        let random_peer = PeerId::random();
        swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(random_peer);

        // Proactively request indices from peers we lack index for
        let active = self.node_manager.get_active_nodes();
        for p in active {
            let known = self.peer_discovery.peer_indices.contains_key(&p) || {
                let key = crate::database::key_utils::peer_index_key(&p.to_string());
                self.db.get_string::<usize>(&key).ok().flatten().is_some()
            };
            if !known {
                info!("🔎 Requesting PeerList from {} to learn indices", p);
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&p, crate::types::rpc::RPCRequest::GetPeerList);
            }
        }
    }

    /// Log periodic DKG status
    async fn log_periodic_dkg_status(&self) {
        if let Some(dkg_node) = &self.dkg_node {
            let status = dkg_node.get_status();
            info!("📊 DKG Status Check - Current status: {:?}", status);

            if let DKGStatus::Completed = status {
                // DKG is completed, log final results
                if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                    info!("🎯 DKG COMPLETED - Final secret share: {:?}", secret_share);
                }
                if let Some(public_key) = dkg_node.get_final_public_key().await {
                    info!("🔑 DKG COMPLETED - Final public key: {:?}", public_key);
                }
            } else if let DKGStatus::Started = status {
                // DKG is in progress, check progress
                info!("⏳ DKG in progress...");
            }
        }
    }
}
