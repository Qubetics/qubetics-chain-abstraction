/// Main event loop for network layer
/// Handles swarm events, channel messages, and periodic tasks
use anyhow::Result;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use std::time::Duration;
use tracing::{error, info, warn};

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
            .add_node(self.local_peer_id)
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

        info!("🌐 [P2P] Starting P2P server...");
        info!("🔑 [P2P] Local Peer ID: {}", self.local_peer_id);

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

        info!("⏳ [P2P] Waiting for listen addresses to be assigned...");

        self.dial_seed_addresses(&mut swarm);
        // Dial command-line provided addresses
        self.dial_command_line_addresses(&mut swarm);

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
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

                // Contract sequencer removed - contract transactions are executed directly

                // Network transaction sequencer handler
                network_request = async {
                    if let Some(sequencer) = &self.network_transaction_sequencer {
                        // Check if currently processing and waiting for consensus
                        if let Some((tx_id, _sequence, is_confirmed)) = sequencer.get_current_processing().await {
                            if !is_confirmed {
                                // Check if we already processed and confirmed locally
                                if sequencer.is_locally_confirmed().await {
                                    // Wait for other nodes to confirm
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                    return None;
                                }

                                let has_consensus = sequencer.has_consensus().await;
                                if has_consensus {
                                    info!("✅ [NETWORK_SEQUENCER] Consensus reached for tx_id={}, proceeding to process", tx_id);
                                    if let Some(request) = sequencer.get_current_request().await {
                                        sequencer.mark_processing(&tx_id).await.ok();
                                        return Some(request);
                                    } else {
                                        info!("⚠️ [NETWORK_SEQUENCER] Consensus reached but request not found for tx_id={}, will retry", tx_id);
                                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                        return None;
                                    }
                                } else {
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                    return None;
                                }
                            } else {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                return None;
                            }
                        }

                        // Get next request (only if previous confirmed)
                        if let Some(request) = sequencer.get_next_request().await {
                            let tx_id = request.transaction_id.clone();
                            let sequence = request.sequence;

                            info!("🎯 [NETWORK_SEQUENCER] Got next request: tx_id={}, sequence={}", tx_id, sequence);

                            sequencer.cache_current_request(request.clone()).await;

                            if sequencer.propose_transaction(&tx_id, sequence).await.unwrap_or(false) {
                                info!("📤 [NETWORK_SEQUENCER] Proposed tx_id={}, waiting for consensus...", tx_id);

                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;

                                let mut consensus_wait_count = 0;
                                loop {
                                    let has_consensus = sequencer.has_consensus().await;
                                    if has_consensus {
                                        info!("✅ [NETWORK_SEQUENCER] Consensus reached for tx_id={}, proceeding to process", tx_id);
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                    consensus_wait_count += 1;
                                    if consensus_wait_count % 10 == 0 {
                                        info!("⏳ [NETWORK_SEQUENCER] Still waiting for consensus: tx_id={}, wait_count={}", tx_id, consensus_wait_count);
                                    }
                                    if consensus_wait_count > 100 {
                                        warn!("⚠️ [NETWORK_SEQUENCER] Consensus timeout for tx_id={}, proceeding anyway", tx_id);
                                        break;
                                    }
                                }

                                sequencer.mark_processing(&tx_id).await.ok();
                                Some(request)
                            } else {
                                info!("⏸️ [NETWORK_SEQUENCER] Previous transaction not confirmed, will retry");
                                None
                            }
                        } else {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            None
                        }
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(request) = network_request {
                        let tx_id = request.transaction_id.clone();
                        let sequence = request.sequence;

                        let flow_desc = match &request.flow {
                            crate::network::sequencer::NetworkTransactionFlow::NetworkToTarget { intent_hash, .. } => {
                                format!("network_to_target:{}", intent_hash)
                            }
                            crate::network::sequencer::NetworkTransactionFlow::WithdrawLiquidity { solver_address, amount, .. } => {
                                format!("withdraw_liquidity:{}:{}", solver_address, amount)
                            }
                            crate::network::sequencer::NetworkTransactionFlow::RewardPayout { solver_address, amount, .. } => {
                                format!("reward_payout:{}:{}", solver_address, amount)
                            }
                        };

                        let lock = self.network_transaction_processing_lock.clone();
                        let _lock = lock.lock().await;

                        info!("🚀 [NETWORK_SEQUENCER] Starting synchronized processing (locked): flow={}, tx_id={}, sequence={}", flow_desc, tx_id, sequence);

                        let start_time = std::time::Instant::now();
                        if let Err(e) = self.process_network_transaction(request.clone()).await {
                            error!("❌ [NETWORK_SEQUENCER] Failed to process network transaction tx_id={} (sequence={}): {}", tx_id, sequence, e);
                        } else {
                            let duration = start_time.elapsed();
                            info!("⏱️ [NETWORK_SEQUENCER] Transaction tx_id={} (sequence={}) processed in {:?}", tx_id, sequence, duration);

                            // For WithdrawLiquidity, record pending liquidity contract update (same as original flow after signing)
                            if let crate::network::sequencer::NetworkTransactionFlow::WithdrawLiquidity { solver_address, amount, .. } = &request.flow {
                                self.record_pending_liquidity_contract_update(
                                    solver_address,
                                    crate::types::TransactionNetwork::TICS,
                                    *amount,
                                )
                                .await;
                            }
                        }

                        if let Some(sequencer) = &self.network_transaction_sequencer {
                            info!("✅ [NETWORK_SEQUENCER] Marking tx_id={} (sequence={}) as completed, waiting for all nodes to confirm...", tx_id, sequence);

                            if let Err(e) = sequencer.mark_completed(&tx_id).await {
                                error!(
                                    "⚠️ [NETWORK_SEQUENCER] Failed to mark tx_id={} as completed: {}. Clearing state to avoid deadlock.",
                                    tx_id, e
                                );
                                sequencer
                                    .force_clear_processing(&tx_id, "mark_completed failure")
                                    .await;
                            }
                        }

                        info!("🏁 [NETWORK_SEQUENCER] Completed synchronized processing (lock released): flow={}, tx_id={}, sequence={}", flow_desc, tx_id, sequence);
                    }
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
                Some(i) => entries.push(format!("{p}=>{i}")),
                None => entries.push(format!("{p}=>?")),
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
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&p, crate::types::rpc::RPCRequest::GetPeerList);
            }
        }
    }

    /// Log periodic DKG status
    async fn log_periodic_dkg_status(&self) {
        // Periodic DKG status check (logging removed to reduce overhead)
    }
}
