/// Main event loop for network layer
/// Handles swarm events, channel messages, and periodic tasks
use anyhow::Result;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use std::time::Duration;
use tracing::{debug, error, info, warn};

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

        // Global clock timer - reads interval from environment variable
        let clock_interval_secs = std::env::var("GLOBAL_CLOCK_INTERVAL_SECONDS")
            .ok()
            .and_then(|val| val.parse::<u64>().ok())
            .unwrap_or_else(|| {
                info!("GLOBAL_CLOCK_INTERVAL_SECONDS not set, defaulting to 35 seconds");
                35
            });

        // Calculate next epoch-aligned trigger time for synchronized global clock
        // This ensures all nodes trigger at the same wall-clock time regardless of startup time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before Unix epoch");
        let current_epoch_secs = now.as_secs();
        let next_trigger_epoch =
            ((current_epoch_secs / clock_interval_secs) + 1) * clock_interval_secs;
        let wait_duration = Duration::from_secs(next_trigger_epoch - current_epoch_secs);

        info!(
            "⏰ [CLOCK] Synchronizing global clock to epoch boundaries - interval: {}s, first trigger in {}s",
            clock_interval_secs,
            wait_duration.as_secs()
        );

        let first_tick = tokio::time::Instant::now() + wait_duration;
        let mut global_clock_timer =
            tokio::time::interval_at(first_tick, Duration::from_secs(clock_interval_secs));
        global_clock_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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

                _ = global_clock_timer.tick() => {
                    info!("⏰ [CLOCK] Global clock tick triggered");
                    if let Err(e) = self.handle_global_clock_tick().await {
                        error!("⏰ [CLOCK] Clock task failed: {}", e);
                    } else {
                        info!("⏰ [CLOCK] Clock task executed successfully");
                    }
                }

                // Contract sequencer removed - contract transactions are executed directly
                // Network transaction sequencer removed - will be replaced with pool approach
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
        // This can be quite verbose on large networks; keep at debug level by default.
        debug!(
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

    /// Handle global clock tick - performs HRW node selection every clock tick
    /// This method has direct access to all network resources:
    /// - self.db_signing_node: Arc<Mutex<DatabaseSigningNode>> (round/selection service, signing)
    /// - self.signing_node: Option<SigningNode>
    /// - self.dkg_node: Option<DKGNode>
    /// - self.user_intent_manager: Option<UserIntentManager>
    /// - self.db: Database
    /// - self.node_manager: Box<dyn NodeMembership> (for getting available nodes)
    /// - And all other MpcNetworkLayer fields
    async fn handle_global_clock_tick(&mut self) -> Result<()> {
        info!("⏰ [CLOCK] Global clock tick triggered - performing node selection");

        // Get available nodes from node manager and convert to Vec
        let available_nodes: Vec<libp2p::PeerId> =
            self.node_manager.get_active_nodes().into_iter().collect();

        if available_nodes.is_empty() {
            warn!("⏰ [CLOCK] No available nodes for selection, skipping");
            return Ok(());
        }

        // Trigger nonce pre-generation on first clock tick when network is ready
        // GATE: Only start nonce generation AFTER initial DKG is complete.
        // Before DKG completion, nodes are still joining and dkg_signer_count is unknown,
        // which causes nonces to be created with inconsistent contributor counts across nodes.
        let initial_dkg_complete = if let Some(dkg_node) = &self.dkg_node {
            dkg_node.is_initial_dkg_complete().await
        } else {
            false
        };

        if !initial_dkg_complete {
            info!("⏳ [CLOCK] Skipping nonce pre-generation - initial DKG not yet complete");
        } else if let Some(arc) = &self.signing_node {
            let signing_node = arc.lock().await;

            // Only DKG signers initiate nonce pre-generation.
            // Observer nodes receive finalized nonces via NonceTupleBroadcast.
            if !signing_node.has_dkg_share().await {
                // Observer: just ensure NonceManager has correct dkg_signer_count
                // for nonce pool filtering, but don't start generation
                if let Some(dkg_node) = &self.dkg_node {
                    if let Some(count) = dkg_node.get_dkg_signer_count() {
                        signing_node.update_nonce_dkg_signer_count(count).await;
                    }
                }
            } else {
                // DKG signer: update NonceManager params and start pre-generation
                if let Some(dkg_node) = &self.dkg_node {
                    if let Some(count) = dkg_node.get_dkg_signer_count() {
                        signing_node.update_nonce_dkg_signer_count(count).await;
                    }
                }
                let current_node_count = self.node_manager.get_total_nodes();
                if current_node_count > 0 {
                    signing_node.update_nonce_manager_total_nodes(current_node_count).await;
                }

                if !signing_node.is_nonce_pool_ready().await {
                    info!("🎲 [CLOCK] DKG complete + network ready, triggering nonce pre-generation");
                    if let Err(e) = signing_node.start_nonce_pregeneration().await {
                        warn!("⚠️ [CLOCK] Failed to start nonce pre-generation: {}", e);
                    }
                }
            }
        }

        info!(
            "⏰ [CLOCK] Available nodes for VRF selection: count={}",
            available_nodes.len(),
        );

        // Get round/selection service - prefer signing_node, fall back to db_signing_node
        // This matches the pattern used in rpc_handlers.rs
        // Try signing_node first
        if let Some(arc) = &self.signing_node {
            let mut signing_node = arc.lock().await;
            // Update signing node with latest available nodes
            // This is critical for async tasks (like parallel contract update) that read from signing_node state later
            signing_node.set_available_nodes(available_nodes.clone());

            // Get round and sync result first so we can release vrf_service borrow before replicate_vrf_round_to_consensus (mut borrow)
            let (sync_result, round) = if let Some(vrf_service) = signing_node.vrf_service() {
                let sync_result = vrf_service.sync_rounds_before_signing().await;
                let round = vrf_service.get_next_round().await;
                (sync_result, round)
            } else {
                (Err(anyhow::anyhow!("no round service")), 0u64)
            };

            match &sync_result {
                Ok(synced_round) => signing_node.replicate_vrf_round_to_consensus(*synced_round),
                Err(e) => warn!(
                    "⏰ [CLOCK] Failed to sync rounds before selection: {}",
                    e
                ),
            }
            signing_node.replicate_vrf_round_to_consensus(round);

            if let Some(vrf_service) = signing_node.vrf_service() {
                info!(
                    "⏰ [CLOCK] Performing selection for round {} with {} available nodes (using signing_node)",
                    round,
                    available_nodes.len()
                );

                // Perform HRW node selection (selects 1 node) - ONLY ONCE
                match vrf_service
                    .perform_node_selection(
                        &available_nodes,
                        crate::vrf::VRF_NODE_SELECTION_COUNT,
                        round,
                        "global_clock",
                    )
                    .await
                {
                    Ok(selection_result) => {
                        info!(
                            "🎯 [CLOCK] Selection completed successfully for round {} (selected_nodes={}, total_nodes={})",
                            round,
                            selection_result.selected_nodes.len(),
                            selection_result.total_nodes,
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        error!("❌ [CLOCK] Selection failed for round {}: {}", round, e);
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
}
