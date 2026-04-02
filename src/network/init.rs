use anyhow::Result;
use libp2p::{gossipsub, kad, noise, tcp, yamux, Multiaddr, PeerId};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::sync::{mpsc, Mutex};
use tracing::info;

use crate::database::{keys, Database};
use crate::node_selection::NodeMembership;

use crate::network::config::NetworkConfig;
use crate::network::discovery::types::{DatabaseSyncState, PeerDiscoveryState, StateSyncState};
use crate::network::rpc::channel_monitor::ChannelHealthMonitor;
use crate::network::rpc::retry_manager::RetryManager;
use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer, MPC_TOPICS};

impl MpcNetworkLayer {
    /// Create a new MpcNetworkLayer instance with provided keypair and optional extra bootstrap peers
    pub async fn new_with_bootstrap(
        node_manager: Box<dyn NodeMembership>,
        db: Database,
        keypair: libp2p::identity::Keypair,
        extra_bootstrap: Vec<Multiaddr>,
    ) -> Result<Self> {
        // Load network configuration from config.rs (hardcoded bootstrap nodes)
        let mut network_config = NetworkConfig::default();

        // Merge CLI-provided bootstrap peers into the config (if any)
        for addr in extra_bootstrap {
            network_config.bootstrap_peers.push(addr.clone());
            network_config.discovery_seeds.push(addr);
        }

        // Log bootstrap node configuration
        info!(
            "🌐 [NETWORK_CONFIG] Loaded {} bootstrap peers and {} discovery seeds",
            network_config.bootstrap_peers.len(),
            network_config.discovery_seeds.len()
        );
        if !network_config.bootstrap_peers.is_empty() {
            for (i, addr) in network_config.bootstrap_peers.iter().enumerate() {
                info!("   Bootstrap peer {}: {}", i + 1, addr);
            }
        }
        if !network_config.discovery_seeds.is_empty() {
            for (i, addr) in network_config.discovery_seeds.iter().enumerate() {
                info!("   Discovery seed {}: {}", i + 1, addr);
            }
        }

        // Use the provided keypair instead of loading/creating one
        let local_peer_id = PeerId::from(keypair.public());
        info!(
            "🔑 [NETWORK] Using provided keypair - Peer ID: {}",
            local_peer_id
        );
        // Production: Large channel capacity for high-concurrency scenarios
        // With 11+ parallel users, each can generate multiple messages simultaneously
        // Channel needs to handle: broadcasts + retries + ACKs + internal messages
        // Formula: (users * avg_messages_per_user * burst_factor) + retry_buffer
        // For high load: (50 * 15 * 3) + 2000 = 2250 + large safety margin
        // Increased significantly to handle parallel burst traffic without channel blocking
        // Increased to 50000 to prevent channel overflow and message loss under extreme load
        let (tx, rx) = mpsc::channel(50000); // Increased from 10000 to 50000 to prevent overflow and message loss
        let tx_for_retry = tx.clone();

        // Initialize channel health monitor for production monitoring
        let channel_health = Arc::new(ChannelHealthMonitor::new());

        let mut this = Self {
            local_key: keypair,
            local_peer_id,
            message_tx: tx,
            message_rx: rx,
            topics: HashSet::new(),
            dkg_node: None,
            signing_node: None,
            db_signing_node: None,
            consensus_node: None,
            command_processor: None,
            user_intent_manager: None,
            node_manager,
            scheduled_dkg_task: None,
            vrf_round_requested: false,
            peer_rounds: HashMap::new(),
            peer_discovery: PeerDiscoveryState::new(),
            db,
            db_sync_state: DatabaseSyncState::new(),
            needs_database_sync: false,
            state_sync_state: StateSyncState::new(),
            needs_state_sync: true, // New node requests full state from first peer it connects to
            bootstrap_addresses: network_config.bootstrap_peers,
            bootstrap_peer_ids: Vec::new(),
            discovery_seeds: network_config.discovery_seeds,
            connected_peers_cache: std::collections::HashSet::new(),
            // Removed: deterministic_selection field
            // Removed: network_transaction_processing_lock field (unused)
            retry_manager: Some(RetryManager::new(tx_for_retry)),
            channel_health,
            outbound_inflight: Arc::new(Mutex::new(HashMap::new())),
            outbound_retry: Arc::new(Mutex::new(HashMap::new())),
            peer_invalidation_pending: Arc::new(Mutex::new(HashMap::new())),
            clock_tick_count: 0,
            failed_dial_addresses: HashMap::new(),
            rejected_peers: HashMap::new(),
            processed_batch_rounds: HashSet::new(),
        };

        this.bootstrap_peer_ids = this
            .bootstrap_addresses
            .iter()
            .filter_map(Self::extract_peer_id)
            .collect();

        // Preload any persisted peer indices into memory
        if let Ok(keys) = this.db.get_keys_with_prefix_async(keys::PEER_INDEX).await {
            for k in keys {
                if let Some(peer_str) = k.strip_prefix(keys::PEER_INDEX) {
                    if let Ok(Some(idx)) = this.db.get_string_async::<usize>(&k).await {
                        if let Ok(pid) = peer_str.parse() {
                            this.peer_discovery.peer_indices.insert(pid, idx);
                        }
                    }
                }
            }
        }

        // Preload any persisted peer addresses into memory
        if let Ok(keys) = this
            .db
            .get_keys_with_prefix_async(crate::database::keys::PEER_ADDR)
            .await
        {
            info!("🔐 [PEER_LIST] Loading peer addresses from database");
            for k in keys {
                if let Some(peer_str) = k.strip_prefix(crate::database::keys::PEER_ADDR) {
                    if let (Ok(Some(addr_str)), Ok(pid)) = (
                        this.db.get_string_async::<String>(&k).await,
                        peer_str.parse(),
                    ) {
                        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                            this.peer_discovery.peer_multiaddresses.insert(pid, addr);
                        }
                    }
                }
            }
        }

        // Ensure we have our own index persisted
        this.ensure_local_index();

        Ok(this)
    }

    fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
        addr.iter().find_map(|proto| match proto {
            libp2p::multiaddr::Protocol::P2p(multihash) => {
                PeerId::from_multihash(multihash.into()).ok()
            }
            _ => None,
        })
    }

    /// Subscribe to default gossipsub topics
    pub(crate) fn subscribe_to_default_topics(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        use tracing::warn;

        let mut subscribed = 0usize;
        let mut failed = 0usize;
        for topic in MPC_TOPICS {
            let topic_str = topic.as_str();
            let topic_hash = gossipsub::IdentTopic::new(topic_str);

            match swarm.behaviour_mut().gossipsub.subscribe(&topic_hash) {
                Ok(_) => {
                    subscribed += 1;
                }
                Err(err) => {
                    warn!(
                        "Failed to subscribe to topic: {} error {:?}",
                        topic_str, err
                    );
                    failed += 1;
                }
            }
            self.topics.insert(topic_hash.hash());
        }

        info!(
            "[P2P] Subscribed to {}/{} gossipsub topics (failed: {})",
            subscribed,
            MPC_TOPICS.len(),
            failed
        );

        Ok(())
    }

    /// Backwards-compatible constructor without extra bootstrap peers (used in tests)
    pub async fn new(
        node_manager: Box<dyn NodeMembership>,
        db: Database,
        keypair: libp2p::identity::Keypair,
    ) -> Result<Self> {
        Self::new_with_bootstrap(node_manager, db, keypair, Vec::new()).await
    }

    /// Build swarm with configured behavior
    pub(crate) fn build_swarm(&self) -> Result<libp2p::Swarm<MpcNetworkBehaviour>> {
        use crate::types::rpc::build_mpc_behaviour;
        use kad::{store::MemoryStore, BucketInserts};

        let bootstrap_nodes = self.bootstrap_addresses.clone();
        let discovery_seeds = self.discovery_seeds.clone();

        let swarm = libp2p::SwarmBuilder::with_existing_identity(self.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    message.topic.hash(&mut s);
                    message.source.hash(&mut s);
                    message.sequence_number.hash(&mut s);

                    gossipsub::MessageId::from(s.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1)) // Default heartbeat interval (1s)
                    .validation_mode(gossipsub::ValidationMode::Strict) // Faster validation (changed from Strict)
                    .message_id_fn(message_id_fn)
                    .flood_publish(false)
                    .fanout_ttl(Duration::from_secs(60))
                    .prune_peers(10)
                    .prune_backoff(Duration::from_secs(60))
                    // Increase internal gossipsub connection handler queue to match
                    // the external mpsc channel capacity (50_000). This reduces the
                    // chance of hitting PublishError::AllQueuesFull(...) under high load.
                    .connection_handler_queue_len(50_000)
                    // Heavy-load tuning:
                    // Allow publish/forward queues to buffer longer before dropping,
                    // to give slow peers time to drain under bursty load.
                    .publish_queue_duration(Duration::from_secs(10))
                    .forward_queue_duration(Duration::from_secs(5))
                    // Increase history so high-throughput topics (vrf-selection, transactions)
                    // are still gossipable even with many messages per heartbeat.
                    .history_length(100)
                    .history_gossip(50)
                    // Allow larger messages / batches if needed.
                    .max_transmit_size(10_000_000) // 10 MB
                    // For small-ish networks, slightly lower mesh_n_* to keep mesh stable
                    // but not too sparse; can be tuned further if needed.
                    .mesh_n_low(2)
                    .mesh_n(4)
                    .mesh_n_high(8)
                    .mesh_outbound_min(1)
                    // .validate_messages()  // Enable async validation to prevent blocking
                    .build()
                    .map_err(io::Error::other)?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // Initialize Kademlia
                let store = MemoryStore::new(key.public().to_peer_id());
                let mut kademlia_config = kad::Config::default();
                kademlia_config.set_kbucket_inserts(BucketInserts::OnConnected);
                kademlia_config.set_query_timeout(Duration::from_secs(60));
                kademlia_config
                    .set_replication_factor(NonZeroUsize::new(3).expect("3 is non-zero"));

                let mut kademlia =
                    kad::Behaviour::with_config(key.public().to_peer_id(), store, kademlia_config);

                // Add bootstrap nodes and discovery seeds to Kademlia
                let mut added_count = 0;
                for addr in bootstrap_nodes.iter().chain(discovery_seeds.iter()) {
                    if let Some(peer_id) = Self::extract_peer_id(addr) {
                        // Strip /p2p/ component — Kademlia keys by peer_id separately
                        let clean_addr: libp2p::Multiaddr = addr
                            .iter()
                            .filter(|proto| {
                                !matches!(proto, libp2p::multiaddr::Protocol::P2p(_))
                            })
                            .collect();
                        kademlia.add_address(&peer_id, clean_addr);
                        added_count += 1;
                    }
                }
                info!(
                    "🌐 [KADEMLIA] Added {} bootstrap/discovery addresses to Kademlia DHT",
                    added_count
                );

                let request_response = build_mpc_behaviour();

                Ok(MpcNetworkBehaviour {
                    gossipsub,
                    request_response,
                    kademlia,
                })
            })?
            .build();

        Ok(swarm)
    }
}
