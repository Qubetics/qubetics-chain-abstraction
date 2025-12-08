use anyhow::Result;
use libp2p::{gossipsub, kad, noise, tcp, yamux, Multiaddr, PeerId};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::sync::mpsc;
use tracing::info;

use crate::database::{keys, Database, KeyStore};
use crate::node_selection::NodeMembership;

use crate::network::discovery::types::{DatabaseSyncState, PeerDiscoveryState};
use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer, MPC_TOPICS};

impl MpcNetworkLayer {
    /// Create a new MpcNetworkLayer instance
    pub async fn new(node_manager: Box<dyn NodeMembership>, db: Database) -> Result<Self> {
        // Load or create persistent keypair using the injected database
        // Wrap in Arc to satisfy KeyStore trait object requirements
        // Clone the database since we need to move it into the struct later
        let keystore: Arc<dyn KeyStore> = Arc::new(db.clone());
        let (local_key, local_peer_id) = Self::load_or_create_keypair(keystore).await?;
        let (tx, rx) = mpsc::channel(100);

        let mut this = Self {
            local_key,
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
            peer_discovery: PeerDiscoveryState::new(),
            db,
            db_sync_state: DatabaseSyncState::new(),
            needs_database_sync: false,
            bootstrap_addresses: Self::load_multiaddrs_from_env("BOOTSTRAP_PEERS"),
            bootstrap_peer_ids: Vec::new(),
            discovery_seeds: Self::load_multiaddrs_from_env("DISCOVERY_SEEDS"),
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

    fn load_multiaddrs_from_env(env_key: &str) -> Vec<Multiaddr> {
        use tracing::warn;

        std::env::var(env_key)
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|raw| {
                        let trimmed = raw.trim();
                        if trimmed.is_empty() {
                            return None;
                        }

                        match trimmed.parse::<Multiaddr>() {
                            Ok(addr) => Some(addr),
                            Err(err) => {
                                warn!(
                                    "Ignoring invalid multiaddr from {}: {} ({})",
                                    env_key, trimmed, err
                                );
                                None
                            }
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
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

        for topic in MPC_TOPICS {
            let topic_str = topic.as_str();
            let topic_hash = gossipsub::IdentTopic::new(topic_str);
            info!("🔔 Attempting to subscribe to topic: {}", topic_str);
            info!("🔔 Topic hash: {:?}", topic_hash.hash());

            let res = swarm.behaviour_mut().gossipsub.subscribe(&topic_hash);
            match res {
                Ok(_) => {
                    info!("✅ Successfully subscribed to topic: {}", topic_str);
                }
                Err(err) => {
                    warn!(
                        "❌ Failed to subscribe to topic: {} with error {:?}",
                        topic_str, err
                    );
                }
            }
            self.topics.insert(topic_hash.hash());
        }

        // Log current gossipsub state
        let peer_count = swarm.behaviour_mut().gossipsub.all_peers().count();
        info!("📊 Current gossipsub peer count: {}", peer_count);

        Ok(())
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
                    .heartbeat_interval(Duration::from_secs(5))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .flood_publish(true)
                    .fanout_ttl(Duration::from_secs(60))
                    .prune_peers(10)
                    .prune_backoff(Duration::from_secs(1))
                    .build()
                    .map_err(io::Error::other)
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

                for addr in bootstrap_nodes.iter().chain(discovery_seeds.iter()) {
                    if let Some(peer_id) = Self::extract_peer_id(addr) {
                        kademlia.add_address(&peer_id, addr.clone());
                    }
                }

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
