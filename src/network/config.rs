use libp2p::Multiaddr;

use crate::network::bootstrap_nodes::get_bootstrap_nodes;

/// Network configuration for P2P bootstrap and discovery
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Bootstrap peer addresses (with peer IDs) for initial network connection
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Discovery seed addresses for peer discovery
    pub discovery_seeds: Vec<Multiaddr>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // Load bootstrap nodes from bootstrap_nodes.rs
        let default_bootstrap_peers = get_bootstrap_nodes();

        // Discovery seeds (using same as bootstrap nodes)
        let default_discovery_seeds = default_bootstrap_peers.clone();

        Self {
            bootstrap_peers: default_bootstrap_peers,
            discovery_seeds: default_discovery_seeds,
        }
    }
}

impl NetworkConfig {

    /// Get all bootstrap addresses (bootstrap peers + discovery seeds)
    pub fn all_bootstrap_addresses(&self) -> Vec<Multiaddr> {
        self.bootstrap_peers
            .iter()
            .chain(self.discovery_seeds.iter())
            .cloned()
            .collect()
    }
}

