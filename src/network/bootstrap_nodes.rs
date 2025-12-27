use libp2p::Multiaddr;

/// Production bootstrap nodes for the network
/// These are the trusted bootstrap peers that nodes will connect to on startup
pub const BOOTSTRAP_NODES: &[&str] = &[
//     "/ip4/124.243.185.174/tcp/4001/p2p/12D3KooWNefwVcwqcF71E8B3gNdTyK3gxn2nXAt8bF9d7gH9M6c4",
//     "/ip4/124.243.179.78/tcp/4001/p2p/12D3KooWRNv4uaXbpTduNV3sr58Ga1zPum3SDmKAMJsVKUioESpH",
];

/// Parse bootstrap nodes from the constant array
pub fn get_bootstrap_nodes() -> Vec<Multiaddr> {
    use tracing::warn;
    
    BOOTSTRAP_NODES
        .iter()
        .filter_map(|addr_str| {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => Some(addr),
                Err(err) => {
                    warn!(
                        "Failed to parse bootstrap node address: {} ({})",
                        addr_str, err
                    );
                    None
                }
            }
        })
        .collect()
}

