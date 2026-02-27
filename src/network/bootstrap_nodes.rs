use libp2p::Multiaddr;

/// Production bootstrap nodes for the network
/// These are the trusted bootstrap peers that nodes will connect to on startup
pub const BOOTSTRAP_NODES: &[&str] = &[
    // "/ip4/159.138.130.56/tcp/4001/p2p/12D3KooWPa6rSxpPBZrgRzFUuN9RK2SqLdNinL3wTL593hjNbQRP",
    // "/ip4/27.106.121.254/tcp/4001/p2p/12D3KooWMbYhUUxpG6pNjnw4LCW4uG8yKJBhbjzBkHRDVYvnkUS5",
    // "/ip4/119.8.37.76/tcp/4001/p2p/12D3KooWHBCq9LpJ7Fn7NG9VAZfZD7d11F9R3rcTGxgBayF4Dwt4",
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

