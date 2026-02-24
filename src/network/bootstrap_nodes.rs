use libp2p::Multiaddr;

/// Production bootstrap nodes for the network
/// These are the trusted bootstrap peers that nodes will connect to on startup
pub const BOOTSTRAP_NODES: &[&str] = &[
    "/ip4/159.138.130.56/tcp/4001/p2p/12D3KooWJwXX32gTt5tyRuU1WnNW9F498PHaFNHq7Y9T5WfJUhHy",
    "/ip4/27.106.121.254/tcp/4001/p2p/12D3KooWD19JJh8G34gMUej4Hgrg4aeqhQKYDtbpTTKavkNsa8uF",
    "/ip4/119.8.37.76/tcp/4001/p2p/12D3KooWMopsLZ5XQbCFg92ZL4WN6ENT2gp5mcSzm5KPE9FXbtLH",
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

