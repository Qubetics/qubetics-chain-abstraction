use libp2p::Multiaddr;

/// Production bootstrap nodes for the network
/// These are the trusted bootstrap peers that nodes will connect to on startup
pub const BOOTSTRAP_NODES: &[&str] = &[
    "ip4/124.243.185.174/tcp/4001/p2p/12D3KooWMfUUY6QpM1N8soMouSyP2ESDScytBgRV8Fqdd6TxLntg",
    "ip4/159.138.121.15/tcp/4001/p2p/12D3KooWJn2zhxi5uZrVSuz6iuVZ1vdebha4goArREU112Kvy9dW",
    "ip4/124.243.179.78/tcp/4001/p2p/12D3KooWG6EvLVQ5SYxMSmYv3uEJWS4A7UfdWTZDYKtuZzDbnz9i"
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

