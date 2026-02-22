use libp2p::Multiaddr;

/// Production bootstrap nodes for the network
/// These are the trusted bootstrap peers that nodes will connect to on startup
pub const BOOTSTRAP_NODES: &[&str] = &[
    "/ip4/49.0.205.131/tcp/4001/p2p/12D3KooWFZvv2tNAhMHsyLZjAo6o2YLMtr75ef58pMBYW44U8zYc",
    "/ip4/159.138.121.15/tcp/4001/p2p/12D3KooWExzJcdLds9E4qQu5xBnESvSWWPzvJoYEbCbvrPxwgMzc",
    "/ip4/124.243.185.174/tcp/4001/p2p/12D3KooWMeB5M1ui8AZ3zJZeqsKta64UJMUmTMe7JMCXWRjY26JN",
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

