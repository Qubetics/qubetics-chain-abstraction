use libp2p::Multiaddr;

/// Production bootstrap nodes for the network
/// These are the trusted bootstrap peers that nodes will connect to on startup
pub const BOOTSTRAP_NODES: &[&str] = &[
    "/ip4/124.243.185.174/tcp/4001/p2p/12D3KooWAtVuWwRp31q7nKYfbfjCdoimzcQy9WhYo1caofo3PWin",
    "/ip4/159.138.121.15/tcp/4001/p2p/12D3KooWMTSCtJZ4nkJx7eLdTEiz6ZoxwoVMjVeQnvZmNZ8BcmaB",
    "/ip4/49.0.205.131/tcp/4001/p2p/12D3KooWFx2tuwQNAhgyuYSX2tz4W7eb88jeVUJRT3KTBtWwHxiT",
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

