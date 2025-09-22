use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mpc-node")]
#[command(about = "Multi-Party Computation Node for Qubetics Chain Abstraction")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[arg(long, default_value = "./data")]
    pub data_dir: PathBuf,
    
    #[arg(long = "mpc-nodes", value_delimiter = ',')]
    pub bootstrap_nodes: Vec<String>,
    
    /// Development mode - resets the database on startup
    #[arg(long)]
    pub dev: bool,
    
    #[arg(long, default_value = "8082")]
    pub rpc_port: u16,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
    
    pub fn has_bootstrap_nodes(&self) -> bool {
        !self.bootstrap_nodes.is_empty()
    }
    
    pub fn bootstrap_node_count(&self) -> usize {
        self.bootstrap_nodes.len()
    }
    
    pub fn is_dev_mode(&self) -> bool {
        self.dev
    }
    
    /// Get the RPC server port
    pub fn get_rpc_port(&self) -> u16 {
        self.rpc_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_default_values() {
        let cli = Cli::try_parse_from(&["mpc-node"]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from("./data"));
        assert!(cli.bootstrap_nodes.is_empty());
        assert!(!cli.has_bootstrap_nodes());
    }

    #[test]
    fn test_custom_data_dir() {
        let cli = Cli::try_parse_from(&["mpc-node", "--data-dir", "/tmp/test"]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_single_bootstrap_node() {
        let cli = Cli::try_parse_from(&[
            "mpc-node",
            "--mpc-nodes",
            "/ip4/192.168.1.155/tcp/64135/p2p/12D3KooWRZzptPrcQya5miu1tHPJCXM6tpbbtB4udrgPwQDGUjHV"
        ]).unwrap();
        assert_eq!(cli.bootstrap_nodes.len(), 1);
        assert!(cli.has_bootstrap_nodes());
    }

    #[test]
    fn test_multiple_bootstrap_nodes() {
        let cli = Cli::try_parse_from(&[
            "mpc-node",
            "--mpc-nodes",
            "/ip4/192.168.1.155/tcp/64135/p2p/12D3KooWRZzptPrcQya5miu1tHPJCXM6tpbbtB4udrgPwQDGUjHV,/ip4/192.168.1.156/tcp/64136/p2p/12D3KooWAnotherPeerIdHere"
        ]).unwrap();
        assert_eq!(cli.bootstrap_nodes.len(), 2);
        assert_eq!(cli.bootstrap_node_count(), 2);
    }

    #[test]
    fn test_both_options() {
        let cli = Cli::try_parse_from(&[
            "mpc-node",
            "--data-dir",
            "/custom/data",
            "--mpc-nodes",
            "/ip4/192.168.1.155/tcp/64135/p2p/12D3KooWRZzptPrcQya5miu1tHPJCXM6tpbbtB4udrgPwQDGUjHV"
        ]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from("/custom/data"));
        assert_eq!(cli.bootstrap_nodes.len(), 1);
    }

    #[test]
    fn test_dev_flag() {
        let cli = Cli::try_parse_from(&["mpc-node", "--dev"]).unwrap();
        assert!(cli.is_dev_mode());
        assert!(cli.dev); // This should be true when --dev flag is provided
    }

    #[test]
    fn test_dev_flag_with_other_options() {
        let cli = Cli::try_parse_from(&[
            "mpc-node",
            "--dev",
            "--data-dir",
            "/dev/data",
            "--mpc-nodes",
            "/ip4/192.168.1.155/tcp/64135/p2p/12D3KooWRZzptPrcQya5miu1tHPJCXM6tpbbtB4udrgPwQDGUjHV"
        ]).unwrap();
        assert!(cli.is_dev_mode());
        assert_eq!(cli.data_dir, PathBuf::from("/dev/data"));
        assert_eq!(cli.bootstrap_nodes.len(), 1);
    }

    #[test]
    fn test_rpc_port_default() {
        let cli = Cli::try_parse_from(&["mpc-node"]).unwrap();
        assert_eq!(cli.get_rpc_port(), 8081);
    }

    #[test]
    fn test_rpc_port_custom() {
        let cli = Cli::try_parse_from(&["mpc-node", "--rpc-port", "9090"]).unwrap();
        assert_eq!(cli.get_rpc_port(), 9090);
    }

    #[test]
    fn test_rpc_port_with_other_options() {
        let cli = Cli::try_parse_from(&[
            "mpc-node",
            "--rpc-port",
            "8082",
            "--data-dir",
            "/custom/data",
            "--dev"
        ]).unwrap();
        assert_eq!(cli.get_rpc_port(), 8082);
        assert_eq!(cli.data_dir, PathBuf::from("/custom/data"));
        assert!(cli.is_dev_mode());
    }
}
