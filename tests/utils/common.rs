use std::{
    io::BufRead,
    process::{Child, Command, Stdio},
    time::Duration,
};

use crate::utils::wait_for_dkg;
use reqwest::Client;
use std::string::ToString;
use tokio::time::sleep;

const TARGET_ADDRESS_ETH: &str = "0x7bfF967268b7A551bc53fC68104bF22d36577C37";
const TARGET_ADDRESS_BTC: &str = "myap9aRxhb9YVcAhhXdqruKLfyzoVCGGLJ";

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum SupportedNetwork {
    Qubetics,
    Bitcoin,
}

impl ToString for SupportedNetwork {
    fn to_string(&self) -> String {
        match self {
            SupportedNetwork::Qubetics => "qubetics".to_string(),
            SupportedNetwork::Bitcoin => "bitcoin".to_string(),
        }
    }
}

pub fn get_pair_and_target_address(
    source_network: SupportedNetwork,
    target_network: SupportedNetwork,
) -> (String, String, String) {
    if source_network == SupportedNetwork::Qubetics && target_network == SupportedNetwork::Bitcoin {
        return (
            "TICS".to_string(),
            "BTC".to_string(),
            TARGET_ADDRESS_BTC.to_string(),
        );
    } else if source_network == SupportedNetwork::Bitcoin
        && target_network == SupportedNetwork::Qubetics
    {
        return (
            "BTC".to_string(),
            "TICS".to_string(),
            TARGET_ADDRESS_ETH.to_string(),
        );
    } else {
        panic!(
            "Invalid network pair: {:?} -> {:?}",
            source_network, target_network
        );
    }
}

pub struct NodeProcess {
    pub child: Child,
    pub id: usize,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        println!("Node {} stopped.", self.id);
    }
}

pub async fn run_nodes(
    client: &Client,
    rpc_port: u16,
    node_dirs: &[&str],
) -> anyhow::Result<(Vec<NodeProcess>, String, u16)> {
    // Load environment variables for test
    dotenv::dotenv().ok();
    // Ensure NETWORK_TYPE is set for the test process
    std::env::set_var("NETWORK_TYPE", "testnet");
    // Initialize the global network type
    let _ = mpc_node::types::init_network_type_from_env();

    println!("Building project (release)...");
    let status = Command::new("cargo")
        .args(&["build", "--release"])
        .status()
        .expect("Failed to build project");
    if !status.success() {
        return Err(anyhow::anyhow!("Build failed"));
    }

    println!("Preparing directories and binaries...");
    let source_bin = "./target/release/mpc-node";

    // Clean root data/logs (for Node 1)
    for _ in 0..5 {
        if std::fs::remove_dir_all("data").is_ok() {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    for _ in 0..5 {
        if std::fs::remove_dir_all("logs").is_ok() {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    std::fs::create_dir_all("logs")?;

    for dir in node_dirs {
        let _ = std::fs::create_dir_all(dir);

        let _ = std::fs::remove_dir_all(format!("{}/data", dir));
        let _ = std::fs::remove_dir_all(format!("{}/logs", dir));
        std::fs::create_dir_all(format!("{}/logs", dir))?;

        // Copy binary
        let _ = std::fs::remove_file(format!("{}/mpc-node", dir));
        std::fs::copy(source_bin, format!("{}/mpc-node", dir))
            .expect(&format!("Failed to copy binary to {}", dir));
    }

    println!("Starting Node 1 (Main) on port {}", rpc_port);
    let log_file_1 = std::fs::File::create("logs/node_1.log")?;

    let mut node1_child = Command::new(source_bin)
        .env("RPC_PORT", rpc_port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped()) // Capture stdout for multiaddr
        .stderr(Stdio::from(log_file_1))
        .spawn()
        .expect("Failed to start Node 1");

    let stdout = node1_child.stdout.take().expect("Failed to capture stdout");
    let reader = std::io::BufReader::new(stdout);

    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        for line in reader.lines() {
            if let Ok(l) = line {
                println!("[Node 1] {}", l);
                if l.contains("multiaddress   : /ip4/127.0.0.1") {
                    if let Some(addr_part) = l.split("multiaddress   : ").nth(1) {
                        let addr = addr_part.trim().to_string();
                        let _ = tx.send(addr);
                    }
                }
            }
        }
    });

    let node1_addr = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("Timed out waiting for Node 1 multiaddress");
    println!("✅ Captured Node 1 Address: {}", node1_addr);

    let mut nodes = vec![NodeProcess {
        child: node1_child,
        id: 1,
    }];

    for (i, dir) in node_dirs.iter().enumerate() {
        let node_id = i + 2; // 2, 3, 4
        println!("Starting Node {} from ./{}", node_id, dir);

        let log_file = std::fs::File::create(format!("{}/logs/node.log", dir))?;

        let mut child = Command::new("./mpc-node") // Relative to current_dir
            .current_dir(dir)
            .env("RPC_PORT", (rpc_port + node_id as u16).to_string())
            // Run inside node directory
            .arg(&node1_addr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped()) // Capture stdout to print
            .stderr(Stdio::from(log_file)) // Keep stderr to file (or pipe if needed)
            .spawn()
            .expect(&format!("Failed to start Node {}", node_id));

        if let Some(stdout) = child.stdout.take() {
            let reader = std::io::BufReader::new(stdout);
            std::thread::spawn(move || {
                for line in reader.lines() {
                    if let Ok(l) = line {
                        println!("[Node {}] {}", node_id, l);
                    }
                }
            });
        }

        nodes.push(NodeProcess { child, id: node_id });
        sleep(Duration::from_secs(2)).await;
    }

    let dkg_success = wait_for_dkg(&client, rpc_port).await;
    assert!(dkg_success, "DKG failed to complete within timeout");

    let parts: Vec<&str> = node1_addr.split("/p2p/").collect();
    let node1_peer_id = parts
        .get(1)
        .expect("Failed to extract peer ID from multiaddr");
    println!("Node 1 Peer ID: {}", node1_peer_id);

    let node1_p2p_port: u16 = node1_addr
        .split("/tcp/")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Failed to parse p2p port from multiaddr: {}", node1_addr))?;
    println!("Node 1 P2P Port: {}", node1_p2p_port);

    Ok((nodes, node1_peer_id.to_string(), node1_p2p_port))
}

pub async fn sleep_for_10_seconds() {
    sleep(Duration::from_secs(10)).await;
}

pub async fn run_fifth_node(rpc_port: u16, p2p_port: u16, node1_addr: &str) -> anyhow::Result<NodeProcess> {
    let node_dir = "node4";
    let node_id = 5;
    let source_bin = "./target/release/mpc-node";

    // Prepare directory for node5
    let _ = std::fs::create_dir_all(node_dir);
    let _ = std::fs::remove_dir_all(format!("{}/data", node_dir));
    let _ = std::fs::remove_dir_all(format!("{}/logs", node_dir));
    std::fs::create_dir_all(format!("{}/logs", node_dir))?;

    // Copy binary
    let _ = std::fs::remove_file(format!("{}/mpc-node", node_dir));
    std::fs::copy(source_bin, format!("{}/mpc-node", node_dir))
        .expect(&format!("Failed to copy binary to {}", node_dir));

    // Construct the bootstrap multiaddress using node1's peer ID
    let node1_addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", p2p_port, node1_addr);

    println!("Node 1 Address: {}", node1_addr);

    println!("Starting Node {} from ./{}", node_id, node_dir);

    let log_file = std::fs::File::create(format!("{}/logs/node.log", node_dir))?;

    let mut child = Command::new("./mpc-node")
        .current_dir(node_dir)
        .env("RPC_PORT", (rpc_port + node_id as u16).to_string())
        .arg(&node1_addr)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect(&format!("Failed to start Node {}", node_id));

    if let Some(stdout) = child.stdout.take() {
        let reader = std::io::BufReader::new(stdout);
        std::thread::spawn(move || {
            for line in reader.lines() {
                if let Ok(l) = line {
                    println!("[Node {}] {}", node_id, l);
                }
            }
        });
    }

    // Give the node time to connect and sync
    sleep(Duration::from_secs(10)).await;

    println!("✅ Node {} started and connected to the network", node_id);

    Ok(NodeProcess { child, id: node_id })
}
