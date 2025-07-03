use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting DKG Demo - Rectified Flow");
    println!("=====================================");

    // Start the first node (bootstrap node)
    println!("📡 Starting bootstrap node...");
    let mut bootstrap = Command::new("cargo")
        .args(&["run", "--bin", "mpc_node"])
        .spawn()?;

    // Wait a bit for bootstrap to start
    sleep(Duration::from_secs(3)).await;

    // Start additional nodes
    let mut nodes = vec![];
    for i in 1..=3 {
        println!("📡 Starting node {}...", i);
        let node = Command::new("cargo")
            .args(&["run", "--bin", "mpc_node"])
            .spawn()?;
        nodes.push(node);

        // Wait between node starts
        sleep(Duration::from_secs(2)).await;
    }

    println!("✅ All nodes started. DKG should begin automatically when enough nodes connect.");
    println!("📊 Expected behavior:");
    println!("   1. Nodes will discover each other via Kademlia");
    println!("   2. When threshold + 1 nodes are connected, DKG will start automatically");
    println!("   3. Each node will generate and broadcast shares");
    println!("   4. Nodes will validate received shares");
    println!("   5. Final secret shares and public keys will be logged");
    println!("   6. DKG status will be marked as 'Completed'");

    println!("\n🔍 Check the logs for:");
    println!("   - Node connection messages");
    println!("   - DKG start messages");
    println!("   - Share distribution and validation");
    println!("   - Final secret shares and public keys");
    println!("   - DKG completion status");

    // Keep running for a while to see the DKG process
    println!("\n⏳ Running for 60 seconds to observe DKG flow...");
    sleep(Duration::from_secs(60)).await;

    // Clean up
    println!("🛑 Stopping all nodes...");
    bootstrap.kill()?;
    for mut node in nodes {
        node.kill()?;
    }

    println!("✅ Demo completed!");
    Ok(())
}
