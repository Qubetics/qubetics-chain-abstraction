use anyhow::Result;
use libp2p::identity::Keypair;
use mpc_node::{
    consensus::{ConsensusNode, ConsensusResult},
    signing::SigningNode,
    types::{p2p::SerializablePeerId, ChannelMessage},
    vrf::{VrfNodeSelector, VrfSelectedNodesBroadcast},
};
use std::str::FromStr;
use tokio::sync::mpsc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting VRF-Consensus Integration Demo");

    // Create test nodes
    let nodes: Vec<SerializablePeerId> = (0..5)
        .map(|_| SerializablePeerId(libp2p::PeerId::from(Keypair::generate_ed25519().public())))
        .collect();

    info!("Created {} test nodes", nodes.len());

    // Create a channel for the signing node
    let (message_tx, _message_rx) = mpsc::channel::<ChannelMessage>(100);

    // Create signing node (which includes VRF selector and consensus node)
    let mut signing_node = SigningNode::new(
        nodes[0].0.to_string(),
        3, // threshold
        message_tx,
    );

    // Set available nodes
    let available_nodes: Vec<libp2p::PeerId> = nodes.iter().map(|n| n.0).collect();
    signing_node.set_available_nodes(available_nodes);

    // Simulate VRF selections from different nodes
    info!("=== Simulating VRF Selections ===");

    let round = 1;

    // Node 0 selects nodes[1]
    let broadcast_0 = VrfSelectedNodesBroadcast {
        selected_nodes: vec![nodes[1].clone()],
        round,
        selector_node_id: nodes[0].clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    signing_node.handle_vrf_selected_nodes_broadcast(broadcast_0);

    // Node 1 selects nodes[1] (same as node 0)
    let broadcast_1 = VrfSelectedNodesBroadcast {
        selected_nodes: vec![nodes[1].clone()],
        round,
        selector_node_id: nodes[1].clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    signing_node.handle_vrf_selected_nodes_broadcast(broadcast_1);

    // Node 2 selects nodes[2]
    let broadcast_2 = VrfSelectedNodesBroadcast {
        selected_nodes: vec![nodes[2].clone()],
        round,
        selector_node_id: nodes[2].clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    signing_node.handle_vrf_selected_nodes_broadcast(broadcast_2);

    // Node 3 selects nodes[1] (same as nodes 0 and 1)
    let broadcast_3 = VrfSelectedNodesBroadcast {
        selected_nodes: vec![nodes[1].clone()],
        round,
        selector_node_id: nodes[3].clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    signing_node.handle_vrf_selected_nodes_broadcast(broadcast_3);

    info!(
        "📊 [VRF] Collected VRF selections from 4 nodes for round {}",
        round
    );

    // Check if consensus can be started
    let can_start = signing_node.can_start_consensus(round, 2);
    info!("🔍 [CONSENSUS] Can start consensus: {}", can_start);

    if can_start {
        info!("🎯 [CONSENSUS] Starting consensus for round {}", round);

        // Start consensus
        match signing_node.start_consensus_for_round(round).await {
            Ok(Some(result)) => {
                info!("✅ [CONSENSUS] Consensus completed!");
                info!("  Final node: {:?}", result.final_node);
                info!("  Total selections: {}", result.total_selections);
                info!("  Node frequencies: {:?}", result.node_frequencies);

                // Check if this node is the final selected node
                let own_node_id =
                    SerializablePeerId(libp2p::PeerId::from_str(signing_node.get_node_id())?);
                if result.final_node == own_node_id {
                    info!("🏆 [CONSENSUS] This node is the final selected node!");
                } else {
                    info!("📋 [CONSENSUS] This node is not the final selected node");
                }
            }
            Ok(None) => {
                info!("⚠️ [CONSENSUS] No consensus result available");
            }
            Err(e) => {
                info!("❌ [CONSENSUS] Failed to start consensus: {}", e);
            }
        }
    } else {
        info!("⏳ [CONSENSUS] Not enough selections to start consensus yet");
    }

    // Test 2: Same frequency scenario
    info!("=== Test 2: Same Frequency Scenario ===");
    let round_2 = 2;

    // Each node selects a different node
    let broadcasts_round_2 = vec![
        (nodes[0].clone(), nodes[1].clone()),
        (nodes[1].clone(), nodes[2].clone()),
        (nodes[2].clone(), nodes[3].clone()),
        (nodes[3].clone(), nodes[0].clone()),
    ];

    for (selector_id, selected_node) in broadcasts_round_2 {
        let broadcast = VrfSelectedNodesBroadcast {
            selected_nodes: vec![selected_node],
            round: round_2,
            selector_node_id: selector_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        signing_node.handle_vrf_selected_nodes_broadcast(broadcast);
    }

    info!(
        "📊 [VRF] Collected VRF selections for round {} (each node selected once)",
        round_2
    );

    if signing_node.can_start_consensus(round_2, 2) {
        info!("🎯 [CONSENSUS] Starting consensus for round {}", round_2);

        match signing_node.start_consensus_for_round(round_2).await {
            Ok(Some(result)) => {
                info!("✅ [CONSENSUS] Consensus completed for round {}!", round_2);
                info!("  Final node: {:?}", result.final_node);
                info!("  Total selections: {}", result.total_selections);
                info!("  Node frequencies: {:?}", result.node_frequencies);

                // Should select the first node when all have same frequency
                info!("⚖️ [CONSENSUS] All nodes had same frequency, selected first node");
            }
            Ok(None) => {
                info!(
                    "⚠️ [CONSENSUS] No consensus result available for round {}",
                    round_2
                );
            }
            Err(e) => {
                info!(
                    "❌ [CONSENSUS] Failed to start consensus for round {}: {}",
                    round_2, e
                );
            }
        }
    }

    info!("🎉 VRF-Consensus Integration Demo completed successfully!");
    Ok(())
}
