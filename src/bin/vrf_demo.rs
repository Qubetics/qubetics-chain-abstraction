use anyhow::Result;
use libp2p::identity::Keypair;
use mpc_node::{
    node_management::{DefaultThresholdCalculator, NodeMembership, VrfNodeManager},
    vrf::{VrfNodeSelector},
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting VRF-based MPC node selection demo");

    // Generate node identity
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from(local_key.public());

    info!("Node PeerId: {}", local_peer_id);

    // Create VRF-based node manager
    let threshold_calculator = Box::new(DefaultThresholdCalculator);
    let mut node_manager = VrfNodeManager::new(
        local_peer_id,
        threshold_calculator,
        10, // selection interval
    );

    // Add some test nodes
    let test_nodes: Vec<libp2p::PeerId> = (0..7)
        .map(|_| libp2p::PeerId::from(Keypair::generate_ed25519().public()))
        .collect();

    info!("Adding {} test nodes to the network", test_nodes.len());
    for (i, node) in test_nodes.iter().enumerate() {
        node_manager.add_node(*node).map_err(anyhow::Error::msg)?;
        info!("Added node {}: {:?}", i + 1, node);
    }

    info!("Total nodes in network: {}", node_manager.get_total_nodes());
    info!("Threshold for MPC: {}", node_manager.get_threshold());

    // Trigger VRF-based node selection
    info!("Triggering VRF-based node selection...");
    let selection_result = node_manager.trigger_selection().await?;

    info!(
        "Selection completed for round {}",
        selection_result.selection_round
    );
    info!(
        "Selected {} nodes for MPC:",
        selection_result.selected_nodes.len()
    );

    for (i, node) in selection_result.selected_nodes.iter().enumerate() {
        let is_self = node.0 == local_peer_id;
        info!(
            "  {}. {:?} {}",
            i + 1,
            node,
            if is_self { "(this node)" } else { "" }
        );
    }

    // Check if this node is selected
    if node_manager.is_self_selected_for_mpc() {
        info!("✅ This node is selected for MPC participation!");
    } else {
        info!("❌ This node is not selected for MPC participation");
    }

    // Demonstrate VRF proof generation
    info!(
        "Generating VRF proof for round {}",
        node_manager.get_current_round()
    );
    let vrf_selector = VrfNodeSelector::new(local_peer_id);
    let input = b"test-selection-input";
    let vrf_output = vrf_selector.generate_vrf_proof(input);

    info!("VRF proof generated:");
    info!("  Hash: {:?}", vrf_output.hash);
    info!("  Value: {}", vrf_output.value);
    info!("  Proof length: {} bytes", vrf_output.proof.len());

    // Show VRF public key
    let public_key = node_manager.get_vrf_public_key();
    info!("VRF public key: {:?}", public_key);

    // Advance to next round
    info!("Advancing to next selection round...");
    node_manager.advance_round();
    info!("Current round: {}", node_manager.get_current_round());

    info!("Demo completed successfully!");
    Ok(())
}
