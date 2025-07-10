use anyhow::Result;
use libp2p::identity::Keypair;
use mpc_node::{
    node_management::{DefaultThresholdCalculator, NodeMembership, VrfNodeManager},
    vrf::{VrfNodeSelector, VrfSelectedNodesBroadcast},
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting VRF selected nodes broadcast test");

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
    let test_nodes: Vec<libp2p::PeerId> = (0..5)
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
        info!("  {}. {:?}", i + 1, node.0);
    }

    // Test creating a broadcast message
    let vrf_selector = node_manager.get_vrf_selector();
    if let Some(broadcast_msg) =
        vrf_selector.create_selected_nodes_broadcast(selection_result.selection_round)
    {
        info!("Created VRF selected nodes broadcast message:");
        info!("  Round: {}", broadcast_msg.round);
        info!("  Selector node: {:?}", broadcast_msg.selector_node_id.0);
        info!("  Selected nodes: {:?}", broadcast_msg.selected_nodes);
        info!("  Timestamp: {}", broadcast_msg.timestamp);

        // Simulate receiving this broadcast on another node
        let mut test_selector = VrfNodeSelector::new(local_peer_id);
        test_selector.handle_selected_nodes_broadcast(broadcast_msg);

        // Get all selected nodes for this round
        let all_selected =
            test_selector.get_all_selected_nodes_for_round(selection_result.selection_round);
        info!(
            "All selected nodes after receiving broadcast: {:?}",
            all_selected
        );
    }

    info!("✅ VRF selected nodes broadcast test completed successfully!");
    Ok(())
}
