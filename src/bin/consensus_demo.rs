use anyhow::Result;
use libp2p::identity::Keypair;
use mpc_node::{
    consensus::{ConsensusNode, ConsensusResult},
    types::p2p::SerializablePeerId,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting Consensus Demo");

    // Create test nodes
    let nodes: Vec<SerializablePeerId> = (0..5)
        .map(|_| SerializablePeerId(libp2p::PeerId::from(Keypair::generate_ed25519().public())))
        .collect();

    info!("Created {} test nodes", nodes.len());

    // Create consensus node
    let mut consensus = ConsensusNode::new();

    // Test 1: Most frequent node selection
    info!("=== Test 1: Most Frequent Node Selection ===");
    let selected_nodes_1 = vec![
        nodes[0].clone(), // appears 3 times
        nodes[0].clone(),
        nodes[0].clone(),
        nodes[1].clone(), // appears 2 times
        nodes[1].clone(),
        nodes[2].clone(), // appears 1 time
        nodes[3].clone(), // appears 1 time
    ];

    consensus.add_selected_nodes(1, selected_nodes_1);
    let result_1 = consensus.start_consensus(1)?;

    info!("Consensus result for round 1:");
    info!("  Final node: {:?}", result_1.final_node);
    info!("  Total selections: {}", result_1.total_selections);
    info!("  Node frequencies: {:?}", result_1.node_frequencies);

    assert_eq!(
        result_1.final_node, nodes[0],
        "Should select most frequent node"
    );

    // Test 2: Same frequency selection (should pick first)
    info!("=== Test 2: Same Frequency Selection ===");
    let selected_nodes_2 = vec![
        nodes[0].clone(), // each appears once
        nodes[1].clone(),
        nodes[2].clone(),
        nodes[3].clone(),
    ];

    consensus.add_selected_nodes(2, selected_nodes_2);
    let result_2 = consensus.start_consensus(2)?;

    info!("Consensus result for round 2:");
    info!("  Final node: {:?}", result_2.final_node);
    info!("  Total selections: {}", result_2.total_selections);
    info!("  Node frequencies: {:?}", result_2.node_frequencies);

    assert_eq!(
        result_2.final_node, nodes[0],
        "Should select first node when all have same frequency"
    );

    // Test 3: Mixed frequencies
    info!("=== Test 3: Mixed Frequencies ===");
    let selected_nodes_3 = vec![
        nodes[1].clone(), // appears 4 times
        nodes[1].clone(),
        nodes[1].clone(),
        nodes[1].clone(),
        nodes[0].clone(), // appears 2 times
        nodes[0].clone(),
        nodes[2].clone(), // appears 1 time
    ];

    consensus.add_selected_nodes(3, selected_nodes_3);
    let result_3 = consensus.start_consensus(3)?;

    info!("Consensus result for round 3:");
    info!("  Final node: {:?}", result_3.final_node);
    info!("  Total selections: {}", result_3.total_selections);
    info!("  Node frequencies: {:?}", result_3.node_frequencies);

    assert_eq!(
        result_3.final_node, nodes[1],
        "Should select most frequent node"
    );

    // Test 4: Check if specific node is final
    info!("=== Test 4: Check Final Node ===");
    let is_final = consensus.is_final_node(3, &nodes[1]);
    info!("Is node[1] final for round 3: {}", is_final);
    assert!(is_final, "Node[1] should be final for round 3");

    let is_not_final = consensus.is_final_node(3, &nodes[0]);
    info!("Is node[0] final for round 3: {}", is_not_final);
    assert!(!is_not_final, "Node[0] should not be final for round 3");

    // Test 5: Round management
    info!("=== Test 5: Round Management ===");
    info!(
        "Current round before advance: {}",
        consensus.get_current_round()
    );
    consensus.advance_round();
    info!(
        "Current round after advance: {}",
        consensus.get_current_round()
    );

    // Test 6: Clear round data
    info!("=== Test 6: Clear Round Data ===");
    consensus.clear_round_data(1);
    let result_after_clear = consensus.get_consensus_result(1);
    info!("Result after clearing round 1: {:?}", result_after_clear);
    assert!(result_after_clear.is_none(), "Round 1 should be cleared");

    info!("✅ All consensus tests passed!");
    info!("🎉 Consensus demo completed successfully!");

    Ok(())
}
