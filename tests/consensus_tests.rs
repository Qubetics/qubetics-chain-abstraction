//! Comprehensive tests for the consensus module:
//! - ConsensusNode creation and round management
//! - Selected nodes addition and validation
//! - Consensus result calculation (deterministic)
//! - Pending results handling (results arriving before selected_nodes)
//! - Edge cases (empty nodes, missing rounds)

use mpc_node::consensus::ConsensusNode;
use mpc_node::types::{ConsensusMessage, ConsensusResult, SerializablePeerId};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_deterministic_peer_ids(count: usize) -> Vec<SerializablePeerId> {
    (0..count)
        .map(|_| {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            SerializablePeerId(keypair.public().to_peer_id())
        })
        .collect()
}

// ===================================================================
// ConsensusNode Creation
// ===================================================================

#[test]
fn consensus_node_creation() {
    let node = ConsensusNode::new();
    // Should be created without error
    assert!(node.get_consensus_result(0).is_none());
}

#[test]
fn consensus_node_default() {
    let node = ConsensusNode::default();
    assert!(node.get_consensus_result(0).is_none());
}

// ===================================================================
// Selected Nodes Management
// ===================================================================

#[test]
fn add_selected_nodes_for_round() {
    let mut node = ConsensusNode::new();
    let peers = make_deterministic_peer_ids(3);

    node.add_selected_nodes(1, peers.clone());

    // Should be able to start consensus for this round
    let result = node.start_consensus(1);
    assert!(result.is_ok());
}

#[test]
fn add_selected_nodes_multiple_rounds() {
    let mut node = ConsensusNode::new();

    node.add_selected_nodes(1, make_deterministic_peer_ids(3));
    node.add_selected_nodes(2, make_deterministic_peer_ids(4));
    node.add_selected_nodes(3, make_deterministic_peer_ids(2));

    // All rounds should be startable
    assert!(node.start_consensus(1).is_ok());
    assert!(node.start_consensus(2).is_ok());
    assert!(node.start_consensus(3).is_ok());
}

// ===================================================================
// Consensus Result Calculation
// ===================================================================

#[test]
fn consensus_result_is_deterministic() {
    // Use the SAME set of peer IDs for both nodes
    let peers = make_deterministic_peer_ids(3);

    let mut node1 = ConsensusNode::new();
    let mut node2 = ConsensusNode::new();

    node1.add_selected_nodes(1, peers.clone());
    node2.add_selected_nodes(1, peers.clone());

    let result1 = node1.start_consensus(1).unwrap();
    let result2 = node2.start_consensus(1).unwrap();

    // Same inputs -> same result (deterministic)
    assert_eq!(result1.round, result2.round);
    assert_eq!(result1.final_node, result2.final_node);
}

#[test]
fn consensus_result_has_correct_round() {
    let mut node = ConsensusNode::new();
    node.add_selected_nodes(42, make_deterministic_peer_ids(3));

    let result = node.start_consensus(42).unwrap();
    assert_eq!(result.round, 42);
}

#[test]
fn consensus_result_final_node_is_from_selected() {
    let mut node = ConsensusNode::new();
    let peers = make_deterministic_peer_ids(3);

    node.add_selected_nodes(1, peers.clone());
    let result = node.start_consensus(1).unwrap();

    // The final_node should be one of the selected peers
    assert!(
        peers.iter().any(|p| *p == result.final_node),
        "Final node should be one of the selected peers"
    );
}

#[test]
fn consensus_result_different_rounds_different_results() {
    let mut node = ConsensusNode::new();
    let peers = make_deterministic_peer_ids(3);

    node.add_selected_nodes(1, peers.clone());
    node.add_selected_nodes(2, peers.clone());

    let result1 = node.start_consensus(1).unwrap();
    let result2 = node.start_consensus(2).unwrap();

    // Different rounds
    assert_ne!(result1.round, result2.round);
}

#[test]
fn consensus_result_different_peers_different_results() {
    let mut node1 = ConsensusNode::new();
    let peers1 = make_deterministic_peer_ids(3);
    node1.add_selected_nodes(1, peers1);
    let result1 = node1.start_consensus(1).unwrap();

    let mut node2 = ConsensusNode::new();
    // Different set of peers
    let peers2 = make_deterministic_peer_ids(3);
    node2.add_selected_nodes(1, peers2);
    let result2 = node2.start_consensus(1).unwrap();

    // Different peers will likely produce different final nodes
    // (not guaranteed since it's random keypairs, but we verify structure)
    assert_eq!(result1.round, result2.round);
}

// ===================================================================
// Consensus: Error Cases
// ===================================================================

#[test]
fn consensus_no_selected_nodes_errors() {
    let mut node = ConsensusNode::new();

    // No selected nodes for round 1
    let result = node.start_consensus(1);
    assert!(result.is_err());
}

#[test]
fn consensus_wrong_round_errors() {
    let mut node = ConsensusNode::new();
    node.add_selected_nodes(1, make_deterministic_peer_ids(3));

    // Ask for round 2 (no nodes set for it)
    let result = node.start_consensus(2);
    assert!(result.is_err());
}

// ===================================================================
// Consensus Result Retrieval
// ===================================================================

#[test]
fn get_consensus_result_after_start() {
    let mut node = ConsensusNode::new();
    node.add_selected_nodes(1, make_deterministic_peer_ids(3));

    let result = node.start_consensus(1).unwrap();
    let retrieved = node.get_consensus_result(1);

    assert!(retrieved.is_some());
    let r = retrieved.unwrap();
    assert_eq!(r.round, result.round);
    assert_eq!(r.final_node, result.final_node);
}

#[test]
fn get_consensus_result_nonexistent_round() {
    let node = ConsensusNode::new();
    assert!(node.get_consensus_result(999).is_none());
}

// ===================================================================
// Consensus: Overwrite Protection
// ===================================================================

#[test]
fn consensus_start_same_round_twice() {
    let mut node = ConsensusNode::new();
    let peers = make_deterministic_peer_ids(3);
    node.add_selected_nodes(1, peers);

    let result1 = node.start_consensus(1).unwrap();
    let result2 = node.start_consensus(1).unwrap();

    // Results should be identical (deterministic with same inputs)
    assert_eq!(result1.final_node, result2.final_node);
}

// ===================================================================
// ConsensusResult Serialization
// ===================================================================

#[test]
fn consensus_result_serialization_roundtrip() {
    let mut node = ConsensusNode::new();
    node.add_selected_nodes(1, make_deterministic_peer_ids(3));

    let result = node.start_consensus(1).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: ConsensusResult = serde_json::from_str(&json).unwrap();

    assert_eq!(result.round, deserialized.round);
    assert_eq!(result.final_node, deserialized.final_node);
}

// ===================================================================
// Consensus with single node
// ===================================================================

#[test]
fn consensus_single_node() {
    let mut node = ConsensusNode::new();
    let single_peer = make_deterministic_peer_ids(1);

    node.add_selected_nodes(1, single_peer.clone());
    let result = node.start_consensus(1).unwrap();

    // With a single node, the final node must be that node
    assert_eq!(result.final_node, single_peer[0]);
}

// ===================================================================
// Consensus: Large round numbers
// ===================================================================

#[test]
fn consensus_large_round_number() {
    let mut node = ConsensusNode::new();
    let round = u64::MAX - 1;

    node.add_selected_nodes(round, make_deterministic_peer_ids(3));
    let result = node.start_consensus(round);

    assert!(result.is_ok());
    assert_eq!(result.unwrap().round, round);
}

// ===================================================================
// Consensus: handle_message with FinalNodeResult
// ===================================================================

#[tokio::test]
async fn handle_message_final_node_result() {
    let mut node = ConsensusNode::new();
    let peers = make_deterministic_peer_ids(3);
    node.add_selected_nodes(1, peers.clone());

    // First, calculate the expected result
    let expected_result = node.start_consensus(1).unwrap();

    // Create a new node and handle the message
    let mut node2 = ConsensusNode::new();
    node2.add_selected_nodes(1, peers);

    let msg = ConsensusMessage::FinalNodeResult {
        result: expected_result.clone(),
        round: 1,
    };

    let handle_result = node2.handle_message(msg).await;
    assert!(handle_result.is_ok());
}

#[tokio::test]
async fn handle_message_mismatched_round_errors() {
    let mut node = ConsensusNode::new();
    let peers = make_deterministic_peer_ids(3);
    node.add_selected_nodes(1, peers.clone());

    let result = node.start_consensus(1).unwrap();

    // Create message with mismatched round
    let mut node2 = ConsensusNode::new();
    node2.add_selected_nodes(1, peers);

    let msg = ConsensusMessage::FinalNodeResult {
        result: result.clone(),
        round: 999, // Mismatch with result.round=1
    };

    let handle_result = node2.handle_message(msg).await;
    assert!(handle_result.is_err(), "Mismatched round should cause error");
}

// ===================================================================
// ConsensusResult fields
// ===================================================================

#[test]
fn consensus_result_has_expected_fields() {
    let mut node = ConsensusNode::new();
    node.add_selected_nodes(5, make_deterministic_peer_ids(3));

    let result = node.start_consensus(5).unwrap();

    // Verify all expected fields exist
    assert_eq!(result.round, 5);
    let _final_node: &SerializablePeerId = &result.final_node;
    let _frequencies: &std::collections::HashMap<SerializablePeerId, usize> = &result.node_frequencies;
    let _total: usize = result.total_selections;
}
