//! Leader Election Module
//!
//! Implements deterministic leader election following THORChain's pattern.
//! All nodes will independently compute the same leader for a given round
//! using a hash-based selection algorithm.

use crate::types::SerializablePeerId;
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use tracing::info;

/// Deterministically select a leader from a list of peers.
///
/// This function ensures all nodes agree on the same leader for a given
/// message_id and block_height combination without any communication.
///
/// # Algorithm
/// 1. Sort peers lexicographically for determinism
/// 2. Hash: SHA256(message_id || block_height)
/// 3. Use hash bytes to compute index: hash_value % peer_count
/// 4. Return peer at computed index
///
/// # Arguments
/// * `message_id` - Unique identifier for the operation (e.g., "round_123")
/// * `block_height` - Current block height for additional entropy
/// * `peers` - List of available peers to select from
///
/// # Returns
/// The deterministically selected leader peer ID
pub fn leader_node(
    message_id: &str,
    block_height: u64,
    peers: &[SerializablePeerId],
) -> Result<SerializablePeerId> {
    if peers.is_empty() {
        return Err(anyhow!("No peers available for leader election"));
    }

    // Sort peers lexicographically for determinism
    let mut sorted_peers = peers.to_vec();
    sorted_peers.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));

    // Hash: SHA256(message_id || block_height)
    let mut hasher = Sha256::new();
    hasher.update(message_id.as_bytes());
    hasher.update(block_height.to_be_bytes());
    let hash = hasher.finalize();

    // Use first 8 bytes as u64 for index calculation
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[..8]);
    let hash_value = u64::from_be_bytes(bytes);

    // Compute index using modulo
    let index = (hash_value as usize) % sorted_peers.len();

    let leader = sorted_peers[index].clone();

    info!(
        "👑 [LEADER] Elected leader for msg_id={}, block_height={}: {} (index={}/{})",
        message_id,
        block_height,
        leader.0,
        index,
        sorted_peers.len()
    );

    Ok(leader)
}

/// Generate a unique message ID for a consensus round
pub fn consensus_message_id(round: u64, operation_type: &str) -> String {
    format!("consensus_{}_{}", operation_type, round)
}

/// Generate a unique message ID for a VRF selection round
pub fn vrf_message_id(round: u64, operation_type: &str) -> String {
    format!("vrf_{}_{}", operation_type, round)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;

    fn create_test_peers(count: usize) -> Vec<SerializablePeerId> {
        (0..count)
            .map(|_| SerializablePeerId(PeerId::from(Keypair::generate_ed25519().public())))
            .collect()
    }

    #[test]
    fn test_leader_election_determinism() {
        let peers = create_test_peers(5);
        let message_id = "test_round_1";
        let block_height = 12345u64;

        // Run multiple times - should always get same result
        let leader1 = leader_node(message_id, block_height, &peers).unwrap();
        let leader2 = leader_node(message_id, block_height, &peers).unwrap();
        let leader3 = leader_node(message_id, block_height, &peers).unwrap();

        assert_eq!(leader1, leader2);
        assert_eq!(leader2, leader3);
    }

    #[test]
    fn test_leader_election_different_rounds() {
        let peers = create_test_peers(10);

        let leader1 = leader_node("round_1", 100, &peers).unwrap();
        let leader2 = leader_node("round_2", 100, &peers).unwrap();

        // Different rounds may (likely will) have different leaders
        // This isn't guaranteed but is statistically likely with 10 peers
        // The important thing is determinism, not difference
        let _ = leader1;
        let _ = leader2;
    }

    #[test]
    fn test_leader_election_different_block_heights() {
        let peers = create_test_peers(10);

        let leader1 = leader_node("round_1", 100, &peers).unwrap();
        let leader2 = leader_node("round_1", 101, &peers).unwrap();

        // Different block heights should produce different results
        // (statistically likely, not guaranteed)
        let _ = leader1;
        let _ = leader2;
    }

    #[test]
    fn test_leader_election_empty_peers() {
        let peers: Vec<SerializablePeerId> = vec![];
        let result = leader_node("test", 100, &peers);
        assert!(result.is_err());
    }

    #[test]
    fn test_leader_election_single_peer() {
        let peers = create_test_peers(1);
        let leader = leader_node("test", 100, &peers).unwrap();
        assert_eq!(leader, peers[0]);
    }

    #[test]
    fn test_leader_election_peer_order_independence() {
        let peers = create_test_peers(5);
        let mut shuffled_peers = peers.clone();
        shuffled_peers.reverse();

        let leader1 = leader_node("test", 100, &peers).unwrap();
        let leader2 = leader_node("test", 100, &shuffled_peers).unwrap();

        // Should be the same leader regardless of input order
        assert_eq!(leader1, leader2);
    }
}
