//! Blame Manager Module
//!
//! Implements fault detection and attribution following THORChain's pattern.
//! Tracks node failures during consensus/signing operations and provides
//! verifiable blame data for slashing or reputation systems.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::types::SerializablePeerId;

/// Reasons for blaming a node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailReason {
    /// Hash verification failed
    HashCheckFail,
    /// Node timed out during operation
    TssTimeout,
    /// Nodes failed to sync before keygen/keysign
    TssSyncFail,
    /// TSS share verification failed (wrong share provided)
    TssBrokenMsg,
    /// Internal error prevented joining the party
    InternalError,
    /// Node sent conflicting messages
    ConflictingMessages,
    /// Node was offline when expected to be online
    NodeOffline,
    /// Consensus result mismatch
    ConsensusMismatch,
}

impl std::fmt::Display for FailReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailReason::HashCheckFail => write!(f, "hash check failed"),
            FailReason::TssTimeout => write!(f, "TSS timeout"),
            FailReason::TssSyncFail => write!(f, "signers failed to sync before keygen/keysign"),
            FailReason::TssBrokenMsg => write!(f, "TSS share verification failed"),
            FailReason::InternalError => write!(f, "failed to start join party"),
            FailReason::ConflictingMessages => write!(f, "sent conflicting messages"),
            FailReason::NodeOffline => write!(f, "node was offline"),
            FailReason::ConsensusMismatch => write!(f, "consensus result mismatch"),
        }
    }
}

/// Information about a blamed node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameNode {
    /// The peer ID of the blamed node
    pub peer_id: SerializablePeerId,
    /// Additional data proving the fault (e.g., conflicting message hashes)
    pub blame_data: Vec<u8>,
    /// Optional signature over the blame data for verification
    pub signature: Option<Vec<u8>>,
}

/// A blame record for a failed operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blame {
    /// The reason for the failure
    pub fail_reason: FailReason,
    /// Whether this was a unicast (point-to-point) or broadcast failure
    pub is_unicast: bool,
    /// The round in which the failure occurred
    pub round: u64,
    /// List of nodes responsible for the failure
    pub blame_nodes: Vec<BlameNode>,
    /// Timestamp when the blame was recorded
    pub timestamp: u64,
}

impl Blame {
    /// Create a new blame record
    pub fn new(fail_reason: FailReason, round: u64) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            fail_reason,
            is_unicast: false,
            round,
            blame_nodes: Vec::new(),
            timestamp,
        }
    }

    /// Add a blamed node
    pub fn add_node(&mut self, peer_id: SerializablePeerId, blame_data: Vec<u8>) {
        self.blame_nodes.push(BlameNode {
            peer_id,
            blame_data,
            signature: None,
        });
    }

    /// Set whether this was a unicast failure
    pub fn set_unicast(&mut self, is_unicast: bool) {
        self.is_unicast = is_unicast;
    }
}

/// Information about a round for tracking purposes
#[derive(Debug, Clone)]
struct RoundInfo {
    /// Messages received in this round, keyed by peer ID
    messages: HashMap<SerializablePeerId, Vec<u8>>,
    /// Expected participants
    expected_peers: HashSet<SerializablePeerId>,
    /// Peers that actually participated
    actual_peers: HashSet<SerializablePeerId>,
    /// Start time of the round
    start_time: std::time::Instant,
}

impl RoundInfo {
    fn new() -> Self {
        Self {
            messages: HashMap::new(),
            expected_peers: HashSet::new(),
            actual_peers: HashSet::new(),
            start_time: std::time::Instant::now(),
        }
    }
}

/// Blame Manager tracks failures and identifies responsible nodes
#[derive(Clone)]
pub struct BlameManager {
    /// Messages by round for tracking
    round_messages: Arc<RwLock<HashMap<u64, RoundInfo>>>,
    /// Last unicast peer for timeout attribution
    last_unicast_peer: Arc<RwLock<Option<(SerializablePeerId, u64)>>>,
    /// Recorded blames
    blames: Arc<RwLock<Vec<Blame>>>,
    /// Node blame counts (for reputation tracking)
    blame_counts: Arc<RwLock<HashMap<SerializablePeerId, usize>>>,
}

impl Default for BlameManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BlameManager {
    /// Create a new BlameManager
    pub fn new() -> Self {
        Self {
            round_messages: Arc::new(RwLock::new(HashMap::new())),
            last_unicast_peer: Arc::new(RwLock::new(None)),
            blames: Arc::new(RwLock::new(Vec::new())),
            blame_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set expected peers for a round
    pub async fn set_expected_peers(&self, round: u64, peers: &[SerializablePeerId]) {
        let mut rounds = self.round_messages.write().await;
        let info = rounds.entry(round).or_insert_with(RoundInfo::new);
        info.expected_peers = peers.iter().cloned().collect();
        debug!(
            "📋 [BLAME] Set {} expected peers for round {}",
            peers.len(),
            round
        );
    }

    /// Record a message from a peer for a round
    pub async fn record_message(
        &self,
        round: u64,
        peer_id: SerializablePeerId,
        message_hash: Vec<u8>,
    ) {
        let mut rounds = self.round_messages.write().await;
        let info = rounds.entry(round).or_insert_with(RoundInfo::new);
        info.messages.insert(peer_id.clone(), message_hash);
        info.actual_peers.insert(peer_id.clone());
        debug!(
            "📝 [BLAME] Recorded message from {} for round {}",
            peer_id.0, round
        );
    }

    /// Set the last peer we sent a unicast message to
    pub async fn set_last_unicast_peer(&self, peer_id: SerializablePeerId, round: u64) {
        let mut last = self.last_unicast_peer.write().await;
        *last = Some((peer_id, round));
    }

    /// Check if a message has already been received (for deduplication)
    pub async fn check_message_duplication(
        &self,
        round: u64,
        peer_id: &SerializablePeerId,
    ) -> bool {
        let rounds = self.round_messages.read().await;
        if let Some(info) = rounds.get(&round) {
            info.messages.contains_key(peer_id)
        } else {
            false
        }
    }

    /// Identify nodes that failed to sync before a ceremony
    pub async fn node_sync_blame(
        &self,
        round: u64,
        expected_peers: &[SerializablePeerId],
        online_peers: &[SerializablePeerId],
    ) -> Blame {
        let online_set: HashSet<_> = online_peers.iter().collect();

        let mut blame = Blame::new(FailReason::TssSyncFail, round);

        for peer in expected_peers {
            if !online_set.contains(peer) {
                blame.add_node(peer.clone(), vec![]);
                info!("🚫 [BLAME] Node {} failed to sync for round {}", peer.0, round);
            }
        }

        // Update blame counts
        self.update_blame_counts(&blame).await;

        blame
    }

    /// Identify nodes causing timeout during unicast operations
    pub async fn get_unicast_timeout_blame(&self, round: u64) -> Blame {
        let mut blame = Blame::new(FailReason::TssTimeout, round);
        blame.set_unicast(true);

        let last = self.last_unicast_peer.read().await;
        if let Some((peer_id, last_round)) = last.as_ref() {
            if *last_round == round {
                blame.add_node(peer_id.clone(), vec![]);
                warn!(
                    "⏰ [BLAME] Node {} caused unicast timeout in round {}",
                    peer_id.0, round
                );
            }
        }

        self.update_blame_counts(&blame).await;
        blame
    }

    /// Identify nodes causing timeout during broadcast operations
    pub async fn get_broadcast_timeout_blame(&self, round: u64) -> Blame {
        let mut blame = Blame::new(FailReason::TssTimeout, round);

        let rounds = self.round_messages.read().await;
        if let Some(info) = rounds.get(&round) {
            for peer in &info.expected_peers {
                if !info.actual_peers.contains(peer) {
                    blame.add_node(peer.clone(), vec![]);
                    warn!(
                        "⏰ [BLAME] Node {} caused broadcast timeout in round {}",
                        peer.0, round
                    );
                }
            }
        }

        self.update_blame_counts(&blame).await;
        blame
    }

    /// Blame nodes that provided inconsistent consensus results
    pub async fn consensus_mismatch_blame(
        &self,
        round: u64,
        expected_node: &SerializablePeerId,
        received_node: &SerializablePeerId,
        sender: &SerializablePeerId,
    ) -> Blame {
        let mut blame = Blame::new(FailReason::ConsensusMismatch, round);

        // The sender provided a mismatching consensus result
        let blame_data = format!(
            "expected:{},received:{}",
            expected_node.0, received_node.0
        )
        .into_bytes();

        blame.add_node(sender.clone(), blame_data);

        warn!(
            "🚫 [BLAME] Node {} sent mismatching consensus result for round {}: expected {}, got {}",
            sender.0, round, expected_node.0, received_node.0
        );

        self.update_blame_counts(&blame).await;
        blame
    }

    /// Update blame counts for a blame record
    async fn update_blame_counts(&self, blame: &Blame) {
        let mut counts = self.blame_counts.write().await;
        for node in &blame.blame_nodes {
            *counts.entry(node.peer_id.clone()).or_insert(0) += 1;
        }
    }

    /// Record a blame
    pub async fn record_blame(&self, blame: Blame) {
        info!(
            "📊 [BLAME] Recording blame for round {}: {} - {} nodes blamed",
            blame.round,
            blame.fail_reason,
            blame.blame_nodes.len()
        );

        // Update blame counts before recording
        self.update_blame_counts(&blame).await;

        let mut blames = self.blames.write().await;
        blames.push(blame);
    }

    /// Get all blames for a specific round
    pub async fn get_blames_for_round(&self, round: u64) -> Vec<Blame> {
        let blames = self.blames.read().await;
        blames.iter().filter(|b| b.round == round).cloned().collect()
    }

    /// Get the blame count for a specific node
    pub async fn get_blame_count(&self, peer_id: &SerializablePeerId) -> usize {
        let counts = self.blame_counts.read().await;
        counts.get(peer_id).copied().unwrap_or(0)
    }

    /// Get all nodes with blame counts above a threshold
    pub async fn get_frequently_blamed_nodes(&self, min_count: usize) -> Vec<(SerializablePeerId, usize)> {
        let counts = self.blame_counts.read().await;
        counts
            .iter()
            .filter(|(_, count)| **count >= min_count)
            .map(|(peer, count)| (peer.clone(), *count))
            .collect()
    }

    /// Clean up old round data
    pub async fn cleanup_old_rounds(&self, keep_rounds: usize) {
        let mut rounds = self.round_messages.write().await;
        if rounds.len() <= keep_rounds {
            return;
        }

        let mut round_nums: Vec<u64> = rounds.keys().copied().collect();
        round_nums.sort();

        let to_remove = round_nums.len() - keep_rounds;
        for round in round_nums.into_iter().take(to_remove) {
            rounds.remove(&round);
            debug!("🧹 [BLAME] Cleaned up round data for round {}", round);
        }
    }

    /// Get statistics about blame records
    pub async fn get_statistics(&self) -> BlameStatistics {
        let blames = self.blames.read().await;
        let counts = self.blame_counts.read().await;

        let mut reason_counts: HashMap<String, usize> = HashMap::new();
        for blame in blames.iter() {
            *reason_counts
                .entry(blame.fail_reason.to_string())
                .or_insert(0) += 1;
        }

        BlameStatistics {
            total_blames: blames.len(),
            unique_blamed_nodes: counts.len(),
            reason_counts,
            most_blamed_node: counts
                .iter()
                .max_by_key(|(_, count)| *count)
                .map(|(peer, count)| (peer.clone(), *count)),
        }
    }
}

/// Statistics about blame records
#[derive(Debug, Clone)]
pub struct BlameStatistics {
    pub total_blames: usize,
    pub unique_blamed_nodes: usize,
    pub reason_counts: HashMap<String, usize>,
    pub most_blamed_node: Option<(SerializablePeerId, usize)>,
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

    #[tokio::test]
    async fn test_blame_creation() {
        let blame = Blame::new(FailReason::TssTimeout, 1);
        assert_eq!(blame.fail_reason, FailReason::TssTimeout);
        assert_eq!(blame.round, 1);
        assert!(blame.blame_nodes.is_empty());
    }

    #[tokio::test]
    async fn test_node_sync_blame() {
        let manager = BlameManager::new();
        let all_peers = create_test_peers(5);
        let online_peers = vec![all_peers[0].clone(), all_peers[1].clone()];

        let blame = manager.node_sync_blame(1, &all_peers, &online_peers).await;

        assert_eq!(blame.fail_reason, FailReason::TssSyncFail);
        assert_eq!(blame.blame_nodes.len(), 3); // 3 nodes failed to sync
    }

    #[tokio::test]
    async fn test_blame_count_tracking() {
        let manager = BlameManager::new();
        let peers = create_test_peers(2);

        // Create a blame with one node
        let mut blame = Blame::new(FailReason::TssTimeout, 1);
        blame.add_node(peers[0].clone(), vec![]);
        manager.record_blame(blame).await;

        // Create another blame with the same node
        let mut blame2 = Blame::new(FailReason::TssSyncFail, 2);
        blame2.add_node(peers[0].clone(), vec![]);
        manager.update_blame_counts(&blame2).await;

        let count = manager.get_blame_count(&peers[0]).await;
        assert_eq!(count, 2);

        let count2 = manager.get_blame_count(&peers[1]).await;
        assert_eq!(count2, 0);
    }

    #[tokio::test]
    async fn test_message_deduplication() {
        let manager = BlameManager::new();
        let peer = create_test_peers(1)[0].clone();

        // First message should not be a duplicate
        assert!(!manager.check_message_duplication(1, &peer).await);

        // Record the message
        manager
            .record_message(1, peer.clone(), vec![1, 2, 3])
            .await;

        // Now it should be detected as a duplicate
        assert!(manager.check_message_duplication(1, &peer).await);
    }

    #[tokio::test]
    async fn test_cleanup_old_rounds() {
        let manager = BlameManager::new();
        let peer = create_test_peers(1)[0].clone();

        // Add messages for 10 rounds
        for i in 1..=10 {
            manager.record_message(i, peer.clone(), vec![i as u8]).await;
        }

        // Cleanup, keeping only 5 rounds
        manager.cleanup_old_rounds(5).await;

        let rounds = manager.round_messages.read().await;
        assert_eq!(rounds.len(), 5);

        // Should have kept the most recent rounds
        assert!(rounds.contains_key(&6));
        assert!(rounds.contains_key(&10));
        assert!(!rounds.contains_key(&1));
    }
}
