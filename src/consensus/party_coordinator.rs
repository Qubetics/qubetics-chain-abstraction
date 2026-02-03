//! Party Coordinator Module
//!
//! Implements leader-based party coordination following THORChain's pattern.
//! Ensures all nodes have a consistent view of the participant set before
//! starting consensus or signing operations.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::network::transport::types::TOPIC_PARTY_COORDINATION;
use crate::types::{ChannelMessage, GossipsubMessage, SerializablePeerId};

use super::leader::leader_node;

/// Default timeout for party formation
pub const DEFAULT_PARTY_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval for sending join requests as a member
pub const JOIN_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// Message types for party coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PartyCoordinationMessage {
    /// Member sends join request to leader
    JoinRequest {
        round: u64,
        peer_id: SerializablePeerId,
        timestamp: u64,
    },
    /// Leader broadcasts the canonical party composition
    PartyComposition {
        round: u64,
        leader: SerializablePeerId,
        members: Vec<SerializablePeerId>,
        timestamp: u64,
    },
    /// Acknowledgment that member received the party composition
    JoinAck {
        round: u64,
        peer_id: SerializablePeerId,
    },
}

/// Status of a peer in the party formation process
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// Peer has sent a join request
    Requested,
    /// Peer has been confirmed as part of the party
    Confirmed,
    /// Peer timed out or failed to respond
    TimedOut,
}

/// Tracks the state of a party formation for a specific round
#[derive(Debug)]
struct PartyGroup {
    /// The elected leader for this party
    leader: SerializablePeerId,
    /// Members who have joined or been confirmed
    members: HashMap<SerializablePeerId, PeerStatus>,
    /// Notification channel for when party is ready
    notify: Arc<Notify>,
    /// Required threshold for party formation
    threshold: usize,
    /// When this party group was created
    created_at: Instant,
    /// Final canonical member list (set by leader)
    canonical_members: Option<Vec<SerializablePeerId>>,
}

impl PartyGroup {
    fn new(leader: SerializablePeerId, threshold: usize) -> Self {
        Self {
            leader,
            members: HashMap::new(),
            notify: Arc::new(Notify::new()),
            threshold,
            created_at: Instant::now(),
            canonical_members: None,
        }
    }

    fn add_member(&mut self, peer_id: SerializablePeerId, status: PeerStatus) {
        self.members.insert(peer_id, status);
    }

    fn confirmed_count(&self) -> usize {
        self.members
            .values()
            .filter(|s| **s == PeerStatus::Confirmed || **s == PeerStatus::Requested)
            .count()
    }

    fn is_ready(&self) -> bool {
        self.confirmed_count() >= self.threshold
    }

    fn set_canonical_members(&mut self, members: Vec<SerializablePeerId>) {
        self.canonical_members = Some(members);
    }
}

/// Party Coordinator handles the coordination of nodes for consensus/signing
#[derive(Clone)]
pub struct PartyCoordinator {
    /// This node's peer ID
    node_id: PeerId,
    /// Timeout for party formation
    timeout: Duration,
    /// Active party groups by round
    party_groups: Arc<RwLock<HashMap<u64, PartyGroup>>>,
    /// Channel for sending messages
    message_tx: mpsc::Sender<ChannelMessage>,
    /// Lock for coordinating party operations
    coordination_lock: Arc<Mutex<()>>,
}

impl PartyCoordinator {
    /// Create a new PartyCoordinator
    pub fn new(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self::with_timeout(node_id, message_tx, DEFAULT_PARTY_TIMEOUT)
    }

    /// Create a new PartyCoordinator with custom timeout
    pub fn with_timeout(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        timeout: Duration,
    ) -> Self {
        Self {
            node_id,
            timeout,
            party_groups: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            coordination_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Join a party with leader-based coordination
    ///
    /// This is the main entry point for party coordination.
    /// All nodes call this method, and internally it determines whether
    /// this node is the leader or a member.
    pub async fn join_party_with_leader(
        &self,
        round: u64,
        block_height: u64,
        peers: &[SerializablePeerId],
        threshold: usize,
        operation_type: &str,
    ) -> Result<Vec<SerializablePeerId>> {
        // Acquire coordination lock to prevent race conditions
        let _lock = self.coordination_lock.lock().await;

        if peers.is_empty() {
            return Err(anyhow!("No peers available for party coordination"));
        }

        if threshold > peers.len() {
            return Err(anyhow!(
                "Threshold {} exceeds available peers {}",
                threshold,
                peers.len()
            ));
        }

        // Determine leader deterministically
        let message_id = format!("party_{}_{}", operation_type, round);
        let leader = leader_node(&message_id, block_height, peers)?;
        let own_peer_id = SerializablePeerId(self.node_id);

        info!(
            "🎭 [PARTY] Round {}: Leader is {} (this node: {})",
            round,
            leader.0,
            if leader == own_peer_id { "YES" } else { "NO" }
        );

        // Initialize party group
        {
            let mut groups = self.party_groups.write().await;
            if !groups.contains_key(&round) {
                let mut group = PartyGroup::new(leader.clone(), threshold);
                // Add ourselves as a member
                group.add_member(own_peer_id.clone(), PeerStatus::Confirmed);
                groups.insert(round, group);
            }
        }

        if leader == own_peer_id {
            self.join_party_as_leader(round, peers, threshold).await
        } else {
            self.join_party_as_member(round, &leader, threshold).await
        }
    }

    /// Leader flow: collect join requests and broadcast canonical member list
    async fn join_party_as_leader(
        &self,
        round: u64,
        peers: &[SerializablePeerId],
        threshold: usize,
    ) -> Result<Vec<SerializablePeerId>> {
        info!(
            "👑 [LEADER] Starting party formation for round {} (threshold: {}, peers: {})",
            round,
            threshold,
            peers.len()
        );

        let deadline = Instant::now() + self.timeout;
        let _own_peer_id = SerializablePeerId(self.node_id);

        // Get the notify handle
        let notify = {
            let groups = self.party_groups.read().await;
            groups
                .get(&round)
                .map(|g| g.notify.clone())
                .ok_or_else(|| anyhow!("Party group not found for round {}", round))?
        };

        // Wait for join requests with timeout
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                info!("👑 [LEADER] Timeout reached for round {}", round);
                break;
            }

            // Check if we have enough members
            {
                let groups = self.party_groups.read().await;
                if let Some(group) = groups.get(&round) {
                    if group.is_ready() {
                        info!(
                            "👑 [LEADER] Threshold reached for round {} ({}/{})",
                            round,
                            group.confirmed_count(),
                            threshold
                        );
                        break;
                    }
                }
            }

            // Wait for notifications or timeout
            tokio::select! {
                _ = notify.notified() => {
                    debug!("👑 [LEADER] Received notification for round {}", round);
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Small sleep to prevent busy-waiting
                }
            }
        }

        // Get final member list
        let members: Vec<SerializablePeerId> = {
            let groups = self.party_groups.read().await;
            groups
                .get(&round)
                .map(|g| {
                    g.members
                        .iter()
                        .filter(|(_, status)| {
                            **status == PeerStatus::Confirmed || **status == PeerStatus::Requested
                        })
                        .map(|(peer, _)| peer.clone())
                        .collect()
                })
                .unwrap_or_default()
        };

        if members.len() < threshold {
            // If we don't have enough confirmed members, use all available peers
            // This is a fallback for the case where join requests were lost
            warn!(
                "👑 [LEADER] Not enough confirmed members ({}/{}), using all available peers as fallback",
                members.len(),
                threshold
            );

            // Use the original peer list (which includes all available nodes)
            let fallback_members: Vec<SerializablePeerId> =
                peers.iter().take(threshold).cloned().collect();

            // Broadcast canonical member list
            self.broadcast_party_composition(round, &fallback_members)
                .await?;

            // Store canonical members
            {
                let mut groups = self.party_groups.write().await;
                if let Some(group) = groups.get_mut(&round) {
                    group.set_canonical_members(fallback_members.clone());
                }
            }

            return Ok(fallback_members);
        }

        // Broadcast canonical member list to all participants
        self.broadcast_party_composition(round, &members).await?;

        // Store canonical members
        {
            let mut groups = self.party_groups.write().await;
            if let Some(group) = groups.get_mut(&round) {
                group.set_canonical_members(members.clone());
            }
        }

        info!(
            "👑 [LEADER] Party formed for round {} with {} members: {:?}",
            round,
            members.len(),
            members.iter().map(|p| p.0.to_string()).collect::<Vec<_>>()
        );

        Ok(members)
    }

    /// Member flow: send join request to leader and wait for party composition
    async fn join_party_as_member(
        &self,
        round: u64,
        leader: &SerializablePeerId,
        _threshold: usize,
    ) -> Result<Vec<SerializablePeerId>> {
        info!(
            "📤 [MEMBER] Sending join request to leader {} for round {}",
            leader.0, round
        );

        let deadline = Instant::now() + self.timeout;
        let _own_peer_id = SerializablePeerId(self.node_id);

        // Get the notify handle
        let notify = {
            let groups = self.party_groups.read().await;
            groups
                .get(&round)
                .map(|g| g.notify.clone())
                .ok_or_else(|| anyhow!("Party group not found for round {}", round))?
        };

        // Send join requests periodically until we get a response
        let mut last_request_time = Instant::now() - JOIN_REQUEST_INTERVAL;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(
                    "📤 [MEMBER] Timeout waiting for party composition for round {}",
                    round
                );
                break;
            }

            // Check if we have received canonical members from leader
            {
                let groups = self.party_groups.read().await;
                if let Some(group) = groups.get(&round) {
                    if let Some(ref members) = group.canonical_members {
                        info!(
                            "📥 [MEMBER] Received canonical member list for round {}: {} members",
                            round,
                            members.len()
                        );
                        return Ok(members.clone());
                    }
                }
            }

            // Send join request periodically
            if last_request_time.elapsed() >= JOIN_REQUEST_INTERVAL {
                self.send_join_request(round, leader).await?;
                last_request_time = Instant::now();
            }

            // Wait for notification or small timeout
            tokio::select! {
                _ = notify.notified() => {
                    debug!("📤 [MEMBER] Received notification for round {}", round);
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Small sleep to prevent busy-waiting
                }
            }
        }

        // Timeout occurred - check if we have any members at all
        let groups = self.party_groups.read().await;
        if let Some(group) = groups.get(&round) {
            if let Some(ref members) = group.canonical_members {
                return Ok(members.clone());
            }
        }

        Err(anyhow!(
            "Timeout waiting for party composition for round {}",
            round
        ))
    }

    /// Send a join request to the leader
    async fn send_join_request(&self, round: u64, leader: &SerializablePeerId) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let message = PartyCoordinationMessage::JoinRequest {
            round,
            peer_id: SerializablePeerId(self.node_id),
            timestamp,
        };

        let gossip_msg = GossipsubMessage::PartyCoordination(message);
        let data = serde_json::to_vec(&gossip_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: TOPIC_PARTY_COORDINATION.to_string(),
                data,
            })
            .await
            .map_err(|e| anyhow!("Failed to send join request: {}", e))?;

        debug!(
            "📤 [MEMBER] Sent join request for round {} to leader {}",
            round, leader.0
        );

        Ok(())
    }

    /// Broadcast the canonical party composition to all members
    async fn broadcast_party_composition(
        &self,
        round: u64,
        members: &[SerializablePeerId],
    ) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let message = PartyCoordinationMessage::PartyComposition {
            round,
            leader: SerializablePeerId(self.node_id),
            members: members.to_vec(),
            timestamp,
        };

        let gossip_msg = GossipsubMessage::PartyCoordination(message);
        let data = serde_json::to_vec(&gossip_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: TOPIC_PARTY_COORDINATION.to_string(),
                data,
            })
            .await
            .map_err(|e| anyhow!("Failed to broadcast party composition: {}", e))?;

        info!(
            "👑 [LEADER] Broadcasted party composition for round {} with {} members",
            round,
            members.len()
        );

        Ok(())
    }

    /// Handle incoming party coordination messages
    pub async fn handle_message(
        &self,
        message: PartyCoordinationMessage,
        sender: PeerId,
    ) -> Result<()> {
        match message {
            PartyCoordinationMessage::JoinRequest {
                round,
                peer_id,
                timestamp,
            } => {
                self.handle_join_request(round, peer_id, sender, timestamp)
                    .await
            }
            PartyCoordinationMessage::PartyComposition {
                round,
                leader,
                members,
                timestamp,
            } => {
                self.handle_party_composition(round, leader, members, sender, timestamp)
                    .await
            }
            PartyCoordinationMessage::JoinAck { round, peer_id } => {
                self.handle_join_ack(round, peer_id, sender).await
            }
        }
    }

    /// Handle a join request (leader only)
    async fn handle_join_request(
        &self,
        round: u64,
        peer_id: SerializablePeerId,
        sender: PeerId,
        _timestamp: u64,
    ) -> Result<()> {
        // Verify the peer_id matches the sender
        if peer_id.0 != sender {
            warn!(
                "🚫 [LEADER] Join request peer_id mismatch: claimed {}, actual {}",
                peer_id.0, sender
            );
            return Err(anyhow!("Join request peer_id mismatch"));
        }

        let mut groups = self.party_groups.write().await;

        if let Some(group) = groups.get_mut(&round) {
            // Only process if we are the leader
            if group.leader.0 != self.node_id {
                debug!(
                    "📥 [PARTY] Ignoring join request for round {} - not leader",
                    round
                );
                return Ok(());
            }

            // Add the peer as requested
            group.add_member(peer_id.clone(), PeerStatus::Requested);

            info!(
                "👑 [LEADER] Received join request from {} for round {} ({}/{})",
                peer_id.0,
                round,
                group.confirmed_count(),
                group.threshold
            );

            // Notify that we have a new member
            group.notify.notify_one();
        } else {
            debug!(
                "📥 [PARTY] No party group for round {} - creating one",
                round
            );
            // Create a new group if it doesn't exist
            // This can happen if join requests arrive before we've initialized
            let mut group = PartyGroup::new(SerializablePeerId(self.node_id), 1);
            group.add_member(peer_id.clone(), PeerStatus::Requested);
            groups.insert(round, group);
        }

        Ok(())
    }

    /// Handle a party composition message (members only)
    async fn handle_party_composition(
        &self,
        round: u64,
        leader: SerializablePeerId,
        members: Vec<SerializablePeerId>,
        sender: PeerId,
        _timestamp: u64,
    ) -> Result<()> {
        // Verify the leader matches the sender
        if leader.0 != sender {
            warn!(
                "🚫 [MEMBER] Party composition leader mismatch: claimed {}, actual {}",
                leader.0, sender
            );
            return Err(anyhow!("Party composition leader mismatch"));
        }

        let mut groups = self.party_groups.write().await;

        if let Some(group) = groups.get_mut(&round) {
            // Verify this is from the expected leader
            if group.leader != leader {
                warn!(
                    "🚫 [MEMBER] Party composition from wrong leader: expected {}, got {}",
                    group.leader.0, leader.0
                );
                return Err(anyhow!("Party composition from wrong leader"));
            }

            // Store canonical members
            group.set_canonical_members(members.clone());

            // Update member statuses
            for member in &members {
                group.add_member(member.clone(), PeerStatus::Confirmed);
            }

            info!(
                "📥 [MEMBER] Received party composition for round {} from leader {}: {} members",
                round,
                leader.0,
                members.len()
            );

            // Notify waiting tasks
            group.notify.notify_waiters();
        } else {
            // Create a new group with the received composition
            let mut group = PartyGroup::new(leader.clone(), members.len());
            for member in &members {
                group.add_member(member.clone(), PeerStatus::Confirmed);
            }
            group.set_canonical_members(members.clone());
            let notify = group.notify.clone();
            groups.insert(round, group);
            notify.notify_waiters();
        }

        // Send acknowledgment
        drop(groups); // Release lock before sending
        self.send_join_ack(round).await?;

        Ok(())
    }

    /// Handle a join acknowledgment
    async fn handle_join_ack(
        &self,
        round: u64,
        peer_id: SerializablePeerId,
        sender: PeerId,
    ) -> Result<()> {
        // Verify peer_id matches sender
        if peer_id.0 != sender {
            warn!(
                "🚫 [LEADER] Join ack peer_id mismatch: claimed {}, actual {}",
                peer_id.0, sender
            );
            return Ok(()); // Don't error, just ignore
        }

        let mut groups = self.party_groups.write().await;

        if let Some(group) = groups.get_mut(&round) {
            // Update status to confirmed
            group.add_member(peer_id.clone(), PeerStatus::Confirmed);

            debug!(
                "👑 [LEADER] Received join ack from {} for round {}",
                peer_id.0, round
            );
        }

        Ok(())
    }

    /// Send a join acknowledgment
    async fn send_join_ack(&self, round: u64) -> Result<()> {
        let message = PartyCoordinationMessage::JoinAck {
            round,
            peer_id: SerializablePeerId(self.node_id),
        };

        let gossip_msg = GossipsubMessage::PartyCoordination(message);
        let data = serde_json::to_vec(&gossip_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: TOPIC_PARTY_COORDINATION.to_string(),
                data,
            })
            .await
            .map_err(|e| anyhow!("Failed to send join ack: {}", e))?;

        Ok(())
    }

    /// Get the canonical members for a round (if available)
    pub async fn get_canonical_members(&self, round: u64) -> Option<Vec<SerializablePeerId>> {
        let groups = self.party_groups.read().await;
        groups
            .get(&round)
            .and_then(|g| g.canonical_members.clone())
    }

    /// Check if party formation is complete for a round
    pub async fn is_party_ready(&self, round: u64) -> bool {
        let groups = self.party_groups.read().await;
        groups
            .get(&round)
            .map(|g| g.canonical_members.is_some())
            .unwrap_or(false)
    }

    /// Clean up old party groups
    pub async fn cleanup_old_rounds(&self, keep_rounds: usize) {
        let mut groups = self.party_groups.write().await;
        if groups.len() <= keep_rounds {
            return;
        }

        let mut rounds: Vec<u64> = groups.keys().copied().collect();
        rounds.sort();

        let to_remove = rounds.len() - keep_rounds;
        for round in rounds.into_iter().take(to_remove) {
            groups.remove(&round);
            debug!("🧹 [PARTY] Cleaned up party group for round {}", round);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use tokio::sync::mpsc;

    fn create_test_coordinator() -> (PartyCoordinator, mpsc::Receiver<ChannelMessage>) {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let (tx, rx) = mpsc::channel(100);
        let coordinator = PartyCoordinator::with_timeout(node_id, tx, Duration::from_millis(100));
        (coordinator, rx)
    }

    fn create_test_peers(count: usize) -> Vec<SerializablePeerId> {
        (0..count)
            .map(|_| SerializablePeerId(PeerId::from(Keypair::generate_ed25519().public())))
            .collect()
    }

    #[tokio::test]
    async fn test_party_coordinator_creation() {
        let (coordinator, _rx) = create_test_coordinator();
        assert!(!coordinator.is_party_ready(1).await);
    }

    #[tokio::test]
    async fn test_cleanup_old_rounds() {
        let (coordinator, _rx) = create_test_coordinator();

        // Add some party groups
        {
            let mut groups = coordinator.party_groups.write().await;
            for i in 1..=10 {
                groups.insert(i, PartyGroup::new(create_test_peers(1)[0].clone(), 1));
            }
        }

        // Cleanup, keeping only 5 rounds
        coordinator.cleanup_old_rounds(5).await;

        let groups = coordinator.party_groups.read().await;
        assert_eq!(groups.len(), 5);

        // Should have kept the most recent rounds
        assert!(groups.contains_key(&6));
        assert!(groups.contains_key(&10));
        assert!(!groups.contains_key(&1));
        assert!(!groups.contains_key(&5));
    }
}
