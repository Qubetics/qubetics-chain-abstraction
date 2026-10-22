use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::Instant;

/// Database sync state for tracking synchronization progress
#[derive(Debug, Clone)]
pub struct DatabaseSyncState {
    pub in_progress: bool,
    pub source_peer: Option<PeerId>,
    pub total_entries: usize,
    pub batch_size: usize,
    pub current_batch: usize,
    pub total_batches: usize,
    pub entries_synced: usize,
}

impl Default for DatabaseSyncState {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseSyncState {
    pub fn new() -> Self {
        Self {
            in_progress: false,
            source_peer: None,
            total_entries: 0,
            batch_size: 0,
            current_batch: 0,
            total_batches: 0,
            entries_synced: 0,
        }
    }

    pub fn start_sync(&mut self, peer: PeerId, total_entries: usize, batch_size: usize) {
        self.in_progress = true;
        self.source_peer = Some(peer);
        self.total_entries = total_entries;
        self.batch_size = batch_size;
        self.current_batch = 0;
        self.total_batches = total_entries.div_ceil(batch_size);
        self.entries_synced = 0;
    }

    pub fn complete_batch(&mut self, entries_count: usize) {
        self.current_batch += 1;
        self.entries_synced += entries_count;
    }

    pub fn finish_sync(&mut self) {
        self.in_progress = false;
        self.source_peer = None;
    }

    pub fn progress_percentage(&self) -> f32 {
        if self.total_entries == 0 {
            return 100.0;
        }
        (self.entries_synced as f32 / self.total_entries as f32) * 100.0
    }
}

/// State sync state for new nodes (users, intents, pending tx, rounds, peer invalidation; no private data).
#[derive(Debug, Clone, Default)]
pub struct StateSyncState {
    pub in_progress: bool,
    pub source_peer: Option<PeerId>,
    /// (prefix, count) from StateSyncMetadata
    pub prefix_counts: Vec<(String, usize)>,
    pub current_prefix_index: usize,
    pub current_batch_index: usize,
    pub batch_size: usize,
    pub withdraw_rounds: Vec<u64>,
    pub claim_reward_rounds: Vec<u64>,
    /// (round_string, solver_ids) for peer invalidation; applied when sync completes.
    pub peer_invalidation_pending: Vec<(String, Vec<String>)>,
    pub entries_synced: usize,
}

impl StateSyncState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start_sync(
        &mut self,
        peer: PeerId,
        prefix_counts: Vec<(String, usize)>,
        batch_size: usize,
        withdraw_rounds: Vec<u64>,
        claim_reward_rounds: Vec<u64>,
        peer_invalidation_pending: Vec<(String, Vec<String>)>,
    ) {
        self.in_progress = true;
        self.source_peer = Some(peer);
        self.prefix_counts = prefix_counts;
        self.current_prefix_index = 0;
        self.current_batch_index = 0;
        self.batch_size = batch_size;
        self.withdraw_rounds = withdraw_rounds;
        self.claim_reward_rounds = claim_reward_rounds;
        self.peer_invalidation_pending = peer_invalidation_pending;
        self.entries_synced = 0;
    }

    pub fn complete_batch(&mut self, entries_count: usize) {
        self.current_batch_index += 1;
        self.entries_synced += entries_count;
    }

    pub fn next_prefix(&mut self) {
        self.current_prefix_index += 1;
        self.current_batch_index = 0;
    }

    pub fn current_prefix(&self) -> Option<&(String, usize)> {
        self.prefix_counts.get(self.current_prefix_index)
    }

    pub fn total_batches_for_current_prefix(&self) -> usize {
        self.current_prefix()
            .map(|(_, count)| count.div_ceil(self.batch_size))
            .unwrap_or(0)
    }

    pub fn finish_sync(&mut self) {
        self.in_progress = false;
        self.source_peer = None;
    }
}

/// Peer discovery subsystem state for MPC networking
#[derive(Debug, Default)]
pub struct PeerDiscoveryState {
    pub peer_indices: HashMap<PeerId, usize>,
    pub pending_peer_discovery_retry: bool,
    pub processed_disconnects: HashMap<PeerId, Instant>,
    pub peer_multiaddresses: HashMap<PeerId, Multiaddr>,
    /// Track if we've already processed a PeerList response to prevent duplicate new node joining checks
    pub peer_list_processed: bool,
}

impl PeerDiscoveryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_retry_pending(&mut self) {
        self.pending_peer_discovery_retry = true;
    }

    pub fn clear_retry(&mut self) {
        self.pending_peer_discovery_retry = false;
    }
}
