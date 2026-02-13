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

/// Peer discovery subsystem state for MPC networking
#[derive(Debug)]
pub struct PeerDiscoveryState {
    pub peer_indices: HashMap<PeerId, usize>,
    pub pending_peer_discovery_retry: bool,
    pub processed_disconnects: HashMap<PeerId, Instant>,
    pub peer_multiaddresses: HashMap<PeerId, Multiaddr>,
    /// Track if we've already processed a PeerList response to prevent duplicate new node joining checks
    pub peer_list_processed: bool,
    /// Debounce timer for polynomial refresh after node disconnections.
    /// When set, the event loop will trigger a single batched refresh once
    /// this deadline expires. Each new disconnect resets the deadline so that
    /// near-simultaneous disconnects are coalesced into one refresh, ensuring
    /// all remaining nodes agree on the same participant set.
    pub pending_refresh_deadline: Option<tokio::time::Instant>,
}

impl Default for PeerDiscoveryState {
    fn default() -> Self {
        Self {
            peer_indices: HashMap::new(),
            pending_peer_discovery_retry: false,
            processed_disconnects: HashMap::new(),
            peer_multiaddresses: HashMap::new(),
            peer_list_processed: false,
            pending_refresh_deadline: None,
        }
    }
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
