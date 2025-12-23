use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use libp2p::PeerId;
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    time::Duration,
};
use tracing::{info, warn};

use crate::{
    database::VrfStorage,
    types::{p2p::SerializablePeerId, vrf::VrfRoundSyncRequest, ChannelMessage, GossipsubMessage},
};

use super::{
    selector::VrfNodeSelector,
    types::{NodeSelectionResult, VrfSelectedNodesBroadcast, VrfSelectionMessage},
};

/// Number of nodes to select for VRF-based signing operations.
/// This constant determines how many nodes are selected for each signing round.
/// Can be adjusted for redundancy, threshold signing, security improvement, or decentralization.
pub const VRF_NODE_SELECTION_COUNT: usize = 1;

#[derive(Debug, Clone)]
pub struct VrfServiceConfig {
    pub allow_synthetic_submissions: bool,
}

impl Default for VrfServiceConfig {
    fn default() -> Self {
        Self {
            allow_synthetic_submissions: true,
        }
    }
}

/// Independent VRF Service for chain-agnostic node selection
#[derive(Clone)]
pub struct VrfService {
    selector: Arc<RwLock<VrfNodeSelector>>,
    message_tx: mpsc::Sender<ChannelMessage>,
    node_id: PeerId,
    current_round: Arc<RwLock<u64>>,
    round_update_lock: Arc<Mutex<()>>,
    vrf_storage: Option<VrfStorage>,
    context: String,
    config: VrfServiceConfig,
}

#[derive(Clone, Copy, Debug)]
pub enum VrfRoundSyncKind {
    Signing,
    MainSequencer,
    VaultSequencer,
}

impl VrfRoundSyncKind {
    fn to_message(self, request: VrfRoundSyncRequest) -> GossipsubMessage {
        match self {
            VrfRoundSyncKind::Signing => GossipsubMessage::VrfRoundSyncRequest(request),
            VrfRoundSyncKind::MainSequencer => {
                GossipsubMessage::MainSequencerVrfRoundSyncRequest(request)
            }
            VrfRoundSyncKind::VaultSequencer => {
                GossipsubMessage::VaultSequencerVrfRoundSyncRequest(request)
            }
        }
    }

    fn topic(self) -> &'static str {
        match self {
            VrfRoundSyncKind::Signing => crate::network::transport::types::TOPIC_CONSENSUS,
            VrfRoundSyncKind::MainSequencer => {
                crate::network::transport::types::TOPIC_MAIN_SEQUENCER_VRF
            }
            VrfRoundSyncKind::VaultSequencer => {
                crate::network::transport::types::TOPIC_VAULT_SEQUENCER_VRF
            }
        }
    }
}

impl VrfService {
    /// Create a new VRF service
    pub fn new(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self::with_config_and_storage(node_id, message_tx, VrfServiceConfig::default(), None, "")
    }

    pub fn new_with_context(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        context: impl Into<String>,
    ) -> Self {
        Self::with_config_and_storage(
            node_id,
            message_tx,
            VrfServiceConfig::default(),
            None,
            context,
        )
    }

    pub fn new_with_storage(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        vrf_storage: VrfStorage,
    ) -> Self {
        Self::with_config_and_storage(
            node_id,
            message_tx,
            VrfServiceConfig::default(),
            Some(vrf_storage),
            "",
        )
    }

    pub fn new_with_storage_and_context(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        vrf_storage: VrfStorage,
        context: impl Into<String>,
    ) -> Self {
        Self::with_config_and_storage(
            node_id,
            message_tx,
            VrfServiceConfig::default(),
            Some(vrf_storage),
            context,
        )
    }

    pub fn with_config(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
    ) -> Self {
        Self::with_config_and_storage(node_id, message_tx, config, None, "")
    }

    pub fn with_config_and_context(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
        context: impl Into<String>,
    ) -> Self {
        Self::with_config_and_storage(node_id, message_tx, config, None, context)
    }

    pub fn with_config_and_storage(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
        vrf_storage: Option<VrfStorage>,
        context: impl Into<String>,
    ) -> Self {
        let context = context.into();
        let selector = VrfNodeSelector::new(node_id);
        let initial_round = vrf_storage
            .as_ref()
            .and_then(|storage| storage.get_current_round_for_context(&context).ok())
            .unwrap_or(0);

        Self {
            selector: Arc::new(RwLock::new(selector)),
            message_tx,
            node_id,
            current_round: Arc::new(RwLock::new(initial_round)),
            round_update_lock: Arc::new(Mutex::new(())),
            vrf_storage,
            context,
            config,
        }
    }

    pub fn storage(&self) -> Option<VrfStorage> {
        self.vrf_storage.clone()
    }

    /// Perform VRF node selection for any chain operation
    pub async fn perform_node_selection(
        &self,
        available_nodes: &[PeerId],
        threshold: usize,
        round: u64,
        operation_type: &str,
    ) -> Result<NodeSelectionResult> {
        info!(
            "🎯 [VRF] Starting {} operation node selection for round {} with {} available nodes",
            operation_type,
            round,
            available_nodes.len()
        );

        let mut selector = self.selector.write().await;
        selector.ensure_local_submission(round);
        let selection_result = selector.select_mpc_nodes(
            available_nodes,
            threshold,
            round,
            self.config.allow_synthetic_submissions,
        )?;
        info!("🧐 Selection result: {:?}", selection_result);

        info!("⏳ Waiting 3 seconds before broadcasting selection...");
        tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

        info!(
            "🎯 [VRF] Node {} selected {} nodes for {} operation round {}: {:?}",
            self.node_id,
            selection_result.selected_nodes.len(),
            operation_type,
            round,
            selection_result.selected_nodes
        );

        if let Some(broadcast_msg) = selector.create_selected_nodes_broadcast(round) {
            let broadcast_data =
                serde_json::to_vec(&GossipsubMessage::VrfSelectedNodes(broadcast_msg))?;

            self.message_tx
                .send(ChannelMessage::Broadcast {
                    topic: "vrf-selection".to_string(),
                    data: broadcast_data,
                })
                .await?;

            info!(
                "📤 [VRF] Node {} broadcasted VRF-selected nodes for {} operation round {}",
                self.node_id, operation_type, round
            );
        }

        Ok(selection_result)
    }

    pub async fn get_all_selected_nodes_for_round(&self, round: u64) -> Vec<SerializablePeerId> {
        let selector = self.selector.read().await;
        selector.get_all_selected_nodes_for_round(round)
    }

    /// Perform VRF node selection without broadcasting (for custom broadcast handling)
    pub async fn perform_node_selection_without_broadcast(
        &self,
        available_nodes: &[PeerId],
        threshold: usize,
        round: u64,
        operation_type: &str,
    ) -> Result<NodeSelectionResult> {
        info!(
            "🎯 [VRF] Starting {} operation node selection for round {} with {} available nodes (no auto-broadcast)",
            operation_type,
            round,
            available_nodes.len()
        );

        let mut selector = self.selector.write().await;
        selector.ensure_local_submission(round);
        let selection_result = selector.select_mpc_nodes(
            available_nodes,
            threshold,
            round,
            self.config.allow_synthetic_submissions,
        )?;

        info!(
            "✅ [VRF] Node {} selected {} nodes for {} operation round {}: {:?}",
            self.node_id,
            selection_result.selected_nodes.len(),
            operation_type,
            round,
            selection_result.selected_nodes
        );

        Ok(selection_result)
    }

    /// Create a broadcast message for a specific round
    pub async fn create_broadcast_for_round(
        &self,
        round: u64,
    ) -> Option<VrfSelectedNodesBroadcast> {
        let selector = self.selector.read().await;
        selector.create_selected_nodes_broadcast(round)
    }

    pub async fn handle_vrf_broadcast(
        &self,
        broadcast: VrfSelectedNodesBroadcast,
        total_nodes: usize,
    ) {
        let round = broadcast.round;

        // Check if we have our own selection for this round
        let has_own_selection = {
            let selector = self.selector.read().await;
            selector.get_selection_result(round).is_some()
        };

        // If we don't have our own selection, trigger one for this specific round
        if !has_own_selection {
            warn!(
                "⚠️ [VRF] Node {} doesn't have selection for round {}, triggering selection...",
                self.node_id, round
            );

            // Infer available nodes from the broadcast and received selections
            let available_nodes = {
                let selector = self.selector.read().await;
                let mut nodes: HashSet<PeerId> = HashSet::new();

                // Add ourselves
                nodes.insert(self.node_id);

                // Add the broadcaster
                nodes.insert(broadcast.selector_node_id.0);

                // Add all nodes from received selections for this round
                let received_broadcasts = selector.get_received_selections_for_round(round);
                for broadcast_msg in received_broadcasts {
                    nodes.insert(broadcast_msg.selector_node_id.0);
                }

                // Add selected nodes from the broadcast as potential candidates
                for selected_node in &broadcast.selected_nodes {
                    nodes.insert(selected_node.0);
                }

                let mut node_vec: Vec<PeerId> = nodes.into_iter().collect();
                node_vec.sort(); // Sort for determinism
                node_vec
            };

            if !available_nodes.is_empty() && available_nodes.len() >= 2 {
                // Use a reasonable threshold (typically 3 for 4 nodes, or 2/3 of available)
                let threshold = std::cmp::min(
                    std::cmp::max(3, (available_nodes.len() * 2) / 3),
                    available_nodes.len(),
                );

                info!(
                    "🔄 [VRF] Auto-triggering selection for round {} with {} available nodes (threshold: {})",
                    round, available_nodes.len(), threshold
                );

                // Trigger selection for this specific round
                if let Err(e) = self
                    .trigger_selection_for_round(&available_nodes, threshold, round)
                    .await
                {
                    warn!(
                        "⚠️ [VRF] Failed to trigger selection for round {}: {}",
                        round, e
                    );
                }
            } else {
                warn!(
                    "⚠️ [VRF] Cannot trigger selection for round {}: insufficient nodes (have {}, need at least 2)",
                    round, available_nodes.len()
                );
            }
        }

        let mut selector = self.selector.write().await;
        selector.handle_selected_nodes_broadcast(broadcast, total_nodes);

        let min_selections = total_nodes;
        if selector.can_start_consensus(round, min_selections) {
            info!(
                "🎯 [VRF] Enough selections collected for round {}, consensus can be triggered",
                round
            );
        }
    }

    /// Trigger VRF selection for a specific round
    async fn trigger_selection_for_round(
        &self,
        available_nodes: &[PeerId],
        threshold: usize,
        round: u64,
    ) -> Result<()> {
        let mut selector = self.selector.write().await;

        // Ensure local submission for this round
        selector.ensure_local_submission(round);

        // Perform selection for this specific round
        let selection_result = selector.select_mpc_nodes(
            available_nodes,
            threshold,
            round,
            self.config.allow_synthetic_submissions,
        )?;

        info!(
            "✅ [VRF] Successfully created selection for round {}: {} nodes selected",
            round,
            selection_result.selected_nodes.len()
        );

        // Create and broadcast the selection
        if let Some(broadcast_msg) = selector.create_selected_nodes_broadcast(round) {
            let broadcast_data =
                serde_json::to_vec(&GossipsubMessage::VrfSelectedNodes(broadcast_msg))?;

            self.message_tx
                .send(ChannelMessage::Broadcast {
                    topic: "vrf-selection".to_string(),
                    data: broadcast_data,
                })
                .await?;

            info!(
                "📤 [VRF] Broadcasted selection for round {} after auto-trigger",
                round
            );
        }

        Ok(())
    }

    pub async fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        let selector = self.selector.read().await;
        selector.can_start_consensus(round, min_selections)
    }

    pub async fn get_next_round(&self) -> u64 {
        let _guard = self.round_update_lock.lock().await;

        let mut current = self.current_round.write().await;
        let round = *current;
        *current += 1;

        self.persist_current_round(*current).await;

        info!(
            "[VRF][{}] advanced round to {} (next {})",
            self.context, round, *current
        );
        round
    }

    pub async fn get_current_round(&self) -> u64 {
        let current = self.current_round.read().await;
        let round = *current;
        info!("[VRF][{}] current round: {}", self.context, round);
        round
    }

    pub async fn sync_rounds(&self, sync_kind: VrfRoundSyncKind) -> Result<u64> {
        let _guard = self.round_update_lock.lock().await;

        let local_round = {
            let current = self.current_round.read().await;
            *current
        };

        // Gather candidate peers to query for their VRF round.
        let peer_candidates = {
            let selector = self.selector.read().await;
            selector.get_all_selected_nodes_for_round(local_round)
        };

        // Send round sync requests to peers through the VRF/consensus channel.
        let sync_request = VrfRoundSyncRequest {
            from: SerializablePeerId(self.node_id),
            current_round: Some(local_round),
            context: self.context.clone(),
        };
        let request_bytes = serde_json::to_vec(&sync_kind.to_message(sync_request))?;

        if !peer_candidates.is_empty() {
            self.message_tx
                .send(ChannelMessage::Broadcast {
                    topic: sync_kind.topic().to_string(),
                    data: request_bytes,
                })
                .await?;

            info!(
                "📡 [VRF_SYNC] Sent round sync request for round {} to {} peers",
                local_round,
                peer_candidates.len()
            );
        }

        // Wait for peer responses to arrive and be persisted to database
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Read peer rounds from database (single source of truth)
        let peer_rounds: Vec<u64> = if let Some(storage) = &self.vrf_storage {
            match storage.get_all_peer_rounds_for_context(&self.context) {
                Ok(peer_rounds_map) => {
                    let rounds: Vec<u64> = peer_rounds_map.values().copied().collect();
                    info!(
                        "📥 [VRF_SYNC] Retrieved {} peer rounds from database: {:?}",
                        rounds.len(),
                        rounds
                    );
                    rounds
                }
                Err(e) => {
                    warn!(
                        "⚠️ [VRF_SYNC] Failed to read peer rounds from database: {}",
                        e
                    );
                    Vec::new()
                }
            }
        } else {
            warn!("⚠️ [VRF_SYNC] No VRF storage available, cannot read peer rounds");
            Vec::new()
        };

        let synchronized_round = self
            .update_round_from_peer_rounds(local_round, peer_rounds)
            .await;

        Ok(synchronized_round)
    }

    /// Synchronize the VRF round with peers before producing a signing round.
    pub async fn sync_rounds_before_signing(&self) -> Result<u64> {
        self.sync_rounds(VrfRoundSyncKind::Signing).await
    }

    #[cfg(test)]
    pub(crate) async fn sync_rounds_with_mocked_peers(&self, peer_rounds: Vec<u64>) -> u64 {
        let _guard = self.round_update_lock.lock().await;

        let local_round = {
            let current = self.current_round.read().await;
            *current
        };

        self.update_round_from_peer_rounds(local_round, peer_rounds)
            .await
    }

    async fn update_round_from_peer_rounds(&self, local_round: u64, peer_rounds: Vec<u64>) -> u64 {
        let synchronized_round = peer_rounds
            .into_iter()
            .chain(std::iter::once(local_round))
            .max()
            .unwrap_or(local_round);

        if synchronized_round > local_round {
            let mut current = self.current_round.write().await;
            *current = synchronized_round;
            self.persist_current_round(synchronized_round).await;
            info!(
                "🔄 [VRF_SYNC] Updated local round to synchronized round {}",
                synchronized_round
            );
        }

        synchronized_round
    }

    pub(crate) fn round_update_lock(&self) -> Arc<Mutex<()>> {
        self.round_update_lock.clone()
    }

    pub fn context(&self) -> &str {
        &self.context
    }

    pub async fn set_current_round(&self, round: u64) {
        let mut current = self.current_round.write().await;
        *current = round;
        self.persist_current_round(round).await;
        info!(
            "🔄 [VRF][{}] Node {} set current round to: {}",
            self.context, self.node_id, round
        );
    }

    async fn persist_current_round(&self, round: u64) {
        if let Some(storage) = &self.vrf_storage {
            if let Err(error) = storage.set_current_round_for_context(&self.context, round) {
                tracing::warn!(
                    "⚠️ [VRF][{}] Failed to persist current round {} to storage: {:?}",
                    self.context,
                    round,
                    error
                );
            }
        }
    }

    pub async fn get_public_key(&self) -> Vec<u8> {
        let selector = self.selector.read().await;
        selector.get_public_key()
    }

    pub async fn get_public_key_hex(&self) -> String {
        let selector = self.selector.read().await;
        selector.get_public_key_hex()
    }

    pub async fn handle_message(&self, msg: VrfSelectionMessage) -> Result<()> {
        let mut selector = self.selector.write().await;
        selector.handle_message(msg).await
    }

    pub async fn get_all_selected_nodes_with_frequencies(
        &self,
        round: u64,
    ) -> Vec<SerializablePeerId> {
        let selector = self.selector.read().await;
        selector.get_all_selected_nodes_with_frequencies(round)
    }

    pub async fn get_selection_result(&self, round: u64) -> Option<NodeSelectionResult> {
        let selector = self.selector.read().await;
        selector.get_selection_result(round).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{Database, DatabaseConfig, VrfStorage};
    use libp2p::{identity::Keypair, PeerId};
    use tempfile::TempDir;
    use tokio::sync::Barrier;

    use futures::future::join_all;

    fn create_database() -> (Database, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = DatabaseConfig::default();
        config.path = temp_dir.path().to_string_lossy().to_string();
        let db = Database::new(config).unwrap();
        (db, temp_dir)
    }

    fn random_peer_id() -> PeerId {
        let keypair = Keypair::generate_ed25519();
        PeerId::from_public_key(&keypair.public())
    }

    #[tokio::test]
    async fn initializes_round_from_storage_default_zero() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let peer_id = random_peer_id();

        let service = VrfService::new_with_storage(peer_id, tx, storage.clone());

        assert_eq!(service.get_current_round().await, 0);
        assert_eq!(storage.get_current_round().unwrap(), 0);
    }

    #[tokio::test]
    async fn initializes_round_from_existing_storage_value() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        storage.set_current_round(7).unwrap();

        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let peer_id = random_peer_id();

        let service = VrfService::new_with_storage(peer_id, tx, storage.clone());

        assert_eq!(service.get_current_round().await, 7);
    }

    #[tokio::test]
    async fn persists_round_updates() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let peer_id = random_peer_id();

        let mut service = VrfService::new_with_storage(peer_id, tx, storage.clone());

        service.set_current_round(3).await;
        assert_eq!(storage.get_current_round().unwrap(), 3);

        let _ = service.get_next_round().await;
        assert_eq!(storage.get_current_round().unwrap(), 4);
    }

    #[tokio::test]
    async fn concurrent_sync_rounds_do_not_advance() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        storage.set_current_round(2).unwrap();

        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let peer_id = random_peer_id();
        let service = VrfService::new_with_storage(peer_id, tx, storage.clone());

        let task_count = 8;
        let barrier = Arc::new(Barrier::new(task_count));

        let handles: Vec<_> = (0..task_count)
            .map(|_| {
                let svc = service.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    svc.sync_rounds_before_signing().await.unwrap();
                    svc.get_current_round().await
                })
            })
            .collect();

        let rounds = join_all(handles)
            .await
            .into_iter()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();

        assert!(rounds.iter().all(|round| *round == 2));
        assert_eq!(service.get_current_round().await, 2);
        assert_eq!(storage.get_current_round().unwrap(), 2);
    }

    #[tokio::test]
    async fn concurrent_round_advancement_is_serialized() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let peer_id = random_peer_id();
        let service = VrfService::new_with_storage(peer_id, tx, storage.clone());

        let task_count = 6;
        let barrier = Arc::new(Barrier::new(task_count));

        let handles: Vec<_> = (0..task_count)
            .map(|_| {
                let svc = service.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    svc.sync_rounds_before_signing().await.unwrap();
                    svc.get_next_round().await
                })
            })
            .collect();

        let mut next_rounds = join_all(handles)
            .await
            .into_iter()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();

        next_rounds.sort_unstable();

        let expected: Vec<u64> = (0..task_count as u64).collect();
        assert_eq!(next_rounds, expected);
        assert_eq!(service.get_current_round().await, task_count as u64);
        assert_eq!(storage.get_current_round().unwrap(), task_count as u64);
    }

    #[tokio::test]
    async fn syncing_with_peer_rounds_only_moves_forward() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        storage.set_current_round(3).unwrap();

        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let peer_id = random_peer_id();
        let service = VrfService::new_with_storage(peer_id, tx, storage.clone());

        let synchronized = service.sync_rounds_with_mocked_peers(vec![5, 4]).await;
        assert_eq!(synchronized, 5);
        assert_eq!(service.get_current_round().await, 5);
        assert_eq!(storage.get_current_round().unwrap(), 5);

        let synchronized = service.sync_rounds_with_mocked_peers(vec![2, 1]).await;
        assert_eq!(synchronized, 5);
        assert_eq!(service.get_current_round().await, 5);
        assert_eq!(storage.get_current_round().unwrap(), 5);
    }
}
