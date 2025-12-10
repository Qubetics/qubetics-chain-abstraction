use std::sync::Arc;

use anyhow::Result;
use libp2p::PeerId;
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    time::{timeout, Duration},
};
use tracing::info;

use crate::{
    database::VrfStorage,
    types::{p2p::SerializablePeerId, ChannelMessage, GossipsubMessage, VrfRoundSyncRequest},
};

use super::{
    selector::VrfNodeSelector,
    types::{NodeSelectionResult, VrfSelectedNodesBroadcast, VrfSelectionMessage},
};

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
    config: VrfServiceConfig,
}

impl VrfService {
    /// Create a new VRF service
    pub fn new(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self::with_config(node_id, message_tx, VrfServiceConfig::default())
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
        )
    }

    pub fn with_config(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
    ) -> Self {
        Self::with_config_and_storage(node_id, message_tx, config, None)
    }

    pub fn with_config_and_storage(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
        vrf_storage: Option<VrfStorage>,
    ) -> Self {
        let selector = VrfNodeSelector::new(node_id);
        let initial_round = vrf_storage
            .as_ref()
            .and_then(|storage| storage.get_current_round().ok())
            .unwrap_or(0);

        Self {
            selector: Arc::new(RwLock::new(selector)),
            message_tx,
            node_id,
            current_round: Arc::new(RwLock::new(initial_round)),
            round_update_lock: Arc::new(Mutex::new(())),
            vrf_storage,
            config,
        }
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

    pub async fn handle_vrf_broadcast(
        &self,
        broadcast: VrfSelectedNodesBroadcast,
        total_nodes: usize,
    ) {
        let mut selector = self.selector.write().await;
        let round = broadcast.round;

        selector.handle_selected_nodes_broadcast(broadcast, total_nodes);

        let min_selections = total_nodes;
        if selector.can_start_consensus(round, min_selections) {
            info!(
                "🎯 [VRF] Enough selections collected for round {}, consensus can be triggered",
                round
            );
        }
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

        round
    }

    pub async fn get_current_round(&self) -> u64 {
        let current = self.current_round.read().await;
        *current
    }

    /// Synchronize the VRF round with peers before producing a signing round.
    pub async fn sync_rounds_before_signing(&self) -> Result<u64> {
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
        };
        let request_bytes = serde_json::to_vec(&sync_request)?;

        if !peer_candidates.is_empty() {
            self.message_tx
                .send(ChannelMessage::Broadcast {
                    topic: crate::network::transport::types::TOPIC_CONSENSUS.to_string(),
                    data: request_bytes,
                })
                .await?;

            info!(
                "📡 [VRF_SYNC] Sent round sync request for round {} to {} peers",
                local_round,
                peer_candidates.len()
            );
        }

        // Briefly wait for peer responses to arrive on the network layer.
        let peer_rounds: Vec<u64> = timeout(Duration::from_millis(500), async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Vec::new()
        })
        .await
        .unwrap_or_default();

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

        Ok(synchronized_round)
    }

    pub(crate) fn round_update_lock(&self) -> Arc<Mutex<()>> {
        self.round_update_lock.clone()
    }

    pub async fn set_current_round(&mut self, round: u64) {
        let mut current = self.current_round.write().await;
        *current = round;
        self.persist_current_round(round).await;
        info!(
            "🔄 [VRF] Node {} set current round to: {}",
            self.node_id, round
        );
    }

    async fn persist_current_round(&self, round: u64) {
        if let Some(storage) = &self.vrf_storage {
            if let Err(error) = storage.set_current_round(round) {
                tracing::warn!(
                    "⚠️ [VRF] Failed to persist current round {} to storage: {:?}",
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
}
