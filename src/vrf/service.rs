use std::sync::Arc;

use anyhow::Result;
use libp2p::PeerId;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

use crate::types::{p2p::SerializablePeerId, ChannelMessage, GossipsubMessage};

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
    config: VrfServiceConfig,
}

impl VrfService {
    /// Create a new VRF service
    pub fn new(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self::with_config(node_id, message_tx, VrfServiceConfig::default())
    }

    pub fn with_config(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
    ) -> Self {
        let selector = VrfNodeSelector::new(node_id);

        Self {
            selector: Arc::new(RwLock::new(selector)),
            message_tx,
            node_id,
            current_round: Arc::new(RwLock::new(0)),
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
        let mut current = self.current_round.write().await;
        let round = *current;
        *current += 1;
        round
    }

    pub async fn get_current_round(&self) -> u64 {
        let current = self.current_round.read().await;
        *current
    }

    pub async fn set_current_round(&mut self, round: u64) {
        let mut current = self.current_round.write().await;
        *current = round;
        info!(
            "🔄 [VRF] Node {} set current round to: {}",
            self.node_id, round
        );
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
