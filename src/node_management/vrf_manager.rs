use crate::node_management::{NodeMembership, ThresholdCalculator};
use crate::types::p2p::SerializablePeerId;
use crate::vrf::{NodeSelectionResult, VrfNodeSelector, VrfSelectionMessage};
use anyhow::{anyhow, Result};
use libp2p::PeerId;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct VrfNodeManagerConfig {
    pub selection_interval: u64,
    pub heartbeat_timeout: Duration,
    pub allow_synthetic_submissions: bool,
    pub min_active_nodes: usize,
}

impl Default for VrfNodeManagerConfig {
    fn default() -> Self {
        Self {
            selection_interval: 10,
            heartbeat_timeout: Duration::from_secs(30),
            allow_synthetic_submissions: true,
            min_active_nodes: 1,
        }
    }
}

#[derive(Debug, Clone)]
struct NodeRecord {
    peer_id: PeerId,
    vrf_public_key: Option<Vec<u8>>,
    last_seen: SystemTime,
    is_active: bool,
}

impl NodeRecord {
    fn new(peer_id: PeerId, vrf_public_key: Option<Vec<u8>>) -> Self {
        Self {
            peer_id,
            vrf_public_key,
            last_seen: SystemTime::now(),
            is_active: true,
        }
    }

    fn mark_heartbeat(&mut self) {
        self.last_seen = SystemTime::now();
        self.is_active = true;
    }

    fn deactivate(&mut self) {
        self.is_active = false;
    }
}

/// VRF-based node manager that uses VRF for MPC node selection
pub struct VrfNodeManager {
    nodes: HashMap<PeerId, NodeRecord>,
    threshold_calculator: Box<dyn ThresholdCalculator>,
    vrf_selector: VrfNodeSelector,
    current_selection: Option<NodeSelectionResult>,
    config: VrfNodeManagerConfig,
    threshold_override: Option<usize>,
}

impl VrfNodeManager {
    pub fn new(
        node_id: PeerId,
        threshold_calculator: Box<dyn ThresholdCalculator>,
        selection_interval: u64,
    ) -> Self {
        let mut config = VrfNodeManagerConfig::default();
        config.selection_interval = selection_interval;
        Self::with_config(node_id, threshold_calculator, config)
    }

    pub fn with_config(
        node_id: PeerId,
        threshold_calculator: Box<dyn ThresholdCalculator>,
        config: VrfNodeManagerConfig,
    ) -> Self {
        Self {
            nodes: HashMap::new(),
            threshold_calculator,
            vrf_selector: VrfNodeSelector::new(node_id),
            current_selection: None,
            config,
            threshold_override: None,
        }
    }

    pub fn register_node_with_vrf(
        &mut self,
        node_id: PeerId,
        vrf_public_key: Vec<u8>,
    ) -> Result<(), String> {
        self.register_node_internal(node_id, Some(vrf_public_key))
    }

    pub fn mark_node_heartbeat(&mut self, node_id: &PeerId) {
        if let Some(record) = self.nodes.get_mut(node_id) {
            record.mark_heartbeat();
        }
    }

    pub fn prune_inactive_nodes(&mut self) {
        let now = SystemTime::now();
        for record in self.nodes.values_mut() {
            if let Ok(elapsed) = now.duration_since(record.last_seen) {
                if elapsed > self.config.heartbeat_timeout {
                    record.deactivate();
                }
            }
        }
    }

    fn register_node_internal(
        &mut self,
        node_id: PeerId,
        vrf_public_key: Option<Vec<u8>>,
    ) -> Result<(), String> {
        if self.nodes.contains_key(&node_id) {
            return Err(format!("Node {} already exists", node_id));
        }
        self.nodes
            .insert(node_id, NodeRecord::new(node_id, vrf_public_key));
        info!("Registered node {} with VRF manager", node_id);
        Ok(())
    }

    fn active_peer_ids(&self) -> Vec<PeerId> {
        self.nodes
            .values()
            .filter(|record| record.is_active)
            .map(|record| record.peer_id.clone())
            .collect()
    }

    /// Trigger a new VRF-based node selection
    pub async fn trigger_selection(&mut self) -> Result<NodeSelectionResult> {
        self.prune_inactive_nodes();
        let mut available_nodes = self.active_peer_ids();
        if available_nodes.len() < self.config.min_active_nodes {
            return Err(anyhow!(
                "insufficient active nodes for VRF selection ({} available, require at least {})",
                available_nodes.len(),
                self.config.min_active_nodes
            ));
        }

        // Sort deterministically to ensure consistent synthetic submissions
        available_nodes.sort_by(|a, b| a.to_bytes().cmp(&b.to_bytes()));

        let computed_threshold = self.get_threshold();
        let threshold = if computed_threshold > available_nodes.len() {
            warn!(
                "threshold {} is higher than active nodes {}; clamping to {}",
                computed_threshold,
                available_nodes.len(),
                available_nodes.len()
            );
            available_nodes.len()
        } else {
            computed_threshold
        };

        if threshold == 0 {
            return Err(anyhow!("VRF selection threshold cannot be zero"));
        }

        let round = self.vrf_selector.get_current_round();
        info!(
            "Triggering VRF-based node selection for round {} with {} candidates (threshold={})",
            round,
            available_nodes.len(),
            threshold
        );

        self.vrf_selector.ensure_local_submission(round);
        let result = self.vrf_selector.select_mpc_nodes(
            &available_nodes,
            threshold,
            round,
            self.config.allow_synthetic_submissions,
        )?;
        self.current_selection = Some(result.clone());

        Ok(result)
    }

    /// Get the currently selected MPC nodes
    pub fn get_selected_mpc_nodes(&self) -> Option<&Vec<SerializablePeerId>> {
        self.current_selection.as_ref().map(|r| &r.selected_nodes)
    }

    /// Check if a specific node is currently selected for MPC
    pub fn is_node_selected_for_mpc(&self, node_id: &PeerId) -> bool {
        if let Some(selection) = &self.current_selection {
            selection
                .selected_nodes
                .iter()
                .any(|node| node.0 == *node_id)
        } else {
            false
        }
    }

    /// Check if this node is selected for MPC
    pub fn is_self_selected_for_mpc(&self) -> bool {
        let round = self.vrf_selector.get_current_round();
        self.vrf_selector.is_selected(round)
    }

    /// Handle VRF selection messages
    pub async fn handle_vrf_message(&mut self, msg: VrfSelectionMessage) -> Result<()> {
        self.vrf_selector.handle_message(msg).await
    }

    /// Advance to the next selection round
    pub fn advance_round(&mut self) {
        self.vrf_selector.advance_round();
        debug!(
            "Advanced to selection round {}",
            self.vrf_selector.get_current_round()
        );
    }

    /// Get the current selection round
    pub fn get_current_round(&self) -> u64 {
        self.vrf_selector.get_current_round()
    }

    /// Get VRF public key for this node
    pub fn get_vrf_public_key(&self) -> String {
        self.vrf_selector.get_public_key_hex()
    }

    /// Get the current selection result
    pub fn get_current_selection(&self) -> Option<&NodeSelectionResult> {
        self.current_selection.as_ref()
    }

    /// Set the selection interval
    pub fn set_selection_interval(&mut self, interval: u64) {
        self.config.selection_interval = interval;
    }

    /// Get the selection interval
    pub fn get_selection_interval(&self) -> u64 {
        self.config.selection_interval
    }

    /// Get a reference to the VRF selector
    pub fn get_vrf_selector(&self) -> &VrfNodeSelector {
        &self.vrf_selector
    }

    /// Get a mutable reference to the VRF selector
    pub fn get_vrf_selector_mut(&mut self) -> &mut VrfNodeSelector {
        &mut self.vrf_selector
    }
}

// ─── implement Clone so we can clone_box ─────────────────────────────────────
impl Clone for VrfNodeManager {
    fn clone(&self) -> Self {
        VrfNodeManager {
            nodes: self.nodes.clone(),
            threshold_calculator: self.threshold_calculator.clone(),
            vrf_selector: self.vrf_selector.clone(),
            current_selection: self.current_selection.clone(),
            config: self.config.clone(),
            threshold_override: self.threshold_override,
        }
    }
}

impl NodeMembership for VrfNodeManager {
    fn add_node(&mut self, node_id: PeerId) -> Result<(), String> {
        self.register_node_internal(node_id, None)
    }

    fn clone_box(&self) -> Box<dyn NodeMembership> {
        Box::new(self.clone())
    }

    fn remove_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if !self.nodes.contains_key(&node_id) {
            return Err(format!("Node {} not found", node_id));
        }
        self.nodes.remove(&node_id);
        info!("Removed node {} from VRF node manager", node_id);
        Ok(())
    }

    fn get_total_nodes(&self) -> usize {
        self.nodes.len()
    }

    fn get_threshold(&self) -> usize {
        if let Some(threshold) = self.threshold_override {
            threshold
        } else {
            self.threshold_calculator
                .calculate_threshold(self.get_total_nodes())
        }
    }

    fn set_threshold(&mut self, threshold: usize) -> usize {
        self.threshold_override = Some(threshold);
        threshold
    }

    fn get_active_nodes(&self) -> HashSet<PeerId> {
        self.nodes
            .values()
            .filter(|record| record.is_active)
            .map(|record| record.peer_id.clone())
            .collect()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_management::DefaultThresholdCalculator;
    use libp2p::identity::Keypair;

    // Custom threshold calculator for testing
    #[derive(Clone)]
    struct TestThresholdCalculator;

    impl ThresholdCalculator for TestThresholdCalculator {
        fn calculate_threshold(&self, _total_nodes: usize) -> usize {
            3 // Always return 3 for testing
        }
        fn clone_box(&self) -> Box<dyn ThresholdCalculator> {
            Box::new(self.clone())
        }
    }

    #[tokio::test]
    async fn test_vrf_node_manager() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let threshold_calculator = Box::new(TestThresholdCalculator);
        let mut manager = VrfNodeManager::new(node_id, threshold_calculator, 10);

        // Add some test nodes
        let test_nodes: Vec<PeerId> = (0..5)
            .map(|_| PeerId::from(Keypair::generate_ed25519().public()))
            .collect();

        for node in &test_nodes {
            manager.add_node(*node).unwrap();
        }

        assert_eq!(manager.get_total_nodes(), 5);

        // Trigger selection
        let result = manager.trigger_selection().await.unwrap();
        assert_eq!(result.selected_nodes.len(), 3); // Should select 3 nodes
        assert_eq!(result.total_nodes, 5);
    }

    #[test]
    fn test_node_selection_check() {
        let keypair = Keypair::generate_ed25519();
        let node_id = PeerId::from(keypair.public());
        let threshold_calculator = Box::new(DefaultThresholdCalculator);
        let manager = VrfNodeManager::new(node_id, threshold_calculator, 10);

        // Should return false when no selection has been made
        assert!(!manager.is_self_selected_for_mpc());
    }
}
