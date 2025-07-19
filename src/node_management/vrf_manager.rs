use crate::node_management::{NodeMembership, ThresholdCalculator};
use crate::types::p2p::SerializablePeerId;
use crate::vrf::{NodeSelectionResult, VrfNodeSelector, VrfSelectionMessage};
use anyhow::Result;
use libp2p::PeerId;
use std::any::Any;
use std::collections::HashSet;
use tracing::{debug, info};

/// VRF-based node manager that uses VRF for MPC node selection
pub struct VrfNodeManager {
    base_nodes: HashSet<PeerId>,
    threshold_calculator: Box<dyn ThresholdCalculator>,
    vrf_selector: VrfNodeSelector,
    current_selection: Option<NodeSelectionResult>,
    selection_interval: u64, // rounds between selections
}

impl VrfNodeManager {
    pub fn new(
        node_id: PeerId,
        threshold_calculator: Box<dyn ThresholdCalculator>,
        selection_interval: u64,
    ) -> Self {
        Self {
            base_nodes: HashSet::new(),
            threshold_calculator,
            vrf_selector: VrfNodeSelector::new(node_id),
            current_selection: None,
            selection_interval,
        }
    }

    /// Trigger a new VRF-based node selection
    pub async fn trigger_selection(&mut self) -> Result<NodeSelectionResult> {
        let available_nodes: Vec<PeerId> = self.base_nodes.iter().cloned().collect();
        let threshold = self
            .threshold_calculator
            .calculate_threshold(available_nodes.len());
        let round = self.vrf_selector.get_current_round();

        info!("Triggering VRF-based node selection for round {}", round);

        let result = self
            .vrf_selector
            .select_mpc_nodes(&available_nodes, threshold, round);
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
        self.selection_interval = interval;
    }

    /// Get the selection interval
    pub fn get_selection_interval(&self) -> u64 {
        self.selection_interval
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
            base_nodes: self.base_nodes.clone(),
            // Box<dyn ThresholdCalculator> now implements Clone
            threshold_calculator: self.threshold_calculator.clone(),
            vrf_selector: self.vrf_selector.clone(),
            current_selection: self.current_selection.clone(),
            selection_interval: self.selection_interval,
        }
    }
}

impl NodeMembership for VrfNodeManager {
    fn add_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if self.base_nodes.contains(&node_id) {
            return Err(format!("Node {} already exists", node_id));
        }
        self.base_nodes.insert(node_id);
        info!(
            "\x1b[34m➕ Added node {} to VRF node manager\x1b[0m",
            node_id
        );
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn NodeMembership> {
        Box::new(self.clone())
    }

    fn remove_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if !self.base_nodes.contains(&node_id) {
            return Err(format!("Node {} not found", node_id));
        }
        self.base_nodes.remove(&node_id);
        info!(
            "\x1b[31m➖ Removed node {} from VRF node manager\x1b[0m",
            node_id
        );
        Ok(())
    }

    fn get_total_nodes(&self) -> usize {
        self.base_nodes.len()
    }

    fn get_threshold(&self) -> usize {
        self.threshold_calculator
            .calculate_threshold(self.get_total_nodes())
    }

    fn set_threshold(&self, threshold: usize) -> usize {
        threshold
    }

    fn get_active_nodes(&self) -> HashSet<PeerId> {
        self.base_nodes.clone()
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
