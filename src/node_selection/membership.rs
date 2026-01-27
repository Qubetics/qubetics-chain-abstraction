use libp2p::PeerId;
use std::any::Any;
use std::collections::HashSet;
use tracing::info;

use super::threshold::ThresholdCalculator;

/// Trait for managing node membership in the network
pub trait NodeMembership: Send + Sync {
    /// Add a new node to the network
    fn add_node(&mut self, node_id: PeerId) -> Result<(), String>;

    /// Remove a node from the network
    fn remove_node(&mut self, node_id: PeerId) -> Result<(), String>;

    /// Get the current total number of nodes
    fn get_total_nodes(&self) -> usize;

    /// Get the current threshold value
    fn get_threshold(&self) -> usize;

    /// Set the threshold
    fn set_threshold(&mut self, threshold: usize) -> usize;

    /// Get all active node IDs
    fn get_active_nodes(&self) -> HashSet<PeerId>;

    /// Get all active nodes except the specified one
    /// This is a convenience method to avoid duplicating the filter pattern
    fn get_other_active_nodes(&self, exclude: PeerId) -> Vec<PeerId> {
        self.get_active_nodes()
            .into_iter()
            .filter(|&pid| pid != exclude)
            .collect()
    }

    /// Get reference to self as Any for downcasting
    fn as_any(&self) -> &dyn Any;

    fn clone_box(&self) -> Box<dyn NodeMembership>;
}

impl Clone for Box<dyn NodeMembership> {
    fn clone(&self) -> Box<dyn NodeMembership> {
        self.clone_box()
    }
}

/// Basic implementation of NodeMembership
#[derive(Clone)]
pub struct BasicNodeManager {
    nodes: HashSet<PeerId>,
    threshold_calculator: Box<dyn ThresholdCalculator>,
    threshold_override: Option<usize>,
}

impl BasicNodeManager {
    pub fn new(threshold_calculator: Box<dyn ThresholdCalculator>) -> Self {
        Self {
            nodes: HashSet::new(),
            threshold_calculator,
            threshold_override: None,
        }
    }
}

impl NodeMembership for BasicNodeManager {
    fn set_threshold(&mut self, threshold: usize) -> usize {
        self.threshold_override = Some(threshold);
        threshold
    }

    fn add_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if self.nodes.contains(&node_id) {
            return Err(format!("Node {node_id} already exists"));
        }
        info!("Adding node: {:?}", node_id);
        self.nodes.insert(node_id);
        Ok(())
    }

    fn remove_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if !self.nodes.contains(&node_id) {
            return Err(format!("Node {node_id} not found"));
        }
        self.nodes.remove(&node_id);
        Ok(())
    }

    fn get_total_nodes(&self) -> usize {
        self.nodes.len()
    }

    fn get_threshold(&self) -> usize {
        if let Some(override_value) = self.threshold_override {
            override_value
        } else {
            self.threshold_calculator
                .calculate_threshold(self.get_total_nodes())
        }
    }

    fn get_active_nodes(&self) -> HashSet<PeerId> {
        self.nodes.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn NodeMembership> {
        Box::new(self.clone())
    }
}
