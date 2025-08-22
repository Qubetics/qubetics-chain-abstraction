use libp2p::PeerId;
use std::any::Any;
use std::collections::HashSet;
use tracing::info;

pub mod vrf_manager;
pub use vrf_manager::VrfNodeManager;

/// Trait for managing node membership in the network
pub trait NodeMembership {
    /// Add a new node to the network
    fn add_node(&mut self, node_id: PeerId) -> Result<(), String>;

    /// Remove a node from the network
    fn remove_node(&mut self, node_id: PeerId) -> Result<(), String>;

    /// Get the current total number of nodes
    fn get_total_nodes(&self) -> usize;

    /// Get the current threshold value
    fn get_threshold(&self) -> usize;

    /// Set the threshold
    fn set_threshold(&self, threshold: usize) -> usize;

    /// Get all active node IDs
    fn get_active_nodes(&self) -> HashSet<PeerId>;

    /// Get reference to self as Any for downcasting
    fn as_any(&self) -> &dyn Any;

    fn clone_box(&self) -> Box<dyn NodeMembership>;
}

impl Clone for Box<dyn NodeMembership> {
    fn clone(&self) -> Box<dyn NodeMembership> {
        self.clone_box()
    }
}

/// Trait for calculating threshold based on total nodes
pub trait ThresholdCalculator {
    /// Calculate the threshold based on the total number of nodes
    fn calculate_threshold(&self, total_nodes: usize) -> usize;

    fn clone_box(&self) -> Box<dyn ThresholdCalculator>;
}

/// Default implementation of ThresholdCalculator
#[derive(Clone)]
pub struct DefaultThresholdCalculator;

impl ThresholdCalculator for DefaultThresholdCalculator {
    fn calculate_threshold(&self, _total_nodes: usize) -> usize {
        _total_nodes/2 + 1
    }

    fn clone_box(&self) -> Box<dyn ThresholdCalculator> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ThresholdCalculator> {
    fn clone(&self) -> Box<dyn ThresholdCalculator> {
        self.clone_box()
    }
}

/// Basic mplementation of NodeMembership
#[derive(Clone)]
pub struct BasicNodeManager {
    nodes: HashSet<PeerId>,
    threshold_calculator: Box<dyn ThresholdCalculator>,
}

impl BasicNodeManager {
    pub fn new(threshold_calculator: Box<dyn ThresholdCalculator>) -> Self {
        Self {
            nodes: HashSet::new(),
            threshold_calculator,
        }
    }
}

impl NodeMembership for BasicNodeManager {
    fn set_threshold(&self, threshold: usize) -> usize {
        threshold
    }

    fn add_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if self.nodes.contains(&node_id) {
            return Err(format!("Node {} already exists", node_id));
        }
        info!("Adding nodeasasa: {:?}", node_id);
        self.nodes.insert(node_id);
        Ok(())
    }

    fn remove_node(&mut self, node_id: PeerId) -> Result<(), String> {
        if !self.nodes.contains(&node_id) {
            return Err(format!("Node {} not found", node_id));
        }
        self.nodes.remove(&node_id);
        Ok(())
    }

    fn get_total_nodes(&self) -> usize {
        self.nodes.len()
    }

    fn get_threshold(&self) -> usize {
        self.threshold_calculator
            .calculate_threshold(self.get_total_nodes())
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
