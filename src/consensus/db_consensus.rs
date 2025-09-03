use crate::types::p2p::SerializablePeerId;
use crate::database::{ConsensusStorage, Database};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use super::{ConsensusResult, ConsensusMessage};

/// Database-backed consensus node that stores state in RocksDB
#[derive(Clone)]
pub struct DatabaseConsensusNode {
    consensus_storage: ConsensusStorage,
}

impl DatabaseConsensusNode {
    pub fn new(database: Database) -> Self {
        let consensus_storage = ConsensusStorage::new(database);
        
        info!("🏗️ [DB_CONSENSUS] Created new DatabaseConsensusNode instance");
        
        Self {
            consensus_storage,
        }
    }

    /// Add selected nodes for a specific round
    pub async fn add_selected_nodes(&self, round: u64, selected_nodes: Vec<SerializablePeerId>) -> Result<()> {
        info!(
            "📋 [DB_CONSENSUS] Adding {} selected nodes for round {}",
            selected_nodes.len(),
            round
        );
        
        self.consensus_storage.store_selected_nodes(round, &selected_nodes).await?;
        Ok(())
    }

    /// Get selected nodes for a specific round
    pub async fn get_selected_nodes(&self, round: u64) -> Result<Option<Vec<SerializablePeerId>>> {
        self.consensus_storage.get_selected_nodes(round).await
    }

    /// Get all selected nodes by round
    pub async fn get_all_selected_nodes_by_round(&self) -> Result<HashMap<u64, Vec<SerializablePeerId>>> {
        self.consensus_storage.get_all_selected_nodes_by_round().await
    }

    /// Start consensus for a specific round
    pub async fn start_consensus(&self, round: u64) -> Result<ConsensusResult> {
        info!("🚀 [DB_CONSENSUS] Starting consensus for round {}", round);
        
        // Get selected nodes for this round
        let selected_nodes = match self.get_selected_nodes(round).await? {
            Some(nodes) => nodes,
            None => {
                return Err(anyhow::anyhow!("No selected nodes found for round {}", round));
            }
        };

        if selected_nodes.is_empty() {
            return Err(anyhow::anyhow!("No nodes available for consensus in round {}", round));
        }

        // Count node frequencies (simulate consensus algorithm)
        let mut node_frequencies = HashMap::new();
        let total_selections = selected_nodes.len();

        for node in &selected_nodes {
            *node_frequencies.entry(node.clone()).or_insert(0) += 1;
        }

        // Select the node with highest frequency (or first in case of tie)
        let final_node = selected_nodes
            .iter()
            .max_by_key(|node| node_frequencies.get(node).unwrap_or(&0))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Failed to select final node"))?;

        let result = ConsensusResult {
            final_node: final_node.clone(),
            round,
            node_frequencies,
            total_selections,
        };

        info!(
            "✅ [DB_CONSENSUS] Consensus completed for round {}: final node = {:?}",
            round, final_node
        );

        // Store the consensus result
        self.store_consensus_result(round, &result).await?;

        Ok(result)
    }

    /// Store a consensus result
    pub async fn store_consensus_result(&self, round: u64, result: &ConsensusResult) -> Result<()> {
        self.consensus_storage.store_consensus_result(round, result).await
    }

    /// Get a consensus result for a specific round
    pub async fn get_consensus_result(&self, round: u64) -> Result<Option<ConsensusResult>> {
        self.consensus_storage.get_consensus_result(round).await
    }

    /// Get all consensus results
    pub async fn get_all_consensus_results(&self) -> Result<HashMap<u64, ConsensusResult>> {
        self.consensus_storage.get_all_consensus_results().await
    }

    /// Get the current round number
    pub async fn get_current_round(&self) -> Result<u64> {
        self.consensus_storage.get_current_round().await
    }

    /// Set the current round number
    pub async fn set_current_round(&self, round: u64) -> Result<()> {
        self.consensus_storage.set_current_round(round).await
    }

    /// Increment the current round and return the new value
    pub async fn increment_round(&self) -> Result<u64> {
        self.consensus_storage.increment_round().await
    }

    /// Process a consensus message
    pub async fn process_consensus_message(&self, message: ConsensusMessage) -> Result<()> {
        match message {
            ConsensusMessage::FinalNodeResult { result, round } => {
                self.handle_final_node_result(result, round).await
            }
        }
    }

    /// Handle final node result message
    async fn handle_final_node_result(&self, result: ConsensusResult, round: u64) -> Result<()> {
        info!(
            "📨 [DB_CONSENSUS] Received final node result for round {}: {:?}",
            round, result.final_node
        );

        // Store the received consensus result
        self.store_consensus_result(round, &result).await?;

        // Verify the round matches
        if result.round != round {
            tracing::warn!(
                "Round mismatch in consensus result: expected {}, got {}",
                round, result.round
            );
        }

        info!("✅ [DB_CONSENSUS] Processed final node result for round {}", round);
        Ok(())
    }

    /// Clean up old consensus data (keep only last N rounds)
    pub async fn cleanup_old_rounds(&self, keep_rounds: u64) -> Result<()> {
        self.consensus_storage.cleanup_old_rounds(keep_rounds).await
    }

    /// Get consensus statistics
    pub async fn get_consensus_stats(&self) -> Result<crate::database::ConsensusStats> {
        self.consensus_storage.get_consensus_stats().await
    }

    /// Delete selected nodes for a specific round
    pub async fn delete_selected_nodes(&self, round: u64) -> Result<()> {
        self.consensus_storage.delete_selected_nodes(round).await
    }

    /// Delete consensus result for a specific round
    pub async fn delete_consensus_result(&self, round: u64) -> Result<()> {
        self.consensus_storage.delete_consensus_result(round).await
    }

    /// Check if consensus has been completed for a round
    pub async fn is_consensus_completed(&self, round: u64) -> Result<bool> {
        match self.get_consensus_result(round).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Get the final node for a specific round (if consensus completed)
    pub async fn get_final_node_for_round(&self, round: u64) -> Result<Option<SerializablePeerId>> {
        match self.get_consensus_result(round).await? {
            Some(result) => Ok(Some(result.final_node)),
            None => Ok(None),
        }
    }

    /// Get rounds that have completed consensus
    pub async fn get_completed_rounds(&self) -> Result<Vec<u64>> {
        let all_results = self.get_all_consensus_results().await?;
        let mut rounds: Vec<u64> = all_results.keys().cloned().collect();
        rounds.sort();
        Ok(rounds)
    }

    /// Get pending rounds (have selected nodes but no consensus result)
    pub async fn get_pending_rounds(&self) -> Result<Vec<u64>> {
        let all_selected = self.get_all_selected_nodes_by_round().await?;
        let all_results = self.get_all_consensus_results().await?;
        
        let mut pending_rounds = Vec::new();
        for round in all_selected.keys() {
            if !all_results.contains_key(round) {
                pending_rounds.push(*round);
            }
        }
        
        pending_rounds.sort();
        Ok(pending_rounds)
    }

    /// Perform consensus on all pending rounds
    pub async fn process_pending_rounds(&self) -> Result<Vec<ConsensusResult>> {
        let pending_rounds = self.get_pending_rounds().await?;
        let mut results = Vec::new();
        
        for round in pending_rounds {
            match self.start_consensus(round).await {
                Ok(result) => {
                    results.push(result);
                    info!("✅ [DB_CONSENSUS] Completed consensus for pending round {}", round);
                },
                Err(e) => {
                    tracing::error!("Failed to complete consensus for round {}: {}", round, e);
                }
            }
        }
        
        info!("🎯 [DB_CONSENSUS] Processed {} pending rounds", results.len());
        Ok(results)
    }

    /// Get consensus storage for external access
    pub fn get_consensus_storage(&self) -> &ConsensusStorage {
        &self.consensus_storage
    }
}
