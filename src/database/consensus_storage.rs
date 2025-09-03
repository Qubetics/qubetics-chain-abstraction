use crate::database::{Database, key_utils};
use crate::consensus::ConsensusResult;
use crate::types::p2p::SerializablePeerId;
use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, debug};

/// Database-backed consensus storage
#[derive(Clone)]
pub struct ConsensusStorage {
    db: Database,
}

impl ConsensusStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store selected nodes for a specific round
    pub async fn store_selected_nodes(&self, round: u64, selected_nodes: &[SerializablePeerId]) -> Result<()> {
        let key = key_utils::selected_nodes_key(round);
        let nodes_vec = selected_nodes.to_vec();
        self.db.put_string(&key, &nodes_vec)?;
        info!("✅ [CONSENSUS_STORAGE] Stored {} selected nodes for round: {}", selected_nodes.len(), round);
        Ok(())
    }

    /// Get selected nodes for a specific round
    pub async fn get_selected_nodes(&self, round: u64) -> Result<Option<Vec<SerializablePeerId>>> {
        let key = key_utils::selected_nodes_key(round);
        let nodes = self.db.get_string(&key)?;
        if nodes.is_some() {
            debug!("🔍 [CONSENSUS_STORAGE] Retrieved selected nodes for round: {}", round);
        }
        Ok(nodes)
    }

    /// Get all selected nodes by round
    pub async fn get_all_selected_nodes_by_round(&self) -> Result<HashMap<u64, Vec<SerializablePeerId>>> {
        let prefix = crate::database::keys::SELECTED_NODES;
        let results: Vec<(String, Vec<SerializablePeerId>)> = self.db.get_values_with_prefix(prefix)?;
        
        let mut selected_nodes = HashMap::new();
        for (key, nodes) in results {
            // Extract round from key by removing prefix
            if let Some(round_str) = key.strip_prefix(prefix) {
                if let Ok(round) = round_str.parse::<u64>() {
                    selected_nodes.insert(round, nodes);
                }
            }
        }
        
        debug!("🔍 [CONSENSUS_STORAGE] Retrieved selected nodes for {} rounds", selected_nodes.len());
        Ok(selected_nodes)
    }

    /// Store a consensus result for a specific round
    pub async fn store_consensus_result(&self, round: u64, result: &ConsensusResult) -> Result<()> {
        let key = key_utils::consensus_result_key(round);
        self.db.put_string(&key, result)?;
        info!("✅ [CONSENSUS_STORAGE] Stored consensus result for round: {}", round);
        Ok(())
    }

    /// Get a consensus result for a specific round
    pub async fn get_consensus_result(&self, round: u64) -> Result<Option<ConsensusResult>> {
        let key = key_utils::consensus_result_key(round);
        let result = self.db.get_string(&key)?;
        if result.is_some() {
            debug!("🔍 [CONSENSUS_STORAGE] Retrieved consensus result for round: {}", round);
        }
        Ok(result)
    }

    /// Get all consensus results by round
    pub async fn get_all_consensus_results(&self) -> Result<HashMap<u64, ConsensusResult>> {
        let prefix = crate::database::keys::CONSENSUS_RESULT;
        let results: Vec<(String, ConsensusResult)> = self.db.get_values_with_prefix(prefix)?;
        
        let mut consensus_results = HashMap::new();
        for (key, result) in results {
            // Extract round from key by removing prefix
            if let Some(round_str) = key.strip_prefix(prefix) {
                if let Ok(round) = round_str.parse::<u64>() {
                    consensus_results.insert(round, result);
                }
            }
        }
        
        debug!("🔍 [CONSENSUS_STORAGE] Retrieved consensus results for {} rounds", consensus_results.len());
        Ok(consensus_results)
    }

    /// Delete selected nodes for a specific round
    pub async fn delete_selected_nodes(&self, round: u64) -> Result<()> {
        let key = key_utils::selected_nodes_key(round);
        self.db.delete_string(&key)?;
        info!("🗑️ [CONSENSUS_STORAGE] Deleted selected nodes for round: {}", round);
        Ok(())
    }

    /// Delete consensus result for a specific round
    pub async fn delete_consensus_result(&self, round: u64) -> Result<()> {
        let key = key_utils::consensus_result_key(round);
        self.db.delete_string(&key)?;
        info!("🗑️ [CONSENSUS_STORAGE] Deleted consensus result for round: {}", round);
        Ok(())
    }

    /// Get the current round number (stored as metadata)
    pub async fn get_current_round(&self) -> Result<u64> {
        let key = "current_round";
        match self.db.get_string::<u64>(key)? {
            Some(round) => {
                debug!("🔍 [CONSENSUS_STORAGE] Retrieved current round: {}", round);
                Ok(round)
            },
            None => {
                // Initialize to 0 if not found
                self.set_current_round(0).await?;
                Ok(0)
            }
        }
    }

    /// Set the current round number
    pub async fn set_current_round(&self, round: u64) -> Result<()> {
        let key = "current_round";
        self.db.put_string(key, &round)?;
        info!("✅ [CONSENSUS_STORAGE] Set current round to: {}", round);
        Ok(())
    }

    /// Increment the current round and return the new value
    pub async fn increment_round(&self) -> Result<u64> {
        let current = self.get_current_round().await?;
        let new_round = current + 1;
        self.set_current_round(new_round).await?;
        info!("✅ [CONSENSUS_STORAGE] Incremented round from {} to {}", current, new_round);
        Ok(new_round)
    }

    /// Clean up old consensus data (keep only last N rounds)
    pub async fn cleanup_old_rounds(&self, keep_rounds: u64) -> Result<()> {
        let current_round = self.get_current_round().await?;
        
        if current_round <= keep_rounds {
            debug!("🧹 [CONSENSUS_STORAGE] No old rounds to clean up (current: {}, keep: {})", current_round, keep_rounds);
            return Ok(());
        }
        
        let cleanup_before = current_round - keep_rounds;
        let mut deleted_count = 0;
        
        // Clean up selected nodes
        let selected_nodes_prefix = crate::database::keys::SELECTED_NODES;
        let selected_keys = self.db.get_keys_with_prefix(selected_nodes_prefix)?;
        for key in selected_keys {
            if let Some(round_str) = key.strip_prefix(selected_nodes_prefix) {
                if let Ok(round) = round_str.parse::<u64>() {
                    if round < cleanup_before {
                        self.db.delete_string(&key)?;
                        deleted_count += 1;
                    }
                }
            }
        }
        
        // Clean up consensus results
        let results_prefix = crate::database::keys::CONSENSUS_RESULT;
        let result_keys = self.db.get_keys_with_prefix(results_prefix)?;
        for key in result_keys {
            if let Some(round_str) = key.strip_prefix(results_prefix) {
                if let Ok(round) = round_str.parse::<u64>() {
                    if round < cleanup_before {
                        self.db.delete_string(&key)?;
                        deleted_count += 1;
                    }
                }
            }
        }
        
        info!("🧹 [CONSENSUS_STORAGE] Cleaned up {} old consensus records (kept last {} rounds)", deleted_count, keep_rounds);
        Ok(())
    }

    /// Get consensus statistics
    pub async fn get_consensus_stats(&self) -> Result<ConsensusStats> {
        let current_round = self.get_current_round().await?;
        let all_results = self.get_all_consensus_results().await?;
        let all_selected_nodes = self.get_all_selected_nodes_by_round().await?;
        
        let total_rounds = all_results.len() as u64;
        let total_selected_rounds = all_selected_nodes.len() as u64;
        
        // Calculate average nodes per round
        let total_nodes: usize = all_selected_nodes.values().map(|nodes| nodes.len()).sum();
        let avg_nodes_per_round = if total_selected_rounds > 0 {
            total_nodes as f64 / total_selected_rounds as f64
        } else {
            0.0
        };
        
        let stats = ConsensusStats {
            current_round,
            total_consensus_rounds: total_rounds,
            total_selection_rounds: total_selected_rounds,
            average_nodes_per_round: avg_nodes_per_round,
        };
        
        debug!("📊 [CONSENSUS_STORAGE] Generated consensus stats: {:?}", stats);
        Ok(stats)
    }
}

/// Consensus statistics
#[derive(Debug, Clone)]
pub struct ConsensusStats {
    pub current_round: u64,
    pub total_consensus_rounds: u64,
    pub total_selection_rounds: u64,
    pub average_nodes_per_round: f64,
}
