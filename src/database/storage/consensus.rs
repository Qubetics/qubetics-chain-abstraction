use crate::database::{ConsensusResultKey, CurrentRoundKey, Database, KvStorage, SelectedNodesKey, SELECTED_NODES_PREFIX, CONSENSUS_RESULT_PREFIX};
use crate::consensus::ConsensusResult;
use crate::types::p2p::SerializablePeerId;
use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, debug};

use rocksdb::DB;
use std::sync::Arc;


/// Database-backed consensus storage
#[derive(Clone)]
pub struct ConsensusStorage {
    db: Database,
}


impl KvStorage for ConsensusStorage {
    fn db(&self) -> &Arc<DB> {
        self.db.db()
    }
}



impl ConsensusStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store selected nodes for a specific round
    pub async fn store_selected_nodes(&self, round: u64, selected_nodes: &[SerializablePeerId]) -> Result<()> {
        let key = SelectedNodesKey { round};
        self.put(key, &selected_nodes.to_vec())?;
        info!("✅ [CONSENSUS_STORAGE] Stored {} selected nodes for round: {}", selected_nodes.len(), round);
        Ok(())
    }

    /// Get selected nodes for a specific round
    pub async fn get_selected_nodes(&self, round: u64) -> Result<Option<Vec<SerializablePeerId>>> {
        let key = SelectedNodesKey { round};

        let nodes = self.get(key)?;
        if nodes.is_some() {
            debug!("🔍 [CONSENSUS_STORAGE] Retrieved selected nodes for round: {}", round);
        }
        Ok(nodes)
    }

    /// Get all selected nodes by round
    pub async fn get_all_selected_nodes_by_round(&self) -> Result<HashMap<u64, Vec<SerializablePeerId>>> {
        let mut selected_nodes = HashMap::new();
        let iter = self.db.db().prefix_iterator(SELECTED_NODES_PREFIX);
        for item in iter {
            let (key, value) = item?;
            if let Ok(nodes) = bincode::deserialize::<Vec<SerializablePeerId>>(&value) {
                let round_bytes = &key[SELECTED_NODES_PREFIX.len()..];
                if round_bytes.len() == 8 {
                    let round = u64::from_be_bytes(round_bytes.try_into().unwrap());
                    selected_nodes.insert(round, nodes);
                }
            }
        }

        debug!(
            "🔍 [CONSENSUS_STORAGE] Retrieved selected nodes for {} rounds",
            selected_nodes.len()
        );
        Ok(selected_nodes)
    }

    /// Store a consensus result for a specific round
    pub async fn store_consensus_result(&self, round: u64, result: &ConsensusResult) -> Result<()> {
        let key = ConsensusResultKey { round};
        self.put(key, result)?;
        info!("✅ [CONSENSUS_STORAGE] Stored consensus result for round: {}", round);
        Ok(())
    }

    /// Get a consensus result for a specific round
    pub async fn get_consensus_result(&self, round: u64) -> Result<Option<ConsensusResult>> {
        let key = ConsensusResultKey {round};

        let result = self.get(key)?;
        if result.is_some() {
            debug!("🔍 [CONSENSUS_STORAGE] Retrieved consensus result for round: {}", round);
        }
        Ok(result)
    }

    /// Get all consensus results by round
    pub async fn get_all_consensus_results(&self) -> Result<HashMap<u64, ConsensusResult>> {
        let mut consensus_results = HashMap::new();
        let iter = self.db.db().prefix_iterator(CONSENSUS_RESULT_PREFIX);
        for item in iter {
            let (key, value) = item?;
            if let Ok(result) = bincode::deserialize::<ConsensusResult>(&value) {
                let round_bytes = &key[CONSENSUS_RESULT_PREFIX.len()..];
                if round_bytes.len() == 8 {
                    let round = u64::from_be_bytes(round_bytes.try_into().unwrap());
                    consensus_results.insert(round, result);
                }
            }
        }
        debug!(
            "🔍 [CONSENSUS_STORAGE] Retrieved consensus results for {} rounds",
            consensus_results.len()
        );
        Ok(consensus_results)
    }

    /// Delete selected nodes for a specific round
    pub async fn delete_selected_nodes(&self, round: u64) -> Result<()> {
        let key = SelectedNodesKey { round};
        self.delete(key)?;
        info!("🗑️ [CONSENSUS_STORAGE] Deleted selected nodes for round: {}", round);
        Ok(())
    }

    /// Delete consensus result for a specific round
    pub async fn delete_consensus_result(&self, round: u64) -> Result<()> {
        let key = ConsensusResultKey { round };
        self.delete(key)?;
        info!("🗑️ [CONSENSUS_STORAGE] Deleted consensus result for round: {}", round);
        Ok(())
    }

    /// Get the current round number (stored as metadata)
    pub async fn get_current_round(&self) -> Result<u64> {
        let key = CurrentRoundKey{};
        match self.get::<_, u64>(key)? {
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
        let key = CurrentRoundKey{};
        self.put(key, &round)?;
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
            debug!(
                "🧹 [CONSENSUS_STORAGE] No old rounds to clean up (current: {}, keep: {})",
                current_round, keep_rounds
            );
            return Ok(());
        }

        let cleanup_before = current_round - keep_rounds;
        let mut deleted_count = 0;

        // Clean up selected nodes
        let iter_nodes = self.db.db().prefix_iterator(SELECTED_NODES_PREFIX);
        for item in iter_nodes {
            let (key, _) = item?;
            let round_bytes = &key[SELECTED_NODES_PREFIX.len()..];
            if round_bytes.len() == 8 {
                let round = u64::from_be_bytes(round_bytes.try_into().unwrap());
                if round < cleanup_before {
                    self.db.db().delete(&key)?;
                    deleted_count += 1;
                }
            }
        }

        // Clean up consensus results
        let iter_results = self.db.db().prefix_iterator(CONSENSUS_RESULT_PREFIX);
        for item in iter_results {
            let (key, _) = item?;
            let round_bytes = &key[CONSENSUS_RESULT_PREFIX.len()..];
            if round_bytes.len() == 8 {
                let round = u64::from_be_bytes(round_bytes.try_into().unwrap());
                if round < cleanup_before {
                    self.db.db().delete(&key)?;
                    deleted_count += 1;
                }
            }
        }

        info!(
            "🧹 [CONSENSUS_STORAGE] Cleaned up {} old consensus records (kept last {} rounds)",
            deleted_count, keep_rounds
        );
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
