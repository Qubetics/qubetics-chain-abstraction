use crate::{
	consensus::ConsensusResult,
	database::{
		ConsensusResultKey, CurrentRoundKey, Database, KvStorage, SelectedNodesKey,
		CONSENSUS_RESULT_PREFIX, CURRENT_ROUND_PREFIX, SELECTED_NODES_PREFIX,
	},
	define_storage,
	types::p2p::SerializablePeerId,
};
use anyhow::Result;
use rocksdb::DB;
use std::{collections::HashMap, convert::TryInto, sync::Arc};
use tracing::{debug, info};

define_storage!(
	ConsensusResultStorage,
	ConsensusResultKey,
	ConsensusResult,
	CONSENSUS_RESULT_PREFIX
);

define_storage!(
	SelectedNodesStorage,
	SelectedNodesKey,
	Vec<SerializablePeerId>,
	SELECTED_NODES_PREFIX
);

define_storage!(CurrentRoundStorage, CurrentRoundKey, u64, CURRENT_ROUND_PREFIX);

#[derive(Clone)]
pub struct ConsensusStorage {
	consensus_results: ConsensusResultStorage,
	selected_nodes: SelectedNodesStorage,
	consensus_round: CurrentRoundStorage,
}

impl ConsensusStorage {
	pub fn new(db: Database) -> Self {
		Self {
			consensus_results: ConsensusResultStorage::new(db.clone()),
			selected_nodes: SelectedNodesStorage::new(db.clone()),
			consensus_round: CurrentRoundStorage::new(db.clone()),
		}
	}

	/// Store selected nodes for a specific round
	pub async fn store_selected_nodes(
		&self,
		round: u64,
		selected_nodes: &[SerializablePeerId],
	) -> Result<()> {
		info!(
			"✅ [CONSENSUS_STORAGE] Stored {} selected nodes for round: {}",
			selected_nodes.len(),
			round
		);
		self.selected_nodes.put(SelectedNodesKey { round }, &selected_nodes.to_vec());
		Ok(())
	}

	/// Get selected nodes for a specific round
	pub async fn get_selected_nodes(&self, round: u64) -> Result<Option<Vec<SerializablePeerId>>> {
		let key = SelectedNodesKey { round };

		let nodes = self.selected_nodes.get(key)?;
		if nodes.is_some() {
			debug!("🔍 [CONSENSUS_STORAGE] Retrieved selected nodes for round: {}", round);
		}
		Ok(nodes)
	}

	pub async fn get_all_selected_nodes_by_round(
		&self,
	) -> Result<HashMap<u64, Vec<SerializablePeerId>>> {
		let selected_nodes = self.selected_nodes.get_all_by_key()?;

		debug!(
			"🔍 [CONSENSUS_STORAGE] Retrieved selected nodes for {} rounds",
			selected_nodes.len()
		);
		Ok(selected_nodes
			.into_iter()
			.map(|(key, value)| (u64::from_be_bytes(key.try_into().unwrap()), value))
			.collect())
	}

	/// Store a consensus result for a specific round
	pub async fn store_consensus_result(&self, round: u64, result: &ConsensusResult) -> Result<()> {
		let key = ConsensusResultKey { round };
		self.consensus_results.put(key, result)?;
		info!("✅ [CONSENSUS_STORAGE] Stored consensus result for round: {}", round);
		Ok(())
	}

	/// Get a consensus result for a specific round
	pub async fn get_consensus_result(&self, round: u64) -> Result<Option<ConsensusResult>> {
		let key = ConsensusResultKey { round };

		let result = self.consensus_results.get(key)?;
		if result.is_some() {
			debug!("🔍 [CONSENSUS_STORAGE] Retrieved consensus result for round: {}", round);
		}
		Ok(result)
	}

	/// Get all consensus results by round
	pub async fn get_all_consensus_results(&self) -> Result<HashMap<u64, ConsensusResult>> {
		let consensus_results = self.consensus_results.get_all()?;
		debug!(
			"🔍 [CONSENSUS_STORAGE] Retrieved consensus results for {} rounds",
			consensus_results.len()
		);
		Ok(consensus_results
			.into_iter()
			.map(|(key, value)| {
				(u64::from_be_bytes(key.try_into().expect("Key must be 8 bytes")), value)
			})
			.collect())
	}

	/// Delete selected nodes for a specific round
	pub async fn delete_selected_nodes(&self, round: u64) -> Result<()> {
		let key = SelectedNodesKey { round };
		self.selected_nodes.delete(key)?;
		info!("🗑️ [CONSENSUS_STORAGE] Deleted selected nodes for round: {}", round);
		Ok(())
	}

	/// Delete consensus result for a specific round
	pub async fn delete_consensus_result(&self, round: u64) -> Result<()> {
		let key = ConsensusResultKey { round };
		self.consensus_results.delete(key)?;
		info!("🗑️ [CONSENSUS_STORAGE] Deleted consensus result for round: {}", round);
		Ok(())
	}

	/// Get the current round number (stored as metadata)
	pub async fn get_current_round(&self) -> Result<u64> {
		let key = CurrentRoundKey {};
		Ok(self.consensus_round.get(key)?.unwrap_or(0))
	}

	/// Set the current round number
	pub async fn set_current_round(&self, round: u64) -> Result<()> {
		let key = CurrentRoundKey {};
		self.consensus_round.put(key, &round)?;
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
