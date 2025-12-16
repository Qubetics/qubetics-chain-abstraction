use crate::types::p2p::SerializablePeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Sequencer type for deterministic selection
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SequencerType {
    /// Main sequencer group (S_main)
    Main,
    /// Vault sequencer group (S_vault)
    Vault,
}

impl SequencerType {
    /// Get the domain tag for seed derivation
    pub fn domain_tag(&self) -> &'static str {
        match self {
            SequencerType::Main => "MAIN",
            SequencerType::Vault => "VAULT",
        }
    }
}

/// Per-round seed for deterministic node selection
/// Derived from: H(domain_tag || prev_block_hash || round)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSeed {
    pub sequencer_type: SequencerType,
    pub round: u64,
    pub seed_hash: Vec<u8>,
}

impl RoundSeed {
    /// Derive a new round seed from the previous block hash and round number
    pub fn derive(
        sequencer_type: SequencerType,
        prev_block_hash: &[u8],
        round: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        
        // Domain separation: H("MAIN" || prev_block_hash || r) or H("VAULT" || prev_block_hash || r)
        hasher.update(sequencer_type.domain_tag().as_bytes());
        hasher.update(prev_block_hash);
        hasher.update(round.to_be_bytes());
        
        let seed_hash = hasher.finalize().to_vec();
        
        Self {
            sequencer_type,
            round,
            seed_hash,
        }
    }
    
    /// Get seed as u64 for modulo operations
    pub fn as_u64(&self) -> u64 {
        // Take first 8 bytes of hash and convert to u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.seed_hash[..8]);
        u64::from_be_bytes(bytes)
    }
}

/// Deterministic final node selection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalNodeSelection {
    pub sequencer_type: SequencerType,
    pub round: u64,
    pub selected_node: SerializablePeerId,
    pub seed: RoundSeed,
    pub total_available_nodes: usize,
}

impl FinalNodeSelection {
    /// Select the final node deterministically from the available nodes
    /// All honest nodes will derive the same result
    pub fn select(
        sequencer_type: SequencerType,
        round: u64,
        prev_block_hash: &[u8],
        available_nodes: &[SerializablePeerId],
    ) -> anyhow::Result<Self> {
        if available_nodes.is_empty() {
            anyhow::bail!("Cannot select final node from empty node list");
        }
        
        // Derive the per-sequencer seed
        let seed = RoundSeed::derive(sequencer_type, prev_block_hash, round);
        
        // Deterministic selection: idx = H(R_seq(r)) mod |Nodes_seq|
        let idx = (seed.as_u64() as usize) % available_nodes.len();
        let selected_node = available_nodes[idx].clone();
        
        Ok(Self {
            sequencer_type,
            round,
            selected_node,
            seed,
            total_available_nodes: available_nodes.len(),
        })
    }
}

/// Request selection policy for deterministic request picking
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RequestSelectionPolicy {
    /// Select request with lowest hash value
    LowestHash,
    /// Select request with earliest arrival time
    EarliestArrival,
    /// Select request with highest fee
    HighestFee,
}

impl Default for RequestSelectionPolicy {
    fn default() -> Self {
        RequestSelectionPolicy::LowestHash
    }
}

/// Request metadata for deterministic selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub request_id: String,
    pub arrival_timestamp: u128,
    pub fee: u128,
}

impl RequestMetadata {
    /// Get the hash of the request ID for deterministic ordering
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.request_id.as_bytes());
        hasher.finalize().to_vec()
    }
    
    /// Select the best request according to the policy
    pub fn select_best<'a>(
        requests: &'a [RequestMetadata],
        policy: RequestSelectionPolicy,
    ) -> Option<&'a RequestMetadata> {
        if requests.is_empty() {
            return None;
        }
        
        match policy {
            RequestSelectionPolicy::LowestHash => {
                requests.iter().min_by(|a, b| a.hash().cmp(&b.hash()))
            }
            RequestSelectionPolicy::EarliestArrival => {
                requests.iter().min_by_key(|r| r.arrival_timestamp)
            }
            RequestSelectionPolicy::HighestFee => {
                requests.iter().max_by_key(|r| r.fee)
            }
        }
    }
}

/// Message broadcast by the final node to select a request for processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectRequestMessage {
    /// Type of sequencer (main or vault)
    pub sequencer_type: SequencerType,
    /// Round number for this selection
    pub round: u64,
    /// The request ID chosen by the final node
    pub request_id: String,
    /// Signature from the final node attesting to selection
    pub signature: Vec<u8>,
    /// Public key of the final node (for verification)
    pub final_node_pubkey: Vec<u8>,
    /// Final node ID
    pub final_node_id: SerializablePeerId,
    /// Timestamp when selection was made
    pub timestamp: u128,
}

impl SelectRequestMessage {
    /// Create a new select request message
    pub fn new(
        sequencer_type: SequencerType,
        round: u64,
        request_id: String,
        final_node_id: SerializablePeerId,
        final_node_pubkey: Vec<u8>,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
            
        Self {
            sequencer_type,
            round,
            request_id,
            signature: Vec::new(), // To be filled by signing
            final_node_pubkey,
            final_node_id,
            timestamp,
        }
    }
    
    /// Get the message bytes for signing
    pub fn message_for_signing(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.sequencer_type.domain_tag().as_bytes());
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.final_node_id.0.to_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.finalize().to_vec()
    }
}

/// Deterministic selection state per sequencer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerSelectionState {
    /// Current round number for this sequencer
    pub current_round: u64,
    /// Last finalized block hash used for seed derivation
    pub last_block_hash: Vec<u8>,
    /// Currently selected request ID (locked in for this round)
    pub locked_request: Option<String>,
    /// Final node for current round
    pub current_final_node: Option<SerializablePeerId>,
    /// Selection policy for this sequencer
    pub selection_policy: RequestSelectionPolicy,
}

impl SequencerSelectionState {
    pub fn new(selection_policy: RequestSelectionPolicy) -> Self {
        Self {
            current_round: 0,
            last_block_hash: vec![0u8; 32], // Genesis hash
            locked_request: None,
            current_final_node: None,
            selection_policy,
        }
    }
    
    /// Advance to the next round
    pub fn advance_round(&mut self, new_block_hash: Vec<u8>) {
        self.current_round += 1;
        self.last_block_hash = new_block_hash;
        self.locked_request = None;
        self.current_final_node = None;
    }
}

/// Result of deterministic request selection process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicSelectionResult {
    pub sequencer_type: SequencerType,
    pub round: u64,
    pub final_node: SerializablePeerId,
    pub selected_request_id: String,
    pub available_nodes: Vec<SerializablePeerId>,
}

/// Gossipsub message for deterministic selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeterministicSelectionMessage {
    /// Final node broadcasts its request selection
    SelectRequest(SelectRequestMessage),
    /// Node acknowledges receipt and processing of selected request
    AckRequest {
        sequencer_type: SequencerType,
        round: u64,
        request_id: String,
        node_id: SerializablePeerId,
    },
    /// Node reports it's missing the selected request (needs fetch)
    MissingRequest {
        sequencer_type: SequencerType,
        round: u64,
        request_id: String,
        node_id: SerializablePeerId,
    },
}

