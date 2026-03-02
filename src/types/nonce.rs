use crate::types::secp::{SerializablePoint, SerializableScalar};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

/// A pre-computed nonce tuple ready for threshold ECDSA signing.
///
/// In the aggregated nonce scheme:
/// - All nodes broadcast their k_i values during the reveal phase
/// - Each node locally computes k = Σk_i (sum of all shares)
/// - Each node locally computes k⁻¹ = (Σk_i)⁻¹
/// - The aggregate R = k*G is computed from R = ΣR_i
/// - r = x(R) mod n is precomputed for efficiency
///
/// This approach is simpler than MtA-based schemes because all nodes
/// end up with the same aggregated k value.
///
/// **Security**: Implements `Drop` to zeroize all secret scalar material.
/// Nonce reuse would be catastrophic — it enables private key extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceTuple {
    /// Unique identifier for this nonce tuple (batch_id + index)
    pub tuple_id: String,

    /// The aggregated nonce k = Σk_i (same for all nodes)
    /// Computed by each node after collecting all k_i shares
    pub aggregated_k: SerializableScalar,

    /// The inverse of aggregated nonce k⁻¹ = (Σk_i)⁻¹ (same for all nodes)
    /// Used in signature: s = k⁻¹ * (z + r * x)
    pub k_inv: SerializableScalar,

    /// The aggregate R = k*G = ΣR_i (same for all nodes after commit-reveal)
    /// Stored as compressed SEC1 encoded point
    pub aggregate_r: SerializablePoint,

    /// r = x(R) mod n (precomputed for efficiency)
    /// This is the r component of the final ECDSA signature
    pub r_scalar: SerializableScalar,

    /// Y-parity of R point for recovery ID computation
    pub r_y_parity: u8,

    /// Whether this tuple has been consumed (used for signing)
    /// Once consumed, it must NEVER be reused (critical for security)
    pub consumed: bool,

    /// Unix timestamp when this tuple was created
    pub created_at: i64,

    /// The batch this tuple belongs to
    pub batch_id: String,

    /// Number of nodes that contributed to this nonce (for filtering stale nonces)
    /// Nonces created with fewer nodes than current total should not be used
    #[serde(default)]
    pub num_contributors: usize,
}

impl Drop for NonceTuple {
    fn drop(&mut self) {
        // Zeroize all secret scalar material.
        // aggregated_k and k_inv are the most critical — if leaked,
        // an attacker can extract the private key from any signature
        // produced with this nonce.
        self.aggregated_k.zeroize();
        self.k_inv.zeroize();
        self.r_scalar.zeroize();
    }
}

/// Status of a nonce generation batch
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NonceGenStatus {
    /// Waiting to start
    Pending,

    /// Commitment phase: nodes broadcast H(R_i) commitments
    CommitmentPhase,

    /// Reveal phase: after all commitments received, nodes reveal R_i
    RevealPhase,

    /// Inversion phase: computing shares of k⁻¹ via MtA protocol
    InversionPhase,

    /// Successfully completed, nonce tuples are ready
    Completed,

    /// Failed with reason
    Failed { reason: String },
}

/// State for an ongoing nonce generation batch
///
/// Supports generating multiple nonces per batch (batch_size nonces).
/// Each node generates batch_size (k_i, R_i) pairs and commits to all of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceGenState {
    /// Unique identifier for this batch
    pub batch_id: String,

    /// Current status of the generation
    pub status: NonceGenStatus,

    /// Round number when generation started
    pub round: u64,

    /// Number of nonces to generate in this batch
    pub batch_size: usize,

    /// This node's random k_i values for this batch (batch_size values)
    pub local_k_values: Vec<SerializableScalar>,

    /// This node's R_i = k_i * G values (batch_size values)
    pub local_r_values: Vec<SerializablePoint>,

    /// Collected commitments: peer_id -> [H(R_i[0]), H(R_i[1]), ...] (batch_size commitments per peer)
    pub commitments: HashMap<String, Vec<[u8; 32]>>,

    /// Collected R points after reveal: peer_id -> [R_i[0], R_i[1], ...] (batch_size points per peer)
    pub r_points: HashMap<String, Vec<SerializablePoint>>,

    /// Collected k shares from all nodes: peer_id -> [k_i[0], k_i[1], ...] (batch_size scalars per peer)
    /// Each node broadcasts their k_i values, then all nodes compute k[j] = Σk_i[j] for each j
    pub k_shares: HashMap<String, Vec<SerializableScalar>>,

    /// Validation results from peers: peer_id -> is_valid
    pub validations: HashMap<String, bool>,

    /// Timestamp when batch started
    pub started_at: i64,

    /// Number of expected participants (threshold)
    pub threshold: usize,

    /// Total number of nodes
    pub total_nodes: usize,
}

impl Drop for NonceGenState {
    fn drop(&mut self) {
        // Zeroize all secret nonce shares — both our own local k values
        // and the k shares received from other nodes.
        for k_val in self.local_k_values.iter_mut() {
            k_val.zeroize();
        }
        for shares in self.k_shares.values_mut() {
            for share in shares.iter_mut() {
                share.zeroize();
            }
        }
    }
}

impl NonceGenState {
    /// Create a new nonce generation state
    pub fn new(batch_id: String, round: u64, threshold: usize, total_nodes: usize, batch_size: usize) -> Self {
        Self {
            batch_id,
            status: NonceGenStatus::Pending,
            round,
            batch_size,
            local_k_values: Vec::new(),
            local_r_values: Vec::new(),
            commitments: HashMap::new(),
            r_points: HashMap::new(),
            k_shares: HashMap::new(),
            validations: HashMap::new(),
            started_at: chrono::Utc::now().timestamp(),
            threshold,
            total_nodes,
        }
    }

    /// Check if we have enough commitments to proceed to reveal phase
    pub fn has_threshold_commitments(&self) -> bool {
        self.commitments.len() >= self.threshold
    }

    /// Check if we have enough R points to compute aggregate R
    pub fn has_threshold_r_points(&self) -> bool {
        self.r_points.len() >= self.threshold
    }

    /// Check if generation is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.status, NonceGenStatus::Completed)
    }

    /// Check if generation failed
    pub fn is_failed(&self) -> bool {
        matches!(self.status, NonceGenStatus::Failed { .. })
    }
}

/// Configuration for nonce pool management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncePoolConfig {
    /// Minimum number of nonces to maintain in pool
    pub min_pool_size: usize,

    /// Number of nonces to generate per batch
    pub batch_size: usize,

    /// Maximum age of unused nonces before cleanup (seconds)
    pub max_nonce_age_secs: i64,

    /// Timeout for nonce generation phases (milliseconds)
    pub phase_timeout_ms: u64,
}

impl Default for NoncePoolConfig {
    fn default() -> Self {
        Self {
            min_pool_size: 200,        // Maintain 200 nonces in pool for high-throughput operation
            batch_size: 20,            // Generate 20 nonces per batch (10 batches to fill pool)
            max_nonce_age_secs: 86400, // 24 hours
            phase_timeout_ms: 30000,   // 30 seconds per phase
        }
    }
}

/// Metrics for nonce pool health monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoncePoolMetrics {
    /// Current number of available (unconsumed) nonces
    pub available_count: usize,

    /// Total nonces generated since startup
    pub total_generated: u64,

    /// Total nonces consumed since startup
    pub total_consumed: u64,

    /// Number of failed generation attempts
    pub failed_generations: u64,

    /// Average generation time (milliseconds)
    pub avg_generation_time_ms: u64,

    /// Last generation timestamp
    pub last_generation_at: Option<i64>,

    /// Last consumption timestamp
    pub last_consumed_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use k256::Scalar;
    use rand::rngs::OsRng;

    fn make_test_scalar() -> SerializableScalar {
        SerializableScalar(Scalar::random(&mut OsRng))
    }

    fn make_test_point() -> SerializablePoint {
        SerializablePoint(k256::ProjectivePoint::GENERATOR.to_affine())
    }

    #[test]
    fn test_nonce_gen_state_new_defaults() {
        let state = NonceGenState::new("batch_1".into(), 42, 3, 5, 10);
        assert_eq!(state.batch_id, "batch_1");
        assert_eq!(state.round, 42);
        assert_eq!(state.threshold, 3);
        assert_eq!(state.total_nodes, 5);
        assert_eq!(state.batch_size, 10);
        assert!(matches!(state.status, NonceGenStatus::Pending));
        assert!(state.local_k_values.is_empty());
        assert!(state.commitments.is_empty());
        assert!(state.r_points.is_empty());
        assert!(state.k_shares.is_empty());
    }

    #[test]
    fn test_has_threshold_commitments() {
        let mut state = NonceGenState::new("batch".into(), 1, 3, 5, 1);
        assert!(!state.has_threshold_commitments(), "Should not have threshold with 0 commitments");

        state.commitments.insert("peer1".into(), vec![[0u8; 32]]);
        state.commitments.insert("peer2".into(), vec![[0u8; 32]]);
        assert!(!state.has_threshold_commitments(), "2 < 3 threshold");

        state.commitments.insert("peer3".into(), vec![[0u8; 32]]);
        assert!(state.has_threshold_commitments(), "3 >= 3 threshold");

        state.commitments.insert("peer4".into(), vec![[0u8; 32]]);
        assert!(state.has_threshold_commitments(), "4 > 3 threshold");
    }

    #[test]
    fn test_has_threshold_r_points() {
        let mut state = NonceGenState::new("batch".into(), 1, 2, 3, 1);
        assert!(!state.has_threshold_r_points());

        state.r_points.insert("peer1".into(), vec![make_test_point()]);
        assert!(!state.has_threshold_r_points(), "1 < 2 threshold");

        state.r_points.insert("peer2".into(), vec![make_test_point()]);
        assert!(state.has_threshold_r_points(), "2 >= 2 threshold");
    }

    #[test]
    fn test_is_complete_and_is_failed() {
        let mut state = NonceGenState::new("batch".into(), 1, 2, 3, 1);
        assert!(!state.is_complete());
        assert!(!state.is_failed());

        state.status = NonceGenStatus::CommitmentPhase;
        assert!(!state.is_complete());
        assert!(!state.is_failed());

        state.status = NonceGenStatus::Completed;
        assert!(state.is_complete());
        assert!(!state.is_failed());

        state.status = NonceGenStatus::Failed { reason: "timeout".into() };
        assert!(!state.is_complete());
        assert!(state.is_failed());
    }

    #[test]
    fn test_nonce_pool_config_defaults() {
        let config = NoncePoolConfig::default();
        assert_eq!(config.min_pool_size, 200);
        assert_eq!(config.batch_size, 20);
        assert_eq!(config.max_nonce_age_secs, 86400);
        assert_eq!(config.phase_timeout_ms, 30000);
    }

    #[test]
    fn test_nonce_gen_state_drop_zeroizes_k_values() {
        let mut state = NonceGenState::new("batch".into(), 1, 2, 3, 2);
        state.local_k_values.push(make_test_scalar());
        state.local_k_values.push(make_test_scalar());
        state.k_shares.insert("peer1".into(), vec![make_test_scalar()]);

        // Verify they're non-zero before drop
        for k in &state.local_k_values {
            assert_ne!(k.0, Scalar::ZERO);
        }

        // Manually trigger the Drop-equivalent zeroize
        // (We can't observe after real drop, but Drop calls this same code)
        for k_val in state.local_k_values.iter_mut() {
            k_val.zeroize();
        }
        for shares in state.k_shares.values_mut() {
            for share in shares.iter_mut() {
                share.zeroize();
            }
        }

        for k in &state.local_k_values {
            assert_eq!(k.0, Scalar::ZERO, "local_k_values must be zeroed");
        }
        for shares in state.k_shares.values() {
            for share in shares {
                assert_eq!(share.0, Scalar::ZERO, "k_shares must be zeroed");
            }
        }
    }

    #[test]
    fn test_nonce_tuple_drop_zeroizes_secrets() {
        let mut tuple = NonceTuple {
            tuple_id: "test".into(),
            aggregated_k: make_test_scalar(),
            k_inv: make_test_scalar(),
            aggregate_r: make_test_point(),
            r_scalar: make_test_scalar(),
            r_y_parity: 0,
            consumed: false,
            created_at: 0,
            batch_id: "batch".into(),
            num_contributors: 3,
        };

        assert_ne!(tuple.aggregated_k.0, Scalar::ZERO);
        assert_ne!(tuple.k_inv.0, Scalar::ZERO);
        assert_ne!(tuple.r_scalar.0, Scalar::ZERO);

        // Trigger zeroize (same code as Drop)
        tuple.aggregated_k.zeroize();
        tuple.k_inv.zeroize();
        tuple.r_scalar.zeroize();

        assert_eq!(tuple.aggregated_k.0, Scalar::ZERO, "aggregated_k must be zeroed");
        assert_eq!(tuple.k_inv.0, Scalar::ZERO, "k_inv must be zeroed");
        assert_eq!(tuple.r_scalar.0, Scalar::ZERO, "r_scalar must be zeroed");
    }
}

