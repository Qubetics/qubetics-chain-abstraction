//! Message handlers for nonce protocol
//!
//! This module contains helper functions for processing nonce protocol messages.
//! The main protocol logic is in mod.rs; these are utility functions.

use crate::types::nonce::{NonceGenState, NonceGenStatus};
use crate::types::secp::SerializablePoint;
use anyhow::Result;
use k256::AffinePoint;
use tracing::{info, warn};

/// Result of processing a nonce message
#[derive(Debug)]
pub enum NonceMessageResult {
    /// Message processed, no action needed
    Processed,

    /// Ready to move to reveal phase
    ReadyForReveal { batch_id: String },

    /// Ready to compute aggregate R
    ReadyForAggregation {
        batch_id: String,
        r_points: Vec<Vec<AffinePoint>>,
    },

    /// Generation complete
    Complete { batch_id: String },

    /// Error occurred
    Error { batch_id: String, reason: String },
}

/// Handler for batch nonce commitment messages
///
/// Each peer sends batch_size commitments
pub fn handle_batch_commitment(
    state: &mut NonceGenState,
    from: &str,
    commitments: Vec<[u8; 32]>,
    threshold: usize,
) -> NonceMessageResult {
    // Only accept commitments in commitment phase
    if state.status != NonceGenStatus::CommitmentPhase && state.status != NonceGenStatus::Pending {
        warn!(
            "⚠️ [NONCE_HANDLER] Received commitment in wrong phase: {:?}",
            state.status
        );
        return NonceMessageResult::Processed;
    }

    // Store all commitments from this peer
    state.commitments.insert(from.to_string(), commitments);

    info!(
        "📥 [NONCE_HANDLER] Stored {} commitments from {} ({}/{} peers received)",
        state.batch_size,
        from,
        state.commitments.len(),
        threshold
    );

    // Check if we have threshold peers
    if state.commitments.len() >= threshold {
        state.status = NonceGenStatus::RevealPhase;
        info!(
            "✅ [NONCE_HANDLER] Threshold commitments reached for batch {}",
            state.batch_id
        );
        return NonceMessageResult::ReadyForReveal {
            batch_id: state.batch_id.clone(),
        };
    }

    NonceMessageResult::Processed
}

/// Validate that a set of R points are all valid curve points
pub fn validate_r_points(r_points: &[SerializablePoint]) -> Result<Vec<AffinePoint>> {
    let mut validated = Vec::with_capacity(r_points.len());

    for (i, point) in r_points.iter().enumerate() {
        // Check that point is on curve (SerializablePoint ensures this)
        // and is not the identity
        if point.0 == AffinePoint::IDENTITY {
            return Err(anyhow::anyhow!("R point {} is identity (invalid)", i));
        }
        validated.push(point.0);
    }

    Ok(validated)
}

/// Check if a batch has timed out
pub fn check_batch_timeout(state: &NonceGenState, timeout_secs: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    (now - state.started_at) > timeout_secs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::secp::SerializableScalar;
    use ff::Field;
    use k256::{ProjectivePoint, Scalar};
    use rand::rngs::OsRng;

    #[test]
    fn test_batch_commitment_handling() {
        let batch_size = 10;
        let mut state = NonceGenState::new("test_batch".to_string(), 1, 2, 3, batch_size);
        state.status = NonceGenStatus::CommitmentPhase;

        // Create batch_size commitments
        let commitments: Vec<[u8; 32]> = (0..batch_size).map(|i| {
            let mut c = [0u8; 32];
            c[0] = i as u8;
            c
        }).collect();

        let result = handle_batch_commitment(&mut state, "peer1", commitments.clone(), 2);

        match result {
            NonceMessageResult::Processed => {
                assert_eq!(state.commitments.len(), 1);
                assert_eq!(state.commitments.get("peer1").unwrap().len(), batch_size);
            }
            _ => panic!("Expected Processed result"),
        }

        // Add second peer's commitments to reach threshold
        let result2 = handle_batch_commitment(&mut state, "peer2", commitments, 2);

        match result2 {
            NonceMessageResult::ReadyForReveal { batch_id } => {
                assert_eq!(batch_id, "test_batch");
                assert_eq!(state.status, NonceGenStatus::RevealPhase);
            }
            _ => panic!("Expected ReadyForReveal result"),
        }
    }

    #[test]
    fn test_validate_r_points() {
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);

        let r1 = SerializablePoint((ProjectivePoint::GENERATOR * k1).to_affine());
        let r2 = SerializablePoint((ProjectivePoint::GENERATOR * k2).to_affine());

        let validated = validate_r_points(&[r1, r2]).unwrap();
        assert_eq!(validated.len(), 2);
    }
}
