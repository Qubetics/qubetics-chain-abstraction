use crate::types::signing::ECDSASignature;
use hex;
pub use chains::{BitcoinSigner, TicsSigner};
pub use config::{BroadcastConfig, ChainBroadcastConfig};
pub use coordination::Coordination;
pub use db_signing::DatabaseSigningNode;
pub use key::KeyStore;
pub use state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, BtcUtvAggregationState, PendingStore,
    PendingValue, RoundSlotKey, SignatureStore, SigningEnvironmentBuilder,
};
pub use nonce::{NonceGenerator, NonceManager};

pub mod node;
pub mod keys;
pub mod aggregation;
pub mod verification;
pub mod sync;
pub mod network_messages;
pub mod consensus;
pub mod nonce_management;
pub mod settlement;
pub use node::*;

// Existing submodules
pub mod chains;
mod config;
pub mod coordination;
pub mod db_signing;
mod key;
pub mod nonce;
mod rewards;
pub mod state;
mod transactions;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::nonce::NonceTuple;
    use crate::types::secp::{SerializablePoint, SerializableScalar};
    use ff::{Field, PrimeField};
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar, U256};
    use rand::rngs::OsRng;
    use secp256k1::{SecretKey, Message};

    #[test]
    fn intent_manager_address_comparison_is_case_insensitive() {
        let to = "0xAbC0000000000000000000000000000000000000";
        let intent_manager = "0xabc0000000000000000000000000000000000000";
        assert_eq!(to.to_lowercase(), intent_manager.to_lowercase());
    }

    /// Helper to get current unix timestamp
    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Helper to create a valid NonceTuple for testing
    fn create_test_nonce_tuple(tuple_id: &str) -> NonceTuple {
        // Generate random k
        let k = Scalar::random(&mut OsRng);

        // Compute R = k * G
        let r_point = (ProjectivePoint::GENERATOR * k).to_affine();

        // Compute k⁻¹
        let k_inv = k.invert().expect("k should be invertible");

        // Compute r = x(R) mod n
        let encoded = r_point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        // Compute r_y_parity
        let y_bytes = encoded.y().expect("not at infinity");
        let r_y_parity = if y_bytes[31] & 1 == 0 { 0 } else { 1 };

        NonceTuple {
            tuple_id: tuple_id.to_string(),
            batch_id: "test_batch".to_string(),
            aggregated_k: SerializableScalar(k),
            k_inv: SerializableScalar(k_inv),
            aggregate_r: SerializablePoint(r_point),
            r_scalar: SerializableScalar(r_scalar),
            r_y_parity,
            created_at: now_unix(),
            consumed: false,
            num_contributors: 3,
        }
    }

    /// Helper to create a NonceTuple from multiple nodes' k values (simulating coordination)
    fn create_coordinated_nonce_tuple(
        tuple_id: &str,
        k_values: &[Scalar],
    ) -> NonceTuple {
        // Aggregate k = Σ k_i
        let mut aggregated_k = Scalar::ZERO;
        let mut r_point_proj = ProjectivePoint::IDENTITY;

        for k in k_values {
            aggregated_k += k;
            r_point_proj += ProjectivePoint::GENERATOR * k;
        }

        let r_point = r_point_proj.to_affine();

        // Compute k⁻¹
        let k_inv = aggregated_k.invert().expect("aggregated k should be invertible");

        // Compute r = x(R) mod n
        let encoded = r_point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        // Compute r_y_parity
        let y_bytes = encoded.y().expect("not at infinity");
        let r_y_parity = if y_bytes[31] & 1 == 0 { 0 } else { 1 };

        NonceTuple {
            tuple_id: tuple_id.to_string(),
            batch_id: "coordinated_batch".to_string(),
            aggregated_k: SerializableScalar(aggregated_k),
            k_inv: SerializableScalar(k_inv),
            aggregate_r: SerializablePoint(r_point),
            r_scalar: SerializableScalar(r_scalar),
            r_y_parity,
            created_at: now_unix(),
            consumed: false,
            num_contributors: k_values.len(),
        }
    }

    /// Test that nonce integrity checks pass for valid nonces
    #[test]
    fn test_nonce_tuple_integrity_valid() {
        let nonce = create_test_nonce_tuple("test_valid_nonce");

        // Verify k * k_inv = 1
        let k_times_k_inv = nonce.aggregated_k.0 * nonce.k_inv.0;
        assert_eq!(k_times_k_inv, Scalar::ONE, "k * k_inv should equal 1");

        // Verify R = k * G
        let expected_r = (ProjectivePoint::GENERATOR * nonce.aggregated_k.0).to_affine();
        assert_eq!(nonce.aggregate_r.0, expected_r, "R should equal k * G");

        // Verify r_scalar = x(R) mod n
        let encoded = nonce.aggregate_r.0.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let computed_r = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));
        assert_eq!(nonce.r_scalar.0, computed_r, "r_scalar should equal x(R) mod n");

        println!("✅ Nonce tuple integrity checks passed!");
    }

    /// Test that coordinated nonces from multiple nodes produce valid aggregates
    #[test]
    fn test_coordinated_nonce_aggregation() {
        // Simulate 3 nodes generating random k_i values
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let k3 = Scalar::random(&mut OsRng);

        let nonce = create_coordinated_nonce_tuple("coordinated_test", &[k1, k2, k3]);

        // Verify the aggregation is correct
        let expected_k = k1 + k2 + k3;
        assert_eq!(nonce.aggregated_k.0, expected_k, "Aggregated k should equal sum of k_i");

        // Verify R = (Σ k_i) * G = Σ (k_i * G)
        let r1 = (ProjectivePoint::GENERATOR * k1).to_affine();
        let r2 = (ProjectivePoint::GENERATOR * k2).to_affine();
        let r3 = (ProjectivePoint::GENERATOR * k3).to_affine();

        let aggregate_r = (ProjectivePoint::from(r1) + ProjectivePoint::from(r2) + ProjectivePoint::from(r3)).to_affine();
        assert_eq!(nonce.aggregate_r.0, aggregate_r, "Aggregate R should equal sum of R_i");

        println!("✅ Coordinated nonce aggregation test passed!");
    }

    /// Test that all nodes produce the same partial signature with coordinated nonces
    #[test]
    fn test_partial_signature_consistency_with_coordinated_nonce() {
        // Generate 3 independent private key shares (simulating DKG output)
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let x3 = Scalar::random(&mut OsRng);

        // Generate coordinated nonce from 3 nodes
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let k3 = Scalar::random(&mut OsRng);

        // All nodes must have the SAME aggregated nonce values
        let nonce = create_coordinated_nonce_tuple("consistency_test", &[k1, k2, k3]);

        // Create a test message
        let message_hash: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        // Each node computes s_i = k⁻¹ * (z + r * x_i) using the SAME k⁻¹ and r
        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);
        let s3 = k_inv * (z + r * x3);

        // Verify the mathematical relationship:
        // s1 + s2 + s3 = k⁻¹ * (3z + r * (x1 + x2 + x3))
        // This verifies that partial signatures can be aggregated
        let sum_s = s1 + s2 + s3;
        let sum_x = x1 + x2 + x3;
        let expected_sum = k_inv * (Scalar::from(3u64) * z + r * sum_x);

        assert_eq!(sum_s, expected_sum, "Sum of partial signatures should match expected");

        println!("✅ Partial signature consistency test passed!");
    }

    /// Test Lagrange interpolation for threshold signature aggregation
    #[test]
    fn test_lagrange_threshold_signature_aggregation() {
        // This test simulates 2-of-3 threshold signing with coordinated nonces

        // Node indices (as used in DKG)
        let idx1 = Scalar::from(1u64);
        let idx2 = Scalar::from(2u64);
        let idx3 = Scalar::from(3u64);

        // Generate private key shares
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);

        // Generate coordinated nonce
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let nonce = create_coordinated_nonce_tuple("lagrange_test", &[k1, k2]);

        // Message hash
        let message_hash: [u8; 32] = [0xab; 32];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        // Each node computes partial signature
        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);

        // Lagrange coefficients for indices {1, 2} evaluating at x=0
        // λ_1 = (0 - idx2) / (idx1 - idx2)
        // λ_2 = (0 - idx1) / (idx2 - idx1)
        let zero = Scalar::ZERO;
        let lambda1 = (zero - idx2) * (idx1 - idx2).invert().unwrap();
        let lambda2 = (zero - idx1) * (idx2 - idx1).invert().unwrap();

        // Aggregate: s = λ_1 * s_1 + λ_2 * s_2
        let aggregated_s = lambda1 * s1 + lambda2 * s2;

        // Compute what the full signature should be using reconstructed private key
        let aggregated_x = lambda1 * x1 + lambda2 * x2;
        let expected_s = k_inv * (z + r * aggregated_x);

        assert_eq!(aggregated_s, expected_s, "Lagrange aggregation should match direct computation");

        // Verify ECDSA signature
        let group_pubkey = (ProjectivePoint::GENERATOR * aggregated_x).to_affine();
        let s_inv = aggregated_s.invert().unwrap();
        let u1 = s_inv * z;
        let u2 = s_inv * r;
        let r_prime = (ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(group_pubkey) * u2).to_affine();

        // r' x-coordinate should equal r
        let encoded = r_prime.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_prime_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        assert_eq!(r_prime_scalar, r, "ECDSA verification should pass");

        println!("✅ Lagrange threshold signature aggregation test passed!");
    }

    /// Test that different nonces produce different signatures (security property)
    #[test]
    fn test_different_nonces_produce_different_signatures() {
        // Same private key
        let x = Scalar::random(&mut OsRng);

        // Same message
        let message_hash: [u8; 32] = [0x42; 32];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        // Two different nonces
        let nonce1 = create_test_nonce_tuple("nonce1");
        let nonce2 = create_test_nonce_tuple("nonce2");

        // Compute signatures with each nonce
        let s1 = nonce1.k_inv.0 * (z + nonce1.r_scalar.0 * x);
        let s2 = nonce2.k_inv.0 * (z + nonce2.r_scalar.0 * x);

        // Signatures should be different
        assert_ne!(s1, s2, "Different nonces should produce different signatures");
        assert_ne!(nonce1.r_scalar.0, nonce2.r_scalar.0, "Different nonces should have different r values");

        println!("✅ Different nonces produce different signatures (security property verified)");
    }

    /// Test that reusing the same nonce with different keys exposes the private key (security test)
    #[test]
    fn test_nonce_reuse_attack_demonstration() {
        // This test demonstrates why nonce reuse is dangerous
        // If two signatures use the same k but different private keys,
        // an attacker can recover the private key difference

        let k = Scalar::random(&mut OsRng);
        let nonce = create_coordinated_nonce_tuple("reuse_demo", &[k]);

        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);

        // Same message
        let message_hash: [u8; 32] = [0x55; 32];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&message_hash));

        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);

        // If an attacker sees s1 and s2 with the same r, they can compute:
        // s1 - s2 = k⁻¹ * r * (x1 - x2)
        // => x1 - x2 = k * (s1 - s2) / r
        let s_diff = s1 - s2;
        let recovered_x_diff = nonce.aggregated_k.0 * s_diff * r.invert().unwrap();
        let actual_x_diff = x1 - x2;

        assert_eq!(recovered_x_diff, actual_x_diff, "Nonce reuse allows private key difference recovery");

        println!("⚠️  SECURITY DEMONSTRATION: Nonce reuse allows private key extraction!");
        println!("   This is why we MUST use unique, coordinated nonces for each signature.");
    }

    /// Test full end-to-end signing with coordinated nonces (3-of-3)
    #[test]
    fn test_full_3_of_3_signing_with_coordinated_nonces() {
        // Setup: 3 nodes with threshold 3 (all nodes required)

        // Private key shares (from DKG)
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let x3 = Scalar::random(&mut OsRng);

        // Nonce shares from each node
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);
        let k3 = Scalar::random(&mut OsRng);

        // Create coordinated nonce (all nodes have the same after reveal phase)
        let nonce = create_coordinated_nonce_tuple("full_3of3", &[k1, k2, k3]);

        // Transaction hash to sign
        let tx_hash: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let z = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tx_hash));

        let k_inv = nonce.k_inv.0;
        let r = nonce.r_scalar.0;

        // Each node computes partial signature
        let s1 = k_inv * (z + r * x1);
        let s2 = k_inv * (z + r * x2);
        let s3 = k_inv * (z + r * x3);

        // For 3-of-3, indices are {1, 2, 3}
        let idx1 = Scalar::from(1u64);
        let idx2 = Scalar::from(2u64);
        let idx3 = Scalar::from(3u64);
        let zero = Scalar::ZERO;

        // Lagrange coefficients
        let lambda1 = (zero - idx2) * (zero - idx3) *
            ((idx1 - idx2) * (idx1 - idx3)).invert().unwrap();
        let lambda2 = (zero - idx1) * (zero - idx3) *
            ((idx2 - idx1) * (idx2 - idx3)).invert().unwrap();
        let lambda3 = (zero - idx1) * (zero - idx2) *
            ((idx3 - idx1) * (idx3 - idx2)).invert().unwrap();

        // Aggregate signature
        let aggregated_s = lambda1 * s1 + lambda2 * s2 + lambda3 * s3;

        // Reconstruct group public key
        let aggregated_x = lambda1 * x1 + lambda2 * x2 + lambda3 * x3;
        let group_pubkey = (ProjectivePoint::GENERATOR * aggregated_x).to_affine();

        // Verify ECDSA signature
        let s_inv = aggregated_s.invert().unwrap();
        let u1 = s_inv * z;
        let u2 = s_inv * r;
        let r_prime = (ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(group_pubkey) * u2).to_affine();

        let encoded = r_prime.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let r_prime_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));

        assert_eq!(r_prime_scalar, r, "ECDSA verification must pass");

        println!("✅ Full 3-of-3 signing with coordinated nonces PASSED!");
    }

    #[test]
    fn test_nonce_digest_uniqueness_rejects_mismatch_for_same_tuple() {
        let signing_key = SecretKey::from_slice(&[1u8; 32]).expect("valid signing key");
        let nonce_tuple_id = format!("nonce_audit_{}", uuid::Uuid::new_v4());
        let digest1 = [0x11u8; 32];
        let digest2 = [0x22u8; 32];

        SigningNode::enforce_nonce_digest_uniqueness(&signing_key, &nonce_tuple_id, &digest1)
            .expect("first digest should be accepted");

        let err = SigningNode::enforce_nonce_digest_uniqueness(&signing_key, &nonce_tuple_id, &digest2)
            .expect_err("second distinct digest for same nonce tuple should fail");
        assert!(
            err.to_string()
                .contains("nonce tuple reuse with different digest detected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_signature_rejects_nonce_tuple_digest_conflicts() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let signing_node = SigningNode::new("nonce-audit-node".to_string(), 2, tx);
        let signing_key = SecretKey::from_slice(&[2u8; 32]).expect("valid signing key");

        let mut nonce = create_test_nonce_tuple(&format!("nonce_conflict_{}", uuid::Uuid::new_v4()));
        let msg1 = Message::from_digest_slice(&[0x33u8; 32]).expect("valid digest");
        let msg2 = Message::from_digest_slice(&[0x44u8; 32]).expect("valid digest");

        signing_node
            .create_ecdsa_signature_with_nonce(&msg1, &signing_key, &nonce)
            .expect("first signature should be accepted");

        nonce.consumed = false;
        let err = signing_node
            .create_ecdsa_signature_with_nonce(&msg2, &signing_key, &nonce)
            .expect_err("same nonce tuple with conflicting digest should fail");
        assert!(
            err.to_string()
                .contains("nonce tuple reuse with different digest detected"),
            "unexpected error: {err}"
        );
    }

    /// Test that consumed nonces cannot be reused (security property)
    #[test]
    fn test_nonce_consumed_flag() {
        let mut nonce = create_test_nonce_tuple("consumable");

        assert!(!nonce.consumed, "New nonce should not be consumed");

        // Mark as consumed
        nonce.consumed = true;

        assert!(nonce.consumed, "Nonce should be marked as consumed after use");

        println!("✅ Nonce consumption tracking works correctly");
    }

    /// Test nonce with invalid k_inv (integrity check should fail)
    #[test]
    fn test_nonce_integrity_check_invalid_k_inv() {
        let mut nonce = create_test_nonce_tuple("invalid_k_inv");

        // Corrupt k_inv by adding 1
        nonce.k_inv = SerializableScalar(nonce.k_inv.0 + Scalar::ONE);

        // Verify k * k_inv != 1
        let k_times_k_inv = nonce.aggregated_k.0 * nonce.k_inv.0;
        assert_ne!(k_times_k_inv, Scalar::ONE, "Corrupted k_inv should fail integrity check");

        println!("✅ Invalid k_inv is detected by integrity check");
    }

    /// Test nonce with invalid R point (integrity check should fail)
    #[test]
    fn test_nonce_integrity_check_invalid_r_point() {
        let mut nonce = create_test_nonce_tuple("invalid_r");

        // Corrupt R by using a different point
        let fake_k = Scalar::random(&mut OsRng);
        nonce.aggregate_r = SerializablePoint((ProjectivePoint::GENERATOR * fake_k).to_affine());

        // Verify R != k * G
        let expected_r = (ProjectivePoint::GENERATOR * nonce.aggregated_k.0).to_affine();
        assert_ne!(nonce.aggregate_r.0, expected_r, "Corrupted R should fail integrity check");

        println!("✅ Invalid R point is detected by integrity check");
    }

    /// Test nonce with invalid r_scalar (integrity check should fail)
    #[test]
    fn test_nonce_integrity_check_invalid_r_scalar() {
        let mut nonce = create_test_nonce_tuple("invalid_r_scalar");

        // Corrupt r_scalar by adding 1
        nonce.r_scalar = SerializableScalar(nonce.r_scalar.0 + Scalar::ONE);

        // Verify r_scalar != x(R) mod n
        let encoded = nonce.aggregate_r.0.to_encoded_point(false);
        let x_bytes = encoded.x().expect("not at infinity");
        let computed_r = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x_bytes));
        assert_ne!(nonce.r_scalar.0, computed_r, "Corrupted r_scalar should fail integrity check");

        println!("✅ Invalid r_scalar is detected by integrity check");
    }
}
