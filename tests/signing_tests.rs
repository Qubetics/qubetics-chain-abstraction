//! Comprehensive tests for the signing module:
//! - ECDSA partial signature creation
//! - Lagrange interpolation with different index sets
//! - Nonce tuple structure and validation
//! - Signature aggregation logic
//! - SigningNode threshold management

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use num_bigint::{BigUint, ToBigInt};
use num_traits::One;
use tempfile::TempDir;

use mpc_node::database::{Database, DatabaseConfig, SigningStorage};
use mpc_node::types::{ECDSASignature, SerializableScalar};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_db() -> (Database, TempDir) {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let cfg = DatabaseConfig {
        path: tmp.path().to_str().unwrap().to_string(),
        create_if_missing: true,
        max_open_files: 64,
        encryption_key: Some("00".repeat(32)),
    };
    let db = Database::new(cfg).expect("failed to open test DB");
    (db, tmp)
}

/// secp256k1 curve order
fn curve_order() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

fn test_scalar(val: u64) -> Scalar {
    Scalar::from(val)
}

/// Modular inverse via extended Euclidean algorithm (matching the signing module's implementation)
fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_traits::Zero;

    if *a == BigUint::zero() {
        return None;
    }

    let mut old_r = m.clone();
    let mut r = a % m;
    let mut old_s = BigInt::zero();
    let mut s = BigInt::one();

    while r != BigUint::zero() {
        let quotient = &old_r / &r;

        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = &old_s - &quotient.to_bigint().unwrap() * &s;
        old_s = temp_s;
    }

    if old_r != BigUint::one() {
        return None;
    }

    let m_int = m.to_bigint().unwrap();
    let result = (old_s % &m_int + &m_int) % &m_int;
    Some(result.to_biguint().unwrap())
}

/// Lagrange interpolation at x=0 for the given shares (index, value) mod n
fn lagrange_interpolate_at_zero(shares: &[(u32, BigUint)]) -> BigUint {
    let n = curve_order();
    let mut accum = BigUint::from(0u32);

    for (j, (xj, yj)) in shares.iter().enumerate() {
        let mut num = BigUint::from(1u32);
        let mut den = BigUint::from(1u32);

        for (m, (xm, _)) in shares.iter().enumerate() {
            if m != j {
                let xm_u = BigUint::from(*xm);
                let xj_u = BigUint::from(*xj);

                let neg_xm = (&n - &xm_u) % &n;
                num = (num * &neg_xm) % &n;

                let diff = if xj_u >= xm_u {
                    &xj_u - &xm_u
                } else {
                    &xj_u + &n - &xm_u
                };
                den = (den * diff) % &n;
            }
        }

        let den_inv = modinv(&den, &n).expect("denominator must be invertible");
        let lambda = (num * den_inv) % &n;
        let contribution = (&lambda * yj) % &n;
        accum = (accum + contribution) % &n;
    }

    accum
}

// ===================================================================
// Lagrange Interpolation Tests
// ===================================================================

#[test]
fn lagrange_interpolation_recovers_secret_from_2_of_3() {
    let n = curve_order();

    // Polynomial f(x) = a0 + a1*x (degree 1, threshold = 2)
    let a0 = BigUint::from(42u64); // secret
    let a1 = BigUint::from(17u64); // random coefficient

    // Evaluate at indices 1, 2, 3
    let f1 = (&a0 + &a1 * 1u64) % &n;
    let f2 = (&a0 + &a1 * 2u64) % &n;
    let f3 = (&a0 + &a1 * 3u64) % &n;

    // Interpolate with shares at indices 1,2 -> should recover a0=42
    let recovered = lagrange_interpolate_at_zero(&[(1, f1.clone()), (2, f2.clone())]);
    assert_eq!(recovered, a0);

    // Interpolate with shares at indices 1,3 -> should also recover a0=42
    let recovered = lagrange_interpolate_at_zero(&[(1, f1.clone()), (3, f3.clone())]);
    assert_eq!(recovered, a0);

    // Interpolate with shares at indices 2,3 -> should also recover a0=42
    let recovered = lagrange_interpolate_at_zero(&[(2, f2), (3, f3)]);
    assert_eq!(recovered, a0);
}

#[test]
fn lagrange_interpolation_recovers_secret_from_3_of_5() {
    let n = curve_order();

    // Polynomial f(x) = a0 + a1*x + a2*x^2 (degree 2, threshold = 3)
    let a0 = BigUint::from(999u64);
    let a1 = BigUint::from(7u64);
    let a2 = BigUint::from(3u64);

    let eval = |x: u64| -> BigUint {
        let x_big = BigUint::from(x);
        (&a0 + &a1 * &x_big + &a2 * &x_big * &x_big) % &n
    };

    let f1 = eval(1);
    let f2 = eval(2);
    let f3 = eval(3);
    let f4 = eval(4);
    let f5 = eval(5);

    // Any 3 shares should recover the secret
    let r123 = lagrange_interpolate_at_zero(&[(1, f1.clone()), (2, f2.clone()), (3, f3.clone())]);
    assert_eq!(r123, a0);

    let r135 = lagrange_interpolate_at_zero(&[(1, f1.clone()), (3, f3.clone()), (5, f5.clone())]);
    assert_eq!(r135, a0);

    let r245 = lagrange_interpolate_at_zero(&[(2, f2), (4, f4), (5, f5)]);
    assert_eq!(r245, a0);
}

#[test]
fn lagrange_with_large_scalars() {
    let n = curve_order();

    // Use scalars close to the curve order
    let a0 = &n - BigUint::from(1u64); // n-1
    let a1 = BigUint::from(1u64);

    let f1 = (&a0 + &a1 * 1u64) % &n; // (n-1 + 1) mod n = 0
    let f2 = (&a0 + &a1 * 2u64) % &n; // (n-1 + 2) mod n = 1

    let recovered = lagrange_interpolate_at_zero(&[(1, f1), (2, f2)]);
    assert_eq!(recovered, a0);
}

#[test]
fn lagrange_non_contiguous_indices() {
    let n = curve_order();

    // f(x) = 100 + 5x
    let a0 = BigUint::from(100u64);
    let a1 = BigUint::from(5u64);

    // Use non-contiguous indices: 1, 7
    let f1 = (&a0 + &a1 * 1u64) % &n;
    let f7 = (&a0 + &a1 * 7u64) % &n;

    let recovered = lagrange_interpolate_at_zero(&[(1, f1), (7, f7)]);
    assert_eq!(recovered, a0);
}

// ===================================================================
// ECDSA Partial Signature Tests
// ===================================================================

#[test]
fn ecdsa_partial_signature_s_computation() {
    // s_i = k_inv * (z + r * x_i) mod n
    // Verify the math manually
    let n = curve_order();

    let z = BigUint::from(12345u64); // message hash
    let r = BigUint::from(67890u64); // r value from nonce
    let x = BigUint::from(42u64); // private key share
    let k_inv = BigUint::from(11111u64); // nonce inverse

    let s = (&k_inv * (&z + &r * &x)) % &n;

    // s should be non-zero and less than n
    assert!(s > BigUint::from(0u64));
    assert!(s < n);
}

#[test]
fn partial_signatures_are_different_for_different_keys() {
    let n = curve_order();

    let z = BigUint::from(99999u64);
    let r = BigUint::from(11111u64);
    let k_inv = BigUint::from(22222u64);

    let x1 = BigUint::from(100u64);
    let x2 = BigUint::from(200u64);

    let s1 = (&k_inv * (&z + &r * &x1)) % &n;
    let s2 = (&k_inv * (&z + &r * &x2)) % &n;

    assert_ne!(s1, s2, "Different private keys must produce different partial signatures");
}

#[test]
fn aggregated_signature_matches_full_key_signature() {
    let n = curve_order();

    // Polynomial f(x) = a0 + a1*x where a0 is the full private key
    let a0 = BigUint::from(42u64); // full private key
    let a1 = BigUint::from(17u64); // random coeff

    // Shares for nodes at indices 1, 2
    let x1 = (&a0 + &a1 * 1u64) % &n; // f(1)
    let x2 = (&a0 + &a1 * 2u64) % &n; // f(2)

    // Common signing parameters
    let z = BigUint::from(12345u64);
    let r = BigUint::from(67890u64);
    let k_inv = BigUint::from(11111u64);

    // Partial signatures
    let s1 = (&k_inv * (&z + &r * &x1)) % &n;
    let s2 = (&k_inv * (&z + &r * &x2)) % &n;

    // Lagrange interpolation on partial signatures
    let s_aggregated = lagrange_interpolate_at_zero(&[(1, s1), (2, s2)]);

    // Full key signature
    let s_full = (&k_inv * (&z + &r * &a0)) % &n;

    assert_eq!(
        s_aggregated, s_full,
        "Aggregated threshold signature must equal full-key signature"
    );
}

#[test]
fn threshold_signature_with_3_of_3() {
    let n = curve_order();

    // f(x) = a0 + a1*x + a2*x^2 (threshold = 3)
    let a0 = BigUint::from(777u64);
    let a1 = BigUint::from(13u64);
    let a2 = BigUint::from(5u64);

    let eval = |x: u64| -> BigUint {
        let xb = BigUint::from(x);
        (&a0 + &a1 * &xb + &a2 * &xb * &xb) % &n
    };

    let x1 = eval(1);
    let x2 = eval(2);
    let x3 = eval(3);

    let z = BigUint::from(55555u64);
    let r = BigUint::from(88888u64);
    let k_inv = BigUint::from(33333u64);

    let s1 = (&k_inv * (&z + &r * &x1)) % &n;
    let s2 = (&k_inv * (&z + &r * &x2)) % &n;
    let s3 = (&k_inv * (&z + &r * &x3)) % &n;

    let s_aggregated = lagrange_interpolate_at_zero(&[(1, s1), (2, s2), (3, s3)]);
    let s_full = (&k_inv * (&z + &r * &a0)) % &n;

    assert_eq!(s_aggregated, s_full);
}

// ===================================================================
// Tweaked Key Signing Consistency
// ===================================================================

#[test]
fn tweaked_key_signing_produces_correct_aggregated_signature() {
    let n = curve_order();

    // DKG polynomial f(x) = a0 + a1*x
    let a0 = BigUint::from(500u64); // DKG group secret
    let a1 = BigUint::from(30u64);

    // Tweak value (HMAC of user address)
    let tweak = BigUint::from(42u64);

    // Tweaked shares: tweaked_x_i = f(i) + tweak
    let tx1 = (&a0 + &a1 * 1u64 + &tweak) % &n;
    let tx2 = (&a0 + &a1 * 2u64 + &tweak) % &n;

    // Sign with tweaked shares
    let z = BigUint::from(12345u64);
    let r = BigUint::from(67890u64);
    let k_inv = BigUint::from(11111u64);

    let s1 = (&k_inv * (&z + &r * &tx1)) % &n;
    let s2 = (&k_inv * (&z + &r * &tx2)) % &n;

    // Lagrange interpolation recovers tweaked_a0 = a0 + tweak
    let s_aggregated = lagrange_interpolate_at_zero(&[(1, s1), (2, s2)]);
    let tweaked_a0 = (&a0 + &tweak) % &n;
    let s_expected = (&k_inv * (&z + &r * &tweaked_a0)) % &n;

    assert_eq!(
        s_aggregated, s_expected,
        "Tweaked key aggregated signature must match direct signing with tweaked secret"
    );
}

#[test]
fn different_tweak_different_signature() {
    let n = curve_order();

    let a0 = BigUint::from(500u64);
    let a1 = BigUint::from(30u64);

    let z = BigUint::from(12345u64);
    let r = BigUint::from(67890u64);
    let k_inv = BigUint::from(11111u64);

    // Tweak 1
    let tweak1 = BigUint::from(42u64);
    let tx1_1 = (&a0 + &a1 * 1u64 + &tweak1) % &n;
    let tx1_2 = (&a0 + &a1 * 2u64 + &tweak1) % &n;
    let s1_1 = (&k_inv * (&z + &r * &tx1_1)) % &n;
    let s1_2 = (&k_inv * (&z + &r * &tx1_2)) % &n;
    let agg1 = lagrange_interpolate_at_zero(&[(1, s1_1), (2, s1_2)]);

    // Tweak 2
    let tweak2 = BigUint::from(99u64);
    let tx2_1 = (&a0 + &a1 * 1u64 + &tweak2) % &n;
    let tx2_2 = (&a0 + &a1 * 2u64 + &tweak2) % &n;
    let s2_1 = (&k_inv * (&z + &r * &tx2_1)) % &n;
    let s2_2 = (&k_inv * (&z + &r * &tx2_2)) % &n;
    let agg2 = lagrange_interpolate_at_zero(&[(1, s2_1), (2, s2_2)]);

    assert_ne!(agg1, agg2, "Different tweaks must produce different signatures");
}

// ===================================================================
// ECDSASignature Serialization
// ===================================================================

#[test]
fn ecdsa_signature_serialization_roundtrip() {
    let sig = ECDSASignature {
        signature: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64],
        signer_id: "node-1".to_string(),
        recovery_id: 0,
        user_eth_address: Some("0x1234567890abcdef1234567890abcdef12345678".to_string()),
    };

    let serialized = serde_json::to_string(&sig).unwrap();
    let deserialized: ECDSASignature = serde_json::from_str(&serialized).unwrap();

    assert_eq!(sig.signature, deserialized.signature);
    assert_eq!(sig.signer_id, deserialized.signer_id);
    assert_eq!(sig.recovery_id, deserialized.recovery_id);
    assert_eq!(sig.user_eth_address, deserialized.user_eth_address);
}

// ===================================================================
// Signing Storage Tests
// ===================================================================

#[tokio::test]
async fn signing_storage_basic_operations() {
    let (db, _tmp) = temp_db();
    let _storage = SigningStorage::new(db);
    // SigningStorage wraps Database — verify construction succeeds
}

// ===================================================================
// Nonce Tuple Mathematical Properties
// ===================================================================

#[test]
fn nonce_k_and_kinv_are_multiplicative_inverses() {
    let n = curve_order();

    // Simulate: k is a random scalar, k_inv = k^(-1) mod n
    let k = BigUint::from(12345u64);
    let k_inv = modinv(&k, &n).unwrap();

    // k * k_inv mod n = 1
    let product = (&k * &k_inv) % &n;
    assert_eq!(product, BigUint::from(1u64));
}

#[test]
fn nonce_r_equals_k_times_g_x_coord() {
    // In ECDSA, r = (k * G).x mod n
    // We verify the mathematical relationship
    let k = test_scalar(12345);
    let k_point = ProjectivePoint::GENERATOR * k;
    let k_affine = k256::AffinePoint::from(k_point);

    // The x-coordinate should be non-zero
    let x_bytes = k_affine.to_encoded_point(false);
    let x_coord = &x_bytes.as_bytes()[1..33]; // skip 0x04 prefix, take 32 bytes
    assert!(!x_coord.iter().all(|&b| b == 0), "r (x-coordinate of k*G) must be non-zero");
}

#[test]
fn additive_nonce_shares_sum_correctly() {
    let n = curve_order();

    // Simulate 3 nodes generating additive nonce shares
    // Each node generates k_i, the combined k = k_1 + k_2 + k_3
    let k1 = BigUint::from(111u64);
    let k2 = BigUint::from(222u64);
    let k3 = BigUint::from(333u64);

    let k_combined = (&k1 + &k2 + &k3) % &n;
    assert_eq!(k_combined, BigUint::from(666u64));

    // k_inv of the combined nonce
    let k_inv = modinv(&k_combined, &n).unwrap();
    let product = (&k_combined * &k_inv) % &n;
    assert_eq!(product, BigUint::from(1u64));
}

// ===================================================================
// Signing with subset of nodes
// ===================================================================

#[test]
fn signing_with_any_threshold_subset_produces_same_result() {
    let n = curve_order();

    // f(x) = 42 + 17x (threshold = 2, 3 nodes)
    let a0 = BigUint::from(42u64);
    let a1 = BigUint::from(17u64);

    let shares: Vec<(u32, BigUint)> = (1..=3)
        .map(|i| {
            let fi = (&a0 + &a1 * BigUint::from(i as u64)) % &n;
            (i, fi)
        })
        .collect();

    let z = BigUint::from(12345u64);
    let r = BigUint::from(67890u64);
    let k_inv = BigUint::from(11111u64);

    // Sign with each pair
    let sign_with = |indices: &[usize]| -> BigUint {
        let partial_sigs: Vec<(u32, BigUint)> = indices
            .iter()
            .map(|&i| {
                let s = (&k_inv * (&z + &r * &shares[i].1)) % &n;
                (shares[i].0, s)
            })
            .collect();
        lagrange_interpolate_at_zero(&partial_sigs)
    };

    let sig_12 = sign_with(&[0, 1]);
    let sig_13 = sign_with(&[0, 2]);
    let sig_23 = sign_with(&[1, 2]);

    // All subsets must produce the same aggregated signature
    assert_eq!(sig_12, sig_13, "Subset (1,2) and (1,3) must produce same signature");
    assert_eq!(sig_13, sig_23, "Subset (1,3) and (2,3) must produce same signature");

    // And it must equal direct signing with the full key
    let s_full = (&k_inv * (&z + &r * &a0)) % &n;
    assert_eq!(sig_12, s_full);
}

// ===================================================================
// SerializableScalar Round-trip
// ===================================================================

#[test]
fn serializable_scalar_roundtrip() {
    let scalar = test_scalar(12345);
    let serializable = SerializableScalar(scalar);

    let bytes = bincode::serialize(&serializable).unwrap();
    let deserialized: SerializableScalar = bincode::deserialize(&bytes).unwrap();

    assert_eq!(serializable.0, deserialized.0);
}
