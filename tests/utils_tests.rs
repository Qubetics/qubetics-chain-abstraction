//! Comprehensive tests for the utils module:
//! - HMAC helper functions (hmac256, hmac64, hmac_scalar_mod_n, bytes_to_scalar_mod_n)
//! - Ethereum address derivation from group keys
//! - Bitcoin address derivation from group keys
//! - Intent hash calculation
//! - Address validation
//! - Intent validation

use k256::{ProjectivePoint, Scalar};

use mpc_node::utils;
use mpc_node::utils::hmac_helper;

// ===================================================================
// HMAC Helper: hmac256_from_addr
// ===================================================================

#[test]
fn hmac256_known_test_vector() {
    let key = b"vanijya-v1";
    let addr = "0x000000000000000000000000000000000000dead";
    let h = hmac_helper::hmac256_from_addr(addr, key).unwrap();
    assert_eq!(
        hex::encode(h),
        "1708cce8ea41e6a5d09878ae91d1a1206725eb90bffec0d5aa402245978cfb7a"
    );
}

#[test]
fn hmac256_without_0x_prefix() {
    let key = b"test-key";
    let addr_with = "0x000000000000000000000000000000000000dead";
    let addr_without = "000000000000000000000000000000000000dead";

    let h1 = hmac_helper::hmac256_from_addr(addr_with, key).unwrap();
    let h2 = hmac_helper::hmac256_from_addr(addr_without, key).unwrap();

    assert_eq!(h1, h2, "With and without 0x prefix should produce same HMAC");
}

#[test]
fn hmac256_different_addresses_different_output() {
    let key = b"test-key";
    let addr1 = "0x0000000000000000000000000000000000000001";
    let addr2 = "0x0000000000000000000000000000000000000002";

    let h1 = hmac_helper::hmac256_from_addr(addr1, key).unwrap();
    let h2 = hmac_helper::hmac256_from_addr(addr2, key).unwrap();

    assert_ne!(h1, h2);
}

#[test]
fn hmac256_different_keys_different_output() {
    let addr = "0x000000000000000000000000000000000000dead";

    let h1 = hmac_helper::hmac256_from_addr(addr, b"key1").unwrap();
    let h2 = hmac_helper::hmac256_from_addr(addr, b"key2").unwrap();

    assert_ne!(h1, h2);
}

#[test]
fn hmac256_invalid_address_too_short() {
    let key = b"test";
    let result = hmac_helper::hmac256_from_addr("0x1234", key);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not a 20-byte hex address"));
}

#[test]
fn hmac256_invalid_address_too_long() {
    let key = b"test";
    let result = hmac_helper::hmac256_from_addr(
        "0x00000000000000000000000000000000000000dead00",
        key,
    );
    assert!(result.is_err());
}

#[test]
fn hmac256_invalid_hex() {
    let key = b"test";
    // 40 chars but invalid hex
    let result = hmac_helper::hmac256_from_addr(
        "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        key,
    );
    assert!(result.is_err());
}

#[test]
fn hmac256_deterministic() {
    let key = b"my-secret";
    let addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD80";

    let h1 = hmac_helper::hmac256_from_addr(addr, key).unwrap();
    let h2 = hmac_helper::hmac256_from_addr(addr, key).unwrap();

    assert_eq!(h1, h2, "HMAC must be deterministic");
}

// ===================================================================
// HMAC Helper: hmac64_from_addr
// ===================================================================

#[test]
fn hmac64_returns_first_8_bytes_of_hmac256() {
    let key = b"test-key";
    let addr = "0x000000000000000000000000000000000000dead";

    let h256 = hmac_helper::hmac256_from_addr(addr, key).unwrap();
    let h64 = hmac_helper::hmac64_from_addr(addr, key).unwrap();

    let expected_u64 = u64::from_be_bytes(h256[0..8].try_into().unwrap());
    assert_eq!(h64, expected_u64);
}

#[test]
fn hmac64_different_addresses_different_values() {
    let key = b"test-key";
    let h1 = hmac_helper::hmac64_from_addr("0x0000000000000000000000000000000000000001", key).unwrap();
    let h2 = hmac_helper::hmac64_from_addr("0x0000000000000000000000000000000000000002", key).unwrap();
    assert_ne!(h1, h2);
}

// ===================================================================
// HMAC Helper: hmac_scalar_mod_n
// ===================================================================

#[test]
fn hmac_scalar_mod_n_produces_valid_scalar() {
    let key = b"chain-code";
    let addr = "0x000000000000000000000000000000000000dead";

    let result = hmac_helper::hmac_scalar_mod_n(addr, key).unwrap();

    // Result should be 32 bytes
    assert_eq!(result.len(), 32);

    // Result should be non-zero
    assert!(!result.iter().all(|&b| b == 0), "Scalar must not be zero");

    // Result should be valid as a k256 Scalar
    use k256::elliptic_curve::PrimeField;
    let scalar = Scalar::from_repr(result.into());
    assert!(bool::from(scalar.is_some()), "Must be a valid secp256k1 scalar");
}

#[test]
fn hmac_scalar_mod_n_deterministic() {
    let key = b"chain-code";
    let addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD80";

    let s1 = hmac_helper::hmac_scalar_mod_n(addr, key).unwrap();
    let s2 = hmac_helper::hmac_scalar_mod_n(addr, key).unwrap();

    assert_eq!(s1, s2);
}

#[test]
fn hmac_scalar_mod_n_different_inputs_different_scalars() {
    let key = b"chain-code";
    let s1 = hmac_helper::hmac_scalar_mod_n(
        "0x0000000000000000000000000000000000000001",
        key,
    ).unwrap();
    let s2 = hmac_helper::hmac_scalar_mod_n(
        "0x0000000000000000000000000000000000000002",
        key,
    ).unwrap();

    assert_ne!(s1, s2);
}

// ===================================================================
// HMAC Helper: bytes_to_scalar_mod_n
// ===================================================================

#[test]
fn bytes_to_scalar_zero_input() {
    let input = [0u8; 32];
    let result = hmac_helper::bytes_to_scalar_mod_n(&input);
    assert_eq!(result, [0u8; 32], "0 mod n = 0");
}

#[test]
fn bytes_to_scalar_small_value() {
    let mut input = [0u8; 32];
    input[31] = 42;
    let result = hmac_helper::bytes_to_scalar_mod_n(&input);
    assert_eq!(result, input, "42 < n, so result should be 42");
}

#[test]
fn bytes_to_scalar_max_value_reduces() {
    let input = [0xFFu8; 32]; // 2^256 - 1, which is > curve order
    let result = hmac_helper::bytes_to_scalar_mod_n(&input);

    // Result should be different from input (reduced mod n)
    assert_ne!(result, input);

    // Result should be less than curve order
    use num_bigint::BigUint;
    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    ).unwrap();
    let result_big = BigUint::from_bytes_be(&result);
    assert!(result_big < n);
}

#[test]
fn bytes_to_scalar_deterministic() {
    let input = [0xABu8; 32];
    let r1 = hmac_helper::bytes_to_scalar_mod_n(&input);
    let r2 = hmac_helper::bytes_to_scalar_mod_n(&input);
    assert_eq!(r1, r2);
}

// ===================================================================
// Ethereum Address Derivation
// ===================================================================

#[test]
fn eth_address_from_generator() {
    let pubkey = ProjectivePoint::GENERATOR;
    let addr = utils::get_eth_address_from_group_key(pubkey);

    // Should start with 0x
    assert!(addr.starts_with("0x"));
    // Should be 42 chars (0x + 40 hex chars)
    assert_eq!(addr.len(), 42);
    // Should be lowercase hex
    assert!(addr[2..].chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn eth_address_deterministic() {
    let pubkey = ProjectivePoint::GENERATOR * Scalar::from(12345u64);
    let addr1 = utils::get_eth_address_from_group_key(pubkey);
    let addr2 = utils::get_eth_address_from_group_key(pubkey);
    assert_eq!(addr1, addr2);
}

#[test]
fn eth_address_different_keys_different_addresses() {
    let pk1 = ProjectivePoint::GENERATOR * Scalar::from(1u64);
    let pk2 = ProjectivePoint::GENERATOR * Scalar::from(2u64);

    let addr1 = utils::get_eth_address_from_group_key(pk1);
    let addr2 = utils::get_eth_address_from_group_key(pk2);

    assert_ne!(addr1, addr2);
}

#[test]
fn eth_address_tweaked_key_differs_from_base() {
    let base_key = ProjectivePoint::GENERATOR * Scalar::from(100u64);
    let tweak = Scalar::from(50u64);
    let tweaked_key = base_key + ProjectivePoint::GENERATOR * tweak;

    let base_addr = utils::get_eth_address_from_group_key(base_key);
    let tweaked_addr = utils::get_eth_address_from_group_key(tweaked_key);

    assert_ne!(base_addr, tweaked_addr, "Tweaked key must produce different address");
}

// ===================================================================
// Bitcoin Address Derivation
// ===================================================================

#[test]
fn btc_address_from_generator() {
    // Initialize NETWORK_TYPE for tests
    std::env::set_var("NETWORK_TYPE", "testnet");
    let _ = mpc_node::types::network::init_network_type_from_env();

    let pubkey = ProjectivePoint::GENERATOR;
    let addr = utils::get_btc_address_from_group_key(pubkey)
        .expect("BTC address derivation from generator point should succeed");

    // Should be non-empty
    assert!(!addr.is_empty());
}

#[test]
fn btc_address_deterministic() {
    std::env::set_var("NETWORK_TYPE", "testnet");
    let _ = mpc_node::types::network::init_network_type_from_env();

    let pubkey = ProjectivePoint::GENERATOR * Scalar::from(12345u64);
    let addr1 = utils::get_btc_address_from_group_key(pubkey)
        .expect("BTC address derivation should succeed");
    let addr2 = utils::get_btc_address_from_group_key(pubkey)
        .expect("BTC address derivation should succeed");
    assert_eq!(addr1, addr2);
}

#[test]
fn btc_address_different_keys_different_addresses() {
    std::env::set_var("NETWORK_TYPE", "testnet");
    let _ = mpc_node::types::network::init_network_type_from_env();

    let pk1 = ProjectivePoint::GENERATOR * Scalar::from(1u64);
    let pk2 = ProjectivePoint::GENERATOR * Scalar::from(2u64);

    let addr1 = utils::get_btc_address_from_group_key(pk1)
        .expect("BTC address derivation should succeed");
    let addr2 = utils::get_btc_address_from_group_key(pk2)
        .expect("BTC address derivation should succeed");

    assert_ne!(addr1, addr2);
}

// ===================================================================
// Intent Hash Calculation
// ===================================================================

#[test]
fn intent_hash_deterministic() {
    let intent = mpc_node::types::DepositIntent {
        source_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        target_address: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
        source_chain: "qubetics".to_string(),
        target_chain: "qubetics".to_string(),
        amount: "1000000000000000000".to_string(),
        source_token: "TICS".to_string(),
        target_token: "TICS".to_string(),
        timestamp: 1234567890,
    };

    let hash1 = utils::calculate_intent_hash(&intent).unwrap();
    let hash2 = utils::calculate_intent_hash(&intent).unwrap();

    assert_eq!(hash1, hash2);
}

#[test]
fn intent_hash_different_amounts_different_hashes() {
    let intent1 = mpc_node::types::DepositIntent {
        source_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        target_address: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
        source_chain: "qubetics".to_string(),
        target_chain: "qubetics".to_string(),
        amount: "1000".to_string(),
        source_token: "TICS".to_string(),
        target_token: "TICS".to_string(),
        timestamp: 1234567890,
    };

    let mut intent2 = intent1.clone();
    intent2.amount = "2000".to_string();

    let hash1 = utils::calculate_intent_hash(&intent1).unwrap();
    let hash2 = utils::calculate_intent_hash(&intent2).unwrap();

    assert_ne!(hash1, hash2);
}

#[test]
fn intent_hash_different_timestamps_different_hashes() {
    let intent1 = mpc_node::types::DepositIntent {
        source_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        target_address: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
        source_chain: "qubetics".to_string(),
        target_chain: "qubetics".to_string(),
        amount: "1000".to_string(),
        source_token: "TICS".to_string(),
        target_token: "TICS".to_string(),
        timestamp: 1000,
    };

    let mut intent2 = intent1.clone();
    intent2.timestamp = 2000;

    let hash1 = utils::calculate_intent_hash(&intent1).unwrap();
    let hash2 = utils::calculate_intent_hash(&intent2).unwrap();

    assert_ne!(hash1, hash2, "Different timestamps must produce different hashes");
}

#[test]
fn intent_hash_is_hex_string() {
    let intent = mpc_node::types::DepositIntent {
        source_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        target_address: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
        source_chain: "qubetics".to_string(),
        target_chain: "qubetics".to_string(),
        amount: "1000".to_string(),
        source_token: "TICS".to_string(),
        target_token: "TICS".to_string(),
        timestamp: 12345,
    };

    let hash = utils::calculate_intent_hash(&intent).unwrap();

    // Keccak256 produces 32 bytes = 64 hex chars
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ===================================================================
// Address Consistency: ETH address from public key
// ===================================================================

#[test]
fn eth_address_from_sum_of_public_keys() {
    // Simulate DKG: group key = sum of individual public keys
    let s1 = Scalar::from(10u64);
    let s2 = Scalar::from(20u64);
    let s3 = Scalar::from(30u64);

    let pk1 = ProjectivePoint::GENERATOR * s1;
    let pk2 = ProjectivePoint::GENERATOR * s2;
    let pk3 = ProjectivePoint::GENERATOR * s3;

    let group_key = pk1 + pk2 + pk3;

    // This should equal G * (10 + 20 + 30) = G * 60
    let expected = ProjectivePoint::GENERATOR * Scalar::from(60u64);
    assert_eq!(group_key, expected);

    let addr = utils::get_eth_address_from_group_key(group_key);
    let expected_addr = utils::get_eth_address_from_group_key(expected);
    assert_eq!(addr, expected_addr);
}

// ===================================================================
// User Key Derivation: Full Pipeline
// ===================================================================

#[test]
fn user_key_derivation_full_pipeline() {
    // Simulate the full user key derivation pipeline:
    // 1. Group key from DKG
    // 2. HMAC tweak from user address + chain code
    // 3. User key = group_key + tweak * G
    // 4. Derive ETH address from user key

    let group_secret = Scalar::from(1000u64);
    let group_key = ProjectivePoint::GENERATOR * group_secret;

    let chain_code = b"2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194abe4";
    let user_addr = "0x91b4fd67c5671819f1f903b63dc7dbb83b80fde0";

    // Compute HMAC tweak
    let hmac_bytes = hmac_helper::hmac_scalar_mod_n(user_addr, chain_code).unwrap();

    use k256::elliptic_curve::PrimeField;
    let tweak_scalar = Scalar::from_repr(hmac_bytes.into());
    assert!(bool::from(tweak_scalar.is_some()), "HMAC must produce valid scalar");
    let tweak = tweak_scalar.unwrap();

    // User key = group_key + tweak * G
    let user_key = group_key + ProjectivePoint::GENERATOR * tweak;

    // Derive ETH address
    let derived_addr = utils::get_eth_address_from_group_key(user_key);
    assert!(derived_addr.starts_with("0x"));
    assert_eq!(derived_addr.len(), 42);

    // User key should be different from group key
    assert_ne!(user_key, group_key);

    // Derived address should be different from group address
    let group_addr = utils::get_eth_address_from_group_key(group_key);
    assert_ne!(derived_addr, group_addr);
}

// ===================================================================
// Tweaked Secret Consistency
// ===================================================================

#[test]
fn tweaked_secret_public_key_correspondence() {
    // Verify: if tweaked_secret = secret + tweak, then
    // G * tweaked_secret = G * secret + G * tweak

    let secret = Scalar::from(100u64);
    let tweak = Scalar::from(50u64);
    let tweaked_secret = secret + tweak;

    let pub_from_tweaked = ProjectivePoint::GENERATOR * tweaked_secret;
    let pub_from_parts = ProjectivePoint::GENERATOR * secret + ProjectivePoint::GENERATOR * tweak;

    assert_eq!(pub_from_tweaked, pub_from_parts);
}

// ===================================================================
// DepositIntent Serialization
// ===================================================================

#[test]
fn deposit_intent_json_roundtrip() {
    let intent = mpc_node::types::DepositIntent {
        source_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        target_address: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "qubetics".to_string(),
        amount: "5000000000000000000".to_string(),
        source_token: "ETH".to_string(),
        target_token: "TICS".to_string(),
        timestamp: 1234567890,
    };

    let json = serde_json::to_string(&intent).unwrap();
    let deserialized: mpc_node::types::DepositIntent = serde_json::from_str(&json).unwrap();

    assert_eq!(intent.source_address, deserialized.source_address);
    assert_eq!(intent.target_address, deserialized.target_address);
    assert_eq!(intent.amount, deserialized.amount);
    assert_eq!(intent.timestamp, deserialized.timestamp);
}
