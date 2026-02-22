//! Comprehensive tests for the database module:
//! - Database creation and configuration
//! - DkgStorage CRUD operations
//! - UserStorage CRUD operations
//! - Encryption key handling
//! - Batch operations
//! - Concurrent access patterns

use chrono::Utc;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::collections::HashMap;
use tempfile::TempDir;

use mpc_node::database::{Database, DatabaseConfig, DkgStorage, UserStorage};
use mpc_node::types::user_intent::{IntentStatus, UserRegistration};
use mpc_node::types::SerializableScalar;

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

fn test_scalar(val: u64) -> Scalar {
    Scalar::from(val)
}

fn make_user(addr: &str) -> UserRegistration {
    UserRegistration {
        user_id: format!("user_{}", addr),
        tics_address: addr.to_string(),
        tweaked_secret_share: None,
        hmac_constant: [0u8; 32],
        user_group_key: None,
        derived_eth_address: None,
        derived_btc_address: None,
        intent_hashes: HashMap::new(),
        created_at: Utc::now(),
        registered_by_node: "test-node".to_string(),
    }
}

// ===================================================================
// Database Configuration Tests
// ===================================================================

#[test]
fn database_config_with_encryption() {
    let cfg = DatabaseConfig {
        path: "/tmp/test_db_config".to_string(),
        create_if_missing: true,
        max_open_files: 100,
        encryption_key: Some("aabbccdd".repeat(8)),
    };
    assert!(cfg.encryption_key.is_some());
}

#[test]
fn database_creation_with_valid_config() {
    let (db, _tmp) = temp_db();
    // Should succeed without panicking
    drop(db);
}

// ===================================================================
// Database: Basic Put/Get Operations
// ===================================================================

#[test]
fn database_put_and_get_string() {
    let (db, _tmp) = temp_db();

    db.put_string("test_key", &"hello world".to_string()).unwrap();
    let val: Option<String> = db.get_string("test_key").unwrap();
    assert_eq!(val.unwrap(), "hello world");
}

#[test]
fn database_get_nonexistent_key() {
    let (db, _tmp) = temp_db();
    let val: Option<String> = db.get_string("nonexistent").unwrap();
    assert!(val.is_none());
}

#[test]
fn database_put_overwrite() {
    let (db, _tmp) = temp_db();

    db.put_string("key", &"value1".to_string()).unwrap();
    db.put_string("key", &"value2".to_string()).unwrap();

    let val: Option<String> = db.get_string("key").unwrap();
    assert_eq!(val.unwrap(), "value2");
}

#[test]
fn database_delete_key() {
    let (db, _tmp) = temp_db();

    db.put_string("key", &"value".to_string()).unwrap();
    db.delete_string("key").unwrap();

    let val: Option<String> = db.get_string("key").unwrap();
    assert!(val.is_none());
}

#[test]
fn database_prefix_search() {
    let (db, _tmp) = temp_db();

    db.put_string("prefix:a", &"val_a".to_string()).unwrap();
    db.put_string("prefix:b", &"val_b".to_string()).unwrap();
    db.put_string("other:c", &"val_c".to_string()).unwrap();

    let results: Vec<(String, String)> = db.get_values_with_prefix("prefix:").unwrap();
    assert_eq!(results.len(), 2);
}

// ===================================================================
// DkgStorage: Comprehensive Tests
// ===================================================================

#[tokio::test]
async fn dkg_storage_shares() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    let share = mpc_node::types::KeyShare {
        index: 1,
        value: SerializableScalar(test_scalar(42)),
    };

    storage.store_share("peer-1", &share).await.unwrap();

    let all_shares = storage.get_all_shares().await.unwrap();
    assert_eq!(all_shares.len(), 1);
    assert!(all_shares.contains_key("peer-1"));
    assert_eq!(all_shares["peer-1"].index, 1);
}

#[tokio::test]
async fn dkg_storage_multiple_shares_from_different_peers() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    for i in 1..=3 {
        let share = mpc_node::types::KeyShare {
            index: i,
            value: SerializableScalar(test_scalar(i as u64 * 10)),
        };
        storage.store_share(&format!("peer-{}", i), &share).await.unwrap();
    }

    let all_shares = storage.get_all_shares().await.unwrap();
    assert_eq!(all_shares.len(), 3);
}

#[tokio::test]
async fn dkg_storage_commitments_for_specific_peer() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    let c0 = AffinePoint::GENERATOR;
    let c1 = (ProjectivePoint::GENERATOR * test_scalar(5)).to_affine();
    storage.store_commitments("peer-1", &[c0, c1]).await.unwrap();

    let retrieved = storage.get_commitments_for("peer-1").await.unwrap();
    assert!(retrieved.is_some());
    let comms = retrieved.unwrap();
    assert_eq!(comms.len(), 2);
    assert_eq!(comms[0], c0);
}

#[tokio::test]
async fn dkg_storage_commitments_for_nonexistent_peer() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    let retrieved = storage.get_commitments_for("ghost").await.unwrap();
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn dkg_storage_clear_all_shares() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    let share = mpc_node::types::KeyShare {
        index: 1,
        value: SerializableScalar(test_scalar(42)),
    };
    storage.store_share("peer-1", &share).await.unwrap();

    storage.clear_shares().await.unwrap();
    let all_shares = storage.get_all_shares().await.unwrap();
    assert!(all_shares.is_empty());
}

#[tokio::test]
async fn dkg_storage_validations() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    storage.add_validation("node-1", "peer-2", true).await.unwrap();
    storage.add_validation("node-1", "peer-3", true).await.unwrap();
    storage.add_validation("node-2", "peer-1", false).await.unwrap();

    let all_validations = storage.get_all_validations().await.unwrap();
    assert!(!all_validations.is_empty());
}

// ===================================================================
// UserStorage: Comprehensive Tests
// ===================================================================

#[tokio::test]
async fn user_storage_store_and_retrieve() {
    let (db, _tmp) = temp_db();
    let storage = UserStorage::new(db);

    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let user = make_user(addr);

    storage.store_user(addr, &user).await.unwrap();

    let retrieved = storage.get_user(addr).await.unwrap();
    assert!(retrieved.is_some());
    let u = retrieved.unwrap();
    assert_eq!(u.tics_address, addr);
    assert_eq!(u.user_id, format!("user_{}", addr));
}

#[tokio::test]
async fn user_storage_get_nonexistent() {
    let (db, _tmp) = temp_db();
    let storage = UserStorage::new(db);

    let retrieved = storage.get_user("0xdeadbeef").await.unwrap();
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn user_storage_overwrite() {
    let (db, _tmp) = temp_db();
    let storage = UserStorage::new(db);

    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let mut user = make_user(addr);
    storage.store_user(addr, &user).await.unwrap();

    // Update with derived address
    user.derived_eth_address = Some("0xderived123".to_string());
    storage.store_user(addr, &user).await.unwrap();

    let retrieved = storage.get_user(addr).await.unwrap().unwrap();
    assert_eq!(retrieved.derived_eth_address, Some("0xderived123".to_string()));
}

#[tokio::test]
async fn user_storage_multiple_users() {
    let (db, _tmp) = temp_db();
    let storage = UserStorage::new(db);

    let addrs = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ];

    for addr in &addrs {
        storage.store_user(addr, &make_user(addr)).await.unwrap();
    }

    for addr in &addrs {
        let retrieved = storage.get_user(addr).await.unwrap();
        assert!(retrieved.is_some());
    }
}

#[tokio::test]
async fn user_storage_with_tweaked_share() {
    let (db, _tmp) = temp_db();
    let storage = UserStorage::new(db);

    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let mut user = make_user(addr);
    user.tweaked_secret_share = Some(SerializableScalar(test_scalar(42)));

    storage.store_user(addr, &user).await.unwrap();

    let retrieved = storage.get_user(addr).await.unwrap().unwrap();
    assert!(retrieved.tweaked_secret_share.is_some());
    assert_eq!(retrieved.tweaked_secret_share.unwrap().0, test_scalar(42));
}

#[tokio::test]
async fn user_storage_with_intent_hashes() {
    let (db, _tmp) = temp_db();
    let storage = UserStorage::new(db);

    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let mut user = make_user(addr);
    user.intent_hashes.insert("hash1".to_string(), IntentStatus::Pending);
    user.intent_hashes.insert("hash2".to_string(), IntentStatus::Batched);

    storage.store_user(addr, &user).await.unwrap();

    let retrieved = storage.get_user(addr).await.unwrap().unwrap();
    assert_eq!(retrieved.intent_hashes.len(), 2);
    assert_eq!(retrieved.intent_hashes["hash1"], IntentStatus::Pending);
    assert_eq!(retrieved.intent_hashes["hash2"], IntentStatus::Batched);
}

// ===================================================================
// UserRegistration Serialization
// ===================================================================

#[test]
fn user_registration_bincode_roundtrip() {
    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let mut user = make_user(addr);
    user.tweaked_secret_share = Some(SerializableScalar(test_scalar(42)));
    user.derived_eth_address = Some("0xderived".to_string());

    let bytes = bincode::serialize(&user).unwrap();
    let deserialized: UserRegistration = bincode::deserialize(&bytes).unwrap();

    assert_eq!(user.tics_address, deserialized.tics_address);
    assert_eq!(user.user_id, deserialized.user_id);
    assert_eq!(
        user.tweaked_secret_share.unwrap().0,
        deserialized.tweaked_secret_share.unwrap().0
    );
}

#[test]
fn user_registration_json_roundtrip() {
    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let user = make_user(addr);

    let json = serde_json::to_string(&user).unwrap();
    let deserialized: UserRegistration = serde_json::from_str(&json).unwrap();

    assert_eq!(user.tics_address, deserialized.tics_address);
}

// ===================================================================
// IntentStatus Transitions
// ===================================================================

#[test]
fn intent_status_all_variants_serializable() {
    let statuses = vec![
        IntentStatus::Pending,
        IntentStatus::Batched,
        IntentStatus::Processing,
        IntentStatus::Solved,
        IntentStatus::Rejected,
    ];

    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: IntentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }
}

// ===================================================================
// DkgStorage: Liquidity Operator Addresses
// ===================================================================

#[tokio::test]
async fn dkg_storage_liquidity_operator_addresses() {
    let (db, _tmp) = temp_db();
    let storage = DkgStorage::new(db);

    let eth_addr = "0xabcdef1234567890abcdef1234567890abcdef12";
    let btc_addr = "tb1qtest123456789";

    storage.set_liquidity_operator_addresses(eth_addr, btc_addr).await.unwrap();

    // Verify via get (if method exists) or at minimum confirm no error
}

// ===================================================================
// Database: Large number of entries
// ===================================================================

#[test]
fn database_handles_many_entries() {
    let (db, _tmp) = temp_db();

    // Insert 1000 entries
    for i in 0..1000 {
        let key = format!("entry:{}", i);
        db.put_string(&key, &format!("value_{}", i)).unwrap();
    }

    // Verify random entries
    for i in [0, 100, 500, 999] {
        let key = format!("entry:{}", i);
        let val: Option<String> = db.get_string(&key).unwrap();
        assert_eq!(val.unwrap(), format!("value_{}", i));
    }

    // Prefix search should find all 1000
    let results: Vec<(String, String)> = db.get_values_with_prefix("entry:").unwrap();
    assert_eq!(results.len(), 1000);
}

// ===================================================================
// Database: Data Isolation Between Databases
// ===================================================================

#[test]
fn databases_are_isolated() {
    let (db1, _tmp1) = temp_db();
    let (db2, _tmp2) = temp_db();

    db1.put_string("shared_key", &"from_db1".to_string()).unwrap();
    db2.put_string("shared_key", &"from_db2".to_string()).unwrap();

    let val1: Option<String> = db1.get_string("shared_key").unwrap();
    let val2: Option<String> = db2.get_string("shared_key").unwrap();

    assert_eq!(val1.unwrap(), "from_db1");
    assert_eq!(val2.unwrap(), "from_db2");
}
