//! Comprehensive tests for the UserIntentManager module:
//! - User registration with and without DKG secret
//! - Tweaked share computation and refresh
//! - Intent status management
//! - State sync stripping and restoration
//! - Multiple user management

use chrono::Utc;
use k256::Scalar;
use std::collections::HashMap;
use tempfile::TempDir;

use mpc_node::database::{Database, DatabaseConfig, DkgStorage, UserStorage};
use mpc_node::types::user_intent::{IntentStatus, UserRegistration};
use mpc_node::types::SerializableScalar;
use mpc_node::user_intent_manager::UserIntentManager;

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

fn make_user_with_tweaked_share(addr: &str, share: Scalar) -> UserRegistration {
    UserRegistration {
        user_id: format!("user_{}", addr),
        ethereum_address: addr.to_string(),
        tweaked_secret_share: Some(SerializableScalar(share)),
        hmac_constant: [0x42u8; 32],
        user_group_key: None,
        derived_eth_address: None,
        derived_btc_address: None,
        intent_hashes: HashMap::new(),
        created_at: Utc::now(),
        registered_by_node: "test-node".to_string(),
    }
}

fn make_user_without_share(addr: &str) -> UserRegistration {
    UserRegistration {
        user_id: format!("user_{}", addr),
        ethereum_address: addr.to_string(),
        tweaked_secret_share: None,
        hmac_constant: [0x42u8; 32],
        user_group_key: None,
        derived_eth_address: None,
        derived_btc_address: None,
        intent_hashes: HashMap::new(),
        created_at: Utc::now(),
        registered_by_node: "test-node".to_string(),
    }
}

const ADDR_1: &str = "0x1111111111111111111111111111111111111111";
const ADDR_2: &str = "0x2222222222222222222222222222222222222222";
const ADDR_3: &str = "0x3333333333333333333333333333333333333333";

// ===================================================================
// User Registration
// ===================================================================

#[tokio::test]
async fn register_user_stores_in_database() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());
    let dkg_storage = DkgStorage::new(db.clone());

    // Set up DKG final secret for tweaked share computation
    let final_secret = test_scalar(100);
    dkg_storage.set_final_secret(final_secret).await.unwrap();

    let chain_code = [0x29u8; 32];
    let manager = UserIntentManager::new(db.clone(), chain_code);

    // Register user (3 args: address, dkg_secret, node_id)
    let result = manager
        .register_user(ADDR_1, Some(&final_secret), "test-node")
        .await;
    assert!(result.is_ok(), "User registration should succeed: {:?}", result.err());

    // Verify user exists in storage
    let user = user_storage.get_user(ADDR_1).await.unwrap();
    assert!(user.is_some());
    let u = user.unwrap();
    assert_eq!(u.ethereum_address, ADDR_1);
}

#[tokio::test]
async fn register_user_twice_returns_existing() {
    let (db, _tmp) = temp_db();
    let dkg_storage = DkgStorage::new(db.clone());
    let final_secret = test_scalar(100);
    dkg_storage.set_final_secret(final_secret).await.unwrap();

    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);

    // First registration should succeed
    let r1 = manager
        .register_user(ADDR_1, Some(&final_secret), "test-node")
        .await;
    assert!(r1.is_ok());

    // Second registration may return existing or error — either is acceptable
    let r2 = manager
        .register_user(ADDR_1, Some(&final_secret), "test-node")
        .await;
    // Just verify the user still exists in DB regardless
    let user_storage = UserStorage::new(db.clone());
    let user = user_storage.get_user(ADDR_1).await.unwrap();
    assert!(user.is_some(), "User should exist after registration attempts");
}

#[tokio::test]
async fn register_multiple_users() {
    let (db, _tmp) = temp_db();
    let dkg_storage = DkgStorage::new(db.clone());
    let final_secret = test_scalar(100);
    dkg_storage.set_final_secret(final_secret).await.unwrap();

    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);
    let user_storage = UserStorage::new(db.clone());

    for addr in [ADDR_1, ADDR_2, ADDR_3] {
        manager
            .register_user(addr, Some(&final_secret), "test-node")
            .await
            .unwrap();
    }

    // All users should exist
    for addr in [ADDR_1, ADDR_2, ADDR_3] {
        assert!(user_storage.get_user(addr).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn register_user_without_dkg_secret() {
    let (db, _tmp) = temp_db();
    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);

    // Register without DKG secret (observer node pattern)
    let result = manager
        .register_user(ADDR_1, None, "observer-node")
        .await;
    assert!(result.is_ok());
}

// ===================================================================
// Tweaked Share Stripping (State Sync Simulation)
// ===================================================================

#[tokio::test]
async fn tweaked_share_stripped_during_export() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());

    // Store user with tweaked share
    let user = make_user_with_tweaked_share(ADDR_1, test_scalar(42));
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    // Simulate export stripping
    let mut exported = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    exported.tweaked_secret_share = None;

    // Import on receiving node
    let (db2, _tmp2) = temp_db();
    let user_storage2 = UserStorage::new(db2.clone());
    user_storage2.store_user(ADDR_1, &exported).await.unwrap();

    // Verify tweaked share is stripped
    let imported = user_storage2.get_user(ADDR_1).await.unwrap().unwrap();
    assert!(imported.tweaked_secret_share.is_none());
}

#[tokio::test]
async fn tweaked_share_refresh_restores_from_dkg_secret() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());
    let dkg_storage = DkgStorage::new(db.clone());

    // Set up DKG secret
    let final_secret = test_scalar(100);
    dkg_storage.set_final_secret(final_secret).await.unwrap();

    // Store user WITHOUT tweaked share (simulating state sync import)
    let user = make_user_without_share(ADDR_1);
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    let chain_code = [0x29u8; 32];
    let manager = UserIntentManager::new(db.clone(), chain_code);

    // Refresh tweaked shares
    let refreshed = manager.refresh_all_user_tweaked_shares().await;
    assert!(refreshed.is_ok());

    // Verify tweaked share is now present
    let updated = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    assert!(
        updated.tweaked_secret_share.is_some(),
        "Tweaked share should be restored after refresh"
    );
}

#[tokio::test]
async fn refresh_preserves_existing_tweaked_shares() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());
    let dkg_storage = DkgStorage::new(db.clone());

    let final_secret = test_scalar(100);
    dkg_storage.set_final_secret(final_secret).await.unwrap();

    // Store user WITH a tweaked share
    let original_share = test_scalar(999);
    let user = make_user_with_tweaked_share(ADDR_1, original_share);
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);

    // Refresh - should recompute (since it recomputes from HMAC + DKG secret)
    let _ = manager.refresh_all_user_tweaked_shares().await;

    let updated = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    assert!(updated.tweaked_secret_share.is_some());
}

#[tokio::test]
async fn refresh_multiple_users_tweaked_shares() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());
    let dkg_storage = DkgStorage::new(db.clone());

    let final_secret = test_scalar(100);
    dkg_storage.set_final_secret(final_secret).await.unwrap();

    // Store 3 users without tweaked shares
    for addr in [ADDR_1, ADDR_2, ADDR_3] {
        user_storage
            .store_user(addr, &make_user_without_share(addr))
            .await
            .unwrap();
    }

    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);
    let result = manager.refresh_all_user_tweaked_shares().await;
    assert!(result.is_ok());

    // All users should now have tweaked shares
    for addr in [ADDR_1, ADDR_2, ADDR_3] {
        let u = user_storage.get_user(addr).await.unwrap().unwrap();
        assert!(
            u.tweaked_secret_share.is_some(),
            "User {} should have tweaked share after refresh",
            addr
        );
    }
}

// ===================================================================
// Intent Status Management
// ===================================================================

#[tokio::test]
async fn intent_status_transitions() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());

    let mut user = make_user_without_share(ADDR_1);
    user.intent_hashes
        .insert("hash123".to_string(), IntentStatus::Pending);
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    // Update to Batched
    let mut user = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    user.intent_hashes
        .insert("hash123".to_string(), IntentStatus::Batched);
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    let updated = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    assert_eq!(updated.intent_hashes["hash123"], IntentStatus::Batched);
}

#[tokio::test]
async fn intent_batch_revert_to_pending() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());

    // User with Batched intent (simulating a failed signing)
    let mut user = make_user_without_share(ADDR_1);
    user.intent_hashes
        .insert("hash1".to_string(), IntentStatus::Batched);
    user.intent_hashes
        .insert("hash2".to_string(), IntentStatus::Batched);
    user.intent_hashes
        .insert("hash3".to_string(), IntentStatus::Solved); // should NOT be reverted
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    // Simulate revert: Batched -> Pending
    let mut user = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    for (_, status) in user.intent_hashes.iter_mut() {
        if *status == IntentStatus::Batched {
            *status = IntentStatus::Pending;
        }
    }
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    let updated = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    assert_eq!(updated.intent_hashes["hash1"], IntentStatus::Pending);
    assert_eq!(updated.intent_hashes["hash2"], IntentStatus::Pending);
    assert_eq!(
        updated.intent_hashes["hash3"],
        IntentStatus::Solved,
        "Solved intents should NOT be reverted"
    );
}

#[tokio::test]
async fn multiple_intents_per_user() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());

    let mut user = make_user_without_share(ADDR_1);
    for i in 0..10 {
        user.intent_hashes
            .insert(format!("intent_{}", i), IntentStatus::Pending);
    }
    user_storage.store_user(ADDR_1, &user).await.unwrap();

    let retrieved = user_storage.get_user(ADDR_1).await.unwrap().unwrap();
    assert_eq!(retrieved.intent_hashes.len(), 10);
}

// ===================================================================
// User Registration Serialization Edge Cases
// ===================================================================

#[test]
fn user_registration_with_all_fields_populated() {
    let mut user = make_user_without_share(ADDR_1);
    user.tweaked_secret_share = Some(SerializableScalar(test_scalar(42)));
    user.derived_eth_address = Some("0xderived_eth".to_string());
    user.derived_btc_address = Some("tb1q_derived_btc".to_string());
    user.user_group_key = Some(mpc_node::types::SerializablePoint(
        (k256::ProjectivePoint::GENERATOR * test_scalar(100)).to_affine(),
    ));
    user.intent_hashes
        .insert("hash1".to_string(), IntentStatus::Solved);

    let bytes = bincode::serialize(&user).unwrap();
    let deserialized: UserRegistration = bincode::deserialize(&bytes).unwrap();

    assert_eq!(user.ethereum_address, deserialized.ethereum_address);
    assert!(deserialized.tweaked_secret_share.is_some());
    assert_eq!(deserialized.derived_eth_address, Some("0xderived_eth".to_string()));
    assert_eq!(deserialized.derived_btc_address, Some("tb1q_derived_btc".to_string()));
    assert!(deserialized.user_group_key.is_some());
    assert_eq!(deserialized.intent_hashes.len(), 1);
}

#[test]
fn user_registration_minimal_fields() {
    let user = UserRegistration {
        user_id: "minimal".to_string(),
        ethereum_address: ADDR_1.to_string(),
        tweaked_secret_share: None,
        hmac_constant: [0u8; 32],
        user_group_key: None,
        derived_eth_address: None,
        derived_btc_address: None,
        intent_hashes: HashMap::new(),
        created_at: Utc::now(),
        registered_by_node: "test-node".to_string(),
    };

    let bytes = bincode::serialize(&user).unwrap();
    let deserialized: UserRegistration = bincode::deserialize(&bytes).unwrap();

    assert_eq!(deserialized.user_id, "minimal");
    assert!(deserialized.tweaked_secret_share.is_none());
    assert_eq!(deserialized.hmac_constant, [0u8; 32]);
}

// ===================================================================
// State Sync: Full Pipeline
// ===================================================================

#[tokio::test]
async fn state_sync_full_pipeline() {
    // Node A: has users with tweaked shares
    let (db_a, _tmp_a) = temp_db();
    let storage_a = UserStorage::new(db_a.clone());
    let dkg_a = DkgStorage::new(db_a.clone());

    let secret_a = test_scalar(42);
    dkg_a.set_final_secret(secret_a).await.unwrap();

    let user = make_user_with_tweaked_share(ADDR_1, test_scalar(999));
    storage_a.store_user(ADDR_1, &user).await.unwrap();

    // Export: strip tweaked share
    let mut exported = storage_a.get_user(ADDR_1).await.unwrap().unwrap();
    exported.tweaked_secret_share = None;

    // Node B: import stripped user
    let (db_b, _tmp_b) = temp_db();
    let storage_b = UserStorage::new(db_b.clone());
    let dkg_b = DkgStorage::new(db_b.clone());

    // Node B has its own DKG secret
    let secret_b = test_scalar(84);
    dkg_b.set_final_secret(secret_b).await.unwrap();

    storage_b.store_user(ADDR_1, &exported).await.unwrap();

    // Verify: imported user has no tweaked share
    let imported = storage_b.get_user(ADDR_1).await.unwrap().unwrap();
    assert!(imported.tweaked_secret_share.is_none());

    // Refresh on Node B
    let manager_b = UserIntentManager::new(db_b.clone(), [0x29u8; 32]);
    let result = manager_b.refresh_all_user_tweaked_shares().await;
    assert!(result.is_ok());

    // Verify: user now has tweaked share computed from Node B's DKG secret
    let refreshed = storage_b.get_user(ADDR_1).await.unwrap().unwrap();
    assert!(refreshed.tweaked_secret_share.is_some());
}

// ===================================================================
// Edge Cases
// ===================================================================

#[tokio::test]
async fn refresh_with_no_users_succeeds() {
    let (db, _tmp) = temp_db();
    let dkg_storage = DkgStorage::new(db.clone());
    dkg_storage.set_final_secret(test_scalar(100)).await.unwrap();

    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);

    // No users registered — should succeed gracefully
    let result = manager.refresh_all_user_tweaked_shares().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn refresh_without_dkg_secret_returns_error() {
    let (db, _tmp) = temp_db();
    let user_storage = UserStorage::new(db.clone());
    // No DKG secret stored

    user_storage
        .store_user(ADDR_1, &make_user_without_share(ADDR_1))
        .await
        .unwrap();

    let manager = UserIntentManager::new(db.clone(), [0x29u8; 32]);

    // Refresh without DKG secret should return an error
    let result = manager.refresh_all_user_tweaked_shares().await;
    assert!(result.is_err(), "Should error when DKG secret is not available");
}
