//! Tests for three critical fixes to node reconnection behaviour:
//!
//! 1. **VRF round skew** (`is_vrf_round_within_range`): rounds *ahead* are always
//!    accepted so a rejoining node can catch up; only rounds too far *behind* are
//!    rejected.  (Inline tests in `src/network/rpc/rpc_handlers.rs`.)
//!
//! 2. **State sync tweaked-share refresh**: after importing user records from a
//!    peer (where `tweaked_secret_share` is stripped for security), the receiving
//!    node must recompute the shares from its own DKG final secret.
//!
//! 3. **Batch signing failure revert**: when TICS/BTC `sign_*_batch` fails, intent
//!    statuses that were set to `Batched` are reverted to `Pending` so they can be
//!    re-picked.

use chrono::Utc;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use std::collections::HashMap;

use mpc_node::database::{Database, DatabaseConfig, DkgStorage, UserStorage};
use mpc_node::types::user_intent::{IntentStatus, UserRegistration};
use mpc_node::types::SerializableScalar;
use mpc_node::user_intent_manager::UserIntentManager;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a temporary RocksDB-backed `Database` for tests.
fn temp_db() -> (Database, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let cfg = DatabaseConfig {
        path: tmp.path().to_str().unwrap().to_string(),
        create_if_missing: true,
        max_open_files: 64,
        // 32-byte hex key (all-zeros is fine for test encryption)
        encryption_key: Some("00".repeat(32)),
    };
    let db = Database::new(cfg).expect("failed to open test DB");
    (db, tmp)
}

/// A fixed, non-zero scalar usable as a DKG final secret share in tests.
fn test_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = 42;
    Option::from(Scalar::from_repr(bytes.into())).expect("valid scalar")
}

const TEST_ETH_ADDR: &str = "0x1234567890abcdef1234567890abcdef12345678";
const TEST_NODE_ID: &str = "12D3KooWTestNode1";

// ===================================================================
// State-sync tweaked-share stripping and refresh
// ===================================================================

/// Simulates the state-sync export stripping `tweaked_secret_share` and
/// verifies that `refresh_all_user_tweaked_shares` restores it.
#[tokio::test]
async fn tweaked_share_survives_strip_and_refresh_cycle() {
    let (db, _tmp) = temp_db();
    let chain_code = [1u8; 32];
    let uim = UserIntentManager::new(db.clone(), chain_code);

    let secret = test_scalar();

    // Register a user with a DKG secret share -> tweaked_secret_share is set.
    let reg = uim
        .register_user(TEST_ETH_ADDR, Some(&secret), TEST_NODE_ID)
        .await
        .expect("register_user should succeed");

    assert!(
        reg.tweaked_secret_share.is_some(),
        "tweaked share should be set after registration with DKG share"
    );

    let original_tweaked = reg.tweaked_secret_share.clone().unwrap();

    // -- Simulate the state-sync export: strip tweaked_secret_share --
    let addr_key = reg.ethereum_address.clone();
    let mut stripped = reg.clone();
    stripped.tweaked_secret_share = None;

    // Overwrite the user record in the DB (just like import_batch does).
    let user_storage = UserStorage::new(db.clone());
    user_storage
        .store_user(&addr_key, &stripped)
        .await
        .expect("store_user should succeed");

    // Verify it's gone.
    let fetched = uim
        .get_user_by_address(&addr_key)
        .await
        .expect("user should exist");
    assert!(
        fetched.tweaked_secret_share.is_none(),
        "tweaked share should be None after simulated sync import"
    );

    // -- Now store the DKG final secret so refresh can find it --
    let dkg_storage = DkgStorage::new(db.clone());
    dkg_storage
        .set_final_secret(secret)
        .await
        .expect("set_final_secret should succeed");

    // -- Call the refresh function (the fix) --
    uim.refresh_all_user_tweaked_shares()
        .await
        .expect("refresh should succeed");

    // Verify the tweaked share is restored.
    let refreshed = uim
        .get_user_by_address(&addr_key)
        .await
        .expect("user should exist after refresh");
    assert!(
        refreshed.tweaked_secret_share.is_some(),
        "tweaked share should be restored after refresh"
    );

    // Verify it matches the original value.
    let refreshed_bytes = refreshed.tweaked_secret_share.unwrap().0.to_bytes();
    let original_bytes = original_tweaked.0.to_bytes();
    assert_eq!(
        refreshed_bytes, original_bytes,
        "refreshed tweaked share must equal the original"
    );
}

/// When no DKG final secret exists, `refresh_all_user_tweaked_shares` should
/// return an error rather than silently leaving shares as None.
#[tokio::test]
async fn refresh_fails_without_dkg_final_secret() {
    let (db, _tmp) = temp_db();
    let chain_code = [1u8; 32];
    let uim = UserIntentManager::new(db.clone(), chain_code);

    // Register a user *without* a DKG secret (tweaked share will be None).
    uim.register_user(TEST_ETH_ADDR, None, TEST_NODE_ID)
        .await
        .expect("register_user should succeed");

    // No final secret stored -> refresh should fail with a clear error.
    let result = uim.refresh_all_user_tweaked_shares().await;
    assert!(
        result.is_err(),
        "refresh should fail when no DKG final secret is stored"
    );
}

/// Multiple users all get their tweaked shares refreshed.
#[tokio::test]
async fn refresh_handles_multiple_users() {
    let (db, _tmp) = temp_db();
    let chain_code = [2u8; 32];
    let uim = UserIntentManager::new(db.clone(), chain_code);
    let secret = test_scalar();

    let addresses = [
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "0xcccccccccccccccccccccccccccccccccccccccc",
    ];

    // Register all users with DKG share, then strip tweaked shares.
    let user_storage = UserStorage::new(db.clone());
    let mut original_shares: HashMap<String, Vec<u8>> = HashMap::new();

    for addr in &addresses {
        let reg = uim
            .register_user(addr, Some(&secret), TEST_NODE_ID)
            .await
            .expect("register_user should succeed");

        original_shares.insert(
            reg.ethereum_address.clone(),
            reg.tweaked_secret_share.clone().unwrap().0.to_bytes().to_vec(),
        );

        // Simulate stripping (state sync export)
        let mut stripped = reg.clone();
        stripped.tweaked_secret_share = None;
        user_storage
            .store_user(&reg.ethereum_address, &stripped)
            .await
            .unwrap();
    }

    // Store final secret and refresh.
    let dkg_storage = DkgStorage::new(db.clone());
    dkg_storage.set_final_secret(secret).await.unwrap();
    uim.refresh_all_user_tweaked_shares().await.unwrap();

    // Verify all users got their shares back.
    for (addr, orig_bytes) in &original_shares {
        let user = uim
            .get_user_by_address(addr)
            .await
            .expect("user should exist");
        let refreshed_bytes = user
            .tweaked_secret_share
            .expect("tweaked share should be set")
            .0
            .to_bytes()
            .to_vec();
        assert_eq!(
            &refreshed_bytes, orig_bytes,
            "tweaked share for {} must match original",
            addr
        );
    }
}

/// Registration without a DKG share leaves tweaked_secret_share as None.
#[tokio::test]
async fn registration_without_dkg_share_has_no_tweaked_share() {
    let (db, _tmp) = temp_db();
    let uim = UserIntentManager::new(db, [0u8; 32]);

    let reg = uim
        .register_user(TEST_ETH_ADDR, None, TEST_NODE_ID)
        .await
        .expect("register_user should succeed");

    assert!(
        reg.tweaked_secret_share.is_none(),
        "tweaked share should be None when no DKG share is provided"
    );
}

// ===================================================================
// Batch signing failure -> intent status revert to Pending
// ===================================================================

/// When a batch signing fails, intents must be reverted from Batched to Pending.
#[tokio::test]
async fn intent_status_reverts_from_batched_to_pending() {
    let (db, _tmp) = temp_db();
    let chain_code = [3u8; 32];
    let uim = UserIntentManager::new(db.clone(), chain_code);

    // Register a user.
    let reg = uim
        .register_user(TEST_ETH_ADDR, None, TEST_NODE_ID)
        .await
        .expect("register_user should succeed");
    let addr = &reg.ethereum_address;

    // Store an intent as Pending (simulating deposit intake).
    let intent_hash = "abcd1234";
    let user_storage = UserStorage::new(db.clone());
    user_storage
        .store_user_intent(addr, intent_hash, IntentStatus::Pending)
        .await
        .expect("store_user_intent should succeed");

    // Move to Batched (simulating batch pickup by coordinator).
    uim.update_intent_status(addr, intent_hash, IntentStatus::Batched)
        .await
        .expect("update to Batched should succeed");

    // Verify it's Batched.
    let status = uim
        .get_intent_status(addr, intent_hash)
        .await
        .expect("should get status");
    assert_eq!(status, IntentStatus::Batched);

    // -- Simulate batch signing failure: revert to Pending --
    uim.update_intent_status(addr, intent_hash, IntentStatus::Pending)
        .await
        .expect("revert to Pending should succeed");

    let reverted = uim
        .get_intent_status(addr, intent_hash)
        .await
        .expect("should get status after revert");
    assert_eq!(
        reverted,
        IntentStatus::Pending,
        "intent should be back to Pending after batch signing failure"
    );
}

/// Multiple intents in a batch are all reverted on failure.
#[tokio::test]
async fn multiple_intents_all_revert_on_batch_failure() {
    let (db, _tmp) = temp_db();
    let chain_code = [4u8; 32];
    let uim = UserIntentManager::new(db.clone(), chain_code);

    let reg = uim
        .register_user(TEST_ETH_ADDR, None, TEST_NODE_ID)
        .await
        .expect("register_user should succeed");
    let addr = &reg.ethereum_address;

    let intent_hashes = ["intent_001", "intent_002", "intent_003"];
    let user_storage = UserStorage::new(db.clone());

    // Store and batch all intents.
    for hash in &intent_hashes {
        user_storage
            .store_user_intent(addr, hash, IntentStatus::Pending)
            .await
            .expect("store_user_intent should succeed");
        uim.update_intent_status(addr, hash, IntentStatus::Batched)
            .await
            .expect("update to Batched should succeed");
    }

    // Verify all Batched.
    for hash in &intent_hashes {
        let s = uim.get_intent_status(addr, hash).await.unwrap();
        assert_eq!(s, IntentStatus::Batched);
    }

    // -- Simulate batch signing failure: revert all --
    for hash in &intent_hashes {
        uim.update_intent_status(addr, hash, IntentStatus::Pending)
            .await
            .expect("revert should succeed");
    }

    // Verify all Pending.
    for hash in &intent_hashes {
        let s = uim.get_intent_status(addr, hash).await.unwrap();
        assert_eq!(
            s,
            IntentStatus::Pending,
            "intent {} should be Pending after revert",
            hash
        );
    }
}

/// An intent that is already Solved should NOT be affected by a batch failure
/// revert (only Batched intents get reverted in the real code).
#[tokio::test]
async fn solved_intent_is_not_affected_by_revert() {
    let (db, _tmp) = temp_db();
    let chain_code = [5u8; 32];
    let uim = UserIntentManager::new(db.clone(), chain_code);

    let reg = uim
        .register_user(TEST_ETH_ADDR, None, TEST_NODE_ID)
        .await
        .expect("register_user should succeed");
    let addr = &reg.ethereum_address;

    let solved_hash = "solved_001";
    let batched_hash = "batched_001";

    let user_storage = UserStorage::new(db.clone());

    // Store both intents.
    user_storage
        .store_user_intent(addr, solved_hash, IntentStatus::Pending)
        .await
        .unwrap();
    user_storage
        .store_user_intent(addr, batched_hash, IntentStatus::Pending)
        .await
        .unwrap();

    // One is Solved, one is Batched.
    uim.update_intent_status(addr, solved_hash, IntentStatus::Solved)
        .await
        .unwrap();
    uim.update_intent_status(addr, batched_hash, IntentStatus::Batched)
        .await
        .unwrap();

    // Revert only the batched one (this is what the real code does -- it iterates
    // batch_intents which only contains the intents from the current batch).
    uim.update_intent_status(addr, batched_hash, IntentStatus::Pending)
        .await
        .unwrap();

    // Verify: solved is still Solved, batched is now Pending.
    let s1 = uim.get_intent_status(addr, solved_hash).await.unwrap();
    let s2 = uim.get_intent_status(addr, batched_hash).await.unwrap();
    assert_eq!(s1, IntentStatus::Solved, "solved intent must stay Solved");
    assert_eq!(
        s2,
        IntentStatus::Pending,
        "batched intent must revert to Pending"
    );
}

/// Intent status transitions: Pending -> Batched -> Pending -> Batched -> Solved
/// Ensures that the revert+re-pick cycle works multiple times.
#[tokio::test]
async fn intent_can_be_re_batched_after_revert() {
    let (db, _tmp) = temp_db();
    let uim = UserIntentManager::new(db.clone(), [6u8; 32]);

    let reg = uim
        .register_user(TEST_ETH_ADDR, None, TEST_NODE_ID)
        .await
        .unwrap();
    let addr = &reg.ethereum_address;
    let hash = "retry_intent";

    let user_storage = UserStorage::new(db.clone());
    user_storage
        .store_user_intent(addr, hash, IntentStatus::Pending)
        .await
        .unwrap();

    // First batch attempt fails.
    uim.update_intent_status(addr, hash, IntentStatus::Batched)
        .await
        .unwrap();
    assert_eq!(
        uim.get_intent_status(addr, hash).await.unwrap(),
        IntentStatus::Batched
    );

    // Revert.
    uim.update_intent_status(addr, hash, IntentStatus::Pending)
        .await
        .unwrap();
    assert_eq!(
        uim.get_intent_status(addr, hash).await.unwrap(),
        IntentStatus::Pending
    );

    // Second batch attempt succeeds.
    uim.update_intent_status(addr, hash, IntentStatus::Batched)
        .await
        .unwrap();
    uim.update_intent_status(addr, hash, IntentStatus::Solved)
        .await
        .unwrap();
    assert_eq!(
        uim.get_intent_status(addr, hash).await.unwrap(),
        IntentStatus::Solved,
        "intent should reach Solved after successful re-batch"
    );
}

// ===================================================================
// State-sync export strips tweaked_secret_share via serialization
// ===================================================================

/// Verifies that the bincode round-trip of stripping tweaked_secret_share works:
/// serialize with None -> deserialize -> field is None.
#[test]
fn bincode_roundtrip_strips_tweaked_share() {
    let mut user = UserRegistration {
        user_id: "test-id".to_string(),
        ethereum_address: TEST_ETH_ADDR.to_string(),
        hmac_constant: [7u8; 32],
        tweaked_secret_share: Some(SerializableScalar(test_scalar())),
        user_group_key: None,
        derived_eth_address: None,
        derived_btc_address: None,
        created_at: Utc::now(),
        registered_by_node: TEST_NODE_ID.to_string(),
        intent_hashes: HashMap::new(),
    };

    // Verify initially has tweaked share.
    assert!(user.tweaked_secret_share.is_some());

    // Strip it (same as rpc_handlers.rs line 1100).
    user.tweaked_secret_share = None;

    // Serialize and deserialize (same as state sync export/import).
    let bytes = bincode::serialize(&user).expect("serialize should succeed");
    let deserialized: UserRegistration =
        bincode::deserialize(&bytes).expect("deserialize should succeed");

    assert!(
        deserialized.tweaked_secret_share.is_none(),
        "stripped share must remain None after bincode round-trip"
    );
    assert_eq!(deserialized.ethereum_address, TEST_ETH_ADDR);
    assert_eq!(deserialized.hmac_constant, [7u8; 32]);
}

/// Verifies that bincode serialization preserves tweaked_secret_share when
/// it's NOT stripped (normal DB storage).
#[test]
fn bincode_roundtrip_preserves_tweaked_share() {
    let scalar = test_scalar();
    let user = UserRegistration {
        user_id: "test-id".to_string(),
        ethereum_address: TEST_ETH_ADDR.to_string(),
        hmac_constant: [7u8; 32],
        tweaked_secret_share: Some(SerializableScalar(scalar)),
        user_group_key: None,
        derived_eth_address: None,
        derived_btc_address: None,
        created_at: Utc::now(),
        registered_by_node: TEST_NODE_ID.to_string(),
        intent_hashes: HashMap::new(),
    };

    let bytes = bincode::serialize(&user).expect("serialize should succeed");
    let deserialized: UserRegistration =
        bincode::deserialize(&bytes).expect("deserialize should succeed");

    assert!(
        deserialized.tweaked_secret_share.is_some(),
        "non-stripped share must survive bincode round-trip"
    );
    assert_eq!(
        deserialized.tweaked_secret_share.unwrap().0.to_bytes(),
        scalar.to_bytes(),
        "scalar value must match after round-trip"
    );
}

/// Simulates the full state-sync export→import→refresh pipeline via
/// bincode serialization (without needing a real network).
#[tokio::test]
async fn full_state_sync_simulation() {
    let (source_db, _tmp1) = temp_db();
    let (target_db, _tmp2) = temp_db();
    let chain_code = [9u8; 32];
    let secret = test_scalar();

    // Source node: register user with DKG share.
    let source_uim = UserIntentManager::new(source_db.clone(), chain_code);
    let reg = source_uim
        .register_user(TEST_ETH_ADDR, Some(&secret), TEST_NODE_ID)
        .await
        .unwrap();
    assert!(reg.tweaked_secret_share.is_some());

    // Source node: export with tweaked_secret_share stripped (as rpc_handlers does).
    let source_user_storage = UserStorage::new(source_db.clone());
    let user = source_user_storage
        .get_user(&reg.ethereum_address)
        .await
        .unwrap()
        .unwrap();
    let mut export_user = user.clone();
    export_user.tweaked_secret_share = None;
    let wire_bytes = bincode::serialize(&export_user).unwrap();

    // Target node: import the stripped user record.
    let target_user_storage = UserStorage::new(target_db.clone());
    let imported: UserRegistration = bincode::deserialize(&wire_bytes).unwrap();
    target_user_storage
        .store_user(&imported.ethereum_address, &imported)
        .await
        .unwrap();

    // Target node: verify tweaked share is None before refresh.
    let target_uim = UserIntentManager::new(target_db.clone(), chain_code);
    let before = target_uim
        .get_user_by_address(&reg.ethereum_address)
        .await
        .unwrap();
    assert!(
        before.tweaked_secret_share.is_none(),
        "imported record should have no tweaked share"
    );

    // Target node: store the same DKG final secret and refresh.
    let target_dkg = DkgStorage::new(target_db.clone());
    target_dkg.set_final_secret(secret).await.unwrap();
    target_uim.refresh_all_user_tweaked_shares().await.unwrap();

    // Target node: tweaked share is now restored and matches source.
    let after = target_uim
        .get_user_by_address(&reg.ethereum_address)
        .await
        .unwrap();
    assert!(after.tweaked_secret_share.is_some());
    assert_eq!(
        after.tweaked_secret_share.unwrap().0.to_bytes(),
        reg.tweaked_secret_share.unwrap().0.to_bytes(),
        "target node's refreshed share must match source node's original"
    );
}
