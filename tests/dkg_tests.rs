//! Comprehensive tests for the DKG module:
//! - DKG storage (final secret/public, commitments, peer indices, vault keys)
//! - Vault key derivation (tweaked secret shares, user group keys)
//! - Original commitments persistence

use k256::{AffinePoint, ProjectivePoint, Scalar};

use mpc_node::database::{Database, DatabaseConfig, DkgStorage};
use mpc_node::DKGNode;

fn temp_db() -> (Database, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = DatabaseConfig {
        path: tmp.path().to_str().unwrap().to_string(),
        create_if_missing: true,
        max_open_files: 64,
        encryption_key: Some("00".repeat(32)),
    };
    (Database::new(cfg).unwrap(), tmp)
}

fn s(val: u64) -> Scalar { Scalar::from(val) }

// === Final Secret / Public ===

#[tokio::test]
async fn store_and_retrieve_final_secret() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_final_secret().await.unwrap().is_none());
    st.set_final_secret(s(42)).await.unwrap();
    assert_eq!(st.get_final_secret().await.unwrap().unwrap(), s(42));
}

#[tokio::test]
async fn store_and_retrieve_final_public() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_final_public().await.unwrap().is_none());
    let pk = ProjectivePoint::GENERATOR * s(12345);
    st.set_final_public(pk).await.unwrap();
    assert_eq!(st.get_final_public().await.unwrap().unwrap(), pk);
}

#[tokio::test]
async fn delete_final_secret_and_public() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    st.set_final_secret(s(99)).await.unwrap();
    st.set_final_public(ProjectivePoint::GENERATOR).await.unwrap();
    st.delete_final_secret().await.unwrap();
    st.delete_final_public().await.unwrap();
    assert!(st.get_final_secret().await.unwrap().is_none());
    assert!(st.get_final_public().await.unwrap().is_none());
}

// === Commitments ===

#[tokio::test]
async fn store_and_retrieve_commitments() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    let c0 = AffinePoint::GENERATOR;
    let c1 = (ProjectivePoint::GENERATOR * s(2)).to_affine();
    st.store_commitments("peer-1", &[c0, c1]).await.unwrap();
    let all = st.get_all_commitments().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all["peer-1"].len(), 2);
    assert_eq!(all["peer-1"][0], c0);
}

#[tokio::test]
async fn original_commitments_persist_after_regular_clear() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    let c = vec![AffinePoint::GENERATOR];
    st.store_commitments("p1", &c).await.unwrap();
    st.store_original_commitments("p1", &c).await.unwrap();
    st.clear_commitments().await.unwrap();
    assert!(st.get_all_commitments().await.unwrap().is_empty());
    assert_eq!(st.get_all_original_commitments().await.unwrap().len(), 1);
}

#[tokio::test]
async fn multiple_peers_original_commitments() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    st.store_original_commitments("p1", &[AffinePoint::GENERATOR]).await.unwrap();
    st.store_original_commitments("p2", &[(ProjectivePoint::GENERATOR * s(7)).to_affine()]).await.unwrap();
    st.store_original_commitments("p3", &[(ProjectivePoint::GENERATOR * s(13)).to_affine()]).await.unwrap();
    assert_eq!(st.get_all_original_commitments().await.unwrap().len(), 3);
}

#[tokio::test]
async fn commitments_for_nonexistent_peer() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_commitments_for("ghost").await.unwrap().is_none());
}

// === Peer Indices ===

#[tokio::test]
async fn peer_index_storage() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    st.set_peer_index("p1", 1).unwrap();
    st.set_peer_index("p2", 2).unwrap();
    st.set_peer_index("p3", 3).unwrap();
    let idx = st.get_peer_indices().await.unwrap();
    assert_eq!(idx.len(), 3);
    assert_eq!(idx["p1"], 1);
    assert_eq!(st.get_peer_index_for("p2").unwrap(), Some(2));
    assert_eq!(st.get_peer_index_for("none").unwrap(), None);
}

#[tokio::test]
async fn my_permanent_index() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_my_permanent_index().await.unwrap().is_none());
    st.set_my_permanent_index(2).await.unwrap();
    assert_eq!(st.get_my_permanent_index().await.unwrap(), Some(2));
}

// === Vault Tweaked Secret ===

#[tokio::test]
async fn vault_tweaked_secret_crud() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_vault_tweaked_secret().await.unwrap().is_none());
    st.set_vault_tweaked_secret(s(777)).await.unwrap();
    assert_eq!(st.get_vault_tweaked_secret().await.unwrap().unwrap(), s(777));
    st.delete_vault_tweaked_secret().await.unwrap();
    assert!(st.get_vault_tweaked_secret().await.unwrap().is_none());
}

// === Vault Group Key ===

#[tokio::test]
async fn vault_group_key_crud() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_vault_group_key().await.unwrap().is_none());
    let gk = ProjectivePoint::GENERATOR * s(555);
    st.set_vault_group_key(gk).await.unwrap();
    assert_eq!(st.get_vault_group_key().await.unwrap().unwrap(), gk);
    st.delete_vault_group_key().await.unwrap();
    assert!(st.get_vault_group_key().await.unwrap().is_none());
}

// === Initial DKG Complete Flag ===

#[tokio::test]
async fn initial_dkg_complete_flag() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(!st.is_initial_dkg_complete().await.unwrap_or(false));
    st.set_initial_dkg_complete(true).await.unwrap();
    assert!(st.is_initial_dkg_complete().await.unwrap());
    st.set_initial_dkg_complete(false).await.unwrap();
    assert!(!st.is_initial_dkg_complete().await.unwrap());
}

// === Signer Count ===

#[tokio::test]
async fn signer_count() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(st.get_dkg_signer_count().unwrap().is_none());
    st.set_dkg_signer_count(3).unwrap();
    assert_eq!(st.get_dkg_signer_count().unwrap(), Some(3));
}

// === Share Tracking ===

#[tokio::test]
async fn share_tracking() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    assert!(!st.is_share_received("p1").await.unwrap());
    st.mark_share_received("p1").await.unwrap();
    assert!(st.is_share_received("p1").await.unwrap());
    assert!(!st.is_share_received("p2").await.unwrap());
}

// === Shares ===

#[tokio::test]
async fn share_storage() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    let share = mpc_node::types::KeyShare {
        index: 1,
        value: mpc_node::types::SerializableScalar(s(42)),
    };
    st.store_share("p1", &share).await.unwrap();
    let all = st.get_all_shares().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all["p1"].index, 1);
    st.clear_shares().await.unwrap();
    assert!(st.get_all_shares().await.unwrap().is_empty());
}

// === Validations ===

#[tokio::test]
async fn validations() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    st.add_validation("n1", "p2", true).await.unwrap();
    st.add_validation("n1", "p3", true).await.unwrap();
    let v = st.get_all_validations().await.unwrap();
    assert!(!v.is_empty());
}

// === Vault: Tweaked Secret Share via DKGNode ===

#[tokio::test]
async fn vault_tweaked_share_calculation() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db.clone());
    let final_secret = s(100);
    st.set_final_secret(final_secret).await.unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n1".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let tweak = s(50);
    let tweaked = node.calculate_vault_tweaked_secret_share(tweak).await.unwrap();
    assert_eq!(tweaked, final_secret + tweak);
}

#[tokio::test]
async fn vault_tweaked_share_no_secret_errors() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n1".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let result = node.calculate_vault_tweaked_secret_share(s(50)).await;
    assert!(result.is_err());
}

// === Vault: User Group Key ===

#[tokio::test]
async fn user_group_key_uses_final_public() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db.clone());
    let fp = ProjectivePoint::GENERATOR * s(999);
    st.set_final_public(fp).await.unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let tweak = s(42);
    let uk = node.derive_user_specific_group_key_from_commitments(tweak).await.unwrap();
    assert_eq!(uk, fp + ProjectivePoint::GENERATOR * tweak);
}

#[tokio::test]
async fn user_group_key_no_final_public_errors() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let result = node.derive_user_specific_group_key_from_commitments(s(42)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn user_group_key_different_tweaks() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db.clone());
    st.set_final_public(ProjectivePoint::GENERATOR * s(999)).await.unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let k1 = node.derive_user_specific_group_key_from_commitments(s(1)).await.unwrap();
    let k2 = node.derive_user_specific_group_key_from_commitments(s(2)).await.unwrap();
    assert_ne!(k1, k2);
}

// === Vault: Original Commitments Derivation ===

#[tokio::test]
async fn vault_from_original_commitments() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db.clone());
    st.store_original_commitments("p1", &[(ProjectivePoint::GENERATOR * s(10)).to_affine()]).await.unwrap();
    st.store_original_commitments("p2", &[(ProjectivePoint::GENERATOR * s(20)).to_affine()]).await.unwrap();
    st.store_original_commitments("p3", &[(ProjectivePoint::GENERATOR * s(30)).to_affine()]).await.unwrap();
    st.set_peer_index("p1", 1).unwrap();
    st.set_peer_index("p2", 2).unwrap();
    st.set_peer_index("p3", 3).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let tweak = s(5);
    let vk = node.derive_vault_group_key_from_original_commitments(tweak).await.unwrap();
    let expected = ProjectivePoint::GENERATOR * s(60) + ProjectivePoint::GENERATOR * tweak;
    assert_eq!(vk, expected);
}

#[tokio::test]
async fn vault_from_empty_original_commitments_errors() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db);
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    assert!(node.derive_vault_group_key_from_original_commitments(s(1)).await.is_err());
}

// === Consistency: tweaked share is additive ===

#[tokio::test]
async fn tweaked_share_additive_property() {
    let (db, _t) = temp_db();
    let st = DkgStorage::new(db.clone());
    let fs = s(1000);
    let tw = s(234);
    st.set_final_secret(fs).await.unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let node = DKGNode::new("n".to_string(), 2, 3, tx, st, [0x29u8; 32]);
    let tweaked = node.calculate_vault_tweaked_secret_share(tw).await.unwrap();
    assert_eq!(tweaked, fs + tw);
    // Public key consistency
    assert_eq!(
        ProjectivePoint::GENERATOR * tweaked,
        ProjectivePoint::GENERATOR * fs + ProjectivePoint::GENERATOR * tw
    );
}

// === Consistency: user key same regardless of commitment state ===

#[tokio::test]
async fn user_key_consistent_despite_partial_commitments() {
    let fp = ProjectivePoint::GENERATOR * s(60);
    let tweak = s(42);

    let (db1, _t1) = temp_db();
    let s1 = DkgStorage::new(db1.clone());
    s1.set_final_public(fp).await.unwrap();
    s1.store_commitments("p1", &[AffinePoint::GENERATOR]).await.unwrap();
    s1.store_commitments("p2", &[(ProjectivePoint::GENERATOR * s(2)).to_affine()]).await.unwrap();
    let (tx1, _rx1) = tokio::sync::mpsc::channel(10);
    let n1 = DKGNode::new("n1".to_string(), 2, 3, tx1, s1, [0x29u8; 32]);

    let (db2, _t2) = temp_db();
    let s2 = DkgStorage::new(db2.clone());
    s2.set_final_public(fp).await.unwrap();
    // Only 1 commitment (peer disconnect)
    s2.store_commitments("p1", &[AffinePoint::GENERATOR]).await.unwrap();
    let (tx2, _rx2) = tokio::sync::mpsc::channel(10);
    let n2 = DKGNode::new("n2".to_string(), 2, 3, tx2, s2, [0x29u8; 32]);

    let k1 = n1.derive_user_specific_group_key_from_commitments(tweak).await.unwrap();
    let k2 = n2.derive_user_specific_group_key_from_commitments(tweak).await.unwrap();
    assert_eq!(k1, k2, "User key must be same regardless of commitment state");
}
