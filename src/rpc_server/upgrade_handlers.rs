/// RPC handlers for node upgrade operations
use anyhow::Result;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use warp::{reject, reply, Rejection, Reply};

use super::errors::RpcError;
use crate::{
    database::Database,
    network::upgrade::{
        NetworkVersionTracker, RollingUpgradeOrchestrator, UpgradePhase, UpgradeValidation,
    },
};

/// Helper function to create orchestrator from database and node_id
fn create_orchestrator(
    database: &Database,
    node_id: &str,
) -> Result<RollingUpgradeOrchestrator, RpcError> {
    let peer_id = PeerId::from_str(node_id).map_err(|e| RpcError::InternalError(e.to_string()))?;

    let version_tracker = Arc::new(NetworkVersionTracker::new());
    let backup_path = std::path::PathBuf::from("./backups");

    Ok(RollingUpgradeOrchestrator::new(
        peer_id,
        database.clone(),
        backup_path,
        version_tracker,
    ))
}

#[derive(Deserialize)]
pub struct ValidateUpgradeRequest {
    pub version: String,
    pub binary_path: Option<String>,
}

#[derive(Serialize)]
pub struct ValidateUpgradeResponse {
    pub safe: bool,
    pub checks: UpgradeValidation,
}

pub async fn handle_validate_upgrade(
    request: ValidateUpgradeRequest,
    database: Arc<Database>,
    node_id: String,
) -> Result<impl Reply, Rejection> {
    let orchestrator = create_orchestrator(&database, &node_id).map_err(|e| reject::custom(e))?;

    let validation = orchestrator
        .validate_upgrade(&request.version, request.binary_path.as_deref())
        .await
        .map_err(|e| reject::custom(RpcError::InternalError(e.to_string())))?;

    let safe = validation.is_safe();

    Ok(reply::json(&ValidateUpgradeResponse {
        safe,
        checks: validation,
    }))
}

#[derive(Deserialize)]
pub struct StartUpgradeRequest {
    pub version: String,
    pub binary_path: Option<String>,
}

#[derive(Serialize)]
pub struct StartUpgradeResponse {
    pub status: String,
    pub snapshot_id: String,
    pub message: String,
}

pub async fn handle_start_upgrade(
    request: StartUpgradeRequest,
    database: Arc<Database>,
    node_id: String,
) -> Result<impl Reply, Rejection> {
    let orchestrator = create_orchestrator(&database, &node_id).map_err(|e| reject::custom(e))?;

    let snapshot_id = orchestrator
        .start_upgrade(&request.version, request.binary_path.as_deref())
        .await
        .map_err(|e| reject::custom(RpcError::UpgradeFailed(e.to_string())))?;

    Ok(reply::json(&StartUpgradeResponse {
        status: "ready_for_restart".to_string(),
        snapshot_id,
        message: format!(
            "Node prepared for upgrade to {}. Restart required.",
            request.version
        ),
    }))
}

// Alias for compatibility
pub use handle_start_upgrade as handle_upgrade;

#[derive(Serialize)]
pub struct UpgradeStatusResponse {
    pub phase: String,
    pub snapshot_id: Option<String>,
    pub upgrade_mode: bool,
}

pub async fn handle_upgrade_status(database: Arc<Database>) -> Result<impl Reply, Rejection> {
    // For status, we need to read from database directly without node_id
    // Use a placeholder peer_id since we're just reading status
    let peer_id = PeerId::random();
    let version_tracker = Arc::new(NetworkVersionTracker::new());
    let backup_path = std::path::PathBuf::from("./backups");
    let orchestrator =
        RollingUpgradeOrchestrator::new(peer_id, (*database).clone(), backup_path, version_tracker);

    let status = orchestrator.get_status().await;

    let phase_str = match status.phase {
        UpgradePhase::Idle => "idle",
        UpgradePhase::Validating => "validating",
        UpgradePhase::PreparingSnapshot => "preparing_snapshot",
        UpgradePhase::SnapshotComplete => "snapshot_complete",
        UpgradePhase::EnteringUpgradeMode => "entering_upgrade_mode",
        UpgradePhase::DrainingOperations => "draining_operations",
        UpgradePhase::RunningMigrations => "running_migrations",
        UpgradePhase::ReadyForRestart => "ready_for_restart",
        UpgradePhase::Restarting => "restarting",
        UpgradePhase::Completed => "completed",
        UpgradePhase::Failed { .. } => "failed",
        UpgradePhase::RollingBack => "rolling_back",
        UpgradePhase::RolledBack => "rolled_back",
    };

    Ok(reply::json(&UpgradeStatusResponse {
        phase: phase_str.to_string(),
        snapshot_id: status.snapshot_id,
        upgrade_mode: status.upgrade_mode,
    }))
}

#[derive(Deserialize)]
pub struct RollbackRequest {
    pub snapshot_id: Option<String>,
}

#[derive(Serialize)]
pub struct RollbackResponse {
    pub status: String,
    pub message: String,
}

pub async fn handle_rollback(
    request: RollbackRequest,
    database: Arc<Database>,
) -> Result<impl Reply, Rejection> {
    let peer_id = PeerId::random();
    let version_tracker = Arc::new(NetworkVersionTracker::new());
    let backup_path = std::path::PathBuf::from("./backups");
    let orchestrator =
        RollingUpgradeOrchestrator::new(peer_id, (*database).clone(), backup_path, version_tracker);

    orchestrator
        .rollback(request.snapshot_id.as_deref())
        .await
        .map_err(|e| reject::custom(RpcError::UpgradeFailed(e.to_string())))?;

    Ok(reply::json(&RollbackResponse {
        status: "rolled_back".to_string(),
        message: "Node successfully rolled back. Restart with previous binary.".to_string(),
    }))
}

#[derive(Deserialize)]
pub struct CleanupSnapshotsRequest {
    pub keep_count: Option<usize>,
}

#[derive(Serialize)]
pub struct CleanupSnapshotsResponse {
    pub deleted_snapshots: usize,
}

pub async fn handle_cleanup_snapshots(
    request: CleanupSnapshotsRequest,
    database: Arc<Database>,
) -> Result<impl Reply, Rejection> {
    let keep_count = request.keep_count.unwrap_or(2);

    let peer_id = PeerId::random();
    let version_tracker = Arc::new(NetworkVersionTracker::new());
    let backup_path = std::path::PathBuf::from("./backups");
    let orchestrator =
        RollingUpgradeOrchestrator::new(peer_id, (*database).clone(), backup_path, version_tracker);

    let deleted = orchestrator
        .cleanup_snapshots(keep_count)
        .await
        .map_err(|e| reject::custom(RpcError::InternalError(e.to_string())))?;

    Ok(reply::json(&CleanupSnapshotsResponse {
        deleted_snapshots: deleted,
    }))
}

pub async fn handle_complete_upgrade(database: Arc<Database>) -> Result<impl Reply, Rejection> {
    let peer_id = PeerId::random();
    let version_tracker = Arc::new(NetworkVersionTracker::new());
    let backup_path = std::path::PathBuf::from("./backups");
    let orchestrator =
        RollingUpgradeOrchestrator::new(peer_id, (*database).clone(), backup_path, version_tracker);

    orchestrator
        .complete_upgrade()
        .await
        .map_err(|e| reject::custom(RpcError::InternalError(e.to_string())))?;

    Ok(reply::json(&serde_json::json!({
        "status": "completed",
        "message": "Upgrade completed successfully"
    })))
}
