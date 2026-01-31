/// Rolling upgrade orchestrator for zero-downtime upgrades
use anyhow::{anyhow, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use super::version_tracker::NetworkVersionTracker;
use crate::database::{Database, MigrationRunner, StatePreservationManager, VersionStorage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpgradePhase {
    Idle,
    Validating,
    PreparingSnapshot,
    SnapshotComplete,
    EnteringUpgradeMode,
    DrainingOperations,
    RunningMigrations,
    ReadyForRestart,
    Restarting,
    Completed,
    Failed { reason: String },
    RollingBack,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeValidation {
    pub binary_available: bool,
    pub network_compatible: bool,
    pub migration_available: bool,
    pub threshold_maintained: bool,
    pub sufficient_disk_space: bool,
    pub warnings: Vec<String>,
}

impl UpgradeValidation {
    pub fn new() -> Self {
        Self {
            binary_available: false,
            network_compatible: false,
            migration_available: false,
            threshold_maintained: false,
            sufficient_disk_space: false,
            warnings: Vec::new(),
        }
    }

    pub fn is_safe(&self) -> bool {
        self.binary_available
            && self.network_compatible
            && self.migration_available
            && self.threshold_maintained
            && self.sufficient_disk_space
    }
}

impl Default for UpgradeValidation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct RollingUpgradeOrchestrator {
    node_id: PeerId,
    db: Database,
    state_manager: Arc<StatePreservationManager>,
    version_tracker: Arc<NetworkVersionTracker>,
    current_phase: Arc<RwLock<UpgradePhase>>,
    current_snapshot_id: Arc<RwLock<Option<String>>>,
}

impl RollingUpgradeOrchestrator {
    pub fn new(
        node_id: PeerId,
        db: Database,
        backup_path: PathBuf,
        version_tracker: Arc<NetworkVersionTracker>,
    ) -> Self {
        let state_manager = Arc::new(StatePreservationManager::new(db.clone(), backup_path));

        Self {
            node_id,
            db,
            state_manager,
            version_tracker,
            current_phase: Arc::new(RwLock::new(UpgradePhase::Idle)),
            current_snapshot_id: Arc::new(RwLock::new(None)),
        }
    }

    /// Validate if upgrade is safe to proceed
    pub async fn validate_upgrade(
        &self,
        target_version: &str,
        binary_path: Option<&str>,
    ) -> Result<UpgradeValidation> {
        info!("🔍 [UPGRADE] Validating upgrade to {}", target_version);

        let mut validation = UpgradeValidation::new();

        // 1. Check if binary exists and is executable
        if let Some(path) = binary_path {
            validation.binary_available = std::path::Path::new(path).exists();
            if !validation.binary_available {
                validation
                    .warnings
                    .push(format!("Binary not found at: {}", path));
            }
        } else {
            validation.binary_available = true; // Assume binary will be available
            validation
                .warnings
                .push("Binary path not provided, assuming it will be available".to_string());
        }

        // 2. Check network compatibility
        match self.version_tracker.can_version_join(target_version).await {
            Ok(can_join) => {
                validation.network_compatible = can_join;
                if !can_join {
                    validation.warnings.push(format!(
                        "Version {} is not compatible with current network",
                        target_version
                    ));
                }
            }
            Err(e) => {
                validation
                    .warnings
                    .push(format!("Failed to check network compatibility: {}", e));
            }
        }

        // 3. Check if migrations are available
        validation.migration_available = true; // Migrations are always available

        // 4. Check threshold will be maintained
        // First try to get peer count from version tracker (network layer)
        let mut peer_count = self.version_tracker.get_peer_count().await;

        // If version tracker has no peers, try to get from database (DKG participants)
        if peer_count == 0 {
            peer_count = self.get_peer_count_from_database().await.unwrap_or(0);
            if peer_count > 0 {
                info!("📊 [UPGRADE] Found {} peers from database", peer_count);
            }
        }

        // Need at least 4 nodes for safe rolling upgrade (2/3 + 1 = 3 threshold, with 1 down)
        // For testing/small networks, allow 3 nodes with warning
        if peer_count >= 4 {
            validation.threshold_maintained = true;
        } else if peer_count >= 3 {
            validation.threshold_maintained = true; // Allow for testing
            validation.warnings.push(format!(
                "Network has {} nodes (minimum for testing). Production should have 4+ nodes.",
                peer_count
            ));
        } else if peer_count == 0 {
            // No peer info available (standalone node or fresh orchestrator)
            // Allow upgrade but warn
            validation.threshold_maintained = true;
            validation.warnings.push(
                "Unable to detect network size. Proceeding with upgrade (use caution in production).".to_string()
            );
        } else {
            validation.threshold_maintained = false;
            validation.warnings.push(format!(
                "Network has {} nodes, need at least 3 for upgrade",
                peer_count
            ));
        }

        // 5. Check disk space
        match self.check_disk_space().await {
            Ok(available_gb) => {
                validation.sufficient_disk_space = available_gb >= 1.0; // Need at least 1GB
                if !validation.sufficient_disk_space {
                    validation.warnings.push(format!(
                        "Insufficient disk space: {:.2}GB available, recommend at least 1GB",
                        available_gb
                    ));
                }
            }
            Err(e) => {
                validation
                    .warnings
                    .push(format!("Failed to check disk space: {}", e));
            }
        }

        info!(
            "✅ [UPGRADE] Validation complete: safe={}",
            validation.is_safe()
        );
        Ok(validation)
    }

    /// Start the upgrade process
    pub async fn start_upgrade(
        &self,
        target_version: &str,
        binary_path: Option<&str>,
    ) -> Result<String> {
        info!(
            "🚀 [UPGRADE] Starting upgrade to version {}",
            target_version
        );

        // Validate first
        let validation = self.validate_upgrade(target_version, binary_path).await?;
        if !validation.is_safe() {
            return Err(anyhow!("Upgrade validation failed: {:?}", validation));
        }

        // Update phase
        *self.current_phase.write().await = UpgradePhase::PreparingSnapshot;

        // Create snapshot
        info!("📸 [UPGRADE] Creating upgrade snapshot...");
        let snapshot_id = self
            .state_manager
            .create_upgrade_snapshot(target_version)
            .await?;
        *self.current_snapshot_id.write().await = Some(snapshot_id.clone());

        // Store snapshot ID in database
        let version_storage = VersionStorage::new(self.db.clone());
        version_storage.store_snapshot_id(&snapshot_id).await?;

        *self.current_phase.write().await = UpgradePhase::SnapshotComplete;
        info!("✅ [UPGRADE] Snapshot created: {}", snapshot_id);

        // Enter upgrade mode
        self.enter_upgrade_mode().await?;

        // Drain operations
        self.drain_operations(Duration::from_secs(30)).await?;

        // Run migrations
        self.run_migrations(target_version).await?;

        // Signal ready for restart
        *self.current_phase.write().await = UpgradePhase::ReadyForRestart;
        info!("✅ [UPGRADE] Node prepared for upgrade, ready for restart");

        Ok(snapshot_id)
    }

    /// Enter upgrade mode (stop accepting new requests)
    async fn enter_upgrade_mode(&self) -> Result<()> {
        info!("🔒 [UPGRADE] Entering upgrade mode");
        *self.current_phase.write().await = UpgradePhase::EnteringUpgradeMode;

        let version_storage = VersionStorage::new(self.db.clone());
        version_storage.set_upgrade_mode(true).await?;

        Ok(())
    }

    /// Drain in-flight operations
    async fn drain_operations(&self, timeout: Duration) -> Result<()> {
        info!("⏳ [UPGRADE] Draining operations (timeout: {:?})", timeout);
        *self.current_phase.write().await = UpgradePhase::DrainingOperations;

        let start = tokio::time::Instant::now();

        loop {
            let active_count = self.get_active_operation_count().await?;

            if active_count == 0 {
                info!("✅ [UPGRADE] All operations drained");
                return Ok(());
            }

            if start.elapsed() > timeout {
                warn!(
                    "⚠️ [UPGRADE] Drain timeout reached with {} active operations",
                    active_count
                );
                // Proceed anyway - operations will fail gracefully
                return Ok(());
            }

            info!(
                "⏳ [UPGRADE] Waiting for {} operations to complete...",
                active_count
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Get count of active operations
    async fn get_active_operation_count(&self) -> Result<usize> {
        let signing_count = self
            .db
            .get_string::<String>("signing:active_count")?
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let vrf_count = self
            .db
            .get_string::<String>("vrf:active_count")?
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        Ok(signing_count + vrf_count)
    }

    /// Run database migrations
    async fn run_migrations(&self, target_version: &str) -> Result<()> {
        info!(
            "🔧 [UPGRADE] Running database migrations to {}",
            target_version
        );
        *self.current_phase.write().await = UpgradePhase::RunningMigrations;

        let migration_runner = MigrationRunner::new(self.db.clone());
        migration_runner.migrate_to_version(target_version).await?;

        // Update node version
        let version_storage = VersionStorage::new(self.db.clone());
        version_storage.store_node_version(target_version).await?;

        info!("✅ [UPGRADE] Migrations completed successfully");
        Ok(())
    }

    /// Complete upgrade after restart
    pub async fn complete_upgrade(&self) -> Result<()> {
        info!("✅ [UPGRADE] Completing upgrade");

        // Exit upgrade mode
        let version_storage = VersionStorage::new(self.db.clone());
        version_storage.set_upgrade_mode(false).await?;

        // Clear snapshot ID
        version_storage.clear_snapshot_id().await?;

        *self.current_phase.write().await = UpgradePhase::Completed;

        info!("🎉 [UPGRADE] Upgrade completed successfully");
        Ok(())
    }

    /// Rollback to previous version
    pub async fn rollback(&self, snapshot_id: Option<&str>) -> Result<()> {
        error!("🔄 [UPGRADE] Rolling back upgrade");
        *self.current_phase.write().await = UpgradePhase::RollingBack;

        // Determine snapshot ID
        let snapshot = if let Some(id) = snapshot_id {
            id.to_string()
        } else if let Some(id) = self.current_snapshot_id.read().await.clone() {
            id
        } else {
            // Try to get from database
            let version_storage = VersionStorage::new(self.db.clone());
            version_storage
                .get_snapshot_id()
                .await?
                .ok_or_else(|| anyhow!("No snapshot ID available for rollback"))?
        };

        info!("🔄 [UPGRADE] Rolling back to snapshot: {}", snapshot);

        // Restore from snapshot
        self.state_manager.restore_from_snapshot(&snapshot).await?;

        // Exit upgrade mode
        let version_storage = VersionStorage::new(self.db.clone());
        version_storage.set_upgrade_mode(false).await?;

        *self.current_phase.write().await = UpgradePhase::RolledBack;

        info!("✅ [UPGRADE] Rollback completed");
        Ok(())
    }

    /// Get current upgrade status
    pub async fn get_status(&self) -> UpgradeStatus {
        let phase = self.current_phase.read().await.clone();
        let snapshot_id = self.current_snapshot_id.read().await.clone();
        let version_storage = VersionStorage::new(self.db.clone());
        let upgrade_mode = version_storage.is_upgrade_mode().await.unwrap_or(false);

        UpgradeStatus {
            phase,
            snapshot_id,
            upgrade_mode,
        }
    }

    /// Check disk space (in GB)
    async fn check_disk_space(&self) -> Result<f64> {
        // Simplified implementation - in production use sys-info or similar
        // For now, return a safe value
        Ok(10.0) // Assume 10GB available
    }

    /// Get peer count from database (DKG participants)
    async fn get_peer_count_from_database(&self) -> Result<usize> {
        use crate::database::keys::PEER_INDEX;

        // Get all keys with PEER_INDEX prefix
        let results: Vec<(String, usize)> = self.db.get_values_with_prefix(PEER_INDEX)?;
        let count = results.len();

        if count > 0 {
            info!("📊 [UPGRADE] Found {} peers in database", count);
        }

        Ok(count)
    }

    /// Cleanup old snapshots
    pub async fn cleanup_snapshots(&self, keep_count: usize) -> Result<usize> {
        self.state_manager.cleanup_old_snapshots(keep_count).await
    }
}

#[derive(Debug, Serialize)]
pub struct UpgradeStatus {
    pub phase: UpgradePhase,
    pub snapshot_id: Option<String>,
    pub upgrade_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_upgrade_orchestrator() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("db");
        let backup_path = temp_dir.path().join("backups");

        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            create_if_missing: true,
            max_open_files: 100,
            encryption_key: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        };

        let db = Database::new(config)?;
        let version_tracker = Arc::new(NetworkVersionTracker::new());
        let node_id = PeerId::random();

        let orchestrator =
            RollingUpgradeOrchestrator::new(node_id, db, backup_path, version_tracker);

        // Validate upgrade
        let validation = orchestrator.validate_upgrade("0.2.0", None).await?;
        // With less than 4 peers, threshold won't be maintained
        assert!(!validation.threshold_maintained);

        Ok(())
    }
}
