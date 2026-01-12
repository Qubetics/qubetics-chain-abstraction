use crate::database::Database;
/// State preservation for safe upgrades and rollbacks
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

pub struct StatePreservationManager {
    db: Database,
    backup_path: PathBuf,
}

impl StatePreservationManager {
    pub fn new(db: Database, backup_path: PathBuf) -> Self {
        // Ensure backup directory exists
        if let Err(e) = std::fs::create_dir_all(&backup_path) {
            warn!("Failed to create backup directory {:?}: {}", backup_path, e);
        }

        Self { db, backup_path }
    }

    /// Create a snapshot before upgrade
    /// Returns snapshot ID for rollback
    pub async fn create_upgrade_snapshot(&self, version: &str) -> Result<String> {
        let snapshot_id = format!(
            "pre_upgrade_{}_{}",
            version.replace('.', "_"),
            Utc::now().timestamp()
        );

        let snapshot_path = self.backup_path.join(&snapshot_id);
        std::fs::create_dir_all(&snapshot_path)?;

        info!("📸 [STATE] Creating upgrade snapshot: {}", snapshot_id);

        // Backup critical data prefixes
        let critical_prefixes = vec![
            "dkg:",       // DKG shares and state
            "peer:",      // Peer indices and metadata
            "vrf:",       // VRF state
            "signing:",   // Signing state
            "consensus:", // Consensus state
            "node:",      // Node configuration
            "schema:",    // Database schema version
        ];

        for prefix in critical_prefixes {
            self.backup_prefix(prefix, &snapshot_path).await?;
        }

        // Store snapshot metadata
        self.store_snapshot_metadata(&snapshot_id, version, &snapshot_path)
            .await?;

        info!("✅ [STATE] Snapshot created successfully: {}", snapshot_id);
        Ok(snapshot_id)
    }

    /// Backup all keys with a specific prefix
    async fn backup_prefix(&self, prefix: &str, snapshot_path: &Path) -> Result<()> {
        let backup_file = snapshot_path.join(format!("{}.backup", prefix.replace(':', "_")));

        // Get all keys with this prefix
        let keys = self.get_keys_with_prefix(prefix)?;

        if keys.is_empty() {
            info!("   ℹ️  No keys found for prefix: {}", prefix);
            return Ok(());
        }

        info!(
            "   📦 Backing up {} keys with prefix: {}",
            keys.len(),
            prefix
        );

        // Serialize key-value pairs
        let mut backup_data: Vec<(String, Vec<u8>)> = Vec::new();
        for key in keys {
            if let Some(value) = self.db.get(&key)? {
                backup_data.push((key, value));
            }
        }

        // Write to file
        let serialized = bincode::serialize(&backup_data)?;
        std::fs::write(backup_file, serialized)?;

        Ok(())
    }

    /// Get all keys with a specific prefix
    fn get_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        // Note: This is a simplified implementation
        // In production, you'd iterate through the database properly
        // For now, we'll return empty and log a warning
        warn!("⚠️  [STATE] Key enumeration not fully implemented - using known keys");

        // Return hardcoded critical keys based on prefix
        let keys = match prefix {
            "dkg:" => vec![
                "dkg:final_secret_share",
                "dkg:vault_tweaked_share",
                "dkg:status",
                "dkg:permanent_index",
            ],
            "peer:" => vec!["peer:indices", "peer:addresses"],
            "vrf:" => vec!["vrf:current_round", "vrf:selection_cache"],
            "signing:" => vec!["signing:threshold", "signing:active_count"],
            "node:" => vec!["node:version", "node:upgrade_mode"],
            "schema:" => vec!["schema:version", "schema:upgrade_metadata:enabled"],
            _ => vec![],
        };

        Ok(keys.iter().map(|s| s.to_string()).collect())
    }

    /// Store snapshot metadata
    async fn store_snapshot_metadata(
        &self,
        snapshot_id: &str,
        version: &str,
        snapshot_path: &Path,
    ) -> Result<()> {
        let metadata = serde_json::json!({
            "snapshot_id": snapshot_id,
            "version": version,
            "timestamp": Utc::now().to_rfc3339(),
            "path": snapshot_path.to_string_lossy(),
        });

        let metadata_file = snapshot_path.join("metadata.json");
        std::fs::write(metadata_file, serde_json::to_string_pretty(&metadata)?)?;

        Ok(())
    }

    /// Restore from snapshot (rollback)
    pub async fn restore_from_snapshot(&self, snapshot_id: &str) -> Result<()> {
        let snapshot_path = self.backup_path.join(snapshot_id);

        if !snapshot_path.exists() {
            return Err(anyhow!("Snapshot not found: {}", snapshot_id));
        }

        info!("🔄 [STATE] Restoring from snapshot: {}", snapshot_id);

        // Read all backup files
        let backup_files: Vec<_> = std::fs::read_dir(&snapshot_path)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|s| s.to_str()) == Some("backup"))
            .collect();

        info!("   📦 Found {} backup files to restore", backup_files.len());

        for file in backup_files {
            self.restore_backup_file(&file.path()).await?;
        }

        info!("✅ [STATE] Snapshot restored successfully");
        Ok(())
    }

    /// Restore individual backup file
    async fn restore_backup_file(&self, backup_file: &Path) -> Result<()> {
        let serialized = std::fs::read(backup_file)?;
        let backup_data: Vec<(String, Vec<u8>)> = bincode::deserialize(&serialized)?;

        info!(
            "   🔧 Restoring {} keys from {:?}",
            backup_data.len(),
            backup_file.file_name()
        );

        for (key, value) in backup_data {
            self.db.put(&key, &value)?;
        }

        Ok(())
    }

    /// List available snapshots
    pub async fn list_snapshots(&self) -> Result<Vec<String>> {
        let mut snapshots = Vec::new();

        if !self.backup_path.exists() {
            return Ok(snapshots);
        }

        for entry in std::fs::read_dir(&self.backup_path)? {
            let entry = entry?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    snapshots.push(name.to_string());
                }
            }
        }

        // Sort by timestamp (newest first)
        snapshots.sort_by(|a, b| b.cmp(a));

        Ok(snapshots)
    }

    /// Delete old snapshots (keep only N most recent)
    pub async fn cleanup_old_snapshots(&self, keep_count: usize) -> Result<usize> {
        let snapshots = self.list_snapshots().await?;

        if snapshots.len() <= keep_count {
            return Ok(0);
        }

        let to_delete = &snapshots[keep_count..];
        let deleted_count = to_delete.len();

        info!(
            "🧹 [STATE] Cleaning up {} old snapshots (keeping {})",
            deleted_count, keep_count
        );

        for snapshot_id in to_delete {
            self.delete_snapshot(snapshot_id).await?;
        }

        Ok(deleted_count)
    }

    /// Delete a specific snapshot
    pub async fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        let snapshot_path = self.backup_path.join(snapshot_id);

        if snapshot_path.exists() {
            std::fs::remove_dir_all(&snapshot_path)?;
            info!("🗑️  [STATE] Deleted snapshot: {}", snapshot_id);
        }

        Ok(())
    }

    /// Get snapshot info
    pub async fn get_snapshot_info(&self, snapshot_id: &str) -> Result<serde_json::Value> {
        let snapshot_path = self.backup_path.join(snapshot_id);
        let metadata_file = snapshot_path.join("metadata.json");

        if !metadata_file.exists() {
            return Err(anyhow!("Snapshot metadata not found: {}", snapshot_id));
        }

        let metadata = std::fs::read_to_string(metadata_file)?;
        Ok(serde_json::from_str(&metadata)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_snapshot_creation() -> Result<()> {
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
        let manager = StatePreservationManager::new(db.clone(), backup_path);

        // Store some test data
        db.put_string("dkg:final_secret_share", &"test_share")?;

        // Create snapshot
        let snapshot_id = manager.create_upgrade_snapshot("0.2.0").await?;

        // Verify snapshot exists
        let snapshots = manager.list_snapshots().await?;
        assert!(snapshots.contains(&snapshot_id));

        // Verify snapshot info
        let info = manager.get_snapshot_info(&snapshot_id).await?;
        assert_eq!(info["version"], "0.2.0");

        Ok(())
    }
}
