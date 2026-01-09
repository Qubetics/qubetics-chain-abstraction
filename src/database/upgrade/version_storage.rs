use crate::database::Database;
/// Version storage for tracking node software version
use anyhow::Result;
use tracing::info;

#[derive(Clone)]
pub struct VersionStorage {
    db: Database,
}

impl VersionStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store the current node version
    pub async fn store_node_version(&self, version: &str) -> Result<()> {
        self.db.put_string("node:version", &version)?;
        info!("💾 [VERSION] Stored node version: {}", version);
        Ok(())
    }

    /// Get the stored node version
    pub async fn get_node_version(&self) -> Result<Option<String>> {
        self.db.get_string("node:version")
    }

    /// Check if migration is needed (version mismatch)
    pub async fn check_needs_migration(&self, current_version: &str) -> Result<bool> {
        match self.get_node_version().await? {
            None => Ok(false), // Fresh install, no migration needed
            Some(stored) if stored == current_version => Ok(false), // Same version
            Some(_) => Ok(true), // Version changed, needs migration
        }
    }

    /// Store upgrade metadata
    pub async fn store_upgrade_metadata(&self, key: &str, value: &str) -> Result<()> {
        let full_key = format!("upgrade:metadata:{}", key);
        self.db.put_string(&full_key, &value)?;
        Ok(())
    }

    /// Get upgrade metadata
    pub async fn get_upgrade_metadata(&self, key: &str) -> Result<Option<String>> {
        let full_key = format!("upgrade:metadata:{}", key);
        self.db.get_string(&full_key)
    }

    /// Check if node is in upgrade mode
    pub async fn is_upgrade_mode(&self) -> Result<bool> {
        Ok(self
            .db
            .get_string::<String>("node:upgrade_mode")?
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false))
    }

    /// Set upgrade mode
    pub async fn set_upgrade_mode(&self, enabled: bool) -> Result<()> {
        self.db.put_string("node:upgrade_mode", &enabled)?;
        if enabled {
            info!("🔒 [VERSION] Node entering upgrade mode");
        } else {
            info!("🔓 [VERSION] Node exiting upgrade mode");
        }
        Ok(())
    }

    /// Store snapshot ID for rollback
    pub async fn store_snapshot_id(&self, snapshot_id: &str) -> Result<()> {
        self.db
            .put_string("upgrade:current_snapshot", &snapshot_id)?;
        info!("💾 [VERSION] Stored snapshot ID: {}", snapshot_id);
        Ok(())
    }

    /// Get current snapshot ID
    pub async fn get_snapshot_id(&self) -> Result<Option<String>> {
        self.db.get_string("upgrade:current_snapshot")
    }

    /// Clear snapshot ID after successful upgrade
    pub async fn clear_snapshot_id(&self) -> Result<()> {
        let key = "upgrade:current_snapshot";
        self.db.delete(&key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseConfig;

    #[tokio::test]
    async fn test_version_storage() -> Result<()> {
        let config = DatabaseConfig {
            path: "/tmp/test_version_storage".to_string(),
            create_if_missing: true,
            max_open_files: 100,
            encryption_key: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        };

        let db = Database::new(config)?;
        let storage = VersionStorage::new(db);

        // Test storing and retrieving version
        storage.store_node_version("0.1.0").await?;
        let version = storage.get_node_version().await?;
        assert_eq!(version, Some("0.1.0".to_string()));

        // Test migration check
        assert!(!storage.check_needs_migration("0.1.0").await?);
        assert!(storage.check_needs_migration("0.2.0").await?);

        // Clean up
        std::fs::remove_dir_all("/tmp/test_version_storage").ok();

        Ok(())
    }
}
