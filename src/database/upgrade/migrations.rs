use crate::database::Database;
/// Migration framework for database schema evolution
use anyhow::{anyhow, Result};
use chrono::Utc;
use tracing::{error, info};

/// Trait for database migrations
pub trait Migration: Send + Sync {
    /// Migration version
    fn version(&self) -> &str;

    /// Migration description
    fn description(&self) -> &str;

    /// Apply migration
    fn up(&self, db: &Database) -> Result<()>;

    /// Rollback migration
    fn down(&self, db: &Database) -> Result<()>;

    /// Validate migration succeeded
    fn validate(&self, db: &Database) -> Result<bool>;
}

/// Migration runner
pub struct MigrationRunner {
    db: Database,
    migrations: Vec<Box<dyn Migration>>,
}

impl MigrationRunner {
    pub fn new(db: Database) -> Self {
        // Register all migrations in order
        let migrations: Vec<Box<dyn Migration>> = vec![
            Box::new(Migration_v0_1_0_to_v0_2_0),
            // Add future migrations here
        ];

        Self { db, migrations }
    }

    /// Migrate to a specific version
    pub async fn migrate_to_version(&self, target_version: &str) -> Result<()> {
        let current_version = self.get_current_schema_version().await?;

        info!(
            "📦 [MIGRATION] Starting migration from {} to {}",
            current_version, target_version
        );

        // Find migrations to run
        let to_run: Vec<_> = self
            .migrations
            .iter()
            .filter(|m| self.should_run_migration(&current_version, m.version()))
            .collect();

        if to_run.is_empty() {
            info!("✅ [MIGRATION] No migrations needed");
            return Ok(());
        }

        info!("📋 [MIGRATION] Will run {} migrations", to_run.len());

        // Run migrations sequentially
        for migration in to_run {
            self.run_migration(migration).await?;
        }

        // Update schema version
        self.set_schema_version(target_version).await?;

        info!("✅ [MIGRATION] All migrations completed successfully");
        Ok(())
    }

    /// Run a single migration
    async fn run_migration(&self, migration: &Box<dyn Migration>) -> Result<()> {
        let version = migration.version();
        let description = migration.description();

        info!("🔧 [MIGRATION] Running {}: {}", version, description);

        // Check if already applied
        if self.is_migration_applied(version).await? {
            info!("   ℹ️  Migration {} already applied, skipping", version);
            return Ok(());
        }

        // Apply migration
        match migration.up(&self.db) {
            Ok(_) => {
                // Validate
                if migration.validate(&self.db)? {
                    self.record_migration_applied(version).await?;
                    info!("✅ [MIGRATION] Completed: {}", version);
                    Ok(())
                } else {
                    error!("❌ [MIGRATION] Validation failed for {}", version);
                    // Attempt rollback
                    if let Err(e) = migration.down(&self.db) {
                        error!("❌ [MIGRATION] Rollback also failed: {}", e);
                    }
                    Err(anyhow!("Migration {} validation failed", version))
                }
            }
            Err(e) => {
                error!("❌ [MIGRATION] Failed: {}", e);
                // Attempt rollback
                if let Err(rollback_err) = migration.down(&self.db) {
                    error!("❌ [MIGRATION] Rollback also failed: {}", rollback_err);
                }
                Err(e)
            }
        }
    }

    /// Check if migration should run
    fn should_run_migration(&self, current: &str, migration_version: &str) -> bool {
        // Simple string comparison for now
        // In production, use semantic versioning
        migration_version > current
    }

    /// Get current schema version
    async fn get_current_schema_version(&self) -> Result<String> {
        Ok(self
            .db
            .get_string("schema:version")?
            .unwrap_or_else(|| "0.1.0".to_string()))
    }

    /// Set schema version
    async fn set_schema_version(&self, version: &str) -> Result<()> {
        self.db.put_string("schema:version", &version)?;
        Ok(())
    }

    /// Check if migration was applied
    async fn is_migration_applied(&self, version: &str) -> Result<bool> {
        let key = format!("migration:applied:{}", version);
        Ok(self.db.get_string::<String>(&key)?.is_some())
    }

    /// Record migration as applied
    async fn record_migration_applied(&self, version: &str) -> Result<()> {
        let key = format!("migration:applied:{}", version);
        let timestamp = Utc::now().to_rfc3339();
        self.db.put_string(&key, &timestamp)?;
        Ok(())
    }

    /// List applied migrations
    pub async fn list_applied_migrations(&self) -> Result<Vec<String>> {
        // Note: This requires iterating through database keys
        // Simplified implementation for now
        let mut applied = Vec::new();

        for migration in &self.migrations {
            if self.is_migration_applied(migration.version()).await? {
                applied.push(migration.version().to_string());
            }
        }

        Ok(applied)
    }
}

// ============================================================================
// Example Migrations
// ============================================================================

/// Migration from 0.1.0 to 0.2.0
struct Migration_v0_1_0_to_v0_2_0;

impl Migration for Migration_v0_1_0_to_v0_2_0 {
    fn version(&self) -> &str {
        "0.2.0"
    }

    fn description(&self) -> &str {
        "Add upgrade infrastructure and version tracking"
    }

    fn up(&self, db: &Database) -> Result<()> {
        info!("   🔧 Adding upgrade metadata schema...");

        // Add upgrade metadata flag
        db.put_string("schema:upgrade_metadata:enabled", &true)?;

        // Initialize version history
        let history: Vec<String> = vec!["0.1.0".to_string()];
        db.put_string("schema:version_history", &history)?;

        // Initialize upgrade tracking
        db.put_string("schema:supports_rolling_upgrade", &true)?;

        info!("   ✅ Upgrade metadata schema added");
        Ok(())
    }

    fn down(&self, db: &Database) -> Result<()> {
        info!("   🔄 Rolling back upgrade metadata schema...");

        // Remove added keys
        let key1 = "schema:upgrade_metadata:enabled";
        let key2 = "schema:version_history";
        let key3 = "schema:supports_rolling_upgrade";
        db.delete(&key1)?;
        db.delete(&key2)?;
        db.delete(&key3)?;

        info!("   ✅ Rollback complete");
        Ok(())
    }

    fn validate(&self, db: &Database) -> Result<bool> {
        // Verify the migration succeeded
        let enabled = db
            .get_string::<bool>("schema:upgrade_metadata:enabled")?
            .is_some();
        let history = db
            .get_string::<Vec<String>>("schema:version_history")?
            .is_some();

        Ok(enabled && history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_migration_runner() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = DatabaseConfig {
            path: temp_dir.path().join("db").to_string_lossy().to_string(),
            create_if_missing: true,
            max_open_files: 100,
            encryption_key: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        };

        let db = Database::new(config)?;
        let runner = MigrationRunner::new(db.clone());

        // Run migrations
        runner.migrate_to_version("0.2.0").await?;

        // Verify schema version updated
        let version = db.get_string("schema:version")?;
        assert_eq!(version, Some("0.2.0".to_string()));

        // Verify migration was applied
        let applied = runner.list_applied_migrations().await?;
        assert!(applied.contains(&"0.2.0".to_string()));

        Ok(())
    }
}
