pub mod compatibility;
pub mod migrations;
pub mod state_preservation;
/// Upgrade and migration infrastructure for MPC node
///
/// This module provides version tracking, state preservation, and migration capabilities
pub mod version_storage;

pub use compatibility::{CompatibilityMatrix, VersionRange};
pub use migrations::{Migration, MigrationRunner};
pub use state_preservation::StatePreservationManager;
pub use version_storage::VersionStorage;
