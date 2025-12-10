use std::sync::Arc;

use anyhow::Result;
use tracing::{debug, info};

use super::{
    consensus_storage::ConsensusStorage,
    dkg_storage::DkgStorage,
    liquidity_storage::LiquidityStorage,
    reward_storage::RewardStorage,
    signing_storage::SigningStorage,
    user_storage::{IntentStorage, TransactionStatusStorage, UserStorage},
    vrf_storage::VrfStorage,
    Database, DatabaseConfig,
};

/// Aggregates every database-backed storage behind a single cheap-to-clone handle.
/// This lets higher layers depend on one object instead of wiring each storage manually.
#[derive(Clone)]
pub struct DatabaseModule {
    inner: Arc<DatabaseModuleInner>,
}

struct DatabaseModuleInner {
    config: DatabaseConfig,
    database: Database,
    user_storage: UserStorage,
    intent_storage: IntentStorage,
    tx_status_storage: TransactionStatusStorage,
    reward_storage: RewardStorage,
    liquidity_storage: LiquidityStorage,
    consensus_storage: ConsensusStorage,
    dkg_storage: DkgStorage,
    signing_storage: SigningStorage,
    vrf_storage: VrfStorage,
}

impl DatabaseModule {
    /// Bootstrap RocksDB and every storage component from a config descriptor.
    pub fn initialize(config: DatabaseConfig) -> Result<Self> {
        let db = Database::new(config.clone())?;
        Ok(Self::from_database_with_config(db, config))
    }

    /// Wrap an already-initialized `Database` (useful for tests / embedded nodes).
    pub fn from_database(database: Database) -> Self {
        Self::from_database_with_config(database, DatabaseConfig::default())
    }

    fn from_database_with_config(database: Database, config: DatabaseConfig) -> Self {
        info!(
            "🧩 [DATABASE_MODULE] Wiring storages for path {}",
            config.path
        );

        let user_storage = UserStorage::new(database.clone());
        let intent_storage = IntentStorage::new(database.clone());
        let tx_status_storage = TransactionStatusStorage::new(database.clone());
        let reward_storage = RewardStorage::new(database.clone());
        let liquidity_storage = LiquidityStorage::new(database.clone());
        let consensus_storage = ConsensusStorage::new(database.clone());
        let dkg_storage = DkgStorage::new(database.clone());
        let signing_storage = SigningStorage::new(database.clone());
        let vrf_storage = VrfStorage::new(database.clone());

        let inner = DatabaseModuleInner {
            config,
            database,
            user_storage,
            intent_storage,
            tx_status_storage,
            reward_storage,
            liquidity_storage,
            consensus_storage,
            dkg_storage,
            signing_storage,
            vrf_storage,
        };

        debug!("🧩 [DATABASE_MODULE] Storages wired successfully");

        Self {
            inner: Arc::new(inner),
        }
    }

    /// Expose the raw database handle (cheap clone for convenience).
    pub fn database(&self) -> Database {
        self.inner.database.clone()
    }

    pub fn config(&self) -> &DatabaseConfig {
        &self.inner.config
    }

    pub fn user_storage(&self) -> UserStorage {
        self.inner.user_storage.clone()
    }

    pub fn intent_storage(&self) -> IntentStorage {
        self.inner.intent_storage.clone()
    }

    pub fn transaction_status_storage(&self) -> TransactionStatusStorage {
        self.inner.tx_status_storage.clone()
    }

    pub fn reward_storage(&self) -> RewardStorage {
        self.inner.reward_storage.clone()
    }

    pub fn liquidity_storage(&self) -> LiquidityStorage {
        self.inner.liquidity_storage.clone()
    }

    pub fn consensus_storage(&self) -> ConsensusStorage {
        self.inner.consensus_storage.clone()
    }

    pub fn dkg_storage(&self) -> DkgStorage {
        self.inner.dkg_storage.clone()
    }

    pub fn signing_storage(&self) -> SigningStorage {
        self.inner.signing_storage.clone()
    }

    pub fn vrf_storage(&self) -> VrfStorage {
        self.inner.vrf_storage.clone()
    }
}
