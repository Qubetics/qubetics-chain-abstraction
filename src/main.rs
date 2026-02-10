#![recursion_limit = "4096"]

use anyhow::{anyhow, Context, Result};
use dotenv::dotenv;
use hex::FromHex;
use libp2p::{identity::Keypair, PeerId};
use mpc_node::node_selection::{DefaultThresholdCalculator, NodeMembership, VrfNodeManager};
use mpc_node::{
    commands::CommandProcessor,
    consensus::{ConsensusNode, DatabaseConsensusNode},
    database::{Database, DatabaseConfig, DatabaseModule, DkgStorage},
    network::transport::types::MpcNetworkLayer,
    protocols::DKGNode,
    rpc_server,
    signing::{DatabaseSigningNode, SigningNode},
    types::network::init_network_type_from_env,
    user_intent_manager::UserIntentManager,
};
use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::level_filters::LevelFilter;
use tracing::{error, info, warn};
use tracing_appender::non_blocking;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const CHAIN_CODE_ENV: &str = "CHAIN_CODE_HEX";

#[derive(Clone)]
struct Config {
    rpc_port: u16,
    db_config: DatabaseConfig,
    selection_interval: u64,
}

#[derive(Default)]
struct ConfigBuilder {
    rpc_port: Option<u16>,
    db_config: Option<DatabaseConfig>,
    selection_interval: Option<u64>,
}

impl ConfigBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn with_env(mut self) -> Result<Self> {
        self.rpc_port = Some(
            std::env::var("RPC_PORT")
                .ok()
                .map(|port| port.parse::<u16>())
                .transpose()
                .context("RPC_PORT")?
                .unwrap_or(8081),
        );

        self.db_config =
            Some(DatabaseConfig::from_env().or_else(|_| DatabaseConfig::default().validate())?);

        if self.selection_interval.is_none() {
            self.selection_interval = Some(10);
        }

        Ok(self)
    }

    fn build(mut self) -> Result<Config> {
        if self.rpc_port.is_none() || self.db_config.is_none() {
            self = self.with_env()?;
        }

        Ok(Config {
            rpc_port: self.rpc_port.unwrap_or(8081),
            db_config: self.db_config.unwrap_or_else(|| {
                DatabaseConfig::default()
                    .validate()
                    .expect("valid default config")
            }),
            selection_interval: self.selection_interval.unwrap_or(10),
        })
    }
}

fn load_chain_code() -> Result<[u8; 32]> {
    let raw = std::env::var(CHAIN_CODE_ENV).map_err(|_| {
        anyhow!(
            "{} env var missing; provide 32-byte secret hex (optionally 0x-prefixed)",
            CHAIN_CODE_ENV
        )
    })?;
    let sanitized = raw.trim().trim_start_matches("0x");
    let chain_code = <[u8; 32]>::from_hex(sanitized)
        .map_err(|e| anyhow!("invalid {} value: {}", CHAIN_CODE_ENV, e))?;
    Ok(chain_code)
}

struct NodeContext {
    config: Config,
    peer_id: PeerId,
    chain_code: [u8; 32],
    database_module: Option<DatabaseModule>,
    database: Option<Arc<Database>>,
    network: Option<MpcNetworkLayer>,
    dkg_storage: Option<DkgStorage>,
    user_intent_manager: Option<Arc<UserIntentManager>>,
    start_time: Instant,
}

impl NodeContext {
    fn new(config: Config) -> Result<Self> {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let chain_code = load_chain_code()?;

        Ok(Self {
            config,
            peer_id,
            chain_code,
            database_module: None,
            database: None,
            network: None,
            dkg_storage: None,
            user_intent_manager: None,
            start_time: Instant::now(),
        })
    }

    fn init_logging(&self) -> Result<()> {
        let rand_num: u32 = thread_rng().gen_range(1000..9999);
        let file_appender =
            tracing_appender::rolling::never("logs", format!("mpcn-{rand_num}.log"));
        let (writer, _guard) = non_blocking(file_appender);
        let file_layer = fmt::layer::<_>()
            .with_writer(writer)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_thread_names(false);

        let stdout_layer = fmt::layer::<_>()
            .with_writer(std::io::stdout)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_thread_names(false);
        let stderr_layer = fmt::layer::<_>()
            .with_writer(std::io::stderr)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_thread_names(false);

        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .parse("")?;

        tracing_subscriber::registry()
            .with(env_filter)
            .with(file_layer)
            .with(stdout_layer)
            .with(stderr_layer)
            .init();

        Ok(())
    }

    fn database_path_for_peer(&self) -> String {
        format!(
            "./data/rocksdb-{}",
            self.peer_id.to_string().chars().take(8).collect::<String>()
        )
    }

    fn init_database(&mut self) -> Result<()> {
        let mut db_config = self.config.db_config.clone();
        db_config.path = self.database_path_for_peer();
        let db_config = db_config
            .validate()
            .map_err(|e| anyhow!("Invalid database configuration: {}", e))?;

        let database_module = DatabaseModule::initialize(db_config)?;
        let database: Arc<Database> = Arc::new(database_module.database());
        let dkg_storage = database_module.dkg_storage();

        self.database_module = Some(database_module);
        self.database = Some(database);
        self.dkg_storage = Some(dkg_storage);

        info!("🗄️ [MAIN] Database initialized successfully");
        info!("🧩 [MAIN] Database module wired for dependent components");

        Ok(())
    }

    async fn check_and_migrate(&self) -> Result<()> {
        use mpc_node::database::upgrade::{MigrationRunner, VersionStorage};

        let db = self
            .database
            .as_ref()
            .context("Database must be initialized before migration check")?;

        let version_storage = VersionStorage::new((**db).clone());
        let current_version = env!("CARGO_PKG_VERSION");

        // Check if this is first run or version changed
        match version_storage.get_node_version().await? {
            None => {
                info!("📦 [MIGRATION] First run detected, initializing version tracking");
                version_storage.store_node_version(current_version).await?;
            }
            Some(stored_version) if stored_version == current_version => {
                info!(
                    "✅ [MIGRATION] Node version {} matches database, no migration needed",
                    current_version
                );
            }
            Some(stored_version) => {
                info!(
                    "🔄 [MIGRATION] Version change detected: {} -> {}",
                    stored_version, current_version
                );

                // Run migrations
                let migration_runner = MigrationRunner::new((**db).clone());
                migration_runner.migrate_to_version(current_version).await?;

                // Update stored version
                version_storage.store_node_version(current_version).await?;

                info!(
                    "✅ [MIGRATION] Successfully migrated to version {}",
                    current_version
                );
            }
        }

        Ok(())
    }

    async fn init_network(&mut self) -> Result<()> {
        let database = self
            .database
            .clone()
            .context("database must be initialized before network")?;
        let database_module = self
            .database_module
            .clone()
            .context("database module must be initialized before network")?;

        let threshold_calculator = Box::new(DefaultThresholdCalculator);
        let node_manager = Box::new(VrfNodeManager::new(
            self.peer_id,
            threshold_calculator,
            self.config.selection_interval,
        ));

        let total = node_manager.get_total_nodes();
        let threshold = node_manager.get_threshold();

        info!("Initial node count: {}, threshold: {}", total, threshold);

        let mut network = MpcNetworkLayer::new(node_manager, database.as_ref().clone()).await?;

        let db_signing_node = Arc::new(Mutex::new(DatabaseSigningNode::new(
            network.get_local_peer_id().to_string(),
            threshold,
            network.get_msg_tx(),
            database.as_ref().clone(),
        )));

        let signing_node = Arc::new(Mutex::new(SigningNode::new(
            network.get_local_peer_id().to_string(),
            threshold,
            network.get_msg_tx(),
        )));

        // Note: NonceManager initialization moved after set_database() below
        // because NonceStorage requires a database reference

        let dkg_storage: DkgStorage = database_module.dkg_storage();
        let chain_code = self.chain_code;
        let mut dkg_node = DKGNode::new(
            network.get_local_peer_id().to_string(),
            threshold,
            total,
            network.get_msg_tx(),
            dkg_storage.clone(),
            chain_code,
        );

        if let Err(e) = dkg_node.load_permanent_index().await {
            warn!("⚠️ Failed to load permanent index: {:?}", e);
        }

        let _db_consensus_node = DatabaseConsensusNode::new(database.as_ref().clone());
        let consensus_node = ConsensusNode::new();
        let command_processor = CommandProcessor::new();

        network.set_dkg_node(dkg_node);
        network.set_signing_node(signing_node.clone()).await;
        network.set_db_signing_node(db_signing_node.clone());
        network.set_consensus_node(consensus_node);
        network.set_command_processor(command_processor);

        let db_user_intent_manager = Arc::new(UserIntentManager::from_module(
            database_module.clone(),
            chain_code,
        ));
        info!("🏗️ [MAIN] Created Arc<UserIntentManager>");

        info!(
            "🔗 [MAIN] Setting database user registry in network layer - Arc pointer: {:p}",
            Arc::as_ptr(&db_user_intent_manager)
        );
        network.set_user_intent_manager(db_user_intent_manager.clone()).await;

        network.set_database(database).await;

        // Initialize nonce manager for random k generation
        // MUST be called AFTER set_database() since NonceStorage requires database
        {
            let mut sn = signing_node.lock().await;
            sn.init_nonce_manager(total);
            info!("🔐 [MAIN] Initialized NonceManager for random nonce generation");
        }

        self.user_intent_manager = Some(db_user_intent_manager);
        self.network = Some(network);
        self.dkg_storage = Some(dkg_storage);

        info!("📊 [MAIN] Database components initialized:");
        info!("  📝 DatabaseSigningNode: Available");
        info!("  🗳️ DatabaseConsensusNode: Available");
        info!("  👥 UserIntentManager: Available");
        info!("  🗄️ Database path: {}", self.database_path_for_peer());

        Ok(())
    }

    async fn spawn_rpc(&self) -> Result<()> {
        let network = self
            .network
            .as_ref()
            .context("network must be initialized")?;
        let user_intent_manager = self
            .user_intent_manager
            .clone()
            .context("user intent manager must be initialized")?;
        let dkg_storage = self
            .dkg_storage
            .clone()
            .context("DKG storage must be initialized")?;
        let database = self
            .database
            .clone()
            .context("database must be initialized")?;

        let message_tx = network.get_msg_tx();
        let rpc_port = self.config.rpc_port;
        let node_id = network.get_local_peer_id().to_string();
        let start_time = self.start_time;

        tokio::spawn(async move {
            info!("🚀 Starting RPC server on port {}", rpc_port);
            info!(
                "🔗 [MAIN] Passing database user registry to RPC server - Arc pointer: {:p}",
                Arc::as_ptr(&user_intent_manager)
            );
            if let Err(e) = rpc_server::start_http_server(
                message_tx,
                rpc_port,
                user_intent_manager.clone(),
                dkg_storage,
                (*database).clone(),
                node_id,
                start_time,
            )
            .await
            {
                info!("❌ RPC server failed: {:?}", e);
            }
        });

        Ok(())
    }

    async fn start_network(&mut self) -> Result<()> {
        let network = self
            .network
            .as_mut()
            .context("network must be initialized before start")?;

        network.start().await?;

        Ok(())
    }

}

// Increase tokio worker threads from default (num_cpus) to 16
// This allows more parallel processing of RPC requests, message handling, and consensus
// Critical for handling 20+ parallel user transactions efficiently
#[tokio::main(worker_threads = 16)]
async fn main() -> Result<()> {
    dotenv().ok();
    init_network_type_from_env()?;

    let config = ConfigBuilder::new().build()?;
    let mut context = NodeContext::new(config)?;

    context.init_logging()?;

    // CRITICAL: Database now persists across restarts (no wipe)
    // This preserves DKG shares, peer indices, and all cryptographic state
    info!(
        "📊 [MAIN] Using persistent database at {}",
        context.database_path_for_peer()
    );

    context.init_database()?;

    // Check and run migrations if version changed
    if let Err(e) = context.check_and_migrate().await {
        error!("❌ [MAIN] Migration failed: {}", e);
        return Err(e);
    }

    context.init_network().await?;
    context.spawn_rpc().await?;
    context.start_network().await?;
    // Global clock is now integrated into the network event loop
    // See: src/network/transport/event_loop.rs -> handle_global_clock_tick()

    Ok(())
}
