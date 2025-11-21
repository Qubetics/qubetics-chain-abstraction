use anyhow::{anyhow, Context, Result};
use dotenv::dotenv;
use libp2p::{identity::Keypair, PeerId};
use mpc_node::node_selection::{DefaultThresholdCalculator, NodeMembership, VrfNodeManager};
use mpc_node::{
    commands::CommandProcessor,
    consensus::{ConsensusNode, DatabaseConsensusNode},
    database::{Database, DatabaseConfig, DatabaseModule, DkgStorage, RewardStorage},
    network::transport::types::MpcNetworkLayer,
    protocols::DKGNode,
    rpc_server,
    signing::{DatabaseSigningNode, SigningNode},
    user_intent_manager::UserIntentManager,
};
use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::level_filters::LevelFilter;
use tracing::{info, warn};
use tracing_appender::non_blocking;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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

struct NodeContext {
    config: Config,
    peer_id: PeerId,
    database_module: Option<DatabaseModule>,
    database: Option<Arc<Database>>,
    network: Option<MpcNetworkLayer>,
    dkg_storage: Option<DkgStorage>,
    reward_storage: Option<RewardStorage>,
    user_intent_manager: Option<Arc<UserIntentManager>>,
    start_time: Instant,
}

impl NodeContext {
    fn new(config: Config) -> Result<Self> {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        Ok(Self {
            config,
            peer_id,
            database_module: None,
            database: None,
            network: None,
            dkg_storage: None,
            reward_storage: None,
            user_intent_manager: None,
            start_time: Instant::now(),
        })
    }

    fn init_logging(&self) -> Result<()> {
        let rand_num: u32 = thread_rng().gen_range(1000..9999);
        let file_appender =
            tracing_appender::rolling::never("logs", format!("mpcn-{}.log", rand_num));
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
        let reward_storage = database_module.reward_storage();

        self.database_module = Some(database_module);
        self.database = Some(database);
        self.dkg_storage = Some(dkg_storage);
        self.reward_storage = Some(reward_storage);

        info!("🗄️ [MAIN] Database initialized successfully");
        info!("🧩 [MAIN] Database module wired for dependent components");

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

        let dkg_storage: DkgStorage = database_module.dkg_storage();
        let reward_storage: RewardStorage = database_module.reward_storage();
        let chain_code = [42u8; 32];
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
        network.set_signing_node(signing_node.lock().await.clone());
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
        network.set_user_intent_manager(db_user_intent_manager.clone());

        network.set_database(database);

        self.user_intent_manager = Some(db_user_intent_manager);
        self.network = Some(network);
        self.dkg_storage = Some(dkg_storage);
        self.reward_storage = Some(reward_storage);

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
        let reward_storage = self
            .reward_storage
            .clone()
            .context("reward storage must be initialized")?;

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
                reward_storage,
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

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let config = ConfigBuilder::new().build()?;
    let mut context = NodeContext::new(config)?;

    context.init_logging()?;
    context.init_database()?;
    context.init_network().await?;
    context.spawn_rpc().await?;
    context.start_network().await?;

    Ok(())
}
