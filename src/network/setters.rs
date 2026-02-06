use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::commands::CommandProcessor;
use crate::consensus::ConsensusNode;
use crate::database::Database;
use crate::protocols::DKGNode;
use crate::signing::{DatabaseSigningNode, SigningNode};
use crate::user_intent_manager::UserIntentManager;

use crate::network::transport::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Set the DKG node
    pub fn set_dkg_node(&mut self, dkg_node: DKGNode) {
        self.dkg_node = Some(dkg_node);
    }

    /// Set the signing node (Arc<Mutex<SigningNode>>). Calls set_self_arc on the node so it can spawn aggregation tasks.
    pub async fn set_signing_node(&mut self, signing_node: Arc<Mutex<SigningNode>>) {
        signing_node.lock().await.set_self_arc(Arc::clone(&signing_node));
        self.signing_node = Some(signing_node);
    }

    /// Set the database signing node
    pub fn set_db_signing_node(&mut self, db_signing_node: Arc<Mutex<DatabaseSigningNode>>) {
        self.db_signing_node = Some(db_signing_node);
    }

    /// Set the consensus node
    pub fn set_consensus_node(&mut self, node: ConsensusNode) {
        self.consensus_node = Some(node);
    }

    /// Set the command processor
    pub fn set_command_processor(&mut self, processor: CommandProcessor) {
        self.command_processor = Some(processor);
    }

    /// Set the user intent manager
    pub async fn set_user_intent_manager(&mut self, registry: Arc<UserIntentManager>) {
        info!(
            "🔗 [NETWORK] Received database user registry - Arc pointer: {:p}",
            Arc::as_ptr(&registry)
        );
        info!("🔗 [NETWORK] About to clone UserIntentManager from Arc");
        self.user_intent_manager = Some((*registry).clone());
        info!("🔗 [NETWORK] UserIntentManager clone stored in network layer");

        // Also set the user registry on the signing node for transaction ID storage
        if let Some(signing_node) = &self.signing_node {
            signing_node.lock().await.set_user_intent_manager(registry.clone());
            info!("📋 [NETWORK] Set user registry on signing node for transaction ID storage");
        } else {
            info!("⚠️ [NETWORK] Signing node not available when setting user registry");
        }

        // Attach user registry to DKG node so it can refresh user shares after secret updates
        if let Some(dkg_node) = &mut self.dkg_node {
            dkg_node.set_user_intent_manager(registry.clone());
            info!("🔗 [NETWORK] Attached user registry to DKG node");
        } else {
            info!("⚠️ [NETWORK] DKG node not available when setting user registry");
        }
    }

    /// Set the database on signing node
    pub async fn set_database(&mut self, database: Arc<Database>) {
        info!("🗄️ [NETWORK] Setting database on signing node for solver amount storage");

        // Set the database on the signing node for solver amount storage
        if let Some(signing_node) = &self.signing_node {
            signing_node.lock().await.set_database(database);
            info!("🗄️ [NETWORK] Set database on signing node for solver amount storage");
        } else {
            info!("⚠️ [NETWORK] Signing node not available when setting database");
        }
    }

}
