use crate::consensus::ConsensusNode;
use crate::database::VrfStorage;
use crate::protocols::{VrfSelectionFacade, VrfService};
use crate::types::ChannelMessage;
use libp2p::PeerId;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

pub fn derive_peer_id_from_string(id: &str) -> PeerId {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    let hash = hasher.finalize();

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash[..32]);

    let ed_kp = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut key_bytes)
        .unwrap_or_else(|_| libp2p::identity::ed25519::Keypair::generate());
    let kp = libp2p::identity::Keypair::from(ed_kp);

    PeerId::from_public_key(&kp.public())
}

#[derive(Clone)]
pub struct Coordination {
    pub vrf_service: Option<VrfService>,
    pub consensus_node: Option<ConsensusNode>,
    pub available_nodes: Option<Vec<PeerId>>,
    pub vrf_storage: Option<VrfStorage>,
    // Store these to recreate VrfService when database is set
    node_id: Option<PeerId>,
    message_tx: Option<mpsc::Sender<ChannelMessage>>,
}

impl Coordination {
    pub fn new(peer_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            vrf_service: Some(VrfSelectionFacade::new_service_with_context(
                peer_id,
                message_tx.clone(),
                "signing_contract",
            )),
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
            vrf_storage: None,
            node_id: Some(peer_id),
            message_tx: Some(message_tx),
        }
    }

    pub fn new_with_database(
        peer_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        database: Arc<crate::database::Database>,
    ) -> Self {
        let vrf_storage = VrfStorage::new(database.as_ref().clone());
        let vrf_service = VrfService::new_with_storage_and_context(
            peer_id,
            message_tx.clone(),
            vrf_storage.clone(),
            "signing_contract",
        );
        Self {
            vrf_service: Some(vrf_service),
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
            vrf_storage: Some(vrf_storage),
            node_id: Some(peer_id),
            message_tx: Some(message_tx),
        }
    }

    pub fn set_database(&mut self, database: Arc<crate::database::Database>) {
        let vrf_storage = VrfStorage::new(database.as_ref().clone());
        self.vrf_storage = Some(vrf_storage.clone());

        // Recreate VrfService with storage if we have the necessary info
        // The VrfService will automatically load the current round from storage on initialization
        if let (Some(node_id), Some(message_tx)) = (self.node_id, self.message_tx.clone()) {
            // Create new VrfService with storage - it will load round from storage automatically
            let new_vrf_service = VrfService::new_with_storage_and_context(
                node_id,
                message_tx,
                vrf_storage,
                "signing_contract",
            );

            self.vrf_service = Some(new_vrf_service);
            info!("✅ [COORDINATION] Updated VrfService with database storage");
        }
    }

    pub fn vrf_service(&self) -> Option<&VrfService> {
        self.vrf_service.as_ref()
    }

    pub fn vrf_service_mut(&mut self) -> Option<&mut VrfService> {
        self.vrf_service.as_mut()
    }

    pub fn consensus_node(&self) -> Option<&ConsensusNode> {
        self.consensus_node.as_ref()
    }

    pub fn consensus_node_mut(&mut self) -> Option<&mut ConsensusNode> {
        self.consensus_node.as_mut()
    }

    /// Replicate round into consensus so consensus stays aligned.
    /// Call after sync_rounds_before_signing or get_next_round.
    pub fn replicate_vrf_round_to_consensus(&mut self, round: u64) {
        if let Some(cn) = self.consensus_node.as_mut() {
            cn.set_current_round_if_higher(round);
        }
    }

    pub async fn get_available_nodes(&self) -> Vec<PeerId> {
        self.available_nodes.clone().unwrap_or_default()
    }

    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.available_nodes = Some(nodes);
    }

    pub async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
        if let Some(ref nodes) = self.available_nodes {
            nodes.clone()
        } else {
            self.get_available_nodes().await
        }
    }

    pub async fn initialize_vrf_service_with_network_sync(
        &mut self,
        peer_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        network_round: Option<u64>,
    ) {
        if self.vrf_service.is_some() {
            info!("🔄 [ROUND] Service already initialized, synchronizing round only");
            if let Some(vrf_service) = &mut self.vrf_service {
                if let Some(round) = network_round {
                    vrf_service.set_current_round(round).await;
                }
            }
            return;
        }

        // Create VrfService with storage if available, otherwise without
        let vrf_service = if let Some(ref storage) = self.vrf_storage {
            VrfService::new_with_storage_and_context(
                peer_id,
                message_tx,
                storage.clone(),
                "signing_contract",
            )
        } else {
            VrfSelectionFacade::new_service_with_context(peer_id, message_tx, "signing_contract")
        };

        if let Some(round) = network_round {
            info!(
                "🔄 [ROUND] Synchronizing round from network state: {}",
                round
            );
            vrf_service.set_current_round(round).await;
        }

        self.vrf_service = Some(vrf_service);
    }
}
