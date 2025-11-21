use crate::consensus::ConsensusNode;
use crate::protocols::{VrfSelectionFacade, VrfService};
use crate::types::ChannelMessage;
use libp2p::PeerId;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Clone)]
pub struct Coordination {
    pub vrf_service: Option<VrfService>,
    pub consensus_node: Option<ConsensusNode>,
    pub available_nodes: Option<Vec<PeerId>>,
}

impl Coordination {
    pub fn new(peer_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            vrf_service: Some(VrfSelectionFacade::new_service(peer_id, message_tx)),
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
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
            info!("🔄 [VRF] VRF service already initialized, synchronizing round only");
            if let Some(vrf_service) = &mut self.vrf_service {
                if let Some(round) = network_round {
                    vrf_service.set_current_round(round).await;
                }
            }
            return;
        }

        let mut vrf_service = VrfSelectionFacade::new_service(peer_id, message_tx);
        if let Some(round) = network_round {
            info!(
                "🔄 [VRF] Synchronizing VRF round from network state: {}",
                round
            );
            vrf_service.set_current_round(round).await;
        }

        self.vrf_service = Some(vrf_service);
    }
}
