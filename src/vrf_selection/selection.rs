use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::types::ChannelMessage;

use super::{
    selector::VrfNodeSelector,
    service::{VrfService, VrfServiceConfig},
};

/// Facade over the VRF selector/service/types that other subsystems can depend on.
pub struct VrfSelectionFacade;

impl VrfSelectionFacade {
    pub fn new_service(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> VrfService {
        VrfService::new(node_id, message_tx)
    }

    pub fn new_service_with_config(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        config: VrfServiceConfig,
    ) -> VrfService {
        VrfService::with_config(node_id, message_tx, config)
    }

    pub fn selector(node_id: PeerId) -> VrfNodeSelector {
        VrfNodeSelector::new(node_id)
    }
}

