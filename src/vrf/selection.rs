use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::{database::VrfStorage, types::ChannelMessage};

use super::{
    selector::VrfNodeSelector,
    service::VrfService,
};

/// Facade over the VRF selector/service/types that other subsystems can depend on.
pub struct VrfSelectionFacade;

impl VrfSelectionFacade {
    pub fn new_service(node_id: PeerId, message_tx: mpsc::Sender<ChannelMessage>) -> VrfService {
        VrfService::new(node_id, message_tx)
    }

    pub fn new_service_with_context(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        context: impl Into<String>,
    ) -> VrfService {
        VrfService::new_with_context(node_id, message_tx, context)
    }

    pub fn new_service_with_storage(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        storage: VrfStorage,
    ) -> VrfService {
        VrfService::new_with_storage(node_id, message_tx, storage)
    }

    pub fn new_service_with_storage_and_context(
        node_id: PeerId,
        message_tx: mpsc::Sender<ChannelMessage>,
        storage: VrfStorage,
        context: impl Into<String>,
    ) -> VrfService {
        VrfService::new_with_storage_and_context(node_id, message_tx, storage, context)
    }

    pub fn selector(node_id: PeerId) -> VrfNodeSelector {
        VrfNodeSelector::new(node_id)
    }
}
