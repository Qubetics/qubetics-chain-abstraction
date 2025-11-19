use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::signing::SigningNode;
use crate::threshold_dkg::DKGNode;
use crate::types::ChannelMessage;
use crate::user_intent_manager::UserIntentManager;

use super::types::NetworkLayer;

impl NetworkLayer {
    /// Get mutable reference to DKG node
    pub fn get_dkg_node(&mut self) -> Option<&mut DKGNode> {
        self.dkg_node.as_mut()
    }

    /// Get mutable reference to signing node
    pub fn get_signing_node(&mut self) -> Option<&mut SigningNode> {
        self.signing_node.as_mut()
    }

    /// Get mutable reference to user intent manager
    pub fn get_user_intent_manager(&mut self) -> Option<&mut UserIntentManager> {
        self.user_intent_manager.as_mut()
    }

    /// Get message transmitter channel
    pub fn get_msg_tx(&self) -> mpsc::Sender<ChannelMessage> {
        self.message_tx.clone()
    }

    /// Get mutable reference to message receiver channel
    pub fn get_msg_rx(&mut self) -> &mut mpsc::Receiver<ChannelMessage> {
        &mut self.message_rx
    }

    /// Get local peer ID
    pub fn get_local_peer_id<'a>(&'a self) -> &'a PeerId {
        &self.local_peer_id
    }
}
