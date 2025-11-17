use tokio::sync::mpsc;

use crate::{types::ChannelMessage, user_registry::DatabaseUserRegistry};

#[derive(Default)]
pub struct MpcRpcService {
    message_tx: Option<mpsc::Sender<ChannelMessage>>,
    user_registry: Option<DatabaseUserRegistry>,
}

impl MpcRpcService {
    pub fn new(message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            message_tx: Some(message_tx),
            user_registry: None,
        }
    }

    pub fn with_user_registry(mut self, user_registry: DatabaseUserRegistry) -> Self {
        self.user_registry = Some(user_registry);
        self
    }

    pub fn get_message_tx(&self) -> Option<mpsc::Sender<ChannelMessage>> {
        self.message_tx.clone()
    }

    pub fn get_user_registry(&self) -> Option<&DatabaseUserRegistry> {
        self.user_registry.as_ref()
    }
}
