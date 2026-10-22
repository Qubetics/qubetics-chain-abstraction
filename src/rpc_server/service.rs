use tokio::sync::mpsc;

use crate::{types::ChannelMessage, user_intent_manager::UserIntentManager};

#[derive(Default)]
pub struct MpcRpcService {
    message_tx: Option<mpsc::Sender<ChannelMessage>>,
    user_intent_manager: Option<UserIntentManager>,
}

impl MpcRpcService {
    pub fn new(message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            message_tx: Some(message_tx),
            user_intent_manager: None,
        }
    }

    pub fn with_user_intent_manager(mut self, user_intent_manager: UserIntentManager) -> Self {
        self.user_intent_manager = Some(user_intent_manager);
        self
    }

    pub fn get_message_tx(&self) -> Option<mpsc::Sender<ChannelMessage>> {
        self.message_tx.clone()
    }

    pub fn get_user_intent_manager(&self) -> Option<&UserIntentManager> {
        self.user_intent_manager.as_ref()
    }
}
