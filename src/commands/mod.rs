use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    ShareGeneration { threshold: usize },
    SignMessage { message: Vec<u8> },
    UpdateState { key: String, value: Vec<u8> },
    ConsensusProposal { round: u64, value: Vec<u8> },
}

pub struct CommandProcessor {
    handlers: HashMap<CommandKind, Box<dyn Fn(Command) -> anyhow::Result<()> + Send + Sync>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CommandKind {
    ShareGeneration,
    SignMessage,
    UpdateState,
    ConsensusProposal,
}

impl Command {
    pub fn kind(&self) -> CommandKind {
        match self {
            Command::ShareGeneration { .. } => CommandKind::ShareGeneration,
            Command::SignMessage { .. } => CommandKind::SignMessage,
            Command::UpdateState { .. } => CommandKind::UpdateState,
            Command::ConsensusProposal { .. } => CommandKind::ConsensusProposal,
        }
    }
}

impl Default for CommandProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandProcessor {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn register_handler<F>(&mut self, command_kind: CommandKind, handler: F)
    where
        F: Fn(Command) -> anyhow::Result<()> + Send + Sync + 'static,
    {
        self.handlers.insert(command_kind, Box::new(handler));
    }

    pub async fn handle_message(&mut self, msg: Command) -> anyhow::Result<()> {
        let kind = msg.kind();

        match (kind, self.handlers.get(&kind)) {
            (_, Some(handler)) => {
                handler(msg)?;
            }
            (missing_kind, None) => {
                warn!("No handler registered for command kind: {:?}", missing_kind);
                anyhow::bail!("No handler registered for command kind: {:?}", missing_kind);
            }
        }
        Ok(())
    }
}
