use serde::{Deserialize, Serialize};

pub const MSG_TOPIC_DKG: &str = "topic-dkg";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ADKGMessage {
    
}