use serde::{Deserialize, Serialize};

pub const MSG_TOPIC_DKG: &str = "topic-dkg";
pub const MSG_TOPIC_PEER_DISCOVERY: &str = "peer-discovery";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ADKGMessage {
    
}