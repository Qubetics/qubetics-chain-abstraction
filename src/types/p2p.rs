use libp2p::{Multiaddr, PeerId};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerInfo {
    pub addresses: Vec<Multiaddr>,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerializablePeerId(pub PeerId);

impl Serialize for SerializablePeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // let bytes = self.0.to_bytes();
        // serializer.serialize_bytes(&bytes)
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SerializablePeerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let pid = s.parse().map_err(de::Error::custom)?;
        Ok(SerializablePeerId(pid))
    }
}
