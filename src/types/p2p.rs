use base64::Engine;
use libp2p::PeerId;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerializablePeerId(pub PeerId);

impl Serialize for SerializablePeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes();
        let base64_string = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&base64_string)
    }
}

struct PeerIdVisitor;

impl<'de> Visitor<'de> for PeerIdVisitor {
    type Value = SerializablePeerId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a peerId in base64 string form")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(v)
            .map_err(|_| E::custom("invalid base64 encoding"))?;

        PeerId::from_bytes(&bytes)
            .map(SerializablePeerId)
            .map_err(|_| E::custom("invalid peerId"))
    }
}

impl<'de> Deserialize<'de> for SerializablePeerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PeerIdVisitor)
    }
}
