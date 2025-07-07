use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::GroupEncoding;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use tracing::info;

#[derive(Debug, Clone)]
pub struct SerializableG1Affine(pub G1Affine);

impl Serialize for SerializableG1Affine {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        info!("Serailizing G1Affine");
        // Serialize G1Affine as compressed bytes
        let bytes = self.0.to_compressed();
        serializer.serialize_bytes(&bytes)
    }
}

struct G1AffineVisitor;

impl<'de> Visitor<'de> for G1AffineVisitor {
    type Value = SerializableG1Affine;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a G1Affine point in compressed form or sequence of bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 48 {
            return Err(E::custom("invalid length for G1Affine"));
        }

        let mut bytes = [0u8; 48];
        bytes.copy_from_slice(v);

        Option::from(G1Affine::from_compressed(&bytes))
            .map(SerializableG1Affine)
            .ok_or_else(|| E::custom("invalid G1Affine point"))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut bytes = [0u8; 48];
        for i in 0..48 {
            bytes[i] = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }

        Option::from(G1Affine::from_compressed(&bytes))
            .map(SerializableG1Affine)
            .ok_or_else(|| de::Error::custom("invalid G1Affine point"))
    }
}

impl<'de> Deserialize<'de> for SerializableG1Affine {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        info!("Deserailizing G1Affine");
        deserializer.deserialize_bytes(G1AffineVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct SerializableScalar(pub Scalar);

impl Serialize for SerializableScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes_be();
        serializer.serialize_bytes(&bytes)
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = SerializableScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a Scalar value in bytes form or sequence of bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::custom("invalid length for Scalar"));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(v);

        Option::from(Scalar::from_bytes_be(&bytes))
            .map(SerializableScalar)
            .ok_or_else(|| E::custom("invalid Scalar value"))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }

        Option::from(Scalar::from_bytes_be(&bytes))
            .map(SerializableScalar)
            .ok_or_else(|| de::Error::custom("invalid Scalar value"))
    }
}

impl<'de> Deserialize<'de> for SerializableScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ScalarVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct SerializableG2Affine(pub G2Affine);

impl Serialize for SerializableG2Affine {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        info!("Serializing G2Affine");
        // G2Affine compressed form is 96 bytes
        let bytes = self.0.to_compressed();
        serializer.serialize_bytes(&bytes)
    }
}

struct G2AffineVisitor;

impl<'de> Visitor<'de> for G2AffineVisitor {
    type Value = SerializableG2Affine;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("a G2Affine point in compressed form (96 bytes)")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 96 {
            return Err(E::custom(format!(
                "invalid length for G2Affine: {}",
                v.len()
            )));
        }
        let mut buf = [0u8; 96];
        buf.copy_from_slice(v);
        G2Affine::from_compressed(&buf)
            .into_option()
            .map(SerializableG2Affine)
            .ok_or_else(|| E::custom("invalid G2Affine point"))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf = [0u8; 96];
        for i in 0..96 {
            buf[i] = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        G2Affine::from_compressed(&buf)
            .into_option()
            .map(SerializableG2Affine)
            .ok_or_else(|| de::Error::custom("invalid G2Affine point"))
    }
}

impl<'de> Deserialize<'de> for SerializableG2Affine {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        info!("Deserializing G2Affine");
        deserializer.deserialize_bytes(G2AffineVisitor)
    }
}
