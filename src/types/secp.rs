use k256::{AffinePoint, Scalar, EncodedPoint};
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use ff::PrimeField;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use serde::de::{self, Visitor};
use std::fmt;

/// Wrapper type for serialising `k256::AffinePoint` values.
#[derive(Debug, Clone)]
pub struct SerializablePoint(pub AffinePoint);

impl Serialize for SerializablePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as compressed SEC1 encoded bytes
        let ep = self.0.to_encoded_point(true);
        serializer.serialize_bytes(ep.as_bytes())
    }
}

struct PointVisitor;

impl<'de> Visitor<'de> for PointVisitor {
    type Value = SerializablePoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a secp256k1 affine point in compressed form")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let ep = EncodedPoint::from_bytes(v).map_err(|_| E::custom("invalid point"))?;
        let point = Option::from(AffinePoint::from_encoded_point(&ep))
            .ok_or_else(|| E::custom("invalid point"))?;
        Ok(SerializablePoint(point))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut bytes = Vec::with_capacity(33);
        while let Some(b) = seq.next_element()? {
            bytes.push(b);
        }
        self.visit_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for SerializablePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PointVisitor)
    }
}

/// Wrapper type for serialising `k256::Scalar` values.
#[derive(Debug, Clone)]
pub struct SerializableScalar(pub Scalar);

impl Serialize for SerializableScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes();
        serializer.serialize_bytes(bytes.as_slice())
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = SerializableScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a secp256k1 scalar in bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::custom("invalid length for Scalar"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(v);
        let scalar = Option::from(Scalar::from_repr(arr.into()))
            .ok_or_else(|| E::custom("invalid Scalar"))?;
        Ok(SerializableScalar(scalar))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut arr = [0u8; 32];
        for i in 0..32 {
            arr[i] = seq.next_element()? .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        let scalar = Option::from(Scalar::from_repr(arr.into()))
            .ok_or_else(|| de::Error::custom("invalid Scalar"))?;
        Ok(SerializableScalar(scalar))
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

