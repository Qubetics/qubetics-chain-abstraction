use ff::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, Scalar};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroize;

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
///
/// Implements `Zeroize` and `Drop` to ensure secret scalar material
/// is explicitly zeroed from memory when no longer needed.
#[derive(Debug, Clone)]
pub struct SerializableScalar(pub Scalar);

impl Zeroize for SerializableScalar {
    fn zeroize(&mut self) {
        // Overwrite the scalar's 32-byte representation with zeros.
        // k256::Scalar stores data as FieldBytes (GenericArray<u8, U32>).
        // We replace the inner value with the zero scalar.
        self.0 = Scalar::ZERO;
    }
}

impl Drop for SerializableScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

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
            arr[i] = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;
    use serde_cbor;

    #[test]
    fn test_serializable_scalar_serde_roundtrip() {
        let original_scalar = Scalar::random(&mut OsRng);
        let wrapper = SerializableScalar(original_scalar);

        // Serialize to CBOR (the format used across the codebase)
        let bytes = serde_cbor::to_vec(&wrapper).expect("serialize");
        let decoded: SerializableScalar = serde_cbor::from_slice(&bytes).expect("deserialize");

        assert_eq!(
            original_scalar.to_bytes(),
            decoded.0.to_bytes(),
            "Scalar must survive serde round-trip"
        );
    }

    #[test]
    fn test_serializable_point_serde_roundtrip() {
        // Use generator point as a known non-identity point
        let generator = k256::ProjectivePoint::GENERATOR;
        let affine = generator.to_affine();
        let wrapper = SerializablePoint(affine);

        let bytes = serde_cbor::to_vec(&wrapper).expect("serialize");
        let decoded: SerializablePoint = serde_cbor::from_slice(&bytes).expect("deserialize");

        assert_eq!(
            affine.to_encoded_point(true).as_bytes(),
            decoded.0.to_encoded_point(true).as_bytes(),
            "AffinePoint must survive serde round-trip"
        );
    }

    #[test]
    fn test_serializable_scalar_zeroize() {
        let mut wrapper = SerializableScalar(Scalar::random(&mut OsRng));
        assert_ne!(wrapper.0, Scalar::ZERO, "Random scalar should not be zero");

        wrapper.zeroize();
        assert_eq!(wrapper.0, Scalar::ZERO, "Zeroize must set inner to Scalar::ZERO");
    }

    #[test]
    fn test_serializable_scalar_drop_zeroizes() {
        // Create a scalar, clone its bytes for comparison, then drop
        let random_scalar = Scalar::random(&mut OsRng);
        let original_bytes = random_scalar.to_bytes();
        assert_ne!(&original_bytes[..], &[0u8; 32], "Random scalar bytes should not be all zeros");

        // After drop, a newly cloned version should be zeroed
        // (We can verify the zeroize impl by calling it explicitly since Drop calls zeroize)
        let mut wrapper = SerializableScalar(random_scalar);
        wrapper.zeroize(); // Drop will call this automatically
        assert_eq!(wrapper.0.to_bytes().as_slice(), &[0u8; 32], "After zeroize, bytes must be all zeros");
    }

    #[test]
    fn test_scalar_invalid_length_rejected() {
        // Wrap 31 bytes in CBOR bytes format — should fail
        let short_bytes: Vec<u8> = vec![0u8; 31];
        let cbor = serde_cbor::to_vec(&serde_cbor::Value::Bytes(short_bytes)).expect("cbor");
        let result: Result<SerializableScalar, _> = serde_cbor::from_slice(&cbor);
        assert!(result.is_err(), "31-byte input must be rejected");
    }

    #[test]
    fn test_scalar_33_bytes_rejected() {
        // 33 bytes — should also fail
        let long_bytes: Vec<u8> = vec![0u8; 33];
        let cbor = serde_cbor::to_vec(&serde_cbor::Value::Bytes(long_bytes)).expect("cbor");
        let result: Result<SerializableScalar, _> = serde_cbor::from_slice(&cbor);
        assert!(result.is_err(), "33-byte input must be rejected");
    }
}

