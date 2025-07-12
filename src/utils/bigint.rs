// src/utils/bigint.rs
use num_bigint::BigUint;
use serde::{Deserializer, Serializer};
use serde::de::{self, Visitor};
use std::fmt;

pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_str_radix(10))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    struct BigUintVisitor;
    impl<'de> Visitor<'de> for BigUintVisitor {
        type Value = BigUint;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a big integer as either a number or decimal string")
        }

        fn visit_u64<E>(self, v: u64) -> Result<BigUint, E>
        where
            E: de::Error,
        {
            Ok(BigUint::from(v))
        }

        fn visit_str<E>(self, s: &str) -> Result<BigUint, E>
        where
            E: de::Error,
        {
            BigUint::parse_bytes(s.as_bytes(), 10)
                .ok_or_else(|| de::Error::custom("failed to parse BigUint"))
        }

        fn visit_string<E>(self, s: String) -> Result<BigUint, E>
        where
            E: de::Error,
        {
            self.visit_str(&s)
        }
    }

    deserializer.deserialize_any(BigUintVisitor)
}
