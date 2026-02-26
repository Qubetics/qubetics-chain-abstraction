use hmac::{Hmac, Mac};
use sha2::Sha256;

///    ===============
/// 1) hmac256_from_addr
///    ===============
///    Takes a TICS-style address (20 bytes, hex string with/without 0x),
///    runs HMAC-SHA256 with a secret key, and returns a full 32-byte digest.
///
/// Use case: whenever you want a deterministic 32-byte constant
/// tied to a user's address but hidden behind your server's secret key.
pub fn hmac256_from_addr(addr: &str, key: &[u8]) -> Result<[u8; 32], String> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    if s.len() != 40 {
        return Err("not a 20-byte hex address".into());
    }
    let msg = hex::decode(s).map_err(|_| "invalid hex")?;
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).map_err(|_| "bad key")?;
    mac.update(&msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// ===============
/// 2) hmac64_from_addr
/// ===============
///    Convenience wrapper around hmac256_from_addr:
///    - still HMACs the address with the key
///    - but only returns the first 8 bytes (big-endian) as a u64.
///
///    Use case: when you want a small constant (e.g., numeric ID, seed, index)
///    instead of carrying around 32 bytes.
pub fn hmac64_from_addr(addr: &str, key: &[u8]) -> Result<u64, String> {
    let h = hmac256_from_addr(addr, key)?;
    Ok(u64::from_be_bytes(h[0..8].try_into().unwrap()))
}

/// ===============
/// 3) hmac_scalar_mod_n
/// ===============
/// Turns HMAC-SHA256(addr) into a valid scalar on secp256k1 curve.
/// - Takes the 32-byte HMAC
/// - Reduces it mod the curve order `n`
/// - Ensures it's in [1..n-1] (avoids zero)
///
/// Use case: if you need to map the result into something usable as an
/// TICS private key, ECDSA scalar, or other crypto scalar domain.
/// (This is often necessary if you're generating keys or using it
/// inside threshold signing protocols.)
pub fn hmac_scalar_mod_n(addr: &str, key: &[u8]) -> Result<[u8; 32], String> {
    use num_bigint::BigUint;
    use num_traits::One;

    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    let h = hmac256_from_addr(addr, key)?;
    let x = BigUint::from_bytes_be(&h);
    let one = BigUint::one();
    let x = (x % (&n - &one)) + &one; // ensure 1..n-1

    let mut be = x.to_bytes_be();
    if be.len() > 32 {
        be = be[be.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    Ok(out)
}

/// ===============
/// 4) bytes_to_scalar_mod_n
/// ===============
/// Safely converts arbitrary 32-byte array to a secp256k1 scalar by reducing modulo curve order.
/// - Takes any 32-byte array
/// - Reduces it mod the curve order `n`
/// - Returns the reduced bytes (in [0..n-1])
///
/// Use case: when you have bytes that might be >= curve order and need to safely
/// convert them to a scalar without panicking.
pub fn bytes_to_scalar_mod_n(bytes: &[u8; 32]) -> [u8; 32] {
    use num_bigint::BigUint;

    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    let x = BigUint::from_bytes_be(bytes);
    let x = x % &n; // reduce mod n

    let mut be = x.to_bytes_be();
    if be.len() > 32 {
        be = be[be.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ADDR: &str = "0x000000000000000000000000000000000000dead";
    const VALID_ADDR_NO_PREFIX: &str = "000000000000000000000000000000000000dead";
    const INVALID_ADDR_LENGTH: &str = "0x000000000000000000000000000000000000dea"; // Missing 1 char
    const INVALID_ADDR_HEX: &str = "0x000000000000000000000000000000000000deag"; // 'g' is not hex
    const KEY: &[u8] = b"vanijya-v1";

    #[test]
    fn test_hmac256_from_addr_valid() {
        // Test with 0x prefix
        let h1 = hmac256_from_addr(VALID_ADDR, KEY).unwrap();
        assert_eq!(
            hex::encode(h1),
            "1708cce8ea41e6a5d09878ae91d1a1206725eb90bffec0d5aa402245978cfb7a"
        );

        // Test without 0x prefix
        let h2 = hmac256_from_addr(VALID_ADDR_NO_PREFIX, KEY).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hmac256_from_addr_invalid_length() {
        let res = hmac256_from_addr(INVALID_ADDR_LENGTH, KEY);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "not a 20-byte hex address");
    }

    #[test]
    fn test_hmac256_from_addr_invalid_hex() {
        let res = hmac256_from_addr(INVALID_ADDR_HEX, KEY);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "invalid hex");
    }

    #[test]
    fn test_hmac64_from_addr() {
        let h_u64 = hmac64_from_addr(VALID_ADDR, KEY).unwrap();
        // The first 8 bytes of "1708cce8ea41e6a5..."
        // hex: 1708cce8ea41e6a5 -> decimal: 1659801763420694181
        assert_eq!(h_u64, 1659801763420694181);
    }

    #[test]
    fn test_hmac_scalar_mod_n() {
        let scalar_bytes = hmac_scalar_mod_n(VALID_ADDR, KEY).unwrap();
        assert_eq!(scalar_bytes.len(), 32);
        
        // Ensure not zero
        assert_ne!(scalar_bytes, [0u8; 32]);
    }

    #[test]
    fn test_bytes_to_scalar_mod_n() {
        // Test with bytes less than order n
        let small_bytes = [1u8; 32];
        let reduced = bytes_to_scalar_mod_n(&small_bytes);
        assert_eq!(small_bytes, reduced);

        // Test with bytes greater than order n (e.g., all 0xFF)
        let large_bytes = [0xFF; 32];
        let reduced_large = bytes_to_scalar_mod_n(&large_bytes);
        assert_ne!(large_bytes, reduced_large);
        
        // Ensure result is still 32 bytes
        assert_eq!(reduced_large.len(), 32);
    }
}
