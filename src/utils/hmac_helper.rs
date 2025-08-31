use hmac::{Hmac, Mac};
use sha2::Sha256;

/// ===============
/// 1) hmac256_from_addr
/// ===============
/// Takes an Ethereum-style address (20 bytes, hex string with/without 0x),
/// runs HMAC-SHA256 with a secret key, and returns a full 32-byte digest.
///
/// Use case: whenever you want a deterministic 32-byte constant
/// tied to a user's address but hidden behind your server's secret key.
pub fn hmac256_from_addr(addr: &str, key: &[u8]) -> Result<[u8; 32], String> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    if s.len() != 40 { return Err("not a 20-byte hex address".into()); }
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
/// Convenience wrapper around hmac256_from_addr:
/// - still HMACs the address with the key
/// - but only returns the first 8 bytes (big-endian) as a u64.
///
/// Use case: when you want a small constant (e.g., numeric ID, seed, index)
/// instead of carrying around 32 bytes.
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
/// Ethereum private key, ECDSA scalar, or other crypto scalar domain.
/// (This is often necessary if you're generating keys or using it
/// inside threshold signing protocols.)
pub fn hmac_scalar_mod_n(addr: &str, key: &[u8]) -> Result<[u8; 32], String> {
    use num_bigint::BigUint;
    use num_traits::One;

    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    ).unwrap();

    let h = hmac256_from_addr(addr, key)?;
    let x = BigUint::from_bytes_be(&h);
    let one = BigUint::one();
    let x = (x % (&n - &one)) + &one; // ensure 1..n-1

    let mut be = x.to_bytes_be();
    if be.len() > 32 { be = be[be.len()-32..].to_vec(); }
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tv() {
        let key = b"vanijya-v1";
        let addr = "0x000000000000000000000000000000000000dead";
        let h = hmac256_from_addr(addr, key).unwrap();
        assert_eq!(
            hex::encode(h),
            "1708cce8ea41e6a5d09878ae91d1a1206725eb90bffec0d5aa402245978cfb7a"
        );
    }
} 