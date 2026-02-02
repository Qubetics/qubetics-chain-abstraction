use crate::types::{network as network_cfg, DepositIntent};
use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::{key::CompressedPublicKey, Network};
use ethers_core::utils::keccak256;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha3::{Digest, Keccak256};
pub mod bigint;
pub mod bitcoin_batch;
pub mod contract;
pub mod hmac_helper;
pub mod transaction;

use anyhow::{anyhow, Result};
use bip32::DerivationPath;
use std::str::FromStr;

// BitcoinAddressType enum removed - only P2WPKH is supported

pub fn get_eth_address_from_group_key(pubkey: ProjectivePoint) -> String {
    let affine = AffinePoint::from(pubkey);
    // uncompressed SEC1 encoded point (65 bytes, 0x04 || x || y)
    let ep = affine.to_encoded_point(false);
    let bytes = ep.as_bytes();
    let hash = keccak256(&bytes[1..]);
    let eth_address = &hash[12..];
    format!("0x{}", hex::encode(eth_address))
}

/// Derive an Ethereum address from a group key using a specific derivation path
/// This creates different addresses from the same group key based on the derivation path
pub fn get_eth_address_from_group_key_with_path(
    pubkey: ProjectivePoint,
    derivation_path: &str,
) -> Result<String> {
    // Parse the derivation path (e.g., "m/44'/60'/0'/0/0" for Ethereum)
    let path = DerivationPath::from_str(derivation_path)
        .map_err(|e| anyhow!("Invalid derivation path '{}': {}", derivation_path, e))?;

    // Convert the group key to a scalar for derivation
    let affine = AffinePoint::from(pubkey);
    let ep = affine.to_encoded_point(true); // compressed format for secp256k1

    // Create a pseudo master key from the group key
    // Note: This is a simplified approach - in a full HD wallet implementation,
    // you would typically start with a seed and generate the master key properly
    let master_key_bytes = {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(ep.as_bytes());
        hasher.update(b"master_key_derivation"); // Add some domain separation
        hasher.finalize()
    };

    // Create a master private key (this is a simplified approach)
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&master_key_bytes[..32]);
    let master_scalar = parse_nonzero_scalar(scalar_bytes, "master")?;

    // Derive the child key using the path
    let derived_scalar = derive_key_from_path(master_scalar, &path)?;

    // Convert the derived scalar to a public key point
    let derived_pubkey = ProjectivePoint::GENERATOR * derived_scalar;

    // Generate Ethereum address from the derived public key
    let derived_affine = AffinePoint::from(derived_pubkey);
    let derived_ep = derived_affine.to_encoded_point(false); // uncompressed for Ethereum
    let derived_bytes = derived_ep.as_bytes();
    let hash = keccak256(&derived_bytes[1..]);
    let eth_address = &hash[12..];

    Ok(format!("0x{}", hex::encode(eth_address)))
}

/// Helper function to derive a key from a derivation path
/// This is a simplified implementation of BIP32-style key derivation
fn derive_key_from_path(master_key: Scalar, path: &DerivationPath) -> Result<Scalar> {
    let mut current_key = master_key;

    for child_number in path.iter() {
        // For each level in the path, derive the child key
        current_key = derive_child_key(current_key, child_number.into())?;
    }

    Ok(current_key)
}

/// Derive a child key from a parent key and child number
/// This implements a simplified version of BIP32 key derivation
fn derive_child_key(parent_key: Scalar, child_number: u32) -> Result<Scalar> {
    // Create the parent public key
    let parent_pubkey = ProjectivePoint::GENERATOR * parent_key;
    let parent_affine = AffinePoint::from(parent_pubkey);
    let parent_ep = parent_affine.to_encoded_point(true); // compressed

    // Create HMAC-SHA512 hash of parent public key + child number
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<sha2::Sha512>;

    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed") // Using Bitcoin's chain code
        .map_err(|e| anyhow!("HMAC key error: {}", e))?;

    mac.update(parent_ep.as_bytes());
    mac.update(&child_number.to_be_bytes());

    let result = mac.finalize();
    let hash = result.into_bytes();

    // Split the hash: first 32 bytes for the child key, last 32 bytes for chain code
    let child_key_bytes = &hash[0..32];
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(child_key_bytes);
    let child_scalar = parse_nonzero_scalar(scalar_bytes, "child")?;

    // Add the parent key to the child key (modulo curve order)
    let derived_key = parent_key + child_scalar;

    Ok(derived_key)
}

fn parse_nonzero_scalar(bytes: [u8; 32], label: &str) -> Result<Scalar> {
    let scalar = Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
        .ok_or_else(|| anyhow::anyhow!("Invalid {} scalar: bytes not within curve order", label))?;

    if bool::from(scalar.is_zero()) {
        anyhow::bail!("Invalid {} scalar: zero is not allowed", label);
    }

    Ok(scalar)
}

pub fn get_btc_address_from_group_key(pubkey: ProjectivePoint) -> String {
    // Only generate P2PKH addresses (legacy)
    get_btc_address_from_group_key_p2pkh(pubkey)
        .unwrap_or_else(|_| "Error generating P2PKH address".to_string())
}

/// Intent hash = Keccak256(serde_json::to_string(intent)).
/// Serde serializes all struct fields in definition order, so the hashed bytes include
/// source_address, target_address, source_chain, target_chain, amount, source_token,
/// target_token, and timestamp. Timestamp is therefore part of the hash.
pub fn calculate_intent_hash(intent: &DepositIntent) -> Result<String> {
    let intent_json = serde_json::to_string(intent)
        .map_err(|e| anyhow!("Failed to serialize DepositIntent: {}", e))?;
    let intent_bytes = intent_json.as_bytes();
    let intent_hash = Keccak256::digest(intent_bytes);
    Ok(hex::encode(intent_hash))
}

pub fn get_btc_address_from_group_key_p2pkh(pubkey: ProjectivePoint) -> Result<String> {
    let affine = AffinePoint::from(pubkey);
    let ep = affine.to_encoded_point(true); // compressed 33 bytes
    let secp_pubkey = SecpPublicKey::from_slice(ep.as_bytes())
        .map_err(|e| anyhow!("Invalid secp256k1 public key: {}", e))?;
    let compressed = CompressedPublicKey::from_slice(&secp_pubkey.serialize())
        .map_err(|e| anyhow!("Failed to compress secp256k1 public key: {}", e))?;

    // Generate P2PKH (Legacy): OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    let target_network = if network_cfg::network_type().is_testnet() {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let btc_address = bitcoin::Address::p2pkh(compressed, target_network);

    Ok(btc_address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_different_derivation_paths_produce_different_addresses() {
        // Create a test group key
        let test_group_key = ProjectivePoint::GENERATOR * Scalar::from(12345u64);

        // Test different derivation paths
        let paths = [
            "m/44'/60'/0'/0/0", // Standard Ethereum path
            "m/44'/60'/0'/0/1", // Second address
            "m/44'/60'/1'/0/0", // Second account
            "m/44'/60'/2'/0/0", // Third account
        ];

        let mut addresses = Vec::new();

        // Generate addresses for each path
        for path in &paths {
            match get_eth_address_from_group_key_with_path(test_group_key, path) {
                Ok(address) => {
                    addresses.push((path, address));
                }
                Err(e) => panic!("Failed to derive address for path {}: {}", path, e),
            }
        }

        // Verify all addresses are different
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(
                    addresses[i].1, addresses[j].1,
                    "Addresses for paths {} and {} should be different",
                    addresses[i].0, addresses[j].0
                );
            }
        }

        // Also compare with the original address (no derivation path)
        let original_address = get_eth_address_from_group_key(test_group_key);
        for (path, derived_address) in &addresses {
            assert_ne!(
                original_address, *derived_address,
                "Original address should differ from derived address for path {}",
                path
            );
        }
    }
}
