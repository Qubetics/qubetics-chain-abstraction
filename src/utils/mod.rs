use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::{key::CompressedPublicKey, Network};
use k256::{ProjectivePoint, AffinePoint, Scalar};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::ff::PrimeField;
use ethers_core::utils::keccak256;
use sha3::{Digest, Keccak256};
use crate::rpc_server::DepositIntent;
pub mod bigint;
pub mod transaction;
pub mod hmac_helper;

use anyhow::Result;
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
pub fn get_eth_address_from_group_key_with_path(pubkey: ProjectivePoint, derivation_path: &str) -> Result<String> {
    // Parse the derivation path (e.g., "m/44'/60'/0'/0/0" for Ethereum)
    let path = DerivationPath::from_str(derivation_path)
        .map_err(|e| anyhow::anyhow!("Invalid derivation path '{}': {}", derivation_path, e))?;
    
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
    let master_scalar = Scalar::from_repr(scalar_bytes.into()).unwrap();
    
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
        .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
    
    mac.update(parent_ep.as_bytes());
    mac.update(&child_number.to_be_bytes());
    
    let result = mac.finalize();
    let hash = result.into_bytes();
    
    // Split the hash: first 32 bytes for the child key, last 32 bytes for chain code
    let child_key_bytes = &hash[0..32];
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(child_key_bytes);
    let child_scalar = Scalar::from_repr(scalar_bytes.into()).unwrap();
    
    // Add the parent key to the child key (modulo curve order)
    let derived_key = parent_key + child_scalar;
    
    Ok(derived_key)
}

pub fn get_btc_address_from_group_key(pubkey: ProjectivePoint) -> String {
    // Only generate P2PKH addresses (legacy)
    get_btc_address_from_group_key_p2pkh(pubkey).unwrap_or_else(|_| "Error generating P2PKH address".to_string())
}

/// Calculate intent hash from DepositIntent using the same method as in RPC server
pub fn calculate_intent_hash(intent: &DepositIntent) -> String {
    // Serialize the DepositIntent to match the client's JSON.stringify() format
    // Use compact JSON serialization (no spaces) to match JavaScript's JSON.stringify()
    let intent_json = serde_json::to_string(intent).unwrap();
    let intent_bytes = intent_json.as_bytes();
    let intent_hash = Keccak256::digest(intent_bytes);
    hex::encode(intent_hash)
}

pub fn get_btc_address_from_group_key_p2pkh(pubkey: ProjectivePoint) -> Result<String> {
    let affine = AffinePoint::from(pubkey);
    let ep = affine.to_encoded_point(true); // compressed 33 bytes
    let secp_pubkey = SecpPublicKey::from_slice(ep.as_bytes()).unwrap();
    let compressed = CompressedPublicKey::from_slice(&secp_pubkey.serialize()).unwrap();

    // Generate P2PKH (Legacy): OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    let btc_address = bitcoin::Address::p2pkh(&compressed, Network::Testnet);

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
            "m/44'/60'/0'/0/0",  // Standard Ethereum path
            "m/44'/60'/0'/0/1",  // Second address
            "m/44'/60'/1'/0/0",  // Second account
            "m/44'/60'/2'/0/0",  // Third account
        ];
        
        let mut addresses = Vec::new();
        
        // Generate addresses for each path
        for path in &paths {
            match get_eth_address_from_group_key_with_path(test_group_key, path) {
                Ok(address) => {
                    addresses.push((path, address));
                },
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