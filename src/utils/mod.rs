use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::{key::CompressedPublicKey, Network};
use k256::{ProjectivePoint, AffinePoint};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ethers_core::utils::keccak256;
use anyhow::Result;
pub mod bigint;
pub mod transaction;

pub fn get_eth_address_from_group_key(pubkey: ProjectivePoint) -> String {
    let affine = AffinePoint::from(pubkey);
    // uncompressed SEC1 encoded point (65 bytes, 0x04 || x || y)
    let ep = affine.to_encoded_point(false);
    let bytes = ep.as_bytes();
    let hash = keccak256(&bytes[1..]);
    let eth_address = &hash[12..];
    println!("Generated Ethereum address: {:?}", eth_address);
    format!("0x{}", hex::encode(eth_address))
}

/// Bitcoin address type enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BitcoinAddressType {
    P2PKH,  // Legacy Pay-to-Public-Key-Hash (1...)
    P2SH,   // Pay-to-Script-Hash (3...)
    P2WPKH, // Pay-to-Witness-Public-Key-Hash (bc1...)
    P2WSH,  // Pay-to-Witness-Script-Hash (bc1...)
    P2TR,   // Pay-to-Taproot (bc1p...)
}

impl Default for BitcoinAddressType {
    fn default() -> Self {
        BitcoinAddressType::P2WPKH // Default to modern SegWit
    }
}

pub fn get_btc_address_from_group_key(pubkey: ProjectivePoint) -> String {
    get_btc_address_from_group_key_with_type(pubkey, BitcoinAddressType::default()).unwrap_or_else(|_| "Error generating address".to_string())
}

pub fn get_btc_address_from_group_key_with_type(pubkey: ProjectivePoint, address_type: BitcoinAddressType) -> Result<String> {
    let affine = AffinePoint::from(pubkey);
    let ep = affine.to_encoded_point(true); // compressed 33 bytes
    let secp_pubkey = SecpPublicKey::from_slice(ep.as_bytes()).unwrap();
    let compressed = CompressedPublicKey::from_slice(&secp_pubkey.serialize()).unwrap();

    let btc_address = match address_type {
        BitcoinAddressType::P2PKH => {
            // Legacy P2PKH: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
            bitcoin::Address::p2pkh(&compressed, Network::Testnet)
        },
        BitcoinAddressType::P2SH => {
            // P2SH: OP_HASH160 <script_hash> OP_EQUAL
            // For simplicity, we'll create a P2SH-wrapped P2WPKH (P2SH-P2WPKH)
            let p2wpkh = bitcoin::Address::p2wpkh(&compressed, Network::Testnet);
            bitcoin::Address::p2sh(&p2wpkh.script_pubkey(), Network::Testnet)?
        },
        BitcoinAddressType::P2WPKH => {
            // Native SegWit v0: OP_0 <20-byte-hash>
            bitcoin::Address::p2wpkh(&compressed, Network::Testnet)
        },
        BitcoinAddressType::P2WSH => {
            // Native SegWit v0 script hash: OP_0 <32-byte-hash>
            // For simplicity, we'll create a P2WSH from a simple script
            use bitcoin::ScriptBuf;
            use bitcoin::PublicKey;

            let bitcoin_pubkey = PublicKey::from(secp_pubkey);
            let script = ScriptBuf::new_p2pk(&bitcoin_pubkey);
            bitcoin::Address::p2wsh(&script, Network::Testnet)
        },
        BitcoinAddressType::P2TR => {
            // Taproot: OP_1 <32-byte-hash>
            // For now, fall back to P2WPKH since P2TR requires more complex setup
            bitcoin::Address::p2wpkh(&compressed, Network::Testnet)
        },
    };
    
    println!("Generated Bitcoin {} address: {:?}", format!("{:?}", address_type), btc_address);
    Ok(btc_address.to_string())
}
