use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::{key::CompressedPublicKey, Network};
use k256::{ProjectivePoint, AffinePoint};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ethers_core::utils::keccak256;
pub mod bigint;
pub mod transaction;
pub mod hmac_helper;

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

pub fn get_btc_address_from_group_key(pubkey: ProjectivePoint) -> String {
    let affine = AffinePoint::from(pubkey);
    let ep = affine.to_encoded_point(true); // compressed 33 bytes
    let secp_pubkey = SecpPublicKey::from_slice(ep.as_bytes()).unwrap();
    let compressed = CompressedPublicKey::from_slice(&secp_pubkey.serialize()).unwrap();

    // ✅ Use Legacy P2PKH instead of SegWit to match our transaction format
    let btc_address = bitcoin::Address::p2pkh(&compressed, Network::Testnet);
    println!("Generated Bitcoin address: {:?}", btc_address);
    btc_address.to_string()
}
