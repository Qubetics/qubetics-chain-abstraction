use bls12_381::{G1Affine, G1Projective};
use sha2::{Sha256, Digest};
use ethers_core::utils::keccak256;
use k256::ecdsa::SigningKey;
use bitcoin::{Address as BtcAddress, Network, PublicKey as BtcPublicKey};
use bitcoin::secp256k1::{Secp256k1, PublicKey as SecpPublicKey};
use bip39::Mnemonic;
use bip32::{XPrv, DerivationPath};

pub fn get_eth_address_from_group_key(pubkey: G1Projective) -> String {
    let affine = G1Affine::from(pubkey);
    let pubkey_bytes = affine.to_uncompressed(); // [u8; 96]
    let hash = keccak256(&pubkey_bytes);
    let eth_address = &hash[12..];
    println!("Generated Ethereum address: {:?}", eth_address);
    format!("0x{}", hex::encode(eth_address))
}

pub fn get_btc_address_from_group_key(pubkey: G1Projective) -> String {
    let affine = G1Affine::from(pubkey);
    let pubkey_bytes = affine.to_uncompressed(); // [u8; 96]

    let digest = Sha256::digest(&pubkey_bytes);
    let mnemonic = Mnemonic::from_entropy(&digest).unwrap();
    let seed = mnemonic.to_seed("");
    let seed_arr: [u8; 64] = seed[..64].try_into().unwrap();
    let xprv = XPrv::new(seed_arr).unwrap();

    let path: DerivationPath = "m/44'/0'/0'/0/0".parse().unwrap();
    let mut derived = xprv;
    for child_number in path.into_iter() {
        derived = derived.derive_child(child_number).unwrap();
    }

    let pubkey = derived.public_key();
    let secp = Secp256k1::new();
    let secp_pubkey = SecpPublicKey::from_slice(&pubkey.to_bytes()).unwrap();

    let btc_pubkey = BtcPublicKey {
        compressed: true,
        inner: secp_pubkey,
    };

    let btc_address = BtcAddress::p2pkh(&btc_pubkey, Network::Bitcoin);
    println!("Generated Bitcoin address: {:?}", btc_address);
    btc_address.to_string()
}
