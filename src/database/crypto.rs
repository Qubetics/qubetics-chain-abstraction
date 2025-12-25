use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

/// Size of the nonce for ChaCha20Poly1305 (96 bits)
const NONCE_SIZE: usize = 12;

/// Magic header to identify encrypted data (0xEnc + version 1)
const MAGIC_HEADER: &[u8] = b"Enc\x01";

pub struct Cipher {
    key: Key,
}

impl Cipher {
    pub fn new(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(anyhow!("Encryption key must be exactly 32 bytes"));
        }
        Ok(Self {
            key: *Key::from_slice(key_bytes),
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Format: [MAGIC_HEADER | NONCE | CIPHERTEXT]
        let mut result = Vec::with_capacity(MAGIC_HEADER.len() + NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(MAGIC_HEADER);
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < MAGIC_HEADER.len() + NONCE_SIZE {
            return Err(anyhow!("Data too short to be encrypted"));
        }

        if !data.starts_with(MAGIC_HEADER) {
            return Err(anyhow!("Invalid magic header, not encrypted data"));
        }

        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce_bytes = &data[MAGIC_HEADER.len()..MAGIC_HEADER.len() + NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = &data[MAGIC_HEADER.len() + NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }
}
