use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::Mac;
use rand::RngCore;
use sha2::Sha256;

/// Size of the nonce for ChaCha20Poly1305 (96 bits)
const NONCE_SIZE: usize = 12;

/// Size of HMAC tag (SHA256 = 32 bytes)
const HMAC_SIZE: usize = 32;

/// Magic header to identify encrypted data with integrity (0xEnc + version 2)
const MAGIC_HEADER_V2: &[u8] = b"Enc\x02";

/// Magic header for legacy encrypted data (version 1, no HMAC)
const MAGIC_HEADER_V1: &[u8] = b"Enc\x01";

pub struct Cipher {
    key: Key,
    hmac_key_bytes: [u8; 32], // Separate key for HMAC (derived from encryption key)
}

impl Cipher {
    pub fn new(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(anyhow!("Encryption key must be exactly 32 bytes"));
        }
        
        // Derive HMAC key from encryption key using HKDF-like approach
        // Use a simple XOR with a constant to derive a different key
        let mut hmac_key_bytes = [0u8; 32];
        for (i, byte) in key_bytes.iter().enumerate() {
            hmac_key_bytes[i] = byte ^ 0xAA; // Simple derivation, could use HKDF in production
        }
        
        Ok(Self {
            key: *Key::from_slice(key_bytes),
            hmac_key_bytes,
        })
    }

    /// Encrypt data (legacy method, for keypairs)
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Format: [MAGIC_HEADER_V1 | NONCE | CIPHERTEXT]
        let mut result = Vec::with_capacity(MAGIC_HEADER_V1.len() + NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(MAGIC_HEADER_V1);
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Returns true if the bytes look like data encrypted by this module (V1 or V2).
    /// This is a cheap format check (magic header only), not a cryptographic validation.
    pub fn is_encrypted_format(data: &[u8]) -> bool {
        data.starts_with(MAGIC_HEADER_V2) || data.starts_with(MAGIC_HEADER_V1)
    }

    /// Decrypt data (legacy method, for keypairs)
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < MAGIC_HEADER_V1.len() + NONCE_SIZE {
            return Err(anyhow!("Data too short to be encrypted"));
        }

        // Support both V1 and V2 formats
        let (magic_header, version) = if data.starts_with(MAGIC_HEADER_V2) {
            (MAGIC_HEADER_V2, 2)
        } else if data.starts_with(MAGIC_HEADER_V1) {
            (MAGIC_HEADER_V1, 1)
        } else {
            return Err(anyhow!("Invalid magic header, not encrypted data"));
        };

        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce_bytes = &data[magic_header.len()..magic_header.len() + NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_bytes);
        
        if version == 1 {
            // Legacy format: no HMAC
            let ciphertext = &data[magic_header.len() + NONCE_SIZE..];
            return cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| anyhow!("Decryption failed: {}", e));
        }
        
        // V2 format: has HMAC
        if data.len() < magic_header.len() + NONCE_SIZE + HMAC_SIZE {
            return Err(anyhow!("Data too short for V2 format"));
        }
        
        let ciphertext_with_hmac = &data[magic_header.len() + NONCE_SIZE..];
        let ciphertext_len = ciphertext_with_hmac.len() - HMAC_SIZE;
        let ciphertext = &ciphertext_with_hmac[..ciphertext_len];
        let stored_hmac = &ciphertext_with_hmac[ciphertext_len..];
        
        // Verify HMAC before decryption
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key_bytes)
            .map_err(|e| anyhow!("HMAC key error: {}", e))?;
        mac.update(magic_header);
        mac.update(nonce_bytes);
        mac.update(ciphertext);
        mac.update(self.key.as_slice()); // Include encryption key in HMAC for additional binding
        
        mac.verify_slice(stored_hmac)
            .map_err(|_| anyhow!("HMAC verification failed - data may be tampered"))?;
        
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }

    /// Encrypt data with integrity check and peer-ID binding
    /// Format: [MAGIC_HEADER_V2 | NONCE | CIPHERTEXT | HMAC(header|nonce|ciphertext|peer_id|enc_key)]
    pub fn encrypt_with_integrity(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Compute HMAC over: magic_header | nonce | ciphertext | peer_id | encryption_key
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key_bytes)
            .map_err(|e| anyhow!("HMAC key error: {}", e))?;
        mac.update(MAGIC_HEADER_V2);
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        mac.update(peer_id.as_bytes());
        mac.update(self.key.as_slice()); // Bind to encryption key
        
        let hmac_tag = mac.finalize().into_bytes();

        // Format: [MAGIC_HEADER_V2 | NONCE | CIPHERTEXT | HMAC]
        let mut result = Vec::with_capacity(
            MAGIC_HEADER_V2.len() + NONCE_SIZE + ciphertext.len() + HMAC_SIZE,
        );
        result.extend_from_slice(MAGIC_HEADER_V2);
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);
        result.extend_from_slice(&hmac_tag);

        Ok(result)
    }

    /// Decrypt data with integrity check and peer-ID validation
    pub fn decrypt_with_integrity(&self, data: &[u8], expected_peer_id: &str) -> Result<Vec<u8>> {
        if data.len() < MAGIC_HEADER_V2.len() + NONCE_SIZE + HMAC_SIZE {
            return Err(anyhow!("Data too short for encrypted format with integrity"));
        }

        if !data.starts_with(MAGIC_HEADER_V2) {
            return Err(anyhow!("Invalid magic header, expected V2 format"));
        }

        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce_bytes = &data[MAGIC_HEADER_V2.len()..MAGIC_HEADER_V2.len() + NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let ciphertext_with_hmac = &data[MAGIC_HEADER_V2.len() + NONCE_SIZE..];
        let ciphertext_len = ciphertext_with_hmac.len() - HMAC_SIZE;
        let ciphertext = &ciphertext_with_hmac[..ciphertext_len];
        let stored_hmac = &ciphertext_with_hmac[ciphertext_len..];

        // Verify HMAC with peer-ID binding
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key_bytes)
            .map_err(|e| anyhow!("HMAC key error: {}", e))?;
        mac.update(MAGIC_HEADER_V2);
        mac.update(nonce_bytes);
        mac.update(ciphertext);
        mac.update(expected_peer_id.as_bytes());
        mac.update(self.key.as_slice());

        mac.verify_slice(stored_hmac)
            .map_err(|_| anyhow!("HMAC verification failed - data may be tampered or peer-ID mismatch"))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }
}
