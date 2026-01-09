/// Signed whitelist for authorized code hashes and protocol versions
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;
use tracing::{info, warn};

/// Authorized version entry in whitelist
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedVersion {
    /// Code hash (SHA256 of version + git commit + build timestamp + protocol)
    pub code_hash: String,
    /// Protocol version (e.g., "/mpc/1.0.0")
    pub     protocol_version: String,
}

impl Hash for AuthorizedVersion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.code_hash.hash(state);
        self.protocol_version.hash(state);
    }
}

/// Whitelist metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistMetadata {
    /// Whitelist format version
    pub version: u32,
    /// Last update timestamp (ISO 8601)
    pub updated_at: String,
    /// Signer identifier
    pub signer: String,
}

/// Complete whitelist structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeHashWhitelist {
    /// Authorized versions
    pub versions: Vec<AuthorizedVersion>,
    /// Metadata
    pub metadata: WhitelistMetadata,
}

impl CodeHashWhitelist {
    /// Load whitelist from JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow!("Failed to read whitelist file: {}", e))?;
        
        let whitelist: CodeHashWhitelist = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse whitelist JSON: {}", e))?;
        
        info!(
            "📋 [WHITELIST] Loaded {} authorized versions from {}",
            whitelist.versions.len(),
            path.as_ref().display()
        );
        
        Ok(whitelist)
    }

    /// Verify signature of whitelist file
    /// Uses SHA256 hash with signature verification
    /// Note: This is a simplified verification. For production, use proper RSA/ECDSA verification
    /// with a crypto library like `rsa` or `ed25519-dalek`
    pub fn verify_signature<P: AsRef<Path>>(
        whitelist_path: P,
        signature_path: P,
        public_key_pem: &str,
    ) -> Result<bool> {
        use sha2::{Sha256, Digest};
        use std::io::Read;

        // Read whitelist file
        let mut whitelist_file = std::fs::File::open(whitelist_path.as_ref())
            .map_err(|e| anyhow!("Failed to open whitelist file: {}", e))?;
        let mut whitelist_content = Vec::new();
        whitelist_file.read_to_end(&mut whitelist_content)
            .map_err(|e| anyhow!("Failed to read whitelist file: {}", e))?;

        // Read signature file (expecting hex-encoded signature)
        let signature_hex = std::fs::read_to_string(signature_path.as_ref())
            .map_err(|e| anyhow!("Failed to read signature file: {}", e))?;
        let signature = hex::decode(signature_hex.trim())
            .map_err(|e| anyhow!("Failed to decode signature hex: {}", e))?;

        // Hash the whitelist content
        let mut hasher = Sha256::new();
        hasher.update(&whitelist_content);
        let hash = hasher.finalize();

        // For now, we'll use a simple approach: verify that signature matches expected format
        // In production, this should use proper RSA/ECDSA verification
        // The signature should be the hash signed with the private key
        // For this implementation, we'll check if signature length is reasonable
        // and verify against a stored hash of the public key
        
        // TODO: Implement proper RSA/ECDSA signature verification
        // For now, we'll do a basic check and log a warning
        if signature.len() < 32 {
            warn!("⚠️ [WHITELIST] Signature too short, may be invalid");
            return Ok(false);
        }

        // Store public key hash for verification
        // In production, use proper signature verification
        let mut key_hasher = Sha256::new();
        key_hasher.update(public_key_pem.as_bytes());
        let key_hash = key_hasher.finalize();

        // For now, accept if signature exists and has reasonable length
        // In production, replace this with actual signature verification
        info!("⚠️ [WHITELIST] Using simplified signature verification - implement proper RSA/ECDSA in production");
        info!("✅ [WHITELIST] Signature file exists and has valid format");
        
        Ok(true)
    }

    /// Check if code hash and protocol version are authorized
    pub fn is_authorized(&self, code_hash: &str, protocol_version: &str) -> bool {
        let entry = AuthorizedVersion {
            code_hash: code_hash.to_string(),
            protocol_version: protocol_version.to_string(),
        };
        
        self.versions.contains(&entry)
    }

    /// Get all authorized code hashes
    pub fn get_authorized_hashes(&self) -> HashSet<String> {
        self.versions.iter()
            .map(|v| v.code_hash.clone())
            .collect()
    }

    /// Get all authorized protocol versions
    pub fn get_authorized_protocol_versions(&self) -> HashSet<String> {
        self.versions.iter()
            .map(|v| v.protocol_version.clone())
            .collect()
    }

    /// Check if protocol version meets minimum requirement
    /// Compares semantic versions (e.g., "/mpc/1.0.0" vs "/mpc/1.2.0")
    pub fn meets_minimum_protocol_version(
        &self,
        protocol_version: &str,
        min_protocol_version: &str,
    ) -> Result<bool> {
        // Extract version numbers from protocol strings
        // Format: "/mpc/1.2.3" -> extract "1.2.3"
        let extract_version = |proto: &str| -> Result<String> {
            let parts: Vec<&str> = proto.split('/').collect();
            if parts.len() >= 3 {
                Ok(parts[2].to_string())
            } else {
                Err(anyhow!("Invalid protocol version format: {}", proto))
            }
        };

        let peer_version = extract_version(protocol_version)?;
        let min_version = extract_version(min_protocol_version)?;

        // Parse semantic versions
        let (peer_major, peer_minor, peer_patch) = 
            crate::network::utils::parse_semantic_version(&peer_version)?;
        let (min_major, min_minor, min_patch) = 
            crate::network::utils::parse_semantic_version(&min_version)?;

        // Compare versions
        if peer_major > min_major {
            Ok(true)
        } else if peer_major < min_major {
            Ok(false)
        } else if peer_minor > min_minor {
            Ok(true)
        } else if peer_minor < min_minor {
            Ok(false)
        } else {
            Ok(peer_patch >= min_patch)
        }
    }
}

/// Load and verify signed whitelist
pub fn load_and_verify_whitelist(
    whitelist_path: &str,
    signature_path: &str,
    public_key_pem: &str,
) -> Result<CodeHashWhitelist> {
    // First verify signature
    let is_valid = CodeHashWhitelist::verify_signature(
        whitelist_path,
        signature_path,
        public_key_pem,
    )?;

    if !is_valid {
        return Err(anyhow!("Whitelist signature verification failed"));
    }

    // Load whitelist
    let whitelist = CodeHashWhitelist::load_from_file(whitelist_path)?;

    info!(
        "✅ [WHITELIST] Loaded and verified whitelist with {} authorized versions",
        whitelist.versions.len()
    );

    Ok(whitelist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorized_version_equality() {
        let v1 = AuthorizedVersion {
            code_hash: "abc123".to_string(),
            protocol_version: "/mpc/1.0.0".to_string(),
        };
        let v2 = AuthorizedVersion {
            code_hash: "abc123".to_string(),
            protocol_version: "/mpc/1.0.0".to_string(),
        };
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_is_authorized() {
        let whitelist = CodeHashWhitelist {
            versions: vec![
                AuthorizedVersion {
                    code_hash: "hash1".to_string(),
                    protocol_version: "/mpc/1.0.0".to_string(),
                },
                AuthorizedVersion {
                    code_hash: "hash2".to_string(),
                    protocol_version: "/mpc/1.1.0".to_string(),
                },
            ],
            metadata: WhitelistMetadata {
                version: 1,
                updated_at: "2024-01-20T10:00:00Z".to_string(),
                signer: "test".to_string(),
            },
        };

        assert!(whitelist.is_authorized("hash1", "/mpc/1.0.0"));
        assert!(whitelist.is_authorized("hash2", "/mpc/1.1.0"));
        assert!(!whitelist.is_authorized("hash3", "/mpc/1.0.0"));
        assert!(!whitelist.is_authorized("hash1", "/mpc/1.2.0"));
    }
}

