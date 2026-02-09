use anyhow::{anyhow, Context, Result};
use libp2p::identity::Keypair;
use std::fs;
use std::path::Path;

/// Default path for storing peer identity
const DEFAULT_IDENTITY_PATH: &str = "./data/peer_identity.key";

/// Get the default keypair file path
pub fn default_keypair_path() -> String {
    DEFAULT_IDENTITY_PATH.to_string()
}

/// Save a keypair to a file
pub fn save_keypair(keypair: &Keypair, path: &str) -> Result<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .context(format!("Failed to create directory: {}", parent.display()))?;
    }

    // Encode keypair to protobuf bytes
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow!("Failed to encode keypair: {:?}", e))?;

    // Write to file
    fs::write(path, bytes).context(format!("Failed to write keypair to {}", path))?;

    // Set file permissions to 0600 (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Load a keypair from a file
pub fn load_keypair(path: &str) -> Result<Keypair> {
    // Read file
    let bytes = fs::read(path).context(format!("Failed to read keypair from {}", path))?;

    // Decode from protobuf
    Keypair::from_protobuf_encoding(&bytes)
        .map_err(|e| anyhow!("Failed to decode keypair: {:?}", e))
}

/// Check if a keypair file exists
pub fn keypair_exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Generate a new keypair and save it to the default path
pub fn generate_and_save() -> Result<Keypair> {
    let keypair = Keypair::generate_ed25519();
    let path = default_keypair_path();

    save_keypair(&keypair, &path)?;

    Ok(keypair)
}

/// Load keypair from default path, or generate a new one if it doesn't exist
pub fn load_or_generate() -> Result<Keypair> {
    let path = default_keypair_path();

    if keypair_exists(&path) {
        load_keypair(&path)
    } else {
        generate_and_save()
    }
}
