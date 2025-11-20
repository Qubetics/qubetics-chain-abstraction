/// KeyStore trait for abstracting keypair storage
///
/// This trait allows the MPC stack to use different storage backends
/// (e.g., local database, remote KMS) without coupling to a specific implementation.
/// This makes the identity lifecycle controllable and easier to audit.
use anyhow::Result;

/// Trait for storing and retrieving keypairs
///
/// Implementations can use local databases, remote KMS, or other secure storage
/// mechanisms. This abstraction allows the MPC stack to swap storage backends
/// without changing the keypair management logic.
pub trait KeyStore: Send + Sync {
    /// Store a keypair with the given key identifier
    fn put_keypair(&self, key: &str, keypair_bytes: &[u8]) -> Result<()>;

    /// Retrieve a keypair by key identifier
    fn get_keypair(&self, key: &str) -> Result<Option<Vec<u8>>>;
}
