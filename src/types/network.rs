use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;

/// Environment variable that selects the operational network.
pub const NETWORK_ENV_KEY: &str = "NETWORK_TYPE";
/// Optional RPC override for Qubetics/TICS endpoints.
pub const ETH_RPC_ENV_KEY: &str = "MPC_ETHEREUM_RPC_URL";

static NETWORK_TYPE: OnceCell<NetworkType> = OnceCell::new();

/// Supported environments for the MPC node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Testnet,
    Mainnet,
}

impl NetworkType {
    /// Parse a user-provided string into a [`NetworkType`].
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "testnet" => Some(Self::Testnet),
            "mainnet" => Some(Self::Mainnet),
            _ => None,
        }
    }

    /// Returns true when the configured network is a testnet.
    pub const fn is_testnet(self) -> bool {
        matches!(self, Self::Testnet)
    }

    /// Human readable form used in logs and errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    /// Name passed to Bitcoin chain handlers.
    pub const fn bitcoin_network_label(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

/// Initialize (or reuse) the global network type from environment variables.
pub fn init_network_type_from_env() -> Result<NetworkType> {
    if let Some(nt) = NETWORK_TYPE.get().copied() {
        return Ok(nt);
    }

    let raw = std::env::var(NETWORK_ENV_KEY)
        .unwrap_or_else(|_| "testnet".to_string());
    let parsed = NetworkType::parse(&raw).ok_or_else(|| {
        anyhow!(
            "{} must be 'testnet' or 'mainnet' (got '{}')",
            NETWORK_ENV_KEY,
            raw
        )
    })?;

    NETWORK_TYPE
        .set(parsed)
        .map_err(|_| anyhow!("NETWORK_TYPE already initialized"))?;

    Ok(parsed)
}

/// Returns the globally configured [`NetworkType`], panicking if uninitialized.
pub fn network_type() -> NetworkType {
    NETWORK_TYPE.get().copied().expect(
        "NETWORK_TYPE not initialized; call init_network_type_from_env() before using network_type()",
    )
}

/// Helper that returns `true` when the node runs on testnet.
pub fn is_testnet() -> bool {
    network_type().is_testnet()
}

/// Resolve the RPC URL for the Qubetics chain directly from environment variables.
pub fn qubetics_rpc_url_from_env() -> Result<String> {
    let raw = std::env::var(ETH_RPC_ENV_KEY)
        .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string());

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!(
            "{} env var is empty; populate it with a valid RPC endpoint",
            ETH_RPC_ENV_KEY
        ));
    }

    Ok(trimmed.to_string())
}
