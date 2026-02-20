//! Validation of deposit intents: source/target chain must match token and address type.
//! - TICS chain (tics, qubetics): token must be TICS, address must be EVM (0x...).
//! - BTC chain (btc, bitcoin): token must be BTC, address must be BTC format (not 0x...).

use crate::types::intent::DepositIntent;
use std::result::Result as StdResult;

type ValidationResult = StdResult<(), String>;

fn is_tics_chain(name: &str) -> bool {
    matches!(
        name.trim().to_lowercase().as_str(),
        "tics" | "qubetics"
    )
}

fn is_btc_chain(name: &str) -> bool {
    matches!(name.trim().to_lowercase().as_str(), "btc" | "bitcoin")
}

fn is_tics_token(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("tics")
}

fn is_btc_token(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("btc")
}

/// EVM address: 0x followed by exactly 40 hex chars.
fn looks_like_evm_address(addr: &str) -> bool {
    let a = addr.trim();
    if !a.starts_with("0x") || a.len() != 42 {
        return false;
    }
    a[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// BTC address: not EVM (no 0x prefix); typical base58/bech32 length.
fn looks_like_btc_address(addr: &str) -> bool {
    let a = addr.trim();
    if a.is_empty() {
        return false;
    }
    if a.starts_with("0x") {
        return false;
    }
    // Base58 P2PKH ~25-34; bech32 can be longer
    (25..=90).contains(&a.len())
}

/// Validate that source/target chain, token and address are consistent.
/// - If source_chain is TICS: source_token must be TICS, source_address must be EVM.
/// - If source_chain is BTC: source_token must be BTC, source_address must be BTC-style.
/// - Same rules for target_chain, target_token, target_address.
pub fn validate_intent_chains_tokens_addresses(intent: &DepositIntent) -> ValidationResult {
    if is_tics_chain(&intent.source_chain) {
        if !is_tics_token(&intent.source_token) {
            return Err(format!(
                "source_chain is TICS but source_token is not TICS (got: {})",
                intent.source_token
            ));
        }
        if !looks_like_evm_address(&intent.source_address) {
            return Err(format!(
                "source_chain is TICS but source_address is not a valid EVM address (0x...): {}",
                intent.source_address
            ));
        }
    } else if is_btc_chain(&intent.source_chain) {
        if !is_btc_token(&intent.source_token) {
            return Err(format!(
                "source_chain is BTC but source_token is not BTC (got: {})",
                intent.source_token
            ));
        }
        if !looks_like_btc_address(&intent.source_address) {
            return Err(format!(
                "source_chain is BTC but source_address does not look like a BTC address: {}",
                intent.source_address
            ));
        }
    } else {
        return Err(format!(
            "unsupported source_chain: {} (expected TICS/qubetics or BTC/bitcoin)",
            intent.source_chain
        ));
    }

    if is_tics_chain(&intent.target_chain) {
        if !is_tics_token(&intent.target_token) {
            return Err(format!(
                "target_chain is TICS but target_token is not TICS (got: {})",
                intent.target_token
            ));
        }
        if !looks_like_evm_address(&intent.target_address) {
            return Err(format!(
                "target_chain is TICS but target_address is not a valid EVM address (0x...): {}",
                intent.target_address
            ));
        }
    } else if is_btc_chain(&intent.target_chain) {
        if !is_btc_token(&intent.target_token) {
            return Err(format!(
                "target_chain is BTC but target_token is not BTC (got: {})",
                intent.target_token
            ));
        }
        if !looks_like_btc_address(&intent.target_address) {
            return Err(format!(
                "target_chain is BTC but target_address does not look like a BTC address: {}",
                intent.target_address
            ));
        }
    } else {
        return Err(format!(
            "unsupported target_chain: {} (expected TICS/qubetics or BTC/bitcoin)",
            intent.target_chain
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(
        source_chain: &str,
        target_chain: &str,
        source_token: &str,
        target_token: &str,
        source_address: &str,
        target_address: &str,
    ) -> DepositIntent {
        DepositIntent {
            source_address: source_address.to_string(),
            target_address: target_address.to_string(),
            source_chain: source_chain.to_string(),
            target_chain: target_chain.to_string(),
            amount: "1000000".to_string(),
            source_token: source_token.to_string(),
            target_token: target_token.to_string(),
            timestamp: 0,
        }
    }

    #[test]
    fn tics_to_btc_valid() {
        let i = intent(
            "qubetics",
            "bitcoin",
            "TICS",
            "BTC",
            "0x1234567890123456789012345678901234567890",
            "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhxd0pu",
        );
        assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
    }

    #[test]
    fn tics_source_wrong_token() {
        let i = intent(
            "tics",
            "qubetics",
            "BTC",
            "TICS",
            "0x1234567890123456789012345678901234567890",
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        );
        assert!(validate_intent_chains_tokens_addresses(&i).is_err());
    }

    #[test]
    fn tics_source_wrong_address() {
        let i = intent(
            "qubetics",
            "qubetics",
            "TICS",
            "TICS",
            "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhxd0pu",
            "0x1234567890123456789012345678901234567890",
        );
        assert!(validate_intent_chains_tokens_addresses(&i).is_err());
    }

    #[test]
    fn btc_to_tics_valid() {
        let i = intent(
            "bitcoin",
            "tics",
            "BTC",
            "TICS",
            "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhxd0pu",
            "0x1234567890123456789012345678901234567890",
        );
        assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
    }

    #[test]
    fn unsupported_source_chain() {
        let i = intent(
            "polygon",
            "qubetics",
            "MATIC",
            "TICS",
            "0x1234567890123456789012345678901234567890",
            "0x1234567890123456789012345678901234567890",
        );
        assert!(validate_intent_chains_tokens_addresses(&i).is_err());
    }
}
