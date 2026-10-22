//! Comprehensive unit tests for batch transfer validation across all transaction types.
//!
//! Tests cover every validation check performed during:
//! - Intent intake (RPC deposit endpoint)
//! - Coordinator batch picking
//! - BTC UserToVault batch processing
//! - TICS UserToVault batch processing
//!
//! Transaction directions tested:
//! - TICS → TICS (same-chain)
//! - BTC → BTC (same-chain)
//! - BTC → TICS (cross-chain)
//! - TICS → BTC (cross-chain)

use mpc_node::types::intent::DepositIntent;
use mpc_node::utils::intent_validation::validate_intent_chains_tokens_addresses;
use mpc_node::utils::transaction::DUST_LIMIT_SATS;

// ───────────────────────────────────────────────────────────────────────
// Test helpers
// ───────────────────────────────────────────────────────────────────────

const EVM_ADDR_1: &str = "0x1234567890123456789012345678901234567890";
const EVM_ADDR_2: &str = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const BTC_ADDR_1: &str = "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhxd0pu";
const BTC_ADDR_2: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
const BTC_ADDR_BECH32: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

/// Build a DepositIntent with all fields explicitly set.
fn make_intent(
    source_chain: &str,
    target_chain: &str,
    source_token: &str,
    target_token: &str,
    source_address: &str,
    target_address: &str,
    amount: &str,
) -> DepositIntent {
    DepositIntent {
        source_address: source_address.to_string(),
        target_address: target_address.to_string(),
        source_chain: source_chain.to_string(),
        target_chain: target_chain.to_string(),
        amount: amount.to_string(),
        source_token: source_token.to_string(),
        target_token: target_token.to_string(),
        timestamp: 1700000000,
    }
}

/// Shorthand for a valid TICS → TICS intent with a custom amount.
fn tics_to_tics_intent(amount: &str) -> DepositIntent {
    make_intent("tics", "qubetics", "TICS", "TICS", EVM_ADDR_1, EVM_ADDR_2, amount)
}

/// Shorthand for a valid BTC → BTC intent with a custom amount.
fn btc_to_btc_intent(amount: &str) -> DepositIntent {
    make_intent("bitcoin", "btc", "BTC", "BTC", BTC_ADDR_1, BTC_ADDR_2, amount)
}

/// Shorthand for a valid BTC → TICS intent with a custom amount.
fn btc_to_tics_intent(amount: &str) -> DepositIntent {
    make_intent("bitcoin", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, amount)
}

/// Shorthand for a valid TICS → BTC intent with a custom amount.
fn tics_to_btc_intent(amount: &str) -> DepositIntent {
    make_intent("qubetics", "bitcoin", "TICS", "BTC", EVM_ADDR_1, BTC_ADDR_1, amount)
}

/// Simulates the batch-receiver amount validation logic from gossipsub_handler.
/// Returns Ok(amount) for valid intents, Err(reason) for skipped/rejected intents.
fn validate_btc_batch_amount(intent: &DepositIntent) -> Result<u128, String> {
    let parsed_amount: u128 = intent.amount.parse().unwrap_or(0);
    if parsed_amount == 0 {
        return Err("zero amount".to_string());
    }
    if (parsed_amount as u64) < DUST_LIMIT_SATS {
        return Err(format!(
            "amount {} sats below dust limit {}",
            parsed_amount, DUST_LIMIT_SATS
        ));
    }
    Ok(parsed_amount)
}

/// Simulates the batch-receiver amount validation for TICS batches (no dust check).
fn validate_tics_batch_amount(intent: &DepositIntent) -> Result<u128, String> {
    let parsed_amount: u128 = intent.amount.parse().unwrap_or(0);
    if parsed_amount == 0 {
        return Err("zero amount".to_string());
    }
    Ok(parsed_amount)
}

/// Simulates the BTC source chain check performed by the BTC batch handler.
fn validate_btc_source_chain(intent: &DepositIntent) -> bool {
    intent.source_chain.eq_ignore_ascii_case("bitcoin")
        || intent.source_chain.eq_ignore_ascii_case("btc")
}

/// Simulates the TICS source chain check performed by the TICS batch handler.
fn validate_tics_source_chain(intent: &DepositIntent) -> bool {
    intent.source_chain.eq_ignore_ascii_case("tics")
        || intent.source_chain.eq_ignore_ascii_case("qubetics")
}

/// Simulates the coordinator batch-pick dust filter for BTC-source intents.
fn coordinator_btc_dust_filter(intent: &DepositIntent) -> bool {
    let is_btc_source = intent.source_chain.eq_ignore_ascii_case("bitcoin")
        || intent.source_chain.eq_ignore_ascii_case("btc");
    if is_btc_source {
        let parsed_amount: u64 = intent.amount.parse().unwrap_or(0);
        if parsed_amount < DUST_LIMIT_SATS {
            return false; // filtered out
        }
    }
    true // passes filter
}

/// Simulates the intake BTC-source dust check.
fn intake_btc_source_dust_check(source_chain: &str, source_amount: u128) -> Result<(), String> {
    let src_is_btc = source_chain.eq_ignore_ascii_case("btc")
        || source_chain.eq_ignore_ascii_case("bitcoin");
    if src_is_btc && source_amount < (DUST_LIMIT_SATS as u128) {
        return Err(format!(
            "BTC amount too small: {} satoshis is below Bitcoin dust limit (minimum {} satoshis required)",
            source_amount, DUST_LIMIT_SATS
        ));
    }
    Ok(())
}

/// Simulates the intake TICS→BTC target amount check.
fn intake_tics_to_btc_target_check(
    is_tics_to_btc: bool,
    target_amount: u128,
) -> Result<(), String> {
    const MIN_BTC_INTENT_SATS: u128 = 550;
    if is_tics_to_btc && target_amount < MIN_BTC_INTENT_SATS {
        return Err(format!(
            "TICS to BTC amount too small: converts to {} satoshis (minimum {} satoshis required)",
            target_amount, MIN_BTC_INTENT_SATS
        ));
    }
    Ok(())
}

/// Simulates the full validation pipeline an intent goes through:
/// 1. Chain/token/address validation
/// 2. Amount validation (zero + dust for BTC)
/// 3. Source chain routing check
fn full_btc_batch_validation(intent: &DepositIntent) -> Result<(), String> {
    validate_intent_chains_tokens_addresses(intent)?;
    if !validate_btc_source_chain(intent) {
        return Err("source_chain is not Bitcoin".to_string());
    }
    validate_btc_batch_amount(intent)?;
    Ok(())
}

fn full_tics_batch_validation(intent: &DepositIntent) -> Result<(), String> {
    validate_intent_chains_tokens_addresses(intent)?;
    if !validate_tics_source_chain(intent) {
        return Err("source_chain is not TICS".to_string());
    }
    validate_tics_batch_amount(intent)?;
    Ok(())
}

/// Simulates the complete lifecycle: intake check → coordinator pick → batch validation
fn simulate_full_lifecycle_btc(amount_sats: u128) -> Result<(), String> {
    intake_btc_source_dust_check("bitcoin", amount_sats)?;
    let intent = btc_to_tics_intent(&amount_sats.to_string());
    if !coordinator_btc_dust_filter(&intent) {
        return Err("coordinator filtered out: below dust".to_string());
    }
    full_btc_batch_validation(&intent)?;
    Ok(())
}

fn simulate_full_lifecycle_tics(amount_wei: u128) -> Result<(), String> {
    let intent = tics_to_tics_intent(&amount_wei.to_string());
    full_tics_batch_validation(&intent)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// 1. CHAIN/TOKEN/ADDRESS VALIDATION (validate_intent_chains_tokens_addresses)
// ═══════════════════════════════════════════════════════════════════════

// ─── TICS → TICS ──────────────────────────────────────────────────────

#[test]
fn chain_validation_tics_to_tics_valid() {
    let i = tics_to_tics_intent("1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_tics_to_qubetics_valid() {
    let i = make_intent("tics", "qubetics", "TICS", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_qubetics_to_tics_valid() {
    let i = make_intent("qubetics", "tics", "TICS", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_ethereum_alias_valid() {
    let i = make_intent("ethereum", "evm", "TICS", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_tics_to_tics_wrong_source_token() {
    let i = make_intent("tics", "tics", "BTC", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_token is not TICS"));
}

#[test]
fn chain_validation_tics_to_tics_wrong_target_token() {
    let i = make_intent("tics", "tics", "TICS", "BTC", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("target_token is not TICS"));
}

#[test]
fn chain_validation_tics_source_btc_address_rejected() {
    let i = make_intent("tics", "tics", "TICS", "TICS", BTC_ADDR_1, EVM_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("not a valid EVM address"));
}

#[test]
fn chain_validation_tics_target_btc_address_rejected() {
    let i = make_intent("tics", "tics", "TICS", "TICS", EVM_ADDR_1, BTC_ADDR_1, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("not a valid EVM address"));
}

// ─── BTC → BTC ────────────────────────────────────────────────────────

#[test]
fn chain_validation_btc_to_btc_valid() {
    let i = btc_to_btc_intent("100000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_bitcoin_to_bitcoin_valid() {
    let i = make_intent("bitcoin", "bitcoin", "BTC", "BTC", BTC_ADDR_1, BTC_ADDR_2, "100000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_btc_bech32_addresses_valid() {
    let i = make_intent(
        "bitcoin", "bitcoin", "BTC", "BTC",
        BTC_ADDR_BECH32, BTC_ADDR_1, "100000",
    );
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_btc_to_btc_wrong_source_token() {
    let i = make_intent("bitcoin", "btc", "TICS", "BTC", BTC_ADDR_1, BTC_ADDR_2, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_token is not BTC"));
}

#[test]
fn chain_validation_btc_to_btc_wrong_target_token() {
    let i = make_intent("bitcoin", "btc", "BTC", "TICS", BTC_ADDR_1, BTC_ADDR_2, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("target_token is not BTC"));
}

#[test]
fn chain_validation_btc_source_evm_address_rejected() {
    let i = make_intent("bitcoin", "btc", "BTC", "BTC", EVM_ADDR_1, BTC_ADDR_2, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("does not look like a BTC address"));
}

#[test]
fn chain_validation_btc_target_evm_address_rejected() {
    let i = make_intent("bitcoin", "btc", "BTC", "BTC", BTC_ADDR_1, EVM_ADDR_1, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("does not look like a BTC address"));
}

#[test]
fn chain_validation_btc_empty_source_address_rejected() {
    let i = make_intent("bitcoin", "btc", "BTC", "BTC", "", BTC_ADDR_2, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
}

// ─── BTC → TICS (cross-chain) ────────────────────────────────────────

#[test]
fn chain_validation_btc_to_tics_valid() {
    let i = btc_to_tics_intent("100000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_bitcoin_to_qubetics_valid() {
    let i = make_intent(
        "bitcoin", "qubetics", "BTC", "TICS",
        BTC_ADDR_1, EVM_ADDR_1, "100000",
    );
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_btc_to_tics_wrong_source_token() {
    let i = make_intent("bitcoin", "tics", "TICS", "TICS", BTC_ADDR_1, EVM_ADDR_1, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_token is not BTC"));
}

#[test]
fn chain_validation_btc_to_tics_wrong_target_token() {
    let i = make_intent("bitcoin", "tics", "BTC", "BTC", BTC_ADDR_1, EVM_ADDR_1, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("target_token is not TICS"));
}

#[test]
fn chain_validation_btc_to_tics_evm_source_rejected() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", EVM_ADDR_1, EVM_ADDR_2, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("does not look like a BTC address"));
}

#[test]
fn chain_validation_btc_to_tics_btc_target_rejected() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", BTC_ADDR_1, BTC_ADDR_2, "100000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("not a valid EVM address"));
}

// ─── TICS → BTC (cross-chain) ────────────────────────────────────────

#[test]
fn chain_validation_tics_to_btc_valid() {
    let i = tics_to_btc_intent("1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_qubetics_to_bitcoin_valid() {
    let i = make_intent(
        "qubetics", "bitcoin", "TICS", "BTC",
        EVM_ADDR_1, BTC_ADDR_1, "1000000",
    );
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_tics_to_btc_wrong_source_token() {
    let i = make_intent("qubetics", "bitcoin", "BTC", "BTC", EVM_ADDR_1, BTC_ADDR_1, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_token is not TICS"));
}

#[test]
fn chain_validation_tics_to_btc_wrong_target_token() {
    let i = make_intent("qubetics", "bitcoin", "TICS", "TICS", EVM_ADDR_1, BTC_ADDR_1, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("target_token is not BTC"));
}

#[test]
fn chain_validation_tics_to_btc_btc_source_rejected() {
    let i = make_intent("qubetics", "bitcoin", "TICS", "BTC", BTC_ADDR_1, BTC_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("not a valid EVM address"));
}

#[test]
fn chain_validation_tics_to_btc_evm_target_rejected() {
    let i = make_intent("qubetics", "bitcoin", "TICS", "BTC", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("does not look like a BTC address"));
}

// ─── Unsupported chains ──────────────────────────────────────────────

#[test]
fn chain_validation_unsupported_source_chain() {
    let i = make_intent("polygon", "tics", "MATIC", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("unsupported source_chain"));
}

#[test]
fn chain_validation_unsupported_target_chain() {
    let i = make_intent("tics", "solana", "TICS", "SOL", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    let err = validate_intent_chains_tokens_addresses(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("unsupported target_chain"));
}

#[test]
fn chain_validation_both_chains_unsupported() {
    let i = make_intent("polygon", "solana", "MATIC", "SOL", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_err());
}

// ─── Case insensitivity ──────────────────────────────────────────────

#[test]
fn chain_validation_case_insensitive_chains() {
    let i = make_intent("TICS", "QUBETICS", "TICS", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_case_insensitive_btc_chains() {
    let i = make_intent("BITCOIN", "BTC", "BTC", "BTC", BTC_ADDR_1, BTC_ADDR_2, "100000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

#[test]
fn chain_validation_mixed_case_tokens() {
    let i = make_intent("tics", "bitcoin", "Tics", "Btc", EVM_ADDR_1, BTC_ADDR_1, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_ok());
}

// ─── EVM address edge cases ──────────────────────────────────────────

#[test]
fn chain_validation_evm_address_too_short() {
    let i = make_intent("tics", "tics", "TICS", "TICS", "0x1234", EVM_ADDR_2, "1000000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_err());
}

#[test]
fn chain_validation_evm_address_no_prefix() {
    let i = make_intent(
        "tics", "tics", "TICS", "TICS",
        "1234567890123456789012345678901234567890",
        EVM_ADDR_2, "1000000",
    );
    assert!(validate_intent_chains_tokens_addresses(&i).is_err());
}

#[test]
fn chain_validation_evm_address_non_hex_chars() {
    let i = make_intent(
        "tics", "tics", "TICS", "TICS",
        "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        EVM_ADDR_2, "1000000",
    );
    assert!(validate_intent_chains_tokens_addresses(&i).is_err());
}

// ─── BTC address edge cases ──────────────────────────────────────────

#[test]
fn chain_validation_btc_address_too_short() {
    let i = make_intent("bitcoin", "btc", "BTC", "BTC", "1A1z", BTC_ADDR_2, "100000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_err());
}

#[test]
fn chain_validation_btc_address_empty() {
    let i = make_intent("bitcoin", "btc", "BTC", "BTC", "", BTC_ADDR_2, "100000");
    assert!(validate_intent_chains_tokens_addresses(&i).is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// 2. BTC BATCH AMOUNT VALIDATION (zero + dust checks)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn btc_batch_amount_zero_rejected() {
    let i = btc_to_tics_intent("0");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("zero amount"));
}

#[test]
fn btc_batch_amount_empty_string_rejected() {
    let i = btc_to_tics_intent("");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("zero amount"));
}

#[test]
fn btc_batch_amount_non_numeric_rejected() {
    let i = btc_to_tics_intent("abc");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("zero amount"));
}

#[test]
fn btc_batch_amount_1_sat_below_dust() {
    let i = btc_to_tics_intent("1");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("below dust limit"));
}

#[test]
fn btc_batch_amount_545_below_dust() {
    let i = btc_to_tics_intent("545");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("below dust limit"));
}

#[test]
fn btc_batch_amount_500_below_dust() {
    // The exact scenario from the logs
    let i = btc_to_tics_intent("500");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    let msg = err.unwrap_err();
    assert!(msg.contains("below dust limit"), "expected 'below dust limit' in: {}", msg);
    assert!(msg.contains("500"), "expected '500' in: {}", msg);
}

#[test]
fn btc_batch_amount_546_at_dust_limit_accepted() {
    let i = btc_to_tics_intent("546");
    let result = validate_btc_batch_amount(&i);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 546);
}

#[test]
fn btc_batch_amount_547_above_dust_accepted() {
    let i = btc_to_tics_intent("547");
    let result = validate_btc_batch_amount(&i);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 547);
}

#[test]
fn btc_batch_amount_1000_accepted() {
    let i = btc_to_tics_intent("1000");
    let result = validate_btc_batch_amount(&i);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1000);
}

#[test]
fn btc_batch_amount_100000_accepted() {
    let i = btc_to_tics_intent("100000");
    let result = validate_btc_batch_amount(&i);
    assert!(result.is_ok());
}

#[test]
fn btc_batch_amount_large_value_accepted() {
    // 1 BTC = 100_000_000 sats
    let i = btc_to_tics_intent("100000000");
    let result = validate_btc_batch_amount(&i);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 100_000_000);
}

// ─── BTC → BTC dust checks ──────────────────────────────────────────

#[test]
fn btc_batch_btc_to_btc_below_dust_rejected() {
    let i = btc_to_btc_intent("500");
    let err = validate_btc_batch_amount(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("below dust limit"));
}

#[test]
fn btc_batch_btc_to_btc_at_dust_accepted() {
    let i = btc_to_btc_intent("546");
    assert!(validate_btc_batch_amount(&i).is_ok());
}

// ═════════════════════���═════════════════════════════════════════════════
// 3. TICS BATCH AMOUNT VALIDATION (zero check only, no dust)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tics_batch_amount_zero_rejected() {
    let i = tics_to_tics_intent("0");
    assert!(validate_tics_batch_amount(&i).is_err());
}

#[test]
fn tics_batch_amount_empty_string_rejected() {
    let i = tics_to_tics_intent("");
    assert!(validate_tics_batch_amount(&i).is_err());
}

#[test]
fn tics_batch_amount_non_numeric_rejected() {
    let i = tics_to_tics_intent("not_a_number");
    assert!(validate_tics_batch_amount(&i).is_err());
}

#[test]
fn tics_batch_amount_1_wei_accepted() {
    // TICS has no dust limit — even 1 wei is valid
    let i = tics_to_tics_intent("1");
    assert!(validate_tics_batch_amount(&i).is_ok());
}

#[test]
fn tics_batch_amount_small_accepted() {
    // 100 wei is fine for TICS (no dust limit)
    let i = tics_to_tics_intent("100");
    assert!(validate_tics_batch_amount(&i).is_ok());
}

#[test]
fn tics_batch_amount_500_accepted() {
    // 500 would fail BTC dust check but passes TICS
    let i = tics_to_tics_intent("500");
    let result = validate_tics_batch_amount(&i);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 500);
}

#[test]
fn tics_batch_amount_large_value_accepted() {
    // 1 TICS = 10^18 wei
    let i = tics_to_tics_intent("1000000000000000000");
    let result = validate_tics_batch_amount(&i);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1_000_000_000_000_000_000u128);
}

// ─── TICS → BTC direction (TICS batch processes TICS-source) ─────────

#[test]
fn tics_batch_tics_to_btc_zero_rejected() {
    let i = tics_to_btc_intent("0");
    assert!(validate_tics_batch_amount(&i).is_err());
}

#[test]
fn tics_batch_tics_to_btc_small_amount_accepted() {
    // TICS source, no dust check on TICS side
    let i = tics_to_btc_intent("100");
    assert!(validate_tics_batch_amount(&i).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// 4. SOURCE CHAIN CHECKS (batch handler routing)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn btc_source_chain_bitcoin_accepted() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, "1000");
    assert!(validate_btc_source_chain(&i));
}

#[test]
fn btc_source_chain_btc_accepted() {
    let i = make_intent("btc", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, "1000");
    assert!(validate_btc_source_chain(&i));
}

#[test]
fn btc_source_chain_bitcoin_uppercase_accepted() {
    let i = make_intent("BITCOIN", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, "1000");
    assert!(validate_btc_source_chain(&i));
}

#[test]
fn btc_source_chain_tics_rejected() {
    let i = make_intent("tics", "btc", "TICS", "BTC", EVM_ADDR_1, BTC_ADDR_1, "1000");
    assert!(!validate_btc_source_chain(&i));
}

#[test]
fn btc_source_chain_qubetics_rejected() {
    let i = make_intent("qubetics", "btc", "TICS", "BTC", EVM_ADDR_1, BTC_ADDR_1, "1000");
    assert!(!validate_btc_source_chain(&i));
}

#[test]
fn tics_source_chain_tics_accepted() {
    let i = make_intent("tics", "btc", "TICS", "BTC", EVM_ADDR_1, BTC_ADDR_1, "1000");
    assert!(validate_tics_source_chain(&i));
}

#[test]
fn tics_source_chain_qubetics_accepted() {
    let i = make_intent("qubetics", "btc", "TICS", "BTC", EVM_ADDR_1, BTC_ADDR_1, "1000");
    assert!(validate_tics_source_chain(&i));
}

#[test]
fn tics_source_chain_qubetics_uppercase_accepted() {
    let i = make_intent("QUBETICS", "btc", "TICS", "BTC", EVM_ADDR_1, BTC_ADDR_1, "1000");
    assert!(validate_tics_source_chain(&i));
}

#[test]
fn tics_source_chain_bitcoin_rejected() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, "1000");
    assert!(!validate_tics_source_chain(&i));
}

#[test]
fn tics_source_chain_ethereum_rejected_for_tics_batch() {
    // "ethereum" is accepted by validate_intent_chains_tokens_addresses as TICS-like
    // but NOT by the TICS batch source check which only accepts "tics" | "qubetics"
    let i = make_intent("ethereum", "tics", "TICS", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000");
    assert!(!validate_tics_source_chain(&i));
}

// ═══════════════════════════════════════════════════════════════════════
// 5. COORDINATOR BATCH PICKING — DUST FILTER
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn coordinator_filter_btc_below_dust_filtered_out() {
    let i = btc_to_tics_intent("500");
    assert!(!coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_zero_filtered_out() {
    let i = btc_to_tics_intent("0");
    assert!(!coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_at_dust_passes() {
    let i = btc_to_tics_intent("546");
    assert!(coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_above_dust_passes() {
    let i = btc_to_tics_intent("10000");
    assert!(coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_tics_small_amount_passes() {
    // TICS-source intents are NOT filtered by the BTC dust check
    let i = tics_to_btc_intent("1");
    assert!(coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_tics_to_tics_small_passes() {
    let i = tics_to_tics_intent("1");
    assert!(coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_to_btc_below_dust_filtered() {
    let i = btc_to_btc_intent("100");
    assert!(!coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_non_numeric_amount_filtered() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, "abc");
    assert!(!coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_empty_amount_filtered() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", BTC_ADDR_1, EVM_ADDR_1, "");
    assert!(!coordinator_btc_dust_filter(&i));
}

// ═══════════════════════════════════════════════════════════════════════
// 6. INTAKE VALIDATION — BTC-SOURCE DUST CHECK
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn intake_btc_source_zero_rejected() {
    let result = intake_btc_source_dust_check("bitcoin", 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("below Bitcoin dust limit"));
}

#[test]
fn intake_btc_source_1_sat_rejected() {
    let result = intake_btc_source_dust_check("bitcoin", 1);
    assert!(result.is_err());
}

#[test]
fn intake_btc_source_500_sats_rejected() {
    let result = intake_btc_source_dust_check("btc", 500);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("500 satoshis"));
}

#[test]
fn intake_btc_source_545_rejected() {
    let result = intake_btc_source_dust_check("bitcoin", 545);
    assert!(result.is_err());
}

#[test]
fn intake_btc_source_546_accepted() {
    let result = intake_btc_source_dust_check("bitcoin", 546);
    assert!(result.is_ok());
}

#[test]
fn intake_btc_source_547_accepted() {
    let result = intake_btc_source_dust_check("btc", 547);
    assert!(result.is_ok());
}

#[test]
fn intake_btc_source_100000_accepted() {
    let result = intake_btc_source_dust_check("bitcoin", 100000);
    assert!(result.is_ok());
}

#[test]
fn intake_btc_source_case_insensitive() {
    let result = intake_btc_source_dust_check("BITCOIN", 500);
    assert!(result.is_err());
    let result = intake_btc_source_dust_check("BTC", 100);
    assert!(result.is_err());
}

#[test]
fn intake_tics_source_not_affected_by_btc_dust() {
    // TICS-source should never be rejected by BTC dust check
    let result = intake_btc_source_dust_check("tics", 0);
    assert!(result.is_ok()); // passes because src is not BTC
    let result = intake_btc_source_dust_check("qubetics", 1);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// 7. INTAKE VALIDATION — TICS→BTC TARGET AMOUNT CHECK
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn intake_tics_to_btc_target_zero_rejected() {
    let result = intake_tics_to_btc_target_check(true, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("minimum 550 satoshis"));
}

#[test]
fn intake_tics_to_btc_target_1_sat_rejected() {
    let result = intake_tics_to_btc_target_check(true, 1);
    assert!(result.is_err());
}

#[test]
fn intake_tics_to_btc_target_549_rejected() {
    let result = intake_tics_to_btc_target_check(true, 549);
    assert!(result.is_err());
}

#[test]
fn intake_tics_to_btc_target_550_accepted() {
    let result = intake_tics_to_btc_target_check(true, 550);
    assert!(result.is_ok());
}

#[test]
fn intake_tics_to_btc_target_551_accepted() {
    let result = intake_tics_to_btc_target_check(true, 551);
    assert!(result.is_ok());
}

#[test]
fn intake_tics_to_btc_target_100000_accepted() {
    let result = intake_tics_to_btc_target_check(true, 100000);
    assert!(result.is_ok());
}

#[test]
fn intake_non_tics_to_btc_not_affected() {
    // When is_tics_to_btc is false, any amount should pass
    let result = intake_tics_to_btc_target_check(false, 0);
    assert!(result.is_ok());
    let result = intake_tics_to_btc_target_check(false, 1);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// 8. DUST LIMIT CONSTANT VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn dust_limit_is_546() {
    assert_eq!(DUST_LIMIT_SATS, 546, "Bitcoin dust limit should be 546 sats");
}

#[test]
fn dust_limit_boundary_545_is_below() {
    assert!(545 < DUST_LIMIT_SATS);
}

#[test]
fn dust_limit_boundary_546_is_at() {
    assert!(546 >= DUST_LIMIT_SATS);
}

// ═══════════════════════════════════════════════════════════════════════
// 9. FULL PIPELINE TESTS — end-to-end validation simulation
// ═══════════════════════════════════════════════════════════════════════

// ─── BTC → TICS full pipeline ────────────────────────────────────────

#[test]
fn full_btc_to_tics_valid_intent() {
    let i = btc_to_tics_intent("10000");
    assert!(full_btc_batch_validation(&i).is_ok());
}

#[test]
fn full_btc_to_tics_below_dust_rejected() {
    let i = btc_to_tics_intent("500");
    let err = full_btc_batch_validation(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("dust limit"));
}

#[test]
fn full_btc_to_tics_zero_rejected() {
    let i = btc_to_tics_intent("0");
    let err = full_btc_batch_validation(&i);
    assert!(err.is_err());
}

#[test]
fn full_btc_to_tics_wrong_token_rejected() {
    let i = make_intent("bitcoin", "tics", "TICS", "TICS", BTC_ADDR_1, EVM_ADDR_1, "10000");
    let err = full_btc_batch_validation(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_token is not BTC"));
}

#[test]
fn full_btc_to_tics_wrong_address_rejected() {
    let i = make_intent("bitcoin", "tics", "BTC", "TICS", EVM_ADDR_1, EVM_ADDR_2, "10000");
    let err = full_btc_batch_validation(&i);
    assert!(err.is_err());
}

// ─── TICS → TICS full pipeline ───────────────────────────────────────

#[test]
fn full_tics_to_tics_valid_intent() {
    let i = tics_to_tics_intent("1000000000000000000");
    assert!(full_tics_batch_validation(&i).is_ok());
}

#[test]
fn full_tics_to_tics_1_wei_accepted() {
    let i = tics_to_tics_intent("1");
    assert!(full_tics_batch_validation(&i).is_ok());
}

#[test]
fn full_tics_to_tics_zero_rejected() {
    let i = tics_to_tics_intent("0");
    assert!(full_tics_batch_validation(&i).is_err());
}

#[test]
fn full_tics_to_tics_wrong_token_rejected() {
    let i = make_intent("tics", "tics", "BTC", "TICS", EVM_ADDR_1, EVM_ADDR_2, "1000000");
    let err = full_tics_batch_validation(&i);
    assert!(err.is_err());
}

// ─── TICS → BTC full pipeline (goes through TICS batch) ─────────────

#[test]
fn full_tics_to_btc_valid_intent() {
    let i = tics_to_btc_intent("1000000000000000000");
    assert!(full_tics_batch_validation(&i).is_ok());
}

#[test]
fn full_tics_to_btc_small_amount_accepted() {
    // TICS source has no dust limit
    let i = tics_to_btc_intent("100");
    assert!(full_tics_batch_validation(&i).is_ok());
}

#[test]
fn full_tics_to_btc_zero_rejected() {
    let i = tics_to_btc_intent("0");
    assert!(full_tics_batch_validation(&i).is_err());
}

// ─── BTC → BTC full pipeline ─────────────────────────────────────────

#[test]
fn full_btc_to_btc_valid_intent() {
    let i = btc_to_btc_intent("100000");
    assert!(full_btc_batch_validation(&i).is_ok());
}

#[test]
fn full_btc_to_btc_at_dust_accepted() {
    let i = btc_to_btc_intent("546");
    assert!(full_btc_batch_validation(&i).is_ok());
}

#[test]
fn full_btc_to_btc_below_dust_rejected() {
    let i = btc_to_btc_intent("545");
    assert!(full_btc_batch_validation(&i).is_err());
}

#[test]
fn full_btc_to_btc_zero_rejected() {
    let i = btc_to_btc_intent("0");
    assert!(full_btc_batch_validation(&i).is_err());
}

// ─── Cross-routing: TICS intent sent to BTC batch → rejected ─────────

#[test]
fn full_tics_intent_in_btc_batch_rejected() {
    let i = tics_to_btc_intent("1000000");
    let err = full_btc_batch_validation(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_chain is not Bitcoin"));
}

#[test]
fn full_btc_intent_in_tics_batch_rejected() {
    let i = btc_to_tics_intent("10000");
    let err = full_tics_batch_validation(&i);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("source_chain is not TICS"));
}

// ═══════════════════════════════════════════════════════════════════════
// 10. EDGE CASES AND BOUNDARY TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn btc_batch_amount_negative_string_rejected() {
    let i = btc_to_tics_intent("-100");
    assert!(validate_btc_batch_amount(&i).is_err());
}

#[test]
fn btc_batch_amount_float_rejected() {
    let i = btc_to_tics_intent("546.5");
    assert!(validate_btc_batch_amount(&i).is_err());
}

#[test]
fn btc_batch_amount_overflow_string() {
    let i = btc_to_tics_intent("999999999999999999999999999999999999999999");
    assert!(validate_btc_batch_amount(&i).is_err());
}

#[test]
fn btc_batch_amount_whitespace_rejected() {
    let i = btc_to_tics_intent(" 1000 ");
    assert!(validate_btc_batch_amount(&i).is_err());
}

#[test]
fn tics_batch_amount_negative_rejected() {
    let i = tics_to_tics_intent("-1");
    assert!(validate_tics_batch_amount(&i).is_err());
}

#[test]
fn tics_batch_amount_float_rejected() {
    let i = tics_to_tics_intent("1.5");
    assert!(validate_tics_batch_amount(&i).is_err());
}

#[test]
fn coordinator_filter_btc_545_boundary() {
    let i = btc_to_tics_intent("545");
    assert!(!coordinator_btc_dust_filter(&i));
}

#[test]
fn coordinator_filter_btc_546_boundary() {
    let i = btc_to_tics_intent("546");
    assert!(coordinator_btc_dust_filter(&i));
}

#[test]
fn intake_btc_dust_check_boundary_exact_dust() {
    assert!(intake_btc_source_dust_check("bitcoin", DUST_LIMIT_SATS as u128).is_ok());
    assert!(intake_btc_source_dust_check("bitcoin", (DUST_LIMIT_SATS - 1) as u128).is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// 11. COMBINED INTAKE + BATCH VALIDATION (simulating real flow)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn lifecycle_btc_500_sats_fails_at_intake() {
    let result = simulate_full_lifecycle_btc(500);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("dust limit"));
}

#[test]
fn lifecycle_btc_546_sats_passes_all_stages() {
    assert!(simulate_full_lifecycle_btc(546).is_ok());
}

#[test]
fn lifecycle_btc_10000_sats_passes_all_stages() {
    assert!(simulate_full_lifecycle_btc(10000).is_ok());
}

#[test]
fn lifecycle_btc_0_fails_at_intake() {
    let result = simulate_full_lifecycle_btc(0);
    assert!(result.is_err());
}

#[test]
fn lifecycle_tics_1_wei_passes_all_stages() {
    assert!(simulate_full_lifecycle_tics(1).is_ok());
}

#[test]
fn lifecycle_tics_0_fails_at_batch() {
    let result = simulate_full_lifecycle_tics(0);
    assert!(result.is_err());
}

#[test]
fn lifecycle_tics_large_amount_passes() {
    assert!(simulate_full_lifecycle_tics(1_000_000_000_000_000_000).is_ok());
}
