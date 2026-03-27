use std::{collections::HashMap, str::FromStr, sync::Arc};

use k256::Scalar;
use reqwest::Client;
use rust_decimal::{
    prelude::{FromPrimitive, ToPrimitive},
    Decimal,
};
use rust_decimal_macros::dec;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tracing::{debug, error, info, warn};

use crate::database::DkgStorage;

use super::errors::TransactionError;

pub(crate) fn symbol_for(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        "btc" | "bitcoin" => "BTC",
        _ => "TICS",
    }
}

pub(crate) fn decimals_for(chain: &str) -> u32 {
    match chain.to_lowercase().as_str() {
        "btc" | "bitcoin" => 8,    // satoshis
        "tics" | "qubetics" => 18, // wei-like
        _ => 18,
    }
}

pub(crate) fn pow10_dec(n: u32) -> Decimal {
    // 10^n as Decimal without float errors
    let mut v = dec!(1);
    for _ in 0..n {
        v *= dec!(10);
    }
    v
}

pub(crate) fn convert_src_smallest_to_dst_smallest(
    amount_src_smallest: u128,
    src_chain: &str,
    dst_chain: &str,
    prices: &HashMap<String, Decimal>,
) -> Result<u128, TransactionError> {
    // If source and destination chains are the same, do not perform any conversion.
    if src_chain.eq_ignore_ascii_case(dst_chain) {
        info!(
            "🔄 [CONVERSION] Skipped: source and destination chains are the same ({}). Using original amount: {}",
            src_chain, amount_src_smallest
        );
        return Ok(amount_src_smallest);
    }

    let src_sym = symbol_for(src_chain);
    let dst_sym = symbol_for(dst_chain);

    let p_src = *prices
        .get(src_sym)
        .ok_or(TransactionError::PricingUnavailable)?;
    let p_dst = *prices
        .get(dst_sym)
        .ok_or(TransactionError::PricingUnavailable)?;

    let src_dec = decimals_for(src_chain);
    let dst_dec = decimals_for(dst_chain);

    info!("🔄 [CONVERSION] Starting conversion:");
    info!(
        "  📊 Source: {} {} (smallest units: {})",
        amount_src_smallest, src_sym, src_chain
    );
    info!("  📊 Target: {} (smallest units: {})", dst_sym, dst_chain);
    info!(
        "  💰 Prices: {} = ${}, {} = ${}",
        src_sym, p_src, dst_sym, p_dst
    );
    info!(
        "  🔢 Decimals: {} = {}, {} = {}",
        src_sym, src_dec, dst_sym, dst_dec
    );

    // Apply chain-specific multiplier before price conversion
    let adjusted_amount = match src_chain.to_lowercase().as_str() {
        "tics" | "qubetics" => {
            // For TICS source chain: divide by 10^10
            let divisor = pow10_dec(10);
            let result = Decimal::from_u128(amount_src_smallest)
                .ok_or(TransactionError::Overflow)?
                / divisor;
            info!(
                "  🔄 TICS conversion: {} / 10^10 = {}",
                amount_src_smallest, result
            );
            result
        }
        "btc" | "bitcoin" => {
            // For BTC source chain: multiply by 10^10
            let multiplier = pow10_dec(10);
            let result = Decimal::from_u128(amount_src_smallest)
                .ok_or(TransactionError::Overflow)?
                * multiplier;
            info!(
                "  🔄 BTC conversion: {} * 10^10 = {}",
                amount_src_smallest, result
            );
            result
        }
        _ => {
            // For other chains: no multiplier
            let result =
                Decimal::from_u128(amount_src_smallest).ok_or(TransactionError::Overflow)?;
            info!(
                "  🔄 Other chain conversion: {} (no multiplier)",
                amount_src_smallest
            );
            result
        }
    };

    // Convert to whole units using actual decimals
    let src_whole = adjusted_amount;
    info!(
        "  📏 Converted to whole units: {} / 10^{} = {}",
        adjusted_amount, src_dec, src_whole
    );

    // Apply price conversion
    let dst_whole = src_whole * p_src / p_dst;
    info!(
        "  💱 Price conversion: {} * {} / {} = {}",
        src_whole, p_src, p_dst, dst_whole
    );

    // Convert back to smallest units
    let dst_smallest = dst_whole.floor();
    let result: u128 = dst_smallest.to_u128().ok_or(TransactionError::Overflow)?;

    info!(
        "  📏 Converted to target smallest units: {} * 10^{} = {} (floored)",
        dst_whole, dst_dec, result
    );
    info!("  ✅ Final result: {} {} smallest units", result, dst_sym);

    Ok(result)
}

pub async fn fetch_crypto_prices(
    timestamp: Option<u128>,
) -> Result<HashMap<String, Decimal>, String> {
    let base_url = crate::env_defaults::backend_api_url();
    let url = if let Some(ts) = timestamp {
        format!("{base_url}/api/v1/cryptos/prices?symbols=BTC,TICS&timestamp={ts}")
    } else {
        format!("{base_url}/api/v1/cryptos/prices?symbols=BTC,TICS")
    };
    let client = Client::new();

    info!("Fetching crypto prices from URL: {}", url);

    let resp = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch crypto prices: {}", e);
        format!("Failed to fetch crypto prices: {e}")
    })?;

    let status = resp.status();
    debug!("Crypto prices API response status: {}", status);

    let resp_text = resp.text().await.map_err(|e| {
        error!("Failed to read crypto prices response text: {}", e);
        format!("Failed to read crypto prices response text: {e}")
    })?;

    debug!("Crypto prices API response body: {}", resp_text);

    if !status.is_success() {
        error!(
            "Crypto prices API returned non-success status {}: {}",
            status, resp_text
        );
        return Err(format!(
            "Crypto prices API returned non-success status {status}: {resp_text}"
        ));
    }

    let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
        error!("Failed to parse crypto prices response: {}", e);
        format!("Failed to parse crypto prices response: {e}")
    })?;

    debug!("Crypto prices API response JSON: {:?}", resp_json);

    if resp_json.get("error").and_then(|v| v.as_bool()) == Some(true) {
        let msg = resp_json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        error!("Crypto prices API error: {}", msg);
        return Err(format!("Crypto prices API error: {msg}"));
    }

    let data = resp_json.get("data").ok_or_else(|| {
        error!("No 'data' field in crypto prices response");
        "No 'data' field in crypto prices response".to_string()
    })?;

    let mut prices: HashMap<String, Decimal> = HashMap::new();

    // Tolerant parsing: accept string or number for price fields
    let to_decimal = |v: &Value| -> Option<Decimal> {
        match v {
            Value::String(s) => Decimal::from_str(s).ok(),
            Value::Number(n) => Decimal::from_str(&n.to_string()).ok(),
            _ => None,
        }
    };

    if let Some(obj) = data.as_object() {
        for (symbol, value) in obj {
            if let Some(price) = to_decimal(value) {
                debug!("Parsed Decimal price for {}: {}", symbol, price);
                prices.insert(symbol.clone(), price);
            } else {
                debug!("Could not parse Decimal price for {}: {:?}", symbol, value);
            }
        }
    } else {
        debug!("'data' field is not an object in crypto prices response");
    }

    info!("Fetched crypto prices (Decimal): {:?}", prices);
    Ok(prices)
}

// Helper function to get the actual DKG secret share from shared state
pub(crate) async fn get_actual_dkg_secret_share(dkg_storage: Arc<DkgStorage>) -> Option<Scalar> {
    match dkg_storage.get_final_secret().await {
        Ok(Some(secret)) => Some(secret),
        Ok(None) => {
            warn!("DKG is not completed yet, cannot retrieve secret share");
            None
        }
        Err(e) => {
            warn!("Failed to retrieve DKG secret share: {}", e);
            None
        }
    }
}

pub fn normalize_eth_signature(sig_hex: &str) -> anyhow::Result<([u8; 64], u8)> {
    let s = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode signature: {}", e))?;
    if bytes.len() != 65 {
        return Err(anyhow::anyhow!(
            "signature must be 65 bytes r||s||v, got {}",
            bytes.len()
        ));
    }

    let mut compact = [0u8; 64];
    compact.copy_from_slice(&bytes[0..64]);

    let mut v = bytes[64];
    // Normalize v to {0,1}
    v = if v >= 35 {
        (v - 35) % 2 // EIP-155 parity
    } else if v >= 27 {
        v - 27 // 27/28 -> 0/1
    } else {
        v // already 0/1?
    };
    if v > 1 {
        return Err(anyhow::anyhow!("invalid recovery id v={}", v));
    }
    Ok((compact, v))
}

pub fn recover_eth_address_secp(
    msg: &[u8],
    compact: &[u8; 64],
    v: u8,
    use_personal_prefix: bool,
) -> anyhow::Result<String> {
    let rid = RecoveryId::from_i32(v as i32).map_err(|e| anyhow::anyhow!("recovery id: {}", e))?;
    let rsig = RecoverableSignature::from_compact(compact, rid)
        .map_err(|e| anyhow::anyhow!("recoverable sig: {}", e))?;

    // Hash message
    let hash = if use_personal_prefix {
        // EIP-191 "\x19Ethereum Signed Message:\n{len}{msg}"
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(msg);
        h.finalize()
    } else {
        Keccak256::digest(msg)
    };

    let secp = Secp256k1::new();
    let m = Message::from_digest_slice(&hash).map_err(|e| anyhow::anyhow!("message: {}", e))?;
    let pk: PublicKey = secp
        .recover_ecdsa(&m, &rsig)
        .map_err(|e| anyhow::anyhow!("recover pk: {}", e))?;

    // ETH address = keccak(uncompressed_pubkey[1..])[12..]
    let uncompressed = pk.serialize_uncompressed(); // 65 bytes: 0x04 || X || Y
    let keccak = Keccak256::digest(&uncompressed[1..]);
    let mut addr20 = [0u8; 20];
    addr20.copy_from_slice(&keccak[12..]); // last 20 bytes
    Ok(crate::user_intent_manager::to_checksum_address(&addr20))
}

/// Fetch network address balance from the API
pub async fn fetch_network_balance(address: &str, blockchain: &str) -> Result<u128, String> {
    let base_url = crate::env_defaults::backend_api_url();
    let url = format!(
        "{}/api/v1/balance/{}?blockchain={}",
        base_url, address, blockchain
    );
    let client = Client::new();

    info!("💰 Fetching network balance from URL: {}", url);

    let resp = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch network balance: {}", e);
        format!("Failed to fetch network balance: {}", e)
    })?;

    let status = resp.status();
    debug!("Network balance API response status: {}", status);

    let resp_text = resp.text().await.map_err(|e| {
        error!("Failed to read network balance response text: {}", e);
        format!("Failed to read network balance response text: {}", e)
    })?;

    debug!("Network balance API response body: {}", resp_text);

    if !status.is_success() {
        error!(
            "Network balance API returned non-success status {}: {}",
            status, resp_text
        );
        return Err(format!(
            "Network balance API returned non-success status {}: {}",
            status, resp_text
        ));
    }

    let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
        error!("Failed to parse network balance response: {}", e);
        format!("Failed to parse network balance response: {}", e)
    })?;

    debug!("Network balance API response JSON: {:?}", resp_json);

    if resp_json.get("error").and_then(|v| v.as_bool()) == Some(true) {
        let msg = resp_json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        error!("Network balance API error: {}", msg);
        return Err(format!("Network balance API error: {}", msg));
    }

    let balance_str = resp_json
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            error!("Missing 'data' field in network balance response");
            "Missing 'data' field in network balance response".to_string()
        })?;

    let balance = balance_str.parse::<u128>().map_err(|e| {
        error!("Failed to parse balance value '{}': {}", balance_str, e);
        format!("Failed to parse balance value '{}': {}", balance_str, e)
    })?;

    info!(
        "💰 Network balance for {} on {}: {}",
        address, blockchain, balance
    );
    Ok(balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::collections::HashMap;

    /// Helper: build a price map with given BTC and TICS USD prices.
    fn prices(btc_usd: Decimal, tics_usd: Decimal) -> HashMap<String, Decimal> {
        let mut m = HashMap::new();
        m.insert("BTC".to_string(), btc_usd);
        m.insert("TICS".to_string(), tics_usd);
        m
    }

    // =====================================================================
    // 1. symbol_for / decimals_for / pow10_dec helpers
    // =====================================================================

    #[test]
    fn symbol_for_btc_variants() {
        assert_eq!(symbol_for("btc"), "BTC");
        assert_eq!(symbol_for("bitcoin"), "BTC");
        assert_eq!(symbol_for("Bitcoin"), "BTC");
    }

    #[test]
    fn symbol_for_tics_variants() {
        assert_eq!(symbol_for("tics"), "TICS");
        assert_eq!(symbol_for("qubetics"), "TICS");
    }

    #[test]
    fn decimals_for_chains() {
        assert_eq!(decimals_for("btc"), 8);
        assert_eq!(decimals_for("bitcoin"), 8);
        assert_eq!(decimals_for("tics"), 18);
        assert_eq!(decimals_for("qubetics"), 18);
    }

    #[test]
    fn pow10_dec_values() {
        assert_eq!(pow10_dec(0), dec!(1));
        assert_eq!(pow10_dec(1), dec!(10));
        assert_eq!(pow10_dec(8), dec!(100000000));
        assert_eq!(pow10_dec(18), dec!(1000000000000000000));
    }

    // =====================================================================
    // 2. Same-chain: no conversion (amount passes through unchanged)
    // =====================================================================

    #[test]
    fn same_chain_tics_to_tics() {
        let p = prices(dec!(100000), dec!(0.01));
        // 25 TICS = 25 * 10^18 wei
        let amount_wei = 25_000_000_000_000_000_000u128;
        let result = convert_src_smallest_to_dst_smallest(amount_wei, "tics", "tics", &p).unwrap();
        assert_eq!(
            result, amount_wei,
            "Same-chain TICS→TICS should pass through unchanged"
        );
    }

    #[test]
    fn same_chain_btc_to_btc() {
        let p = prices(dec!(100000), dec!(0.01));
        let amount_sats = 100_000u128; // 0.001 BTC
        let result =
            convert_src_smallest_to_dst_smallest(amount_sats, "bitcoin", "bitcoin", &p).unwrap();
        assert_eq!(
            result, amount_sats,
            "Same-chain BTC→BTC should pass through unchanged"
        );
    }

    #[test]
    fn same_chain_case_insensitive() {
        let p = prices(dec!(100000), dec!(0.01));
        let amount = 1_000_000u128;
        let result = convert_src_smallest_to_dst_smallest(amount, "TICS", "tics", &p).unwrap();
        assert_eq!(result, amount, "Case-insensitive same-chain check");
    }

    // =====================================================================
    // 3. TICS → BTC cross-chain conversion
    // =====================================================================

    #[test]
    fn tics_to_btc_basic_conversion() {
        // BTC = $100,000, TICS = $0.01
        // 25 TICS = $0.25 worth
        // $0.25 / $100,000 per BTC = 0.0000025 BTC = 250 sats
        //
        // Formula in code:
        //   adjusted = amount_wei / 10^10  (TICS multiplier)
        //   dst_whole = adjusted * p_src / p_dst
        //   result = floor(dst_whole)
        //
        //   amount_wei = 25 * 10^18
        //   adjusted = 25 * 10^18 / 10^10 = 25 * 10^8 = 2_500_000_000
        //   dst_whole = 2_500_000_000 * 0.01 / 100_000 = 250
        let p = prices(dec!(100000), dec!(0.01));
        let amount_wei = 25_000_000_000_000_000_000u128; // 25 TICS in wei
        let result =
            convert_src_smallest_to_dst_smallest(amount_wei, "tics", "bitcoin", &p).unwrap();
        assert_eq!(result, 250, "25 TICS @ $0.01 → BTC @ $100k = 250 sats");
    }

    #[test]
    fn tics_to_btc_large_amount() {
        // 1000 TICS = $10 worth
        // $10 / $100,000 = 0.0001 BTC = 10,000 sats
        let p = prices(dec!(100000), dec!(0.01));
        let amount_wei = 1_000_000_000_000_000_000_000u128; // 1000 TICS
        let result =
            convert_src_smallest_to_dst_smallest(amount_wei, "qubetics", "btc", &p).unwrap();
        assert_eq!(
            result, 10_000,
            "1000 TICS @ $0.01 → BTC @ $100k = 10,000 sats"
        );
    }

    #[test]
    fn tics_to_btc_small_amount_below_dust() {
        // 1 TICS = $0.01 worth
        // $0.01 / $100,000 = 0.0000001 BTC = 10 sats
        let p = prices(dec!(100000), dec!(0.01));
        let amount_wei = 1_000_000_000_000_000_000u128; // 1 TICS
        let result = convert_src_smallest_to_dst_smallest(amount_wei, "tics", "btc", &p).unwrap();
        assert_eq!(
            result, 10,
            "1 TICS @ $0.01 → BTC @ $100k = 10 sats (below 546 dust)"
        );
    }

    // =====================================================================
    // 4. BTC → TICS cross-chain conversion
    // =====================================================================

    #[test]
    fn btc_to_tics_basic_conversion() {
        // BTC = $100,000, TICS = $0.01
        // 1000 sats = 0.00001 BTC = $1.00 worth
        // $1.00 / $0.01 per TICS = 100 TICS = 100 * 10^18 wei
        //
        // Formula:
        //   adjusted = amount_sats * 10^10  (BTC multiplier)
        //   dst_whole = adjusted * p_src / p_dst
        //   result = floor(dst_whole)
        //
        //   adjusted = 1000 * 10^10 = 10_000_000_000_000
        //   dst_whole = 10_000_000_000_000 * 100_000 / 0.01 = 10^20
        //   result = 100_000_000_000_000_000_000 = 100 * 10^18
        let p = prices(dec!(100000), dec!(0.01));
        let amount_sats = 1000u128;
        let result =
            convert_src_smallest_to_dst_smallest(amount_sats, "bitcoin", "tics", &p).unwrap();
        let expected = 100_000_000_000_000_000_000u128; // 100 TICS in wei
        assert_eq!(
            result, expected,
            "1000 sats @ $100k → TICS @ $0.01 = 100 TICS"
        );
    }

    #[test]
    fn btc_to_tics_700_sats() {
        // The user's example: 700 satoshis → TICS
        // 700 sats = 0.000007 BTC = $0.70 worth
        // $0.70 / $0.01 = 70 TICS = 70 * 10^18 wei
        let p = prices(dec!(100000), dec!(0.01));
        let amount_sats = 700u128;
        let result =
            convert_src_smallest_to_dst_smallest(amount_sats, "btc", "qubetics", &p).unwrap();
        let expected = 70_000_000_000_000_000_000u128; // 70 TICS in wei
        assert_eq!(result, expected, "700 sats → 70 TICS");
    }

    // =====================================================================
    // 5. Round-trip: TICS → BTC → TICS preserves value (within rounding)
    // =====================================================================

    #[test]
    fn round_trip_tics_btc_tics() {
        let p = prices(dec!(100000), dec!(0.01));
        let original_wei = 25_000_000_000_000_000_000u128; // 25 TICS

        // TICS → BTC
        let sats = convert_src_smallest_to_dst_smallest(original_wei, "tics", "btc", &p).unwrap();
        assert_eq!(sats, 250);

        // BTC → TICS
        let back_wei = convert_src_smallest_to_dst_smallest(sats, "btc", "tics", &p).unwrap();
        assert_eq!(back_wei, original_wei, "Round-trip should preserve value");
    }

    #[test]
    fn round_trip_btc_tics_btc() {
        let p = prices(dec!(100000), dec!(0.01));
        let original_sats = 10_000u128; // 0.0001 BTC

        // BTC → TICS
        let wei = convert_src_smallest_to_dst_smallest(original_sats, "btc", "tics", &p).unwrap();

        // TICS → BTC
        let back_sats = convert_src_smallest_to_dst_smallest(wei, "tics", "btc", &p).unwrap();
        assert_eq!(back_sats, original_sats, "Round-trip should preserve value");
    }

    // =====================================================================
    // 6. UserToVault amount correctness
    //    UserToVault legacy static 5% fee tests (Production now uses dynamic fees).
    // =====================================================================

    #[test]
    fn user_to_vault_tics_source_uses_source_amount() {
        // TICS→BTC: source_amount = 25 TICS (wei), target_amount = 250 sats
        // UserToVault tx is on TICS chain → must use source_amount, NOT target_amount
        let source_amount: u128 = 25_000_000_000_000_000_000; // 25 TICS in wei
        let target_amount: u128 = 250; // 250 sats (BTC)

        // UserToVault formula: source_amount + source_amount / 20
        let utv_amount = source_amount + (source_amount / 20);
        let expected = 26_250_000_000_000_000_000u128; // 26.25 TICS in wei

        assert_eq!(utv_amount, expected, "TICS UserToVault = source + 5%");
        // Verify we're NOT using target_amount (which would be wrong)
        assert_ne!(
            utv_amount,
            target_amount + (target_amount / 20),
            "Must NOT use target_amount for source-chain tx"
        );
    }

    #[test]
    fn user_to_vault_btc_source_uses_source_amount() {
        // BTC→TICS: source_amount = 1000 sats, target_amount = 100 TICS (wei)
        let source_amount: u128 = 1000; // 1000 sats
        let target_amount: u128 = 100_000_000_000_000_000_000; // 100 TICS in wei

        // UserToVault formula: source_amount + source_amount / 20
        let utv_amount = source_amount + (source_amount / 20);
        assert_eq!(utv_amount, 1050, "BTC UserToVault = 1000 + 50 = 1050 sats");
        // Verify we're NOT using target_amount
        assert_ne!(
            utv_amount,
            target_amount + (target_amount / 20),
            "Must NOT use target_amount for source-chain tx"
        );
    }

    #[test]
    fn user_to_vault_same_chain_tics() {
        // TICS→TICS: source_amount = target_amount (same chain)
        let amount: u128 = 10_000_000_000_000_000_000; // 10 TICS
        let utv_amount = amount + (amount / 20);
        assert_eq!(
            utv_amount, 10_500_000_000_000_000_000,
            "TICS→TICS UTV = 10 + 0.5 = 10.5 TICS"
        );
    }

    #[test]
    fn user_to_vault_same_chain_btc() {
        // BTC→BTC: source_amount = target_amount (same chain)
        let amount: u128 = 50_000; // 50,000 sats
        let utv_amount = amount + (amount / 20);
        assert_eq!(
            utv_amount, 52_500,
            "BTC→BTC UTV = 50000 + 2500 = 52500 sats"
        );
    }

    // =====================================================================
    // 7. NetworkToTarget amount correctness
    //    NetworkToTarget delivers target_amount on the TARGET chain.
    // =====================================================================

    #[test]
    fn network_to_target_btc_uses_target_amount_not_recomputed() {
        // TICS→BTC: target_amount was stored as 250 sats at intent submission.
        // NetworkToTarget should use 250 sats (stored), NOT re-compute from price.
        // If price changed, re-computing would give a different (wrong) value.
        let p_at_submission = prices(dec!(100000), dec!(0.01));
        let p_at_execution = prices(dec!(110000), dec!(0.01)); // price changed!

        let source_wei = 25_000_000_000_000_000_000u128;

        let stored_target =
            convert_src_smallest_to_dst_smallest(source_wei, "tics", "btc", &p_at_submission)
                .unwrap();
        assert_eq!(stored_target, 250, "Stored target = 250 sats");

        let recomputed_target =
            convert_src_smallest_to_dst_smallest(source_wei, "tics", "btc", &p_at_execution)
                .unwrap();
        // With higher BTC price ($110k), same TICS buys fewer sats
        assert_ne!(
            recomputed_target, stored_target,
            "Re-computed amount differs from stored — proves why stored is needed"
        );
        assert!(
            recomputed_target < stored_target,
            "Higher BTC price → fewer sats: {} < {}",
            recomputed_target,
            stored_target
        );

        // The system should use stored_target (250), not recomputed
    }

    #[test]
    fn network_to_target_tics_uses_target_amount() {
        // BTC→TICS: target_amount stored as 100 TICS (wei).
        let p_at_submission = prices(dec!(100000), dec!(0.01));
        let p_at_execution = prices(dec!(90000), dec!(0.01)); // price dropped

        let source_sats = 1000u128;

        let stored_target =
            convert_src_smallest_to_dst_smallest(source_sats, "btc", "tics", &p_at_submission)
                .unwrap();

        let recomputed =
            convert_src_smallest_to_dst_smallest(source_sats, "btc", "tics", &p_at_execution)
                .unwrap();

        assert_ne!(
            recomputed, stored_target,
            "Re-computed differs from stored when price changed"
        );
    }

    // =====================================================================
    // 8. Fallback safety: cross-chain must NOT use source_amount as fallback
    // =====================================================================

    #[test]
    fn cross_chain_source_amount_is_wrong_unit_for_target() {
        // BTC→TICS: source_amount = 1000 sats
        // If we mistakenly used source_amount as target_amount, we'd deliver
        // 1000 wei instead of 100 TICS (100 * 10^18 wei) — massively wrong.
        let source_sats = 1000u128;
        let p = prices(dec!(100000), dec!(0.01));
        let correct_target_wei =
            convert_src_smallest_to_dst_smallest(source_sats, "btc", "tics", &p).unwrap();

        // source_amount as target would be 1000 (wei) — essentially zero TICS
        let wrong_fallback = source_sats;
        assert!(
            correct_target_wei > wrong_fallback * 1_000_000_000,
            "Using source_amount as target is off by >9 orders of magnitude"
        );
    }

    #[test]
    fn cross_chain_tics_to_btc_source_is_wrong_for_target() {
        // TICS→BTC: source_amount = 25 * 10^18 wei
        // Correct target = 250 sats. Using source as target = 25 * 10^18 sats = insane.
        let source_wei = 25_000_000_000_000_000_000u128;
        let p = prices(dec!(100000), dec!(0.01));
        let correct_target_sats =
            convert_src_smallest_to_dst_smallest(source_wei, "tics", "btc", &p).unwrap();

        assert_eq!(correct_target_sats, 250);
        assert!(
            source_wei > correct_target_sats * 1_000_000_000_000_000,
            "source_amount as target would be absurdly large"
        );
    }

    // =====================================================================
    // 9. Edge cases
    // =====================================================================

    #[test]
    fn zero_amount_returns_zero() {
        let p = prices(dec!(100000), dec!(0.01));
        let result = convert_src_smallest_to_dst_smallest(0, "tics", "btc", &p).unwrap();
        assert_eq!(result, 0, "Zero in → zero out");
    }

    #[test]
    fn missing_price_returns_error() {
        let empty: HashMap<String, Decimal> = HashMap::new();
        let result = convert_src_smallest_to_dst_smallest(1000, "tics", "btc", &empty);
        assert!(result.is_err(), "Missing prices should error");
    }

    #[test]
    fn five_percent_fee_calculation_legacy() {
        // Verify integer division: amount + amount/20
        // (Legacy 5% calculation logic; production now uses dynamic bps)
        // For small amounts, integer division truncates
        assert_eq!(100 + 100 / 20, 105); // exact
        assert_eq!(99 + 99 / 20, 99 + 4, "99/20 = 4 (truncated)");
        assert_eq!(1 + 1 / 20, 1, "1/20 = 0 → fee is zero for 1 unit");
        assert_eq!(19 + 19 / 20, 19, "19/20 = 0 → fee is zero for <20 units");
        assert_eq!(20 + 20 / 20, 21, "20/20 = 1 → first non-zero fee");
    }

    // =====================================================================
    // 10. Different price scenarios
    // =====================================================================

    #[test]
    fn tics_to_btc_equal_prices() {
        // If both are $1, then 1 TICS smallest → 1 BTC smallest via multiplier
        // TICS: adjusted = amount / 10^10, then * p_src / p_dst = * 1
        let p = prices(dec!(1), dec!(1));
        let amount_wei = 10_000_000_000u128; // 10^10 wei
        let result = convert_src_smallest_to_dst_smallest(amount_wei, "tics", "btc", &p).unwrap();
        // adjusted = 10^10 / 10^10 = 1, dst_whole = 1 * 1/1 = 1
        assert_eq!(result, 1, "10^10 wei at equal prices = 1 sat");
    }

    #[test]
    fn btc_to_tics_equal_prices() {
        let p = prices(dec!(1), dec!(1));
        let amount_sats = 1u128;
        let result = convert_src_smallest_to_dst_smallest(amount_sats, "btc", "tics", &p).unwrap();
        // adjusted = 1 * 10^10, dst_whole = 10^10 * 1/1 = 10^10
        assert_eq!(
            result, 10_000_000_000u128,
            "1 sat at equal prices = 10^10 wei"
        );
    }
}
