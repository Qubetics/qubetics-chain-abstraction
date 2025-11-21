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
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::{database::DkgStorage, user_intent_manager::UserIntentManager};

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

pub async fn fetch_crypto_prices() -> Result<HashMap<String, Decimal>, String> {
    let base_url =
        std::env::var("BACKEND_API_URL").unwrap_or_else(|_| "http://172.16.15.63:7322".to_string());
    let url = format!("{}/api/v1/cryptos/prices?symbols=BTC,TICS", base_url);
    let client = Client::new();

    info!("Fetching crypto prices from URL: {}", url);

    let resp = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch crypto prices: {}", e);
        format!("Failed to fetch crypto prices: {}", e)
    })?;

    let status = resp.status();
    debug!("Crypto prices API response status: {}", status);

    let resp_text = resp.text().await.map_err(|e| {
        error!("Failed to read crypto prices response text: {}", e);
        format!("Failed to read crypto prices response text: {}", e)
    })?;

    debug!("Crypto prices API response body: {}", resp_text);

    if !status.is_success() {
        error!(
            "Crypto prices API returned non-success status {}: {}",
            status, resp_text
        );
        return Err(format!(
            "Crypto prices API returned non-success status {}: {}",
            status, resp_text
        ));
    }

    let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
        error!("Failed to parse crypto prices response: {}", e);
        format!("Failed to parse crypto prices response: {}", e)
    })?;

    debug!("Crypto prices API response JSON: {:?}", resp_json);

    if resp_json.get("error").and_then(|v| v.as_bool()) == Some(true) {
        let msg = resp_json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        error!("Crypto prices API error: {}", msg);
        return Err(format!("Crypto prices API error: {}", msg));
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

pub(crate) async fn get_transaction_id_for_intent(
    user_intent_manager: &UserIntentManager,
    intent_hash: &[u8],
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let intent_hash_hex = hex::encode(intent_hash);

    // Fetch any recorded transaction IDs for this intent hash
    if let Some(tx_ids) = user_intent_manager
        .get_intent_transaction_ids(&intent_hash_hex)
        .await
    {
        // Check each candidate transaction id individually
        let mut user_to_network_tx_id = None;
        if let Some(ref tx_id) = tx_ids.user_to_network_tx_id {
            if user_intent_manager
                .get_transaction_status(tx_id)
                .await
                .is_some()
            {
                user_to_network_tx_id = Some(tx_id.clone());
            }
        }

        let mut network_to_target_tx_id = None;
        if let Some(ref tx_id) = tx_ids.network_to_target_tx_id {
            if user_intent_manager
                .get_transaction_status(tx_id)
                .await
                .is_some()
            {
                network_to_target_tx_id = Some(tx_id.clone());
            }
        }

        let mut vault_to_network_tx_id = None;
        if let Some(ref tx_id) = tx_ids.vault_to_network_tx_id {
            if user_intent_manager
                .get_transaction_status(tx_id)
                .await
                .is_some()
            {
                vault_to_network_tx_id = Some(tx_id.clone());
            }
        }
        let final_solver_id = tx_ids.final_solver_id.clone();
        return (
            user_to_network_tx_id,
            network_to_target_tx_id,
            vault_to_network_tx_id,
            final_solver_id,
        );
    }

    (None, None, None, None)
}

/// Wait for a transaction ID or chain error associated with the given intent hash.
/// Polls the database frequently to return as soon as possible and times out
/// after the provided number of seconds. Tries to get all transaction IDs when possible,
/// but returns with whatever is available after the timeout.
pub(crate) async fn wait_for_transaction_result(
    user_intent_manager: &UserIntentManager,
    intent_hash: &[u8],
    timeout_secs: u64,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let start = Instant::now();
    let intent_hash_hex = hex::encode(intent_hash);
    let poll_interval = Duration::from_millis(250);
    let timeout = Duration::from_secs(timeout_secs);

    // Give a bit more time to potentially get all transaction IDs
    let extended_timeout = timeout + Duration::from_secs(2);
    let mut best_result = (None, None, None, None, None);

    loop {
        // Check for transaction ids
        let (u2n_tx, n2t_tx, v2n_tx, final_solver) =
            get_transaction_id_for_intent(user_intent_manager, intent_hash).await;

        // Update our best result if we have new information
        if u2n_tx.is_some() || n2t_tx.is_some() || v2n_tx.is_some() {
            best_result = (u2n_tx, n2t_tx, v2n_tx, final_solver, None);
            // If we have all transaction IDs, return immediately
            if best_result.0.is_some() && best_result.1.is_some() && best_result.2.is_some() {
                return best_result;
            }

            // If we have at least one, continue polling for a bit longer to see if we can get the others
            // But don't wait too long - return after the original timeout if we have at least one
            if start.elapsed() >= timeout {
                return best_result;
            }
        }

        // Check for any recorded chain error
        if let Some(tx_ids) = user_intent_manager
            .get_intent_transaction_ids(&intent_hash_hex)
            .await
        {
            if let Some(error_msg) = tx_ids.error_message {
                return (
                    None,
                    None,
                    None,
                    tx_ids.final_solver_id.clone(),
                    Some(error_msg),
                );
            }
        }

        // If we've exceeded the extended timeout, return whatever we have
        if start.elapsed() >= extended_timeout {
            break;
        }

        tokio::time::sleep(poll_interval).await;
    }

    // Return the best result we found, or None if we found nothing
    best_result
}

/// Wait for reward transaction IDs (BTC/TICS) associated with a solver.
/// Compares against previously observed IDs to ensure we only return new values.
pub(crate) async fn wait_for_reward_transaction_ids(
    user_intent_manager: &UserIntentManager,
    solver_address: &str,
    expect_tics: bool,
    expect_btc: bool,
    previous_tics_tx_id: Option<String>,
    previous_btc_tx_id: Option<String>,
    timeout_secs: u64,
) -> (Option<String>, Option<String>) {
    if !expect_tics && !expect_btc {
        return (None, None);
    }

    let start = Instant::now();
    let poll_interval = Duration::from_millis(250);
    let timeout = Duration::from_secs(timeout_secs);

    let mut latest_tics_tx = None;
    let mut latest_btc_tx = None;

    loop {
        if expect_tics && latest_tics_tx.is_none() {
            if let Some(current) = user_intent_manager
                .get_solver_tics_txn_hash(solver_address)
                .await
            {
                if previous_tics_tx_id.as_ref() != Some(&current) {
                    latest_tics_tx = Some(current);
                }
            }
        }

        if expect_btc && latest_btc_tx.is_none() {
            if let Some(current) = user_intent_manager
                .get_solver_btc_txn_hash(solver_address)
                .await
            {
                if previous_btc_tx_id.as_ref() != Some(&current) {
                    latest_btc_tx = Some(current);
                }
            }
        }

        if (!expect_tics || latest_tics_tx.is_some()) && (!expect_btc || latest_btc_tx.is_some()) {
            break;
        }

        if start.elapsed() >= timeout {
            break;
        }

        tokio::time::sleep(poll_interval).await;
    }

    (latest_tics_tx, latest_btc_tx)
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
