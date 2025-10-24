use rust_decimal::{
	prelude::{FromPrimitive, ToPrimitive},
	Decimal,
};
use rust_decimal_macros::dec;
use std::collections::HashMap;
use tracing::{info, warn};

use crate::{
	rpc_server::types::errors::{RpcError, TransactionError},
	user_registry::{checksum_from_any, to_checksum_address},
	DatabaseUserRegistry, DkgStorage,
};
use secp256k1::{
	ecdsa::{RecoverableSignature, RecoveryId},
	Message, PublicKey, Secp256k1,
};
use sha2::Digest;
use sha3::Keccak256;

fn symbol_for(chain: &str) -> &'static str {
	match chain.to_lowercase().as_str() {
		"btc" | "bitcoin" => "BTC",
		_ => "TICS",
	}
}

fn decimals_for(chain: &str) -> u32 {
	match chain.to_lowercase().as_str() {
		"btc" | "bitcoin" => 8,    // satoshis
		"tics" | "qubetics" => 18, // wei-like
		_ => 18,
	}
}

fn pow10_dec(n: u32) -> Decimal {
	// 10^n as Decimal without float errors
	let mut v = dec!(1);
	for _ in 0..n {
		v *= dec!(10);
	}
	v
}

/// Convert source smallest units -> target smallest units using token prices (per whole units)
pub fn convert_src_smallest_to_dst_smallest(
	amount_src_smallest: u128,
	src_chain: &str,
	dst_chain: &str,
	prices: &HashMap<String, Decimal>,
) -> Result<u128, TransactionError> {
	let src_sym = symbol_for(src_chain);
	let dst_sym = symbol_for(dst_chain);

	let p_src = *prices.get(src_sym).ok_or(TransactionError::PricingUnavailable)?;
	let p_dst = *prices.get(dst_sym).ok_or(TransactionError::PricingUnavailable)?;

	let src_dec = decimals_for(src_chain);
	let dst_dec = decimals_for(dst_chain);

	info!("🔄 [CONVERSION] Starting conversion:");
	info!("  📊 Source: {} {} (smallest units: {})", amount_src_smallest, src_sym, src_chain);
	info!("  📊 Target: {} (smallest units: {})", dst_sym, dst_chain);
	info!("  💰 Prices: {} = ${}, {} = ${}", src_sym, p_src, dst_sym, p_dst);
	info!("  🔢 Decimals: {} = {}, {} = {}", src_sym, src_dec, dst_sym, dst_dec);

	// Apply chain-specific multiplier before price conversion
	let adjusted_amount = match src_chain.to_lowercase().as_str() {
		"tics" | "qubetics" => {
			// For TICS source chain: divide by 10^10
			let divisor = pow10_dec(10);
			let result = Decimal::from_u128(amount_src_smallest)
				.ok_or(TransactionError::Overflow)? /
				divisor;
			info!("  🔄 TICS conversion: {} / 10^10 = {}", amount_src_smallest, result);
			result
		},
		"btc" | "bitcoin" => {
			// For BTC source chain: multiply by 10^10
			let multiplier = pow10_dec(10);
			let result = Decimal::from_u128(amount_src_smallest)
				.ok_or(TransactionError::Overflow)? *
				multiplier;
			info!("  🔄 BTC conversion: {} * 10^10 = {}", amount_src_smallest, result);
			result
		},
		_ => {
			// For other chains: no multiplier
			let result =
				Decimal::from_u128(amount_src_smallest).ok_or(TransactionError::Overflow)?;
			info!("  🔄 Other chain conversion: {} (no multiplier)", amount_src_smallest);
			result
		},
	};

	// Convert to whole units using actual decimals
	let src_whole = adjusted_amount;
	info!("  📏 Converted to whole units: {} / 10^{} = {}", adjusted_amount, src_dec, src_whole);

	// Apply price conversion
	let dst_whole = src_whole * p_src / p_dst;
	info!("  💱 Price conversion: {} * {} / {} = {}", src_whole, p_src, p_dst, dst_whole);

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

// Input validation helper
pub fn validate_ethereum_address(address: &str) -> Result<String, RpcError> {
	if address.trim().is_empty() {
		return Err(RpcError::InvalidAddress("Address cannot be empty".to_string()));
	}

	if !address.starts_with("0x") && address.len() != 42 {
		return Err(RpcError::InvalidAddress(
			"Address must be 42 characters and start with 0x".to_string(),
		));
	}

	match checksum_from_any(address) {
		Ok(normalized) => Ok(normalized),
		Err(e) => Err(RpcError::InvalidAddress(format!("Invalid address format: {}", e))),
	}
}

// Helper function to get the actual DKG secret share from shared state
pub async fn get_actual_dkg_secret_share(
	dkg_storage: std::sync::Arc<DkgStorage>,
) -> Option<k256::Scalar> {
	match dkg_storage.get_final_secret().await {
		Ok(Some(secret)) => Some(secret),
		Ok(None) => {
			warn!("DKG is not completed yet, cannot retrieve secret share");
			None
		},
		Err(e) => {
			warn!("Failed to retrieve DKG secret share: {}", e);
			None
		},
	}
}

pub fn normalize_eth_signature(sig_hex: &str) -> anyhow::Result<([u8; 64], u8)> {
	let s = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
	let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode signature: {}", e))?;
	if bytes.len() != 65 {
		return Err(anyhow::anyhow!("signature must be 65 bytes r||s||v, got {}", bytes.len()));
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
	Ok(to_checksum_address(&addr20))
}

/// Wait for a transaction ID or chain error associated with the given intent hash.
/// Polls the database frequently to return as soon as possible and times out
/// after the provided number of seconds. Tries to get all transaction IDs when possible,
/// but returns with whatever is available after the timeout.
pub async fn wait_for_transaction_result(
	user_registry: &DatabaseUserRegistry,
	intent_hash: &[u8],
	timeout_secs: u64,
) -> (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) {
	let start = std::time::Instant::now();
	let intent_hash_hex = hex::encode(intent_hash);
	let poll_interval = tokio::time::Duration::from_millis(250);
	let timeout = tokio::time::Duration::from_secs(timeout_secs);

	// Give a bit more time to potentially get all transaction IDs
	let extended_timeout = timeout + tokio::time::Duration::from_secs(2);
	let mut best_result = (None, None, None, None, None);

	loop {
		// Check for transaction ids
		let (u2n_tx, n2t_tx, v2n_tx, final_solver) =
			get_transaction_id_for_intent(user_registry, intent_hash).await;

		// Update our best result if we have new information
		if u2n_tx.is_some() || n2t_tx.is_some() || v2n_tx.is_some() {
			best_result = (u2n_tx, n2t_tx, v2n_tx, final_solver, None);
			// If we have all transaction IDs, return immediately
			if best_result.0.is_some() && best_result.1.is_some() && best_result.2.is_some() {
				return best_result;
			}

			// If we have at least one, continue polling for a bit longer to see if we can get the
			// others But don't wait too long - return after the original timeout if we have at
			// least one
			if start.elapsed() >= timeout {
				return best_result;
			}
		}

		// Check for any recorded chain error
		if let Some(tx_ids) = user_registry.get_intent_transaction_ids(&intent_hash_hex).await {
			if let Some(error_msg) = tx_ids.error_message {
				return (None, None, None, tx_ids.final_solver_id.clone(), Some(error_msg));
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

// Helper function to get transaction ID from intent hash
pub async fn get_transaction_id_for_intent(
	user_registry: &DatabaseUserRegistry,
	intent_hash: &[u8],
) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
	let intent_hash_hex = hex::encode(intent_hash);

	// Fetch any recorded transaction IDs for this intent hash
	if let Some(tx_ids) = user_registry.get_intent_transaction_ids(&intent_hash_hex).await {
		// Check each candidate transaction id individually
		let mut user_to_network_tx_id = None;
		if let Some(ref tx_id) = tx_ids.user_to_network_tx_id {
			if user_registry.get_transaction_status(tx_id).await.is_some() {
				user_to_network_tx_id = Some(tx_id.clone());
			}
		}

		let mut network_to_target_tx_id = None;
		if let Some(ref tx_id) = tx_ids.network_to_target_tx_id {
			if user_registry.get_transaction_status(tx_id).await.is_some() {
				network_to_target_tx_id = Some(tx_id.clone());
			}
		}

		let mut vault_to_network_tx_id = None;
		if let Some(ref tx_id) = tx_ids.vault_to_network_tx_id {
			if user_registry.get_transaction_status(tx_id).await.is_some() {
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
