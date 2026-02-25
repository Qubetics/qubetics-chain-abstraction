//! Secure threshold ECDSA signing using cggmp21.
//!
//! The nonce `k` is never revealed in plain text. cggmp21 handles the Paillier
//! MtA exchange internally during its 3-round signing protocol.

use anyhow::{anyhow, Result};
use cggmp21::{supported_curves::Secp256k1, DataToSign, ExecutionId, KeyShare};
use rand::rngs::OsRng;
use tracing::info;

use crate::signing::mpc_net::MpcSession;

/// Run the threshold signing protocol for a single message hash.
///
/// * `key_share`              — completed `cggmp21::KeyShare` (from DB)
/// * `local_signing_index`    — this signer's 0-based index within the signing set
/// * `participants_at_keygen` — maps signing-index to keygen-index for each participant
/// * `message_hash`           — 32-byte pre-hash (must already be SHA-256 or Keccak256)
/// * `session`                — gossipsub-connected `MpcSession` keyed to this tx_id
/// * `tx_id`                  — unique identifier; used as the `ExecutionId`
///
/// Returns a 64-byte compact secp256k1 ECDSA signature `(r || s)`.
pub async fn run_signing(
    key_share: &KeyShare<Secp256k1>,
    local_signing_index: u16,
    participants_at_keygen: &[u16],
    message_hash: [u8; 32],
    session: MpcSession,
    tx_id: &str,
) -> Result<Vec<u8>> {
    info!(
        "🔏 [MPC-SIGN] Starting threshold signing for tx {} (signer {}/{})",
        tx_id,
        local_signing_index,
        participants_at_keygen.len() - 1
    );

    let eid = ExecutionId::new(tx_id.as_bytes());

    // Let the compiler infer the Msg type from the `signing()` call below.
    let (incoming, outgoing) = session.into_network(|_to, _bytes| {});
    let party = round_based::MpcParty::connected((incoming, outgoing));

    // Build DataToSign from the pre-computed 32-byte hash.
    // We hash the already-hashed bytes once more to produce the Scalar value;
    // this matches a SHA-256(SHA-256(tx)) double-hash, which is standard for Bitcoin.
    // For Ethereum (Keccak256), the contract verifies the raw hash, so pass it directly.
    let data_to_sign = DataToSign::digest::<sha2::Sha256>(&message_hash);

    let signature = cggmp21::signing(eid, local_signing_index, participants_at_keygen, key_share)
        .sign(&mut OsRng, party, data_to_sign)
        .await
        .map_err(|e| anyhow!("cggmp21 signing failed: {:?}", e))?;

    // Serialise to 64-byte compact `(r || s)`.
    let r_bytes = signature.r.to_bytes();
    let s_bytes = signature.s.to_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);

    info!("✅ [MPC-SIGN] Threshold signature ready for tx {}", tx_id);
    Ok(out)
}
