//! Secure DKG Key Generation using cggmp21.
//!
//! # Protocol flow
//! 1. `run_aux_info_gen` — one-time Paillier key setup per signer group  
//! 2. `run_keygen`       — 3-signer t-of-n DKG; returns `IncompleteKeyShare`
//!
//! Observer nodes call neither and only receive the broadcasted group public key.

use anyhow::{anyhow, Result};
use cggmp21::{
    security_level::SecurityLevel128, supported_curves::Secp256k1, ExecutionId, IncompleteKeyShare,
    PregeneratedPrimes,
};
use futures::channel::mpsc as futures_mpsc;
use rand::rngs::OsRng;
use tracing::info;

use crate::signing::mpc_net::MpcSession;

/// Number of core DKG signers.
pub const DKG_N: u16 = 3;
/// Signing threshold.
pub const DKG_T: u16 = 2;

/// One-time auxiliary info generation (Paillier primes + ZK proofs).
///
/// Computationally heavy — run once and cache the result in the DB.
pub async fn run_aux_info_gen(
    i: u16,
    session: MpcSession,
) -> Result<cggmp21::key_share::AuxInfo<SecurityLevel128>> {
    info!(
        "🔐 [MPC-KEYGEN] Starting aux_info_gen for signer {}/{}",
        i,
        DKG_N - 1
    );

    let primes = PregeneratedPrimes::generate(&mut OsRng);
    info!("🔐 [MPC-KEYGEN] Paillier primes ready for signer {}", i);

    let eid = ExecutionId::new(b"qubetics-aux-info-v1");

    // Let the compiler infer the Msg type from the aux_info_gen call below.
    let (incoming, outgoing) = session.into_network(|_to, _bytes| {
        // send_fn: routing is wired up by the gossipsub coordinator
    });
    let party = round_based::MpcParty::connected((incoming, outgoing));

    let aux_info = cggmp21::aux_info_gen::<SecurityLevel128>(eid, i, DKG_N, primes)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| anyhow!("aux_info_gen failed: {:?}", e))?;

    info!("✅ [MPC-KEYGEN] aux_info_gen complete for signer {}", i);
    Ok(aux_info)
}

/// 3-signer distributed key generation.
///
/// Returns the `IncompleteKeyShare` to store in the DB.
pub async fn run_keygen(i: u16, session: MpcSession) -> Result<IncompleteKeyShare<Secp256k1>> {
    info!(
        "🔐 [MPC-KEYGEN] Starting keygen for signer {}/{} (threshold {}-of-{})",
        i,
        DKG_N - 1,
        DKG_T,
        DKG_N
    );

    let eid = ExecutionId::new(b"qubetics-keygen-v1");

    let (incoming, outgoing) = session.into_network(|_to, _bytes| {});
    let party = round_based::MpcParty::connected((incoming, outgoing));

    let share = cggmp21::keygen::<Secp256k1>(eid, i, DKG_N)
        .set_threshold(DKG_T)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| anyhow!("keygen failed: {:?}", e))?;

    info!("✅ [MPC-KEYGEN] keygen complete for signer {}", i);
    Ok(share)
}
