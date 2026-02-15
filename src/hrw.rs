//! HRW (Highest Random Weight / Rendezvous hashing) for deterministic final-node selection.
//!
//! All nodes compute the same function over (domain, round, candidate set) and get the same winner.
//! Candidate set must be canonical (e.g. from DKG storage) and sorted by PeerId bytes.

use anyhow::Result;
use blake3::Hasher;
use libp2p::PeerId;
use std::str::FromStr;
use tracing::debug;

/// Domain tag for HRW to avoid collisions across use cases (e.g. signing vs vrf-sync).
pub const HRW_DOMAIN_FINAL_NODE: &str = "mpc-final-node-v1";

/// Select the single final node using HRW.
///
/// - `round`: canonical round (same on all nodes).
/// - `candidates`: canonical sorted list (e.g. from [`crate::hrw::candidates::get_hrw_candidates`]).
/// - `domain`: domain separator (e.g. [`HRW_DOMAIN_FINAL_NODE`]).
///
/// Returns `None` if `candidates` is empty.
pub fn select_final(round: u64, candidates: &[PeerId], domain: &str) -> Option<PeerId> {
    if candidates.is_empty() {
        return None;
    }

    let mut best_peer: Option<PeerId> = None;
    let mut best_score: Option<[u8; 32]> = None;

    for p in candidates {
        let score = {
            let mut h = Hasher::new();
            h.update(domain.as_bytes());
            h.update(&round.to_be_bytes());
            h.update(p.to_bytes().as_slice());
            *h.finalize().as_bytes()
        };

        let wins = match &best_score {
            None => true,
            Some(s) => match score.cmp(s) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => p.to_bytes().as_slice() < best_peer.unwrap().to_bytes().as_slice(),
            },
        };

        if wins {
            best_score = Some(score);
            best_peer = Some(*p);
        }
    }

    debug!(
        "HRW select_final domain={} round={} candidates={} winner={:?}",
        domain,
        round,
        candidates.len(),
        best_peer.map(|p| p.to_string())
    );
    best_peer
}

/// HRW candidate set: read from peer_id→index storage, sort in a separate list only.
///
/// - Does **not** sort or modify the existing peer_id→index storage (DKG DB or
///   [`crate::network::discovery::types::PeerDiscoveryState::peer_indices`]).
/// - Only **reads** from DKG storage; the sorted order is applied to a separate
///   in-memory list used solely for HRW selection.
pub mod candidates {
    use super::*;
    use crate::database::DkgStorage;

    /// Get canonical HRW candidates from DKG storage (read-only).
    ///
    /// Includes ALL connected peers (DKG participants + observers).
    /// Observer nodes can be selected as final node for aggregation and broadcast;
    /// they skip individual signing but still aggregate partial signatures from DKG nodes.
    /// Builds a **separate** list of peer IDs sorted by PeerId bytes for deterministic HRW.
    /// The underlying storage and any peer_indices mapping are never modified or sorted.
    /// Invalid peer ID strings are skipped (and logged).
    pub fn get_hrw_candidates(dkg: &DkgStorage) -> Result<Vec<PeerId>> {
        // Read-only: get_all_peer_indices does not modify storage.
        let indices = dkg.get_all_peer_indices()?;

        let mut peer_ids: Vec<PeerId> = Vec::new();
        for (s, _idx) in &indices {
            match PeerId::from_str(s) {
                Ok(pid) => peer_ids.push(pid),
                Err(e) => tracing::warn!(
                    "HRW candidates: skip invalid peer_id {:?}: {}",
                    s, e
                ),
            }
        }
        // Sort only our local list; never write back to or sort the peer_id→index storage.
        peer_ids.sort_by(|a, b| a.to_bytes().as_slice().cmp(b.to_bytes().as_slice()));
        tracing::info!(
            "🎯 [HRW] Candidates: {} peers (all eligible for final node selection)",
            peer_ids.len()
        );
        Ok(peer_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        let kp = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut bytes)
            .unwrap_or_else(|_| libp2p::identity::ed25519::Keypair::generate());
        PeerId::from_public_key(&libp2p::identity::Keypair::from(kp).public())
    }

    #[test]
    fn hrw_empty_candidates_returns_none() {
        assert!(select_final(1, &[], "test").is_none());
    }

    #[test]
    fn hrw_single_candidate_returns_it() {
        let p = peer_id_from_byte(1);
        let out = select_final(1, &[p], "test");
        assert_eq!(out, Some(p));
    }

    #[test]
    fn hrw_deterministic_same_input_same_winner() {
        let a = peer_id_from_byte(1);
        let b = peer_id_from_byte(2);
        let c = peer_id_from_byte(3);
        let candidates = [a, b, c];
        let r1 = select_final(42, &candidates, "d");
        let r2 = select_final(42, &candidates, "d");
        assert_eq!(r1, r2);
    }

    #[test]
    fn hrw_different_round_different_winner_possible() {
        let a = peer_id_from_byte(10);
        let b = peer_id_from_byte(20);
        let candidates = [a, b];
        let r0 = select_final(0, &candidates, "d");
        let r1 = select_final(1, &candidates, "d");
        // Not required to differ for all inputs, but domain/round affect the hash
        assert!(r0.is_some() && r1.is_some());
    }
}
