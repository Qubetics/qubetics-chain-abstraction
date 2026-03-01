use super::*;
use tracing::debug;
pub use chains::{BitcoinSigner, TicsSigner};
pub use config::{BroadcastConfig, ChainBroadcastConfig};
pub use coordination::Coordination;
pub use db_signing::DatabaseSigningNode;
pub use key::KeyStore;
pub use state::{
    BroadcastPolicy, BtcAggregationState, BtcRoundExtras, BtcUtvAggregationState, PendingStore,
    PendingValue, RoundSlotKey, SignatureStore, SigningEnvironmentBuilder,
};
pub use nonce::{NonceGenerator, NonceManager};

impl SigningNode {
    /// Sweep in-memory signature/pending data older than the latest 1000 rounds.
    /// Should be called periodically (e.g. every 10 clock ticks) to bound memory growth.
    pub async fn sweep_old_rounds(&self) {
        // Determine cutoff from signatures_by_round (the primary round tracker)
        let cutoff = {
            let map = self.signatures.signatures_by_round.read().await;
            if map.len() <= 1000 {
                return; // nothing to sweep
            }
            let mut rounds: Vec<u64> = map.keys().copied().collect();
            rounds.sort_unstable();
            rounds[rounds.len() - 1000]
        };

        debug!("[SIGNING] Sweeping rounds older than {} (keeping latest 1000)", cutoff);

        self.signatures.sweep_old_rounds().await;
        self.pending.sweep_old_rounds(cutoff).await;
        self.btc_state.sweep_old_rounds(cutoff).await;
        self.btc_utv_state.sweep_old_rounds(cutoff).await;
    }

    /// Return (withdraw_rounds, claim_reward_rounds) for state sync (no private data).
    pub async fn get_pending_rounds_for_sync(&self) -> (Vec<u64>, Vec<u64>) {
        let wr: Vec<u64> = self
            .pending
            .withdraw_rounds
            .read()
            .await
            .iter()
            .copied()
            .collect();
        let cr: Vec<u64> = self
            .pending
            .claim_reward_rounds
            .read()
            .await
            .iter()
            .copied()
            .collect();
        (wr, cr)
    }

    /// Apply synced withdraw/claim_reward rounds from a peer (used when joining the network).
    pub async fn apply_synced_pending_rounds(
        &self,
        withdraw_rounds: &[u64],
        claim_reward_rounds: &[u64],
    ) {
        if withdraw_rounds.is_empty() && claim_reward_rounds.is_empty() {
            return;
        }
        let mut wr = self.pending.withdraw_rounds.write().await;
        for r in withdraw_rounds {
            wr.insert(*r);
        }
        let mut cr = self.pending.claim_reward_rounds.write().await;
        for r in claim_reward_rounds {
            cr.insert(*r);
        }
    }

    /// Clear stale pending rounds and apply fresh state from peer.
    /// Used during state sync on rejoin to avoid mixing stale and fresh data.
    pub async fn clear_and_apply_synced_pending_rounds(
        &self,
        withdraw_rounds: &[u64],
        claim_reward_rounds: &[u64],
    ) {
        let mut wr = self.pending.withdraw_rounds.write().await;
        wr.clear();
        for r in withdraw_rounds {
            wr.insert(*r);
        }

        let mut cr = self.pending.claim_reward_rounds.write().await;
        cr.clear();
        for r in claim_reward_rounds {
            cr.insert(*r);
        }
    }

}
