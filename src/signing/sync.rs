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

#[cfg(test)]
mod sync_tests {
    use super::*;
    use tokio::sync::mpsc;

    fn make_signing_node() -> SigningNode {
        let (tx, _rx) = mpsc::channel(1);
        SigningNode::new("test-sync-node".to_string(), 2, tx)
    }

    #[tokio::test]
    async fn test_apply_synced_pending_rounds() {
        let node = make_signing_node();
        let withdraw_rounds = vec![10, 20, 30];
        let claim_rounds = vec![15, 25];

        node.apply_synced_pending_rounds(&withdraw_rounds, &claim_rounds).await;

        let (wr, cr) = node.get_pending_rounds_for_sync().await;
        assert!(wr.contains(&10));
        assert!(wr.contains(&20));
        assert!(wr.contains(&30));
        assert!(cr.contains(&15));
        assert!(cr.contains(&25));
    }

    #[tokio::test]
    async fn test_apply_empty_synced_rounds_is_noop() {
        let node = make_signing_node();
        // First add some rounds
        node.apply_synced_pending_rounds(&[100], &[200]).await;

        // Apply empty — should be noop (existing rounds preserved)
        node.apply_synced_pending_rounds(&[], &[]).await;

        let (wr, cr) = node.get_pending_rounds_for_sync().await;
        assert!(wr.contains(&100), "Existing withdraw round should be preserved");
        assert!(cr.contains(&200), "Existing claim round should be preserved");
    }

    #[tokio::test]
    async fn test_clear_and_apply_synced_pending_rounds() {
        let node = make_signing_node();
        // Add initial rounds
        node.apply_synced_pending_rounds(&[1, 2, 3], &[4, 5]).await;

        // Clear and replace with new rounds
        node.clear_and_apply_synced_pending_rounds(&[10, 20], &[30]).await;

        let (wr, cr) = node.get_pending_rounds_for_sync().await;
        assert_eq!(wr.len(), 2);
        assert!(wr.contains(&10));
        assert!(wr.contains(&20));
        assert!(!wr.contains(&1), "Old rounds should be cleared");
        assert_eq!(cr.len(), 1);
        assert!(cr.contains(&30));
    }

    #[tokio::test]
    async fn test_get_pending_rounds_for_sync_returns_inserted() {
        let node = make_signing_node();
        node.apply_synced_pending_rounds(&[42, 43], &[99]).await;

        let (wr, cr) = node.get_pending_rounds_for_sync().await;
        assert_eq!(wr.len(), 2);
        assert_eq!(cr.len(), 1);
    }

    #[tokio::test]
    async fn test_sweep_old_rounds_under_1000_is_noop() {
        let node = make_signing_node();
        // With no signatures, sweep should return early without panic
        node.sweep_old_rounds().await;
        // If we reach here, it didn't panic — passes
    }
}

