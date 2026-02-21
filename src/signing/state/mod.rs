use crate::chain_abstraction::{ChainHandler, ChainHandlerFactory, ChainTransaction};
use crate::signing::config::BroadcastConfig;
use crate::signing::coordination::{self, Coordination};
use crate::types::signing::ECDSASignature;
use crate::types::TransactionType;
use crate::types::{ChannelMessage, SpendKind};
use secp256k1::{ecdsa::RecoverableSignature, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BtcRoundExtras {
    #[serde(with = "serde_big_array::BigArray")] // works for any array length
    pub pubkey33: [u8; 33],
    pub signer_h160: [u8; 20],
    pub from_kind: SpendKind,
    pub is_testnet: bool,
}

pub type PendingValue = (
    ChainTransaction,
    Vec<u8>,
    Option<Vec<String>>, // intent_hashes (batch support)
    Option<TransactionType>,
    Option<BtcRoundExtras>, // <-- NEW
);

/// Per-slot partials for TICS UserToVault batch: (round, slot_id) -> node_id -> signature.
pub type RoundSlotKey = (u64, String);

/// TX data received from a DKG node for threshold verification.
/// The final node collects these and accepts the data once threshold matching copies arrive.
#[derive(Clone, Debug)]
pub struct ReceivedTxData {
    pub from: String,
    pub tx_bytes: Vec<u8>,
    pub chain_tx_json: String,
    pub intent_hash: Option<String>,
    pub transaction_type: Option<String>,
    pub request_id: Option<String>,
    pub user_tics_address: Option<String>,
    /// Full batch identifiers for withdraw/claim-reward batches ("request_id|solver_address").
    pub batch_identifiers: Option<Vec<String>>,
}

/// Key for received TX data: (round, slot_id).
/// For non-batch TXs, slot_id is None => we use empty string "".
pub type TxDataKey = (u64, String);

#[derive(Clone)]
pub struct SignatureStore {
    pub public_keys: Arc<RwLock<HashMap<String, PublicKey>>>, // Other nodes' public keys
    pub signatures: Arc<RwLock<HashMap<String, ECDSASignature>>>,
    pub signatures_by_round: Arc<RwLock<HashMap<u64, HashMap<String, ECDSASignature>>>>, // round -> node_id -> signature
    /// TICS UserToVault batch: (round, intent_hash) -> node_id -> signature. One aggregation per slot.
    pub signatures_by_round_slot: Arc<RwLock<HashMap<RoundSlotKey, HashMap<String, ECDSASignature>>>>,
    pub final_nodes_by_round: Arc<RwLock<HashMap<u64, String>>>, // round -> final_node_id
    pub aggregated_rounds: Arc<RwLock<HashSet<u64>>>, // Track rounds that have been aggregated
    /// Rounds/slots that have been aggregated for TICS UserToVault batch.
    pub aggregated_round_slots: Arc<RwLock<HashSet<RoundSlotKey>>>,
}

impl Default for SignatureStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of recent rounds to keep in memory for signature data.
const MAX_SIGNATURE_ROUNDS_IN_MEMORY: usize = 1000;

impl SignatureStore {
    pub fn new() -> Self {
        Self {
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            signatures_by_round: Arc::new(RwLock::new(HashMap::new())),
            signatures_by_round_slot: Arc::new(RwLock::new(HashMap::new())),
            final_nodes_by_round: Arc::new(RwLock::new(HashMap::new())),
            aggregated_rounds: Arc::new(RwLock::new(HashSet::new())),
            aggregated_round_slots: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Sweep old round data, keeping only the latest `MAX_SIGNATURE_ROUNDS_IN_MEMORY` rounds.
    /// Call this periodically (e.g. every N clock ticks) to prevent unbounded memory growth.
    pub async fn sweep_old_rounds(&self) {
        // Determine the cutoff round from signatures_by_round
        let cutoff = {
            let map = self.signatures_by_round.read().await;
            if map.len() <= MAX_SIGNATURE_ROUNDS_IN_MEMORY {
                return; // nothing to sweep
            }
            let mut rounds: Vec<u64> = map.keys().copied().collect();
            rounds.sort_unstable();
            // Keep the top MAX_SIGNATURE_ROUNDS_IN_MEMORY rounds
            rounds[rounds.len() - MAX_SIGNATURE_ROUNDS_IN_MEMORY]
        };

        // Sweep signatures_by_round
        {
            let mut map = self.signatures_by_round.write().await;
            map.retain(|&round, _| round >= cutoff);
        }

        // Sweep final_nodes_by_round
        {
            let mut map = self.final_nodes_by_round.write().await;
            map.retain(|&round, _| round >= cutoff);
        }

        // Sweep aggregated_rounds
        {
            let mut set = self.aggregated_rounds.write().await;
            set.retain(|&round| round >= cutoff);
        }

        // Sweep signatures_by_round_slot (keyed by (round, slot_id))
        {
            let mut map = self.signatures_by_round_slot.write().await;
            map.retain(|&(round, _), _| round >= cutoff);
        }

        // Sweep aggregated_round_slots
        {
            let mut set = self.aggregated_round_slots.write().await;
            set.retain(|&(round, _)| round >= cutoff);
        }
    }
}

#[derive(Clone)]
pub struct PendingStore {
    pub pending_transactions: Arc<
        RwLock<
            HashMap<
                u64,
                (
                    ChainTransaction,
                    Vec<u8>,
                    Option<String>,
                    Option<TransactionType>,
                    Option<String>, // request_id for retry tracking (contract_request removed)
                    Option<()>,     // deprecated original_request (unused)
                ),
            >,
        >,
    >,
    pub pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>,
    /// TICS withdraw: (chain_tx, tx_bytes, identifiers, tx_type, request_id, original_request).
    /// identifiers: None or Some(vec!) for single-solver; Some(vec!["request_id|solver", ...]) for batch.
    pub withdraw_pending_transactions_tics: Arc<
        RwLock<
            HashMap<
                u64,
                (
                    ChainTransaction,
                    Vec<u8>,
                    Option<Vec<String>>,
                    Option<TransactionType>,
                    Option<String>, // request_id for retry tracking (contract_request removed)
                    Option<()>,     // deprecated original_request (unused)
                ),
            >,
        >,
    >,
    pub withdraw_pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>,
    pub withdraw_rounds: Arc<RwLock<HashSet<u64>>>,
    /// BTC claim-reward batch: same shape as withdraw_pending_transactions_btc; tx-id broadcast updates PendingClaimRewardRequest (do not mark done).
    pub claim_reward_pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>,
    /// TICS claim-reward batch: same shape as withdraw_pending_transactions_tics; tx-id broadcast stores tx_id on TICS requests and marks done; marks BTC requests done only.
    pub claim_reward_pending_transactions_tics: Arc<
        RwLock<
            HashMap<
                u64,
                (
                    ChainTransaction,
                    Vec<u8>,
                    Option<Vec<String>>,
                    Option<TransactionType>,
                    Option<String>,
                    Option<()>,
                ),
            >,
        >,
    >,
    pub claim_reward_rounds: Arc<RwLock<HashSet<u64>>>,
    /// BTC claim-platform-fee batch: same shape as claim_reward_pending_transactions_btc.
    pub claim_platform_fee_pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>,
    pub claim_platform_fee_rounds: Arc<RwLock<HashSet<u64>>>,
    /// TICS claim-platform-fee batch: same shape as claim_reward_pending_transactions_tics.
    /// Signed with admin's tweaked share; tx-id broadcast marks requests Completed.
    pub claim_platform_fee_pending_transactions_tics: Arc<
        RwLock<
            HashMap<
                u64,
                (
                    ChainTransaction,
                    Vec<u8>,
                    Option<Vec<String>>,     // identifiers: "request_id|admin"
                    Option<TransactionType>, // ClaimPlatformFee
                    Option<String>,          // unused (request_id for retry)
                    Option<()>,              // deprecated original_request
                ),
            >,
        >,
    >,
    /// Per-round list of intent hashes (single intent = len 1, batch = len >1, solver-only = empty)
    pub intent_hashes_by_round: Arc<RwLock<HashMap<u64, Vec<String>>>>,
    /// TICS UserToVault batch: round -> [(intent_hash, user_eth, chain_tx, tx_bytes)]. Same round, multiple txs.
    pub user_to_vault_tics_batch: Arc<
        RwLock<
            HashMap<
                u64,
                Vec<(
                    String,           // intent_hash
                    String,           // user_tics_address
                    ChainTransaction,
                    Vec<u8>,          // tx_bytes
                )>,
            >,
        >,
    >,
    /// BTC UserToVault batch: round -> [(intent_hash, user_eth, chain_tx, tx_bytes, extras)].
    /// Same round, multiple txs (up to 30 slots). Each slot can have multiple inputs.
    pub user_to_vault_btc_batch: Arc<
        RwLock<
            HashMap<
                u64,
                Vec<(
                    String,              // intent_hash (slot_id)
                    String,              // user_tics_address
                    ChainTransaction,    // Bitcoin tx with potentially multiple inputs
                    Vec<u8>,             // tx_bytes (serialized unsigned tx)
                    Option<BtcRoundExtras>, // BTC extras (pubkey33, signer_h160, from_kind, is_testnet)
                )>,
            >,
        >,
    >,
    /// Universal TX data collection for threshold verification.
    /// Observer final nodes collect TX data from DKG nodes; once threshold matching
    /// copies of tx_bytes arrive for a given (round, slot_id), the data is trusted
    /// and promoted to the appropriate pending store for reconstruction.
    /// Key: (round, slot_id) where slot_id="" for non-batch TXs.
    /// Value: Vec of received TX data from different nodes.
    pub received_tx_data: Arc<RwLock<HashMap<TxDataKey, Vec<ReceivedTxData>>>>,
}

impl Default for PendingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingStore {
    pub fn new() -> Self {
        Self {
            pending_transactions: Arc::new(RwLock::new(HashMap::new())),
            pending_transactions_btc: Arc::new(RwLock::new(HashMap::new())),
            withdraw_pending_transactions_tics: Arc::new(RwLock::new(HashMap::new())),
            withdraw_pending_transactions_btc: Arc::new(RwLock::new(HashMap::new())),
            withdraw_rounds: Arc::new(RwLock::new(HashSet::new())),
            claim_reward_pending_transactions_btc: Arc::new(RwLock::new(HashMap::new())),
            claim_reward_pending_transactions_tics: Arc::new(RwLock::new(HashMap::new())),
            claim_reward_rounds: Arc::new(RwLock::new(HashSet::new())),
            claim_platform_fee_pending_transactions_btc: Arc::new(RwLock::new(HashMap::new())),
            claim_platform_fee_rounds: Arc::new(RwLock::new(HashSet::new())),
            claim_platform_fee_pending_transactions_tics: Arc::new(RwLock::new(HashMap::new())),
            intent_hashes_by_round: Arc::new(RwLock::new(HashMap::new())),
            user_to_vault_tics_batch: Arc::new(RwLock::new(HashMap::new())),
            user_to_vault_btc_batch: Arc::new(RwLock::new(HashMap::new())),
            received_tx_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Sweep old round data, keeping only rounds >= cutoff.
    pub async fn sweep_old_rounds(&self, cutoff: u64) {
        self.pending_transactions.write().await.retain(|&round, _| round >= cutoff);
        self.pending_transactions_btc.write().await.retain(|&round, _| round >= cutoff);
        self.withdraw_pending_transactions_tics.write().await.retain(|&round, _| round >= cutoff);
        self.withdraw_pending_transactions_btc.write().await.retain(|&round, _| round >= cutoff);
        self.withdraw_rounds.write().await.retain(|&round| round >= cutoff);
        self.claim_reward_pending_transactions_btc.write().await.retain(|&round, _| round >= cutoff);
        self.claim_reward_pending_transactions_tics.write().await.retain(|&round, _| round >= cutoff);
        self.claim_reward_rounds.write().await.retain(|&round| round >= cutoff);
        self.claim_platform_fee_pending_transactions_btc.write().await.retain(|&round, _| round >= cutoff);
        self.claim_platform_fee_rounds.write().await.retain(|&round| round >= cutoff);
        self.claim_platform_fee_pending_transactions_tics.write().await.retain(|&round, _| round >= cutoff);
        self.intent_hashes_by_round.write().await.retain(|&round, _| round >= cutoff);
        self.user_to_vault_tics_batch.write().await.retain(|&round, _| round >= cutoff);
        self.user_to_vault_btc_batch.write().await.retain(|&round, _| round >= cutoff);
        self.received_tx_data.write().await.retain(|&(round, _), _| round >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::{Database, DatabaseConfig, VrfStorage},
        types::signing::ECDSASignature,
        vrf::service::VrfService,
    };
    use libp2p::{identity::Keypair, PeerId};
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    fn create_database() -> (Database, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = DatabaseConfig::default();
        config.path = temp_dir.path().to_string_lossy().to_string();
        config.encryption_key =
            Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());
        let db = Database::new(config).unwrap();
        (db, temp_dir)
    }

    fn random_peer_id() -> PeerId {
        let keypair = Keypair::generate_ed25519();
        PeerId::from_public_key(&keypair.public())
    }

    #[tokio::test]
    async fn signatures_use_non_decreasing_rounds_after_sync() {
        let (db, _temp_dir) = create_database();
        let storage = VrfStorage::new(db);
        let (tx, _rx) = mpsc::channel(4);
        let peer_id = random_peer_id();
        let service = VrfService::new_with_storage(peer_id, tx, storage.clone());
        let signatures = SignatureStore::new();

        let first_round = service.sync_rounds_with_mocked_peers(vec![2, 3]).await;
        {
            let mut signatures_by_round = signatures.signatures_by_round.write().await;
            signatures_by_round.entry(first_round).or_default().insert(
                "node-a".to_string(),
                ECDSASignature {
                    signature: vec![1u8; 65],
                    signer_id: "node-a".to_string(),
                    recovery_id: 0,
                    user_tics_address: None,
                },
            );
        }

        let second_round = service.sync_rounds_with_mocked_peers(vec![0, 1]).await;
        {
            let mut signatures_by_round = signatures.signatures_by_round.write().await;
            signatures_by_round.entry(second_round).or_default().insert(
                "node-b".to_string(),
                ECDSASignature {
                    signature: vec![2u8; 65],
                    signer_id: "node-b".to_string(),
                    recovery_id: 1,
                    user_tics_address: Some("0xabc".to_string()),
                },
            );
        }

        let mut recorded_rounds: Vec<u64> = signatures
            .signatures_by_round
            .read()
            .await
            .keys()
            .cloned()
            .collect();
        recorded_rounds.sort_unstable();

        assert_eq!(recorded_rounds.len(), 2);
        assert!(recorded_rounds
            .windows(2)
            .all(|window| window[0] <= window[1]));
        assert_eq!(recorded_rounds.first().copied().unwrap(), first_round);
        assert_eq!(recorded_rounds.last().copied().unwrap(), second_round);
        assert_eq!(service.get_current_round().await, second_round);
        assert_eq!(storage.get_current_round().unwrap(), second_round);
    }
}

#[derive(Clone)]
pub struct BtcAggregationState {
    pub btc_sigs_by_round:
        Arc<RwLock<HashMap<u64, HashMap<usize, HashMap<String, ECDSASignature>>>>>,
    pub btc_agg_by_round: Arc<RwLock<HashMap<u64, HashMap<usize, RecoverableSignature>>>>,
    pub btc_done_inputs_by_round: Arc<RwLock<HashMap<u64, HashSet<usize>>>>,
}

impl Default for BtcAggregationState {
    fn default() -> Self {
        Self::new()
    }
}

impl BtcAggregationState {
    pub fn new() -> Self {
        Self {
            btc_sigs_by_round: Arc::new(RwLock::new(HashMap::new())),
            btc_agg_by_round: Arc::new(RwLock::new(HashMap::new())),
            btc_done_inputs_by_round: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Sweep old round data, keeping only rounds >= cutoff.
    pub async fn sweep_old_rounds(&self, cutoff: u64) {
        {
            let mut map = self.btc_sigs_by_round.write().await;
            map.retain(|&round, _| round >= cutoff);
        }
        {
            let mut map = self.btc_agg_by_round.write().await;
            map.retain(|&round, _| round >= cutoff);
        }
        {
            let mut map = self.btc_done_inputs_by_round.write().await;
            map.retain(|&round, _| round >= cutoff);
        }
    }
}

/// BTC UserToVault batch aggregation state.
/// Hybrid of TICS UTV (slot-based) and N2T (multi-input).
/// Key: (round, slot_id) where slot_id is the intent_hash.
/// Each slot can have multiple inputs (UTXOs).
#[derive(Clone)]
pub struct BtcUtvAggregationState {
    /// 4-level storage: (round, slot_id) → input_index → peer_id → signature
    pub btc_utv_sigs_by_round_slot:
        Arc<RwLock<HashMap<RoundSlotKey, HashMap<usize, HashMap<String, ECDSASignature>>>>>,
    /// Aggregated sigs per slot: (round, slot_id) → input_index → aggregated_sig
    pub btc_utv_agg_by_round_slot:
        Arc<RwLock<HashMap<RoundSlotKey, HashMap<usize, RecoverableSignature>>>>,
    /// Track completed inputs per slot: (round, slot_id) → set of done input indices
    pub btc_utv_done_inputs_by_round_slot: Arc<RwLock<HashMap<RoundSlotKey, HashSet<usize>>>>,
    /// Track fully completed slots (all inputs done + broadcast)
    pub btc_utv_completed_slots: Arc<RwLock<HashSet<RoundSlotKey>>>,
}

impl Default for BtcUtvAggregationState {
    fn default() -> Self {
        Self::new()
    }
}

impl BtcUtvAggregationState {
    pub fn new() -> Self {
        Self {
            btc_utv_sigs_by_round_slot: Arc::new(RwLock::new(HashMap::new())),
            btc_utv_agg_by_round_slot: Arc::new(RwLock::new(HashMap::new())),
            btc_utv_done_inputs_by_round_slot: Arc::new(RwLock::new(HashMap::new())),
            btc_utv_completed_slots: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Sweep old round data, keeping only rounds >= cutoff.
    pub async fn sweep_old_rounds(&self, cutoff: u64) {
        {
            let mut map = self.btc_utv_sigs_by_round_slot.write().await;
            map.retain(|&(round, _), _| round >= cutoff);
        }
        {
            let mut map = self.btc_utv_agg_by_round_slot.write().await;
            map.retain(|&(round, _), _| round >= cutoff);
        }
        {
            let mut map = self.btc_utv_done_inputs_by_round_slot.write().await;
            map.retain(|&(round, _), _| round >= cutoff);
        }
        {
            let mut set = self.btc_utv_completed_slots.write().await;
            set.retain(|&(round, _)| round >= cutoff);
        }
    }
}

#[derive(Clone)]
pub struct BroadcastPolicy {
    pub config: BroadcastConfig,
}

impl BroadcastPolicy {
    pub fn from_env() -> Self {
        Self {
            config: BroadcastConfig::from_env(),
        }
    }

    pub fn config(&self) -> &BroadcastConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut BroadcastConfig {
        &mut self.config
    }
}

pub struct SigningEnvironment {
    pub coordination: Coordination,
    pub chain_handler: Arc<dyn ChainHandler>, // Chain-specific operations for regular transactions
    pub contract_chain_handler: Arc<dyn ChainHandler>, // Chain handler specifically for contract transactions
    pub broadcast_policy: BroadcastPolicy,
}

pub struct SigningEnvironmentBuilder {
    id: String,
    message_tx: mpsc::Sender<ChannelMessage>,
}

impl SigningEnvironmentBuilder {
    pub fn new(id: String, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        Self { id, message_tx }
    }

    pub fn build(self) -> SigningEnvironment {
        let peer_id = coordination::derive_peer_id_from_string(&self.id);
        let coordination = Coordination::new(peer_id, self.message_tx.clone());

        let chain_handler = ChainHandlerFactory::create_tics_handler(9029);
        let chain_handler: Arc<dyn ChainHandler> = chain_handler.into();

        let contract_chain_handler = ChainHandlerFactory::create_tics_handler(9029);
        let contract_chain_handler: Arc<dyn ChainHandler> = contract_chain_handler.into();

        SigningEnvironment {
            coordination,
            chain_handler,
            contract_chain_handler,
            broadcast_policy: BroadcastPolicy::from_env(),
        }
    }

    pub fn build_with_coordination(self, coordination: Coordination) -> SigningEnvironment {
        let chain_handler = ChainHandlerFactory::create_tics_handler(9029);
        let chain_handler: Arc<dyn ChainHandler> = chain_handler.into();

        let contract_chain_handler = ChainHandlerFactory::create_tics_handler(9029);
        let contract_chain_handler: Arc<dyn ChainHandler> = contract_chain_handler.into();

        SigningEnvironment {
            coordination,
            chain_handler,
            contract_chain_handler,
            broadcast_policy: BroadcastPolicy::from_env(),
        }
    }
}
