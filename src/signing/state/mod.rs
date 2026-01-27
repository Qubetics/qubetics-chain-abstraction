use crate::chain_abstraction::{ChainHandler, ChainHandlerFactory, ChainTransaction};
use crate::signing::config::BroadcastConfig;
use crate::signing::coordination::{self, Coordination};
use crate::types::signing::ECDSASignature;
use crate::types::TransactionType;
use crate::types::{ChannelMessage, SpendKind, TransactionNetwork};
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

#[derive(Clone)]
pub struct SignatureStore {
    pub public_keys: Arc<RwLock<HashMap<String, PublicKey>>>, // Other nodes' public keys
    pub signatures: Arc<RwLock<HashMap<String, ECDSASignature>>>,
    pub signatures_by_round: Arc<RwLock<HashMap<u64, HashMap<String, ECDSASignature>>>>, // round -> node_id -> signature
    pub final_nodes_by_round: Arc<RwLock<HashMap<u64, String>>>, // round -> final_node_id
    pub aggregated_rounds: Arc<RwLock<HashSet<u64>>>, // Track rounds that have been aggregated
}

impl Default for SignatureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureStore {
    pub fn new() -> Self {
        Self {
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            signatures_by_round: Arc::new(RwLock::new(HashMap::new())),
            final_nodes_by_round: Arc::new(RwLock::new(HashMap::new())),
            aggregated_rounds: Arc::new(RwLock::new(HashSet::new())),
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
    pub reward_pending_transactions_tics: Arc<
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
    pub reward_pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>, // round -> (original_tx, tx_bytes, solver_address, None, extras) for BTC rewards
    pub reward_rounds: Arc<RwLock<HashSet<u64>>>, // Set of rounds that are reward transactions
    pub withdraw_pending_transactions_tics: Arc<
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
    pub withdraw_pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>,
    pub withdraw_rounds: Arc<RwLock<HashSet<u64>>>,
    /// Per-round list of intent hashes (single intent = len 1, batch = len >1, solver-only = empty)
    pub intent_hashes_by_round: Arc<RwLock<HashMap<u64, Vec<String>>>>,
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
            reward_pending_transactions_tics: Arc::new(RwLock::new(HashMap::new())),
            reward_pending_transactions_btc: Arc::new(RwLock::new(HashMap::new())),
            reward_rounds: Arc::new(RwLock::new(HashSet::new())),
            withdraw_pending_transactions_tics: Arc::new(RwLock::new(HashMap::new())),
            withdraw_pending_transactions_btc: Arc::new(RwLock::new(HashMap::new())),
            withdraw_rounds: Arc::new(RwLock::new(HashSet::new())),
            intent_hashes_by_round: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a round is a reward transaction round
    pub async fn is_reward_round(&self, round: u64) -> bool {
        let reward_rounds = self.reward_rounds.read().await;
        reward_rounds.contains(&round)
    }

    /// Check if a round is a withdraw liquidity transaction round
    pub async fn is_withdraw_round(&self, round: u64) -> bool {
        let withdraw_rounds = self.withdraw_rounds.read().await;
        withdraw_rounds.contains(&round)
    }

    /// Get the appropriate pending transaction map for a given round and transaction network
    /// Returns a reference to the correct map based on round type (reward/withdraw/regular)
    /// and transaction network (TICS/BTC)
    pub fn get_pending_for_round_btc(
        &self,
        is_reward: bool,
        is_withdraw: bool,
    ) -> Arc<RwLock<HashMap<u64, PendingValue>>> {
        if is_reward {
            self.reward_pending_transactions_btc.clone()
        } else if is_withdraw {
            self.withdraw_pending_transactions_btc.clone()
        } else {
            self.pending_transactions_btc.clone()
        }
    }

    /// Get the appropriate TICS pending transaction map for a given round
    /// Returns a reference to the correct map based on round type (reward/withdraw/regular)
    pub fn get_pending_for_round_tics(
        &self,
        is_reward: bool,
        is_withdraw: bool,
    ) -> Arc<
        RwLock<
            HashMap<
                u64,
                (
                    ChainTransaction,
                    Vec<u8>,
                    Option<String>,
                    Option<TransactionType>,
                    Option<String>,
                    Option<()>,
                ),
            >,
        >,
    > {
        if is_reward {
            self.reward_pending_transactions_tics.clone()
        } else if is_withdraw {
            self.withdraw_pending_transactions_tics.clone()
        } else {
            self.pending_transactions.clone()
        }
    }

    /// Get the appropriate pending map for a round and transaction network.
    /// Uses `is_reward_round`/`is_withdraw_round` and selects reward/withdraw/pending for TICS or BTC.
    pub async fn get_pending_for_round(
        &self,
        round: u64,
        txn_network: TransactionNetwork,
    ) -> PendingMapForRound {
        let is_reward = self.is_reward_round(round).await;
        let is_withdraw = self.is_withdraw_round(round).await;
        match txn_network {
            TransactionNetwork::TICS => {
                PendingMapForRound::Tics(self.get_pending_for_round_tics(is_reward, is_withdraw))
            }
            TransactionNetwork::BTC => {
                PendingMapForRound::Btc(self.get_pending_for_round_btc(is_reward, is_withdraw))
            }
        }
    }
}

/// Pending map reference for a round and network.
/// Use with `PendingStore::get_pending_for_round(round, txn_network).await` then match and call `.read().await` / `.write().await` on the inner `Arc`.
pub enum PendingMapForRound {
    Tics(Arc<
        RwLock<
            HashMap<
                u64,
                (
                    ChainTransaction,
                    Vec<u8>,
                    Option<String>,
                    Option<TransactionType>,
                    Option<String>,
                    Option<()>,
                ),
            >,
        >,
    >),
    Btc(Arc<RwLock<HashMap<u64, PendingValue>>>),
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
                    user_eth_address: None,
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
                    user_eth_address: Some("0xabc".to_string()),
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

        let chain_handler = ChainHandlerFactory::create_ethereum_handler(9029);
        let chain_handler: Arc<dyn ChainHandler> = chain_handler.into();

        let contract_chain_handler = ChainHandlerFactory::create_ethereum_handler(9029);
        let contract_chain_handler: Arc<dyn ChainHandler> = contract_chain_handler.into();

        SigningEnvironment {
            coordination,
            chain_handler,
            contract_chain_handler,
            broadcast_policy: BroadcastPolicy::from_env(),
        }
    }

    pub fn build_with_coordination(self, coordination: Coordination) -> SigningEnvironment {
        let chain_handler = ChainHandlerFactory::create_ethereum_handler(9029);
        let chain_handler: Arc<dyn ChainHandler> = chain_handler.into();

        let contract_chain_handler = ChainHandlerFactory::create_ethereum_handler(9029);
        let contract_chain_handler: Arc<dyn ChainHandler> = contract_chain_handler.into();

        SigningEnvironment {
            coordination,
            chain_handler,
            contract_chain_handler,
            broadcast_policy: BroadcastPolicy::from_env(),
        }
    }
}
