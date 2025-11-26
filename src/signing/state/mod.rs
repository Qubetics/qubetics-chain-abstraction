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
    Option<String>, // intent_hash
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
                ),
            >,
        >,
    >,
    pub withdraw_pending_transactions_btc: Arc<RwLock<HashMap<u64, PendingValue>>>,
    pub withdraw_rounds: Arc<RwLock<HashSet<u64>>>,
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
        }
    }
}

#[derive(Clone)]
pub struct BtcAggregationState {
    pub btc_sigs_by_round:
        Arc<RwLock<HashMap<u64, HashMap<usize, HashMap<String, ECDSASignature>>>>>,
    pub btc_agg_by_round: Arc<RwLock<HashMap<u64, HashMap<usize, RecoverableSignature>>>>,
    pub btc_done_inputs_by_round: Arc<RwLock<HashMap<u64, HashSet<usize>>>>,
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

    pub fn build_with_coordination(
        self,
        coordination: Coordination,
    ) -> SigningEnvironment {
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
