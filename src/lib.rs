#![recursion_limit = "4096"]

pub mod chain_abstraction;
pub mod commands;
pub mod consensus;
pub mod contract;
pub mod database;
// Deterministic selection is now integrated into ContractTransactionSequencer and NetworkTransactionSequencer
// pub mod deterministic_selection;
pub mod dkg;
pub mod intent_manager;
pub mod network;
pub mod node_selection;
pub mod protocols;
pub mod rpc_server;
pub mod signing;
pub mod types;
pub mod user_intent_manager;
pub mod utils;
pub mod vrf;

pub use commands::{CommandKind, CommandProcessor};
pub use consensus::{ConsensusNode, DatabaseConsensusNode};
pub use database::{
    ConsensusStorage, Database, DatabaseConfig, DkgStorage, IntentStorage, RewardStorage,
    SigningStorage, TransactionStatusStorage, UserStorage,
};
// Removed deterministic_selection module - functionality integrated into sequencers
// pub use deterministic_selection::{...};
pub use intent_manager::prepare_unsigned_eip1559_tx;
pub use network::transport::types::MpcNetworkLayer;
pub use node_selection::{
    BasicNodeManager, DefaultThresholdCalculator, NodeMembership, ThresholdCalculator,
    VrfNodeManager, VrfNodeManagerConfig,
};
pub use protocols::{
    DKGMessage, DKGNode, DKGStatus, NodeSelectionResult, VrfNodeSelector, VrfOutput,
    VrfSelectedNodesBroadcast, VrfSelectionFacade, VrfSelectionMessage, VrfService,
    VrfServiceConfig,
};
pub use signing::{DatabaseSigningNode, SigningNode};
pub use types::{ECDSASignature, SigningMessage};
pub use user_intent_manager::{UserIntentManager, UserRegistry};
