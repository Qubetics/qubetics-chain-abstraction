// Network layer module for MPC protocol
// Organized into domain-specific submodules for better maintainability

mod bootstrap_nodes;
pub mod config;
pub mod discovery;
pub mod dkg;
pub mod rpc;
pub mod transport;
pub mod upgrade;

// Internal helpers for initialization and component management
mod getters;
mod init;
mod sequencer;
mod setters;
mod utils;
pub mod whitelist;

pub use sequencer::{
    ContractTransactionRequest, NetworkTransactionFlow,
    NetworkTransactionRequest, NetworkTransactionSequencer,
};
pub use upgrade::{
    NetworkVersionTracker, RollingUpgradeOrchestrator, UpgradePhase, UpgradeValidation,
};
