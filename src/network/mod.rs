// Network layer module for MPC protocol
// Organized into domain-specific submodules for better maintainability

mod bootstrap_nodes;
pub mod config;
pub mod discovery;
pub mod dkg;
pub mod rpc;
pub mod transport;

// Internal helpers for initialization and component management
mod getters;
mod init;
mod setters;
mod utils;
mod sequencer;

pub use sequencer::{
    ContractTransactionRequest, ContractTransactionSequencer,
    NetworkTransactionRequest, NetworkTransactionSequencer, NetworkTransactionFlow,
};
