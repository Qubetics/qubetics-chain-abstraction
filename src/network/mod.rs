// Network layer module for MPC protocol
// Organized into submodules for better maintainability

// Core type definitions and structures
pub mod types;

// Initialization and configuration
mod init;

// Getters and setters for network components
mod getters;
mod setters;

// Peer discovery and management
mod peer_discovery;

// Database synchronization
mod db_sync;

// DKG-specific operations
mod dkg_ops;

// Connection lifecycle management
mod connection;

// Utility functions
mod utils;

// RPC request/response handlers
mod rpc_handlers;

// Main event loop
mod event_loop;

// Event handlers (to be implemented with message handlers)
mod swarm_events;
mod gossipsub_handler;
mod channel_handler;

// Re-export main types for public API
pub use types::{DatabaseSyncState, MpcNetworkBehaviour, NetworkEvent, MpcNetworkLayer};
