//! Protocol-level façade exports.
//!
//! This module provides a single namespace for the major MPC protocol
//! components (e.g. DKG, VRF) so consumers can depend on `crate::protocols`
//! rather than individual submodules when they just need the high-level APIs.

pub use crate::dkg::{
    artifacts::{DKGMessage, DKGStatus},
    DKGNode,
};

pub use crate::vrf::{
    NodeSelectionResult, VrfNodeSelector, VrfOutput, VrfSelectedNodesBroadcast, VrfSelectionFacade,
    VrfSelectionMessage, VrfService
};
