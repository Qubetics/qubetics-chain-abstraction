# Consensus Mechanism for VRF-Based Node Selection

This document explains the consensus mechanism that selects one final node from all VRF-selected nodes and triggers the aggregate signature function.

## Overview

The consensus mechanism works in the following steps:

1. **VRF Selection**: Each node uses VRF to select 1 node from the available network nodes
2. **Consensus Collection**: All nodes broadcast their VRF selection results
3. **Final Selection**: Consensus runs to select one final node from all VRF-selected nodes
4. **Aggregate Signature**: The final selected node triggers the aggregate signature function

## Implementation Details

### 1. VRF Selection (Existing)
- Each node runs VRF to select 1 node from available nodes
- VRF ensures deterministic and verifiable selection
- Results are stored locally

### 2. Consensus Process (New)
- Nodes broadcast their VRF selection results via `ConsensusMessage::VrfSelectionResult`
- When enough VRF results are collected (threshold reached), consensus starts
- All unique VRF-selected nodes are collected from all results
- A final node is selected using VRF from this pool

### 3. Final Selection
- The final selected node is determined using VRF
- Consensus proposal is broadcast with VRF proof
- Nodes vote on the proposal
- When threshold votes are reached, final selection is broadcast

### 4. Aggregate Signature Trigger
- The final selected node automatically triggers aggregate signature
- This is done via a command message to the signing module
- The aggregate signature function is called on the selected node

## Message Types

### Consensus Messages
```rust
pub enum ConsensusMessage {
    VrfSelectionResult {
        from: String,
        vrf_result: NodeSelectionResult,
        round: u64,
    },
    ConsensusProposal {
        from: String,
        selected_node: SerializablePeerId,
        vrf_proof: VrfOutput,
        round: u64,
    },
    ConsensusVote {
        from: String,
        proposal_hash: Hash,
        round: u64,
    },
    FinalSelection {
        from: String,
        final_selected_node: SerializablePeerId,
        round: u64,
    },
}
```

## Flow Diagram

```
1. Node A: VRF selects Node B
2. Node B: VRF selects Node C  
3. Node C: VRF selects Node A

4. All nodes broadcast VRF results
5. Consensus collects: [Node A, Node B, Node C]
6. VRF selects final node (e.g., Node B)
7. Node B triggers aggregate signature
```

## Usage

### Running the Consensus Test
```bash
cargo run --bin consensus_test
```

### Running the Signing Demo (with consensus)
```bash
cargo run --bin signing_demo
```

## Key Features

- **Deterministic**: VRF ensures consistent selection across all nodes
- **Verifiable**: All selections come with cryptographic proofs
- **Fault Tolerant**: Uses threshold-based consensus
- **Automatic**: Aggregate signature is triggered automatically
- **Scalable**: Works with any number of nodes

## Configuration

- **Threshold**: Minimum number of VRF results needed to start consensus
- **Total Nodes**: Total number of nodes in the network
- **Selection Round**: Unique identifier for each consensus round

## Logging

The consensus process provides detailed logging:
- `📥 [CONSENSUS]` - Received messages
- `📤 [CONSENSUS]` - Sent messages  
- `🎯 [CONSENSUS]` - Final selections
- `🔐 [CONSENSUS]` - Aggregate signature triggers 