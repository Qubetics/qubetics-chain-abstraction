# Debug Logging Summary - Node Indexes and Secret Keys

This document summarizes all the debug logging that has been added to the codebase for testing and debugging node indexes and secret keys during transaction signing.

## Overview

The following comprehensive logging has been added to track:
1. **Node DKG Indices** - The index assigned to each node during signing operations
2. **Secret Keys** - The private keys used for signing (for debugging/testing only)
3. **Signature Details** - r, s values and recovery IDs
4. **Available Nodes** - Lists of nodes participating in signing

## Logging Added

### 1. Ethereum Transaction Signing (`src/signing/mod.rs`)

**Location**: `sign_message` function (around line 1688-1820)

Added logs:
```
🔐 [SIGNING-DEBUG] Node {} signing key (hex): 0x{}
🔢 [SIGNING-DEBUG] Node {} DKG index: {}
💾 [SIGNING-DEBUG] Stored signature details - r: 0x{}, s: 0x{}, recovery_id: {}
```

### 2. Contract Transaction Signing (`src/signing/mod.rs`)

**Location**: `sign_contract_message` function (around line 1829-1890)

Added logs:
```
🔐 [SIGNING-DEBUG] Node {} signing key (hex): 0x{}
🔢 [SIGNING-DEBUG] Node {} DKG index: {}
```

### 3. Bitcoin Transaction Signing (`src/signing/mod.rs`)

**Location**: `sign_bitcoin_message` function (around line 451-523)

Added logs:
```
🔐 [BTC-SIGNING-DEBUG] Node {} Bitcoin signing key (hex): 0x{}
🔢 [BTC-SIGNING-DEBUG] Node {} Bitcoin DKG index: {}
💾 [BTC-SIGNING-DEBUG] Stored BTC signature for input {} - r: 0x{}, s: 0x{}, recovery_id: {}
```

### 4. Signature Aggregation (`src/signing/mod.rs`)

**Location**: `aggregate_signatures` function (around line 2214-2310)

Enhanced logs with **Index => PeerId** mapping:
```
🔢 [INDEX-PEER-DEBUG] Index => PeerId mapping:
🔢 [INDEX-PEER-DEBUG]   Index {} => PeerId {}
🔍 [SIGNING-DEBUG] Index {} => PeerId {} => s-share: 0x{}
🔢 [INDEX-PEER-DEBUG] Complete Index => PeerId => Share mapping:
🔢 [INDEX-PEER-DEBUG]   Index {} => {} => 0x{}
🔍 [SIGNING-DEBUG] Complete s_shares (index -> s-value): {:?}
```

### 5. Signature Storage with Index => PeerId (`src/signing/mod.rs`)

**Location**: Signature storage in `sign_message`, `sign_contract_message`, and `sign_bitcoin_message` functions

Added logs showing **Index => PeerId** when storing signatures:
```
💾 [INDEX-PEER-DEBUG] Stored signature for Index {} => PeerId {} (s-share: 0x{})
💾 [INDEX-PEER-DEBUG] Contract: Stored signature for Index {} => PeerId {} (s-share: 0x{})
💾 [INDEX-PEER-DEBUG] BTC: Stored signature for Index {} => PeerId {} input {} (s-share: 0x{})
```

### 6. DKG Index Calculation (`src/signing/mod.rs`)

**Location**: `calculate_dkg_index_for_peer` and `calculate_dkg_index_for_peer_sync` functions (around line 4108-4156)

Added logs:
```
🔢 [DKG-INDEX-DEBUG] Available nodes and their DKG indices:
🔢 [DKG-INDEX-DEBUG]   {} -> index {}
```

This shows a complete mapping of all nodes to their DKG indices.

### 7. Pre-Aggregation Index => PeerId Mapping (`src/signing/mod.rs`)

**Location**: Before signature aggregation (around line 3537-3540)

Added logs:
```
🔢 [INDEX-PEER-DEBUG] Round {} - Index => PeerId mapping for aggregation:
🔢 [INDEX-PEER-DEBUG]   Index {} => {}
```

### 8. Network Transaction Processing (`src/network/mod.rs`)

**Location**: Gossipsub transaction handling (around line 1331-1368)

Added logs:
```
🔢 [NETWORK-DEBUG] Available nodes count: {}
🔢 [NETWORK-DEBUG] Available nodes: {:?}
🔐 [NETWORK-DEBUG] Secret share (hex): 0x{}
```

### 9. Local Transaction Processing (`src/network/mod.rs`)

**Location**: Local transaction handling (around line 2223-2254)

Added logs:
```
🔢 [LOCAL-DEBUG] Available nodes count: {}
🔢 [LOCAL-DEBUG] Available nodes: {:?}
🔐 [LOCAL-DEBUG] Secret share (hex): 0x{}
```

## Log Categories

All debug logs are categorized with prefixes:

- `[SIGNING-DEBUG]` - General signing debug information
- `[BTC-SIGNING-DEBUG]` - Bitcoin-specific signing debug information  
- `[DKG-INDEX-DEBUG]` - DKG index calculation and mapping
- `[INDEX-PEER-DEBUG]` - **Index => PeerId mapping with shares** (NEW)
- `[NETWORK-DEBUG]` - Network-level transaction processing
- `[LOCAL-DEBUG]` - Local transaction processing

### Key Feature: Index => PeerId Mapping

The `[INDEX-PEER-DEBUG]` logs provide explicit **Index => PeerId** mapping throughout the signing process:

1. **At signature storage** - Shows which index corresponds to which node when storing
2. **Before aggregation** - Shows the index mapping for the selected signers
3. **During aggregation** - Shows index => peerId => share for each signature
4. **Complete mapping** - Shows the full index => peerId => share table

This makes it easy to track which node has which index and which share value at every step.

## Usage for Testing

To test the system and verify node indexes and secret keys:

1. **Start multiple nodes** and monitor their logs
2. **Send a transaction** and observe the logs showing:
   - Which nodes are available
   - What DKG index each node has
   - The secret key each node uses for signing
   - The signature components (r, s, recovery_id)
   - The s-values used in aggregation

3. **Verify index consistency**:
   - Check that all nodes calculate the same DKG indices for each peer
   - Verify that the indices used in aggregation match the signing indices

4. **Debug signature issues**:
   - Compare secret keys across nodes
   - Verify signature r and s values
   - Check recovery IDs

## Security Note

⚠️ **WARNING**: These debug logs expose sensitive information including:
- Private keys (secret keys in hex format)
- Signature components
- DKG secret shares

**These logs should ONLY be used in testing/development environments and MUST be removed or disabled in production.**

## Example Log Output

When a transaction is processed, you'll see logs like:

```
🔢 [NETWORK-DEBUG] Available nodes count: 5
🔢 [NETWORK-DEBUG] Available nodes: [12D3KooWAbc..., 12D3KooWDef..., ...]
🔐 [NETWORK-DEBUG] Secret share (hex): 0x1234567890abcdef...
🔢 [DKG-INDEX-DEBUG] Available nodes and their DKG indices:
🔢 [DKG-INDEX-DEBUG]   12D3KooWAbc... -> index 1
🔢 [DKG-INDEX-DEBUG]   12D3KooWDef... -> index 2
🔢 [DKG-INDEX-DEBUG]   12D3KooWGhi... -> index 3
🔐 [SIGNING-DEBUG] Node 12D3KooWAbc... signing key (hex): 0xabcdef...
🔢 [SIGNING-DEBUG] Node 12D3KooWAbc... DKG index: 1
💾 [SIGNING-DEBUG] Stored signature details - r: 0x..., s: 0x..., recovery_id: 0
💾 [INDEX-PEER-DEBUG] Stored signature for Index 1 => PeerId 12D3KooWAbc... (s-share: 0x...)
🔢 [INDEX-PEER-DEBUG] Round 0 - Index => PeerId mapping for aggregation:
🔢 [INDEX-PEER-DEBUG]   Index 1 => 12D3KooWAbc...
🔢 [INDEX-PEER-DEBUG]   Index 2 => 12D3KooWDef...
🔢 [INDEX-PEER-DEBUG]   Index 3 => 12D3KooWGhi...
🔍 [SIGNING] === SIGNATURE INDEX ASSIGNMENT ===
🔢 [INDEX-PEER-DEBUG] Index => PeerId mapping:
🔢 [INDEX-PEER-DEBUG]   Index 1 => PeerId 12D3KooWAbc...
🔢 [INDEX-PEER-DEBUG]   Index 2 => PeerId 12D3KooWDef...
🔢 [INDEX-PEER-DEBUG]   Index 3 => PeerId 12D3KooWGhi...
🔍 [SIGNING-DEBUG] Index 1 => PeerId 12D3KooWAbc... => s-share: 0x...
🔍 [SIGNING-DEBUG] Index 2 => PeerId 12D3KooWDef... => s-share: 0x...
🔢 [INDEX-PEER-DEBUG] Complete Index => PeerId => Share mapping:
🔢 [INDEX-PEER-DEBUG]   Index 1 => 12D3KooWAbc... => 0x...
🔢 [INDEX-PEER-DEBUG]   Index 2 => 12D3KooWDef... => 0x...
🔢 [INDEX-PEER-DEBUG]   Index 3 => 12D3KooWGhi... => 0x...
🔍 [SIGNING-DEBUG] Complete s_shares (index -> s-value): ["1 -> 0x...", "2 -> 0x...", ...]
🔍 [SIGNING] === END SIGNATURE INDEX ASSIGNMENT ===
```

## Files Modified

1. `/data/qubetics-chain-abstraction/src/signing/mod.rs`
   - Enhanced `sign_message` function
   - Enhanced `sign_contract_message` function  
   - Enhanced `sign_bitcoin_message` function
   - Enhanced `aggregate_signatures` function
   - Enhanced `calculate_dkg_index_for_peer` function
   - Enhanced `calculate_dkg_index_for_peer_sync` function

2. `/data/qubetics-chain-abstraction/src/network/mod.rs`
   - Enhanced gossipsub transaction handling
   - Enhanced local transaction processing

## Testing the Changes

Build and run the project:

```bash
cd /data/qubetics-chain-abstraction
cargo build
./target/debug/mpc-node
```

The debug logs will appear in your console output and log files with the `[*-DEBUG]` prefixes.

