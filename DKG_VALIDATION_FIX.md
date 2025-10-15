# DKG Validation Failure Fix

## Issue Summary

The DKG was failing with validation errors where each node only validated 1 out of 3 shares from other nodes:

```
Validations: {
  "12D3KooWDubTqHEtsAyB1TBfF3ULHHZFM48z6Gsf61HqmzMAcutr": [false, false, true], 
  "12D3KooWG4TX7StDSYgXiAWEZ8n3rNBPFDv3FdDk3YigarKL2Jpi": [false, false, true], 
  "12D3KooWFSESwHF4FJNBgVBMP4kHTf2wUfK9po5XhANuasDb4RtQ": [false, true, false], 
  "12D3KooWB6UiUX9hTUJGoJgG6UhT3r1ctoM1WYt7W7Puq4PnjCAP": [true, false, false]
}

⏳ [DKG] DKG not yet complete - need 16 validations and 4 shares, have 4 and 0
```

With 4 nodes, the system expects 16 successful validations (4 nodes × 4 validations each), but was only getting 4.

## Root Cause

The issue was in the **inconsistent use of node indexing schemes** during share generation.

### How Share Generation Worked (Before Fix)

In `src/adkg_secp256k1/mod.rs` lines 307-330, the code had conditional logic:

```rust
// Get all node permanent indices from storage
let node_indices = self.storage.get_all_node_indices().await?;

// Only use VRF indices if we have indices for ALL nodes
let shares = if node_indices.len() == self.total_nodes {
    // Use VRF-based indices (e.g., [125, 237, 48, 192])
    self.generate_shares_for_indices(&polynomial, &node_indices)?
} else {
    // Use sequential indices (e.g., [1, 2, 3, 4])
    self.generate_shares(&polynomial)?
};
```

### The Problem

During initial DKG startup:
- **Node A** might have 4 VRF indices already stored → generates shares for VRF indices `[125, 237, 48, 192]`
- **Node B** might have only 3 VRF indices stored → generates shares for sequential indices `[1, 2, 3, 4]`
- **Node C** might have 2 VRF indices stored → generates shares for sequential indices `[1, 2, 3, 4]`
- **Node D** might have all 4 VRF indices stored → generates shares for VRF indices `[125, 237, 48, 192]`

When nodes exchange shares:
- Node B (expecting index 2) receives shares from Node A (generated for indices 125, 237, 48, 192)
- Node B tries to verify share for index 2, but share verification fails because the indices don't match!
- **Result**: Most validations fail, only validations between nodes using the same indexing scheme succeed

### Why Share Verification Failed

The share verification formula is:
```
G * share_value == sum(commitment[j] * x^j)  where x = share.index
```

If the share was generated for index 125 but the node tries to verify it with index 2, the polynomial evaluation won't match!

## The Fix

### Root Cause Detail

The issue had **two parts**:

1. **Share Generation**: Some nodes used VRF indices, others used sequential indices (inconsistent)
2. **Share Lookup**: Nodes looked for shares using their VRF permanent index (e.g., 1339) but shares were only generated for sequential indices (1, 2, 3, 4)

Example from logs:
```
✅ All shares verified successfully (indices 1, 2, 3, 4)
❌ Share for index 1339 not found in shares
```

### Changes Made

**File**: `src/adkg_secp256k1/mod.rs`

**Lines 307-313**: Removed conditional VRF/sequential logic and **forced sequential indices** for initial DKG:

```rust
// ALWAYS use sequential indices during initial DKG to ensure consistency
// VRF indices will be used during refresh operations when all nodes have permanent indices
info!(
    "🔍 [DKG] Using sequential indices 1..={} for initial DKG to ensure all nodes use the same scheme",
    self.total_nodes
);
let shares = self.generate_shares(&polynomial)?;
```

**Lines 746-802**: Fixed `get_node_index()` to use sorted position during initial DKG:

```rust
fn get_node_index(&self, node_manager: Box<dyn NodeMembership>) -> usize {
    // Check DKG status
    match self.status {
        DKGStatus::Completed => {
            // DKG is complete - use permanent index if available
            if let Some(permanent_index) = self.my_permanent_index {
                return permanent_index;
            }
        }
        _ => {
            // DKG not yet complete - use sorted position for consistency
            info!("🔍 [DKG] DKG not yet complete - using sorted position (ignoring any VRF permanent index)");
        }
    }
    
    // Calculate index based on sorted position
    let mut ids: Vec<String> = node_manager.get_active_nodes().into_iter().map(|p| p.to_string()).collect();
    ids.sort();
    let index = ids.iter().position(|id| id == &self.id).map(|i| i + 1).unwrap_or(1);
    index
}
```

**Key Change**: The function now checks DKG status. During initial DKG (before `Completed` status), it **ignores any VRF permanent index** and uses sorted position instead. This ensures share lookups use the same indices as share generation.

**Lines 614-648**: Added enhanced logging to detect indexing mismatches:

```rust
info!(
    "📥 [DKG] Node {} (expecting index {}) received {} shares from node {}",
    self.id, node_index, shares.len(), from
);
info!(
    "🔍 [DKG] Node {} total_nodes={}, commitments count={}",
    self.id, self.total_nodes, commitments.len()
);

let share_indices: Vec<usize> = shares.iter().map(|s| s.index).collect();
info!("🔍 [DKG] Share indices: {:?}", share_indices);

let is_sequential = share_indices.iter().enumerate().all(|(i, &idx)| idx == i + 1);
if is_sequential {
    info!("✅ [DKG] Shares from {} use SEQUENTIAL indices (1, 2, 3, ...)", from);
} else {
    info!("🎲 [DKG] Shares from {} use VRF/CUSTOM indices: {:?}", from, share_indices);
}
```

### Why This Works

1. **Initial DKG**: All nodes now consistently use sequential indices (1, 2, 3, 4) based on sorted peer IDs
2. **Node Index Calculation**: The `get_node_index()` function already returns sorted position when no VRF index is set
3. **Permanent Index Storage**: After DKG completes, each node stores its sequential index as its "permanent index"
4. **Future Operations**: Refresh and new node operations can still use VRF indices once all permanent indices are established

### Expected Behavior After Fix

All 4 nodes will:
1. Generate shares for sequential indices `[1, 2, 3, 4]`
2. Find their correct share based on sorted position
3. Successfully verify all shares from all other nodes
4. Achieve 16/16 successful validations
5. Complete DKG successfully

## Testing

Run the DKG test again and verify:
- ✅ All nodes log: `Using sequential indices 1..=4 for initial DKG`
- ✅ All nodes log: `Shares from X use SEQUENTIAL indices (1, 2, 3, ...)`
- ✅ Validations show all `true`: `{"node1": [true, true, true], "node2": [true, true, true], ...}`
- ✅ DKG completes: `DKG Complete - have 16 validations and 4 shares`

## VRF Indices - Still Used

VRF indices are still used in:
- **New Node Join**: When a node joins an existing network, it gets a VRF-generated random index
- **Refresh Operations**: After initial DKG, refresh uses the permanent indices (which could include VRF indices from joined nodes)

The key insight: **Initial DKG needs deterministic, consistent indices**, so sequential is the right choice.

