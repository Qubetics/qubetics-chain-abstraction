# Vault Address Changing Bug - Critical Fix

## Problem Summary

The vault address was changing every time a new node joined the network, even though we had already implemented separate storage for "original commitments" that should remain constant.

## Root Cause

The bug was in the `handle_new_node_share_received()` function at lines 1296-1303.

### What Was Happening:

1. **Initial DKG (4 nodes)**:
   - Nodes 1-4 complete DKG
   - Original commitments are stored: `{index_1, index_2, index_3, index_4}`
   - Vault address calculated from these 4 commitments: `0x3886f3030198514faeb6a5ecea5b082fafb8fea1`

2. **Node 5 Joins**:
   - All nodes (1-5) participate in refresh
   - Each node receives shares from all 5 nodes
   - The code builds a new `commitments_map` containing: `{index_1, index_2, index_3, index_4, index_5}`
   - **BUG**: The code then **OVERWRITES** the original commitments with this new map containing 5 nodes!
   - Vault address now calculated from 5 commitments: `0x3de8ec564f6e469ef24d12ef7abf8f2655364216` ❌

3. **Result**: 
   - Vault address changes
   - Funds sent to the old vault address are lost
   - Signature recovery derives a different address (the new vault)

## The Fix

### Before (Buggy Code):
```rust
// Store all commitments as ORIGINAL commitments (these will never change)
// NOTE: commitments_map already uses index-based keys (index_1, index_2, etc.)
info!("🏦 [NEW_NODE] Storing original commitments for permanent vault derivation...");
for (index_key, comms) in commitments_map.iter() {
    if let Err(e) = self.storage.store_original_commitments(index_key, comms).await {
        warn!("⚠️ [NEW_NODE] Failed to store original commitments for {}: {}", index_key, e);
    } else {
        info!("✅ [NEW_NODE] Stored original commitments for {}", index_key);
    }
}
info!("🏦 [NEW_NODE] All original commitments stored successfully");
```

**Problem**: This code runs for ALL nodes (both existing and new), causing existing nodes to overwrite their original commitments.

### After (Fixed Code):
```rust
// Store original commitments ONLY if they don't already exist
// This prevents overwriting the original vault commitments when new nodes join
let existing_originals = self.storage.get_all_original_commitments().await?;
if existing_originals.is_empty() {
    // This is the first DKG for this node - store as original commitments
    info!("🏦 [NEW_NODE] Storing original commitments for permanent vault derivation (first DKG)...");
    for (index_key, comms) in commitments_map.iter() {
        if let Err(e) = self.storage.store_original_commitments(index_key, comms).await {
            warn!("⚠️ [NEW_NODE] Failed to store original commitments for {}: {}", index_key, e);
        } else {
            info!("✅ [NEW_NODE] Stored original commitments for {}", index_key);
        }
    }
    info!("🏦 [NEW_NODE] All original commitments stored successfully");
} else {
    // Already have original commitments - don't overwrite them
    info!("🏦 [NEW_NODE] Original commitments already exist ({} sets) - preserving them", existing_originals.len());
    info!("🏦 [NEW_NODE] Current commitments updated, but vault address remains unchanged");
}
```

**Solution**: Check if original commitments already exist. If they do, preserve them. Only new nodes (with empty original commitments) store the current commitments as their "original" ones.

## Expected Behavior After Fix

1. **Initial DKG (4 nodes)**:
   - Nodes 1-4 complete DKG
   - Original commitments stored: `{index_1, index_2, index_3, index_4}`
   - Vault address: `0x3886f3030198514faeb6a5ecea5b082fafb8fea1`

2. **Node 5 Joins**:
   - **Existing nodes (1-4)**: Detect they already have original commitments → preserve them ✅
   - **New node (5)**: Has no original commitments → stores current set as original
   - Vault address for nodes 1-4: `0x3886f3030198514faeb6a5ecea5b082fafb8fea1` ✅ (unchanged)
   - Vault address for node 5: Calculated from the current active set

3. **Signing**:
   - All nodes use their respective original commitments for vault derivation
   - Nodes 1-4 derive the same vault address
   - Signature recovery works correctly

## Testing

To verify this fix:

1. Start nodes 1-4 and complete initial DKG
2. Note the vault address from logs
3. Add node 5 and complete refresh
4. Check that nodes 1-4 still show the SAME vault address
5. Perform a signing operation
6. Verify that the signature recovers to the correct vault address

## Files Changed

- `/data/qubetics-chain-abstraction/src/adkg_secp256k1/mod.rs` (lines 1294-1312)

## Build

```bash
cargo build --release
```

Binary: `target/release/mpc-node` (36MB)

## Related Issues

This fix completes the vault persistence work:
1. ✅ Separate storage for original commitments (previous fix)
2. ✅ Prevent overwriting original commitments when nodes join (this fix)
3. ✅ Consistent numerical sorting for commitment keys
4. ✅ Proper sender index tracking for commitment storage

The vault address should now remain permanently constant after the initial DKG, regardless of node joins or refresh operations.

