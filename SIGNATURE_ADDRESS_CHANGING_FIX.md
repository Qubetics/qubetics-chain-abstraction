# Signature Address Changing Bug - Critical Fix

## Problem Summary

The user's derived address (recovered from transaction signatures) was **changing every time**, even though we fixed the vault address persistence issue. This meant that signatures were recovering to different addresses after refresh operations or when new nodes joined.

## Root Cause Analysis

### Issue 1: Vault Address Overwrite (Previously Fixed)
When a new node joined, **existing nodes were overwriting their original commitments** with a new set that included the new node. This caused the vault address to change.

**Fix Applied**: Check if original commitments exist before storing. Only new nodes store their current commitments as "original."

### Issue 2: User-Specific Address Using Current Commitments (NEW BUG - CRITICAL)

**The Real Problem:**

When deriving the user's public key for signing, the system was using **CURRENT commitments** (which change after refresh) instead of **ORIGINAL commitments** (which should remain constant).

**Where it happened:**

1. **`network/mod.rs` line 1413** (GOSSIPSUB message handler):
   ```rust
   dkg_node.derive_user_specific_group_key_from_commitments(tweak_scalar).await
   ```

2. **`network/mod.rs` line 2944** (Direct commitment update):
   ```rust
   dkg_node.derive_user_specific_group_key_from_commitments(tweak_scalar).await
   ```

**Why this caused the problem:**

1. User registers → derive user key from current commitments → store in DB
2. Node 5 joins → refresh happens → commitments update
3. User signs transaction → uses the SAME stored user key (correct)
4. BUT when user registers AGAIN or key is re-derived → uses NEW commitments → DIFFERENT address!

**The signature itself was correct**, but the **public key used to create it changed between operations**.

## The Complete Fix

### 1. Added New Function: `derive_user_specific_group_key_from_original_commitments`

In `/data/qubetics-chain-abstraction/src/adkg_secp256k1/mod.rs` (lines 281-329):

```rust
/// Derive user-specific group key from ORIGINAL DKG commitments (never changes after initial DKG)
/// This ensures the user's derived address remains constant even after refresh operations
pub async fn derive_user_specific_group_key_from_original_commitments(
    &self,
    tweak_scalar: Scalar,
) -> Result<ProjectivePoint> {
    let commitments = self.storage.get_all_original_commitments().await?;
    // ... uses ORIGINAL commitments, not current ones
    // P_user = P_base + T (using original commitments)
    Ok(p_user)
}
```

### 2. Updated User Key Derivation Calls

**In `network/mod.rs` line 1415** (GOSSIPSUB handler):
```rust
// BEFORE (BUGGY):
dkg_node.derive_user_specific_group_key_from_commitments(tweak_scalar).await

// AFTER (FIXED):
dkg_node.derive_user_specific_group_key_from_original_commitments(tweak_scalar).await
```

**In `network/mod.rs` line 2946** (Direct update):
```rust
// BEFORE (BUGGY):
dkg_node.derive_user_specific_group_key_from_commitments(tweak_scalar).await

// AFTER (FIXED):
dkg_node.derive_user_specific_group_key_from_original_commitments(tweak_scalar).await
```

## How It Works Now

### Initial DKG (4 nodes):
1. Nodes 1-4 complete DKG
2. **Original commitments** stored: `{index_1, index_2, index_3, index_4}`
3. Vault address calculated from original commitments: `0xAAA...`
4. User registers with HMAC tweak `t`
5. **User public key** = Sum(original C0s) + t*G
6. **User address** derived from user public key: `0xBBB...`
7. Both stored in DB

### Node 5 Joins + Refresh:
1. Node 5 joins, all nodes participate in refresh
2. **Current commitments** updated to new values (for signing verification)
3. **Original commitments PRESERVED** (unchanged)
4. Vault address: Still `0xAAA...` ✅ (from original commitments)
5. User address: Still `0xBBB...` ✅ (from original commitments)

### User Signs Transaction:
1. Retrieve stored user_group_key from DB
2. Derive user-specific tweaked secret share
3. Sign transaction
4. **Signature recovers to**: `0xBBB...` ✅ (matches stored user address)

### User Re-registers or Key is Re-derived:
1. Calculate user key using **ORIGINAL commitments** + HMAC tweak
2. User address: Still `0xBBB...` ✅ (unchanged)

## Key Principles

### 1. Two Types of Commitments:
- **Original Commitments** (`dkg_original_commitment:index_N`): 
  - Stored ONCE during initial DKG
  - NEVER modified
  - Used for vault and user address derivation
  
- **Current Commitments** (`dkg_commitment:index_N` or `dkg_commitment:refresh_index_N`):
  - Updated during refresh operations
  - Used for signature verification and new secret share calculations
  - Change over time for forward secrecy

### 2. Three Types of Addresses:
- **Vault Address**: Derived from original commitments (no user-specific tweak)
- **User-Specific Address**: Derived from original commitments + user's HMAC tweak
- Both must remain CONSTANT after initial DKG

### 3. Signing Process:
- Uses the user's **tweaked secret share** (derived from DKG share + HMAC tweak)
- The corresponding public key is the **user_group_key** (original commitments + HMAC tweak)
- Signature recovery will always return the user's constant address

## Files Changed

1. `/data/qubetics-chain-abstraction/src/adkg_secp256k1/mod.rs`:
   - Added `derive_user_specific_group_key_from_original_commitments()` (lines 281-329)
   - Fixed `handle_new_node_share_received()` to preserve original commitments (lines 1294-1312)

2. `/data/qubetics-chain-abstraction/src/network/mod.rs`:
   - Updated user key derivation in GOSSIPSUB handler (line 1415)
   - Updated user key derivation in direct update path (line 2946)

## Testing

To verify this fix works:

1. **Start 4 nodes and complete DKG**
2. **Register a user** → note their derived address (e.g., `0xBBB...`)
3. **User signs a transaction** → decode signature → should recover to `0xBBB...`
4. **Add node 5 and complete refresh**
5. **User signs another transaction** → decode signature → should STILL recover to `0xBBB...` ✅
6. **Re-register the same user** → derived address should STILL be `0xBBB...` ✅

## Build

```bash
cargo build --release
```

Binary: `target/release/mpc-node`

## Summary

The issue was that we were deriving user-specific keys from **current** commitments that change during refresh, instead of **original** commitments that remain constant. This caused signature recovery to yield different addresses over time.

**The fix ensures:**
- ✅ Vault address NEVER changes (uses original commitments)
- ✅ User addresses NEVER change (uses original commitments + user HMAC)
- ✅ Signatures always recover to the correct, constant user address
- ✅ Original commitments are never overwritten when nodes join
- ✅ Refresh operations update secret shares without changing public addresses

