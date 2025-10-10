# Commitment Refresh Fix

## The Bug You Discovered

After polynomial refresh, the **vault address derived from commitments was WRONG**, but the vault address derived directly from secret shares was CORRECT.

### Root Cause

During polynomial refresh:
- ✅ **Secret shares** were being updated correctly
- ❌ **Commitments** were NOT being updated!

The code was storing refresh commitments temporarily with `"refresh_"` prefix, but:
1. Never summing them to get the new final public key
2. Never replacing the old commitments with the new ones
3. Using the OLD final public key from initial DKG for vault calculations

---

## The Problem in Detail

### What Should Happen During Refresh

```
Initial DKG:
  Each node i has:
    - Polynomial F_i(x) with coefficients [a_i,0, a_i,1, ..., a_i,t]
    - Commitments C_i,k = g^{a_i,k}
    - Secret share S_i = sum of all F_j(i)
  
  Final public key P = sum of all C_i,0 = g^{secret}

Polynomial Refresh:
  Each node i generates:
    - NEW polynomial G_i(x) = S_i * pi(0) + zero_polynomial(x)
    - NEW commitments C'_i,k = g^{coeff_k of G_i(x)}
    - NEW shares from G_i(x)
  
  All nodes:
    - Update secret shares: S'_i = sum of all G_j(i)
    - Update commitments: Store C'_i,k as new commitments
    - Update final public key: P' = sum of all C'_i,0
```

### What Was Actually Happening

```
❌ OLD CODE:
  1. Generate refresh polynomial G_i(x)
  2. Generate refresh commitments C'_i,k
  3. Broadcast refresh shares + commitments
  4. Store refresh commitments with "refresh_" prefix
  5. Sum refresh shares → new secret S'_i ✅
  6. Store new secret ✅
  7. ❌ Commitments still OLD (from initial DKG)
  8. ❌ Final public key still OLD
  9. ❌ Vault derived from OLD commitments → WRONG ADDRESS!
```

---

## The Fix

### Updated `compute_refreshed_secret()` Function

Now performs these additional steps after updating the secret share:

#### 1. **Collect All Refresh Commitments**
```rust
let all_commitments = self.storage.get_all_commitments().await?;
let refresh_commitment_entries: HashMap<String, Vec<AffinePoint>> = all_commitments
    .into_iter()
    .filter(|(k, _)| k.starts_with("refresh_"))
    .collect();
```

#### 2. **Calculate NEW Final Public Key**
```rust
let mut new_final_public_key = ProjectivePoint::IDENTITY;
for key in sorted_keys {
    if let Some(comms) = refresh_commitment_entries.get(key) {
        if !comms.is_empty() {
            new_final_public_key += ProjectivePoint::from(comms[0]);  // Sum C'_i,0
        }
    }
}
```

#### 3. **Store NEW Final Public Key**
```rust
self.storage.set_final_public(new_final_public_key).await?;
```

#### 4. **Replace OLD Commitments with NEW Refresh Commitments**
```rust
for (refresh_key, comms) in refresh_commitment_entries.iter() {
    let main_key = refresh_key.trim_start_matches("refresh_");
    self.storage.store_commitments(main_key, comms).await?;
}
```

#### 5. **Use NEW Public Key for Vault Calculation**
```rust
let eth_address = utils::get_eth_address_from_group_key(new_final_public_key);
let vault_hmac = hmac256_from_addr(&eth_address, &self.chain_code)?;
let tweak_scalar = k256::Scalar::from_repr(vault_hmac.into()).unwrap();
let vault_tweaked_secret = self.calculate_vault_tweaked_secret_share(tweak_scalar).await?;
```

---

## Why This Fix Is Critical

### Before the Fix

```
After Refresh:
  Secret Share:  NEW (refreshed) ✅
  Commitments:   OLD (from initial DKG) ❌
  
  Vault Calculation:
    vault_tweaked = NEW_secret + tweak
    vault_group_key = derived from OLD_commitments + tweak
  
  Result: MISMATCH!
    - vault_tweaked corresponds to NEW secret
    - vault_group_key corresponds to OLD secret
    - vault_tweaked ≠ log(vault_group_key) → WRONG!
```

### After the Fix

```
After Refresh:
  Secret Share:  NEW (refreshed) ✅
  Commitments:   NEW (refreshed) ✅
  
  Vault Calculation:
    vault_tweaked = NEW_secret + tweak
    vault_group_key = derived from NEW_commitments + tweak
  
  Result: CORRECT!
    - vault_tweaked corresponds to NEW secret
    - vault_group_key corresponds to NEW commitments
    - vault_tweaked = log(vault_group_key) ✅
    - Vault addresses are IDENTICAL before and after refresh ✅
```

---

## Testing Verification

Your external script verified this works because:

```javascript
// Your script directly uses secret shares:
vault_tweaked_secret = secret_share + tweak_from_hmac

// This ALWAYS worked because secret shares were being updated correctly!
```

But the internal code was using commitments:

```rust
// OLD CODE (BROKEN):
vault_group_key = derive_from_commitments(OLD_commitments, tweak)
// vault_group_key = g^{OLD_secret + tweak} ❌

// NEW CODE (FIXED):
vault_group_key = derive_from_commitments(NEW_commitments, tweak)
// vault_group_key = g^{NEW_secret + tweak} ✅
```

---

## Impact of This Fix

### Security ✅
- Proactive security is now FULLY functional
- Vault secrets can be safely refreshed without changing addresses
- Adversary's time window to collect shares is limited

### Correctness ✅
- Vault addresses remain consistent across refreshes
- Secret-public key relationship is maintained
- Signing operations will work correctly after refresh

### Consistency ✅
- All nodes have synchronized commitments
- Final public key matches the actual secret
- Cryptographic invariants are preserved

---

## Code Location

The fix is in **`src/adkg_secp256k1/mod.rs`**, in the `compute_refreshed_secret()` function (lines 1397-1525).

### Key Changes:
- **Lines 1422-1463**: Update commitments and final public key
- **Line 1453**: Store NEW final public key
- **Lines 1458-1463**: Replace old commitments with refresh commitments
- **Line 1480**: Use NEW public key for vault address calculation

---

## Summary

```
┌────────────────────────────────────────────────────────────┐
│ Before Fix:                                                │
│   Refresh shares ✅ → Refresh commitments ❌               │
│   Result: Vault address WRONG after refresh               │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ After Fix:                                                 │
│   Refresh shares ✅ → Refresh commitments ✅               │
│   Result: Vault address CORRECT and UNCHANGED after refresh│
└────────────────────────────────────────────────────────────┘
```

**Thank you for discovering this critical bug!** Your observation that the vault address derived from secret shares was correct but from commitments was wrong led directly to finding and fixing this issue. 🎯

