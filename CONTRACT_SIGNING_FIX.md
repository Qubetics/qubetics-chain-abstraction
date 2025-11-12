# Contract Transaction Signing Fix

## Problem
Contract transactions were failing during signing/aggregation. The root cause was that the `sign_contract_message` function was missing critical parameters (`intent_hash` and `transaction_type`) that the working `sign_message` function had.

## Root Cause
When contract transactions were being signed, they were stored in `pending_transactions` with `None` values for both `intent_hash` and `transaction_type`:

```rust
pending_transactions.insert(round, (chain_tx, tx_bytes.clone(), None, None));
```

This caused issues during reconstruction and aggregation because the system couldn't properly identify and process the contract transaction without these critical metadata fields.

## Solution
Updated the `sign_contract_message` function to match the signature and behavior of the working `sign_message` function:

### Changes Made:

1. **Updated function signature** (`src/signing/mod.rs:1888-1896`):
   - Added `intent_hash: Option<String>` parameter
   - Added `transaction_type: Option<crate::types::TransactionType>` parameter

2. **Updated transaction storage** (`src/signing/mod.rs:2045`):
   - Changed from: `pending_transactions.insert(round, (chain_tx, tx_bytes.clone(), None, None))`
   - Changed to: `pending_transactions.insert(round, (chain_tx, tx_bytes.clone(), intent_hash.clone(), transaction_type.clone()))`

3. **Updated all callers** to pass the new parameters:
   - `src/signing/mod.rs:3453` - execute_contract_call_for_transaction in signing module
   - `src/network/mod.rs:3619` - execute_contract_call_for_transaction in network module  
   - `src/utils/contract.rs:62` - execute_contract_call_for_transaction in contract utils

## Testing
- Code compiles successfully with no errors
- All existing warnings remain unchanged (pre-existing)
- Contract transactions should now be properly signed and aggregated like user-to-vault transactions

## Key Insight
The user-to-vault transaction flow was working correctly because it properly tracked the intent_hash and transaction_type throughout the signing and aggregation process. The contract transaction flow was missing this crucial metadata, which caused failures during reconstruction and execution.

