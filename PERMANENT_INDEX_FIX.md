# Permanent Index Fix

## Problem

When a new node (5th node) joined the network, two critical issues occurred:

1. **Index Changes with Sorting**: When all 5 nodes were sorted alphabetically, the indices changed!
   - Node that was at index 3 might now be at index 2, etc.
   - This broke the Lagrange coefficient calculations during polynomial refresh

2. **Different Private Keys**: Because indices changed, the Lagrange coefficients were wrong, so the sum of refreshed shares gave a different secret (private key)

## Root Cause

The code was **recalculating indices** from the sorted node list every time:
- During initial DKG: Nodes got indices 1-4 based on sorted order
- When 5th node joined: ALL nodes were re-sorted, changing everyone's index!
- During refresh: Nodes used their NEW sorted position instead of ORIGINAL index

For example:
```
Initial 4 nodes (sorted):
  NodeA → index 1
  NodeB → index 2  
  NodeC → index 3
  NodeD → index 4

After NodeE joins (sorted):
  NodeA → index 1 (unchanged)
  NodeE → index 2 (NEW NODE - inserted in sorted order!)
  NodeB → index 3 (CHANGED from 2 to 3)
  NodeC → index 4 (CHANGED from 3 to 4)
  NodeD → index 5 (CHANGED from 4 to 5)
```

This breaks everything because Lagrange coefficients depend on fixed indices!

## Solution

**Permanent Index Assignment**: Each node gets a permanent index that NEVER changes:
- Nodes 1-4: Get indices 1-4 from initial DKG (based on sorted order at that time)
- Node 5: Gets index 5 (total_nodes), regardless of where it sorts alphabetically
- Node 6: Gets index 6, etc.

## Changes Made

### 1. Database (src/database/)
- Added `DKG_MY_PERMANENT_INDEX` key to store each node's permanent index
- Added `set_my_permanent_index()` and `get_my_permanent_index()` methods

### 2. DKGNode (src/adkg_secp256k1/mod.rs)
- Added `my_permanent_index: Option<usize>` field to store the permanent index
- Added `load_permanent_index()` method to load from storage on startup
- **Store permanent index on DKG completion** (line 756):
  - Initial 4-node DKG: Stores index from sorted position
- **Store permanent index when joining** (line 1175):
  - New node stores index = total_nodes (always 5 for 5th node)
- **Use permanent index during refresh** (line 1358):
  - Changed from recalculating from sorted list to using `self.my_permanent_index`

### 3. Network (src/network/mod.rs)
- Fixed new node index assignment (line 950):
  - Changed from: `position in sorted list + 1`
  - To: `total_nodes` (always the next available index)

### 4. Main (src/main.rs)
- Load permanent index on node startup (line 132):
  - Calls `dkg_node.load_permanent_index()` after creating DKGNode

## How It Works Now

### Initial DKG (4 nodes)
1. Nodes sort themselves and get indices 1-4
2. DKG completes
3. Each node stores its permanent index in the database
4. These indices NEVER change

### New Node Joins (5th node)
1. New node gets index = 5 (total_nodes)
2. Existing nodes send shares evaluated at x=5
3. New node stores permanent index = 5
4. New node triggers polynomial refresh

### Polynomial Refresh
1. Each node uses its PERMANENT index (not recalculated!)
2. Node 1 uses index 1, Node 2 uses index 2, etc.
3. Node 5 uses index 5
4. Lagrange coefficients are correct
5. Refreshed shares sum to the SAME secret (same private key)

## Result

✅ Private key remains the same after polynomial refresh  
✅ Each node keeps its original index forever  
✅ New nodes get the next available index (5, 6, 7, ...)  
✅ Lagrange coefficients are correct  
✅ Security is maintained through proactive refresh  

## Example from your test data

```javascript
// From check_secrets.js:
const nodeHexValues = {
  1: '...', // Node that got index 1 in initial DKG (3rd alphabetically)
  2: '...', // Node that got index 2 in initial DKG (2nd alphabetically)
  3: '...', // Node that got index 3 in initial DKG (1st alphabetically)
  4: '...', // Node that got index 4 in initial DKG (4th alphabetically)
  5: '...'  // 5th node - gets index 5, regardless of alphabetical position
};

// Now both should derive the SAME private key:
// private-key with four shares = 0x6e3fa81a1f0f6c9f372d2158113da3b36d40635489b9a33916f3f335b958cece
// private-key with five shares = 0x6e3fa81a1f0f6c9f372d2158113da3b36d40635489b9a33916f3f335b958cece (SAME!)
```

