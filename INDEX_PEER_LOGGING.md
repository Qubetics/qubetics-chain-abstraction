# Index => PeerId Logging Enhancement

## Summary

Added comprehensive **Index => PeerId** mapping logs throughout the signing process. Now you can clearly see which DKG index corresponds to which PeerId and which share value at every step.

## New Log Category: `[INDEX-PEER-DEBUG]`

This new log prefix shows explicit **Index => PeerId** mappings with share values.

## What's Logged

### 1. At Signature Storage
When each node stores its signature, it logs:
```
💾 [INDEX-PEER-DEBUG] Stored signature for Index 1 => PeerId 12D3KooW... (s-share: 0xabcd...)
```

For different transaction types:
- **Regular transactions**: `Index {} => PeerId {} (s-share: 0x{})`
- **Contract transactions**: `Contract: Stored signature for Index {} => PeerId {} (s-share: 0x{})`
- **Bitcoin transactions**: `BTC: Stored signature for Index {} => PeerId {} input {} (s-share: 0x{})`

### 2. Before Aggregation
Shows the index mapping for the round:
```
🔢 [INDEX-PEER-DEBUG] Round 0 - Index => PeerId mapping for aggregation:
🔢 [INDEX-PEER-DEBUG]   Index 1 => 12D3KooWAbc...
🔢 [INDEX-PEER-DEBUG]   Index 2 => 12D3KooWDef...
🔢 [INDEX-PEER-DEBUG]   Index 3 => 12D3KooWGhi...
```

### 3. During Aggregation
Multiple detailed mappings:

**Initial mapping:**
```
🔢 [INDEX-PEER-DEBUG] Index => PeerId mapping:
🔢 [INDEX-PEER-DEBUG]   Index 1 => PeerId 12D3KooWAbc...
🔢 [INDEX-PEER-DEBUG]   Index 2 => PeerId 12D3KooWDef...
```

**With share values:**
```
🔍 [SIGNING-DEBUG] Index 1 => PeerId 12D3KooWAbc... => s-share: 0xabcd...
🔍 [SIGNING-DEBUG] Index 2 => PeerId 12D3KooWDef... => s-share: 0xef01...
```

**Complete mapping table:**
```
🔢 [INDEX-PEER-DEBUG] Complete Index => PeerId => Share mapping:
🔢 [INDEX-PEER-DEBUG]   Index 1 => 12D3KooWAbc... => 0xabcd...
🔢 [INDEX-PEER-DEBUG]   Index 2 => 12D3KooWDef... => 0xef01...
🔢 [INDEX-PEER-DEBUG]   Index 3 => 12D3KooWGhi... => 0x2345...
```

## How to Use

### Filter logs by category:
```bash
# See all Index => PeerId mappings
grep "INDEX-PEER-DEBUG" node.log

# See signature storage with index mapping
grep "Stored signature for Index" node.log

# See complete mapping tables
grep "Complete Index => PeerId => Share" node.log
```

### Example Complete Flow:
```
# 1. Node calculates its index
🔢 [DKG-INDEX-DEBUG] Available nodes and their DKG indices:
🔢 [DKG-INDEX-DEBUG]   12D3KooWAbc... -> index 1
🔢 [DKG-INDEX-DEBUG]   12D3KooWDef... -> index 2

# 2. Node signs with its secret key
🔐 [SIGNING-DEBUG] Node 12D3KooWAbc... signing key (hex): 0x123abc...
🔢 [SIGNING-DEBUG] Node 12D3KooWAbc... DKG index: 1

# 3. Stores signature with index mapping
💾 [INDEX-PEER-DEBUG] Stored signature for Index 1 => PeerId 12D3KooWAbc... (s-share: 0xdef456...)

# 4. Pre-aggregation shows selected indices
🔢 [INDEX-PEER-DEBUG] Round 0 - Index => PeerId mapping for aggregation:
🔢 [INDEX-PEER-DEBUG]   Index 1 => 12D3KooWAbc...

# 5. During aggregation, shows complete mapping with shares
🔢 [INDEX-PEER-DEBUG] Complete Index => PeerId => Share mapping:
🔢 [INDEX-PEER-DEBUG]   Index 1 => 12D3KooWAbc... => 0xdef456...
```

## Testing Checklist

Use these logs to verify:

✅ **Index Consistency**: All nodes calculate the same index for each peer
- Check: `[DKG-INDEX-DEBUG] Available nodes and their DKG indices`

✅ **Share Storage**: Each node stores its share with correct index
- Check: `[INDEX-PEER-DEBUG] Stored signature for Index`

✅ **Aggregation Mapping**: The aggregator uses correct index => peer mapping
- Check: `[INDEX-PEER-DEBUG] Round X - Index => PeerId mapping`

✅ **Share Values**: The s-values are correctly associated with indices
- Check: `[INDEX-PEER-DEBUG] Complete Index => PeerId => Share mapping`

## Files Modified

- `src/signing/mod.rs`:
  - Enhanced `sign_message` - added index => peerId logging at storage
  - Enhanced `sign_contract_message` - added index => peerId logging at storage
  - Enhanced `sign_bitcoin_message` - added index => peerId logging at storage
  - Enhanced `aggregate_signatures` - added detailed index => peerId => share mapping
  - Added index => peerId logging before aggregation

## Security Warning ⚠️

These logs expose:
- Secret shares (s-values)
- Index to node mappings
- Complete signature details

**ONLY use in development/testing. MUST be disabled in production!**

