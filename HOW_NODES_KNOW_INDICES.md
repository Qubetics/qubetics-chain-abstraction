# How Nodes Know Each Other's Permanent Indices

## TL;DR

**Nodes DON'T need to know each other's permanent indices!** 

Each node only knows its **own permanent index**, and the system uses a clever broadcast mechanism where:
1. Nodes broadcast shares for **ALL indices** (1, 2, 3, 4, 5...)
2. Each receiving node picks the share matching **its own permanent index**

---

## Detailed Explanation

### Phase 1: Initial DKG (4 nodes)

```
┌─────────────────────────────────────────────────────────────┐
│ All 4 nodes sort the peer list identically                 │
└─────────────────────────────────────────────────────────────┘
                           ↓
        all_nodes = [NodeA, NodeB, NodeC, NodeD]
                           ↓
    Everyone agrees on the same index assignment:
        NodeA → index 1
        NodeB → index 2
        NodeC → index 3
        NodeD → index 4
                           ↓
    Each node stores ONLY its own permanent index locally
```

**Key Point**: All nodes arrive at the same sorted order deterministically, so they all agree on the index assignment without communication!

---

### Phase 2: New Node Joins (5th node)

```
┌─────────────────────────────────────────────────────────────┐
│ New node broadcasts: "I am index 5"                        │
└─────────────────────────────────────────────────────────────┘

NewNodeJoined {
    new_node_id: "NodeE",
    new_node_index: 5  ← Explicitly announces its index
}
                           ↓
    Existing nodes receive this message
                           ↓
    They generate share for index=5 (evaluating polynomial at x=5)
                           ↓
    They send it directly to NodeE
```

**Key Point**: The new node explicitly announces its index, so existing nodes know it has index 5 (but they don't need to remember this mapping long-term).

---

### Phase 3: Polynomial Refresh - The Clever Part!

```
Each node independently:
┌─────────────────────────────────────────────────────────────┐
│ 1. Reads its OWN permanent index from storage              │
│    (e.g., NodeA knows: my_permanent_index = 1)             │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Generates refresh polynomial using its permanent index  │
│    Gi(x) = Si * pi(0) + zero_polynomial(x)                 │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Evaluates polynomial at ALL indices: 1, 2, 3, 4, 5     │
│    Creates shares: [Share(1), Share(2), ... Share(5)]     │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Broadcasts ALL shares to everyone!                      │
│                                                             │
│    RefreshShare {                                          │
│        from: "NodeA",                                      │
│        shares: [                                           │
│            KeyShare { index: 1, value: ... },             │
│            KeyShare { index: 2, value: ... },             │
│            KeyShare { index: 3, value: ... },             │
│            KeyShare { index: 4, value: ... },             │
│            KeyShare { index: 5, value: ... }              │
│        ]                                                   │
│    }                                                       │
└─────────────────────────────────────────────────────────────┘

Each receiving node:
┌─────────────────────────────────────────────────────────────┐
│ 1. Reads its OWN permanent index                           │
│    (e.g., NodeE knows: my_permanent_index = 5)             │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Filters the broadcast to find its own share             │
│                                                             │
│    let my_share = shares.iter()                            │
│        .find(|s| s.index == my_permanent_index)            │
│                                                             │
│    NodeE picks: KeyShare { index: 5, value: ... }         │
└─────────────────────────────────────────────────────────────┘
```

---

## Code Flow

### Initial DKG - Determining Permanent Index

```rust:src/adkg_secp256k1/mod.rs
// In generate_group_key() during initial DKG:
fn get_node_index(&self, node_manager: Box<dyn NodeMembership>) -> usize {
    let mut ids: Vec<String> = node_manager
        .get_active_nodes()
        .into_iter()
        .map(|p| p.to_string())
        .collect();
    ids.sort();  // ← All nodes do the same sort
    
    ids.iter()
        .position(|id| id == &self.id)
        .map(|i| i + 1)  // ← 1-based indexing
        .unwrap_or(1)
}

// Store permanent index after DKG completes:
self.storage.set_my_permanent_index(node_index).await?;
self.my_permanent_index = Some(node_index);
```

### New Node - Announcing Index

```rust:src/adkg_secp256k1/mod.rs
pub async fn request_shares_as_new_node(&self, node_index: usize) -> Result<()> {
    let msg = DKGMessage::NewNodeJoined {
        new_node_id: self.id.clone(),
        new_node_index: node_index,  // ← Tells everyone
    };
    self.broadcast(MSG_TOPIC_DKG, &msg_bytes).await?;
    Ok(())
}
```

### Refresh - Using Permanent Index

```rust:src/adkg_secp256k1/mod.rs
// In execute_polynomial_refresh():
let my_index = self.my_permanent_index
    .ok_or_else(|| anyhow!("Permanent index not set"))?;

let refresh_polynomial = self.generate_refresh_polynomial(my_index, &all_indices).await?;

// Generates shares for ALL indices (1..=total_nodes)
let refresh_shares = self.generate_shares(&refresh_polynomial)?;

// Broadcasts ALL shares
let msg = DKGMessage::RefreshShare {
    from: self.id.clone(),
    shares: refresh_shares,  // Contains shares for indices 1-5
    commitments: refresh_commitments,
};

// In handle_refresh_share():
let my_index = self.my_permanent_index
    .ok_or_else(|| anyhow!("Permanent index not set"))?;

// Each node picks its own share
let my_refresh_share = shares.iter()
    .find(|s| s.index == my_index)  // ← Self-service!
    .ok_or_else(|| anyhow!("No refresh share found"))?;
```

---

## Why This Design Is Brilliant

### ✅ No Central Coordinator
- No single node needs to maintain a global `PeerID → index` mapping
- Each node only needs to know its own permanent index

### ✅ Resilient to Network Topology
- Even if nodes join/leave, permanent indices never change
- No need to synchronize mappings across nodes

### ✅ Simple Broadcast Protocol
- "Broadcast all, take what you need"
- No need for targeted unicast messages during refresh

### ✅ Deterministic Agreement
- All nodes agree on initial indices through identical sorting
- New nodes explicitly announce their index

---

## Summary

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Q: How do nodes know each other's permanent indices?       │
│                                                              │
│  A: THEY DON'T! (and don't need to)                        │
│                                                              │
│  Each node only knows:                                      │
│    1. Its OWN permanent index (stored in database)          │
│    2. The total number of nodes (from node_manager)         │
│                                                              │
│  During operations:                                          │
│    • Generate shares for ALL possible indices (1..n)        │
│    • Broadcast ALL shares                                   │
│    • Each node picks the share matching its own index       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

This design elegantly solves the distributed coordination problem without requiring any global state synchronization!

