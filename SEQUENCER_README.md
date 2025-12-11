# Contract Transaction Sequencer

## Overview

The Contract Transaction Sequencer ensures that all nodes in the MPC network process contract transactions **sequentially** and **synchronously**. This prevents:

- **VRF Round Overlaps**: Without synchronization, different nodes might process different transactions simultaneously, causing VRF rounds to overlap and produce invalid signatures
- **Nonce Collisions**: Sequential processing ensures transactions are executed in order, preventing nonce conflicts
- **State Inconsistencies**: All nodes process the same transaction at the same time, maintaining network-wide consistency

## Architecture

### Key Components

1. **`ContractTransactionSequencer`** (`src/network/sequencer.rs`)
   - Manages the FCFS (First Come First Served) queue
   - Tracks synchronization state across nodes
   - Handles consensus and confirmation logic

2. **Event Loop** (`src/network/transport/event_loop.rs`)
   - Main processing loop that coordinates transaction execution
   - Integrates with `tokio::select!` to handle multiple async operations

3. **Gossipsub Messages** (`src/types/messaging.rs`)
   - `SequencerSync` messages for coordinating state across nodes
   - Topic: `sequencer-sync`

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRANSACTION LIFECYCLE                         │
└─────────────────────────────────────────────────────────────────┘

1. SUBMISSION
   ┌─────────────┐
   │ Transaction │
   │   Request   │
   └──────┬──────┘
          │
          ▼
   ┌─────────────────┐
   │  submit()       │
   │  - Assigns seq#  │
   │  - Adds to queue │
   └──────┬───────────┘
          │
          ▼
   ┌─────────────────┐
   │ pending_requests│
   │   (VecDeque)    │
   └─────────────────┘

2. PROPOSAL PHASE
   ┌─────────────────────────────┐
   │ get_next_request()          │
   │ - Checks if previous        │
   │   confirmed                  │
   │ - Pops oldest from queue    │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ propose_transaction()       │
   │ - Sets current_processing   │
   │ - Clears agreed/confirmed   │
   │ - Adds self to agreed_nodes │
   │ - Broadcasts "proposed"     │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Gossipsub: "proposed"      │
   │ All nodes receive & agree   │
   └──────────┬──────────────────┘

3. CONSENSUS PHASE
   ┌─────────────────────────────┐
   │ has_consensus() loop        │
   │ - Checks agreed_nodes.len() │
   │ - Needs: total_nodes/2 + 1  │
   │ - Yields to tokio::select! │
   │   to process messages       │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ handle_sync_message()       │
   │ - Receives "proposed"        │
   │ - Adds node to agreed_nodes │
   │ - If has tx in queue,       │
   │   sets current_processing   │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Consensus Reached?          │
   │ agreed_nodes >= threshold   │
   └──────────┬──────────────────┘
              │ YES
              ▼
   ┌─────────────────────────────┐
   │ mark_processing()           │
   │ - Broadcasts "processing"   │
   └──────────┬──────────────────┘

4. PROCESSING PHASE
   ┌─────────────────────────────┐
   │ get_current_request()       │
   │ - From cache (if proposed) │
   │ - From queue (if received) │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ process_contract_transaction│
   │ - Acquires processing lock  │
   │ - Executes transaction      │
   │ - Only one at a time        │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ mark_completed()            │
   │ - Adds self to confirmed    │
   │ - Broadcasts "completed"    │
   └──────────┬──────────────────┘

5. CONFIRMATION PHASE
   ┌─────────────────────────────┐
   │ handle_sync_message()       │
   │ - Receives "completed"      │
   │ - Adds node to confirmed    │
   │ - Checks if all confirmed   │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ All Nodes Confirmed?        │
   │ confirmed_nodes == total    │
   └──────────┬──────────────────┘
              │ YES
              ▼
   ┌─────────────────────────────┐
   │ Clear State                 │
   │ - current_processing = None │
   │ - Clear agreed/confirmed    │
   │ - Clear cache               │
   │ - is_confirmed = false      │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Ready for Next Transaction  │
   └─────────────────────────────┘
```

## Detailed Flow

### 1. Transaction Submission

When a contract transaction request is received:

```rust
sequencer.submit(request).await
```

**What happens:**
- Assigns a global sequence number (`global_sequence++`)
- Adds request to `pending_requests` queue (FCFS order)
- All nodes receive the same request via gossip and add to their queues

**Key Point**: All nodes must have the same requests in the same order.

### 2. Getting Next Request

The event loop continuously checks for the next request:

```rust
if let Some(request) = sequencer.get_next_request().await {
    // Process it
}
```

**Conditions for `get_next_request()` to return a request:**
- `current_processing` is `None` (nothing currently processing), OR
- `current_processing` is set but `is_confirmed = true` (previous transaction confirmed by all nodes)

**If previous transaction not confirmed:**
- Returns `None`
- Logs: "⏳ Waiting for confirmation: current_tx=..., confirmed_nodes=X/4"

### 3. Proposing a Transaction

When a request is retrieved:

```rust
sequencer.cache_current_request(request.clone()).await;  // Cache it
sequencer.propose_transaction(&tx_id, sequence).await
```

**What `propose_transaction()` does:**
- Sets `current_processing = Some(tx_id)`
- Sets `current_sequence = sequence`
- Clears `agreed_nodes` and `confirmed_nodes`
- Sets `is_confirmed = false`
- Adds self to `agreed_nodes`
- Broadcasts `SequencerSync { state: "proposed" }` via gossipsub

**Important**: The request is cached so it can be retrieved later even if removed from the queue.

### 4. Consensus Building

**On the proposing node:**
- Enters a loop checking `has_consensus()` every 100ms
- Yields control to `tokio::select!` between checks to process incoming messages
- Continues until `agreed_nodes.len() >= threshold` (majority: `total_nodes/2 + 1`)

**On receiving nodes:**
- Receives `SequencerSync { state: "proposed" }` message
- Calls `handle_sync_message()`
- If `current_processing` is `None` and has the transaction in queue:
  - Sets `current_processing = Some(tx_id)`
  - Adds self to `agreed_nodes`
- If `current_processing` already matches:
  - Adds the sender to `agreed_nodes`

**Consensus Check:**
```rust
let threshold = (total_nodes / 2) + 1;
let has_consensus = agreed_nodes.len() >= threshold;
```

### 5. Processing

Once consensus is reached:

```rust
if sequencer.has_consensus().await {
    let request = sequencer.get_current_request().await;  // From cache or queue
    sequencer.mark_processing(&tx_id).await;
    process_contract_transaction(request).await;
}
```

**What `mark_processing()` does:**
- Broadcasts `SequencerSync { state: "processing" }`
- Other nodes can track that processing has started

**Processing:**
- Acquires a processing lock (ensures only one transaction at a time)
- Executes the contract transaction
- Lock is held until processing completes

### 6. Completion and Confirmation

After processing:

```rust
sequencer.mark_completed(&tx_id).await
```

**What `mark_completed()` does:**
- Adds self to `confirmed_nodes`
- Broadcasts `SequencerSync { state: "completed" }`
- If `confirmed_nodes.len() >= total_nodes`:
  - Clears `current_processing = None`
  - Clears `agreed_nodes` and `confirmed_nodes`
  - Clears cached request
  - Sets `is_confirmed = false` (for next transaction)

**On receiving nodes:**
- Receives `SequencerSync { state: "completed" }` message
- Calls `handle_sync_message()`
- Adds sender to `confirmed_nodes`
- If `confirmed_nodes.len() >= total_nodes`:
  - Clears state (same as above)

### 7. Next Transaction

Once all nodes confirm:
- `current_processing = None`
- `is_confirmed = false`
- `get_next_request()` can now return the next transaction from the queue
- Process repeats from step 2

## State Management

### `SequencerSyncState`

```rust
struct SequencerSyncState {
    current_processing: Option<String>,      // Currently processing tx_id
    current_sequence: u64,                    // Sequence of current transaction
    global_sequence: u64,                    // Global counter for FCFS ordering
    agreed_nodes: HashSet<String>,           // Nodes that agreed to process current tx
    confirmed_nodes: HashSet<String>,        // Nodes that confirmed completion
    total_nodes: usize,                      // Total active nodes (for threshold)
    is_confirmed: bool,                      // Whether current tx is confirmed by all
}
```

### Request Cache

```rust
current_request_cache: Arc<RwLock<Option<ContractTransactionRequest>>>
```

**Purpose**: Stores the request when a node proposes it, so it can be retrieved after consensus even though it was removed from the queue.

## Message Types

### `SequencerSync` Message

```rust
GossipsubMessage::SequencerSync {
    transaction_id: String,    // The transaction ID
    sequence: u64,             // Sequence number
    node_id: String,           // Node that sent this message
    state: String,             // "proposed", "processing", or "completed"
}
```

**Topic**: `sequencer-sync`

**States:**
- `"proposed"`: Node proposes this transaction for processing
- `"processing"`: Node has started processing this transaction
- `"completed"`: Node has completed processing this transaction

## Key Design Decisions

### 1. FCFS (First Come First Served) Ordering

- Uses `VecDeque` to maintain insertion order
- Each request gets a `sequence` number when submitted
- All nodes process in the same order

### 2. Majority Consensus

- Requires `(total_nodes / 2) + 1` nodes to agree before processing
- Prevents a single node from dictating the order
- Ensures network-wide agreement

### 3. All-Node Confirmation

- Requires **ALL** nodes to confirm completion before moving to next transaction
- Prevents race conditions where one node starts next transaction while others are still processing
- Ensures complete synchronization

### 4. Non-Blocking Consensus Loop

- Consensus check yields to `tokio::select!` frequently
- Allows incoming messages to be processed
- Prevents deadlocks where nodes can't receive agreement messages

### 5. Request Caching

- When a node proposes, it caches the request
- When consensus is reached, it retrieves from cache (not queue)
- Handles case where proposer already removed request from queue

## Error Handling

### Consensus Timeout

If consensus is not reached within 100 iterations (10 seconds):
- Logs warning: "⚠️ Consensus timeout, proceeding anyway"
- Attempts to get request and process anyway
- Prevents indefinite blocking

### Missing Request

If consensus is reached but request not found:
- Logs warning: "⚠️ Consensus reached but request not found"
- Retries after short delay
- Eventually times out and continues

## Example Flow

**Scenario**: 4 nodes, 1 transaction in queue

1. **Node 1** gets request, proposes it
   - Broadcasts "proposed"
   - `agreed_nodes = {Node1}`

2. **Nodes 2, 3, 4** receive "proposed"
   - Each adds Node1 to `agreed_nodes`
   - Each adds themselves to `agreed_nodes`
   - `agreed_nodes = {Node1, Node2, Node3, Node4}`

3. **All nodes** check `has_consensus()`
   - `agreed_nodes.len() = 4 >= 3` (threshold) ✅
   - Consensus reached!

4. **All nodes** get request and process it
   - Each broadcasts "processing"
   - Each executes transaction
   - Each broadcasts "completed"

5. **All nodes** receive "completed" messages
   - Each adds sender to `confirmed_nodes`
   - When `confirmed_nodes.len() = 4`:
     - Clear state
     - Ready for next transaction

## Files

- **`src/network/sequencer.rs`**: Core sequencer logic
- **`src/network/transport/event_loop.rs`**: Main event loop integration
- **`src/types/messaging.rs`**: Message type definitions
- **`src/network/transport/types.rs`**: Gossipsub topic definitions
- **`src/network/rpc/gossipsub_handler.rs`**: Message handler

## Debugging

### Common Issues

1. **"Waiting for consensus" but consensus never reached**
   - Check if all nodes are receiving "proposed" messages
   - Verify `total_nodes` is correct
   - Check network connectivity

2. **"Waiting for confirmation" indefinitely**
   - Check if all nodes are broadcasting "completed"
   - Verify `confirmed_nodes` is being updated
   - Check if nodes are processing the transaction

3. **"Request not found in queue"**
   - Check if request was cached when proposed
   - Verify `get_current_request()` checks cache first

### Logs to Watch

- `🎯 [SEQUENCER] Got next request`: Request retrieved
- `📤 [SEQUENCER] Proposed tx_id=...`: Transaction proposed
- `⏳ [SEQUENCER] [CONSENSUS] Waiting for consensus`: Building consensus
- `✅ [SEQUENCER] [CONSENSUS] Consensus reached`: Consensus achieved
- `🚀 [SEQUENCER] Starting synchronized processing`: Processing started
- `✅ [SEQUENCER] Marked tx_id=... as completed`: Processing completed
- `🎉 [SEQUENCER] ALL nodes confirmed`: Ready for next transaction

