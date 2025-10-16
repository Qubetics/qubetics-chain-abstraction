# RocksDB Database Synchronization for New Nodes

## Overview

This document describes the database synchronization mechanism implemented for the Qubetics MPC node network. When a new node joins an existing network, it automatically synchronizes all database state from existing peers to ensure data consistency across the network.

## Features

- **Automatic Sync on Join**: New nodes automatically detect when they're joining an existing network and initiate database synchronization
- **Batch Transfer**: Data is transferred in configurable batches (default: 100 entries) to optimize network usage and memory
- **Progress Tracking**: Real-time progress logging with percentage completion
- **Resilient**: Error handling for network failures and corrupted data
- **Non-blocking**: Sync happens asynchronously without blocking other node operations

## Architecture

### Components

1. **Database Export/Import Methods** (`src/database/mod.rs`)
   - `export_all_entries()` - Export all database entries
   - `export_batch()` - Export a specific batch of entries
   - `import_batch()` - Import a batch of entries
   - `count_entries()` - Count total entries for progress tracking

2. **Network Protocol Messages** (`src/types/rpc.rs`)
   - `RPCRequest::RequestDatabaseSync` - Request to start sync
   - `RPCRequest::RequestDatabaseBatch` - Request a specific batch
   - `RPCResponse::DatabaseSyncMetadata` - Metadata about database size
   - `RPCResponse::DatabaseBatch` - Batch data response
   - `DatabaseEntry` - Single key-value pair structure

3. **Network Layer Integration** (`src/network/mod.rs`)
   - `sync_database_from_peer()` - Initiate sync from a peer
   - `handle_database_sync_metadata()` - Handle sync metadata response
   - `handle_database_batch()` - Handle batch data and request next batch
   - `DatabaseSyncState` - Track sync progress

## Workflow

### New Node Joining Network

1. **Node Discovery**
   ```
   New Node → Existing Peer: GetPeerList request
   Existing Peer → New Node: PeerList response
   ```

2. **Database Sync Initiation**
   ```
   New Node detects: No DKG data + Network has > 4 nodes
   New Node → First Peer: RequestDatabaseSync
   First Peer → New Node: DatabaseSyncMetadata (total_entries, batch_size)
   ```

3. **Batch Transfer**
   ```
   Loop until all batches received:
     New Node → Peer: RequestDatabaseBatch (batch_index, batch_size)
     Peer → New Node: DatabaseBatch (entries, is_last_batch)
     New Node: Import batch into local RocksDB
     Update progress (X/Y entries, Z%)
   ```

4. **DKG Share Request**
   ```
   After sync completes:
   New Node → Network: Request DKG shares for new index
   ```

## Configuration

### Batch Size
Default batch size is 100 entries. This can be adjusted by modifying the response in the request handler:

```rust:src/network/mod.rs
RPCRequest::RequestDatabaseSync { requester_id } => {
    let recommended_batch_size = 100; // Adjust this value
    // ...
}
```

### Sync Conditions
A node initiates database sync when:
- It has no DKG data (`!has_dkg_data`)
- The network has more than 4 nodes (`total > 4`)
- It receives a peer list from the network

These conditions can be adjusted in the `handle_swarm_event` method.

## Monitoring

### Log Messages

Database sync produces detailed log messages for monitoring:

```
📦 [DB_SYNC] Starting database sync from peer <peer_id>
📦 [DB_SYNC] Database has X entries, recommending batch size of Y
📊 [DB_SYNC] Progress: 0/X entries (0.00%)
📦 [DB_SYNC] Received batch N with M entries
✅ [DB_SYNC] Successfully imported batch N - Progress: X/Y entries (Z%)
📦 [DB_SYNC] Requested batch N+1/Total
🎉 [DB_SYNC] Database synchronization completed!
📊 [DB_SYNC] Total synced: X entries from peer <peer_id>
```

### State Tracking

The `DatabaseSyncState` struct tracks:
- `in_progress` - Whether sync is currently running
- `source_peer` - Which peer we're syncing from
- `total_entries` - Total entries to sync
- `batch_size` - Size of each batch
- `current_batch` - Current batch index
- `total_batches` - Total number of batches
- `entries_synced` - Number of entries synced so far

## Data Synced

The database sync transfers all RocksDB entries, including:

- **User Registrations**: Ethereum addresses and user data
- **Intent Registry**: Transaction intents and their statuses
- **DKG State**: (Will be refreshed via DKG share request)
- **Consensus Data**: Selected nodes and consensus results
- **Signing State**: Signature rounds and final nodes
- **Reward Data**: Solver rewards and liquidity tracking
- **Peer Indices**: Persistent peer index mappings
- **Transaction Status**: Intent transaction IDs and statuses

## Performance Considerations

1. **Network Bandwidth**: Batching reduces network overhead. Larger batches = fewer round trips but more memory usage per request.

2. **Memory Usage**: Each batch is held in memory during transfer. Default batch size (100 entries) is conservative.

3. **Startup Time**: Sync time depends on database size:
   - 1000 entries @ 100/batch = ~10 requests
   - 10000 entries @ 100/batch = ~100 requests

4. **Consistency**: Data is imported atomically per batch. If sync fails mid-way, the node will have partial data but can re-sync.

## Error Handling

- **Network Failures**: Sync requests timeout after standard RPC timeout. Node can retry by restarting.
- **Corrupted Data**: Deserialization errors are logged and sync aborts.
- **Peer Unavailable**: If the source peer disconnects, sync will fail. Node should restart to retry with a different peer.

## Testing

### Manual Testing

1. Start a network with 4+ nodes
2. Let the network initialize (complete DKG)
3. Start a 5th node
4. Observe logs for database sync messages
5. Verify the new node has data from existing nodes

### Verification

After sync completes, verify using the RPC endpoint:
```bash
# Check if user registrations were synced
curl -X POST http://localhost:8081/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "get_all_users", "params": []}'
```

## Future Improvements

1. **Compression**: Add compression for batch transfers to reduce network usage
2. **Incremental Sync**: Support syncing only new entries (delta sync)
3. **Multi-peer Sync**: Download different batches from different peers in parallel
4. **Checkpointing**: Save sync progress to resume from last successful batch
5. **Verification**: Add merkle tree or hash verification for data integrity

## Troubleshooting

### Sync Not Starting
- Check if node has > 4 peers in network
- Verify node has no existing DKG data
- Check logs for peer discovery messages

### DialFailure Error on Sync Start
**Symptom**: Logs show `OutboundFailure` with `DialFailure` immediately after sync starts
```
📦 [DB_SYNC] Starting database sync from peer 12D3KooW...
Outbound failure to peer 12D3KooW...: DialFailure
```

**Causes**:
1. **Node trying to sync from itself** - Fixed: Code now filters out local peer ID
2. **No active connection to peer** - **Most Common**: The peer is in the routing table but not yet connected

**Fix**: The code now:
1. Only selects **connected peers** for database sync (not just peers in routing table)
2. Automatically retries sync when a connection is established
3. Logs `🔗 [NEW_NODE] Currently connected to X peers` to show available peers

**Expected Behavior**:
- If no peers are connected yet: `⚠️ [NEW_NODE] No connected peers available for database sync!`
- Node will wait and retry: `⚠️ [NEW_NODE] Will retry database sync when a connection is established`
- When connection is made: `🔄 [DB_SYNC] Connection established, retrying database sync with peer...`

### Sync Fails Mid-way
- Check network connectivity to source peer
- Verify source peer has data (not also a new node)
- Check for sufficient disk space

### No Peers Available for Sync
**Symptom**: Log shows `⚠️ [NEW_NODE] No other peers available for database sync!`

**Cause**: All peers in the network are unavailable or the peer list only contains the local node

**Solution**: 
- Ensure other nodes are online and accessible
- Check network connectivity
- Verify bootstrap nodes are reachable

### Data Inconsistency
- Re-sync by clearing data directory and restarting node
- Verify all nodes are running the same version

## Related Files

- `src/database/mod.rs` - Database export/import implementation
- `src/network/mod.rs` - Network layer sync logic
- `src/types/rpc.rs` - RPC message definitions
- `src/main.rs` - Node initialization with database

## Authors

Implemented as part of the Qubetics MPC node network to enable seamless addition of new nodes to existing networks without manual data migration.

