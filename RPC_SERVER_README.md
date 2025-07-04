# MPC RPC Server Integration

This document explains how the RPC server integrates with the P2P network layer using the existing MPSC (Multi-Producer Single-Consumer) channel.

## Architecture Overview

```
┌─────────────────┐    HTTP/gRPC    ┌─────────────────┐    MPSC Channel    ┌─────────────────┐
│   RPC Client    │ ──────────────► │   RPC Server    │ ─────────────────► │  P2P Network    │
│                 │                 │                 │                    │     Layer       │
└─────────────────┘                 └─────────────────┘                    └─────────────────┘
```

## Components

### 1. RPC Server (`src/rpc_server/mod.rs`)
- **HTTP Server**: Uses `warp` framework for REST API endpoints
- **gRPC Server**: Uses `tonic` framework for gRPC services
- **Message Integration**: Receives requests and forwards them to P2P network via MPSC channel

### 2. MPSC Channel Integration
The RPC server receives a `mpsc::Sender<ChannelMessage>` from the network layer and uses it to:
- Broadcast transactions to the "transactions" topic
- Send DKG commands to the "dkg-commands" topic
- Communicate with other P2P nodes

### 3. Network Layer Updates
- Added new gossipsub topics: "transactions" and "dkg-commands"
- Extended `GossipsubMessage` enum to handle transaction and DKG command messages
- Updated message handling in `handle_gossipsub_message()`

## API Endpoints

### HTTP Endpoints (Port 8080)

#### POST /submit_transaction
Submit a dummy transaction to the P2P network.

**Request Body:**
```json
{
    "from": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
    "to": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b7",
    "amount": 1000000000000000000,
    "nonce": 1,
    "data": "48656c6c6f204d5043204e6574776f726b21"
}
```

**Response:**
```json
{
    "tx_hash": "0x1234...",
    "status": "submitted",
    "message": "Transaction submitted to P2P network"
}
```

#### GET /status
Get the current node status.

**Response:**
```json
{
    "peer_id": "dummy-peer-id",
    "connected_peers": 0,
    "dkg_status": "unknown",
    "is_ready": true
}
```

#### POST /start_dkg
Trigger DKG (Distributed Key Generation) process.

**Response:**
```json
{
    "tx_hash": "dkg-start-request",
    "status": "initiated",
    "message": "DKG start request sent to P2P network"
}
```

### gRPC Endpoints (Port 50051)
The same functionality is also available via gRPC using the `MpcRpc` service.

## Message Flow

### Transaction Submission Flow
1. **Client** sends HTTP POST to `/submit_transaction`
2. **RPC Server** receives the transaction
3. **RPC Server** serializes transaction and sends `ChannelMessage::Broadcast` to MPSC channel
4. **Network Layer** receives the message and broadcasts to "transactions" topic via gossipsub
5. **Other P2P nodes** receive the transaction via gossipsub and process it

### DKG Command Flow
1. **Client** sends HTTP POST to `/start_dkg`
2. **RPC Server** creates `RPCRequest::StartADKG`
3. **RPC Server** sends `ChannelMessage::Broadcast` to "dkg-commands" topic
4. **Network Layer** broadcasts the DKG command to all peers
5. **All nodes** receive the command and start DKG process

## Usage Examples

### Running the MPC Node with RPC Server
```bash
# Build and run the MPC node
cargo run --bin mpcn

# The RPC server will start automatically on port 8080
```

### Testing with Node.js Client
```bash
# Navigate to the client directory
cd clients/nodejs

# Install dependencies
npm install

# Run the test client
node test_client.js
```

### Testing with curl
```bash
# Submit a transaction
curl -X POST http://localhost:8080/submit_transaction \
  -H "Content-Type: application/json" \
  -d '{
    "from": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
    "to": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b7",
    "amount": 1000000000000000000,
    "nonce": 1,
    "data": "48656c6c6f204d5043204e6574776f726b21"
  }'

# Get node status
curl http://localhost:8080/status

# Start DKG
curl -X POST http://localhost:8080/start_dkg
```

## Configuration

### RPC Server Port
The RPC server port can be configured in `src/main.rs`:
```rust
let rpc_port = 8080; // Change this to your desired port
```

### Topics
The gossipsub topics are defined in `src/network/mod.rs`:
```rust
let topics = vec![
    MSG_TOPIC_DKG,
    MSG_TOPIC_PEER_DISCOVERY,
    "signing",
    "consensus",
    "commands",
    "vrf-selection",
    "transactions",      // For transaction messages
    "dkg-commands",      // For DKG command messages
];
```

## Error Handling

The RPC server includes comprehensive error handling:
- **Serialization Errors**: When transaction data cannot be serialized
- **Network Errors**: When MPSC channel is closed or network is unavailable
- **Service Errors**: When RPC service is not properly initialized

## Security Considerations

- The RPC server currently runs on localhost only
- No authentication is implemented (should be added for production)
- Transaction validation should be enhanced for production use
- Consider rate limiting for API endpoints

## Future Enhancements

1. **Authentication**: Add JWT or API key authentication
2. **Transaction Validation**: Implement proper transaction validation
3. **Response Handling**: Add response channels for async operations
4. **Metrics**: Add Prometheus metrics for monitoring
5. **Load Balancing**: Support multiple RPC server instances
6. **WebSocket**: Add real-time transaction status updates 