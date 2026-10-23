# Qubetics Chain Abstraction - MPC Node

A multi-Party Computation (MPC) node implementation for blockchain chain abstraction, enabling secure threshold signing across multiple blockchain networks including Qubetics and Bitcoin.

## Overview

This project implements a distributed MPC node that provides chain abstraction capabilities through threshold cryptography. The system enables secure, decentralized key management and transaction signing across multiple blockchain networks without requiring users to manage individual chain-specific keys.

## Features

- **Multi-Chain Support**: Native support for Qubetics and Bitcoin networks
- **Threshold Signing**: Secure distributed key generation and threshold signature schemes
- **P2P Networking**: Built on libp2p for decentralized peer-to-peer communication
- **VRF-Based Node Selection**: Verifiable Random Function (VRF) for deterministic and verifiable node selection
- **Chain Abstraction**: Unified interface for interacting with multiple blockchain networks
- **User Intent Management**: Secure handling of user deposit and withdrawal intents
- **Database Persistence**: RocksDB-based storage with optional encryption
- **RPC API**: HTTP-based RPC server for client interactions
- **Consensus Mechanisms**: Built-in consensus protocols for distributed coordination

## Architecture

### Core Components

- **Network Layer**: P2P networking using libp2p with Gossipsub, Kademlia DHT, and request-response protocols
- **DKG Protocol**: Distributed Key Generation for secure threshold key sharing
- **Signing Node**: Threshold signature coordination and execution
- **Chain Abstraction**: Unified handlers for Qubetics and Bitcoin transaction processing
- **User Intent Manager**: Manages user registration and intent processing
- **Database Module**: Persistent storage for keys, intents, and consensus state
-**RPC Server**: HTTP API for external client interactions

### Technology Stack

- **Language**: Rust (Edition 2021)
- **Async Runtime**: Tokio
- **P2P Framework**: libp2p 0.55
- **Cryptography**: 
  - secp256k1 for ECDSA signatures
  - ECVRF for verifiable random functions
  - Threshold cryptography primitives
- **Database**: RocksDB with optional encryption
- **Serialization**: CBOR, JSON, RLP

## Prerequisites

- Rust 1.70+ (with Cargo)
- OpenSSL development libraries
- Network access for P2P connectivity

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd qubetics-chain-abstraction
```

2. Build the project:
```bash
cargo build --release
```

3. Install Node.js dependencies (for client examples):
```bash
cd clients/nodejs
npm install
```

## Configuration

1. Copy the environment template:
```bash
cp env.sample .env
```

2. Configure required environment variables in `.env`:

### Required Configuration

- **`CHAIN_CODE_HEX`**: 32-byte chain code secret (64 hex characters)
  - Generate securely: `openssl rand -hex 32`
  - Keep this value private and secure

- **`NETWORK_TYPE`**: Network environment (`testnet` or `mainnet`)
  - Determines both Qubetics/Qubetics and Bitcoin network configuration

- **`MPC_Qubetics_RPC_URL`**: RPC endpoint for the configured network
  - Example: `https://rpc-testnet.qubetics.work`

### Optional Configuration

- **`RPC_PORT`**: HTTP RPC server port (default: 8081)
- **`QUBETICS_DB_ENCRYPTION_KEY`**: 32-byte encryption key for RocksDB (64 hex characters)
  - If unset, database operates in plain text mode
  - Generate securely: `openssl rand -hex 32`

### Example Configuration

```env
CHAIN_CODE_HEX=2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ade4
NETWORK_TYPE=testnet
MPC_Qubetics_RPC_URL=https://rpc-testnet.qubetics.work
RPC_PORT=8081
QUBETICS_DB_ENCRYPTION_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddelll
```

## Usage

### Running the MPC Node

Start the node with:
```bash
cargo run --release
```

The node will:
1. Initialize the database at `./data/rocksdb-<peer-id>`
2. Start the P2P network layer
3. Begin peer discovery and connection
4. Launch the RPC server on the configured port
5. Initialize DKG and signing capabilities

### Client Integration

The project includes Node.js client examples in `clients/nodejs/`:

- `test_register_user.js`: User registration example
- `test_add_liquidity.js`: Liquidity management example
- `test_claim_reward.js`: Reward claiming example
- `test_withdraw_liquidity.js`: Withdrawal example

Example usage:
```bash
cd clients/nodejs
node test_register_user.js
```

## API Reference

### RPC Endpoints

The HTTP RPC server exposes endpoints for:
- User registration and management
- Intent submission and tracking
- Transaction status queries
- Network information
- DKG status and operations
- Reward management

Refer to `src/rpc_server/handlers.rs` for detailed endpoint documentation.

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# With specific features
cargo build --features eth,bitcoin,grpc
```

### Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration_tests
```

### Code Organization

- `src/chain_abstraction/`: Chain-specific transaction handling
- `src/dkg/`: Distributed Key Generation protocol
- `src/network/`: P2P networking and message handling
- `src/signing/`: Threshold signing coordination
- `src/database/`: Storage layer and persistence
- `src/rpc_server/`: HTTP RPC API implementation
- `src/user_intent_manager/`: User intent processing
- `src/vrf/`: Verifiable Random Function implementation

## Proactive Resharing

Proactive resharing (also called *proactive refresh*) replaces every node's secret share of the network key with a new, unrelated share, while keeping the group secret, and so the group public key and every derived address, unchanged. An attacker who collected shares before a refresh can't combine them with shares taken after it. And whenever nodes join or leave, the key gets redistributed across the new set of nodes.

> **Availability:** the refresh protocol described here is implemented on the resharing branches (for example `feat/refresh-fallback`, `fix/refresh-shares`, `feat/share-broadcast`). On branches where `src/dkg/protocol/refresh.rs` is a stub (including `main`), refresh is disabled and new nodes join as passive observers that don't take part in DKG or signing.

### How it works

Let `S` be the group secret and `S_i` the share held by the node with permanent index `i`, so that `S = Σ λ_i(0) · S_i` over the active indices, where `λ_i(0)` is the Lagrange coefficient at zero.

1. **Agree on the participant set.** Each node takes the active nodes from `NodeMembership` and maps them to their *permanent* DKG indices stored in the database. A node's permanent index is assigned at DKG or join time and never changes, and every node must use the same, ascending index list, or the secret would change.
2. **Build a refresh polynomial.** Each node `i` builds a random polynomial `G_i(x)` of degree `t − 1` whose constant term is its weighted contribution to the secret: `G_i(0) = λ_i(0) · S_i`. The other coefficients are fresh random scalars (see `generate_zero_constant_polynomial` and `generate_refresh_polynomial`).
3. **Deal shares and commitments.** Node `i` evaluates `G_i(j)` for every active index `j`. It sends each peer its share by unicast P2P RPC (`ChannelMessage::UnicastRefreshShare`, with outbound retries) and broadcasts Feldman commitments to the coefficients on the DKG gossip topic (`DKGMessage::RefreshCommitmentBroadcast`). A node keeps its own share locally.
4. **Verify.** Each received share is checked against the sender's commitments (`verify_shares`). A share that fails verification is rejected, and shares and commitments may arrive in either order.
5. **Combine.** Once a node holds a refresh share from every active node, its new share is `S'_j = Σ_i G_i(j)`. Since `Σ_i G_i(0) = Σ_i λ_i(0) · S_i = S`, the new shares are a fresh `t`-of-`n` sharing of the same secret.
6. **Check before committing.** The node sums the constant-term commitments `C_i,0` of all refresh polynomials and compares the result with the stored group public key. Only if they match does it persist the new share, the new public key and the new commitments. Otherwise the round is aborted and the old share is kept.

### When a refresh runs

| Trigger | Where |
|---|---|
| A new node finishes joining (after vault key generation) | It broadcasts `DKGMessage::TriggerRefresh` and runs the refresh itself (`src/dkg/membership/new_node.rs`) |
| A peer receives `TriggerRefresh` | `src/dkg/protocol/handlers.rs` → `execute_polynomial_refresh` |
| A node disconnects | Total nodes and threshold are recomputed, DKG and signing parameters are updated, and after a 3-second sync delay the remaining nodes reshare (`src/network/transport/connection.rs`) |
| Refresh-round timeout (`REFRESH_ROUND_TIMEOUT_SECS` = 120 s) | Nodes that sent no refresh share are announced as failed (see the fallback below) |

### Fallback when nodes don't respond

Each round sets a 120-second deadline. When it expires before all shares arrive, every node that didn't send one is treated as failed. For each of them the node broadcasts:

- `DKGMessage::NodeDisconnected`, so the network drops that node from membership and starts a new refresh with the smaller set.
- `GossipsubMessage::PeerDisconnection` on the peer-disconnection topic, so the usual peer-invalidation flow (`PeerInvalidationBatch` → `invalidateSolverIds`) runs.

If the remaining nodes still meet the threshold, the refresh is retried with them. If they don't, the round is aborted and the in-progress flag is cleared so the node can serve requests again.

### Effects on the rest of the codebase

While a refresh runs, a persisted `dkg_refresh_in_progress` flag (`DkgStorage::set_refresh_in_progress`) is set. The rest of the node uses it to keep the participant set and user balances stable:

- **RPC server** (`src/rpc_server/handlers.rs`): `register_user`, `user_mpc_deposit`, `claim_reward` and liquidity withdrawals are rejected with a "shares are getting refreshed" error until the refresh ends.
- **Networking** (`src/network/transport/swarm_events.rs`): new inbound peers are disconnected so membership can't change mid-round.

After the new share is committed, the node rebuilds everything derived from it:

- **Vault key:** the vault's HMAC-tweaked secret share is recomputed, and the vault group key and liquidity-operator ETH/BTC addresses are stored again.
- **Share public keys:** the partial public keys for the network and vault shares are recomputed for every peer (`compute_and_store_all_share_pubkeys`). Signing uses them to verify partial signatures.
- **User shares:** `UserIntentManager::refresh_all_user_tweaked_shares` re-derives every registered user's tweaked share from the new share and the user's HMAC constant, and recomputes each user's share public keys. User deposit addresses don't change.
- **Cleanup:** refresh shares and commitments (stored under `refresh_<peer_id>`) are deleted, and the next round starts clean.

The core implementation is in `src/dkg/protocol/refresh.rs`.

## Security Considerations

- **Chain Code Security**: The `CHAIN_CODE_HEX` must be kept secret and never committed to version control
- **Database Encryption**: Enable database encryption in production environments
- **Network Security**: Ensure proper firewall configuration for P2P ports
- **Key Management**: Private keys are never stored in plain text; use threshold shares only
- **Production Deployment**: Always use `mainnet` configuration with secure, production-grade RPC endpoints

## Logging

Logs are written to:
- Console (stdout/stderr)
- File: `logs/mpcn-<random-id>.log`

Log levels can be controlled via the `RUST_LOG` environment variable:
```bash
RUST_LOG=debug cargo run --release
```

## Performance

The node is configured with:
- 16 Tokio worker threads for parallel processing
- Optimized database access patterns
- Efficient P2P message handling
- Concurrent transaction processing

## Contributing

1. Follow Rust formatting standards: `cargo fmt`
2. Ensure all tests pass: `cargo test`
3. Check for linting issues: `cargo clippy`
4. Update documentation for new features

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please refer to the project's issue tracker or contact the maintainers.

