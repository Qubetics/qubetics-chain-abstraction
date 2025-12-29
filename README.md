# Qubetics Chain Abstraction - MPC Node

A  ulti-Party Computation (MPC) node implementation for blockchain chain abstraction, enabling secure threshold signing across multiple blockchain networks including Qubetics and Bitcoin.

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

[Specify license here]

## Support

For issues, questions, or contributions, please refer to the project's issue tracker or contact the maintainers.

