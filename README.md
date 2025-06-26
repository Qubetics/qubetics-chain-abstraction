# Qubetics Chain Abstraction

A decentralized Multi-Party Computation (MPC) network for cross-chain intent settlement and chain abstraction, built with Rust and libp2p.

## Overview

Qubetics Chain Abstraction is a distributed MPC network that enables secure cross-chain transactions through threshold signature schemes and distributed key generation (DKG). The system provides chain abstraction capabilities by allowing users to submit intents for cross-chain asset transfers that are then settled through a decentralized network of MPC nodes.

## Architecture

The project consists of several key components:

### Core Components

- **MPC Node (`mpcn`)**: The main MPC node that participates in distributed key generation and threshold signing
- **PTP Node (`ptp`)**: A peer-to-peer node for network communication
- **VRF Demo (`vrf_demo`)**: Demonstration of VRF-based node selection
- **Network Layer**: libp2p-based networking with gossipsub, Kademlia DHT, and request-response protocols
- **DKG Module**: Distributed Key Generation using BLS12-381 curves
- **FROST Signer**: Threshold signature scheme implementation
- **VRF Node Selection**: Verifiable Random Function for fair MPC node selection
- **Blockchain Client**: Ethereum integration for transaction execution
- **Intent Service**: gRPC service for processing cross-chain intents

### Key Features

- **Distributed Key Generation**: Secure threshold key generation using BLS12-381
- **Threshold Signing**: FROST protocol for distributed signature generation
- **VRF-based Node Selection**: Fair and verifiable random selection of MPC participants
- **Cross-Chain Intents**: gRPC-based intent submission and processing
- **P2P Networking**: libp2p-based decentralized network communication
- **Chain Abstraction**: Unified interface for cross-chain operations
- **Node Management**: Dynamic node membership and threshold calculation

## VRF-based MPC Node Selection

The system uses Verifiable Random Functions (VRF) to ensure fair and unpredictable selection of MPC participants. This prevents manipulation and ensures decentralization.

### VRF Implementation

- **Cryptographic Security**: Uses Blake3 for VRF proof generation and verification
- **Deterministic Selection**: Same input produces same output across all nodes
- **Fair Distribution**: All nodes have equal probability of being selected
- **Verifiable Proofs**: Each node can prove its selection was fair

### How VRF Selection Works

1. **Round Initialization**: Each selection round has a unique identifier
2. **Proof Generation**: Nodes generate VRF proofs using their secret keys
3. **Value Extraction**: VRF outputs are converted to numerical values
4. **Ranking**: Nodes are ranked by their VRF values
5. **Selection**: Top-ranked nodes are selected for MPC participation

### VRF Components

- **VrfNodeSelector**: Core VRF functionality and proof generation
- **VrfNodeManager**: Integration with node management system
- **VrfSelectionMessage**: Network messages for VRF coordination
- **NodeSelectionResult**: Results of VRF-based selection

## Prerequisites

- Rust 1.70+ and Cargo
- Node.js 18+ (for client examples)
- Git

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd qubetics-chain-abstraction
```

2. Build the project:
```bash
make build
```

Or build individual components:
```bash
cargo build --bin mpcn
cargo build --bin ptp
cargo build --bin vrf_demo
```

## Usage

### Running an MPC Node

Start an MPC node with VRF-based selection:
```bash
make runn
```

Or directly:
```bash
cargo run --bin mpcn
```

### Running a PTP Node

Start a PTP node with optional arguments:
```bash
make runt ARGS="--help"
```

Or directly:
```bash
cargo run --bin ptp -- [ARGS]
```

### VRF Demo

Run the VRF demonstration:
```bash
make runvrf
```

Or directly:
```bash
cargo run --bin vrf_demo
```

### Node.js Client

The project includes a Node.js client for testing and integration:

```bash
cd clients/nodejs
npm install
node main.js
```

## Project Structure

```
qubetics-chain-abstraction/
├── src/
│   ├── main.rs              # MPC node entry point
│   ├── bin/
│   │   ├── ptp.rs           # PTP node entry point
│   │   └── vrf_demo.rs      # VRF demonstration
│   ├── network/             # P2P networking layer
│   ├── dkg/                 # Distributed Key Generation
│   ├── frost/               # FROST threshold signatures
│   ├── vrf/                 # VRF-based node selection
│   ├── chain/               # Blockchain integration
│   ├── consensus/           # Consensus mechanisms
│   ├── signing/             # Multi-party signing
│   ├── settlement/          # Cross-chain settlement
│   ├── solver/              # Intent solving logic
│   ├── commands/            # Command processing
│   ├── node_management/     # Node membership management
│   │   └── vrf_manager.rs   # VRF-based node manager
│   ├── types/               # Common type definitions
│   └── protos/              # Protocol buffer definitions
├── proto/
│   └── intent.proto         # Intent service definitions
├── clients/
│   └── nodejs/              # Node.js client example
├── Cargo.toml               # Rust dependencies
├── Makefile                 # Build and run commands
└── build.rs                 # Build script
```

## Protocol

### Intent Submission

Users submit cross-chain intents via gRPC:

```protobuf
message IntentRequest {
  string source_chain_id = 1;
  string destination_chain_id = 2;
  string source_asset = 3;
  string destination_asset = 4;
  string ev_address = 5;
  uint64 amount = 6;
  bytes signature = 7;
}
```

### DKG Protocol

The DKG protocol follows these steps:
1. Each node generates a random polynomial
2. Shares are distributed to all participants
3. Commitments are broadcast for verification
4. Valid shares are collected
5. Group public key is reconstructed

### FROST Signing

The FROST protocol enables threshold signing:
1. Participants generate nonces and commitments
2. Commitments are shared
3. Message is signed using distributed shares
4. Signature is reconstructed from partial signatures

### VRF Selection Protocol

The VRF-based node selection protocol:
1. **Round Announcement**: New selection round is announced
2. **Proof Generation**: Each node generates VRF proof for the round
3. **Proof Broadcasting**: VRF proofs are shared across the network
4. **Verification**: All nodes verify received VRF proofs
5. **Ranking**: Nodes are ranked by VRF output values
6. **Selection**: Top-ranked nodes are selected for MPC

## Configuration

The system can be configured through environment variables and command-line arguments. Key configuration options include:

- Network ports and addresses
- DKG threshold and total node count
- VRF selection interval and parameters
- Blockchain RPC endpoints
- Logging levels

## Development

### Building

```bash
# Build all components
make build

# Build specific binary
cargo build --bin mpcn
cargo build --bin ptp
cargo build --bin vrf_demo
```

### Testing

```bash
# Run tests
cargo test

# Run specific test module
cargo test test_module_name
```

### Logging

The system uses structured logging with tracing. Logs are written to:
- Console (stdout/stderr)
- Daily rotating log files in `logs/` directory

Log levels can be configured via `RUST_LOG` environment variable.

## Dependencies

### Rust Dependencies
- **libp2p**: P2P networking
- **tokio**: Async runtime
- **bls12_381**: BLS signature curves
- **blake3**: VRF implementation and hashing
- **ethers**: Ethereum integration
- **tonic**: gRPC framework
- **serde**: Serialization
- **tracing**: Logging and observability

### Node.js Dependencies
- **libp2p**: P2P networking client
- **cbor-x**: CBOR serialization
- **@multiformats/multiaddr**: Multiaddress handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

[Add your license information here]

## Security

This project implements cryptographic protocols and should be used with appropriate security considerations:

- All cryptographic operations use well-vetted libraries
- Network communication is encrypted
- Key material is handled securely
- VRF provides fair and verifiable node selection
- Regular security audits are recommended

## Roadmap

- [ ] Enhanced consensus mechanisms
- [ ] Support for additional blockchains
- [ ] Improved intent solving algorithms
- [ ] Web dashboard for monitoring
- [ ] Mobile client support
- [ ] Advanced settlement strategies
- [ ] Enhanced VRF security properties
- [ ] Cross-chain VRF coordination

## Support

For questions and support:
- Create an issue on GitHub
- Join our community discussions
- Review the documentation

---

**Note**: This is a research and development project. Use in production environments requires thorough security auditing and testing. 