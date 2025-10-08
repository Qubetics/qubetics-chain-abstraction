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
cargo build --release --bn mpc-node
```

## Usage

### Running an MPC Node

Node 1 

```
./target/release/mpc-node --data-dir ./data/node1 --dev
```

Node 2 
```
./target/release/mpc-node --data-dir ./data/node2 --mpc-nodes <mpc node id> --dev
```

### Node.js Client

The project includes a Node.js client for testing and integration:

```bash
cd clients/nodejs
npm install
node main.js
```

### Testing

```bash
# Run tests
cargo test

# Run specific test module
cargo test test_module_name
```

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