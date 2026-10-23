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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

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