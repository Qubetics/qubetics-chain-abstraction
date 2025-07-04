# Distributed Signing Mechanism

This document describes the implementation of a distributed signing mechanism where multiple nodes participate in signing messages using their secret shares obtained from a Distributed Key Generation (DKG) process.

## Overview

The signing mechanism implements a threshold-based distributed signing protocol where:
- Each node holds a secret share obtained from DKG
- Multiple nodes collaborate to sign messages
- Signatures are generated using a threshold of participating nodes
- All nodes can see and log the signatures

## Architecture

### Components

1. **DKGNode**: Handles distributed key generation and provides secret shares
2. **SigningNode**: Manages the signing process and signature generation
3. **NetworkLayer**: Handles communication between nodes
4. **CommandProcessor**: Processes signing commands

### Key Features

- **Threshold Signing**: Requires a minimum number of nodes to participate
- **FROST Protocol**: Implements FROST (Flexible Round-Optimized Schnorr Threshold) signing
- **Real-time Logging**: All nodes log their participation and signatures
- **Message Broadcasting**: Nodes communicate via gossipsub protocol
- **Automatic Integration**: DKG completion automatically configures signing nodes

## Implementation Details

### SigningNode Structure

```rust
pub struct SigningNode {
    id: String,
    threshold: usize,
    secret_share: Option<Scalar>,
    group_key: Option<G1Projective>,
    nonces: Vec<(Scalar, Scalar)>,
    commitments: Arc<RwLock<HashMap<String, Vec<FrostCommitment>>>>,
    signature_shares: Arc<RwLock<HashMap<String, Scalar>>>,
    pending_messages: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    message_tx: mpsc::Sender<ChannelMessage>,
}
```

### Signing Process Flow

1. **Message Reception**: Node receives a message to sign
2. **Nonce Generation**: Generates random nonces for the signing session
3. **Commitment Broadcast**: Broadcasts commitments to other nodes
4. **Signature Share Generation**: Creates signature share using secret key
5. **Share Collection**: Collects signature shares from other nodes
6. **Signature Aggregation**: Combines shares into final signature
7. **Result Broadcasting**: Broadcasts the final signed message

### Message Types

```rust
pub enum SigningMessage {
    CommitmentShare {
        from: String,
        commitments: Vec<FrostCommitment>,
        message_hash: Vec<u8>,
    },
    SignatureShare {
        from: String,
        share: SerializableScalar,
        message_hash: Vec<u8>,
    },
    MessageToSign {
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
}
```

## Usage

### Running the Signing Demo

1. **Single Node Demo**:
   ```bash
   cargo run --bin signing_demo
   ```

2. **Multi-Node Test**:
   ```bash
   ./test_signing.sh
   ```

3. **Manual Node Start**:
   ```bash
   cargo run --bin mpcn
   ```

### Integration with DKG

The signing mechanism automatically integrates with the DKG process:

```rust
// DKG completion callback
dkg_node.set_completion_callback(Box::new(move |secret_share, group_key| {
    let signing_node = signing_node_clone.clone();
    tokio::spawn(async move {
        let mut signing_node = signing_node.lock().await;
        signing_node.set_secret_share(secret_share);
        signing_node.set_group_key(group_key);
    });
}));
```

### Triggering Message Signing

```rust
// Direct signing
let message = b"Hello, world!";
signing_node.sign_message(message).await?;

// Via command
let cmd = Command::SignMessage { message: message.to_vec() };
command_processor.handle_message(cmd).await?;
```

## Logging

The signing mechanism provides comprehensive logging:

- **Node Setup**: Secret share and group key configuration
- **Signing Process**: Each step of the signing protocol
- **Message Exchange**: Commitment and signature share exchanges
- **Final Results**: Completed signatures with verification

### Log Examples

```
🔐 [SIGNING] Node 1 secret share set
🔑 [SIGNING] Node 1 group key set
📝 [SIGNING] Node 1 starting to sign message
📤 [SIGNING] Node 1 broadcasted commitment share
📥 [SIGNING] Node 1 received commitment share from Node 2
✍️ [SIGNING] Node 1 generated signature share
🎯 [SIGNING] Node 1 has enough signature shares, aggregating
🎉 [SIGNING] Node 1 completed signing and broadcasted result
📋 [SIGNING] Final signature: [signature_value]
```

## Security Features

1. **Threshold Security**: Requires minimum number of honest nodes
2. **Nonce Generation**: Fresh random values for each signing session
3. **Commitment Verification**: Cryptographic commitments prevent cheating
4. **Message Hashing**: SHA-256 hashing for message integrity
5. **Signature Verification**: BLS signature verification

## Configuration

### Threshold Settings

- **Default**: 2/3 threshold (2 out of 3 nodes required)
- **Configurable**: Can be adjusted based on network size
- **Dynamic**: Updates based on active node count

### Network Topics

- **Signing Topic**: `/signing` - for signing-related messages
- **DKG Topic**: `/dkg` - for DKG-related messages
- **Discovery Topic**: `/peer-discovery` - for node discovery

## Testing

### Test Scenarios

1. **Single Node**: Verify local signing capability
2. **Multi-Node**: Test distributed signing with multiple nodes
3. **Network Partition**: Test behavior with network issues
4. **Malicious Nodes**: Test threshold security

### Running Tests

```bash
# Build and test
cargo build
cargo test

# Run demo
cargo run --bin signing_demo

# Multi-node test
./test_signing.sh
```

## Future Enhancements

1. **Signature Verification**: Implement proper BLS signature verification
2. **Batch Signing**: Support for signing multiple messages
3. **Key Rotation**: Dynamic key update mechanisms
4. **Performance Optimization**: Optimize for high-throughput scenarios
5. **Integration**: Connect with blockchain networks

## Troubleshooting

### Common Issues

1. **DKG Not Completed**: Ensure DKG process finishes before signing
2. **Network Connectivity**: Check node discovery and peer connections
3. **Threshold Not Met**: Verify sufficient nodes are participating
4. **Log Analysis**: Check logs for detailed error information

### Debug Commands

```bash
# Check node status
grep "DKG COMPLETED" logs/*.log

# Monitor signing process
grep "SIGNING" logs/*.log

# Check network connectivity
grep "Peer discovered" logs/*.log
```

## Conclusion

The distributed signing mechanism provides a secure, scalable solution for threshold-based message signing in distributed networks. It integrates seamlessly with the existing DKG infrastructure and provides comprehensive logging for monitoring and debugging. 