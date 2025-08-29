# Bitcoin Transaction Broadcasting

This directory contains Node.js scripts for broadcasting Bitcoin transactions to the Bitcoin network after MPC signature aggregation.

## Files

### `broadcast_bitcoin_transaction.js`
Main broadcasting script with multiple provider support and CLI interface.

**Features:**
- Multiple broadcast providers (Blockstream, BlockCypher, Bitcoin Core RPC)
- Mainnet and testnet support
- Automatic fallback between providers
- Transaction validation
- Result saving
- Comprehensive error handling

### `broadcast_example.js`
Simple example and integration helper for MPC systems.

**Features:**
- Easy integration with Rust MPC system
- Example usage patterns
- Simplified API

## Installation

```bash
cd clients/nodejs
npm install
```

## Usage

### CLI Usage

```bash
# Basic broadcast to testnet
node broadcast_bitcoin_transaction.js 0200000001abc123...

# Broadcast to mainnet with specific providers
node broadcast_bitcoin_transaction.js 0200000001abc123... --network mainnet --providers blockstream,rpc

# Load transaction from file
node broadcast_bitcoin_transaction.js --file signed_tx.hex --network testnet --save-result

# Show help
node broadcast_bitcoin_transaction.js --help
```

### NPM Scripts

```bash
# Run broadcasting tool
npm run broadcast-btc -- 0200000001abc123...

# Run example
npm run broadcast-example
```

### Programmatic Usage

```javascript
import { broadcastBitcoinTransaction } from './broadcast_bitcoin_transaction.js';

// Basic broadcast
const txid = await broadcastBitcoinTransaction(
    '0200000001abc123...', // signed transaction hex
    'testnet',             // network
    ['blockstream']        // providers to try
);

// Integration with MPC
import { broadcastFromMPC } from './broadcast_example.js';

const result = await broadcastFromMPC(
    aggregatedSignatureHex,
    signedTransactionHex,
    'testnet'
);
```

## Configuration

### Providers

1. **Blockstream API** (Recommended)
   - Mainnet: `https://blockstream.info/api/tx`
   - Testnet: `https://blockstream.info/testnet/api/tx`
   - No authentication required
   - Rate limited

2. **BlockCypher API**
   - Mainnet: `https://api.blockcypher.com/v1/btc/main/txs/push`
   - Testnet: `https://api.blockcypher.com/v1/btc/test3/txs/push`
   - No authentication required for basic usage
   - Rate limited

3. **Bitcoin Core RPC**
   - Requires local Bitcoin node
   - Configure credentials in script
   - Most reliable for high-volume usage

### Network Configuration

Edit the `CONFIG` object in `broadcast_bitcoin_transaction.js`:

```javascript
const CONFIG = {
    DEFAULT_NETWORK: 'testnet', // or 'mainnet'
    BITCOIN_RPC: {
        url: 'http://127.0.0.1:8332',
        username: 'bitcoinrpc',
        password: 'your_rpc_password',
        // ... other settings
    }
    // ... other config
};
```

## Integration with Rust MPC System

### After Signature Aggregation

1. **Extract signed transaction bytes** from your Rust aggregation result
2. **Convert to hex string**
3. **Call broadcasting function**

Example integration in your Rust code:

```rust
// After signature aggregation completes
let signed_tx_hex = hex::encode(&final_signed_transaction_bytes);

// Call Node.js broadcasting script
let output = std::process::Command::new("node")
    .arg("clients/nodejs/broadcast_bitcoin_transaction.js")
    .arg(&signed_tx_hex)
    .arg("--network")
    .arg("testnet")
    .output()?;

if output.status.success() {
    let txid = String::from_utf8(output.stdout)?;
    info!("✅ Bitcoin transaction broadcasted: {}", txid);
} else {
    let error = String::from_utf8(output.stderr)?;
    error!("❌ Broadcast failed: {}", error);
}
```

### HTTP API Integration

You can also create a simple HTTP server to call from Rust:

```javascript
import express from 'express';
import { broadcastBitcoinTransaction } from './broadcast_bitcoin_transaction.js';

const app = express();
app.use(express.json());

app.post('/broadcast', async (req, res) => {
    try {
        const { transaction_hex, network = 'testnet' } = req.body;
        const txid = await broadcastBitcoinTransaction(transaction_hex, network);
        res.json({ success: true, txid });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

app.listen(3001, () => console.log('🚀 Broadcast API listening on port 3001'));
```

## Error Handling

The scripts handle various error scenarios:

- **Invalid transaction format**: Validates hex format and minimum size
- **Network errors**: Retries with different providers
- **RPC authentication**: Clear error messages for auth issues
- **Rate limiting**: Automatic fallback to alternative providers
- **Transaction rejection**: Detailed error messages from Bitcoin network

## Security Notes

1. **Never log private keys or sensitive data**
2. **Use HTTPS endpoints only**
3. **For mainnet, always test on testnet first**
4. **Monitor transactions after broadcast**
5. **Set appropriate timeouts for production use**

## Examples

### Successful Broadcast Output
```
🚀 [BROADCAST] Starting Bitcoin transaction broadcast
📊 Network: testnet
📄 Transaction size: 192 bytes
🔧 Providers to try: blockstream,blockcypher

🔄 [BROADCAST] Trying provider: blockstream
🌐 [BLOCKSTREAM] Broadcasting to testnet via https://blockstream.info/testnet/api/tx
✅ [BLOCKSTREAM] Successfully broadcasted transaction
📄 Transaction ID: abc123def456789...
🔗 Explorer: https://blockstream.info/testnet/tx/abc123def456789...

🎉 [SUCCESS] Transaction broadcasted successfully!
```

### Integration with Your MPC Flow
```
1. Create Bitcoin transaction ✅
2. Sign with MPC nodes ✅  
3. Aggregate signatures ✅
4. Broadcast to network ✅ ← This step!
5. Monitor confirmation ⏳
```

## Troubleshooting

### Common Issues

1. **"Invalid transaction hex"**
   - Check transaction format
   - Ensure complete signature

2. **"All providers failed"**
   - Check network connectivity
   - Verify transaction is valid
   - Try different providers

3. **"RPC connection failed"**
   - Check Bitcoin Core is running
   - Verify RPC credentials
   - Check firewall settings

### Debug Mode

Enable detailed logging by setting environment variable:
```bash
DEBUG=1 node broadcast_bitcoin_transaction.js ...
```

For more help, run: `node broadcast_bitcoin_transaction.js --help`
