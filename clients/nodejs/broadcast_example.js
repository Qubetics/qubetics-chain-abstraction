#!/usr/bin/env node

/**
 * Simple Bitcoin Transaction Broadcasting Example
 * 
 * This is a simplified version for quick testing and integration
 */

import { broadcastBitcoinTransaction } from './broadcast_bitcoin_transaction.js';

// Example usage with your MPC signed transaction
async function example() {
    console.log('🚀 Bitcoin Broadcasting Example\n');
    
    // Example signed Bitcoin transaction (replace with your actual signed tx)
    const signedTxHex = "0200000001abc123def456789..."; // Your aggregated signature result
    
    try {
        // Broadcast to testnet using multiple providers
        const txid = await broadcastBitcoinTransaction(
            signedTxHex, 
            'testnet',  // or 'mainnet'
            ['blockstream', 'blockcypher'] // providers to try
        );
        
        console.log(`✅ Success! Transaction ID: ${txid}`);
        console.log(`🔗 View on explorer: https://blockstream.info/testnet/tx/${txid}`);
        
    } catch (error) {
        console.error(`❌ Broadcast failed: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Function to integrate with your Rust MPC system
 * Call this after signature aggregation is complete
 */
async function broadcastFromMPC(aggregatedSignatureHex, transactionHex, network = 'testnet') {
    console.log('🔗 [MPC] Broadcasting Bitcoin transaction from MPC system');
    console.log(`📄 Signature: ${aggregatedSignatureHex.substring(0, 20)}...`);
    console.log(`📄 Transaction: ${transactionHex.substring(0, 20)}...`);
    
    try {
        // In your actual implementation, you'll need to:
        // 1. Combine the aggregated signature with the transaction
        // 2. Create the final signed transaction hex
        // 3. Broadcast it
        
        // For now, assuming transactionHex is already signed
        const txid = await broadcastBitcoinTransaction(transactionHex, network);
        
        console.log(`✅ [MPC] Bitcoin transaction broadcasted successfully!`);
        console.log(`📄 Transaction ID: ${txid}`);
        
        return {
            success: true,
            txid,
            network,
            explorer_url: `https://blockstream.info${network === 'testnet' ? '/testnet' : ''}/tx/${txid}`
        };
        
    } catch (error) {
        console.error(`❌ [MPC] Failed to broadcast: ${error.message}`);
        return {
            success: false,
            error: error.message
        };
    }
}

// Export for integration with your Rust system
export { broadcastFromMPC };

// Example usage
if (import.meta.url === `file://${process.argv[1]}`) {
    // Uncomment to run example
    // example();
    
    console.log(`
🔧 Bitcoin Broadcasting Integration Ready!

To use in your system:
1. Import: import { broadcastFromMPC } from './broadcast_example.js'
2. Call after signature aggregation: await broadcastFromMPC(signature, txHex, 'testnet')

For CLI usage:
node broadcast_bitcoin_transaction.js <transaction_hex> --network testnet
    `);
}
