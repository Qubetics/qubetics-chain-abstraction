#!/usr/bin/env node

/**
 * Bitcoin Transaction Broadcasting Script
 * 
 * This script broadcasts signed Bitcoin transactions to the Bitcoin network
 * using multiple methods: Blockstream API, Bitcoin Core RPC, and other providers
 */

import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';

// Configuration
const CONFIG = {
    // Blockstream API endpoints
    BLOCKSTREAM_MAINNET: 'https://blockstream.info/api/tx',
    BLOCKSTREAM_TESTNET: 'https://blockstream.info/testnet/api/tx',
    
    // Bitcoin Core RPC (if available)
    BITCOIN_RPC: {
        url: 'http://127.0.0.1:8332',
        username: 'bitcoinrpc',
        password: 'your_rpc_password',
        testnet_port: 18332,
        mainnet_port: 8332
    },
    
    // Alternative APIs
    BLOCKCYPHER_MAINNET: 'https://api.blockcypher.com/v1/btc/main/txs/push',
    BLOCKCYPHER_TESTNET: 'https://api.blockcypher.com/v1/btc/test3/txs/push',
    
    // Default network
    DEFAULT_NETWORK: 'testnet' // 'mainnet' or 'testnet'
};

/**
 * Broadcast Bitcoin transaction using Blockstream API
 * @param {string} rawTxHex - Raw transaction hex string
 * @param {string} network - 'mainnet' or 'testnet'
 * @returns {Promise<string>} Transaction ID
 */
async function broadcastViaBlockstream(rawTxHex, network = 'testnet') {
    const url = network === 'mainnet' 
        ? CONFIG.BLOCKSTREAM_MAINNET 
        : CONFIG.BLOCKSTREAM_TESTNET;
    
    console.log(`🌐 [BLOCKSTREAM] Broadcasting to ${network} via ${url}`);
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
                'User-Agent': 'Qubetics-Chain-Abstraction/1.0'
            },
            body: rawTxHex
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const txid = await response.text();
        console.log(`✅ [BLOCKSTREAM] Successfully broadcasted transaction`);
        console.log(`📄 Transaction ID: ${txid}`);
        console.log(`🔗 Explorer: https://blockstream.info${network === 'testnet' ? '/testnet' : ''}/tx/${txid}`);
        
        return txid;
    } catch (error) {
        console.error(`❌ [BLOCKSTREAM] Failed to broadcast:`, error.message);
        throw error;
    }
}

/**
 * Broadcast Bitcoin transaction using Bitcoin Core RPC
 * @param {string} rawTxHex - Raw transaction hex string
 * @param {string} network - 'mainnet' or 'testnet'
 * @returns {Promise<string>} Transaction ID
 */
async function broadcastViaRPC(rawTxHex, network = 'testnet') {
    const port = network === 'mainnet' 
        ? CONFIG.BITCOIN_RPC.mainnet_port 
        : CONFIG.BITCOIN_RPC.testnet_port;
    
    const rpcUrl = `${CONFIG.BITCOIN_RPC.url.replace(':8332', `:${port}`)}`;
    
    console.log(`🔧 [RPC] Broadcasting via Bitcoin Core RPC: ${rpcUrl}`);
    
    const auth = Buffer.from(
        `${CONFIG.BITCOIN_RPC.username}:${CONFIG.BITCOIN_RPC.password}`
    ).toString('base64');
    
    const rpcPayload = {
        jsonrpc: "1.0",
        id: "broadcast_tx",
        method: "sendrawtransaction",
        params: [rawTxHex]
    };

    try {
        const response = await fetch(rpcUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${auth}`
            },
            body: JSON.stringify(rpcPayload)
        });

        if (!response.ok) {
            throw new Error(`RPC Error: HTTP ${response.status}`);
        }

        const result = await response.json();
        
        if (result.error) {
            throw new Error(`RPC Error: ${result.error.message} (Code: ${result.error.code})`);
        }

        const txid = result.result;
        console.log(`✅ [RPC] Successfully broadcasted transaction`);
        console.log(`📄 Transaction ID: ${txid}`);
        
        return txid;
    } catch (error) {
        console.error(`❌ [RPC] Failed to broadcast:`, error.message);
        throw error;
    }
}

/**
 * Broadcast Bitcoin transaction using BlockCypher API
 * @param {string} rawTxHex - Raw transaction hex string
 * @param {string} network - 'mainnet' or 'testnet'
 * @returns {Promise<string>} Transaction ID
 */
async function broadcastViaBlockCypher(rawTxHex, network = 'testnet') {
    const url = network === 'mainnet' 
        ? CONFIG.BLOCKCYPHER_MAINNET 
        : CONFIG.BLOCKCYPHER_TESTNET;
    
    console.log(`🌍 [BLOCKCYPHER] Broadcasting to ${network} via BlockCypher`);
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Qubetics-Chain-Abstraction/1.0'
            },
            body: JSON.stringify({ tx: rawTxHex })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const result = await response.json();
        const txid = result.hash;
        
        console.log(`✅ [BLOCKCYPHER] Successfully broadcasted transaction`);
        console.log(`📄 Transaction ID: ${txid}`);
        console.log(`🔗 Explorer: https://live.blockcypher.com/btc${network === 'testnet' ? '-testnet' : ''}/tx/${txid}/`);
        
        return txid;
    } catch (error) {
        console.error(`❌ [BLOCKCYPHER] Failed to broadcast:`, error.message);
        throw error;
    }
}

/**
 * Validate Bitcoin transaction hex
 * @param {string} rawTxHex - Raw transaction hex string
 * @returns {boolean} True if valid hex
 */
function validateTransactionHex(rawTxHex) {
    // Check if it's valid hex
    if (!/^[0-9a-fA-F]+$/.test(rawTxHex)) {
        return false;
    }
    
    // Minimum transaction size (rough check)
    if (rawTxHex.length < 120) { // ~60 bytes minimum
        return false;
    }
    
    return true;
}

/**
 * Main broadcast function with fallback providers
 * @param {string} rawTxHex - Raw transaction hex string
 * @param {string} network - 'mainnet' or 'testnet'
 * @param {Array<string>} providers - Array of provider names to try
 * @returns {Promise<string>} Transaction ID
 */
async function broadcastBitcoinTransaction(rawTxHex, network = 'testnet', providers = ['blockstream', 'blockcypher']) {
    console.log(`🚀 [BROADCAST] Starting Bitcoin transaction broadcast`);
    console.log(`📊 Network: ${network}`);
    console.log(`📄 Transaction size: ${rawTxHex.length / 2} bytes`);
    console.log(`🔧 Providers to try: ${providers.join(', ')}`);
    
    // Validate transaction hex
    if (!validateTransactionHex(rawTxHex)) {
        throw new Error('Invalid transaction hex format');
    }
    
    const providerFunctions = {
        blockstream: broadcastViaBlockstream,
        rpc: broadcastViaRPC,
        blockcypher: broadcastViaBlockCypher
    };
    
    let lastError;
    
    for (const provider of providers) {
        try {
            console.log(`\n🔄 [BROADCAST] Trying provider: ${provider}`);
            
            if (!providerFunctions[provider]) {
                console.warn(`⚠️ [BROADCAST] Unknown provider: ${provider}, skipping`);
                continue;
            }
            
            const txid = await providerFunctions[provider](rawTxHex, network);
            
            console.log(`\n🎉 [SUCCESS] Transaction broadcasted successfully!`);
            console.log(`📄 Transaction ID: ${txid}`);
            console.log(`⏰ Timestamp: ${new Date().toISOString()}`);
            
            return txid;
            
        } catch (error) {
            console.error(`❌ [${provider.toUpperCase()}] Failed:`, error.message);
            lastError = error;
            
            // Continue to next provider
            if (providers.indexOf(provider) < providers.length - 1) {
                console.log(`🔄 [BROADCAST] Trying next provider...`);
            }
        }
    }
    
    // All providers failed
    console.error(`\n💥 [BROADCAST] All providers failed to broadcast transaction`);
    throw new Error(`Broadcast failed with all providers. Last error: ${lastError?.message}`);
}

/**
 * Load transaction from file
 * @param {string} filePath - Path to transaction file
 * @returns {string} Transaction hex
 */
function loadTransactionFromFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8').trim();
        console.log(`📁 [FILE] Loaded transaction from: ${filePath}`);
        return content;
    } catch (error) {
        throw new Error(`Failed to load transaction from file: ${error.message}`);
    }
}

/**
 * Save transaction result to file
 * @param {string} txid - Transaction ID
 * @param {string} network - Network used
 * @param {string} rawTxHex - Original transaction hex
 */
function saveTransactionResult(txid, network, rawTxHex) {
    const result = {
        txid,
        network,
        timestamp: new Date().toISOString(),
        transaction_hex: rawTxHex,
        explorer_urls: {
            blockstream: `https://blockstream.info${network === 'testnet' ? '/testnet' : ''}/tx/${txid}`,
            blockcypher: `https://live.blockcypher.com/btc${network === 'testnet' ? '-testnet' : ''}/tx/${txid}/`
        }
    };
    
    const fileName = `broadcast_result_${txid.substring(0, 8)}_${Date.now()}.json`;
    const filePath = path.join(process.cwd(), fileName);
    
    try {
        fs.writeFileSync(filePath, JSON.stringify(result, null, 2));
        console.log(`💾 [FILE] Saved result to: ${fileName}`);
    } catch (error) {
        console.warn(`⚠️ [FILE] Failed to save result: ${error.message}`);
    }
}

// CLI Interface
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        console.log(`
🚀 Bitcoin Transaction Broadcasting Tool

Usage:
  node broadcast_bitcoin_transaction.js <transaction_hex> [options]
  node broadcast_bitcoin_transaction.js --file <file_path> [options]

Options:
  --network <mainnet|testnet>     Network to use (default: testnet)
  --providers <provider1,provider2> Providers to try (default: blockstream,blockcypher)
  --file <path>                   Load transaction from file
  --save-result                   Save broadcast result to file
  --help, -h                      Show this help

Providers:
  blockstream     Blockstream.info API (recommended)
  blockcypher     BlockCypher API
  rpc            Bitcoin Core RPC (requires local node)

Examples:
  # Broadcast to testnet using default providers
  node broadcast_bitcoin_transaction.js 0200000001abc123...

  # Broadcast to mainnet using specific providers
  node broadcast_bitcoin_transaction.js 0200000001abc123... --network mainnet --providers blockstream,rpc

  # Load transaction from file
  node broadcast_bitcoin_transaction.js --file ./signed_tx.hex --network testnet --save-result
        `);
        process.exit(0);
    }
    
    try {
        let rawTxHex;
        let network = CONFIG.DEFAULT_NETWORK;
        let providers = ['blockstream', 'blockcypher'];
        let saveResult = false;
        
        // Parse arguments
        for (let i = 0; i < args.length; i++) {
            switch (args[i]) {
                case '--network':
                    network = args[++i];
                    if (!['mainnet', 'testnet'].includes(network)) {
                        throw new Error('Network must be "mainnet" or "testnet"');
                    }
                    break;
                case '--providers':
                    providers = args[++i].split(',').map(p => p.trim());
                    break;
                case '--file':
                    rawTxHex = loadTransactionFromFile(args[++i]);
                    break;
                case '--save-result':
                    saveResult = true;
                    break;
                default:
                    if (!rawTxHex && !args[i].startsWith('--')) {
                        rawTxHex = args[i];
                    }
                    break;
            }
        }
        
        if (!rawTxHex) {
            throw new Error('Transaction hex is required. Use --help for usage info.');
        }
        
        // Broadcast transaction
        const txid = await broadcastBitcoinTransaction(rawTxHex, network, providers);
        
        // Save result if requested
        if (saveResult) {
            saveTransactionResult(txid, network, rawTxHex);
        }
        
        console.log(`\n🎊 [FINAL] Broadcast completed successfully!`);
        process.exit(0);
        
    } catch (error) {
        console.error(`\n💥 [ERROR] ${error.message}`);
        process.exit(1);
    }
}

// Export for use as module
export {
    broadcastBitcoinTransaction,
    broadcastViaBlockstream,
    broadcastViaRPC,
    broadcastViaBlockCypher
};

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}
