#!/usr/bin/env node

/**
 * Bitcoin Transaction Broadcaster
 * 
 * Broadcasts a raw Bitcoin transaction to the network using mempool.space or custom RPC endpoint.
 * 
 * Usage:
 *   node broadcast_bitcoin_tx.js <raw_tx_hex>
 *   echo <raw_tx_hex> | node broadcast_bitcoin_tx.js
 *   node broadcast_bitcoin_tx.js <raw_tx_hex> --testnet
 * 
 * Environment Variables:
 *   MPC_BITCOIN_RPC_URL - Custom RPC endpoint URL (defaults to mempool.space)
 * 
 * Examples:
 *   node broadcast_bitcoin_tx.js 0100000001...
 *   MPC_BITCOIN_RPC_URL=https://blockstream.info/api/tx node broadcast_bitcoin_tx.js 0100000001...
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// Parse command line arguments
const args = process.argv.slice(2);
const isTestnet = args.includes('--testnet') || args.includes('-t');
const testnetIndex = args.indexOf('--testnet');
const testnetIndexShort = args.indexOf('-t');
const testnetArgIndex = testnetIndex !== -1 ? testnetIndex : testnetIndexShort;

// Remove testnet flag from args
if (testnetArgIndex !== -1) {
    args.splice(testnetArgIndex, 1);
}

// Get raw transaction hex from command line or stdin
let rawTxHex = args[0];

// Default URLs
const defaultUrl = isTestnet
    ? 'https://mempool.space/testnet/api/tx'
    : 'https://mempool.space/api/tx';

// Get URL from environment or use default
const url = process.env.MPC_BITCOIN_RPC_URL || defaultUrl;

/**
 * Broadcast transaction to Bitcoin network
 * @param {string} rawTxHex - Raw transaction hex string
 * @param {string} url - API endpoint URL
 * @returns {Promise<{success: boolean, txid?: string, error?: string}>}
 */
async function broadcastTransaction(rawTxHex, url) {
    return new Promise((resolve, reject) => {
        try {
            const urlObj = new URL(url);
            const isHttps = urlObj.protocol === 'https:';
            const client = isHttps ? https : http;

            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'text/plain',
                    'User-Agent': 'mpc-node/0.1.0',
                    'Content-Length': Buffer.byteLength(rawTxHex)
                }
            };

            console.log(`📡 Broadcasting transaction to: ${url}`);
            console.log(`📄 Transaction hex (first 64 chars): ${rawTxHex.substring(0, 64)}...`);

            const req = client.request(options, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    const bodyText = data.trim();

                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        // Try to parse as JSON first
                        let txid = null;

                        try {
                            const json = JSON.parse(bodyText);
                            // Handle { txid: ... } format
                            if (json.txid && typeof json.txid === 'string') {
                                txid = json.txid;
                            }
                            // Handle { data: { txid: ... } } format
                            else if (json.data && json.data.txid && typeof json.data.txid === 'string') {
                                txid = json.data.txid;
                            }
                        } catch (e) {
                            // Not JSON, try as plain text
                            // Check if it's a 64-character hex string (txid)
                            const trimmed = bodyText.trim();
                            if (trimmed.length === 64 && /^[0-9a-fA-F]+$/.test(trimmed)) {
                                txid = trimmed;
                            }
                        }

                        if (txid) {
                            console.log(`✅ Transaction broadcasted successfully!`);
                            console.log(`🆔 TXID: ${txid}`);
                            resolve({ success: true, txid });
                        } else {
                            console.log(`✅ Transaction broadcasted successfully, but no txid found in response`);
                            console.log(`📄 Response: ${bodyText.substring(0, 200)}`);
                            resolve({ success: true, txid: null });
                        }
                    } else {
                        const errorMsg = `HTTP ${res.statusCode}: ${bodyText}`;
                        console.error(`❌ Failed to broadcast transaction: ${errorMsg}`);
                        reject(new Error(errorMsg));
                    }
                });
            });

            req.on('error', (error) => {
                console.error(`❌ Network error: ${error.message}`);
                reject(error);
            });

            req.write(rawTxHex);
            req.end();

        } catch (error) {
            reject(error);
        }
    });
}

/**
 * Read from stdin if no argument provided
 */
function readFromStdin() {
    return new Promise((resolve, reject) => {
        if (rawTxHex) {
            resolve(rawTxHex);
            return;
        }

        let input = '';
        process.stdin.setEncoding('utf8');

        process.stdin.on('data', (chunk) => {
            input += chunk;
        });

        process.stdin.on('end', () => {
            const trimmed = input.trim();
            if (trimmed) {
                resolve(trimmed);
            } else {
                reject(new Error('No transaction hex provided'));
            }
        });

        process.stdin.on('error', reject);
    });
}

// Main execution
(async () => {
    try {
        // Get transaction hex
        const txHex = await readFromStdin();

        // Validate hex string
        if (!txHex || !/^[0-9a-fA-F]+$/.test(txHex)) {
            console.error('❌ Error: Invalid transaction hex string');
            console.error('   Transaction hex must be a valid hexadecimal string');
            process.exit(1);
        }

        if (txHex.length < 20) {
            console.error('❌ Error: Transaction hex is too short');
            process.exit(1);
        }

        // Broadcast transaction
        const result = await broadcastTransaction(txHex, url);

        if (result.success) {
            if (result.txid) {
                console.log(`\n🎉 Success! Transaction ID: ${result.txid}`);
                console.log(`🔗 View on mempool.space: ${isTestnet ? 'https://mempool.space/testnet/tx/' : 'https://mempool.space/tx/'}${result.txid}`);
                process.exit(0);
            } else {
                console.log(`\n⚠️  Transaction broadcasted but no TXID returned`);
                process.exit(0);
            }
        } else {
            process.exit(1);
        }

    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        process.exit(1);
    }
})();

