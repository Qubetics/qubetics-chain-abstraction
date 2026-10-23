#!/usr/bin/env node

/**
 * Test script for solver_add_liquidity flow
 * 
 * This script:
 * 1. Signs an add_liquidity request with your private key
 * 2. Sends it to the RPC endpoint
 * 3. Monitors the response
 * 
 * Usage:
 *   node test_add_liquidity.js
 * 
 * Configuration:
 *   Edit the CONFIG section below to set your parameters
 *   Or use command-line options to override (see parseArgs function)
 */

const ethers = require('ethers');
const https = require('https');
const http = require('http');

// ============================================================================
// CONFIGURATION - EDIT THESE VALUES
// ============================================================================

const CONFIG = {
    // REQUIRED: Private key for signing (must match VERIFICATION_ADDRESS in .env)
    privateKey: process.env.CONFIG_1_PRIVATE_KEY,

    // RPC endpoint URL
    rpcUrl: 'http://localhost:8082',

    // REQUIRED: API key for authentication (must match RPC_API_KEY in .env)
    // Example: '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45'
    apiKey: '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45',

    // Solver ID (unique identifier for the solver)
    solverId: 'SOLVER_002',

    // Solver address (Ethereum address)
    solverAddress: '0xB1Bd33e2021307FE723C6ad795fE7c37Fab60F26',

    // Amount in smallest units (wei for EVM, satoshis for BTC)
    amount: '1000',

    // Chain ID: 0 for BTC, 9029 for EVM/Qubetics
    chainId: 9029,

    // Number of requests to send (for batch testing)
    count: 10,

    // Interval between requests in milliseconds
    interval: 1000,
};

// ============================================================================
// END CONFIGURATION
// ============================================================================

// Parse command line arguments (overrides CONFIG values if provided)
function parseArgs() {
    const args = process.argv.slice(2);
    
    // Start with CONFIG values
    const options = { ...CONFIG };

    // Override with command-line arguments if provided
    for (let i = 0; i < args.length; i += 2) {
        const key = args[i];
        const value = args[i + 1];

        switch (key) {
            case '--private-key':
                options.privateKey = value;
                break;
            case '--rpc-url':
                options.rpcUrl = value;
                break;
            case '--solver-id':
                options.solverId = value;
                break;
            case '--solver-address':
                options.solverAddress = value;
                break;
            case '--amount':
                options.amount = value;
                break;
            case '--chain-id':
                options.chainId = parseInt(value);
                break;
            case '--count':
                options.count = parseInt(value);
                break;
            case '--interval':
                options.interval = parseInt(value);
                break;
            case '--api-key':
                options.apiKey = value;
                break;
            case '--help':
            case '-h':
                printHelp();
                process.exit(0);
            default:
                console.log(`Unknown option: ${key}`);
                printHelp();
                process.exit(1);
        }
    }

    return options;
}

// Print help message
function printHelp() {
    console.log(`
Usage:
  node test_add_liquidity.js [options]

Configuration:
  Edit the CONFIG section in this file to set default values.
  Command-line options override CONFIG values.

Options:
  --private-key <key>      Private key for signing (must match VERIFICATION_ADDRESS)
  --rpc-url <url>          RPC endpoint URL (default: from CONFIG)
  --solver-id <id>         Solver ID (default: from CONFIG)
  --solver-address <addr>  Solver address (default: from CONFIG)
  --amount <amount>        Amount in smallest units (default: from CONFIG)
  --chain-id <id>          Chain ID - 0 for BTC, 9029 for EVM (default: from CONFIG)
  --count <n>              Number of requests to send (default: from CONFIG)
  --interval <ms>          Interval between requests in ms (default: from CONFIG)
  --api-key <key>          API key for authentication (default: from CONFIG)
  --help, -h               Show this help message

Examples:
  # Use CONFIG values
  node test_add_liquidity.js

  # Override specific values
  node test_add_liquidity.js --count 5 --amount 2000000

  # Override private key only
  node test_add_liquidity.js --private-key 0xYOUR_KEY
`);
}

// Sign the message payload
async function signMessage(payload, privateKey) {
    // Create wallet from private key
    const wallet = new ethers.Wallet(privateKey);

    // Stringify the payload (this is what gets signed)
    const message = JSON.stringify(payload);

    // Sign using personal_sign (eth_sign with "\x19Ethereum Signed Message:\n" prefix)
    const signature = await wallet.signMessage(message);

    return { message, signature, signerAddress: wallet.address };
}

// Send request to RPC endpoint
async function sendRequest(url, data, apiKey) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const isHttps = urlObj.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: urlObj.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(JSON.stringify(data)),
                'X-API-KEY': apiKey || '',
            },
        };

        const req = httpModule.request(options, (res) => {
            let body = '';

            res.on('data', (chunk) => {
                body += chunk;
            });

            res.on('end', () => {
                try {
                    const response = JSON.parse(body);
                    resolve({ status: res.statusCode, data: response });
                } catch (e) {
                    resolve({ status: res.statusCode, data: body });
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.write(JSON.stringify(data));
        req.end();
    });
}

// Main function
async function main() {
    const options = parseArgs();

    // Validate private key
    if (!options.privateKey || options.privateKey === '0xYOUR_PRIVATE_KEY_HERE') {
        console.error('❌ Error: Private key is required');
        console.log('\nPlease set your private key in one of these ways:');
        console.log('\n1. Edit the CONFIG section in this file:');
        console.log('   privateKey: \'0xYOUR_ACTUAL_PRIVATE_KEY\'');
        console.log('\n2. Pass it as a command-line argument:');
        console.log('   node test_add_liquidity.js --private-key 0xYOUR_PRIVATE_KEY');
        console.log('\n⚠️  WARNING: Never commit your private key to git!');
        console.log('   Consider using environment variables for production.');
        process.exit(1);
    }

    // Validate API key
    if (!options.apiKey || options.apiKey === 'YOUR_API_KEY_HERE') {
        console.error('❌ Error: API key is required');
        console.log('\nPlease set your API key in one of these ways:');
        console.log('\n1. Edit the CONFIG section in this file:');
        console.log('   apiKey: \'YOUR_API_KEY\'');
        console.log('\n2. Pass it as a command-line argument:');
        console.log('   node test_add_liquidity.js --api-key YOUR_API_KEY');
        console.log('\nThe API key must match RPC_API_KEY in your .env file.');
        process.exit(1);
    }

    // Ensure private key has 0x prefix
    const privateKey = options.privateKey.startsWith('0x') 
        ? options.privateKey 
        : '0x' + options.privateKey;

    console.log('\n🧪 Testing Add Liquidity Flow');
    console.log('================================');
    console.log(`RPC URL:         ${options.rpcUrl}`);
    console.log(`Solver ID:       ${options.solverId}`);
    console.log(`Solver Address:  ${options.solverAddress}`);
    console.log(`Amount:          ${options.amount}`);
    console.log(`Chain ID:        ${options.chainId}`);
    console.log(`Request Count:   ${options.count}`);
    console.log(`Interval:        ${options.interval}ms`);
    console.log('================================\n');

    let successCount = 0;
    let failureCount = 0;

    for (let i = 0; i < options.count; i++) {
        try {
            // Create payload
            const payload = {
                solverId: options.solverId,
                solverAddress: options.solverAddress,
                amount: options.amount,
                chainId: options.chainId,
            };

            console.log(`\n📤 Request ${i + 1}/${options.count}`);
            console.log('Payload:', JSON.stringify(payload, null, 2));

            // Sign the message
            const { message, signature, signerAddress } = await signMessage(payload, privateKey);
            console.log(`✍️  Signed by:   ${signerAddress}`);
            console.log(`📝 Signature:   ${signature.substring(0, 20)}...${signature.substring(signature.length - 10)}`);

            // Prepare request
            const requestData = {
                message,
                signature,
            };

            // Send request
            console.log(`🚀 Sending to:  ${options.rpcUrl}/solver_add_liquidity`);
            const response = await sendRequest(`${options.rpcUrl}/solver_add_liquidity`, requestData, options.apiKey);

            // Process response
            if (response.status === 200 && response.data.status === 'success') {
                console.log(`✅ Success: ${response.data.message}`);
                successCount++;
            } else {
                console.log(`❌ Failed: ${response.data.message || response.data.error_message || 'Unknown error'}`);
                console.log(`   Status: ${response.status}`);
                if (response.data.error_message) {
                    console.log(`   Error: ${response.data.error_message}`);
                }
                failureCount++;
            }

            // Wait before next request (if not the last one)
            if (i < options.count - 1) {
                console.log(`⏳ Waiting ${options.interval}ms before next request...`);
                await new Promise(resolve => setTimeout(resolve, options.interval));
            }

        } catch (error) {
            console.log(`❌ Error: ${error.message}`);
            failureCount++;
        }
    }

    // Summary
    console.log('\n================================');
    console.log('📊 Test Summary');
    console.log('================================');
    console.log(`✅ Successful:   ${successCount}`);
    console.log(`❌ Failed:       ${failureCount}`);
    console.log(`📊 Total:        ${options.count}`);
    console.log('================================\n');

    if (successCount > 0) {
        console.log('💡 Next Steps:');
        console.log('   1. Wait ~60 seconds for global clock tick');
        console.log('   2. Monitor logs for batch processing:');
        console.log('      tail -f logs.txt | grep ADD_LIQUIDITY');
        console.log('   3. Look for these log messages:');
        console.log('      - "✅ [ADD_LIQUIDITY] Accepted solver_add_liquidity request"');
        console.log('      - "📋 [ADD_LIQUIDITY] Selected N requests for batching"');
        console.log('      - "✅ [ADD_LIQUIDITY_BATCH] Submitted batchTransfer transaction"');
        console.log('   4. Verify on-chain transaction on block explorer\n');
    }

    process.exit(failureCount > 0 ? 1 : 0);
}

// Run main function
main().catch((error) => {
    console.error('❌ Unhandled error:', error);
    process.exit(1);
});
