#!/usr/bin/env node

/**
 * Test script for claim reward RPC endpoint (Node.js version)
 * This script tests the claim reward functionality by calling the RPC endpoint
 * with proper signature validation and message formatting.
 */

import https from 'https';
import http from 'http';
import crypto from 'crypto';
import secp256k1 from 'secp256k1';
import keccak from 'keccak';


// Configuration
const RPC_BASE_URL = 'http://127.0.0.1:8083'; // Default RPC port
const CLAIM_REWARD_ENDPOINT = `${RPC_BASE_URL}/claim_reward`;
const API_KEY = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// Test private key - REPLACE THIS WITH YOUR REGISTERED TEST PRIVATE KEY
const TEST_PRIVATE_KEY = 'aa5d2e1f7fc11bbe6f19b12316c7a9acb2d633bba798fc5a3fea547f1cf99b0a';

// Test addresses - REPLACE THESE WITH YOUR ACTUAL TEST ADDRESSES
const TEST_ETH_ADDRESS = '0xf71736a05f5673da815c1853378ff12c1aad4ff6';
const TEST_BTC_ADDRESS = null //'mh12dZHkgTajT1H6t8FkWoNC4KucxByWBA';

// Colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

/**
 * Make HTTP request
 */
function makeRequest(url, data, method = 'POST') {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                'X-API-KEY': "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45" 
            }
        };

        const req = http.request(options, (res) => {
            let responseData = '';
            res.on('data', (chunk) => {
                responseData += chunk;
            });
            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(responseData);
                    resolve({ status: res.statusCode, data: jsonData });
                } catch (e) {
                    resolve({ status: res.statusCode, data: responseData });
                }
            });
        });

        req.on('error', (err) => {
            reject(err);
        });

        req.write(data);
        req.end();
    });
}

/**
 * Check server status
 */
async function checkServerStatus() {
    console.log(`${colors.yellow}🔍 Checking RPC server status...${colors.reset}`);

    try {
        const response = await makeRequest(`${RPC_BASE_URL}/status`, '', 'GET');
        if (response.status === 200) {
            console.log(`${colors.green}✅ RPC server is running${colors.reset}`);
            return true;
        } else {
            console.log(`${colors.red}❌ RPC server returned status: ${response.status}${colors.reset}`);
            return false;
        }
    } catch (error) {
        console.log(`${colors.red}❌ Cannot connect to RPC server: ${error.message}${colors.reset}`);
        console.log(`${colors.yellow}💡 Make sure the server is running on ${RPC_BASE_URL}${colors.reset}`);
        return false;
    }
}

/**
 * Derive Ethereum address from private key
 */
function getEthereumAddress(privateKeyHex) {

    // Remove 0x prefix if present
    const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const privateKeyBuffer = Buffer.from(privateKey, 'hex');

    // Create public key
    const publicKey = secp256k1.publicKeyCreate(privateKeyBuffer, false); // uncompressed

    // Remove the 0x04 prefix (first byte) and convert Uint8Array to Buffer
    const publicKeyWithoutPrefix = Buffer.from(publicKey.slice(1));

    // Hash with Keccak256
    const hash = keccak('keccak256').update(publicKeyWithoutPrefix).digest();

    // Take last 20 bytes as address
    const address = '0x' + hash.slice(-20).toString('hex');

    return address;
}

/**
 * Create a proper Ethereum signature using secp256k1
 */
function createSignature(message, privateKeyHex) {

    // Remove 0x prefix if present
    const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const privateKeyBuffer = Buffer.from(privateKey, 'hex');

    // Create personal message prefix (EIP-191)
    const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
    const prefixedMessage = prefix + message;

    // Hash the prefixed message with Keccak256 (convert string to Buffer)
    const messageHash = keccak('keccak256').update(Buffer.from(prefixedMessage, 'utf8')).digest();

    // Sign the message hash
    const signature = secp256k1.ecdsaSign(messageHash, privateKeyBuffer);

    // Use the recovery ID from the signature
    // secp256k1 returns recid as 0 or 1, but Ethereum expects 27 or 28
    const recoveryId = signature.recid;
    const v = 27 + recoveryId; // Convert to Ethereum format (27 or 28)

    // Format as r||s||v (65 bytes total)
    const r = signature.signature.slice(0, 32);
    const s = signature.signature.slice(32, 64);
    const vBuffer = Buffer.from([v]);

    const fullSignature = Buffer.concat([r, s, vBuffer]);
    return '0x' + fullSignature.toString('hex');
}

/**
 * Test claim reward (ETH only)
 */
async function testClaimRewardEthOnly() {
    console.log(`\n${colors.blue}🧪 Testing claim reward (ETH only)...${colors.reset}`);

    // Derive and display the expected address from the private key
    const expectedAddress = getEthereumAddress(TEST_PRIVATE_KEY);
    console.log(`${colors.blue}🔑 Expected address from private key: ${expectedAddress}${colors.reset}`);

    const message = "hello";
    const signature = createSignature(message, TEST_PRIVATE_KEY);

    console.log(`${colors.yellow}📝 Message: ${message}${colors.reset}`);
    console.log(`${colors.yellow}✍️ Signature: ${signature}${colors.reset}`);
    console.log(`${colors.yellow}📍 Using derived address (must match signer): ${expectedAddress}${colors.reset}`);
    console.log(`${colors.yellow}💡 Note: Server verifies that recovered address matches provided address${colors.reset}`);

    const payload = {
        signature: signature,
        message: message,
        ethereum_address: expectedAddress, // Must match the address derived from the private key
        btc_address: null
    };

    console.log(`${colors.yellow}📤 Sending request to: ${CLAIM_REWARD_ENDPOINT}${colors.reset}`);
    console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
    console.log(JSON.stringify(payload, null, 2));

    try {
        const response = await makeRequest(CLAIM_REWARD_ENDPOINT, JSON.stringify(payload));
        console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
        console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
        console.log(JSON.stringify(response.data, null, 2));

        if (response.status === 200) {
            const result = response.data;
            if (result.status === 'success') {
                console.log(`${colors.green}✅ Claim reward request successful!${colors.reset}`);
                if (result.reward_tics) {
                    console.log(`${colors.green}💰 TICS reward: ${result.reward_tics}${colors.reset}`);
                }
                if (result.reward_btc) {
                    console.log(`${colors.green}💰 BTC reward: ${result.reward_btc}${colors.reset}`);
                }
                if (result.tics_reward_tx_id) {
                    console.log(`${colors.green}🧾 TICS reward tx id: ${result.tics_reward_tx_id}${colors.reset}`);
                }
                if (result.btc_reward_tx_id) {
                    console.log(`${colors.green}🧾 BTC reward tx id: ${result.btc_reward_tx_id}${colors.reset}`);
                }
            } else {
                console.log(`${colors.red}❌ Claim reward failed: ${result.message || 'Unknown error'}${colors.reset}`);
                if (result.error_message) {
                    console.log(`${colors.red}❌ Error details: ${result.error_message}${colors.reset}`);
                }
            }
        } else {
            console.log(`${colors.red}❌ HTTP error: ${response.status}${colors.reset}`);
        }
    } catch (error) {
        console.log(`${colors.red}❌ Request failed: ${error.message}${colors.reset}`);
    }
}

/**
 * Test claim reward (BTC only)
 */
async function testClaimRewardBtcOnly() {
    console.log(`\n${colors.blue}🧪 Testing claim reward (BTC only)...${colors.reset}`);

    const message = `Claim reward for Bitcoin address: ${TEST_BTC_ADDRESS}`;
    const signature = createSignature(message, TEST_PRIVATE_KEY);

    const payload = {
        signature: signature,
        message: message,
        ethereum_address: null,
        btc_address: TEST_BTC_ADDRESS
    };

    console.log(`${colors.yellow}📤 Sending request to: ${CLAIM_REWARD_ENDPOINT}${colors.reset}`);
    console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
    console.log(JSON.stringify(payload, null, 2));

    try {
        const response = await makeRequest(CLAIM_REWARD_ENDPOINT, JSON.stringify(payload));
        console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
        console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
        console.log(JSON.stringify(response.data, null, 2));

        if (response.status === 200) {
            const result = response.data;
            if (result.status === 'success') {
                console.log(`${colors.green}✅ Claim reward request successful!${colors.reset}`);
                if (result.reward_tics) {
                    console.log(`${colors.green}💰 TICS reward: ${result.reward_tics}${colors.reset}`);
                }
                if (result.reward_btc) {
                    console.log(`${colors.green}💰 BTC reward: ${result.reward_btc}${colors.reset}`);
                }
                if (result.tics_reward_tx_id) {
                    console.log(`${colors.green}🧾 TICS reward tx id: ${result.tics_reward_tx_id}${colors.reset}`);
                }
                if (result.btc_reward_tx_id) {
                    console.log(`${colors.green}🧾 BTC reward tx id: ${result.btc_reward_tx_id}${colors.reset}`);
                }
            } else {
                console.log(`${colors.red}❌ Claim reward failed: ${result.message || 'Unknown error'}${colors.reset}`);
                if (result.error_message) {
                    console.log(`${colors.red}❌ Error details: ${result.error_message}${colors.reset}`);
                }
            }
        } else {
            console.log(`${colors.red}❌ HTTP error: ${response.status}${colors.reset}`);
        }
    } catch (error) {
        console.log(`${colors.red}❌ Request failed: ${error.message}${colors.reset}`);
    }
}

/**
 * Test claim reward (Both ETH and BTC)
 */
async function testClaimRewardBoth() {
    console.log(`\n${colors.blue}🧪 Testing claim reward (Both ETH and BTC)...${colors.reset}`);

    const message = `Claim reward for Ethereum: ${TEST_ETH_ADDRESS} and Bitcoin: ${TEST_BTC_ADDRESS}`;
    const signature = createSignature(message, TEST_PRIVATE_KEY);

    const payload = {
        signature: signature,
        message: message,
        ethereum_address: TEST_ETH_ADDRESS,
        btc_address: TEST_BTC_ADDRESS
    };

    console.log(`${colors.yellow}📤 Sending request to: ${CLAIM_REWARD_ENDPOINT}${colors.reset}`);
    console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
    console.log(JSON.stringify(payload, null, 2));

    try {
        const response = await makeRequest(CLAIM_REWARD_ENDPOINT, JSON.stringify(payload));
        console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
        console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
        console.log(JSON.stringify(response.data, null, 2));

        if (response.status === 200) {
            const result = response.data;
            if (result.status === 'success') {
                console.log(`${colors.green}✅ Claim reward request successful!${colors.reset}`);
                if (result.reward_tics) {
                    console.log(`${colors.green}💰 TICS reward: ${result.reward_tics}${colors.reset}`);
                }
                if (result.reward_btc) {
                    console.log(`${colors.green}💰 BTC reward: ${result.reward_btc}${colors.reset}`);
                }
                if (result.tics_reward_tx_id) {
                    console.log(`${colors.green}🧾 TICS reward tx id: ${result.tics_reward_tx_id}${colors.reset}`);
                }
                if (result.btc_reward_tx_id) {
                    console.log(`${colors.green}🧾 BTC reward tx id: ${result.btc_reward_tx_id}${colors.reset}`);
                }
            } else {
                console.log(`${colors.red}❌ Claim reward failed: ${result.message || 'Unknown error'}${colors.reset}`);
                if (result.error_message) {
                    console.log(`${colors.red}❌ Error details: ${result.error_message}${colors.reset}`);
                }
            }
        } else {
            console.log(`${colors.red}❌ HTTP error: ${response.status}${colors.reset}`);
        }
    } catch (error) {
        console.log(`${colors.red}❌ Request failed: ${error.message}${colors.reset}`);
    }
}

/**
 * Test invalid signature
 */
async function testInvalidSignature() {
    console.log(`\n${colors.blue}🧪 Testing claim reward (Invalid signature)...${colors.reset}`);

    const message = `Claim reward for Ethereum address: ${TEST_ETH_ADDRESS}`;
    const invalidSignature = '0x' + '0'.repeat(130); // Invalid signature format

    const payload = {
        signature: invalidSignature,
        message: message,
        ethereum_address: TEST_ETH_ADDRESS,
        btc_address: null
    };

    console.log(`${colors.yellow}📤 Sending request to: ${CLAIM_REWARD_ENDPOINT}${colors.reset}`);
    console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
    console.log(JSON.stringify(payload, null, 2));

    try {
        const response = await makeRequest(CLAIM_REWARD_ENDPOINT, JSON.stringify(payload));
        console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
        console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
        console.log(JSON.stringify(response.data, null, 2));

        if (response.status === 200) {
            const result = response.data;
            if (result.status === 'error') {
                console.log(`${colors.green}✅ Error handling working correctly!${colors.reset}`);
                console.log(`${colors.red}❌ Error message: ${result.message || 'Unknown error'}${colors.reset}`);
            } else {
                console.log(`${colors.red}❌ Expected error but got success - this might be a problem${colors.reset}`);
            }
        } else {
            console.log(`${colors.red}❌ HTTP error: ${response.status}${colors.reset}`);
        }
    } catch (error) {
        console.log(`${colors.red}❌ Request failed: ${error.message}${colors.reset}`);
    }
}

/**
 * Test no addresses
 */
async function testNoAddresses() {
    console.log(`\n${colors.blue}🧪 Testing claim reward (No addresses)...${colors.reset}`);

    const message = 'Claim reward with no addresses';
    const signature = createSignature(message, TEST_PRIVATE_KEY);

    const payload = {
        signature: signature,
        message: message,
        ethereum_address: null,
        btc_address: null
    };

    console.log(`${colors.yellow}📤 Sending request to: ${CLAIM_REWARD_ENDPOINT}${colors.reset}`);
    console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
    console.log(JSON.stringify(payload, null, 2));

    try {
        const response = await makeRequest(CLAIM_REWARD_ENDPOINT, JSON.stringify(payload));
        console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
        console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
        console.log(JSON.stringify(response.data, null, 2));

        if (response.status === 200) {
            const result = response.data;
            if (result.status === 'error') {
                console.log(`${colors.green}✅ Validation working correctly!${colors.reset}`);
                console.log(`${colors.red}❌ Error message: ${result.message || 'Unknown error'}${colors.reset}`);
            } else {
                console.log(`${colors.red}❌ Expected error but got success - this might be a problem${colors.reset}`);
            }
        } else {
            console.log(`${colors.red}❌ HTTP error: ${response.status}${colors.reset}`);
        }
    } catch (error) {
        console.log(`${colors.red}❌ Request failed: ${error.message}${colors.reset}`);
    }
}

/**
 * Main function
 */
async function main() {
    console.log(`${colors.blue}🚀 Starting Claim Reward RPC Test Script${colors.reset}`);
    console.log('==================================================');

    // Check if server is running
    if (!(await checkServerStatus())) {
        console.log(`\n${colors.red}❌ Cannot proceed - RPC server is not accessible${colors.reset}`);
        console.log(`${colors.yellow}💡 Please start the server first and ensure it's running on port 8082${colors.reset}`);
        process.exit(1);
    }

    console.log(`\n${colors.yellow}🔑 Using test private key: ${TEST_PRIVATE_KEY.substring(0, 10)}...${colors.reset}`);
    console.log(`${colors.yellow}📍 Test ETH address: ${TEST_ETH_ADDRESS}${colors.reset}`);
    console.log(`${colors.yellow}📍 Test BTC address: ${TEST_BTC_ADDRESS}${colors.reset}`);
    console.log('\n==================================================');

    // Run successful test only
    await testClaimRewardEthOnly();
    // await testClaimRewardBtcOnly();

    console.log('\n==================================================');
    console.log(`${colors.green}🏁 Test script completed!${colors.reset}`);
    console.log(`\n${colors.yellow}💡 Instructions:${colors.reset}`);
    console.log(`${colors.yellow}1. Replace TEST_PRIVATE_KEY with your registered test private key${colors.reset}`);
    console.log(`${colors.yellow}2. Replace TEST_ETH_ADDRESS with the corresponding Ethereum address${colors.reset}`);
    console.log(`${colors.yellow}3. Replace TEST_BTC_ADDRESS with your Bitcoin address${colors.reset}`);
    console.log(`${colors.yellow}4. Ensure the server is running and has rewards available for testing${colors.reset}`);
    console.log(`${colors.yellow}5. Run the script again to test with your actual credentials${colors.reset}`);
    console.log(`\n${colors.blue}📝 Note: This script uses placeholder signatures. For proper testing,${colors.reset}`);
    console.log(`${colors.blue}   implement proper Ethereum signature generation using ethers.js or web3.js.${colors.reset}`);
}

// Run the main function
main().catch(console.error);
