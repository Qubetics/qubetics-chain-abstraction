#!/usr/bin/env node

/**
 * Test script for claim reward RPC endpoint (Node.js version)
 * This script tests the claim reward functionality by calling the RPC endpoint
 * with proper signature validation and message formatting.
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');

// Configuration
const RPC_BASE_URL = 'http://localhost:8081'; // Default RPC port
const CLAIM_REWARD_ENDPOINT = `${RPC_BASE_URL}/claim_reward`;

// Test private key - REPLACE THIS WITH YOUR REGISTERED TEST PRIVATE KEY
const TEST_PRIVATE_KEY = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

// Test addresses - REPLACE THESE WITH YOUR ACTUAL TEST ADDRESSES
const TEST_ETH_ADDRESS = '0x742d35Cc6634C0532925a3b8D0C4C4C4C4C4C4C4';
const TEST_BTC_ADDRESS = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';

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
function makeRequest(url, data) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data)
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
        const response = await makeRequest(`${RPC_BASE_URL}/status`, '{}');
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
 * Create a simple signature (placeholder - implement proper Ethereum signing)
 */
function createSignature(message, privateKey) {
    // This is a placeholder signature - implement proper Ethereum signature generation
    // For production use, use libraries like ethers.js or web3.js
    const hash = crypto.createHash('sha256').update(message).digest('hex');
    return `0x${hash}${'0'.repeat(64)}`; // Placeholder signature
}

/**
 * Test claim reward (ETH only)
 */
async function testClaimRewardEthOnly() {
    console.log(`\n${colors.blue}🧪 Testing claim reward (ETH only)...${colors.reset}`);
    
    const message = `Claim reward for Ethereum address: ${TEST_ETH_ADDRESS}`;
    const signature = createSignature(message, TEST_PRIVATE_KEY);
    
    const payload = {
        signature: signature,
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
            if (result.status === 'success') {
                console.log(`${colors.green}✅ Claim reward request successful!${colors.reset}`);
                if (result.reward_tics) {
                    console.log(`${colors.green}💰 TICS reward: ${result.reward_tics}${colors.reset}`);
                }
                if (result.reward_btc) {
                    console.log(`${colors.green}💰 BTC reward: ${result.reward_btc}${colors.reset}`);
                }
                if (result.total_reward) {
                    console.log(`${colors.green}💰 Total reward: ${result.total_reward}${colors.reset}`);
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
                if (result.total_reward) {
                    console.log(`${colors.green}💰 Total reward: ${result.total_reward}${colors.reset}`);
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
                if (result.total_reward) {
                    console.log(`${colors.green}💰 Total reward: ${result.total_reward}${colors.reset}`);
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
        console.log(`${colors.yellow}💡 Please start the server first and ensure it's running on port 8081${colors.reset}`);
        process.exit(1);
    }
    
    console.log(`\n${colors.yellow}🔑 Using test private key: ${TEST_PRIVATE_KEY.substring(0, 10)}...${colors.reset}`);
    console.log(`${colors.yellow}📍 ETH address: ${TEST_ETH_ADDRESS}${colors.reset}`);
    console.log(`${colors.yellow}📍 BTC address: ${TEST_BTC_ADDRESS}${colors.reset}`);
    console.log('\n==================================================');
    
    // Run all tests
    await testClaimRewardEthOnly();
    await testClaimRewardBtcOnly();
    await testClaimRewardBoth();
    await testInvalidSignature();
    await testNoAddresses();
    
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
