#!/usr/bin/env node

import axios from 'axios';

// Configuration
const RPC_BASE_URL = 'http://localhost:8081';
const TEST_ETH_ADDRESSES = [
    '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
    '0x1234567890123456789012345678901234567890',
    '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    '0x1111111111111111111111111111111111111111',
    '0x2222222222222222222222222222222222222222'
];

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

async function testRegisterUser(ethereumAddress) {
    try {
        log(`\n🔵 Testing registration for address: ${ethereumAddress}`, 'blue');
        
        const response = await axios.post(`${RPC_BASE_URL}/register_user`, {
            ethereum_address: ethereumAddress
        }, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });

        log(`✅ Registration successful!`, 'cyan');
        log(`📊 Response:`, 'cyan');
        log(`   Status: ${response.data.status}`, 'cyan');
        log(`   Message: ${response.data.message}`, 'cyan');
        log(`   Address 1: ${response.data.address_1}`, 'cyan');
        log(`   Address 2: ${response.data.address_2}`, 'cyan');
        
        return {
            success: true,
            data: response.data
        };
        
    } catch (error) {
        if (error.response) {
            log(`❌ Registration failed with status ${error.response.status}:`, 'red');
            log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
            
            // Log the full error response for debugging
            if (error.response.data) {
                log(`   Full Error Response:`, 'red');
                console.log(JSON.stringify(error.response.data, null, 2));
            }
        } else if (error.code === 'ECONNREFUSED') {
            log(`❌ Connection refused - Is the RPC server running on port 8081?`, 'red');
        } else if (error.code === 'ENOTFOUND') {
            log(`❌ Server not found - Check if the RPC server is accessible`, 'red');
        } else if (error.code === 'ETIMEDOUT') {
            log(`❌ Request timed out - Server might be overloaded`, 'red');
        } else {
            log(`❌ Unexpected error: ${error.message}`, 'red');
        }
        
        return {
            success: false,
            error: error.message
        };
    }
}

async function testGetUserInfo(ethereumAddress) {
    try {
        log(`\n🔍 Testing user info retrieval for address: ${ethereumAddress}`, 'blue');
        
        const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, {
            timeout: 10000
        });

        log(`✅ User info retrieved successfully!`, 'cyan');
        log(`📊 User Info:`, 'cyan');
        log(`   User ID: ${response.data.user_id}`, 'cyan');
        log(`   Ethereum Address: ${response.data.ethereum_address}`, 'cyan');
        log(`   HMAC Constant: ${response.data.hmac_constant}`, 'cyan');
        log(`   Has Tweaked Share: ${response.data.has_tweaked_share}`, 'cyan');
        log(`   Created At: ${response.data.created_at}`, 'cyan');
        
        return {
            success: true,
            data: response.data
        };
        
    } catch (error) {
        if (error.response?.status === 404) {
            log(`❌ User not found: ${ethereumAddress}`, 'yellow');
        } else if (error.response) {
            log(`❌ Failed to get user info: ${error.response.data?.message || error.response.statusText}`, 'red');
        } else {
            log(`❌ Error getting user info: ${error.message}`, 'red');
        }
        
        return {
            success: false,
            error: error.message
        };
    }
}

async function testDKGStatus() {
    try {
        log(`\n🚀 Testing DKG status endpoint`, 'blue');
        
        const response = await axios.get(`${RPC_BASE_URL}/dkg_status`, {
            timeout: 10000
        });

        log(`✅ DKG status retrieved successfully!`, 'cyan');
        log(`📊 DKG Status:`, 'cyan');
        log(`   Status: ${response.data.status}`, 'cyan');
        log(`   DKG Status: ${response.data.dkg_status || 'Unknown'}`, 'cyan');
        log(`   Secret Share Available: ${response.data.secret_share_available}`, 'cyan');
        log(`   Message: ${response.data.message}`, 'cyan');
        
        return {
            success: true,
            data: response.data
        };
        
    } catch (error) {
        log(`❌ Failed to get DKG status: ${error.message}`, 'red');
        return {
            success: false,
            error: error.message
        };
    }
}

async function testStartDKG() {
    try {
        log(`\n🚀 Testing DKG start endpoint`, 'blue');
        
        const response = await axios.post(`${RPC_BASE_URL}/start_dkg`, {}, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });

        log(`✅ DKG start request sent successfully!`, 'cyan');
        log(`📊 Response:`, 'cyan');
        log(`   Status: ${response.data.status}`, 'cyan');
        log(`   Message: ${response.data.message}`, 'cyan');
        
        return {
            success: true,
            data: response.data
        };
        
    } catch (error) {
        if (error.response) {
            log(`❌ DKG start failed: ${error.response.data?.message || error.response.statusText}`, 'red');
        } else {
            log(`❌ Error starting DKG: ${error.message}`, 'red');
        }
        return {
            success: false,
            error: error.message
        };
    }
}

async function runTests() {
    log(`\n${colors.bright}🧪 Starting RPC Endpoint Tests${colors.reset}`, 'bright');
    log(`📍 Testing against: ${RPC_BASE_URL}`, 'cyan');
    
    // Test DKG status first
    log(`\n🔍 Checking DKG status before testing...`, 'blue');
    await testDKGStatus();
    
    // Test DKG start
    log(`\n🚀 Starting DKG process...`, 'blue');
    await testStartDKG();
    
    // Wait a bit for DKG to potentially start
    log(`\n⏳ Waiting 5 seconds for DKG to potentially start...`, 'yellow');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Test DKG status again
    log(`\n🔍 Checking DKG status after start...`, 'blue');
    await testDKGStatus();
    
    // Test user registration with ONLY ONE address
    log(`\n${colors.bright}👥 Testing User Registration (Single Request)${colors.reset}`, 'bright');
    
    // Use only the first address
    const address = TEST_ETH_ADDRESSES[0];
    log(`\n🎯 Testing with single address: ${address}`, 'blue');
    
    const result = await testRegisterUser(address);
    
    if (result.success) {
        // Wait a bit before getting user info
        log(`\n⏳ Waiting 2 seconds before checking user info...`, 'yellow');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Test getting user info
        await testGetUserInfo(address);
    }
    
    log(`\n${colors.bright}✅ Single user test completed!${colors.reset}`, 'bright');
    log(`\n🛑 Script will now exit as requested.`, 'yellow');
}

// Handle command line arguments
if (process.argv.includes('--help') || process.argv.includes('-h')) {
    log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
    log(`  node test_register_user.js [options]`, 'cyan');
    log(`\n${colors.bright}Options:${colors.reset}`, 'bright');
    log(`  --help, -h     Show this help message`, 'cyan');
    log(`\n${colors.bright}Examples:${colors.reset}`, 'bright');
    log(`  node test_register_user.js`, 'cyan');
    log(`\n${colors.bright}Note:${colors.reset}`, 'bright');
    log(`  This script now tests only ONE user registration and then exits.`, 'yellow');
    process.exit(0);
}

// Check if axios is available
try {
    // In ES modules, we can't use require, so we'll just proceed
    // axios should be available if it's installed
} catch (error) {
    log(`\n❌ Error: axios is not installed. Please install it first:`, 'red');
    log(`   npm install axios`, 'yellow');
    log(`   or`, 'yellow');
    log(`   yarn add axios`, 'yellow');
    process.exit(1);
}

// Run the tests
runTests().catch(error => {
    log(`\n❌ Test runner failed: ${error.message}`, 'red');
    process.exit(1);
}); 