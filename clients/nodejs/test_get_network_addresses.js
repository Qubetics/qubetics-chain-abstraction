#!/usr/bin/env node

/**
 * Test script for get_network_addresses RPC endpoint
 * This script retrieves network and vault addresses (ETH/TICS and BTC)
 * These addresses are the same across all nodes in the network
 */

import axios from 'axios';

// Configuration
const RPC_BASE_URL = process.env.RPC_BASE_URL || 'http://127.0.0.1:8083';
const API_KEY = process.env.RPC_API_KEY || process.env.API_KEY || '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

// Colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

/**
 * Get network addresses (network and vault addresses for ETH/TICS and BTC)
 * No peer_id required - addresses are the same across all nodes
 */
async function getNetworkAddresses() {
    try {
        log(`\n🔵 Getting network addresses...`, 'blue');
        log(`   Endpoint: ${RPC_BASE_URL}/get_network_addresses`, 'cyan');

        const headers = {};
        if (API_KEY) {
            headers['X-API-KEY'] = API_KEY;
        }

        const response = await axios.get(
            `${RPC_BASE_URL}/get_network_addresses`,
            {
                headers,
                timeout: 10000
            }
        );

        log(`\n✅ Network addresses retrieved!`, 'green');
        log(`📊 Response:`, 'cyan');
        log(`   Status: ${response.data.status}`, 'cyan');
        log(`   Message: ${response.data.message}`, 'cyan');

        if (response.data.network_addresses) {
            log(`\n   📍 Network Addresses (Main):`, 'green');
            log(`      ETH/TICS Address: ${response.data.network_addresses.eth_address}`, 'cyan');
            log(`      BTC Address: ${response.data.network_addresses.btc_address}`, 'cyan');
        } else {
            log(`   ⚠️ Network Addresses: Not available`, 'yellow');
        }

        if (response.data.vault_addresses) {
            log(`\n   📍 Vault Addresses:`, 'green');
            log(`      ETH/TICS Address: ${response.data.vault_addresses.eth_address}`, 'cyan');
            log(`      BTC Address: ${response.data.vault_addresses.btc_address}`, 'cyan');
        } else {
            log(`   ⚠️ Vault Addresses: Not available`, 'yellow');
        }

        if (response.data.error_message) {
            log(`\n   ❌ Error Message: ${response.data.error_message}`, 'red');
        }

        return { success: true, data: response.data };
    } catch (error) {
        if (error.response) {
            log(`❌ Failed to get network addresses with status ${error.response.status}:`, 'red');
            log(`   Error: ${(error.response.data && error.response.data.message) || error.response.statusText}`, 'red');
            if (error.response.data) {
                log(`   Full Error Response:`, 'red');
                console.log(JSON.stringify(error.response.data, null, 2));
            }
        } else if (error.code === 'ECONNREFUSED') {
            log(`❌ Connection refused - Is the RPC server running on ${RPC_BASE_URL}?`, 'red');
        } else if (error.code === 'ENOTFOUND') {
            log(`❌ Server not found - Check if the RPC server is accessible`, 'red');
        } else if (error.code === 'ETIMEDOUT') {
            log(`❌ Request timed out - Server might be overloaded`, 'red');
        } else {
            log(`❌ Unexpected error: ${error.message}`, 'red');
        }
        return { success: false, error: error.message };
    }
}

// Main execution
getNetworkAddresses()
    .then((result) => {
        if (result.success) {
            log('\n✅ Script completed successfully', 'green');
            process.exit(0);
        } else {
            log('\n❌ Script failed', 'red');
            process.exit(1);
        }
    })
    .catch((error) => {
        log(`\n❌ Unexpected error: ${error.message}`, 'red');
        process.exit(1);
    });

