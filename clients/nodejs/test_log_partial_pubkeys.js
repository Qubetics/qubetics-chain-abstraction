#!/usr/bin/env node

/**
 * Test script for log_partial_pubkeys RPC endpoint
 * This script logs all partial public keys (network, vault, and user share pubkeys) for a specific peer
 */

import axios from 'axios';

// Configuration
const RPC_BASE_URL = process.env.RPC_BASE_URL || 'http://127.0.0.1:8084';
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
 * Log partial pubkeys for a specific peer
 */
async function logPartialPubkeys(peerId) {
    try {
        log(`\n🔵 Logging partial pubkeys for peer: ${peerId}`, 'blue');

        const headers = {
            'Content-Type': 'application/json'
        };
        if (API_KEY) {
            headers['X-API-KEY'] = API_KEY;
        }

        const response = await axios.post(
            `${RPC_BASE_URL}/log_partial_pubkeys`,
            { peer_id: peerId },
            { headers, timeout: 10000 }
        );

        log(`✅ Partial pubkeys retrieved!`, 'green');
        log(`📊 Response:`, 'cyan');
        log(`   Status: ${response.data.status}`, 'cyan');
        log(`   Peer ID: ${response.data.peer_id}`, 'cyan');
        log(`   Message: ${response.data.message}`, 'cyan');

        if (response.data.network_share_pubkey) {
            log(`\n   📍 Network Share Pubkey:`, 'green');
            log(`      0x${response.data.network_share_pubkey}`, 'cyan');
        } else {
            log(`   ⚠️ Network Share Pubkey: Not available`, 'yellow');
        }

        if (response.data.vault_share_pubkey) {
            log(`\n   📍 Vault Share Pubkey:`, 'green');
            log(`      0x${response.data.vault_share_pubkey}`, 'cyan');
        } else {
            log(`   ⚠️ Vault Share Pubkey: Not available`, 'yellow');
        }

        if (response.data.user_share_pubkeys && response.data.user_share_pubkeys.length > 0) {
            log(`\n   📍 User Share Pubkeys (${response.data.user_share_pubkeys.length} users):`, 'green');
            response.data.user_share_pubkeys.forEach((userInfo, index) => {
                log(`      [${index + 1}] User: ${userInfo.user_eth_address}`, 'cyan');
                log(`          Pubkey: 0x${userInfo.share_pubkey}`, 'cyan');
            });
        } else {
            log(`   ⚠️ User Share Pubkeys: None found`, 'yellow');
        }

        if (response.data.error_message) {
            log(`\n   ❌ Error Message: ${response.data.error_message}`, 'red');
        }

        return { success: true, data: response.data };
    } catch (error) {
        if (error.response) {
            log(`❌ Failed to log partial pubkeys with status ${error.response.status}:`, 'red');
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
const peerId = process.argv[2];

if (!peerId) {
    log('❌ Usage: node test_log_partial_pubkeys.js <peer_id>', 'red');
    log('   Example: node test_log_partial_pubkeys.js 12D3KooW...', 'yellow');
    process.exit(1);
}

logPartialPubkeys(peerId)
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

