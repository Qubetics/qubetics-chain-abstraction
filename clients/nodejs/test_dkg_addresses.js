#!/usr/bin/env node

import axios from 'axios';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = 'http://127.0.0.1:8083';
const API_KEY = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// =========================
// Colors for console output
// =========================
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  green: '\x1b[32m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// =========================
// Test Functions
// =========================

/**
 * Test the /main_addresses endpoint
 * Returns main ETH and BTC addresses generated from DKG group key
 */
async function testGetMainAddresses() {
  try {
    log(`\n🔵 Testing GET /main_addresses`, 'blue');

    const response = await axios.get(`${RPC_BASE_URL}/main_addresses`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`✅ Main addresses retrieved!`, 'green');
    log(`📊 Response:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Message: ${response.data.message}`, 'cyan');
    
    if (response.data.ethereum_address) {
      log(`   Ethereum Address: ${response.data.ethereum_address}`, 'green');
    } else {
      log(`   Ethereum Address: Not available`, 'yellow');
    }
    
    if (response.data.btc_address) {
      log(`   Bitcoin Address: ${response.data.btc_address}`, 'green');
    } else {
      log(`   Bitcoin Address: Not available`, 'yellow');
    }

    if (response.data.error_message) {
      log(`   Error Message: ${response.data.error_message}`, 'red');
    }

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`❌ Failed to get main addresses with status ${error.response.status}:`, 'red');
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

/**
 * Test the /vault_addresses endpoint
 * Returns vault ETH and BTC addresses generated from DKG
 */
async function testGetVaultAddresses() {
  try {
    log(`\n🔵 Testing GET /vault_addresses`, 'blue');

    const response = await axios.get(`${RPC_BASE_URL}/vault_addresses`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`✅ Vault addresses retrieved!`, 'green');
    log(`📊 Response:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Message: ${response.data.message}`, 'cyan');
    
    if (response.data.ethereum_address) {
      log(`   Ethereum Address: ${response.data.ethereum_address}`, 'green');
    } else {
      log(`   Ethereum Address: Not available`, 'yellow');
    }
    
    if (response.data.btc_address) {
      log(`   Bitcoin Address: ${response.data.btc_address}`, 'green');
    } else {
      log(`   Bitcoin Address: Not available`, 'yellow');
    }

    if (response.data.error_message) {
      log(`   Error Message: ${response.data.error_message}`, 'red');
    }

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`❌ Failed to get vault addresses with status ${error.response.status}:`, 'red');
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

/**
 * Test DKG status to verify DKG is completed before testing addresses
 */
async function testDKGStatus() {
  try {
    log(`\n🚀 Checking DKG status`, 'blue');
    const response = await axios.get(`${RPC_BASE_URL}/dkg_status`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`✅ DKG status retrieved`, 'green');
    log(`📊 DKG Status:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   DKG Status: ${response.data.dkg_status || 'Unknown'}`, 'cyan');
    log(`   Secret Share Available: ${response.data.secret_share_available}`, 'cyan');
    log(`   Message: ${response.data.message}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    log(`❌ Failed to get DKG status: ${error.message}`, 'red');
    return { success: false, error: error.message };
  }
}

// =========================
// Main Test Runner
// =========================
async function runTests() {
  log(`\n${colors.bright}🧪 Starting DKG Addresses RPC Test${colors.reset}`, 'bright');
  log(`📍 Target RPC: ${RPC_BASE_URL}`, 'cyan');

  // 1) Check DKG status first
  const dkgStatus = await testDKGStatus();
  
  if (!dkgStatus.success) {
    log(`\n⚠️ Could not verify DKG status, but continuing with address tests...`, 'yellow');
  } else if (dkgStatus.data.dkg_status !== 'completed') {
    log(`\n⚠️ DKG is not completed yet (status: ${dkgStatus.data.dkg_status})`, 'yellow');
    log(`   Addresses may not be available.`, 'yellow');
  }

  // 2) Test main addresses
  log(`\n${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
  log(`${colors.bright}Test 1: Main Addresses${colors.reset}`, 'bright');
  log(`${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
  const mainResult = await testGetMainAddresses();

  // 3) Test vault addresses
  log(`\n${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
  log(`${colors.bright}Test 2: Vault Addresses${colors.reset}`, 'bright');
  log(`${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
  const vaultResult = await testGetVaultAddresses();

  // 4) Summary
  log(`\n${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
  log(`${colors.bright}📋 Test Summary${colors.reset}`, 'bright');
  log(`${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
  
  if (mainResult.success) {
    const mainStatus = mainResult.data.status === 'success' ? '✅' : '⚠️';
    log(`${mainStatus} Main Addresses: ${mainResult.data.status}`, mainResult.data.status === 'success' ? 'green' : 'yellow');
  } else {
    log(`❌ Main Addresses: Failed`, 'red');
  }

  if (vaultResult.success) {
    const vaultStatus = vaultResult.data.status === 'success' ? '✅' : '⚠️';
    log(`${vaultStatus} Vault Addresses: ${vaultResult.data.status}`, vaultResult.data.status === 'success' ? 'green' : 'yellow');
  } else {
    log(`❌ Vault Addresses: Failed`, 'red');
  }

  log(`\n${colors.bright}✅ Test completed!${colors.reset}`, 'bright');
}

// =========================
// CLI help
// =========================
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
  log(`  node test_dkg_addresses.js`, 'cyan');
  log(`\n${colors.bright}Description:${colors.reset}`, 'bright');
  log(`  This script tests the RPC endpoints for DKG generated addresses:`, 'yellow');
  log(`  - GET /main_addresses - Returns main ETH and BTC addresses from DKG group key`, 'yellow');
  log(`  - GET /vault_addresses - Returns vault ETH and BTC addresses from DKG`, 'yellow');
  log(`\n${colors.bright}Configuration:${colors.reset}`, 'bright');
  log(`  RPC_BASE_URL: ${RPC_BASE_URL}`, 'cyan');
  log(`  API_KEY: ${API_KEY.substring(0, 20)}...`, 'cyan');
  process.exit(0);
}

// Run
runTests().catch(err => {
  log(`\n❌ Test runner failed: ${err.message}`, 'red');
  process.exit(1);
});

