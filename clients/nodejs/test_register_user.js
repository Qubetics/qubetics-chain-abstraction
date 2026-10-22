#!/usr/bin/env node

import axios from 'axios';
import { Wallet } from 'ethers';
import { randomBytes } from 'crypto';

// Polyfill for randomUUID (Node.js v12 compatible)
function randomUUID() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 10
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join('-');
}

// =========================
// Configuration
// =========================
const RPC_BASE_URL = 'http://127.0.0.1:8082';
const API_KEY = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// 👉 Private key you provided (hex, no 0x prefix needed)
// const TEST_PRIVKEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const TEST_PRIVKEY = '4f1dce53664453b7160cdf7f91c12539b71f4392e10f3c5c46812da97eb6a105';
// const TEST_PRIVKEY = '1e61daf814fae3af13d9ec447f2b2da96a7d307b5c73ec85c275fb9c67ea8f1a';

let TEST_TX_ID = "0x0942448ca6f6517c05c361e249cdaf9f5e054e6290236c43f6537705ef2a7885";

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

const oooo = 2323232
function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

/**
 * Serialize deposit intent for signing. Must match server's serde_json::to_string(DepositIntent):
 * same key order (source_address, target_address, source_chain, target_chain, amount, source_token, target_token, timestamp)
 * and amount as string so the signed message bytes match what the server hashes/verifies.
 */
function serializeDepositIntentForSigning(intent) {
  return JSON.stringify({
    source_address: intent.source_address,
    target_address: intent.target_address,
    source_chain: intent.source_chain,
    target_chain: intent.target_chain,
    amount: String(intent.amount),
    source_token: intent.source_token,
    target_token: intent.target_token,
    timestamp: typeof intent.timestamp === 'number' ? intent.timestamp : Number(intent.timestamp),
  });
}

// =========================
// HTTP helpers
// =========================
async function testRegisterUser(ethereumAddress, wallet) {
  try {
    log(`\n🔵 Registering address: ${ethereumAddress}`, 'blue');

    // Create registration message: "register:{tics_address}:{timestamp}"
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `register:${ethereumAddress}:${timestamp}`;
    log(`📝 Registration message: ${message}`, 'cyan');

    // Sign the message using the wallet
    const signature = await wallet.signMessage(message);
    log(`✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/register_user`,
      {
        tics_address: ethereumAddress,
        signature: signature,
        message: message
      },
      { headers: { 'Content-Type': 'application/json', 'X-API-KEY': "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45" }, timeout: 10000 }
    );

    log(`✅ Registration successful!`, 'green');
    log(`📊 Response:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Message: ${response.data.message}`, 'cyan');
    log(`   Address 1: ${response.data.address_1}`, 'cyan');
    log(`   Address 2: ${response.data.address_2}`, 'cyan');
    log(`   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`❌ Registration failed with status ${error.response.status}:`, 'red');
      log(`   Error: ${(error.response.data && error.response.data.message) || error.response.statusText}`, 'red');
      if (error.response.data) {
        log(`   Full Error Response:`, 'red');
        console.log(JSON.stringify(error.response.data, null, 2));
      }
    } else if (error.code === 'ECONNREFUSED') {
      log(`❌ Connection refused - Is the RPC server running on port ${process.env.RPC_PORT || 8081}?`, 'red');
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

async function testGetUserInfo(ethereumAddress) {
  try {
    log(`\n🔍 Fetching user info for: ${ethereumAddress}`, 'blue');

    const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`✅ User info retrieved!`, 'green');
    log(`📊 User Info:`, 'cyan');
    log(`   User ID: ${response.data.user_id}`, 'cyan');
    log(`   TICS Address: ${response.data.tics_address}`, 'cyan');
    log(`   HMAC Constant: ${response.data.hmac_constant}`, 'cyan');
    log(`   Has Tweaked Share: ${response.data.has_tweaked_share}`, 'cyan');
    log(`   Has User Group Key: ${response.data.has_user_group_key}`, 'cyan');
    log(`   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');
    log(`   Created At: ${response.data.created_at}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      log(`❌ User not found: ${ethereumAddress}`, 'yellow');
    } else if (error.response) {
      log(`❌ Failed to get user info: ${(error.response.data && error.response.data.message) || error.response.statusText}`, 'red');
    } else {
      log(`❌ Error getting user info: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

async function testDKGStatus() {
  try {
    log(`\n🚀 Checking DKG status`, 'blue');
    const response = await axios.get(`${RPC_BASE_URL}/dkg_status`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`✅ DKG status ok`, 'green');
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

// ===============================
//    New: user_mpc_deposit test  
// ===============================  
// This test will show different response types:
// - success: Transaction completed with tx_id
// - submitted: Transaction submitted and being processed
// - processing: Transaction still being processed
// - error: Transaction failed with actual blockchain error message
// - timeout: Transaction processing timed out
// Update testUserMpcDeposit to fetch user info
async function testUserMpcDeposit({ wallet, amount, idempotencyKey }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`\n🔐 Testing user_mpc_deposit WITHOUT tx_id for signer: ${signerAddr}`, 'blue');
    log(`💰 Amount: ${amount}`, 'cyan');

    // Fetch user info to get the canonical Ethereum address
    const userInfo = await testGetUserInfo(signerAddr);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Construct DepositIntent (amount as string to match server DepositIntent.amount)
    const depositIntent = {
      source_address: userInfo.data.derived_eth_address,
      target_address: userInfo.data.derived_eth_address,
      source_chain: 'qubetics',
      target_chain: 'qubetics',
      amount: String(amount),
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp: oooo,
    };
    // const depositIntent = {
    //   source_address: userInfo.data.derived_btc_address, // Use canonical address
    //   target_address: userInfo.data.derived_eth_address,
    //   source_chain: 'bitcoin',
    //   target_chain: 'qubetics',
    //   amount: amount, // Use the passed amount parameter
    //   source_token: 'BTC',
    //   target_token: 'TICS',
    //   timestamp: oooo,
    // };

    log(`📊 Deposit Intent: ${JSON.stringify(depositIntent)}`, 'cyan');
    // Sign the serialized intent (same bytes the server uses for hash/recovery)
    const msg = serializeDepositIntentForSigning(depositIntent);
    log(`📝 Message to sign: ${msg}`, 'cyan');

    // EIP-191 personal_sign over the deposit intent JSON
    const signature = await wallet.signMessage(msg);
    log(`✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      {
        headers: { 'Content-Type': 'application/json', 'X-API-KEY': "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45" },
        timeout: 60000 // 15 seconds timeout to match server processing time
      }
    );

    // Check response status to determine success or error
    const isSuccess = response.data.status === 'success';
    const isSubmitted = response.data.status === 'submitted';
    const isProcessing = response.data.status === 'processing';
    const isError = response.data.status === 'error';
    const isTimeout = response.data.status === 'timeout';

    if (isSuccess) {
      log(`✅ user_mpc_deposit SUCCESS - Transaction completed!`, 'green');
    } else if (isSubmitted) {
      log(`📤 user_mpc_deposit SUBMITTED - Transaction is being processed`, 'yellow');
    } else if (isProcessing) {
      log(`⏳ user_mpc_deposit PROCESSING - Transaction is still being processed`, 'yellow');
    } else if (isError) {
      log(`❌ user_mpc_deposit ERROR - Transaction failed`, 'red');
    } else if (isTimeout) {
      log(`⏰ user_mpc_deposit TIMEOUT - Transaction processing timed out`, 'yellow');
    } else {
      log(`❓ user_mpc_deposit UNKNOWN STATUS: ${response.data.status}`, 'yellow');
    }

    log(`📊 Response Details:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Signer Address (recovered): ${response.data.signer_address}`, 'cyan');
    log(`   Is Registered: ${response.data.is_registered}`, 'cyan');
    log(`   Used personal_sign prefix: ${response.data.used_personal_sign_prefix}`, 'cyan');
    log(`   Amount: ${response.data.amount}`, 'cyan');
    log(`📊 Response: ${response}`, 'cyan');

    // Show transaction ID if available
    if (response.data.user_to_network_tx_id) {
      log(`   🎯 Transaction ID: ${response.data.user_to_network_tx_id}`, 'green');
      TEST_TX_ID = response.data.user_to_network_tx_id;
    } else {
      log(`   🎯 Transaction ID: Not available yet`, 'yellow');
    }
    console.log(`📊 Response: ${JSON.stringify(response.data)}`, 'cyan');
    // Show error message if present
    if (response.data.error_message) {
      if (isError) {
        log(`   💥 Error Message: ${response.data.error_message}`, 'red');
      } else {
        log(`   ℹ️  Message: ${response.data.error_message}`, 'yellow');
      }
    }

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`❌ user_mpc_deposit failed with HTTP status ${error.response.status}:`, 'red');

      // Check if we got a structured response with our new format
      if (error.response.data && error.response.data.status) {
        const errorData = error.response.data;
        log(`   Response Status: ${errorData.status}`, 'red');
        log(`   Signer Address: ${errorData.signer_address || 'Unknown'}`, 'red');
        log(`   Is Registered: ${errorData.is_registered || 'Unknown'}`, 'red');

        if (errorData.tx_id) {
          log(`   Transaction ID: ${errorData.tx_id}`, 'red');
        }

        if (errorData.error_message) {
          log(`   🔥 Chain Error: ${errorData.error_message}`, 'red');
        }
      } else {
        // Fallback for generic HTTP errors
        log(`   Error: ${(error.response.data && error.response.data.message) || error.response.statusText}`, 'red');
      }

      // Always show full response for debugging
      if (error.response.data) {
        log(`   Full Error Response:`, 'red');
        console.log(JSON.stringify(error.response.data, null, 2));
      }
    } else if (error.code === 'ECONNREFUSED') {
      log(`❌ Connection refused - Is the RPC server running on port ${process.env.RPC_PORT || 8081}?`, 'red');
    } else if (error.code === 'ENOTFOUND') {
      log(`❌ Server not found - Check if the RPC server is accessible`, 'red');
    } else if (error.code === 'ETIMEDOUT') {
      log(`❌ Request timed out - Server might be overloaded`, 'red');
    } else {
      log(`❌ user_mpc_deposit error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// =========================
async function runTests() {
  log(`\n${colors.bright}🧪 Starting Registration + MPC Deposit Test (Derived Address Only)${colors.reset}`, 'bright');
  log(`📍 Target RPC: ${RPC_BASE_URL}`, 'cyan');

  // Wallet from provided private key
  const pk = TEST_PRIVKEY.startsWith('0x') ? TEST_PRIVKEY : `0x${TEST_PRIVKEY}`;
  const wallet = new Wallet(pk);
  const signerAddr = await wallet.getAddress();
  log(`\n🔑 Derived signer address from TEST_PRIVKEY: ${signerAddr}`, 'blue');

  // 1) DKG status
  await testDKGStatus();

  // // 2) Register ONLY the derived address 
  // const reg = await testRegisterUser(signerAddr, wallet);

  // if (reg.success) {
  //   log(`\n⏳ Waiting 2 seconds before checking user info...`, 'yellow');
  //   await new Promise(r => setTimeout(r, 2000));
  //   await testGetUserInfo(signerAddr);
  // } else {
  //   log(`\n⚠️ Registration failed; continuing to deposit test (is_registered may be false).`, 'yellow');
  // }

  // // 3) MPC deposit test WITHOUT tx_id (should pass Some(signer) to handle_deposit_intent)
  // log(`\n🧪 Test 1: Normal deposit amount WITHOUT tx_id`, 'blue');
  const amount = "25000000000000000000"
  await testUserMpcDeposit({ wallet, amount });
  // log(`\n🧪 Test 1: Normal deposit amount WITHOUT tx_id`, 'blue');
  // const amount = "2511"
  // await testUserMpcDeposit({ wallet, amount });

  // const address = '0xbac113cebd9CB2fBD2a01B5CBC43D0fC0EBed5e9';
  // await testGetRewardSolver(address);

  // 4) Simple deposit test (intent only, no signature)
  // log(`\n🧪 Test 2: Simple deposit (intent only, no signature)`, 'blue');
  // await testSimpleDeposit();

  // await new Promise(r => setTimeout(r, 10000));
  // 5) MPC deposit test WITHOUT tx_id and status
  // log(`\n🧪 Test 3: Deposit amount WITHOUT tx_id and status`, 'blue');
  // await testUserMpcDeposit({ wallet, amount });   

  // // 6) MPC deposit test with potentially problematic amount (might trigger errors)
  // log(`\n🧪 Test 4: Large deposit amount (might trigger errors)`, 'blue');
  // const largeAmount = 999999999; // Large amount that might cause insufficient funds
  // await testUserMpcDeposit({ wallet, amount: largeAmount });

  // log(`\n${colors.bright}✅ Test completed!${colors.reset}`, 'bright');
}

// =========================
// CLI help
// =========================
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
  log(`  node test_register_user.js`, 'cyan');
  log(`\n${colors.bright}Note:${colors.reset}`, 'bright');
  log(`  This script registers the address derived from the provided private key and tests /user_mpc_deposit.`, 'yellow');
  process.exit(0);
}

// Run
runTests().catch(err => {
  log(`\n❌ Test runner failed: ${err.message}`, 'red');
  process.exit(1);
});
