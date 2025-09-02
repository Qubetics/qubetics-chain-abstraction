#!/usr/bin/env node

import axios from 'axios';
import { Wallet } from 'ethers';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = 'http://localhost:8081';

// 👉 Private key you provided (hex, no 0x prefix needed)
const TEST_PRIVKEY = '2f1765e04f0a5c394eb3b07ee38bf210008473f6e679a4f901f554905f7f3f89';

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
// HTTP helpers
// =========================
async function testRegisterUser(ethereumAddress) {
  try {
    log(`\n🔵 Registering address: ${ethereumAddress}`, 'blue');

    const response = await axios.post(
      `${RPC_BASE_URL}/register_user`,
      { ethereum_address: ethereumAddress },
      { headers: { 'Content-Type': 'application/json' }, timeout: 10000 }
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
      log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
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
    return { success: false, error: error.message };
  }
}

async function testGetUserInfo(ethereumAddress) {
  try {
    log(`\n🔍 Fetching user info for: ${ethereumAddress}`, 'blue');

    const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, { timeout: 10000 });

    log(`✅ User info retrieved!`, 'green');
    log(`📊 User Info:`, 'cyan');
    log(`   User ID: ${response.data.user_id}`, 'cyan');
    log(`   Ethereum Address: ${response.data.ethereum_address}`, 'cyan');
    log(`   HMAC Constant: ${response.data.hmac_constant}`, 'cyan');
    log(`   Has Tweaked Share: ${response.data.has_tweaked_share}`, 'cyan');
    log(`   Has User Group Key: ${response.data.has_user_group_key}`, 'cyan');
    log(`   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');
    log(`   Created At: ${response.data.created_at}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response?.status === 404) {
      log(`❌ User not found: ${ethereumAddress}`, 'yellow');
    } else if (error.response) {
      log(`❌ Failed to get user info: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`❌ Error getting user info: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

async function testDKGStatus() {
  try {
    log(`\n🚀 Checking DKG status`, 'blue');
    const response = await axios.get(`${RPC_BASE_URL}/dkg_status`, { timeout: 10000 });

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

// =========================
// New: user_mpc_deposit test
// =========================
// Update testUserMpcDeposit to fetch user info
async function testUserMpcDeposit({ wallet, amount }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`\n🔐 Testing user_mpc_deposit for signer: ${signerAddr}`, 'blue');
    log(`💰 Amount: ${amount}`, 'cyan');

    // Fetch user info to get the canonical Ethereum address
    const userInfo = await testGetUserInfo(signerAddr);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Construct DepositIntent
    const depositIntent = {
      source_address: userInfo.data.ethereum_address, // Use canonical address
      target_address: '0x541Bc7A7Eb63769c079dc57eF1b9d9651Dd920Af',
      source_chain: 'ethereum',
      target_chain: 'ethereum',
      amount: amount,
      source_token: 'ETH',
      target_token: 'ETH',
      timestamp: Math.floor(Date.now() / 1000), // Current Unix timestamp in seconds
    };

    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);
    log(`📝 Message: ${msg}`, 'cyan');

    // EIP-191 personal_sign
    const signature = await wallet.signMessage(msg);
    log(`✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      { headers: { 'Content-Type': 'application/json' }, timeout: 10000 }
    );

    log(`✅ user_mpc_deposit verified`, 'green');
    log(`📊 Response:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Signer Address (recovered): ${response.data.signer_address}`, 'cyan');
    log(`   Is Registered: ${response.data.is_registered}`, 'cyan');
    log(`   Used personal_sign prefix: ${response.data.used_personal_sign_prefix}`, 'cyan');
    log(`   Echo Amount: ${response.data.amount}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`❌ user_mpc_deposit failed with status ${error.response.status}:`, 'red');
      log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
      if (error.response.data) {
        log(`   Full Error Response:`, 'red');
        console.log(JSON.stringify(error.response.data, null, 2));
      }
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

  // 2) Register ONLY the derived address
  const reg = await testRegisterUser(signerAddr);

  if (reg.success) {
    log(`\n⏳ Waiting 2 seconds before checking user info...`, 'yellow');
    await new Promise(r => setTimeout(r, 2000));
    await testGetUserInfo(signerAddr);
  } else {
    log(`\n⚠️ Registration failed; continuing to deposit test (is_registered may be false).`, 'yellow');
  }

  // 3) MPC deposit test
  const amount = 123456; // keep safe for JSON
  await testUserMpcDeposit({ wallet, amount });

  log(`\n${colors.bright}✅ Test completed!${colors.reset}`, 'bright');
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
