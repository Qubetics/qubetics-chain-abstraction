#!/usr/bin/env node

/**
 * Parallel Intent Test Script
 * 
 * This script registers users on both nodes and then sends deposit intents
 * in parallel to test the signing flow.
 * 
 * Usage:
 *   node test_round_mismatch.js
 * 
 * Environment variables:
 *   NODE1_PORT - Port for first node (default: 8083)
 *   NODE2_PORT - Port for second node (default: 8084)
 *   API_KEY - API key for authentication (default: from test_register_user.js)
 */

import axios from 'axios';
import { Wallet } from 'ethers';

// =========================
// Configuration
// =========================
const NODE1_PORT = process.env.NODE1_PORT || '8083';
const NODE2_PORT = process.env.NODE2_PORT || '8084';
const NODE1_URL = `http://127.0.0.1:${NODE1_PORT}`;
const NODE2_URL = `http://127.0.0.1:${NODE2_PORT}`;
const API_KEY = process.env.API_KEY || "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// Two different private keys for two different users
const PRIVKEY_1 = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const PRIVKEY_2 = 'e41af1d4f1413ed18e0200d225fa810287c5d90d3d11d6fc9723f93538718fc1';

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
  green: '\x1b[32m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  const timestamp = new Date().toISOString();
  console.log(`${colors[color]}[${timestamp}] ${message}${colors.reset}`);
}

/** Serialize deposit intent for signing; must match server serde_json key order and amount-as-string. */
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
// Helper Functions
// =========================

async function getUserInfo(ethereumAddress, nodeUrl, nodeLabel) {
  try {
    const response = await axios.get(`${nodeUrl}/user_info/${ethereumAddress}`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });
    return { success: true, data: response.data };
  } catch (error) {
    if (error.response?.status === 404) {
      log(`[${nodeLabel}] ⚠️  User not found: ${ethereumAddress}`, 'yellow');
    } else {
      log(`[${nodeLabel}] ❌ Failed to get user info: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

async function registerUser(ethereumAddress, wallet, nodeUrl, nodeLabel) {
  try {
    log(`[${nodeLabel}] 🔵 Registering address: ${ethereumAddress}`, 'blue');

    const timestamp = Math.floor(Date.now() / 1000);
    const message = `register:${ethereumAddress}:${timestamp}`;
    const signature = await wallet.signMessage(message);

    const response = await axios.post(
      `${nodeUrl}/register_user`,
      {
        tics_address: ethereumAddress,
        signature: signature,
        message: message
      },
      { 
        headers: { 
          'Content-Type': 'application/json', 
          'X-API-KEY': API_KEY 
        }, 
        timeout: 10000 
      }
    );

    log(`[${nodeLabel}] ✅ Registration successful!`, 'green');
    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`[${nodeLabel}] ❌ Registration failed: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`[${nodeLabel}] ❌ Registration error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

async function submitDepositIntent(wallet, amount, nodeUrl, nodeLabel, intentId) {
  const amountStr = typeof amount === 'string' ? amount : String(amount);
  try {
    const signerAddr = await wallet.getAddress();
    log(`[${nodeLabel}] 🔐 Submitting deposit intent ${intentId} for signer: ${signerAddr}`, 'blue');
    log(`[${nodeLabel}]    Amount: ${amount}`, 'cyan');

    // Fetch user info to get the canonical Ethereum address
    const userInfo = await getUserInfo(signerAddr, nodeUrl, nodeLabel);
    if (!userInfo.success) {
      throw new Error('User not registered on this node');
    }

    // Construct DepositIntent (amount as string to match server DepositIntent.amount)
    const timestamp = Date.now();
    const depositIntent = {
      source_address: userInfo.data.derived_eth_address,
      target_address: userInfo.data.derived_eth_address,
      source_chain: 'qubetics',
      target_chain: 'qubetics',
      amount: amountStr,
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp,
    };

    log(`[${nodeLabel}] 📊 Deposit Intent ${intentId}: ${JSON.stringify(depositIntent)}`, 'cyan');

    // Sign the serialized intent (same bytes the server uses for hash/recovery)
    const msg = serializeDepositIntentForSigning(depositIntent);
    const signature = await wallet.signMessage(msg);

    log(`[${nodeLabel}] ✍️  Signature for intent ${intentId}: ${signature.substring(0, 20)}...`, 'cyan');

    const startTime = Date.now();
    const response = await axios.post(
      `${nodeUrl}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      {
        headers: { 
          'Content-Type': 'application/json', 
          'X-API-KEY': API_KEY 
        },
        timeout: 60000
      }
    );
    const elapsed = Date.now() - startTime;

    const status = response.data.status;
    if (status === 'success') {
      log(`[${nodeLabel}] ✅ Intent ${intentId} SUCCESS - Transaction completed! (${elapsed}ms)`, 'green');
    } else if (status === 'submitted') {
      log(`[${nodeLabel}] 📤 Intent ${intentId} SUBMITTED - Transaction is being processed (${elapsed}ms)`, 'yellow');
    } else if (status === 'processing') {
      log(`[${nodeLabel}] ⏳ Intent ${intentId} PROCESSING - Transaction is still being processed (${elapsed}ms)`, 'yellow');
    } else {
      log(`[${nodeLabel}] ❓ Intent ${intentId} UNKNOWN STATUS: ${status} (${elapsed}ms)`, 'yellow');
    }

    if (response.data.user_to_network_tx_id) {
      log(`[${nodeLabel}] 🎯 Intent ${intentId} Transaction ID: ${response.data.user_to_network_tx_id}`, 'green');
    }

    return { 
      success: true, 
      data: response.data,
      intentId,
      nodeLabel,
      elapsed,
      timestamp
    };
  } catch (error) {
    log(`[${nodeLabel}] ❌ Intent ${intentId} failed: ${error.message}`, 'red');
    if (error.response?.data) {
      log(`[${nodeLabel}]    Error details: ${JSON.stringify(error.response.data)}`, 'red');
    }
    return { 
      success: false, 
      error: error.message,
      intentId,
      nodeLabel
    };
  }
}

// =========================
// Main Test Function
// =========================

async function runRoundMismatchTest() {
  log(`\n${colors.bright}🧪 Starting Parallel Intent Test${colors.reset}`, 'bright');
  log(`📍 Node 1: ${NODE1_URL}`, 'cyan');
  log(`📍 Node 2: ${NODE2_URL}`, 'cyan');

  // Create wallets
  const pk1 = PRIVKEY_1.startsWith('0x') ? PRIVKEY_1 : `0x${PRIVKEY_1}`;
  const pk2 = PRIVKEY_2.startsWith('0x') ? PRIVKEY_2 : `0x${PRIVKEY_2}`;
  const wallet1 = new Wallet(pk1);
  const wallet2 = new Wallet(pk2);
  const addr1 = await wallet1.getAddress();
  const addr2 = await wallet2.getAddress();

//   log(`\n🔑 User 1: ${addr1}`, 'blue');
//   log(`🔑 User 2: ${addr2}`, 'blue');

// //   Step 1: Register users on their respective nodes only
//   log(`\n${colors.bright}📝 Step 1: Registering users on their respective nodes...${colors.reset}`, 'bright');
//   log(`   User 1 → Node 1 only`, 'yellow');
//   log(`   User 2 → Node 2 only`, 'yellow');
  
// //   const [reg1_node1, reg2_node2] = await Promise.all([
// //     registerUser(addr1, wallet1, NODE1_URL, 'Node1-User1'),
// //     registerUser(addr2, wallet2, NODE2_URL, 'Node2-User2')
// //   ]);

// //   Check registration resultscl
//   const allRegistered = reg1_node1.success && reg2_node2.success;
  
//   if (!allRegistered) {
//     log(`\n⚠️  Some registrations failed. Continuing anyway...`, 'yellow');
//   } else {
//     log(`\n✅ Users registered successfully on their respective nodes`, 'green');
//   }

// //   Wait a bit for registration to propagate
//   log(`\n⏳ Waiting 2 seconds for registrations to propagate...`, 'yellow');
//   await new Promise(r => setTimeout(r, 2000));

  // Step 2: Send intents in parallel
  log(`\n${colors.bright}🚀 Step 2: Sending intents in parallel...${colors.reset}`, 'bright');
  
  // Different amounts to make intents clearly distinguishable
  const amount1 = 1400000000000000000; // 1 TICS (regular number, not BigInt)
  const amount2 = 2400000000000000000; // 2 TICS (regular number, not BigInt)

  log(`💰 User 1 amount: ${amount1}`, 'cyan');
  log(`💰 User 2 amount: ${amount2}`, 'cyan');
  log(`\n   User 1 → Node 1 (port ${NODE1_PORT})`, 'yellow');
  log(`   User 2 → Node 2 (port ${NODE2_PORT})`, 'yellow');

  const startTime = Date.now();
// 
//   Send both requests in parallel: User 1 to Node 1, User 2 to Node 2
  const [result1, result2] = await Promise.all([
    submitDepositIntent(wallet1, amount1, NODE1_URL, 'Node1', 'User1'),
    submitDepositIntent(wallet2, amount2, NODE2_URL, 'Node2', 'User2')
  ]);

  const totalElapsed = Date.now() - startTime;

  log(`\n${colors.bright}📊 Results:${colors.reset}`, 'bright');
  log(`   Total elapsed time: ${totalElapsed}ms`, 'cyan');
  log(`   User 1 (Node 1): ${result1.success ? '✅ Success' : '❌ Failed'}`, result1.success ? 'green' : 'red');
  log(`   User 2 (Node 2): ${result2.success ? '✅ Success' : '❌ Failed'}`, result2.success ? 'green' : 'red');

  if (result1.success && result1.data.user_to_network_tx_id) {
    log(`   User 1 TX ID: ${result1.data.user_to_network_tx_id}`, 'cyan');
  }
  if (result2.success && result2.data.user_to_network_tx_id) {
    log(`   User 2 TX ID: ${result2.data.user_to_network_tx_id}`, 'cyan');
  }

  log(`\n${colors.bright}✅ Test completed!${colors.reset}`, 'bright');
}

// =========================
// CLI help
// =========================
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
  log(`  node test_round_mismatch.js`, 'cyan');
  log(`\n${colors.bright}Environment Variables:${colors.reset}`, 'bright');
  log(`  NODE1_PORT  - Port for first node (default: 8083)`, 'cyan');
  log(`  NODE2_PORT  - Port for second node (default: 8084)`, 'cyan');
  log(`  API_KEY     - API key for authentication`, 'cyan');
  log(`\n${colors.bright}Example:${colors.reset}`, 'bright');
  log(`  NODE1_PORT=8083 NODE2_PORT=8084 node test_round_mismatch.js`, 'cyan');
  process.exit(0);
}

// Run
runRoundMismatchTest().catch(err => {
  log(`\n❌ Test runner failed: ${err.message}`, 'red');
  console.error(err);
  process.exit(1);
});

