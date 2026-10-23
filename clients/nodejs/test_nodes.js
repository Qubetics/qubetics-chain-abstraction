#!/usr/bin/env node

/**
 * Sequencer Test Script - Parallel Contract Transactions
 * 
 * Tests the contract transaction sequencer by submitting 10 parallel transactions
 * from 10 different users. The sequencer should process them sequentially to prevent
 * nonce collisions.
 * 
 * Usage:
 *   node test_sequencer_parallel.js step1  # Register users
 *   node test_sequencer_parallel.js step2  # Submit parallel transactions
 */

import axios from 'axios';
import { Wallet } from 'ethers';
import fs from 'fs';
import path from 'path';

// Configuration
const RPC_NODES = [
//   'http://49.0.205.131:8082',
//   'http://159.138.121.15:8082',
  'http://124.243.185.174:8082',
];
const API_KEY = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// Get node for a specific user (consistent assignment based on userId)
function getNodeForUser(userId) {
  return RPC_NODES[(userId - 1) % RPC_NODES.length];
}

// ============================================
// 🔑 PRIVATE KEYS - Load from file or use hardcoded
// ============================================
// To use generated keys: node generate_private_keys.js 100000 --output private_keys.json
// Then run: KEYS_FILE=private_keys.json node test_sequencer_parallel.js step1
// To limit number of keys: KEY_LIMIT=100 KEYS_FILE=private_keys_100k.json node test_sequencer_parallel.js step1
// To force re-registration (ignore local cache): FRESH=1 KEY_LIMIT=100 KEYS_FILE=private_keys_100k.json node test_sequencer_parallel.js step1
// To use specific user IDs: USER_ID=55,101,500 KEYS_FILE=private_keys_100k.json node test_sequencer_parallel.js step2
const KEYS_FILE = process.env.KEYS_FILE || null;
const KEY_LIMIT = process.env.KEY_LIMIT ? parseInt(process.env.KEY_LIMIT, 10) : null;
const USER_IDS = process.env.USER_ID ? process.env.USER_ID.split(',').map(id => parseInt(id.trim(), 10)).filter(id => id > 0) : [];
const FRESH_START = process.env.FRESH === '1' || process.env.FRESH === 'true';

let PRIVATE_KEYS = [];
let USER_ID_MAP = []; // Maps index to original user ID for logging

if (KEYS_FILE && fs.existsSync(KEYS_FILE)) {
  try {
    const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
    const allKeys = keysData.keys.map(k => k.privateKey);
    console.log(`✅ Loaded ${allKeys.length} private keys from ${KEYS_FILE}`);

    // Use specific user IDs if specified (1-indexed)
    if (USER_IDS.length > 0) {
      PRIVATE_KEYS = [];
      USER_ID_MAP = [];
      for (const userId of USER_IDS) {
        if (userId > 0 && userId <= allKeys.length) {
          PRIVATE_KEYS.push(allKeys[userId - 1]);
          USER_ID_MAP.push(userId);
        } else {
          console.warn(`⚠️ User ID ${userId} is out of range (1-${allKeys.length}), skipping`);
        }
      }
      console.log(`👤 Using ${PRIVATE_KEYS.length} specific users: ${USER_IDS.join(', ')}`);
    }
    // Apply key limit if specified
    else if (KEY_LIMIT && KEY_LIMIT > 0 && KEY_LIMIT < allKeys.length) {
      PRIVATE_KEYS = allKeys.slice(0, KEY_LIMIT);
      USER_ID_MAP = Array.from({ length: KEY_LIMIT }, (_, i) => i + 1);
      console.log(`🔢 Limited to first ${KEY_LIMIT} keys`);
    } else {
      PRIVATE_KEYS = allKeys;
      USER_ID_MAP = Array.from({ length: allKeys.length }, (_, i) => i + 1);
    }
  } catch (error) {
    console.error(`❌ Error loading keys from ${KEYS_FILE}: ${error.message}`);
    process.exit(1);
  }
} else {
  // Fallback to hardcoded keys for backward compatibility
  PRIVATE_KEYS = [
  // Original 35 accounts (1-35)
  // // // Additional accounts (36-100) - Properly generated random keys

  // // // Additional 200 accounts (101-300) - Properly generated random keys
  ];
}

// Colors
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

// Register a user (like test_register_user.js)
async function testRegisterUser(ethereumAddress, userId, wallet, nodeUrl) {
  try {
    log(`[User ${userId}] Registering address: ${ethereumAddress} via ${nodeUrl}`, 'blue');

    // Create registration message: "register:{ethereum_address}:{timestamp}"
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `register:${ethereumAddress}:${timestamp}`;
    log(`[User ${userId}] 📝 Registration message: ${message}`, 'cyan');

    // Sign the message using the wallet
    const signature = await wallet.signMessage(message);
    log(`[User ${userId}] ✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${nodeUrl}/register_user`,
      {
        ethereum_address: ethereumAddress,
        signature: signature,
        message: message
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-API-KEY': API_KEY
        },
        timeout: 15000
      }
    );

    log(`[User ${userId}] ✅ Registration successful!`, 'green');
    log(`[User ${userId}]   Status: ${response.data.status}`, 'cyan');
    log(`[User ${userId}]   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`[User ${userId}]   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`[User ${userId}] ❌ Registration failed: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`[User ${userId}] ❌ Registration error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// Get total registered user count from API
async function getUserCount(nodeUrl = RPC_NODES[0]) {
  try {
    log(`📊 Fetching total registered user count from API via ${nodeUrl}...`, 'blue');

    const response = await axios.get(`${nodeUrl}/user_count`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`✅ User count retrieved successfully!`, 'green');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Count: ${response.data.count}`, 'cyan');
    log(`   Message: ${response.data.message}`, 'cyan');

    return { success: true, count: response.data.count };
  } catch (error) {
    if (error.response) {
      log(`❌ Failed to get user count: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`❌ Error getting user count: ${error.message}`, 'red');
    }
    return { success: false, count: 0, error: error.message };
  }
}

// Get user info (like test_register_user.js)
async function testGetUserInfo(ethereumAddress, userId, nodeUrl = RPC_NODES[0]) {
  try {
    log(`[User ${userId}] Fetching user info for: ${ethereumAddress} via ${nodeUrl}`, 'blue');

    const response = await axios.get(`${nodeUrl}/user_info/${ethereumAddress}`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`[User ${userId}] ✅ User info retrieved!`, 'green');
    log(`[User ${userId}]   User ID: ${response.data.user_id}`, 'cyan');
    log(`[User ${userId}]   Ethereum Address: ${response.data.ethereum_address}`, 'cyan');
    log(`[User ${userId}]   Has Tweaked Share: ${response.data.has_tweaked_share}`, 'cyan');
    log(`[User ${userId}]   Has User Group Key: ${response.data.has_user_group_key}`, 'cyan');
    log(`[User ${userId}]   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`[User ${userId}]   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');
    log(`[User ${userId}]   Created At: ${response.data.created_at}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response?.status === 404) {
      log(`[User ${userId}] ❌ User not found: ${ethereumAddress}`, 'yellow');
    } else if (error.response) {
      log(`[User ${userId}] ❌ Failed to get user info: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`[User ${userId}] ❌ Error getting user info: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// Submit deposit using user_mpc_deposit (like test_register_user.js)
async function testUserMpcDeposit({ wallet, amount, userId, nodeUrl }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`[User ${userId}] Testing user_mpc_deposit for signer: ${signerAddr} via ${nodeUrl}`, 'blue');
    log(`[User ${userId}]   Amount: ${amount}`, 'cyan');

    // Fetch user info to get the derived addresses
    const userInfo = await testGetUserInfo(signerAddr, userId, nodeUrl);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Check if derived addresses are available
    if (!userInfo.data.derived_btc_address || !userInfo.data.derived_eth_address) {
      throw new Error('Derived addresses not available yet. Please wait and try again.');
    }

    // Construct DepositIntent (EXACTLY like test_register_user.js)
    const intentTimestamp = new Date().getTime();
    log(`[User ${userId}]   Intent Timestamp: ${intentTimestamp} (${new Date(intentTimestamp).toISOString()})`, 'cyan');

    const depositIntent = {
      source_address: userInfo.data.derived_eth_address,  // ETH address
      // source_address: userInfo.data.derived_btc_address,  // ETH address
      // target_address: userInfo.data.derived_eth_address,
      // target_address: "0x052e109a83bce9217270ca2880035c9d7de9065e",
      target_address: "0x95385e34d72d376f9e021fe02f91a35dbae261d4",
      // target_address: "tb1qgazak34uzm48srpfvmuexemjfux4znvxm8fu42",
      source_chain: 'qubetics',
      target_chain: 'qubetics',
      amount: amount,
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp: intentTimestamp,
    };

    log(`[User ${userId}]   Deposit Intent: ${JSON.stringify(depositIntent)}`, 'cyan');

    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);

    // EIP-191 personal_sign  
    const signature = await wallet.signMessage(msg);
    log(`[User ${userId}]   Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${nodeUrl}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-API-KEY': API_KEY
        },
        timeout: 120000
      }
    );

    // Print full response
    log(`[User ${userId}] 📥 Full Response:`, 'magenta');
    log(`[User ${userId}]   ${JSON.stringify(response.data, null, 2)}`, 'cyan');

    // Check response status
    const status = response.data.status;
    if (status === 'success') {
      log(`[User ${userId}] ✅ user_mpc_deposit SUCCESS - Transaction completed!`, 'green');
    } else if (status === 'submitted') {
      log(`[User ${userId}] 📤 user_mpc_deposit SUBMITTED - Transaction is being processed`, 'yellow');
    } else if (status === 'processing') {
      log(`[User ${userId}] ⏳ user_mpc_deposit PROCESSING - Transaction is still being processed`, 'yellow');
    } else if (status === 'error') {
      log(`[User ${userId}] ❌ user_mpc_deposit ERROR - Transaction failed`, 'red');
    } else if (status === 'timeout') {
      log(`[User ${userId}] ⏰ user_mpc_deposit TIMEOUT - Transaction processing timed out`, 'yellow');
    } else {
      log(`[User ${userId}] ❓ user_mpc_deposit UNKNOWN STATUS: ${status}`, 'yellow');
    }

    log(`[User ${userId}]   Response Status: ${response.data.status}`, 'cyan');
    log(`[User ${userId}]   Signer Address (recovered): ${response.data.signer_address}`, 'cyan');
    log(`[User ${userId}]   Is Registered: ${response.data.is_registered}`, 'cyan');

    // Show transaction ID if available
    if (response.data.user_to_network_tx_id) {
      log(`[User ${userId}]   Transaction ID: ${response.data.user_to_network_tx_id}`, 'green');
    } else {
      log(`[User ${userId}]   Transaction ID: Not available yet`, 'yellow');
    }

    // Show error message if present
    if (response.data.error_message) {
      if (status === 'error') {
        log(`[User ${userId}]   Error Message: ${response.data.error_message}`, 'red');
      } else {
        log(`[User ${userId}]   Message: ${response.data.error_message}`, 'yellow');
      }
    }

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`[User ${userId}] ❌ user_mpc_deposit failed with HTTP status ${error.response.status}`, 'red');
      if (error.response.data) {
        log(`[User ${userId}]   Error Response: ${JSON.stringify(error.response.data)}`, 'red');
      }
    } else {
      log(`[User ${userId}] ❌ user_mpc_deposit error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// Output file for registered addresses - saved on runtime
const REGISTERED_ADDRESSES_FILE = path.join(process.cwd(), 'registered_eth_addresses.json');

// Load existing registered addresses (for resume capability)
function loadExistingAddresses() {
  try {
    if (fs.existsSync(REGISTERED_ADDRESSES_FILE)) {
      return JSON.parse(fs.readFileSync(REGISTERED_ADDRESSES_FILE, 'utf8'));
    }
  } catch (e) {
    log(`⚠️ Could not load existing addresses: ${e.message}`, 'yellow');
  }
  return [];
}

// Save addresses to file (batch save - more efficient for large datasets)
function saveAddressesToFile(existingAddresses) {
  fs.writeFileSync(REGISTERED_ADDRESSES_FILE, JSON.stringify(existingAddresses, null, 2));
}

// Add address to array (does NOT write to file - call saveAddressesToFile separately)
function addAddressToArray(addressData, existingAddresses, existingSet) {
  const key = addressData.walletAddress.toLowerCase();

  if (existingSet.has(key)) {
    // Update existing entry
    const existingIndex = existingAddresses.findIndex(a => a.walletAddress.toLowerCase() === key);
    if (existingIndex >= 0) {
      existingAddresses[existingIndex] = addressData;
    }
  } else {
    // Append new entry
    existingAddresses.push(addressData);
    existingSet.add(key);
  }

  return existingAddresses;
}

// Step 1: Register all users
async function step1_RegisterUsers() {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('📝 STEP 1: REGISTER USERS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const validPrivateKeys = PRIVATE_KEYS.filter(pk => pk && pk.length >= 64);
  log(`📝 Configuration:`, 'yellow');
  log(`   - Number of users: ${validPrivateKeys.length}`, 'yellow');
  log(`   - RPC Nodes: ${RPC_NODES.join(', ')}`, 'yellow');
  log(`   - Load balancing: Round-robin across ${RPC_NODES.length} nodes`, 'yellow');
  log(`   - Output file: ${REGISTERED_ADDRESSES_FILE}`, 'yellow');
  log(`   - Fresh start: ${FRESH_START ? 'YES (ignoring local cache)' : 'NO (resume mode)'}`, 'yellow');
  log('', 'reset');

  // Load existing addresses for resume capability (unless FRESH_START is set)
  let registeredAddresses = [];
  if (FRESH_START) {
    log(`🔄 FRESH_START enabled - clearing local cache and re-registering all users`, 'yellow');
    // Clear the local file
    if (fs.existsSync(REGISTERED_ADDRESSES_FILE)) {
      fs.unlinkSync(REGISTERED_ADDRESSES_FILE);
      log(`   🗑️  Deleted ${REGISTERED_ADDRESSES_FILE}`, 'cyan');
    }
  } else {
    registeredAddresses = loadExistingAddresses();
    const existingCount = registeredAddresses.length;
    if (existingCount > 0) {
      log(`📂 Found ${existingCount} existing registered addresses (will skip or update)`, 'cyan');
    }
  }

  // Build set of existing addresses FIRST (before creating wallets)
  const existingWalletAddresses = new Set(registeredAddresses.map(a => a.walletAddress.toLowerCase()));
  log('', 'reset');

  // Create wallets from private keys - optimized for large numbers
  log(`👥 Creating wallets from ${validPrivateKeys.length} private keys...`, 'magenta');
  const startTime = Date.now();

  const walletsToRegister = [];
  let skippedCount = 0;

  for (let i = 0; i < validPrivateKeys.length; i++) {
    const pk = validPrivateKeys[i];
    const privKey = pk.startsWith('0x') ? pk : `0x${pk}`;
    const wallet = new Wallet(privKey);
    const address = wallet.address;

    // Check if already registered
    if (existingWalletAddresses.has(address.toLowerCase())) {
      skippedCount++;
    } else {
      walletsToRegister.push({ userId: i + 1, wallet, address });
    }

    // Progress update every 10000
    if ((i + 1) % 10000 === 0) {
      log(`   Processed ${i + 1}/${validPrivateKeys.length} keys...`, 'cyan');
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  log(`   ✅ Created wallets in ${elapsed}s`, 'green');

  if (skippedCount > 0) {
    log(`⏭️  Skipping ${skippedCount} already registered wallets`, 'cyan');
  }
  log(`📝 Will register ${walletsToRegister.length} new wallets`, 'yellow');
  log('', 'reset');

  if (walletsToRegister.length === 0) {
    log(`✅ All wallets already registered!`, 'green');
    log('', 'reset');
  } else {
    // Register users in batches
    const BATCH_SIZE = 500;
    let successfulRegistrations = 0;

    for (let i = 0; i < walletsToRegister.length; i += BATCH_SIZE) {
      const batch = walletsToRegister.slice(i, i + BATCH_SIZE);
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(walletsToRegister.length / BATCH_SIZE);

      log(`📦 Batch ${batchNum}/${totalBatches}: Registering users ${batch[0].userId} to ${batch[batch.length - 1].userId}`, 'blue');

      const batchPromises = batch.map(({ address, userId, wallet }) => {
        const nodeUrl = getNodeForUser(userId);
        return testRegisterUser(address, userId, wallet, nodeUrl);
      });
      const batchResults = await Promise.all(batchPromises);

      // Process results and add to array
      let batchSuccess = 0;
      for (let j = 0; j < batch.length; j++) {
        const { address, userId } = batch[j];
        const result = batchResults[j];

        if (result.success) {
          successfulRegistrations++;
          batchSuccess++;

          // Add to array with derived addresses from registration response
          const addressData = {
            userId: userId,
            walletAddress: address,
            derivedEthAddress: result.data.derived_eth_address || null,
            derivedBtcAddress: result.data.derived_btc_address || null,
            hasUserGroupKey: true,
            registeredAt: new Date().toISOString()
          };

          addAddressToArray(addressData, registeredAddresses, existingWalletAddresses);
        }
      }

      log(`   ✅ Batch ${batchNum} complete: ${batchSuccess}/${batch.length} users registered`, 'green');
      log(`   📊 Total registered so far: ${registeredAddresses.length}`, 'cyan');

      // Wait between batches (except after the last batch)
      if (i + BATCH_SIZE < walletsToRegister.length) {
        log(`   ⏳ Waiting 5 seconds before next batch...`, 'yellow');
        await new Promise(r => setTimeout(r, 5000));
      }
      log('', 'reset');
    }

    log(`✅ Total registered in this run: ${successfulRegistrations}/${walletsToRegister.length} users`, 'green');
  }

  // Save to file ONCE after all registrations complete
  log('', 'reset');
  log(`💾 Saving ${registeredAddresses.length} addresses to file...`, 'yellow');
  saveAddressesToFile(registeredAddresses);
  log(`✅ Saved to: ${REGISTERED_ADDRESSES_FILE}`, 'green');
  log('', 'reset');

  // Verify total registered users via API
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('🔍 VERIFYING REGISTERED USERS VIA API', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const userCountResult = await getUserCount();

  if (userCountResult.success) {
    log('', 'reset');
    log(`✅ API reports ${userCountResult.count} total registered users`, 'green');
    log(`   File contains ${registeredAddresses.length} addresses`, 'cyan');
  } else {
    log(`⚠️  Could not verify user count via API`, 'yellow');
  }

  log('', 'reset');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log(`✅ STEP 1 COMPLETE`, 'green');
  log(`   📂 Saved: ${REGISTERED_ADDRESSES_FILE}`, 'cyan');
  log(`   📊 Total addresses: ${registeredAddresses.length}`, 'cyan');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');
  log('💡 Next: Run step 2 to submit parallel transactions', 'cyan');
  log('   node test_sequencer_parallel.js step2', 'cyan');
  log('', 'reset');
}

// Step 2: Submit parallel transactions using the same users
async function step2_SubmitTransactions() {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('🚀 STEP 2: SUBMIT PARALLEL TRANSACTIONS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const validPrivateKeys = PRIVATE_KEYS.filter(pk => pk && pk.length >= 64);
  log(`📝 Configuration:`, 'yellow');
  log(`   - Number of parallel transactions: ${validPrivateKeys.length}`, 'yellow');
  log(`   - RPC Nodes: ${RPC_NODES.join(', ')}`, 'yellow');
  log(`   - Load balancing: Round-robin across ${RPC_NODES.length} nodes`, 'yellow');
  log('', 'reset');

  // Create wallets from the same private keys
  log(`👥 Creating wallets from private keys...`, 'magenta');
  const wallets = validPrivateKeys.map((pk, i) => {
    const privKey = pk.startsWith('0x') ? pk : `0x${pk}`;
    const wallet = new Wallet(privKey);
    // Use actual user ID from USER_ID_MAP if available, otherwise use index+1
    const userId = USER_ID_MAP.length > 0 ? USER_ID_MAP[i] : i + 1;
    log(`   User ${userId}: ${wallet.address}`, 'cyan');
    return { userId, wallet, address: wallet.address };
  });
  log('', 'reset');

  log(`🔥 Submitting ${wallets.length} PARALLEL deposit intents...`, 'magenta');
  log('   Watch the node logs for sequencer activity!', 'yellow');
  log('   Expected behavior: Transactions queued immediately, processed sequentially', 'yellow');
  log('', 'reset');

  const startTime = Date.now();

  // Submit all transactions in parallel, distributed across nodes
  const depositPromises = wallets.map(({ wallet, userId }) => {
    const amount = "2000000000000000000";  // 12 TICS
    // const amount = "700";  // btc
    const nodeUrl = getNodeForUser(userId);
    return testUserMpcDeposit({ wallet, amount, userId, nodeUrl });
  });

  log(`⚡ All ${wallets.length} transactions submitted in parallel!`, 'bright');
  log('📊 Processing...', 'yellow');
  log('', 'reset');

  // Wait for all to complete
  const results = await Promise.all(depositPromises);

  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);

  // Summary
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('📊 TEST RESULTS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  log(`✅ Successful: ${successful}`, 'green');
  log(`❌ Failed: ${failed}`, failed > 0 ? 'red' : 'reset');
  log(`⏱️  Total Duration: ${duration} seconds`, 'cyan');
  log(`📈 Average per transaction: ${(duration / wallets.length).toFixed(2)} seconds`, 'cyan');
  log('', 'reset');

  log('🔍 WHAT TO CHECK IN NODE LOGS:', 'yellow');
  log('   1. Look for "📋 [SEQUENCER] Queued contract transaction" messages', 'yellow');
  log('   2. Verify transactions are processed ONE AT A TIME (sequential)', 'yellow');
  log('   3. Check for "✅ [SEQUENCER] Successfully executed" for each transaction', 'yellow');
  log('   4. Verify no nonce collision errors', 'yellow');
  log('', 'reset');

  if (successful === wallets.length) {
    log('🎉 ALL TRANSACTIONS SUCCESSFUL! Sequencer is working correctly!', 'green');
  } else if (successful > 0) {
    log('⚠️  PARTIAL SUCCESS - Some transactions failed', 'yellow');
  } else {
    log('💥 ALL TRANSACTIONS FAILED - Check node logs and configuration', 'red');
  }

  log('═══════════════════════════════════════════════════════════', 'bright');
}

// Main test function
async function runSequencerTest() {
  const step = process.argv[2] || 'step1';

  if (step === 'step1') {
    await step1_RegisterUsers();
  } else if (step === 'step2') {
    await step2_SubmitTransactions();
  } else {
    log('Usage:', 'yellow');
    log('  node test_sequencer_parallel.js step1  # Register users', 'cyan');
    log('  node test_sequencer_parallel.js step2  # Submit parallel transactions', 'cyan');
    process.exit(1);
  }
}

// Run the test
runSequencerTest().catch(error => {
  log(`💥 Test failed with error: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});
