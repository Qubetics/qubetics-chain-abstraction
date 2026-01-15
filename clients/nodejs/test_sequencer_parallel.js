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
const RPC_BASE_URL = 'http://127.0.0.1:8083';
const API_KEY = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// ============================================
// 🔑 PRIVATE KEYS - Add your 10 test accounts here
// ============================================
const PRIVATE_KEYS = [
  '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e',
  'e41af1d4f1413ed18e0200d225fa810287c5d90d3d11d6fc9723f93538718fc1',
  "b61b1415e8b5e5a3144c0d7b8c556b23baed0366586931011c9d858ecf39bd37",
  "005c880d2bc9c6f560eef60faa20991b68ee25b3b24f3a037c4af5e078cda77a",
  "03c2a0cbaf3a88ddbca8aec76259ff01c9165816794dbcda330ecda5c6008c80",
  "f44356ec40eea5d9f21c7bd2f29bbedb0269d11168bce2ac38f12b4ef5949156",
  "ab71a0afb1ffe76973336a105e14573255863dd4ac5692fac9e5b887ef050555",
  "d12a02464e11ba3d596380d6a2cb854eff3e537c597c69bb9d90639daf85e2c1",
  "bb6ae158bb718b25645f1a545dcf301672c1b10a2bf49b3a08b7bcba62415814",
  "f9a70e39839c17e74af530a7325e55a8796473f32ece2c8284c4c098880a0d28",
  "72321624c6643bd5bbb40be800e063cf4af1d94fd2e2f9ed21321d75a5f8bc25",
  "7f99aa35bc07f235f4bd4688377e5ea865a77f968a1f1669e5de0f05aec2d445",
  "4cf33839b011a638b2a84dcc61fdd2e78320ea49b9acaf661376fb94556cf30d",
  "bec774d1a84f121ffade69bf45a23ddc54278f8fbc4e59680e2835e4185ef896",
  "4592debf089c3019b53f8098f3f1c4ed629e8740a4370caaf6a11a9c85338482",
  "b4221f4b4335926192a4b3a957ca5f0198d7f35f17fa321973bce3be0a5b7db5",
  "e643708c58446c9e3513d11a3bc7531c385f2ee2205037b47dd0dba96239f41e",
  "d9aa82c8b5429c65d0dda7ee04bc2026da4d376bc2d4a305a39af3c45f1b578a",
  "c22462f3e6fe4e288a00a3453f3f93ca5a48cdb29379f8d51394c2c7c91414cc",
  "b83650df6acbe6266fcf52c5288d23d25a2fdc2f2b3564a5825d3a67172c6610",
  "25d16229200a6f13b13548ddd39f104f5336b0cfd984fee6253456efd8bffdd5",
  "728c87ca02ebe88db24398b18437b4a71525808b17158a9bc8fad7005c1ebc84",
  "329625232fe2001268a33c0a2a7523edfeb04138d8db0c18a7697221b4100620",
  "63a9da98227c2efd52498e6a51ccf5640aa707e5bee59e8b5848b3a547e9ab27",
  "01998933eb0d0aa0b51dc41796b29af3142f9039c2138947aa330bfff17ce8b2",
  "a5d6d05532a0f6ee1de3586a2da787429a8b62289d776ca084783c8dc9ffa5a7",
  "15d5488130680e229fb5edceadec7c9a58b6236b5b5c08e339f89236f3ef59b2",
  "4289ba4c078eb7c639b72f3b253e03fe6420d64a3e2f60b2a6f6046b9e6d5010",
  "a28400d43f5f00f95f5ffbfcd1868fd2412685a4695a7dff65ed486488f651b0",
  "8484b8df03e271b07278d61bd97360079f109dfa9bc32af2166873dfaa790415",
  "11ee773c87f7be24e590648091da68546d2273596ad4d0c941e9df078e06e3df",
  "d59977f42a29d6604c97ece9e514e890c4d635537c82acfb6b28856f9195eb9f",
  "21bb33fee6969b26a87f777f77b7c206f3259015db5305eb0e3b2a7dd42d36f1",
  "94bac31302d892ae2c1e474ecb0483475577ff716df6bd383a2094395345fdcf",
  "9bb89847d2252cfd377d89e0ff64fb71d32b18d1dd70be86169ae15fb780e7b4"
];

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
async function testRegisterUser(ethereumAddress, userId, wallet) {
  try {
    log(`[User ${userId}] Registering address: ${ethereumAddress}`, 'blue');

    // Create registration message: "register:{ethereum_address}:{timestamp}"
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `register:${ethereumAddress}:${timestamp}`;
    log(`[User ${userId}] 📝 Registration message: ${message}`, 'cyan');

    // Sign the message using the wallet
    const signature = await wallet.signMessage(message);
    log(`[User ${userId}] ✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/register_user`,
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

// Get user info (like test_register_user.js)
async function testGetUserInfo(ethereumAddress, userId) {
  try {
    log(`[User ${userId}] Fetching user info for: ${ethereumAddress}`, 'blue');

    const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, {
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
async function testUserMpcDeposit({ wallet, amount, userId }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`[User ${userId}] Testing user_mpc_deposit for signer: ${signerAddr}`, 'blue');
    log(`[User ${userId}]   Amount: ${amount}`, 'cyan');

    // Fetch user info to get the derived addresses
    const userInfo = await testGetUserInfo(signerAddr, userId);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Check if derived addresses are available
    if (!userInfo.data.derived_btc_address || !userInfo.data.derived_eth_address) {
      throw new Error('Derived addresses not available yet. Please wait and try again.');
    }

    // Construct DepositIntent (EXACTLY like test_register_user.js)
    const depositIntent = {
      source_address: userInfo.data.derived_eth_address,  // ETH address
      target_address: userInfo.data.derived_eth_address,  // ETH address
      source_chain: 'qubetics',
      target_chain: 'qubetics',
      amount: amount,
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp: 4356767664578,
    };

    log(`[User ${userId}]   Deposit Intent: ${JSON.stringify(depositIntent)}`, 'cyan');

    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);

    // EIP-191 personal_sign  
    const signature = await wallet.signMessage(msg);
    log(`[User ${userId}]   Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-API-KEY': API_KEY
        },
        timeout: 120000
      }
    );

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

// Step 1: Register all users
async function step1_RegisterUsers() {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('📝 STEP 1: REGISTER USERS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const validPrivateKeys = PRIVATE_KEYS.filter(pk => pk && pk.length >= 64);
  log(`📝 Configuration:`, 'yellow');
  log(`   - Number of users: ${validPrivateKeys.length}`, 'yellow');
  log(`   - RPC Endpoint: ${RPC_BASE_URL}`, 'yellow');
  log('', 'reset');

  // Create wallets from private keys
  log(`👥 Creating wallets from private keys...`, 'magenta');
  const wallets = validPrivateKeys.map((pk, i) => {
    const privKey = pk.startsWith('0x') ? pk : `0x${pk}`;
    const wallet = new Wallet(privKey);
    log(`   User ${i + 1}: ${wallet.address}`, 'cyan');
    return { userId: i + 1, wallet, address: wallet.address };
  });
  log('', 'reset');

  // Register users in batches of 5
  log('📝 Registering users in batches of 5...', 'magenta');
  log('   Note: Derived addresses may take a few seconds to generate', 'yellow');
  log('', 'reset');

  const BATCH_SIZE = 5;
  const registrationResults = [];

  for (let i = 0; i < wallets.length; i += BATCH_SIZE) {
    const batch = wallets.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(wallets.length / BATCH_SIZE);

    log(`📦 Batch ${batchNum}/${totalBatches}: Registering users ${batch[0].userId} to ${batch[batch.length - 1].userId}`, 'blue');

    const batchPromises = batch.map(({ address, userId, wallet }) =>
      testRegisterUser(address, userId, wallet)
    );
    const batchResults = await Promise.all(batchPromises);
    registrationResults.push(...batchResults);

    const batchSuccess = batchResults.filter(r => r.success).length;
    log(`   ✅ Batch ${batchNum} complete: ${batchSuccess}/${batch.length} users registered`, 'green');

    // Wait 5 seconds between batches (except after the last batch)
    if (i + BATCH_SIZE < wallets.length) {
      log(`   ⏳ Waiting 5 seconds before next batch...`, 'yellow');
      await new Promise(r => setTimeout(r, 5000));
    }
    log('', 'reset');
  }

  const successfulRegistrations = registrationResults.filter(r => r.success).length;
  log(`✅ Total registered: ${successfulRegistrations}/${wallets.length} users`, 'green');
  log('', 'reset');

  // Wait a bit for derived addresses to be populated
  log('⏳ Waiting 5 seconds for derived addresses to be populated...', 'yellow');
  await new Promise(r => setTimeout(r, 5000));
  log('', 'reset');

  // Get user info for all registered users
  log('🔍 Fetching user info for all registered users...', 'magenta');
  log('', 'reset');

  const userInfoPromises = wallets.map(({ address, userId }) =>
    testGetUserInfo(address, userId)
  );
  const userInfoResults = await Promise.all(userInfoPromises);

  // Save all addresses (wallet + derived) to JSON file
  const addressData = wallets.map(({ address, userId }, index) => {
    const userInfoResult = userInfoResults[index];
    return {
      userId: userId,
      walletAddress: address,
      derivedEthAddress: userInfoResult.success ? userInfoResult.data.derived_eth_address : null,
      derivedBtcAddress: userInfoResult.success ? userInfoResult.data.derived_btc_address : null,
      hasUserGroupKey: userInfoResult.success ? userInfoResult.data.has_user_group_key : false
    };
  });

  const outputFile = path.join(process.cwd(), 'registered_eth_addresses.json');
  fs.writeFileSync(outputFile, JSON.stringify(addressData, null, 2));

  log('', 'reset');
  log(`💾 Saved ${addressData.length} users with derived addresses to: ${outputFile}`, 'green');
  log('', 'reset');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log(`✅ STEP 1 COMPLETE: ${successfulRegistrations}/${wallets.length} users registered`, 'green');
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
  log(`   - RPC Endpoint: ${RPC_BASE_URL}`, 'yellow');
  log('', 'reset');

  // Create wallets from the same private keys
  log(`👥 Creating wallets from private keys...`, 'magenta');
  const wallets = validPrivateKeys.map((pk, i) => {
    const privKey = pk.startsWith('0x') ? pk : `0x${pk}`;
    const wallet = new Wallet(privKey);
    log(`   User ${i + 1}: ${wallet.address}`, 'cyan');
    return { userId: i + 1, wallet, address: wallet.address };
  });
  log('', 'reset');

  log(`🔥 Submitting ${wallets.length} PARALLEL deposit intents...`, 'magenta');
  log('   Watch the node logs for sequencer activity!', 'yellow');
  log('   Expected behavior: Transactions queued immediately, processed sequentially', 'yellow');
  log('', 'reset');

  const startTime = Date.now();

  // Submit all transactions in parallel
  const depositPromises = wallets.map(({ wallet, userId }) => {
    const amount = '1000000000000000000';  // Use same amount as test_register_user.js
    return testUserMpcDeposit({ wallet, amount, userId });
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
