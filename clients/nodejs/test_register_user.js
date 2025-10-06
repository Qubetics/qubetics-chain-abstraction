#!/usr/bin/env node

import axios from 'axios';
import { Wallet } from 'ethers';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = 'http://111.119.250.67:8082';

// 👉 Private key you provided (hex, no 0x prefix needed)
const TEST_PRIVKEY = '6176c7ad6a70652a202e1e894badaa5690260cfc5fbf148a7411462e40ee4bf8';
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

const oooo = 4752453535
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
// This test will show different response types:
// - success: Transaction completed with tx_id
// - submitted: Transaction submitted and being processed
// - processing: Transaction still being processed
// - error: Transaction failed with actual blockchain error message
// - timeout: Transaction processing timed out
// Update testUserMpcDeposit to fetch user info
async function testUserMpcDeposit({ wallet, amount }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`\n🔐 Testing user_mpc_deposit WITHOUT tx_id for signer: ${signerAddr}`, 'blue');
    log(`💰 Amount: ${amount}`, 'cyan');

    // Fetch user info to get the canonical Ethereum address
    const userInfo = await testGetUserInfo(signerAddr);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Construct DepositIntent
    const depositIntent = {
      source_address: userInfo.data.derived_eth_address, // Use canonical address
      target_address: 'mjM7dnr6ssFeKFVMj9i6quhTnD7fy3k3pG',
      source_chain: 'qubetics',
      target_chain: 'btc',
      amount: amount, // Use the passed amount parameter
      source_token: 'TICS',
      target_token: 'BTC',
      timestamp: oooo,
    };
    console.log(`📊 Deposit Intent: ${JSON.stringify(depositIntent)}`, 'cyan');
    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);
    log(`📝 Message: ${msg}`, 'cyan');

    // EIP-191 personal_sign
    const signature = await wallet.signMessage(msg);
    log(`✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      { 
        headers: { 'Content-Type': 'application/json' },
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
        log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
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
// New: Simple deposit test - only passes intent without signature
// =========================
async function testSimpleDeposit() {
  try {
    const amount = 1000000000000000000; // 1 ETH in wei
    const sourceAddress = '0x9e97239232457c06db34790fb062b1e03e73256b';
    const targetAddress = 'n1f5qYrCUSakSHBxyNLnDFetp5LNTaYjKw';
    const sourceChain = 'qubetics';
    const targetChain = 'bitcoin';
    
    log(`\n🔐 Testing user_mpc_deposit with no signature (intent only)`, 'blue');
    log(`💰 Amount: ${amount}`, 'cyan');
    log(`📤 Source: ${sourceAddress} (${sourceChain})`, 'cyan');
    log(`📥 Target: ${targetAddress} (${targetChain})`, 'cyan');

    // Construct DepositIntent without signature
    const depositIntent = {
      source_address: sourceAddress,
      target_address: targetAddress,
      source_chain: sourceChain,
      target_chain: targetChain,
      amount: amount,
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp: oooo, // Current Unix timestamp in seconds
    };

    log(`📊 Deposit Intent:`, 'cyan');
    console.log(JSON.stringify(depositIntent, null, 2));

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`, // Use existing endpoint
      { 
        signature: null, // Explicitly set signature to null
        msg: depositIntent, // Send as msg field like the signed version
      },
      { 
        headers: { 'Content-Type': 'application/json' },
        timeout: 60000 // 60 seconds timeout
      }
    );

    // Check response status to determine success or error
    const isSuccess = response.data.status === 'success';
    const isSubmitted = response.data.status === 'submitted';
    const isProcessing = response.data.status === 'processing';
    const isError = response.data.status === 'error';
    const isTimeout = response.data.status === 'timeout';

    if (isSuccess) {
      log(`✅ Unsigned deposit SUCCESS - Transaction completed!`, 'green');
    } else if (isSubmitted) {
      log(`📤 Unsigned deposit SUBMITTED - Transaction is being processed`, 'yellow');
    } else if (isProcessing) {
      log(`⏳ Unsigned deposit PROCESSING - Transaction is still being processed`, 'yellow');
    } else if (isError) {
      log(`❌ Unsigned deposit ERROR - Transaction failed`, 'red');
    } else if (isTimeout) {
      log(`⏰ Unsigned deposit TIMEOUT - Transaction processing timed out`, 'yellow');
    } else {
      log(`❓ Unsigned deposit UNKNOWN STATUS: ${response.data.status}`, 'yellow');
    }

    log(`📊 Response Details:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Amount: ${response.data.amount}`, 'cyan');
    
    // Show transaction ID if available
    if (response.data.transaction_id || response.data.tx_id) {
      const txId = response.data.transaction_id || response.data.tx_id;
      log(`   🎯 Transaction ID: ${txId}`, 'green');
    } else {
      log(`   🎯 Transaction ID: Not available yet`, 'yellow');
    }

    // Show full response for debugging
    console.log(`📊 Full Response:`, 'cyan');
    console.log(JSON.stringify(response.data, null, 2));
    
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
      log(`❌ Unsigned deposit failed with HTTP status ${error.response.status}:`, 'red');
      
      // Check if we got a structured response
      if (error.response.data && error.response.data.status) {
        const errorData = error.response.data;
        log(`   Response Status: ${errorData.status}`, 'red');
        
        if (errorData.transaction_id || errorData.tx_id) {
          const txId = errorData.transaction_id || errorData.tx_id;
          log(`   Transaction ID: ${txId}`, 'red');
        }
        
        if (errorData.error_message) {
          log(`   🔥 Error: ${errorData.error_message}`, 'red');
        }
      } else {
        // Fallback for generic HTTP errors
        log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
      }
      
      // Log complete response
      log(`   Complete Response:`, 'red');
      console.log(error.response);
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
      log(`❌ Unsigned deposit error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// =========================
// New: user_mpc_deposit test WITH tx_id (should pass None to handle_deposit_intent)
// =========================
async function testUserMpcDepositWithTxId({ wallet, amount, txId, status }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`\n🔐 Testing user_mpc_deposit WITH tx_id for signer: ${signerAddr}`, 'blue');
    log(`💰 Amount: ${amount}`, 'cyan');
    log(`📊 Transaction ID: ${txId}`, 'cyan');
    log(`📊 Status: ${status}`, 'cyan');

    // Fetch user info to get the canonical Ethereum address
    const userInfo = await testGetUserInfo(signerAddr);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    const depositIntent = {
      source_address: userInfo.data.derived_btc_address, // Use canonical address
      target_address: '0xd476f40c612e5262fbEA93809E22B81BFf07efe8',
      source_chain: 'btc',
      target_chain: 'qubetics',
      amount: amount, // Use the passed amount parameter
      source_token: 'BTC',
      target_token: 'TICS',
      timestamp: oooo, // Current Unix timestamp in seconds
    };

    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);
    log(`📝 Message: ${msg}`, 'cyan');

    // EIP-191 personal_sign
    const signature = await wallet.signMessage(msg);
    log(`✍️  Signature: ${signature}`, 'cyan');

    // Request WITH tx_id and status - should pass None to handle_deposit_intent
    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { 
        signature, 
        msg: depositIntent,
        tx_id: txId,    // Include tx_id
        status: status  // Include status
      },
      { 
        headers: { 'Content-Type': 'application/json' },
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
      log(`✅ user_mpc_deposit WITH tx_id SUCCESS - Transaction completed!`, 'green');
    } else if (isSubmitted) {
      log(`📤 user_mpc_deposit WITH tx_id SUBMITTED - Transaction is being processed`, 'yellow');
    } else if (isProcessing) {
      log(`⏳ user_mpc_deposit WITH tx_id PROCESSING - Transaction is still being processed`, 'yellow');
    } else if (isError) {
      log(`❌ user_mpc_deposit WITH tx_id ERROR - Transaction failed`, 'red');
    } else if (isTimeout) {
      log(`⏰ user_mpc_deposit WITH tx_id TIMEOUT - Transaction processing timed out`, 'yellow');
    } else {
      log(`❓ user_mpc_deposit WITH tx_id UNKNOWN STATUS: ${response.data.status}`, 'yellow');
    }

    log(`📊 Response Details:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Signer Address (recovered): ${response.data.signer_address}`, 'cyan');
    log(`   Is Registered: ${response.data.is_registered}`, 'cyan');
    log(`   Used personal_sign prefix: ${response.data.used_personal_sign_prefix}`, 'cyan');
    log(`   Amount: ${response.data.amount}`, 'cyan');
    log(`📊 Response: ${JSON.stringify(response.data)}`, 'cyan');

    // Show transaction ID if available
    if (response.data.network_to_target_tx_id) {
      log(`   🎯 Transaction ID: ${response.data.network_to_target_tx_id

      }`, 'green');
    } else {
      log(`   🎯 Transaction ID: Not available yet`, 'yellow');
    }
    
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
      log(`❌ user_mpc_deposit WITH tx_id failed with HTTP status ${error.response.status}:`, 'red');
      
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
        log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
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
      log(`❌ user_mpc_deposit WITH tx_id error: ${error.message}`, 'red');
    }

    return { success: false, error: error.message };
  }
}

// Add this function to your existing client file
async function testGetRewardSolver(solverAddress) {
  try {
    log(`\n🔍 Getting reward for solver: ${solverAddress}`, 'blue');

    const response = await axios.get(
      `${RPC_BASE_URL}/get_reward_solver`,
      { params: { solver_address: solverAddress }, timeout: 10000 }
    );

    log(`✅ Request successful!`, 'green');
    log(`📊 Response:`, 'cyan');
    log(`   Status: ${response.data.status}`, 'cyan');
    log(`   Solver Address: ${response.data.solver_address}`, 'cyan');
    log(`   Reward: ${response.data.reward || '0'}`, 'cyan');
    log(`   Message: ${response.data.message}`, 'cyan');

    if (response.data.error_message) {
      log(`   Error: ${response.data.error_message}`, 'red');
    }

    return { success: true, data: response.data };
  } catch (error) {
    // Error handling similar to other functions
    if (error.response) {
      log(`❌ Request failed with status ${error.response.status}:`, 'red');
      log(`   Error: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`❌ Unexpected error: ${error.message}`, 'red');
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

  // // // 2) Register ONLY the derived address 
  // const reg = await testRegisterUser(signerAddr);

  // if (reg.success) {
  //   log(`\n⏳ Waiting 2 seconds before checking user info...`, 'yellow');
  //   await new Promise(r => setTimeout(r, 2000));
  //   await testGetUserInfo(signerAddr);
  // } else {
  //   log(`\n⚠️ Registration failed; continuing to deposit test (is_registered may be false).`, 'yellow');
  // }

  // 3) MPC deposit test WITHOUT tx_id (should pass Some(signer) to handle_deposit_intent)
  log(`\n🧪 Test 1: Normal deposit amount WITHOUT tx_id`, 'blue');
  const amount = 20000000000000000000
  await testUserMpcDeposit({ wallet, amount }); 
  
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
