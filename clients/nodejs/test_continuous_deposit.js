#!/usr/bin/env node

import axios from 'axios';
import { Wallet } from 'ethers';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = process.env.RPC_BASE_URL || 'http://127.0.0.1:8083';
const API_KEY = process.env.RPC_API_KEY || process.env.API_KEY || "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// Private key
const TEST_PRIVKEY = process.env.TEST_PRIVKEY;

// Transaction storage file
const TXN_STORAGE_FILE = path.join(process.cwd(), 'deposit_transactions.json');

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
// Transaction Storage Functions
// =========================
function saveTransactions(successful, failed) {
  try {
    const data = {
      last_updated: new Date().toISOString(),
      summary: {
        total_successful: successful.length,
        total_failed: failed.length,
        total_transactions: successful.length + failed.length
      },
      successful_transactions: successful,
      failed_transactions: failed
    };
    
    fs.writeFileSync(TXN_STORAGE_FILE, JSON.stringify(data, null, 2));
    log(`💾 Saved ${successful.length} successful and ${failed.length} failed transactions to ${TXN_STORAGE_FILE}`, 'cyan');
  } catch (error) {
    log(`❌ Failed to save transactions: ${error.message}`, 'red');
  }
}

function loadTransactions() {
  try {
    if (fs.existsSync(TXN_STORAGE_FILE)) {
      const data = fs.readFileSync(TXN_STORAGE_FILE, 'utf8');
      const parsed = JSON.parse(data);
      return {
        successful: parsed.successful_transactions || [],
        failed: parsed.failed_transactions || []
      };
    }
  } catch (error) {
    log(`⚠️  Could not load existing transactions: ${error.message}`, 'yellow');
  }
  return { successful: [], failed: [] };
}

// =========================
// Helper Functions
// =========================
async function testGetUserInfo(ethereumAddress) {
  try {
    const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });
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

async function testUserMpcDeposit({ wallet, amount, timestamp, idempotencyKey }) {
  const requestTime = new Date().toISOString();
  const signerAddr = await wallet.getAddress();
  
  try {
    log(`\n🔐 Testing user_mpc_deposit for signer: ${signerAddr}`, 'blue');
    log(`💰 Amount: ${amount} (${(amount / 1e18).toFixed(2)} TICS)`, 'cyan');
    log(`⏰ Timestamp: ${timestamp}`, 'cyan');

    // Fetch user info to get the canonical Ethereum address
    const userInfo = await testGetUserInfo(signerAddr);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Construct DepositIntent
    const depositIntent = {
      source_address: userInfo.data.derived_eth_address,
      target_address: userInfo.data.derived_eth_address,
      source_chain: 'qubetics',
      target_chain: 'qubetics',
      amount: amount,
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp: timestamp,
    };

    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);

    // EIP-191 personal_sign  
    const signature = await wallet.signMessage(msg);
    log(`✍️  Signature generated`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      {
        headers: { 'Content-Type': 'application/json', 'X-API-KEY': API_KEY },
        timeout: 60000
      }
    );

    // Check response status
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

    log(`📊 Status: ${response.data.status}`, 'cyan');
    
    // Extract transaction IDs
    const txIds = {
      user_to_network: response.data.user_to_network_tx_id || null,
      network_to_target: response.data.network_to_target_tx_id || null,
      vault_to_network: response.data.vault_to_network_tx_id || null,
    };

    if (txIds.user_to_network) {
      log(`   🎯 User->Network TX ID: ${txIds.user_to_network}`, 'green');
    }
    if (txIds.network_to_target) {
      log(`   🎯 Network->Target TX ID: ${txIds.network_to_target}`, 'green');
    }
    if (txIds.vault_to_network) {
      log(`   🎯 Vault->Network TX ID: ${txIds.vault_to_network}`, 'green');
    }

    if (response.data.error_message) {
      if (isError) {
        log(`   💥 Error Message: ${response.data.error_message}`, 'red');
      } else {
        log(`   ℹ️  Message: ${response.data.error_message}`, 'yellow');
      }
    }

    // Return transaction data for storage
    return {
      success: isSuccess || isSubmitted || isProcessing,
      isError: isError,
      isTimeout: isTimeout,
      data: response.data,
      transactionRecord: {
        request_time: requestTime,
        signer_address: signerAddr,
        amount: amount.toString(),
        amount_tics: (amount / 1e18).toFixed(2),
        timestamp: timestamp,
        status: response.data.status,
        transaction_ids: txIds,
        error_message: response.data.error_message || null,
        is_registered: response.data.is_registered || false,
        signer_address_recovered: response.data.signer_address || null,
      }
    };
  } catch (error) {
    const errorMessage = error.response?.data?.error_message || error.message;
    const errorStatus = error.response?.status || null;
    const errorData = error.response?.data || null;

    if (error.response) {
      log(`❌ user_mpc_deposit failed with HTTP status ${errorStatus}:`, 'red');
      if (errorData && errorData.status) {
        log(`   Response Status: ${errorData.status}`, 'red');
        if (errorData.error_message) {
          log(`   🔥 Chain Error: ${errorData.error_message}`, 'red');
        }
      }
    } else {
      log(`❌ user_mpc_deposit error: ${error.message}`, 'red');
    }

    // Return failure record for storage
    return {
      success: false,
      isError: true,
      isTimeout: error.code === 'ETIMEDOUT',
      error: error.message,
      transactionRecord: {
        request_time: requestTime,
        signer_address: signerAddr,
        amount: amount.toString(),
        amount_tics: (amount / 1e18).toFixed(2),
        timestamp: timestamp,
        status: errorData?.status || 'exception',
        transaction_ids: {
          user_to_network: errorData?.user_to_network_tx_id || null,
          network_to_target: errorData?.network_to_target_tx_id || null,
          vault_to_network: errorData?.vault_to_network_tx_id || null,
        },
        error_message: errorMessage,
        http_status: errorStatus,
        error_type: error.code || 'unknown',
      }
    };
  }
}

// =========================
// Main Continuous Test Function
// =========================
async function runContinuousDepositTest() {
  log(`\n${colors.bright}🔄 Starting Continuous MPC Deposit Test${colors.reset}`, 'bright');
  log(`📍 Target RPC: ${RPC_BASE_URL}`, 'cyan');

  // Load existing transactions if any
  const existing = loadTransactions();
  transactionArrays.successful = existing.successful;
  transactionArrays.failed = existing.failed;
  
  log(`📊 Loaded ${transactionArrays.successful.length} successful and ${transactionArrays.failed.length} failed transactions from previous run`, 'cyan');
  log(`💾 Transaction data will be saved to: ${TXN_STORAGE_FILE}`, 'cyan');

  // Wallet from provided private key
  const pk = TEST_PRIVKEY.startsWith('0x') ? TEST_PRIVKEY : `0x${TEST_PRIVKEY}`;
  const wallet = new Wallet(pk);
  const signerAddr = await wallet.getAddress();
  log(`\n🔑 Signer address: ${signerAddr}`, 'blue');

  // Initial amount (will be set to random 10-25 TICS after first 3 calls)
  let currentAmount = 20000000000000000000; // 20 TICS as starting point
  // Initial timestamp (Unix timestamp in seconds)
  let currentTimestamp = Math.floor(Date.now() / 1000);
  let callCount = 0;
  let cycleCount = 0;
  let saveCounter = 0;
  const SAVE_INTERVAL = 10; // Save every 10 transactions

  // Delay between calls (in milliseconds)
  const DELAY_BETWEEN_CALLS = 4000; // 4 seconds

  log(`\n📋 Test Pattern:`, 'cyan');
  log(`   - 3 calls with same intent amount and timestamp`, 'cyan');
  log(`   - Then change to random amount (10-25 TICS) and new timestamp`, 'cyan');
  log(`   - Repeat continuously`, 'cyan');
  log(`   - Delay between calls: ${DELAY_BETWEEN_CALLS}ms`, 'cyan');
  log(`   - Auto-save every ${SAVE_INTERVAL} transactions\n`, 'cyan');

  while (true) {
    cycleCount++;
    callCount++;
    saveCounter++;

    if (callCount <= 3) {
      // First 3 calls with same amount and timestamp
      log(`\n${colors.bright}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`, 'bright');
      log(`🔄 Cycle ${cycleCount} - Call ${callCount}/3 (Same Intent)`, 'blue');
      log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, 'bright');
      
      const result = await testUserMpcDeposit({ wallet, amount: currentAmount, timestamp: currentTimestamp });
      
      // Store transaction record
      if (result.transactionRecord) {
        if (result.success && !result.isError && !result.isTimeout) {
          transactionArrays.successful.push(result.transactionRecord);
          log(`✅ Stored successful transaction (Total: ${transactionArrays.successful.length})`, 'green');
        } else {
          transactionArrays.failed.push(result.transactionRecord);
          log(`❌ Stored failed transaction (Total: ${transactionArrays.failed.length})`, 'red');
        }
      }
      
      // Auto-save periodically
      if (saveCounter >= SAVE_INTERVAL) {
        saveTransactions(transactionArrays.successful, transactionArrays.failed);
        saveCounter = 0;
      }
      
      if (callCount === 3) {
        // After 3 calls, generate new random amount and new timestamp
        const randomTics = Math.floor(Math.random() * (25 - 10 + 1)) + 10; // Random between 10-25
        currentAmount = randomTics * 1e18; // Convert to wei (18 zeros)
        currentTimestamp = Math.floor(Date.now() / 1000); // New Unix timestamp in seconds
        log(`\n🎲 Generated new random amount: ${randomTics} TICS (${currentAmount})`, 'yellow');
        log(`⏰ Generated new timestamp: ${currentTimestamp}`, 'yellow');
        callCount = 0; // Reset counter for next cycle
      }
    }

    // Wait before next call
    log(`\n⏳ Waiting ${DELAY_BETWEEN_CALLS}ms before next call...`, 'yellow');
    await new Promise(r => setTimeout(r, DELAY_BETWEEN_CALLS));
  }
}

// =========================
// Handle graceful shutdown
// =========================
let shutdownInProgress = false;
let transactionArrays = { successful: [], failed: [] };

function gracefulShutdown(signal) {
  if (shutdownInProgress) return;
  shutdownInProgress = true;
  
  log(`\n\n${colors.bright}🛑 Received ${signal}, shutting down gracefully...${colors.reset}`, 'yellow');
  log(`💾 Saving transaction records...`, 'cyan');
  
  saveTransactions(transactionArrays.successful, transactionArrays.failed);
  
  log(`\n📊 Final Summary:`, 'bright');
  log(`   ✅ Successful: ${transactionArrays.successful.length}`, 'green');
  log(`   ❌ Failed: ${transactionArrays.failed.length}`, 'red');
  log(`   📁 Saved to: ${TXN_STORAGE_FILE}`, 'cyan');
  
  process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// =========================
// CLI help
// =========================
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
  log(`  node test_continuous_deposit.js`, 'cyan');
  log(`\n${colors.bright}Environment Variables:${colors.reset}`, 'bright');
  log(`  RPC_BASE_URL    - RPC server URL (default: http://127.0.0.1:8083)`, 'cyan');
  log(`  RPC_API_KEY    - API key for authentication`, 'cyan');
  log(`  TEST_PRIVKEY   - Private key for signing (hex, no 0x prefix needed)`, 'cyan');
  log(`\n${colors.bright}Pattern:${colors.reset}`, 'bright');
  log(`  - Calls testUserMpcDeposit 3 times with same intent amount and timestamp`, 'yellow');
  log(`  - Then changes to random amount (10-25 TICS) and new timestamp`, 'yellow');
  log(`  - Repeats continuously until interrupted (Ctrl+C)`, 'yellow');
  log(`\n${colors.bright}Transaction Storage:${colors.reset}`, 'bright');
  log(`  - All successful and failed transactions are stored in deposit_transactions.json`, 'yellow');
  log(`  - Data is auto-saved every 10 transactions and on shutdown`, 'yellow');
  process.exit(0);
}

// Run
runContinuousDepositTest().catch(err => {
  log(`\n❌ Test runner failed: ${err.message}`, 'red');
  console.error(err);
  process.exit(1);
});

