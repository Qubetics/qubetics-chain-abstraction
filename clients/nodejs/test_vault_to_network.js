#!/usr/bin/env node

import axios from 'axios';
import { Wallet } from 'ethers';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = process.env.RPC_BASE_URL || 'http://localhost:8081';

// 👉 Private key you provided (hex, no 0x prefix needed)
const TEST_PRIVKEY = '415c01d63918df986d1d537f9b5974f383cac3b4fe9edc44f58f09bdfc5f672a';

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
async function getUserInfo(ethereumAddress) {
  try {
    const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, { timeout: 10000 });
    return response.data;
  } catch (error) {
    throw new Error(`User not found: ${ethereumAddress}`);
  }
}

// =========================
// VaultToNetwork Flow Test
// =========================
async function vaultToNetworkTransfer({ wallet, amount }) {
  const signerAddr = await wallet.getAddress();
  log(`🔐 VaultToNetwork - Amount: ${amount}`, 'blue');

  const userInfo = await getUserInfo(signerAddr);
  console.log(`UserInfo: ${JSON.stringify(userInfo, null, 2)}`);
  const depositIntent = {
    source_address: userInfo.derived_btc_address, // Use canonical address
    target_address: 'tb1qzxxlpvxx44ak6tasj5ffstr6gj5xrpxzxwrjy3',
    source_chain: 'bitcoin',
    target_chain: 'bitcoin',
    amount: amount, // Use the passed amount parameter
    source_token: 'TICS',
    target_token: 'TICS',
    timestamp: 909092,
  };

  const msg = JSON.stringify(depositIntent);
  const signature = await wallet.signMessage(msg);

  const response = await axios.post(
    `${RPC_BASE_URL}/user_mpc_deposit`,
    { signature, msg: depositIntent },
    { 
      headers: { 'Content-Type': 'application/json' },
      timeout: 25000
    }
  );

  const status = response.data.status;
  log(`✅ Status: ${status}`, status === 'success' ? 'green' : 'yellow');

  if (response.data.user_to_network_tx_id) {
    log(`   User->Network TX: ${response.data.user_to_network_tx_id}`, 'cyan');
  }
  if (response.data.network_to_target_tx_id) {
    log(`   Network->Target TX: ${response.data.network_to_target_tx_id}`, 'cyan');
  }
  if (response.data.vault_to_network_tx_id) {
    log(`   Vault->Network TX: ${response.data.vault_to_network_tx_id}`, 'cyan');
  }
  
  if (response.data.error_message) {
    log(`   Error: ${response.data.error_message}`, 'red');
  }

  return response.data;
}


async function getIntentByHash(intentHash) {
  log(`🔍 Getting intent: ${intentHash.substring(0, 10)}...`, 'blue');
  const response = await axios.get(`${RPC_BASE_URL}/get_intent_by_hash/${intentHash}`, { timeout: 10000 });
  
  log(`✅ Intent found - Status: ${response.data.status}`, 'green');
  if (response.data.user_to_network_tx_id) {
    log(`   User->Network TX: ${response.data.user_to_network_tx_id}`, 'cyan');
  }
  if (response.data.network_to_target_tx_id) {
    log(`   Network->Target TX: ${response.data.network_to_target_tx_id}`, 'cyan');
  }
  if (response.data.vault_to_network_tx_id) {
    log(`   Vault->Network TX: ${response.data.vault_to_network_tx_id}`, 'cyan');
  }
  
  return response.data;
}

// =========================
// Main Runner
// =========================
async function runVaultToNetworkTests() {
  log(`${colors.bright}🧪 VaultToNetwork Transfer${colors.reset}`, 'bright');
  log(`📍 RPC: ${RPC_BASE_URL}`, 'cyan');

  const pk = TEST_PRIVKEY.startsWith('0x') ? TEST_PRIVKEY : `0x${TEST_PRIVKEY}`;
  const wallet = new Wallet(pk);
  const signerAddr = await wallet.getAddress();
  log(`🔑 Signer: ${signerAddr}`, 'blue');

  // VaultToNetwork transfer
  const amount = 921;
  await vaultToNetworkTransfer({ wallet, amount });
  await new Promise(r => setTimeout(r, 7000));

  log(`${colors.bright}✅ Completed!${colors.reset}`, 'bright');
}

// =========================
// CLI help
// =========================
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log(`${colors.bright}Usage:${colors.reset}`, 'bright');
  log(`  node test_vault_to_network.js`, 'cyan');
  log(`${colors.bright}Features:${colors.reset}`, 'bright');
  log(`  • VaultToNetwork transfer`, 'yellow');
  log(`  • Intent endpoints`, 'yellow');
  process.exit(0);
}

// Run
runVaultToNetworkTests().catch(err => {
  log(`❌ Failed: ${err.message}`, 'red');
  process.exit(1);
});
