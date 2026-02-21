#!/usr/bin/env node

import axios from 'axios';
import { Wallet } from 'ethers';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = process.env.RPC_BASE_URL || 'http://127.0.0.1:8082';
const API_KEY = process.env.RPC_API_KEY || '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

// Admin private key — the corresponding public address must match ADMIN_PUBLIC_ADDRESS on the node
const ADMIN_PRIVKEY = process.env.ADMIN_PRIVKEY || '';

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
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// =========================
// Register Admin
// =========================
async function registerAdmin(wallet) {
  const adminAddress = await wallet.getAddress();
  log(`\n🔵 Registering admin address: ${adminAddress}`, 'blue');

  // Message format: "register_admin:{tics_address}:{timestamp}"
  const timestamp = Math.floor(Date.now() / 1000);
  const message = `register_admin:${adminAddress}:${timestamp}`;
  log(`📝 Message: ${message}`, 'cyan');

  // Sign the message using EIP-191 personal_sign
  const signature = await wallet.signMessage(message);
  log(`✍️  Signature: ${signature}`, 'cyan');

  const response = await axios.post(
    `${RPC_BASE_URL}/register_admin`,
    {
      tics_address: adminAddress,
      signature,
      message,
    },
    {
      headers: { 'Content-Type': 'application/json', 'X-API-KEY': API_KEY },
      timeout: 30000,
    }
  );

  return response.data;
}

// =========================
// Get Admin Info
// =========================
async function getAdminInfo(adminAddress) {
  log(`\n🔍 Fetching admin info for: ${adminAddress}`, 'blue');

  const response = await axios.get(
    `${RPC_BASE_URL}/admin_info/${adminAddress}`,
    {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000,
    }
  );

  return response.data;
}

// =========================
// Main
// =========================
async function main() {
  if (!ADMIN_PRIVKEY) {
    log('❌ ADMIN_PRIVKEY environment variable is required.', 'red');
    log('   Usage: ADMIN_PRIVKEY=<hex_private_key> node register_admin.js', 'yellow');
    process.exit(1);
  }

  const pk = ADMIN_PRIVKEY.startsWith('0x') ? ADMIN_PRIVKEY : `0x${ADMIN_PRIVKEY}`;
  const wallet = new Wallet(pk);
  const adminAddress = await wallet.getAddress();

  log(`\n${colors.bright}🛡️  Admin Registration Script${colors.reset}`, 'bright');
  log(`📍 RPC: ${RPC_BASE_URL}`, 'cyan');
  log(`🔑 Admin address: ${adminAddress}`, 'cyan');

  // --- Step 1: Register admin ---
  try {
    const regResult = await registerAdmin(wallet);

    if (regResult.status === 'success') {
      log(`\n✅ Admin registered successfully!`, 'green');
      log(`   Derived ETH Address: ${regResult.derived_eth_address || 'pending'}`, 'cyan');
      log(`   Derived BTC Address: ${regResult.derived_btc_address || 'pending'}`, 'cyan');
    } else {
      log(`\n❌ Registration failed: ${regResult.message}`, 'red');
      if (regResult.error) {
        log(`   Error: ${JSON.stringify(regResult.error)}`, 'red');
      }
      // If admin already registered, continue to fetch info
      if (!regResult.message.includes('already registered')) {
        process.exit(1);
      }
    }
  } catch (error) {
    if (error.response) {
      log(`\n❌ Registration request failed (HTTP ${error.response.status}):`, 'red');
      log(`   ${JSON.stringify(error.response.data, null, 2)}`, 'red');

      // If admin already registered, continue to fetch info
      const msg = error.response.data?.message || '';
      if (!msg.includes('already registered')) {
        process.exit(1);
      }
      log(`\n⚠️  Admin already registered, fetching info...`, 'yellow');
    } else {
      log(`\n❌ Error: ${error.message}`, 'red');
      process.exit(1);
    }
  }

  // --- Step 2: Fetch admin info to get derived addresses ---
  log(`\n⏳ Waiting 2 seconds before fetching admin info...`, 'yellow');
  await new Promise((r) => setTimeout(r, 2000));

  try {
    const info = await getAdminInfo(adminAddress);

    if (info.status === 'success') {
      log(`\n${colors.bright}📋 Admin Info:${colors.reset}`, 'bright');
      log(`   Admin ID:           ${info.admin_id}`, 'cyan');
      log(`   TICS Address:       ${info.tics_address}`, 'cyan');
      log(`   Has Tweaked Share:  ${info.has_tweaked_share}`, 'cyan');
      log(`   Has Group Key:     ${info.has_group_key}`, 'cyan');
      log(`   Derived ETH Addr:  ${info.derived_eth_address || 'N/A'}`, 'green');
      log(`   Derived BTC Addr:  ${info.derived_btc_address || 'N/A'}`, 'green');
      log(`   Created At:        ${info.created_at}`, 'cyan');
    } else {
      log(`\n❌ Failed to get admin info: ${info.message || JSON.stringify(info)}`, 'red');
    }
  } catch (error) {
    if (error.response) {
      log(`\n❌ Admin info request failed (HTTP ${error.response.status}):`, 'red');
      log(`   ${JSON.stringify(error.response.data, null, 2)}`, 'red');
    } else {
      log(`\n❌ Error fetching admin info: ${error.message}`, 'red');
    }
  }
}

// =========================
// CLI help
// =========================
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
  log(`  ADMIN_PRIVKEY=<hex_private_key> node register_admin.js`, 'cyan');
  log(`\n${colors.bright}Environment Variables:${colors.reset}`, 'bright');
  log(`  ADMIN_PRIVKEY   - (Required) Admin's private key (hex, 0x prefix optional)`, 'cyan');
  log(`  RPC_BASE_URL    - RPC server URL (default: http://127.0.0.1:8082)`, 'cyan');
  log(`  RPC_API_KEY     - API key for authentication`, 'cyan');
  log(`\n${colors.bright}Description:${colors.reset}`, 'bright');
  log(`  Registers the admin on the network and retrieves derived ETH/BTC addresses.`, 'yellow');
  log(`  The admin's public address (derived from ADMIN_PRIVKEY) must match the`, 'yellow');
  log(`  ADMIN_PUBLIC_ADDRESS env var configured on the node.`, 'yellow');
  process.exit(0);
}

main().catch((err) => {
  log(`\n❌ Script failed: ${err.message}`, 'red');
  process.exit(1);
});
