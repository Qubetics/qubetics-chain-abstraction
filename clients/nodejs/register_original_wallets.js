#!/usr/bin/env node

/**
 * Re-register Original Wallets
 *
 * Registers the 12 original wallets from sustained_test.js
 * that have BTC on their derived addresses.
 */

import axios from 'axios';
import { Wallet } from 'ethers';

const RPC_BASE_URL = process.env.RPC_BASE_URL ?? 'http://124.243.185.174:8083';
const API_KEY = process.env.RPC_API_KEY ?? '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

const DELAY_SECONDS = parseInt(process.env.DELAY || '35', 10);

// Original wallets from sustained_test.js
const WALLET_PRIVATE_KEYS = (process.env.WALLET_PRIVATE_KEYS || '').split(',').map((k) => k.trim()).filter(Boolean);

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  blue: '\x1b[34m',
  bright: '\x1b[1m'
};

function log(msg, color = 'reset') {
  const ts = new Date().toISOString().split('T')[1].split('.')[0];
  console.log(`${colors[color]}[${ts}] ${msg}${colors.reset}`);
}

async function registerUser(wallet) {
  const address = await wallet.getAddress();
  const timestamp = Math.floor(Date.now() / 1000);
  const message = `register:${address}:${timestamp}`;
  const signature = await wallet.signMessage(message);

  const response = await axios.post(
    `${RPC_BASE_URL}/register_user`,
    {
      ethereum_address: address,
      signature: signature,
      message: message
    },
    {
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': API_KEY
      },
      timeout: 30000
    }
  );
  return response.data;
}

async function getUserInfo(address) {
  const response = await axios.get(
    `${RPC_BASE_URL}/user_info/${address}`,
    {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    }
  );
  return response.data;
}

async function main() {
  log('========================================', 'cyan');
  log('  RE-REGISTER ORIGINAL WALLETS', 'bright');
  log('========================================', 'cyan');

  log(`\nRegistering ${WALLET_PRIVATE_KEYS.length} original wallets...`, 'yellow');
  log(`Delay between registrations: ${DELAY_SECONDS}s`, 'cyan');
  log(`Estimated time: ${(WALLET_PRIVATE_KEYS.length * DELAY_SECONDS / 60).toFixed(1)} minutes\n`, 'cyan');

  const results = { success: 0, failed: 0, alreadyRegistered: 0 };
  const registeredWallets = [];

  for (let i = 0; i < WALLET_PRIVATE_KEYS.length; i++) {
    const pk = WALLET_PRIVATE_KEYS[i];
    const wallet = new Wallet(pk.startsWith('0x') ? pk : `0x${pk}`);
    const address = await wallet.getAddress();

    log(`\n[${i + 1}/${WALLET_PRIVATE_KEYS.length}] ${address}`, 'blue');

    // First check if already registered
    try {
      const userInfo = await getUserInfo(address);
      if (userInfo.derived_eth_address) {
        log(`   Already registered!`, 'green');
        log(`   Derived ETH: ${userInfo.derived_eth_address}`, 'cyan');
        log(`   Derived BTC: ${userInfo.derived_btc_address}`, 'cyan');
        results.alreadyRegistered++;
        registeredWallets.push({
          address,
          derivedEth: userInfo.derived_eth_address,
          derivedBtc: userInfo.derived_btc_address
        });
        continue;
      }
    } catch (e) {
      // Not registered, proceed with registration
    }

    try {
      await registerUser(wallet);

      // Wait a moment then verify
      await new Promise(r => setTimeout(r, 2000));
      const userInfo = await getUserInfo(address);

      if (userInfo.derived_eth_address) {
        log(`   Registered successfully!`, 'green');
        log(`   Derived ETH: ${userInfo.derived_eth_address}`, 'cyan');
        log(`   Derived BTC: ${userInfo.derived_btc_address}`, 'cyan');
        results.success++;
        registeredWallets.push({
          address,
          derivedEth: userInfo.derived_eth_address,
          derivedBtc: userInfo.derived_btc_address
        });
      } else {
        log(`   Registered but no derived address yet`, 'yellow');
        results.success++;
      }
    } catch (error) {
      if (error.response?.status === 429) {
        log(`   Rate limited! Waiting extra 60s...`, 'yellow');
        await new Promise(r => setTimeout(r, 60000));
        i--; // Retry
        continue;
      }
      log(`   Failed: ${error.response?.data?.message || error.message}`, 'red');
      results.failed++;
    }

    // Wait before next registration
    if (i < WALLET_PRIVATE_KEYS.length - 1) {
      log(`   Waiting ${DELAY_SECONDS}s...`, 'cyan');
      await new Promise(r => setTimeout(r, DELAY_SECONDS * 1000));
    }
  }

  log('\n========================================', 'cyan');
  log('  REGISTRATION COMPLETE', 'bright');
  log('========================================', 'cyan');

  log(`\nResults:`, 'yellow');
  log(`  Already Registered: ${results.alreadyRegistered}`, 'green');
  log(`  Newly Registered:   ${results.success}`, 'green');
  log(`  Failed:             ${results.failed}`, results.failed > 0 ? 'red' : 'green');
  log(`  Total Ready:        ${registeredWallets.length}`, 'cyan');

  if (registeredWallets.length > 0) {
    log(`\nRegistered Wallets:`, 'yellow');
    for (const w of registeredWallets) {
      log(`  ${w.address.substring(0, 10)}... -> BTC: ${w.derivedBtc}`, 'cyan');
    }
  }
}

main().catch(err => {
  log(`\nError: ${err.message}`, 'red');
  process.exit(1);
});
