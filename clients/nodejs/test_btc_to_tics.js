#!/usr/bin/env node

/**
 * Test BTC to TICS transaction - All Wallets
 *
 * This script initiates BTC -> TICS swaps using wallets that have confirmed BTC
 * It automatically calculates the max amount that can be transferred (balance - fees)
 */

import axios from 'axios';
import { Wallet } from 'ethers';
import https from 'https';

// =========================
// Configuration
// =========================
const RPC_BASE_URL = process.env.RPC_BASE_URL ?? 'http://124.243.185.174:8083';
const API_KEY = process.env.RPC_API_KEY ?? '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

// Estimated fee in satoshis (adjust based on network conditions)
const ESTIMATED_FEE_SATS = parseInt(process.env.FEE_SATS || '730', 10);

// Original wallets from sustained_test.js (now re-registered, fetch derived addresses from RPC)
const ORIGINAL_WALLET_KEYS = (process.env.ORIGINAL_WALLET_KEYS || '').split(',').map((k) => k.trim()).filter(Boolean);

// Aachal wallets (need to fetch derived addresses from RPC)
const AACHAL_WALLET_KEYS = (process.env.AACHAL_WALLET_KEYS || '').split(',').map((k) => k.trim()).filter(Boolean);

// Delay between transactions in ms
const DELAY_MS = parseInt(process.env.DELAY || '35000', 10);

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(msg, color = 'reset') {
  const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
  console.log(`${colors[color]}[${timestamp}] ${msg}${colors.reset}`);
}

function bigIntStringify(obj) {
  const entries = Object.entries(obj).map(([k, v]) => {
    if (typeof v === 'bigint') {
      return `"${k}":"${v.toString()}"`;
    } else if (typeof v === 'string') {
      return `"${k}":"${v}"`;
    } else {
      return `"${k}":${JSON.stringify(v)}`;
    }
  });
  return `{${entries.join(',')}}`;
}

async function getUserInfo(address) {
  const response = await axios.get(
    `${RPC_BASE_URL}/user_info/${address}`,
    { headers: { 'X-API-KEY': API_KEY }, timeout: 10000 }
  );
  return response.data;
}

// Check BTC balance on Testnet4
async function getBtcBalance(btcAddress) {
  return new Promise((resolve) => {
    https.get(`https://mempool.space/testnet4/api/address/${btcAddress}`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const confirmed = json.chain_stats.funded_txo_sum - json.chain_stats.spent_txo_sum;
          resolve({ confirmed, error: null });
        } catch(e) {
          resolve({ confirmed: 0, error: e.message });
        }
      });
    }).on('error', (e) => {
      resolve({ confirmed: 0, error: e.message });
    });
  });
}

async function sendBtcToTics(wallet, derivedBtc, derivedEth, amountSats, txNum) {
  const timestamp = Math.floor(Date.now() / 1000) + txNum;

  // Amount in satoshis (BTC smallest unit)
  const amount = BigInt(amountSats);

  const depositIntent = {
    source_address: derivedBtc,      // FROM: BTC address
    target_address: derivedEth,      // TO: ETH address
    source_chain: 'bitcoin',         // FROM chain
    target_chain: 'qubetics',        // TO chain
    amount: amount,                  // Amount in satoshis
    source_token: 'BTC',
    target_token: 'TICS',
    timestamp: timestamp,
  };

  const msg = bigIntStringify(depositIntent);
  const signature = await wallet.signMessage(msg);
  const requestBody = `{"signature":"${signature}","msg":${msg}}`;

  try {
    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      requestBody,
      {
        headers: { 'Content-Type': 'application/json', 'X-API-KEY': API_KEY },
        timeout: 120000
      }
    );

    return response.data;
  } catch (error) {
    if (error.response) {
      return {
        status: 'error',
        error_message: error.response.data?.error_message || error.response.data?.message || JSON.stringify(error.response.data)
      };
    }
    return { status: 'error', error_message: error.message };
  }
}

// =========================
// Metrics
// =========================
const metrics = {
  total: 0,
  success: 0,
  failed: 0,
  insufficientFunds: 0,
  skipped: 0,
  errors: []
};

async function main() {
  log('========================================', 'cyan');
  log('  BTC -> TICS Transaction Test (Max Amount)', 'bright');
  log('========================================', 'cyan');
  log(`Target: ${RPC_BASE_URL}`, 'cyan');
  log(`Estimated Fee: ${ESTIMATED_FEE_SATS} sats`, 'cyan');
  log(`Delay: ${DELAY_MS / 1000}s`, 'cyan');

  // Prepare all wallets
  log('\nPreparing wallets and checking BTC balances...', 'yellow');
  const wallets = [];

  // Add original wallets (fetch from RPC)
  log('\n[Original Wallets - from sustained_test.js]', 'blue');
  for (const pk of ORIGINAL_WALLET_KEYS) {
    const wallet = new Wallet(pk.startsWith('0x') ? pk : `0x${pk}`);
    const address = await wallet.getAddress();

    try {
      const userInfo = await getUserInfo(address);
      if (userInfo.derived_eth_address && userInfo.derived_btc_address) {
        const btcBalance = await getBtcBalance(userInfo.derived_btc_address);
        const maxAmount = Math.max(0, btcBalance.confirmed - ESTIMATED_FEE_SATS);

        wallets.push({
          wallet,
          address,
          derivedEth: userInfo.derived_eth_address,
          derivedBtc: userInfo.derived_btc_address,
          btcBalance: btcBalance.confirmed,
          maxAmount,
          source: 'original'
        });

        if (btcBalance.confirmed > 0) {
          log(`  [OK] ${address.substring(0, 10)}... | BTC: ${userInfo.derived_btc_address} | Balance: ${btcBalance.confirmed} sats | Max TX: ${maxAmount} sats`, 'green');
        } else {
          log(`  [--] ${address.substring(0, 10)}... | BTC: ${userInfo.derived_btc_address} | Balance: 0 sats`, 'yellow');
        }
      }
    } catch (e) {
      log(`  [SKIP] ${address.substring(0, 10)}... not registered`, 'yellow');
    }

    await new Promise(r => setTimeout(r, 200));
  }

  // Add Aachal wallets (fetch from RPC)
  log('\n[Aachal Wallets - from RPC]', 'blue');
  for (const pk of AACHAL_WALLET_KEYS) {
    const wallet = new Wallet(pk.startsWith('0x') ? pk : `0x${pk}`);
    const address = await wallet.getAddress();

    try {
      const userInfo = await getUserInfo(address);
      if (userInfo.derived_eth_address && userInfo.derived_btc_address) {
        const btcBalance = await getBtcBalance(userInfo.derived_btc_address);
        const maxAmount = Math.max(0, btcBalance.confirmed - ESTIMATED_FEE_SATS);

        wallets.push({
          wallet,
          address,
          derivedEth: userInfo.derived_eth_address,
          derivedBtc: userInfo.derived_btc_address,
          btcBalance: btcBalance.confirmed,
          maxAmount,
          source: 'aachal'
        });

        if (btcBalance.confirmed > 0) {
          log(`  [OK] ${address.substring(0, 10)}... | BTC: ${userInfo.derived_btc_address} | Balance: ${btcBalance.confirmed} sats | Max TX: ${maxAmount} sats`, 'green');
        } else {
          log(`  [--] ${address.substring(0, 10)}... | BTC: ${userInfo.derived_btc_address} | Balance: 0 sats`, 'yellow');
        }
      }
    } catch (e) {
      log(`  [SKIP] ${address.substring(0, 10)}... not registered`, 'yellow');
    }

    await new Promise(r => setTimeout(r, 200));
  }

  // Filter wallets with enough balance
  const walletsWithBalance = wallets.filter(w => w.maxAmount > 0);

  log(`\nTotal wallets: ${wallets.length}`, 'cyan');
  log(`Wallets with sufficient BTC: ${walletsWithBalance.length}`, walletsWithBalance.length > 0 ? 'green' : 'yellow');

  if (walletsWithBalance.length === 0) {
    log('\nNo wallets have enough confirmed BTC!', 'red');
    log('Wait for pending transactions to confirm and try again.', 'yellow');

    const totalBalance = wallets.reduce((sum, w) => sum + w.btcBalance, 0);
    log(`\nTotal BTC across all wallets: ${totalBalance} sats (${totalBalance / 100000000} BTC)`, 'cyan');
    process.exit(0);
  }

  // Process each wallet with balance
  log('\n========================================', 'cyan');
  log('  Starting BTC -> TICS Swaps (Max Amount)', 'bright');
  log('========================================', 'cyan');

  for (let i = 0; i < walletsWithBalance.length; i++) {
    const { wallet, address, derivedEth, derivedBtc, btcBalance, maxAmount, source } = walletsWithBalance[i];
    const txNum = i + 1;

    log(`\n[${txNum}/${walletsWithBalance.length}] Wallet: ${address.substring(0, 10)}... (${source})`, 'blue');
    log(`  BTC Address: ${derivedBtc}`, 'cyan');
    log(`  Balance: ${btcBalance} sats`, 'cyan');
    log(`  Sending: ${maxAmount} sats (max - fees)`, 'cyan');

    const result = await sendBtcToTics(wallet, derivedBtc, derivedEth, maxAmount, txNum);

    metrics.total++;

    if (result.status === 'success') {
      metrics.success++;
      log(`  [OK] SUCCESS!`, 'green');
      if (result.user_to_network_tx_id) {
        log(`       User->Network TX: ${result.user_to_network_tx_id}`, 'green');
      }
      if (result.network_to_target_tx_id) {
        log(`       Network->Target TX: ${result.network_to_target_tx_id}`, 'green');
      }
    } else {
      metrics.failed++;
      const errorMsg = result.error_message || 'Unknown error';

      if (errorMsg.includes('Insufficient') || errorMsg.includes('insufficient')) {
        metrics.insufficientFunds++;
        log(`  [SKIP] Insufficient funds`, 'yellow');
        log(`         ${errorMsg.substring(0, 150)}`, 'yellow');
      } else {
        metrics.errors.push({ wallet: address, error: errorMsg });
        log(`  [FAIL] ${errorMsg.substring(0, 150)}`, 'red');
      }
    }

    // Wait before next transaction (unless it's the last one)
    if (i < walletsWithBalance.length - 1) {
      log(`  Waiting ${DELAY_MS / 1000}s...`, 'cyan');
      await new Promise(r => setTimeout(r, DELAY_MS));
    }
  }

  // Final results
  log('\n========================================', 'cyan');
  log('  FINAL RESULTS', 'bright');
  log('========================================', 'cyan');
  log(`Total Attempted:    ${metrics.total}`, 'cyan');
  log(`Successful:         ${metrics.success}`, metrics.success > 0 ? 'green' : 'yellow');
  log(`Failed:             ${metrics.failed}`, metrics.failed > 0 ? 'red' : 'green');
  log(`Insufficient Funds: ${metrics.insufficientFunds}`, 'yellow');

  if (metrics.insufficientFunds > 0) {
    log(`\nNote: ${metrics.insufficientFunds} wallets had insufficient confirmed BTC.`, 'yellow');
    log(`The fee estimate might be too low. Try increasing FEE_SATS.`, 'yellow');
  }
}

main().catch(err => {
  log(`\n[ERROR] Test failed: ${err.message}`, 'red');
  console.error(err);
  process.exit(1);
});
