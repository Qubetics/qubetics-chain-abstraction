#!/usr/bin/env node

/**
 * Check TICS balances and transaction counts for registered addresses
 * Uses RPC eth_getTransactionCount for outgoing tx count (nonce)
 */

import { ethers } from 'ethers';
import fs from 'fs';

const RPC_URL = process.env.RPC_URL || 'https://rpc-testnet.qubetics.work';
const ADDRESSES_FILE = process.env.ADDRESSES_FILE || 'registered_eth_addresses.json';

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  blue: '\x1b[34m',
  red: '\x1b[31m',
  bright: '\x1b[1m'
};

function log(msg, color = 'reset') {
  console.log(`${colors[color]}${msg}${colors.reset}`);
}

async function main() {
  log('═══════════════════════════════════════════════════════════════════════════════', 'cyan');
  log('  TICS BALANCE & TRANSACTION CHECKER', 'bright');
  log('═══════════════════════════════════════════════════════════════════════════════', 'cyan');

  // Load addresses (handle both wallet and walletAddress field names)
  const data = JSON.parse(fs.readFileSync(ADDRESSES_FILE, 'utf8'));
  const addresses = data
    .filter(item => item.derivedEthAddress) // Skip entries with null derived addresses
    .map(item => ({
      wallet: item.wallet || item.walletAddress,
      derived: item.derivedEthAddress
    }));

  log(`\nLoaded ${addresses.length} addresses from ${ADDRESSES_FILE}`, 'cyan');
  log(`RPC: ${RPC_URL}\n`, 'cyan');

  // Disable TLS verification for testnet
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

  let totalBalance = ethers.BigNumber.from(0);
  let totalOutTxs = 0;

  log('Derived ETH Address                          | Balance (TICS) | Out TXs (nonce)', 'yellow');
  log('─'.repeat(80), 'yellow');

  for (const { derived } of addresses) {
    try {
      const [balance, nonce] = await Promise.all([
        provider.getBalance(derived),
        provider.getTransactionCount(derived)
      ]);

      totalBalance = totalBalance.add(balance);
      totalOutTxs += nonce;

      const balanceFormatted = parseFloat(ethers.utils.formatEther(balance)).toFixed(2);

      const color = !balance.isZero() ? 'green' : 'yellow';
      log(
        `${derived} | ${balanceFormatted.padStart(14)} | ${String(nonce).padStart(15)}`,
        color
      );
    } catch (e) {
      log(`${derived} | ERROR: ${e.message}`, 'red');
    }
  }

  log('─'.repeat(80), 'yellow');
  log(
    `${'TOTAL'.padEnd(42)} | ${parseFloat(ethers.utils.formatEther(totalBalance)).toFixed(2).padStart(14)} | ${String(totalOutTxs).padStart(15)}`,
    'bright'
  );
  log(`\nTotal Addresses: ${addresses.length}`, 'cyan');
  log('═══════════════════════════════════════════════════════════════════════════════', 'cyan');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
