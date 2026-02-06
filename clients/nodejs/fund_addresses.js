#!/usr/bin/env node

import { ethers } from 'ethers';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Get current directory in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Disable SSL verification for testnet with self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Configuration
const RPC_URL = 'https://rpc-testnet.qubetics.work';
const FUNDING_KEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const AMOUNT = "200";

// Load addresses from registered_eth_addresses.json
const REGISTERED_ADDRESSES_FILE = path.join(__dirname, 'registered_eth_addresses.json');
let ADDRESSES = [];

try {
  const data = fs.readFileSync(REGISTERED_ADDRESSES_FILE, 'utf8');
  const registered = JSON.parse(data);
  ADDRESSES = registered.map(entry => entry.derivedEthAddress ?? entry.walletAddress).filter(Boolean);
  if (ADDRESSES.length === 0) {
    console.error('❌ No valid addresses (derivedEthAddress or walletAddress) in registered_eth_addresses.json');
    process.exit(1);
  }
  console.log(`✅ Loaded ${ADDRESSES.length} addresses from ${REGISTERED_ADDRESSES_FILE}`);
} catch (error) {
  console.error(`❌ Error loading addresses: ${error.message}`);
  process.exit(1);
}

const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bright: '\x1b[1m'
};

function log(msg, color = 'reset') {
  console.log(`${colors[color]}${msg}${colors.reset}`);
}

async function main() {
  if (!FUNDING_KEY) {
    log('❌ Error: FUNDING_KEY environment variable not set', 'red');
    log('Usage: FUNDING_KEY=your_key node fund_addresses.js', 'yellow');
    log('Optional: RPC_URL=https://... AMOUNT=1.0', 'yellow');
    process.exit(1);
  }

  log('═══════════════════════════════════════════════════════════', 'bright');
  log('💰 FUNDING ADDRESSES', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('');

  try {
    // Create a temporary provider to fetch the actual chain ID
    const tempProvider = new ethers.providers.JsonRpcProvider(RPC_URL);

    log('🔍 Fetching chain ID from network...', 'cyan');
    const network = await tempProvider.getNetwork();
    log(`📡 Chain ID: ${network.chainId}`, 'cyan');
    log('');

    // Now create the proper provider with the correct chain ID
    const provider = new ethers.providers.StaticJsonRpcProvider(RPC_URL, network);
    const wallet = new ethers.Wallet(
      FUNDING_KEY.startsWith('0x') ? FUNDING_KEY : `0x${FUNDING_KEY}`,
      provider
    );

    log(`🔗 RPC: ${RPC_URL}`, 'cyan');
    log(`💼 From: ${wallet.address}`, 'cyan');
    log(`💵 Amount per address: ${AMOUNT} TICS`, 'cyan');
    log('');

    const balance = await provider.getBalance(wallet.address);
    const balanceTics = ethers.utils.formatEther(balance);
    log(`📊 Balance: ${balanceTics} TICS`, 'cyan');

    const totalRequired = ethers.utils.parseEther(AMOUNT).mul(ADDRESSES.length);
    const totalTics = ethers.utils.formatEther(totalRequired);
    log(`📊 Required: ${totalTics} TICS`, 'cyan');
    log('');

    if (balance < totalRequired) {
      log('❌ Insufficient balance', 'red');
      return;
    }

    log(`💸 Funding ${ADDRESSES.length} addresses...`, 'green');
    log('');

    let success = 0;
    for (let i = 0; i < ADDRESSES.length; i++) {
      const addr = ADDRESSES[i];
      try {
        log(`[${i + 1}/${ADDRESSES.length}] Sending to ${addr}...`, 'cyan');

        const tx = await wallet.sendTransaction({
          to: addr,
          value: ethers.utils.parseEther(AMOUNT),
          gasLimit: 100000, // chain requires >21000 intrinsic gas (e.g. 53000)
        });

        log(`  TX: ${tx.hash}`, 'yellow');
        const receipt = await tx.wait();

        if (receipt.status === 1) {
          log(`  ✅ Confirmed (block ${receipt.blockNumber})`, 'green');
          success++;
        } else {
          log(`  ❌ Reverted`, 'red');
        }
      } catch (error) {
        log(`  ❌ Error: ${error.message}`, 'red');
      }
      log('');

      if (i < ADDRESSES.length - 1) {
        await new Promise(r => setTimeout(r, 1000));
      }
    }

    log('═══════════════════════════════════════════════════════════', 'bright');
    log(`✅ Success: ${success}/${ADDRESSES.length}`, success === ADDRESSES.length ? 'green' : 'yellow');
    log('═══════════════════════════════════════════════════════════', 'bright');

  } catch (error) {
    log('', 'reset');
    log(`💥 Error: ${error.message}`, 'red');
    process.exit(1);
  }
}

main();

