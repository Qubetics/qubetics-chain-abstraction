#!/usr/bin/env node

import { ethers } from 'ethers';

// Configuration
const RPC_URL = 'http://114.119.184.52:8545';
const FUNDING_KEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const AMOUNT = "300";

// Addresses to fund (derived from test_sequencer_parallel.js private keys)
const ADDRESSES = [
  "0xfa2e8f79851c665e3fe58d0026240036660b3701",
  "0xd9a03691e4a4e7733017674b32fb8822147d3e89",
  "0x8dd282fde5406ff773b1f6e88ba3bf669ade2492",
  "0xf80fd520a0e81299e3ada8bfa044a35da3c275e1",
  "0xea007faa94ecac62fc7a525244b681ec4d0068c3",
  "0x15284b2e0483216cb8369b95979dfa97f589ea0a",
  "0x15284b2e0483216cb8369b95979dfa97f589ea0a",
  "0x32abb710d4a1e0eeee0a7396443eeb6dd40ced7c",
  "0xac9e081d9268772cf30de51ec42502fb78f2f0a5",
  "0x89d1e87585dfbe4a3ecf491c08d439be538674c7",
  "0xe55123db5d1694abe2f658f1e30e360dde9c2a0a",
  "0xccfdc1db85aeb02164fd4e35673d2e7371c064d8",
  "0x9d3ba4822e66036389c6be74385363031e200357",
];

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
    // Ethers v5 syntax
    const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
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
          gasLimit: 21000,
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

