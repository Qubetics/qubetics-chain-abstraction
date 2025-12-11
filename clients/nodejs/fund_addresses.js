#!/usr/bin/env node

import { ethers } from 'ethers';

// Configuration
const RPC_URL = 'http://114.119.184.52:8545';
const FUNDING_KEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const AMOUNT = "300";

// Addresses to fund (derived from test_sequencer_parallel.js private keys)
const ADDRESSES = [
  "0x0ca92d102ee7d436cdf524a1c05ad9eb0c34acee",
  "0x26878bb40dff9c12ac96ab3d328047203e0a8d3e",
  "0x647f274aa880caf2f76d95782010e80116dc0789",
  "0x5716d019691ccd05f8c953d64a08fb8ed304fb13",
  "0xcd578368c582cfed43f8f7a170a762bb87641e72",
  "0x925ade2f1c01e382dadb5cf7f553b9edc8604578",
  "0xd500312a4a88d1ee6d7f5c6ee312aab5a8da1239",
  "0x07b9483075a9c8302d1a255003628da60cf8bb1a",
  "0x599250a582f8b01b6516d2e1ebbfe9dafb9977ce",
  "0xc6575c468475c5bd6c8c83f44e572bfe6505d742",
  "0xbf903836f84b98462dd16159ad8d312fb206df2b",
  "0xf2b6ecd6a1ce992681e9cf56e97ffbc6d9991b32",
  "0x0eb42da2ac5f19e6b5cf92162d521b6173fe5e09",
  "0xe2608a1b54a1037429a21a6d63c5853bcfc3aaf2",
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
    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const wallet = new ethers.Wallet(
      FUNDING_KEY.startsWith('0x') ? FUNDING_KEY : `0x${FUNDING_KEY}`,
      provider
    );

    log(`🔗 RPC: ${RPC_URL}`, 'cyan');
    log(`💼 From: ${wallet.address}`, 'cyan');
    log(`💵 Amount per address: ${AMOUNT} TICS`, 'cyan');
    log('');

    const balance = await provider.getBalance(wallet.address);
    const balanceTics = ethers.formatEther(balance);
    log(`📊 Balance: ${balanceTics} TICS`, 'cyan');

    const totalRequired = ethers.parseEther(AMOUNT) * BigInt(ADDRESSES.length);
    const totalTics = ethers.formatEther(totalRequired);
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
          value: ethers.parseEther(AMOUNT),
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

