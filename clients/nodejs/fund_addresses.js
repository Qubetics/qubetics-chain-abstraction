#!/usr/bin/env node

import { ethers } from 'ethers';
import https from 'https';

// Disable SSL verification for testnet with self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Configuration
const RPC_URL = 'https://rpc-testnet.qubetics.work';
const FUNDING_KEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const AMOUNT = "100";

// Addresses to fund (derived from test_sequencer_parallel.js private keys)
const ADDRESSES = [
  "0x7ebe71471d9df3cc895cb63e531ed89671c2c470",
  "0x1f0dd3e84b727c0415c7cedaa1bdea465f4fdac8",
  "0x8f6b1a98a7a6180cd0a4ad5456f0eb806a685538",
  "0x4e366b290fe36bcc60ffa5094087ec19c03fddf9",
  "0x1f2c7256e04369d7cf112bc6d352b576661055b1",
  "0x3a168625d2d2ec7cd8cf79a45e166d6ba0bcccfe",
  "0xf9438a20b596459deb512438acb04109995ee558",
  "0x5ef939595630b02c3ed7b89e11e8db82db2b665b",
  "0xc52779d2a23a2a160d371c5bcf78dcbda48a28e5",
  "0x915eb0db0cf86438102ba3570793b123c2030d04",
  "0xc29f15660b70d8842c711ce2f3b95aff2fc9ed1d",
  "0x6e628094c68dfea3ad8399e1666bd12fb42f2a7a",
  "0xb7224f69feab9f3af066b61710bf475bd8d9dfc2",
  "0xfc659d5fb18b1a212fddbeb2b536078af61a6d8e",
  "0x9397d3498dcb5d02604daa1bf36c1ce0ea4c6e66"
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

