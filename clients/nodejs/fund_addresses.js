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
  // "0xf340a30f52e3a8311ed84186f630f7bc31aca5f0",
  // "0x2a9cf33d6e4e223a5ae6404221ce327d3fb4daea",
  // "0x9d691bb91030eaae963ba7394afa0f7f1d624da1",
  // "0xf6c10b5bbce59796aca2a3224d0c55df3f769694",
  // "0x8751a42339dc7d1bb8e6ac6e0305905cb6ce1ae5",
  // "0xa3b0d4973bdb71e8336a0adb47253757152b5be8",
  // "0xd40e4756b469ee08d3143f8b301f2c1a04c158ee",
  "0x401fed70544b37f925b7ad0a4d0130e44d5815e4",
  "0x00db561a10cca31d7acfc5409a3e9d156ea02ad6",
  "0xc751734df86456d84a5141ff98228fb6de4b71d2",
  "0xf4b1e3cc76be8fca605ff65f8195fdc4c6f32967",
  "0x0ef506fd6b9f5576b8ac4591554d2fb2526e1780",
  "0x15422ecc8d6b82eb7372419f78ef11c83e22791c",
  "0x6d09084089cc2159b42d00fa227aa55024b9fbc2"
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

