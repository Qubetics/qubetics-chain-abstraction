#!/usr/bin/env node

import { ethers } from 'ethers';
import https from 'https';

// Disable SSL verification for testnet with self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Configuration
const RPC_URL = 'https://rpc-testnet.qubetics.work';
const FUNDING_KEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';
const AMOUNT = "200";

// Addresses to fund (derived from test_sequencer_parallel.js private keys)
const ADDRESSES = [
  "0xd72a5cce4216030646cafb64256df328e6684830",
  "0x8d56fda77d0675619541015bb359a4347d48ccc5",
  "0xcbd01c959d3a676214d9aa62700b1896e0229f42",
  "0x6cdc81c75e61ce6e34ebe22a8f38c43c8af48a2f",
  "0xf5f1005b177f7ad186d83ba41f68dde775c6ff83",
  "0xb11fbd71e607b5e5b9773b729105956cf25715cf",
  "0x7567653a169b7ba3ea511006ced3e46ec3f8e858",
  "0x41492484360b02aff3181adbc523e057685f674c",
  "0x8a453df9ac3e75bc874ed3f0216cccd40b967dd1",
  "0x861f74e024ea37802f9eef6068ca763228e212d8",
  "0x99471c7d803b24d1dfcf503c5157515707f0a619",
  "0xbcfcbe5c5d8f348b3299244020a62e20bb757afa",
  "0xbe49bce102903ba3f04742c5b30af53738d94090",
  "0xb85e822f4ec9c6feec9e34422a4e28e1d870e6db",
  "0xea54e0b93d6d8fe9d1ef7fe55ca9e17633db3a0e"
  // "0xeeaa148b4bac556d12fcc6b5c245fac294b32084",
  // "0x414a8863b564180b69e0892e4e6a1a15db6b175f",
  // "0x7c36fad068786c5173c92d792121209f8d87067a",
  // "0x13442148fe2fb37bf43a6f7cdd89899198df1819",
  // "0x2b53d03e087903f94d2c6ee5cfbcd22106cf400a",
  // "0xf20a8199cb73dbca97e35914ca504cd725e55ef7",
  // "0x9e5387f2699045599896cf56adcc87480915c6b5",
  // "0x461041bceb1dc179df02027e6586bb3380a85140",
  // "0x1d16e4927bb5efb64f72c6ef42f0ff069413c08b",
  // "0x64d8ec375fc752b9452a1f4b4fc1ae6bda3ef9ea",
  // "0x129151597db8071b8f5ae6eb78aa42b18aebb37e",
  // "0x4497fb089656cda3b5755641481f59c87f80cf8c",
  // "0x45f1e75db47cd2b8b7880cd60339fefaaf453037",
  // "0xad13dceeea174cc3624bbfad01d20ebb5002bfab"
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

