#!/usr/bin/env node

import { ethers } from 'ethers';
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
const AMOUNT = process.env.AMOUNT || "200";

// 10 Funding wallets for parallel transfers
const FUNDING_WALLETS = [
  { privateKey: "0x53e64f03dc3336ce06749693028a60d01ad0479f75142678344e0556ea59bd46", address: "0x66A4F21e9860345947F979301eeea9E18B042fe8" },
  { privateKey: "0x42dd603deedf2a729dea718390304b4671ba2225466d346b8c5b06f359d53995", address: "0xB99c840d956B37C4fC8FFDa6AAf0197C5d4967F3" },
  { privateKey: "0xab6f78e9ab0724a953fba852a1543401956147f039583c5d045b6e5b401a6a0d", address: "0xa62190D7d91C674E45a2dd889b0F3522D5389ba0" },
  { privateKey: "0x815a7dbbdf1f38f71f76c542582b5c65486bccf2c6884c41cce792be0157044f", address: "0xf4c71F0A2b9425FEE13F70a2D73Fa87918dC7F85" },
  { privateKey: "0xff8a50d5efd3f8f09c77c3b6145d0b04f5309933dcfc3aa49068e638fddab4cf", address: "0x182cACC0C15Fd91e935e34aBD9C64b1b3F8C02E6" },
  { privateKey: "0xc4905cf832bb472102948cac2667d381c535ae5f1048a6ddd7805c8f8d3af819", address: "0x1f0D40AB8a0B0fA17FBD25b2374A21B41ED6Fc53" },
  { privateKey: "0xbe6df6a7402a9200293060ee91eb6262c9e52da39c1bc6409234f04cb859a5be", address: "0x7898790087144F9039b5bB55D608DDF011c1047b" },
  { privateKey: "0x0fec61c57762b4eea7c4a70ba50a03434219671a19bdff6de55f56cb7ffbe8e1", address: "0x93ef2e14B28d1BaF4D8625705209e375D326fF0f" },
  { privateKey: "0x2181715bfc16742f2fc71e7576532049d34401f25e55d22752160698eb5f2129", address: "0x02C11316f7212544A3C87F716d7455b6E6bb0253" },
  { privateKey: "0x5dc6f05dbc7174a338f24fccd4e72f4809194b62b0277d3c3a5d157f8bc7e85a", address: "0x8ce50E03753f78218ECCe0F158874018c92c2d2e" }
];

// Master funding wallet (to fund the 10 parallel wallets)
const MASTER_FUNDING_KEY = '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e';

// Load addresses from registered_eth_addresses.json
const REGISTERED_ADDRESSES_FILE = path.join(__dirname, 'registered_eth_addresses.json');
let ADDRESSES = [];

try {
  const data = fs.readFileSync(REGISTERED_ADDRESSES_FILE, 'utf8');
  const registered = JSON.parse(data);
  ADDRESSES = registered.map(entry => entry.derivedEthAddress).filter(addr => addr);
  console.log(`✅ Loaded ${ADDRESSES.length} derived Ethereum addresses from ${REGISTERED_ADDRESSES_FILE}`);
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
  magenta: '\x1b[35m',
  bright: '\x1b[1m'
};

function log(msg, color = 'reset') {
  console.log(`${colors[color]}${msg}${colors.reset}`);
}

// Fund the 10 parallel wallets from master wallet
async function fundParallelWallets(provider, masterWallet, amountPerWallet) {
  log('', 'reset');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('💰 STEP 1: Funding parallel wallets from master', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('');

  const masterBalance = await provider.getBalance(masterWallet.address);
  log(`📊 Master wallet balance: ${ethers.utils.formatEther(masterBalance)} TICS`, 'cyan');

  for (let i = 0; i < FUNDING_WALLETS.length; i++) {
    const wallet = FUNDING_WALLETS[i];
    const balance = await provider.getBalance(wallet.address);

    if (balance.gte(amountPerWallet)) {
      log(`✅ Wallet ${i + 1} (${wallet.address.slice(0, 10)}...) already has ${ethers.utils.formatEther(balance)} TICS`, 'green');
      continue;
    }

    const needed = amountPerWallet.sub(balance);
    log(`💸 Funding wallet ${i + 1} (${wallet.address.slice(0, 10)}...) with ${ethers.utils.formatEther(needed)} TICS...`, 'cyan');

    try {
      const tx = await masterWallet.sendTransaction({
        to: wallet.address,
        value: needed,
        gasLimit: 21000,
      });
      await tx.wait();
      log(`  ✅ Funded (tx: ${tx.hash.slice(0, 20)}...)`, 'green');
    } catch (error) {
      log(`  ❌ Error funding wallet ${i + 1}: ${error.message}`, 'red');
    }
  }

  log('');
}

// Fund a batch of addresses from a single wallet
async function fundBatch(walletIndex, wallet, addresses, amount, provider) {
  const results = { success: 0, failed: 0 };

  for (let i = 0; i < addresses.length; i++) {
    const addr = addresses[i];
    try {
      const tx = await wallet.sendTransaction({
        to: addr,
        value: amount,
        gasLimit: 21000,
      });

      const receipt = await tx.wait();

      if (receipt.status === 1) {
        log(`  [W${walletIndex + 1}] ✅ ${addr.slice(0, 10)}... (block ${receipt.blockNumber})`, 'green');
        results.success++;
      } else {
        log(`  [W${walletIndex + 1}] ❌ ${addr.slice(0, 10)}... (reverted)`, 'red');
        results.failed++;
      }
    } catch (error) {
      log(`  [W${walletIndex + 1}] ❌ ${addr.slice(0, 10)}... (${error.message.slice(0, 50)})`, 'red');
      results.failed++;
    }
  }

  return results;
}

async function main() {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('💰 PARALLEL FUNDING - 10 WALLETS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('');

  try {
    // Create provider and get chain ID
    const tempProvider = new ethers.providers.JsonRpcProvider(RPC_URL);
    log('🔍 Fetching chain ID from network...', 'cyan');
    const network = await tempProvider.getNetwork();
    log(`📡 Chain ID: ${network.chainId}`, 'cyan');
    log('');

    const provider = new ethers.providers.StaticJsonRpcProvider(RPC_URL, network);

    // Create master wallet
    const masterWallet = new ethers.Wallet(
      MASTER_FUNDING_KEY.startsWith('0x') ? MASTER_FUNDING_KEY : `0x${MASTER_FUNDING_KEY}`,
      provider
    );

    log(`🔗 RPC: ${RPC_URL}`, 'cyan');
    log(`💼 Master wallet: ${masterWallet.address}`, 'cyan');
    log(`💵 Amount per address: ${AMOUNT} TICS`, 'cyan');
    log(`📊 Target addresses: ${ADDRESSES.length}`, 'cyan');
    log(`🔧 Parallel wallets: ${FUNDING_WALLETS.length}`, 'cyan');
    log('');

    const amountWei = ethers.utils.parseEther(AMOUNT);

    // Split addresses evenly across 10 wallets
    const addressesPerWallet = Math.ceil(ADDRESSES.length / FUNDING_WALLETS.length);
    const addressBatches = [];
    for (let i = 0; i < FUNDING_WALLETS.length; i++) {
      const start = i * addressesPerWallet;
      const end = Math.min(start + addressesPerWallet, ADDRESSES.length);
      if (start < ADDRESSES.length) {
        addressBatches.push(ADDRESSES.slice(start, end));
      }
    }

    log(`📋 Address distribution:`, 'cyan');
    for (let i = 0; i < addressBatches.length; i++) {
      log(`   Wallet ${i + 1}: ${addressBatches[i].length} addresses`, 'cyan');
    }
    log('');

    // Calculate how much each parallel wallet needs
    const maxAddressesPerWallet = Math.max(...addressBatches.map(b => b.length));
    const amountPerParallelWallet = amountWei.mul(maxAddressesPerWallet).add(ethers.utils.parseEther("1")); // +1 TICS buffer for gas

    // Fund the parallel wallets
    await fundParallelWallets(provider, masterWallet, amountPerParallelWallet);

    // Create wallet instances
    const wallets = FUNDING_WALLETS.map(w => new ethers.Wallet(w.privateKey, provider));

    // Show parallel wallet balances
    log('═══════════════════════════════════════════════════════════', 'bright');
    log('💰 STEP 2: Parallel funding to target addresses', 'bright');
    log('═══════════════════════════════════════════════════════════', 'bright');
    log('');

    log('📊 Parallel wallet balances:', 'cyan');
    for (let i = 0; i < wallets.length; i++) {
      const balance = await provider.getBalance(wallets[i].address);
      log(`   Wallet ${i + 1}: ${ethers.utils.formatEther(balance)} TICS`, 'cyan');
    }
    log('');

    // Fund all batches in parallel
    log('💸 Starting parallel funding...', 'magenta');
    log('');

    const startTime = Date.now();

    const fundingPromises = addressBatches.map((batch, index) =>
      fundBatch(index, wallets[index], batch, amountWei, provider)
    );

    const results = await Promise.all(fundingPromises);

    const endTime = Date.now();
    const durationSec = ((endTime - startTime) / 1000).toFixed(1);

    // Aggregate results
    const totalSuccess = results.reduce((sum, r) => sum + r.success, 0);
    const totalFailed = results.reduce((sum, r) => sum + r.failed, 0);

    log('');
    log('═══════════════════════════════════════════════════════════', 'bright');
    log(`✅ COMPLETE: ${totalSuccess}/${ADDRESSES.length} addresses funded`, totalSuccess === ADDRESSES.length ? 'green' : 'yellow');
    log(`⏱️  Duration: ${durationSec} seconds`, 'cyan');
    if (totalFailed > 0) {
      log(`❌ Failed: ${totalFailed}`, 'red');
    }
    log('═══════════════════════════════════════════════════════════', 'bright');

  } catch (error) {
    log('', 'reset');
    log(`💥 Error: ${error.message}`, 'red');
    console.error(error);
    process.exit(1);
  }
}

main();
