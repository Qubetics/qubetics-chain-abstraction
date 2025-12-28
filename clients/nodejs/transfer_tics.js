#!/usr/bin/env node

/**
 * Script to transfer 1000 TICS to a provided address
 * Usage: node transfer_tics.js <recipient_address>
 * 
 * Environment variables:
 *   - QUBETICS_RPC_URL: RPC URL for Qubetics chain (default: https://rpc-testnet.qubetics.work)
 * 
 * NOTE: This script contains a hardcoded test private key for testing purposes only.
 * DO NOT use this script in production or with real funds.
 */

// Disable SSL verification for testnet with self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ethers v5 is CommonJS; use default import for ESM compatibility
import ethers from 'ethers';
const { Wallet, providers, utils } = ethers;
const { JsonRpcProvider, StaticJsonRpcProvider } = providers;
const { parseUnits, formatUnits } = utils;

// Configuration
const QUBETICS_RPC_URL = 'https://rpc-testnet.qubetics.work';
const QUBETICS_CHAIN_ID = 9029;
const TICS_AMOUNT = 100; // Amount in TICS (whole units)
// TICS uses 10 decimals on this chain; adjust if your deployment differs.
const TICS_DECIMALS = 18;

// Test private key (for testing only - DO NOT use in production)
const TEST_PRIVATE_KEY = '0x2f1765e04f0a5c394eb3b07ee38bf210008473f6e679a4f901f554905f7f3f89';

// Colors for console output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function validateAddress(address) {
  if (!address || !address.startsWith('0x') || address.length !== 42) {
    throw new Error('Invalid Ethereum address format. Must be 0x followed by 40 hex characters.');
  }
  return true;
}

async function transferTics(recipientAddress) {
  try {
    log('🚀 Starting TICS transfer...', 'blue');
    log(`📍 Recipient address: ${recipientAddress}`, 'cyan');
    log(`💰 Amount: ${TICS_AMOUNT} TICS`, 'cyan');
    log(`🌐 RPC URL: ${QUBETICS_RPC_URL}`, 'cyan');
    log('⚠️  Using hardcoded test private key (testing only)', 'yellow');
    log('', 'reset');

    // Validate inputs
    validateAddress(recipientAddress);

    // Create provider and wallet with explicit network configuration
    log('🔗 Connecting to Qubetics network...', 'yellow');
    // Use StaticJsonRpcProvider with explicit network to avoid auto-detection issues
    const network = {
      chainId: QUBETICS_CHAIN_ID,
      name: 'Qubetics Testnet',
    };
    const provider = new StaticJsonRpcProvider(QUBETICS_RPC_URL, network);
    const wallet = new Wallet(TEST_PRIVATE_KEY, provider);

    const senderAddress = await wallet.getAddress();
    log(`👤 Sender address: ${senderAddress}`, 'cyan');

    // Check balance with retry logic
    log('💵 Checking sender balance...', 'yellow');
    let balance;
    {
      let retries = 3;
      while (retries > 0) {
        try {
          balance = await provider.getBalance(senderAddress);
          break;
        } catch (error) {
          retries--;
          if (error.code === -32000 || error.message?.includes('cannot allocate memory')) {
            log(`   ⚠️ RPC memory error, retrying... (${3 - retries}/3)`, 'yellow');
            if (retries > 0) {
              await new Promise(resolve => setTimeout(resolve, 2000 * (4 - retries))); // Exponential backoff
              continue;
            }
          }
          throw error;
        }
      }
    }
    const balanceInTics = formatUnits(balance, TICS_DECIMALS);
    log(`   Balance: ${balanceInTics} TICS`, 'cyan');

    // Calculate amount in smallest units
    // With 18 decimals: 1000 TICS = 1000 * 10^18 = 1000000000000000000000
    // With 10 decimals: 1000 TICS = 1000 * 10^10 = 10000000000000
    const amountInSmallestUnits = parseUnits(TICS_AMOUNT.toString(), TICS_DECIMALS);
    log(`   Amount (raw units): ${amountInSmallestUnits.toString()}`, 'cyan');

    if (balance < amountInSmallestUnits) {
      throw new Error(
        `Insufficient balance. Required: ${TICS_AMOUNT} TICS, Available: ${balanceInTics} TICS`
      );
    }

    // Get current gas price with retry logic
    log('⛽ Fetching gas price...', 'yellow');
    let feeData;
    {
      let retries = 3;
      while (retries > 0) {
        try {
          feeData = await provider.getFeeData();
          break;
        } catch (error) {
          retries--;
          if (error.code === -32000 || error.message?.includes('cannot allocate memory')) {
            log(`   ⚠️ RPC memory error, retrying... (${3 - retries}/3)`, 'yellow');
            if (retries > 0) {
              await new Promise(resolve => setTimeout(resolve, 2000 * (4 - retries))); // Exponential backoff
              continue;
            }
          }
          throw error;
        }
      }
    }
    
    let gasPrice = feeData.gasPrice;
    // Fallback: if RPC returns null/0 or too low, use 1 gwei
    if (!gasPrice || gasPrice.lte(0) || gasPrice.lt(parseUnits('1', 'gwei'))) {
      gasPrice = parseUnits('1', 'gwei');
      log('   ⚠️ Gas price missing/too low from RPC; using fallback 1 gwei', 'yellow');
    }
    log(`   Gas price: ${formatUnits(gasPrice, 'gwei')} Gwei`, 'cyan');

    log('🔢 Fetching nonce...', 'yellow');
    // Use 'latest' instead of 'pending' to reduce RPC node memory pressure
    // 'pending' requires loading more state which can cause memory errors
    let nonce;
    {
      let retries = 3;
      while (retries > 0) {
        try {
          nonce = await provider.getTransactionCount(senderAddress, 'latest');
          log(`   Nonce: ${nonce}`, 'cyan');
          break;
        } catch (error) {
          retries--;
          if (error.code === -32000 || error.message?.includes('cannot allocate memory')) {
            log(`   ⚠️ RPC memory error, retrying... (${3 - retries}/3)`, 'yellow');
            if (retries > 0) {
              await new Promise(resolve => setTimeout(resolve, 2000 * (4 - retries))); // Exponential backoff
              continue;
            }
          }
          throw error;
        }
      }
    }

    // Estimate gas
    log('📊 Estimating gas...', 'yellow');
    let gasEstimate;
    try {
      gasEstimate = await provider.estimateGas({
        to: recipientAddress,
        value: amountInSmallestUnits,
      });
      log(`   Estimated gas: ${gasEstimate.toString()}`, 'cyan');
    } catch (estimateError) {
      gasEstimate = 21_000n;
      const msg = estimateError && estimateError.message ? estimateError.message : 'unknown error';
      log(
        `   ⚠️ Gas estimation failed (${msg}). Falling back to 21,000.`,
        'yellow'
      );
    }

    // Create transaction
    log('📝 Creating transaction...', 'yellow');
    const tx = {
      to: recipientAddress,
      value: amountInSmallestUnits,
      gasLimit: gasEstimate,
      gasPrice: gasPrice,
      nonce: nonce,
      chainId: QUBETICS_CHAIN_ID,
    };

    log('📤 Sending transaction...', 'yellow');
    const txResponse = await wallet.sendTransaction(tx);
    log(`   Transaction hash: ${txResponse.hash}`, 'green');
    log(`   Explorer: https://explorer.qubetics.work/tx/${txResponse.hash}`, 'cyan');

    log('⏳ Waiting for confirmation...', 'yellow');
    const receipt = await txResponse.wait();

    if (receipt.status === 1) {
      log('✅ Transaction confirmed!', 'green');
      log(`   Block number: ${receipt.blockNumber}`, 'cyan');
      log(`   Gas used: ${receipt.gasUsed.toString()}`, 'cyan');
      log(`   Transaction hash: ${receipt.hash}`, 'green');
    } else {
      log('❌ Transaction failed!', 'red');
      log(`   Transaction hash: ${receipt.hash}`, 'red');
    }

    return {
      success: receipt.status === 1,
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed.toString(),
    };
  } catch (error) {
    log(`❌ Error: ${error.message}`, 'red');
    if (error.error) {
      log(`   Details: ${JSON.stringify(error.error, null, 2)}`, 'red');
    }
    throw error;
  }
}

async function transferSequentially(addresses) {
  for (const [index, addr] of addresses.entries()) {
    log(`\n===== 🎯 Transfer ${index + 1} of ${addresses.length} =====`, 'blue');
    try {
      await transferTics(addr);
      log(`🎉 Transfer ${index + 1} succeeded!`, 'green');
    } catch (error) {
      log(`💥 Transfer ${index + 1} failed!`, 'red');
      throw error;
    }
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node transfer_tics.js <recipient_address> [recipient_address2] [recipient_address3]');
    console.log('');
    console.log('Arguments:');
    console.log('  recipient_address   Ethereum address to receive TICS (required, up to 3 addresses supported)');
    console.log('');
    console.log('Environment variables:');
    console.log('  QUBETICS_RPC_URL    RPC URL for Qubetics chain (default: https://rpc-testnet.qubetics.work)');
    console.log('');
    console.log('Examples:');
    console.log('  node transfer_tics.js 0x742d35Cc6634C0532925a3b8D5A42DCA0e23e4');
    console.log('  node transfer_tics.js 0x742d...e4 0xDeaD...Beef');
    console.log('  node transfer_tics.js 0x742d...e4 0xDeaD...Beef 0xCafe...Babe');
    console.log('');
    console.log('⚠️  WARNING: This script uses a hardcoded test private key.');
    console.log('   DO NOT use this script in production or with real funds.');
    process.exit(1);
  }

  if (args.length > 3) {
    console.log('⚠️  Only up to 3 recipient addresses are supported per run.');
    process.exit(1);
  }

  try {
    await transferSequentially(args);
    log('\n🎉 All transfers completed successfully!', 'green');
  } catch (error) {
    log('\n💥 One or more transfers failed!', 'red');
    process.exit(1);
  }
}

main().catch((error) => {
  log(`\n💥 Unexpected error: ${error.stack}`, 'red');
  process.exit(1);
});

