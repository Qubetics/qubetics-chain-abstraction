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

import { Wallet, JsonRpcProvider, parseUnits, formatUnits } from 'ethers';

// Configuration
const QUBETICS_RPC_URL = process.env.QUBETICS_RPC_URL || 'https://rpc-testnet.qubetics.work';
const QUBETICS_CHAIN_ID = 9029;
const TICS_AMOUNT = 1000; // Amount in TICS (whole units)
// Note: Standard native EVM tokens use 18 decimals. If TICS uses different decimals, adjust below.
// Based on codebase, TICS may use 10 decimals (10^10 conversion factor), but native tokens typically use 18.
const TICS_DECIMALS = 18; // Standard for native EVM tokens (adjust to 10 if TICS uses 10 decimals)

// Test private key (for testing only - DO NOT use in production)
const TEST_PRIVATE_KEY = '0x93cc7fbc4bfd7fcfd83d11c85ba522f8fa1c03ece1a3b5f1782bc164996844d9';

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

    // Create provider and wallet
    log('🔗 Connecting to Qubetics network...', 'yellow');
    const provider = new JsonRpcProvider(QUBETICS_RPC_URL);
    const wallet = new Wallet(TEST_PRIVATE_KEY, provider);
    
    const senderAddress = await wallet.getAddress();
    log(`👤 Sender address: ${senderAddress}`, 'cyan');

    // Check balance
    log('💵 Checking sender balance...', 'yellow');
    const balance = await provider.getBalance(senderAddress);
    const balanceInTics = formatUnits(balance, TICS_DECIMALS);
    log(`   Balance: ${balanceInTics} TICS`, 'cyan');

    // Calculate amount in smallest units
    // With 18 decimals: 1000 TICS = 1000 * 10^18 = 1000000000000000000000
    // With 10 decimals: 1000 TICS = 1000 * 10^10 = 10000000000000
    const amountInSmallestUnits = parseUnits(TICS_AMOUNT.toString(), TICS_DECIMALS);
    
    if (balance < amountInSmallestUnits) {
      throw new Error(
        `Insufficient balance. Required: ${TICS_AMOUNT} TICS, Available: ${balanceInTics} TICS`
      );
    }

    // Get current gas price and nonce
    log('⛽ Fetching gas price...', 'yellow');
    const feeData = await provider.getFeeData();
    const gasPrice = feeData.gasPrice;
    if (!gasPrice) {
      throw new Error('Failed to fetch gas price');
    }
    log(`   Gas price: ${formatUnits(gasPrice, 'gwei')} Gwei`, 'cyan');

    log('🔢 Fetching nonce...', 'yellow');
    const nonce = await provider.getTransactionCount(senderAddress, 'pending');
    log(`   Nonce: ${nonce}`, 'cyan');

    // Estimate gas
    log('📊 Estimating gas...', 'yellow');
    const gasEstimate = await provider.estimateGas({
      to: recipientAddress,
      value: amountInSmallestUnits,
    });
    log(`   Estimated gas: ${gasEstimate.toString()}`, 'cyan');

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

    log('✍️ Signing transaction...', 'yellow');
    const signedTx = await wallet.signTransaction(tx);
    log(`   Transaction hash: ${signedTx.hash}`, 'cyan');

    log('📤 Broadcasting transaction...', 'yellow');
    const txResponse = await provider.broadcastTransaction(signedTx);
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

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node transfer_tics.js <recipient_address>');
    console.log('');
    console.log('Arguments:');
    console.log('  recipient_address  Ethereum address to receive TICS (required)');
    console.log('');
    console.log('Environment variables:');
    console.log('  QUBETICS_RPC_URL   RPC URL for Qubetics chain (default: https://rpc-testnet.qubetics.work)');
    console.log('');
    console.log('Examples:');
    console.log('  node transfer_tics.js 0x742d35Cc6634C0532925a3b8D5A42DCA0e23e4');
    console.log('');
    console.log('⚠️  WARNING: This script uses a hardcoded test private key.');
    console.log('   DO NOT use this script in production or with real funds.');
    process.exit(1);
  }

  const recipientAddress = args[0];

  try {
    await transferTics(recipientAddress);
    log('\n🎉 Transfer completed successfully!', 'green');
  } catch (error) {
    log('\n💥 Transfer failed!', 'red');
    process.exit(1);
  }
}

main().catch((error) => {
  log(`\n💥 Unexpected error: ${error.stack}`, 'red');
  process.exit(1);
});

