#!/usr/bin/env node

/**
 * BTC Testnet Transfer Script
 *
 * Transfers BTC from one address to another on testnet3.
 *
 * Usage:
 *   node transfer_btc.js
 *
 * Environment Variables:
 *   BTC_PRIVATE_KEY - WIF format private key of the sender
 *   BTC_TO_ADDRESS  - Recipient address
 *   BTC_AMOUNT_SATS - Amount to send in satoshis
 *   BTC_FEE_RATE    - Fee rate in sat/vB (default: 2)
 *
 * Example:
 *   BTC_PRIVATE_KEY=cNx... BTC_TO_ADDRESS=tb1q... BTC_AMOUNT_SATS=10000 node transfer_btc.js
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';
import https from 'https';

// Initialize ECPair with secp256k1
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

// Testnet network
const network = bitcoin.networks.testnet;

// Configuration from environment
const PRIVATE_KEY_WIF = process.env.BTC_PRIVATE_KEY;
const TO_ADDRESS = process.env.BTC_TO_ADDRESS;
const AMOUNT_SATS = parseInt(process.env.BTC_AMOUNT_SATS || '10000', 10);
const FEE_RATE = parseInt(process.env.BTC_FEE_RATE || '2', 10);

const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
};

/**
 * Fetch UTXOs for an address from blockstream API
 */
async function fetchUTXOs(address) {
  return new Promise((resolve, reject) => {
    const url = `https://blockstream.info/testnet/api/address/${address}/utxo`;

    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const utxos = JSON.parse(data);
          resolve(utxos);
        } catch (e) {
          reject(new Error(`Failed to parse UTXOs: ${e.message}`));
        }
      });
    }).on('error', reject);
  });
}

/**
 * Fetch raw transaction hex
 */
async function fetchRawTx(txid) {
  return new Promise((resolve, reject) => {
    const url = `https://blockstream.info/testnet/api/tx/${txid}/hex`;

    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data.trim()));
    }).on('error', reject);
  });
}

/**
 * Broadcast transaction to testnet
 */
async function broadcastTx(txHex) {
  return new Promise((resolve, reject) => {
    const url = 'https://blockstream.info/testnet/api/tx';

    const req = https.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength(txHex)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data.trim());
        } else {
          reject(new Error(`Broadcast failed: ${res.statusCode} - ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(txHex);
    req.end();
  });
}

/**
 * Get address from key pair based on address type
 */
function getAddressFromKeyPair(keyPair, addressType = 'p2wpkh') {
  if (addressType === 'p2wpkh') {
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: keyPair.publicKey,
      network
    });
    return address;
  } else if (addressType === 'p2pkh') {
    const { address } = bitcoin.payments.p2pkh({
      pubkey: keyPair.publicKey,
      network
    });
    return address;
  }
  throw new Error(`Unsupported address type: ${addressType}`);
}

/**
 * Create and sign a BTC transaction
 */
async function createTransaction(keyPair, fromAddress, toAddress, amountSats, feeRate) {
  console.log(`${colors.blue}Fetching UTXOs for ${fromAddress}...${colors.reset}`);

  const utxos = await fetchUTXOs(fromAddress);

  if (!utxos || utxos.length === 0) {
    throw new Error('No UTXOs found for this address');
  }

  console.log(`${colors.green}Found ${utxos.length} UTXOs${colors.reset}`);

  // Sort UTXOs by value (largest first) and filter confirmed
  const confirmedUtxos = utxos
    .filter(u => u.status.confirmed)
    .sort((a, b) => b.value - a.value);

  if (confirmedUtxos.length === 0) {
    throw new Error('No confirmed UTXOs available');
  }

  // Estimate transaction size for fee calculation
  // P2WPKH: ~110 vbytes for 1 input, 1 output + ~31 vbytes per additional output
  const estimatedVbytes = 110 + 31; // 1 input, 2 outputs (recipient + change)
  const estimatedFee = estimatedVbytes * feeRate;

  console.log(`${colors.yellow}Estimated fee: ${estimatedFee} sats (${feeRate} sat/vB)${colors.reset}`);

  // Select UTXOs
  let selectedUtxos = [];
  let totalInput = 0;
  const targetAmount = amountSats + estimatedFee;

  for (const utxo of confirmedUtxos) {
    selectedUtxos.push(utxo);
    totalInput += utxo.value;
    if (totalInput >= targetAmount) break;
  }

  if (totalInput < targetAmount) {
    throw new Error(`Insufficient funds. Need ${targetAmount} sats, have ${totalInput} sats`);
  }

  console.log(`${colors.blue}Selected ${selectedUtxos.length} UTXO(s) with total ${totalInput} sats${colors.reset}`);

  // Create PSBT
  const psbt = new bitcoin.Psbt({ network });

  // Add inputs
  for (const utxo of selectedUtxos) {
    console.log(`${colors.yellow}Adding input: ${utxo.txid}:${utxo.vout}${colors.reset}`);

    // For P2WPKH, we need witnessUtxo
    if (fromAddress.startsWith('tb1q') || fromAddress.startsWith('bc1q')) {
      // Native SegWit (P2WPKH)
      const payment = bitcoin.payments.p2wpkh({
        pubkey: keyPair.publicKey,
        network
      });

      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: {
          script: payment.output,
          value: utxo.value
        }
      });
    } else if (fromAddress.startsWith('m') || fromAddress.startsWith('n') || fromAddress.startsWith('2')) {
      // Legacy (P2PKH) or P2SH - need full raw tx
      const rawTxHex = await fetchRawTx(utxo.txid);
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        nonWitnessUtxo: Buffer.from(rawTxHex, 'hex')
      });
    } else {
      throw new Error(`Unsupported address format: ${fromAddress}`);
    }
  }

  // Add recipient output
  psbt.addOutput({
    address: toAddress,
    value: amountSats
  });

  // Calculate change
  const change = totalInput - amountSats - estimatedFee;

  if (change > 546) { // Dust threshold
    console.log(`${colors.blue}Adding change output: ${change} sats${colors.reset}`);
    psbt.addOutput({
      address: fromAddress,
      value: change
    });
  } else if (change > 0) {
    console.log(`${colors.yellow}Change ${change} sats is below dust threshold, adding to fee${colors.reset}`);
  }

  // Sign all inputs
  console.log(`${colors.blue}Signing transaction...${colors.reset}`);
  for (let i = 0; i < selectedUtxos.length; i++) {
    psbt.signInput(i, keyPair);
  }

  // Finalize and extract
  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();

  return {
    txHex: tx.toHex(),
    txid: tx.getId(),
    fee: estimatedFee,
    change: change > 546 ? change : 0
  };
}

async function main() {
  console.log(`\n${colors.blue}=== BTC Testnet Transfer ===${colors.reset}\n`);

  // Validate inputs
  if (!PRIVATE_KEY_WIF) {
    console.error(`${colors.red}Error: BTC_PRIVATE_KEY environment variable is required${colors.reset}`);
    console.log(`\nUsage:`);
    console.log(`  BTC_PRIVATE_KEY=<wif> BTC_TO_ADDRESS=<address> BTC_AMOUNT_SATS=<amount> node transfer_btc.js`);
    process.exit(1);
  }

  if (!TO_ADDRESS) {
    console.error(`${colors.red}Error: BTC_TO_ADDRESS environment variable is required${colors.reset}`);
    process.exit(1);
  }

  try {
    // Parse private key
    const keyPair = ECPair.fromWIF(PRIVATE_KEY_WIF, network);

    // Determine from address (assuming P2WPKH for tb1q addresses)
    const fromAddress = getAddressFromKeyPair(keyPair, 'p2wpkh');

    console.log(`${colors.green}From Address: ${fromAddress}${colors.reset}`);
    console.log(`${colors.green}To Address:   ${TO_ADDRESS}${colors.reset}`);
    console.log(`${colors.green}Amount:       ${AMOUNT_SATS} sats (${AMOUNT_SATS / 100000000} BTC)${colors.reset}`);
    console.log(`${colors.green}Fee Rate:     ${FEE_RATE} sat/vB${colors.reset}`);
    console.log('');

    // Create and sign transaction
    const result = await createTransaction(keyPair, fromAddress, TO_ADDRESS, AMOUNT_SATS, FEE_RATE);

    console.log(`\n${colors.green}Transaction created successfully!${colors.reset}`);
    console.log(`${colors.yellow}TXID: ${result.txid}${colors.reset}`);
    console.log(`${colors.yellow}Fee:  ${result.fee} sats${colors.reset}`);
    console.log(`${colors.yellow}Change: ${result.change} sats${colors.reset}`);

    // Ask for confirmation before broadcasting
    console.log(`\n${colors.blue}Broadcasting transaction...${colors.reset}`);

    const broadcastedTxid = await broadcastTx(result.txHex);

    console.log(`\n${colors.green}Transaction broadcasted successfully!${colors.reset}`);
    console.log(`${colors.green}TXID: ${broadcastedTxid}${colors.reset}`);
    console.log(`${colors.blue}View on explorer: https://mempool.space/testnet/tx/${broadcastedTxid}${colors.reset}`);

  } catch (error) {
    console.error(`\n${colors.red}Error: ${error.message}${colors.reset}`);
    if (error.stack) {
      console.error(`${colors.red}${error.stack}${colors.reset}`);
    }
    process.exit(1);
  }
}

main();
