import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';
import axios from 'axios';
import https from 'https';

const ECPair = ECPairFactory(ecc);

// Create axios instance with SSL verification disabled
const api = axios.create({
    httpsAgent: new https.Agent({
        rejectUnauthorized: false
    })
});

// Configuration
const CONFIG = {
    network: bitcoin.networks.testnet,
    targetAddress: 'mgZAXKuNoAN5SwPruw6HoyHaSHh1w8LFRg',
    privateKeyWIF: process.env.CONFIG_1_PRIVATE_KEY_WIF,
    rpcEndpoint: 'https://blockstream.info/testnet/api',
    amountPerTx: 1000, // satoshis
    numberOfTx: 3,
    delayBetweenTx: 2000 // 2 seconds delay between transactions
};

/**
 * Fetch UTXOs for a given address
 */
async function getUTXOs(address) {
    try {
        const response = await api.get(`${CONFIG.rpcEndpoint}/address/${address}/utxo`, {
            headers: { 'Accept': 'application/json' }
        });
        const utxos = response.data;

        console.log(`   DEBUG: Response type: ${typeof utxos}, isArray: ${Array.isArray(utxos)}`);
        if (Array.isArray(utxos)) {
            console.log(`   DEBUG: UTXO count: ${utxos.length}`);
        } else {
            console.log(`   DEBUG: Response sample: ${JSON.stringify(utxos).substring(0, 200)}`);
        }

        // Validate response - sometimes returns HTML for empty addresses
        if (!Array.isArray(utxos)) {
            return [];
        }

        return utxos;
    } catch (error) {
        if (error.response?.status === 404 || error.response?.headers['content-type']?.includes('html')) {
            // Address not found or has no transactions
            return [];
        }
        throw new Error(`Failed to fetch UTXOs: ${error.message}`);
    }
}

/**
 * Broadcast a transaction
 */
async function broadcastTransaction(txHex) {
    try {
        const response = await api.post(`${CONFIG.rpcEndpoint}/tx`, txHex, {
            headers: { 'Content-Type': 'text/plain' }
        });
        return response.data;
    } catch (error) {
        throw new Error(`Failed to broadcast transaction: ${error.message}`);
    }
}

/**
 * Create and send a single transaction
 */
async function sendTransaction(keyPair, fromAddress, toAddress, amount, utxos) {
    const psbt = new bitcoin.Psbt({ network: CONFIG.network });

    // Calculate required amount (amount + estimated fee)
    const estimatedFee = 1000; // Conservative estimate - 1000 sats
    const requiredAmount = amount + estimatedFee;

    // Select UTXOs
    let totalInput = 0;
    const selectedUtxos = [];

    for (const utxo of utxos) {
        if (totalInput >= requiredAmount) break;

        selectedUtxos.push(utxo);
        totalInput += utxo.value;

        // For SegWit (P2WPKH), we use witnessUtxo instead of nonWitnessUtxo
        psbt.addInput({
            hash: utxo.txid,
            index: utxo.vout,
            witnessUtxo: {
                script: Buffer.from('0014' + Buffer.from(bitcoin.crypto.hash160(keyPair.publicKey)).toString('hex'), 'hex'),
                value: utxo.value
            }
        });
    }

    if (totalInput < requiredAmount) {
        throw new Error(`Insufficient funds. Have ${totalInput} sats, need ${requiredAmount} sats`);
    }

    // Add output for recipient
    psbt.addOutput({
        address: toAddress,
        value: amount
    });

    // Add change output if needed
    const change = totalInput - amount - estimatedFee;
    if (change > 546) { // Dust threshold
        psbt.addOutput({
            address: fromAddress,
            value: change
        });
    }

    // Sign all inputs
    selectedUtxos.forEach((_, index) => {
        psbt.signInput(index, keyPair);
    });

    // Finalize and extract transaction
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();

    // Broadcast transaction
    const txid = await broadcastTransaction(txHex);

    return {
        txid,
        amount,
        fee: estimatedFee,
        change
    };
}

/**
 * Main function to send funds multiple times
 */
async function main() {
    console.log('🚀 Starting Bitcoin Testnet3 Fund Transfer Script\n');
    console.log(`Target Address: ${CONFIG.targetAddress}`);
    console.log(`Amount per transaction: ${CONFIG.amountPerTx} satoshis`);
    console.log(`Number of transactions: ${CONFIG.numberOfTx}`);
    console.log(`Total to send: ${CONFIG.amountPerTx * CONFIG.numberOfTx} satoshis\n`);

    // Validate configuration
    if (CONFIG.targetAddress === 'YOUR_TARGET_ADDRESS_HERE' ||
        CONFIG.privateKeyWIF === 'YOUR_PRIVATE_KEY_WIF_HERE') {
        throw new Error('Please configure TARGET_ADDRESS and PRIVATE_KEY_WIF in the script');
    }

    // Initialize key pair
    const keyPair = ECPair.fromWIF(CONFIG.privateKeyWIF, CONFIG.network);
    const wrappedKeyPair = {
        publicKey: Buffer.from(keyPair.publicKey),
        sign: (hash) => Buffer.from(keyPair.sign(hash))
    };
    const { address: fromAddress } = bitcoin.payments.p2wpkh({
        pubkey: wrappedKeyPair.publicKey,
        network: CONFIG.network
    });

    console.log(`Sending from address: ${fromAddress}\n`);

    const results = [];

    // Send transactions
    for (let i = 1; i <= CONFIG.numberOfTx; i++) {
        try {
            console.log(`📤 Sending transaction ${i}/${CONFIG.numberOfTx}...`);

            // Fetch latest UTXOs
            const utxos = await getUTXOs(fromAddress);

            if (utxos.length === 0) {
                throw new Error('No UTXOs available');
            }

            // Send transaction
            const result = await sendTransaction(
                wrappedKeyPair,
                fromAddress,
                CONFIG.targetAddress,
                CONFIG.amountPerTx,
                utxos
            );

            console.log(`✅ Transaction ${i} successful!`);
            console.log(`   TXID: ${result.txid}`);
            console.log(`   Amount: ${result.amount} sats`);
            console.log(`   Fee: ${result.fee} sats`);
            console.log(`   Change: ${result.change} sats\n`);

            results.push({
                index: i,
                ...result
            });

            // Wait before sending next transaction (except for the last one)
            if (i < CONFIG.numberOfTx) {
                console.log(`⏳ Waiting ${CONFIG.delayBetweenTx / 1000} seconds before next transaction...\n`);
                await new Promise(resolve => setTimeout(resolve, CONFIG.delayBetweenTx));
            }

        } catch (error) {
            console.error(`❌ Transaction ${i} failed: ${error.message}\n`);

            // Ask if user wants to continue
            console.log('Stopping script due to error.');
            break;
        }
    }

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total transactions sent: ${results.length}/${CONFIG.numberOfTx}`);
    console.log(`Total amount sent: ${results.reduce((sum, r) => sum + r.amount, 0)} satoshis`);
    console.log(`Total fees paid: ${results.reduce((sum, r) => sum + r.fee, 0)} satoshis`);
    console.log('\nTransaction IDs:');
    results.forEach(r => {
        console.log(`  ${r.index}. ${r.txid}`);
    });
    console.log('='.repeat(60));
}

// Run the script
main().catch(error => {
    console.error('❌ Script failed:', error.message);
    process.exit(1);
});
