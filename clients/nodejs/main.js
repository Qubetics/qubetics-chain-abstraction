import axios from 'axios';
import crypto from 'crypto';

/**
 * Main deposit intent submission script
 * Merges functionality from simple_deposit_intent.js and btc_simple_deposit_intent.js
 * Allows users to choose between different deposit intent types
 */

const SERVER_URL = process.env.RPC_BASE_URL || 'http://localhost:8081';

function createBtcToTicsDepositIntent() {
    return {
        source_address: "tb1q2nd0utgnrseanclhq2tr7hqhqtuc389mmjm2fs",
        target_address: "0x541Bc7A7Eb63769c079dc57eF1b9d9651Dd920Af",
        source_chain: "bitcoin",
        target_chain: "qubetics",
        amount: 4000000000000,
        source_token: "BTC",
        target_token: "ETH",
        path: [1, 2, 3, 4],
        transaction_hash: "0x" + crypto.randomBytes(32).toString('hex')
    };
}

function createTicsToBtcDepositIntent() {   
    return {
        source_address: "0x742d35Cc6634C0532925a3b8D5A42DCA0e23e4",
        target_address: "tb1pu4zlkfqy9z3vjjpt8r0c5m59u9jq7495x0sndymp2qr9nql9udgqt9az2q",
        source_chain: "qubetics",
        target_chain: "bitcoin",
        amount: 9110000000000,
        source_token: "TICS",
        target_token: "BTC",
        path: [1, 2, 3, 4],
        transaction_hash: "0x" + crypto.randomBytes(32).toString('hex')
    };
}

// Function to submit deposit intent
async function submitDepositIntent(depositIntent, intentType) {
    console.log(`🚀 Submitting ${intentType} deposit intent to MPC network...`);
    // Avoid logging full deposit intent payload in production
    console.log('\n' + '='.repeat(50));

    try {
        const response = await axios.post(`${SERVER_URL}/deposit_intent`, depositIntent, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 30000 // 30 second timeout
        });

        console.log('✅ SUCCESS! Deposit intent submitted successfully');
        console.log('📄 Server Response:');
        console.log(JSON.stringify(response.data, null, 2));
        console.log('\n🎉 Intent ID:', response.data.intent_id);
        console.log('📊 Status:', response.data.status);
        console.log('💬 Message:', response.data.message);

    } catch (error) {
        console.error('❌ FAILED to submit deposit intent');
        console.error('🔴 Error:', error.message);

        if (error.response) {
            console.error('📄 Server Error Response:', error.response.data);
            console.error('🔢 Status Code:', error.response.status);
        } else if (error.request) {
            console.error('🌐 Network Error: No response received from server');
            console.error(`💡 Make sure the MPC node is running on port ${process.env.RPC_PORT || 8081}`);
        }

        process.exit(1);
    }

    console.log('\n🏁 Done!');
}

// Main execution function
async function main() {
    const args = process.argv.slice(2);
    const command = args[0];

    console.log('🎯 Deposit Intent Submission Tool');
    console.log('================================');

    if (!command) {
        console.log('Usage:');
        console.log('  node main.js eth-eth    - Submit Ethereum → Ethereum deposit intent');
        console.log('  node main.js eth-btc    - Submit Ethereum → Bitcoin deposit intent');
        console.log('  node main.js both       - Submit both types of deposit intents');
        console.log('');
        console.log('Examples:');
        console.log('  node main.js eth-eth');
        console.log('  node main.js eth-btc');
        console.log('  node main.js both');
        process.exit(1);
    }

    switch (command.toLowerCase()) {
        case 'btc-tics':
            console.log('📝 Submitting Ethereum → Ethereum deposit intent...\n');
            const ethToEthIntent = createBtcToTicsDepositIntent();
            await submitDepositIntent(ethToEthIntent, 'Ethereum-to-Ethereum');
            break;

        case 'tics-btc':
            console.log('📝 Submitting Ethereum → Bitcoin deposit intent...\n');
            const ethToBtcIntent = createTicsToBtcDepositIntent();
            await submitDepositIntent(ethToBtcIntent, 'Ethereum-to-Bitcoin');
            break;

        default:
            console.error('❌ Invalid command:', command);
            console.log('');
            console.log('Valid commands:');
            console.log('  eth-eth  - Submit Ethereum → Ethereum deposit intent');
            console.log('  eth-btc  - Submit Ethereum → Bitcoin deposit intent');
            console.log('  both     - Submit both types of deposit intents');
            process.exit(1);
    }
}

// Run the main function
main().catch(console.error); 