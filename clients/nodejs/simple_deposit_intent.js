import axios from 'axios';
import crypto from 'crypto';

/**
 * Simple deposit intent submission script
 * Makes one call to submit a deposit intent to the MPC network
 */

const SERVER_URL = 'http://localhost:8081';

// Create a sample deposit intent
const depositIntent = {
    source_address: "0x742d35Cc6634C0532925a3b8D5A42DCA0e23e4",
    target_address: "0x742d35Cc6634C0532925a3b8D5A42DCA0e23e4",
    source_chain: "ethereum",
    target_chain: "ethereum",
    amount: 5000000000000, // 1 ETH in wei
    source_token: "ETH",
    target_token: "TICS",
    path: [1, 2, 3, 4],
    transaction_hash: "0x" + crypto.randomBytes(32).toString('hex')
};

console.log('🚀 Submitting deposit intent to MPC network...');
console.log('📋 Deposit Intent:');
console.log(JSON.stringify(depositIntent, null, 2));
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
        console.error('💡 Make sure the MPC node is running on port 8081');
    }

    process.exit(1);
}

console.log('\n🏁 Done!'); 
