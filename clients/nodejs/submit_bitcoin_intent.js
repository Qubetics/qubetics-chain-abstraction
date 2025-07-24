const axios = require('axios');

const RPC_SERVER = 'http://localhost:8082';

async function submitBitcoinIntent() {
    console.log('🚀 Bitcoin Intent Submission Tool');
    console.log('===============================');
    console.log(`RPC Server: ${RPC_SERVER}`);
    console.log('Intent Type: bitcoin\n');

    const bitcoinIntent = {
        source_address: "tb1qc6fq9zd8m5sc0nhckpunz2aqc5n95k3udmk28r",
        target_address: "tb1qc6fq9zd8m5sc0nhckpunz2aqc5n95k3udmk28r",
        source_chain: "bitcoin",
        target_chain: "bitcoin",
        amount: 1000, // 1000 sats
        source_token: "BTC",
        target_token: "BTC",
        path: [],
        transaction_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    };

    console.log('📤 Submitting Bitcoin intent...');
    console.log('Intent data:', JSON.stringify(bitcoinIntent, null, 2));

    try {
        const response = await axios.post(`${RPC_SERVER}/submit_intent`, bitcoinIntent, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        console.log('✅ Bitcoin intent submitted successfully!');
        console.log('Response:', response.data);
    } catch (error) {
        console.error('❌ Failed to submit Bitcoin intent:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        console.error('❌ Bitcoin intent submission failed');
    }
}

// Run the Bitcoin intent submission
submitBitcoinIntent(); 