import axios from 'axios';

const RPC_SERVER = 'http://0.0.0.0:8082';

// Function to submit an intent
// Note: This function now waits for the transaction hash to be generated
// The server will wait up to 2 minutes before timing out
async function submitIntent(intent) {
    try {
        console.log('📤 Submitting intent...');
        console.log('⏳ Note: The server will wait for transaction hash generation (up to 2 minutes)');
        console.log('Intent data:', JSON.stringify(intent, null, 2));

        const response = await axios.post(`${RPC_SERVER}/submit_intent`, intent, {
            headers: { 'Content-Type': 'application/json' }
        });

        console.log('✅ Intent submitted successfully!');
        console.log('Response:', response.data);
        
        // Log specific response fields
        if (response.data.solver_id) {
            console.log('🏆 Solver ID:', response.data.solver_id);
        }
        if (response.data.transaction_hash) {
            console.log('💿 Transaction hash:', response.data.transaction_hash);
        }
        
        return response.data;
    } catch (error) {
        console.error('❌ Failed to submit intent:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        throw error;
    }
}

// Example intents
const exampleIntents = {
    // Ethereum transfer
    qubetics: {
        source_address: "tb1q2nd0utgnrseanclhq2tr7hqhqtuc389mmjm2fs",
        target_address: "0x1bacaEcC83Ed515B77A8d39f24e46e05c8bBC920",
        source_chain: "btc",
        target_chain: "sepolia",
        amount: 4200, // 1 ETH
        source_token: "btc",
        target_token: "usdc",
        path: [],
        transaction_hash: "0x1xxxxxxxcxabcxex12345678xxxxdef1234567asdrabcdkasgdk567890abcdew"

     
    },
    sepolia: {
        source_address: "tb1q2nd0utgnrseanclhq2tr7hqhqtuc389mmjm2fs",
        target_address: "0x5e3146991C52450bACf3c216B8C4Ab30C3795303",
        source_chain: "btc",
        target_chain: "sepolia",
        amount: 420, // 1 ETH
        source_token: "btc",
        target_token: "usdc",
        path: [],
        transaction_hash: "0x1x3456x8cxabcxex1234567890abcdef1234567890abcdef1234567890abcdew"

     
    },

    // Bitcoin transfer
    bitcoin: {
        source_address: "0xceb5057834CB4EdE0E59F9e91046B8cB96C72e9C",
        target_address: "tb1q2nd0utgnrseanclhq2tr7hqhqtuc389mmjm2fs",
        source_chain: "tics",
        target_chain: "bitcoin",
        amount: 800, 
        source_token: "usdc",
        target_token: "BTC",
        path: [],
        transaction_hash: "0xabcdef1234567890abcdxf1234567890abcdef1234567890abcdef1234567890"
    },

    // Cross-chain transfer
    crossChain: {
        source_address: "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
        target_address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        source_chain: "ethereum",
        target_chain: "bitcoin",
        amount: 500000000000000000, // 0.5 ETH (as number)
        source_token: "ETH",
        target_token: "BTC",
        path: [1, 2, 3, 4, 5, 6, 7, 8],
        transaction_hash: "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
    }
};

// Main function
async function main() {
    const args = process.argv.slice(2);
    const intentType = args[0] || 'qubetics';

    console.log('🚀 Intent Submission Tool');
    console.log('========================');
    console.log(`RPC Server: ${RPC_SERVER}`);
    console.log(`Intent Type: ${intentType}`);
    console.log('');

    if (!exampleIntents[intentType]) {
        console.error(`❌ Unknown intent type: ${intentType}`);
        console.log('Available types:', Object.keys(exampleIntents).join(', '));
        process.exit(1);
    }

    try {
        await submitIntent(exampleIntents[intentType]);
    } catch (error) {
        console.error('❌ Intent submission failed');
        process.exit(1);
    }
}

// Export for use in other modules
export { submitIntent, exampleIntents };

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main();
} 
