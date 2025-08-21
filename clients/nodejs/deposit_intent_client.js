import axios from 'axios';
import crypto from 'crypto';

class DepositIntentClient {
    constructor(nodeUrl = 'http://localhost:8081') {
        this.nodeUrl = nodeUrl;
    }

    /**
     * Submit a deposit intent to the MPC network
     * @param {Object} depositIntent - The deposit intent object
     * @returns {Promise<Object>} Response from the server
     */
    async submitDepositIntent(depositIntent) {
        try {
            console.log('📝 Submitting deposit intent to MPC network...');
            console.log('🎯 Target URL:', `${this.nodeUrl}/deposit_intent`);
            console.log('📋 Intent Details:', JSON.stringify(depositIntent, null, 2));

            const response = await axios.post(`${this.nodeUrl}/deposit_intent`, depositIntent, {
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 30000 // 30 second timeout
            });

            console.log('✅ Deposit intent submitted successfully!');
            console.log('📄 Response:', JSON.stringify(response.data, null, 2));

            return {
                success: true,
                data: response.data,
                status: response.status
            };

        } catch (error) {
            console.error('❌ Failed to submit deposit intent:', error.message);

            if (error.response) {
                console.error('📄 Error response:', error.response.data);
                console.error('🔢 Status code:', error.response.status);
            } else if (error.request) {
                console.error('🌐 Network error - no response received');
            }

            return {
                success: false,
                error: error.message,
                status: error.response?.status || 'NETWORK_ERROR'
            };
        }
    }

    /**
     * Check the status of the MPC node
     * @returns {Promise<Object>} Node status information
     */
    async getNodeStatus() {
        try {
            console.log('📊 Checking node status...');

            const response = await axios.get(`${this.nodeUrl}/status`, {
                timeout: 10000 // 10 second timeout
            });

            console.log('✅ Node status retrieved successfully!');
            console.log('📄 Status:', JSON.stringify(response.data, null, 2));

            return {
                success: true,
                data: response.data,
                status: response.status
            };

        } catch (error) {
            console.error('❌ Failed to get node status:', error.message);

            return {
                success: false,
                error: error.message,
                status: error.response?.status || 'NETWORK_ERROR'
            };
        }
    }

    /**
     * Generate a random transaction hash for testing
     * @returns {string} Random hex transaction hash
     */
    generateRandomTxHash() {
        return '0x' + crypto.randomBytes(32).toString('hex');
    }

    /**
     * Create a sample deposit intent for testing
     * @param {Object} overrides - Optional field overrides
     * @returns {Object} Sample deposit intent
     */
    createSampleIntent(overrides = {}) {
        const defaultIntent = {
            source_address: "0x742d35Cc6634C0532925a3b8D5A42DCA0e33e4",
            target_address: "0x123d35Cc6634C0532925a3b8D5A42DCA0e33e4",
            source_chain: "ethereum",
            target_chain: "qubetics",
            amount: 1000000000000000000, // 1 ETH in wei
            source_token: "ETH",
            target_token: "TICS",
            path: [1, 2, 3, 4],
            transaction_hash: this.generateRandomTxHash()
        };

        return { ...defaultIntent, ...overrides };
    }
}

/**
 * Main test function
 */
async function main() {
    console.log('🧪 === Deposit Intent Client Test ===\n');

    const client = new DepositIntentClient();

    // Test 1: Check node status
    console.log('📊 Test 1: Checking node status...');
    const statusResult = await client.getNodeStatus();

    if (!statusResult.success) {
        console.error('❌ Node is not available. Make sure the MPC node is running on port 8081');
        process.exit(1);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Test 2: Submit sample deposit intent
    console.log('📝 Test 2: Submitting sample deposit intent...');
    const sampleIntent = client.createSampleIntent();
    const submitResult = await client.submitDepositIntent(sampleIntent);

    if (!submitResult.success) {
        console.error('❌ Failed to submit deposit intent');
        process.exit(1);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Test 3: Submit custom deposit intent (different chains)
    console.log('📝 Test 3: Submitting custom deposit intent (BSC to Qubetics)...');
    const customIntent = client.createSampleIntent({
        source_chain: "binance_smart_chain",
        target_chain: "qubetics",
        source_token: "BNB",
        target_token: "TICS",
        amount: 500000000000000000, // 0.5 BNB
        source_address: "0x456d35Cc6634C0532925a3b8D5A42DCA0e44e5",
        target_address: "0x789d35Cc6634C0532925a3b8D5A42DCA0e55e6"
    });

    const customResult = await client.submitDepositIntent(customIntent);

    if (!customResult.success) {
        console.error('❌ Failed to submit custom deposit intent');
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Test 4: Submit rapid deposit intents to test VRF aggregator selection
    console.log('🚀 Test 4: Submitting multiple rapid deposit intents to test VRF selection...');

    const rapidIntents = [];
    for (let i = 0; i < 3; i++) {
        const rapidIntent = client.createSampleIntent({
            amount: (i + 1) * 100000000000000000, // Different amounts
            source_address: `0x${i.toString().repeat(40)}`,
            target_address: `0x${(i + 5).toString().repeat(40)}`,
            source_chain: i % 2 === 0 ? "ethereum" : "polygon",
            target_chain: "qubetics"
        });

        console.log(`📋 Rapid Intent ${i + 1}:`, rapidIntent.amount, 'wei');
        const result = await client.submitDepositIntent(rapidIntent);

        if (result.success) {
            console.log(`✅ Intent ${i + 1} submitted: ${result.data.intent_id}`);
        } else {
            console.log(`❌ Intent ${i + 1} failed: ${result.error}`);
        }

        // Small delay between submissions
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Test 5: Final status check
    console.log('📊 Test 5: Final status check...');
    await client.getNodeStatus();

    console.log('\n🏁 All tests completed!');
}

// Export for use as module
export default DepositIntentClient;

// Run tests if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error('💥 Test execution failed:', error);
        process.exit(1);
    });
} 