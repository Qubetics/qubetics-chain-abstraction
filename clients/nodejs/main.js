import axios from 'axios';
import { ethers } from 'ethers';
const RPC_SERVER = 'http://localhost:8081';

console.log('🧪 Testing RPC Server at', RPC_SERVER);
console.log('=====================================');

async function testRPC() {
    try {
        // Test 1: Get node status
        console.log('\n📊 Test 1: Get Node Status');
        const statusResponse = await axios.get(`${RPC_SERVER}/status`);
        console.log('✅ Status:', statusResponse.data);

        // Test 2: Submit a transaction
        console.log('\n📝 Test 2: Submit Transaction');
        const transaction = {
            to: "0xceb5057834CB4EdE0E59F9e91046B8cB96C72e9C",                      // Required
            value: "0x2386f26fc50000",              // Amount to send in wei
            nonce: 3,                                      // Must be correct for sender's account
            gasLimit: 21000,                               // Minimum for ETH transfer   
            gasPrice: "0x3b9aca00",    // Base fee + priority
            chainId: 1043,
        };

        const txResponse = await axios.post(`${RPC_SERVER}/submit_transaction`, transaction, {
            headers: { 'Content-Type': 'application/json' }
        });
        console.log('✅ Transaction submitted:', txResponse.data);

        console.log('\n🎉 All tests completed successfully!');
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        process.exit(1);
    }
}

testRPC(); 
// const nodeHexValues = {
//     1: '393192b21d043fcc3959702fdbea7820326b5d8347f32d2827d63fd7c65b8262',
//     2: '0e826320ac95ce1e50718687a4cb78a1fe901162028e4a67aa20a7733db049d6',
//     3: '66992ad5d609876f62d8c6ff7b2c89c0116b24164a63027f002de428db4cc459',
//     4: '568e7fee802ad2e73f7bdb0278b57dd4e35f0e6a0a8f6a8544855414503a55e3',
//   };