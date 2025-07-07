import axios from 'axios';

const RPC_SERVER = 'http://localhost:8080';

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
            from: "abcd",
            to: "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b7",
            amount: 1000000000000000000,
            nonce: 3,
            data: [72, 101, 108, 108, 111, 32, 77, 80, 67, 32, 78, 101, 116, 119, 111, 114, 107, 33] // "Hello MPC Network!" as byte array
        };

        const txResponse = await axios.post(`${RPC_SERVER}/submit_transaction`, transaction, {
            headers: { 'Content-Type': 'application/json' }
        });
        console.log('✅ Transaction submitted:', txResponse.data);

        // Test 3: Start DKG
        console.log('\n🚀 Test 3: Start DKG');
        const dkgResponse = await axios.post(`${RPC_SERVER}/start_dkg`);
        console.log('✅ DKG started:', dkgResponse.data);

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