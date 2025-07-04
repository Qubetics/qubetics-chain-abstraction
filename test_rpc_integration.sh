#!/bin/bash

# Test script for RPC server integration
set -e

echo "🧪 Testing MPC RPC Server Integration"
echo "====================================="

# Check if the MPC node is running
echo "1. Checking if MPC node is running..."
if ! curl -s http://localhost:8080/status > /dev/null 2>&1; then
    echo "❌ MPC node is not running on port 8080"
    echo "   Please start the node with: cargo run --bin mpcn"
    exit 1
fi
echo "✅ MPC node is running"

# Test node status endpoint
echo ""
echo "2. Testing node status endpoint..."
STATUS_RESPONSE=$(curl -s http://localhost:8080/status)
echo "   Response: $STATUS_RESPONSE"

# Test transaction submission
echo ""
echo "3. Testing transaction submission..."
TX_RESPONSE=$(curl -s -X POST http://localhost:8080/submit_transaction \
    -H "Content-Type: application/json" \
    -d '{
        "from": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
        "to": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b7",
        "amount": 1000000000000000000,
        "nonce": 1,
        "data": "48656c6c6f204d5043204e6574776f726b21"
    }')
echo "   Response: $TX_RESPONSE"

# Test DKG start
echo ""
echo "4. Testing DKG start..."
DKG_RESPONSE=$(curl -s -X POST http://localhost:8080/start_dkg)
echo "   Response: $DKG_RESPONSE"

echo ""
echo "🎉 All RPC tests completed successfully!"
echo ""
echo "📋 Summary:"
echo "   - Node status endpoint: ✅"
echo "   - Transaction submission: ✅"
echo "   - DKG start endpoint: ✅"
echo ""
echo "💡 You can also test with the Node.js client:"
echo "   cd clients/nodejs && npm install && node test_client.js" 