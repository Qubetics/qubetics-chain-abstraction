#!/bin/bash

# Test script for deposit intent RPC endpoint
# Make sure the MPC node is running on port 8081

echo "🧪 Testing Deposit Intent RPC endpoint..."

# Test deposit intent submission
echo "📝 Submitting deposit intent..."
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "source_address": "0x742d35Cc6634C0532925a3b8D5A42DCA0e33e4",
    "target_address": "0x123d35Cc6634C0532925a3b8D5A42DCA0e33e4",
    "source_chain": "ethereum", 
    "target_chain": "qubetics",
    "amount": 1000000000000000000,
    "source_token": "ETH",
    "target_token": "TICS",
    "path": [1, 2, 3, 4],
    "transaction_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  }' \
  http://localhost:8081/deposit_intent

echo -e "\n\n✅ Test completed!"

echo -e "\n📊 Check node status..."
curl -X GET http://localhost:8081/status

echo -e "\n\n🏁 All tests finished!" 