#!/bin/bash

# Test script for the new intent endpoint
echo "🎯 Testing the new intent endpoint..."

# Test data for a deposit intent
INTENT_DATA='{
  "source_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
  "target_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
  "source_chain": "ethereum",
  "target_chain": "ethereum",
  "amount": 1000000000000000000,
  "source_token": "ETH",
  "target_token": "ETH",
  "path": "0x",
  "transaction_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}'

echo "📤 Sending intent to endpoint..."
echo "📋 Intent data: $INTENT_DATA"

# Send POST request to the intent endpoint
curl -X POST http://localhost:8082/submit_intent \
  -H "Content-Type: application/json" \
  -d "$INTENT_DATA" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "✅ Intent endpoint test completed!"
echo ""
echo "🔍 The intent will be:"
echo "   1. Broadcasted to all nodes in the network"
echo "   2. Each node will process it based on the target chain"
echo "   3. For Ethereum/EVM chains, it will:"
echo "      - Fetch nonce from Qubertics chain (chain ID 9029)"
echo "      - Create and sign the transaction"
echo "      - Use the existing MPC signing flow"
echo ""
echo "📝 To test with different chains, modify the 'target_chain' field:"
echo "   - 'ethereum', 'evm', 'eth' -> Creates Ethereum transaction"
echo "   - 'bitcoin', 'btc' -> Creates Bitcoin transaction (placeholder)" 