#!/bin/bash

# Test script to verify DKG state persists across node restarts

API_KEY="${API_KEY:-default_dev_key}"
PORT=${1:-8081}

echo "======================================"
echo "Testing DKG Persistence After Restart"
echo "======================================"
echo ""

# Function to get vault addresses
get_vault_addresses() {
    curl -s -H "X-API-KEY: $API_KEY" http://localhost:$PORT/get-public-key | jq -r '{eth: .vault_eth_address, btc: .vault_btc_address}'
}

# Function to get DKG status
get_dkg_status() {
    curl -s http://localhost:$PORT/node-info | jq -r '.dkg_status'
}

echo "📊 Step 1: Checking current vault addresses..."
VAULT_BEFORE=$(get_vault_addresses)
echo "$VAULT_BEFORE"
echo ""

echo "📊 Step 2: Checking DKG status..."
DKG_STATUS=$(get_dkg_status)
echo "DKG Status: $DKG_STATUS"
echo ""

if [ "$DKG_STATUS" != "Completed" ]; then
    echo "⚠️ DKG not completed yet. Please wait for DKG to complete first."
    exit 1
fi

echo "✅ DKG completed! Now you can safely restart your nodes."
echo ""
echo "To test:"
echo "1. Save these vault addresses"
echo "2. Restart all your nodes"
echo "3. Run this script again with: ./test-dkg-persistence.sh $PORT"
echo "4. Verify vault addresses are the SAME"
echo ""
echo "💾 Saved vault addresses:"
echo "$VAULT_BEFORE" | tee /tmp/vault-addresses-before.json

