#!/bin/bash
# Upgrade script for 3 local MPC nodes
# Usage: ./scripts/upgrade-localhost.sh <version>
# 
# Environment variables:
#   API_KEY - API key for authentication (default: default_dev_key)
#   Example: API_KEY=your_key ./scripts/upgrade-localhost.sh 0.3.0

set -e

VERSION="${1:-0.2.0}"
BINARY="/data/qubetics-chain-abstraction/target/release/mpc-node"
NODES="localhost:8083 localhost:8082 localhost:8081"
API_KEY="${API_KEY:-2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   MPC Localhost Rolling Upgrade"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target Version: $VERSION"
echo "Binary: $BINARY"
echo "API Key: ${API_KEY:0:10}..."
echo ""

# Step 1: Validate all nodes
echo "[Step 1/3] Validating upgrade on all nodes..."
echo ""

for node in $NODES; do
    echo -n "  Checking $node... "
    
    response=$(curl -s -X POST "http://$node/validate-upgrade" \
        -H "Content-Type: application/json" \
        -H "X-API-KEY: $API_KEY" \
        -d "{\"version\": \"$VERSION\", \"binary_path\": \"$BINARY\"}" \
        2>/dev/null || echo "error")
    
    if echo "$response" | jq -e '.safe' > /dev/null 2>&1; then
        safe=$(echo "$response" | jq -r '.safe')
        if [ "$safe" == "true" ]; then
            echo "✓ READY"
        else
            echo "⚠ WARNINGS"
            echo "$response" | jq -r '.checks.warnings[]' 2>/dev/null || true
        fi
    else
        echo "✗ FAILED"
        echo "  Response: $response"
    fi
done

echo ""
read -p "Proceed with upgrade? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Upgrade cancelled"
    exit 0
fi

echo ""
echo "[Step 2/3] Upgrading nodes (one at a time)..."
echo ""

# Step 2: Upgrade each node
node_num=1
for node in $NODES; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Upgrading node $node_num: $node"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Trigger upgrade
    echo -n "  [1/3] Triggering upgrade... "
    upgrade_response=$(curl -s -X POST "http://$node/upgrade" \
        -H "Content-Type: application/json" \
        -H "X-API-KEY: $API_KEY" \
        -d "{\"version\": \"$VERSION\", \"binary_path\": \"$BINARY\"}" \
        2>/dev/null || echo "error")
    
    if echo "$upgrade_response" | jq -e '.status' > /dev/null 2>&1; then
        echo "✓ OK"
        snapshot=$(echo "$upgrade_response" | jq -r '.snapshot_id')
        echo "     Snapshot: $snapshot"
    else
        echo "✗ FAILED"
        echo "     Response: $upgrade_response"
        exit 1
    fi
    
    # Wait for ready state
    echo -n "  [2/3] Waiting for node to prepare... "
    timeout=60
    while [ $timeout -gt 0 ]; do
        status=$(curl -s "http://$node/upgrade-status" 2>/dev/null | jq -r '.phase' 2>/dev/null || echo "error")
        
        if [ "$status" == "ready_for_restart" ]; then
            echo "✓ READY"
            break
        elif [ "$status" == "failed" ]; then
            echo "✗ FAILED"
            exit 1
        fi
        
        sleep 2
        ((timeout-=2))
    done
    
    if [ $timeout -le 0 ]; then
        echo "✗ TIMEOUT"
        exit 1
    fi
    
    # Note: In a real deployment, you would restart the node here
    echo "  [3/3] ⚠️  NODE RESTART REQUIRED"
    echo "     The node is prepared but needs manual restart"
    echo "     After restarting, run: curl http://$node/upgrade-status"
    echo ""
    
    if [ $node_num -lt 3 ]; then
        echo "  ⏳ Waiting 10 seconds before next node..."
        sleep 10
        echo ""
    fi
    
    ((node_num++))
done

echo ""
echo "[Step 3/3] Final verification..."
echo ""

for node in $NODES; do
    echo -n "  Checking $node... "
    status=$(curl -s "http://$node/upgrade-status" 2>/dev/null | jq -r '.phase' 2>/dev/null || echo "error")
    echo "Phase: $status"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Upgrade preparation complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "⚠️  IMPORTANT: Nodes are prepared but need restart"
echo "   Restart each node with the new binary to complete upgrade"
echo ""

