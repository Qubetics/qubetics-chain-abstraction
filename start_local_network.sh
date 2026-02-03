#!/bin/bash
# Start a local MPC network for testing (3 nodes)

set -e

BASE_DIR="/Users/user/My_Data/Qubetics/qubetics-chain-abstraction"
BINARY="$BASE_DIR/target/release/mpc-node"

# Common environment
export CHAIN_CODE_HEX="2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194abe4"
export QUBETICS_DB_ENCRYPTION_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
export NETWORK_TYPE="testnet"
export RUST_LOG=info

# Cleanup
pkill -f "mpc-node" 2>/dev/null || true
sleep 1
rm -rf "$BASE_DIR/node1" "$BASE_DIR/node2" "$BASE_DIR/node3"
mkdir -p "$BASE_DIR/node1" "$BASE_DIR/node2" "$BASE_DIR/node3" "$BASE_DIR/logs"

echo "Starting Node 1..."
cd "$BASE_DIR/node1"
RPC_PORT=8081 $BINARY > "$BASE_DIR/logs/node1.log" 2>&1 &
NODE1_PID=$!
echo "Node 1 started with PID $NODE1_PID"

# Wait for Node 1 to start and get its address
sleep 2
NODE1_ADDR=$(grep -o '/ip4/127.0.0.1/tcp/[0-9]*/p2p/[^"[:space:]]*' "$BASE_DIR/logs/node1.log" | head -1)
echo "Node 1 address: $NODE1_ADDR"

if [ -z "$NODE1_ADDR" ]; then
    echo "ERROR: Could not get Node 1 address"
    exit 1
fi

# Start nodes 2 and 3 simultaneously - DKG triggers when 3 nodes connect
echo "Starting Nodes 2 and 3 simultaneously..."

cd "$BASE_DIR/node2"
RPC_PORT=8082 $BINARY "$NODE1_ADDR" > "$BASE_DIR/logs/node2.log" 2>&1 &
echo "Node 2 started with PID $!"

cd "$BASE_DIR/node3"
RPC_PORT=8083 $BINARY "$NODE1_ADDR" > "$BASE_DIR/logs/node3.log" 2>&1 &
echo "Node 3 started with PID $!"

echo ""
echo "All 3 nodes started. Waiting for peer discovery and DKG to complete..."
echo "Watch logs with: tail -f $BASE_DIR/logs/node*.log"
echo ""

# Wait for DKG completion (triggers when 3 nodes connect)
sleep 45

echo "Checking node status..."
for port in 8081 8082 8083; do
    echo "Node on port $port:"
    curl -s http://localhost:$port/status 2>/dev/null || echo "  Not responding"
    echo ""
done

# Check DKG status
echo "Checking DKG status..."
DKG_STATUS=$(curl -s http://localhost:8081/dkg_status 2>/dev/null)
echo "DKG Status: $DKG_STATUS"
echo ""

# Check network addresses (will be available after DKG completes)
echo "Checking network addresses..."
NETWORK_ADDR=$(curl -s http://localhost:8081/get_network_addresses 2>/dev/null)
echo "Network Addresses: $NETWORK_ADDR"
echo ""

echo "Network is ready for testing!"
echo "To stop: pkill -f mpc-node"
