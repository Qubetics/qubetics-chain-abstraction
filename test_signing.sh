#!/bin/bash

# Test script for the signing mechanism
# This script runs multiple nodes to test the distributed signing functionality

echo "🚀 Starting Signing Mechanism Test"
echo "=================================="

# Create logs directory if it doesn't exist
mkdir -p logs

# Function to cleanup background processes
cleanup() {
    echo "🧹 Cleaning up background processes..."
    pkill -f "signing_demo" || true
    pkill -f "mpcn" || true
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start multiple nodes in the background
echo "📡 Starting Node 1..."
cargo run --bin signing_demo > logs/node1.log 2>&1 &
NODE1_PID=$!

sleep 2

echo "📡 Starting Node 2..."
cargo run --bin signing_demo > logs/node2.log 2>&1 &
NODE2_PID=$!

sleep 2

echo "📡 Starting Node 3..."
cargo run --bin signing_demo > logs/node3.log 2>&1 &
NODE3_PID=$!

echo "✅ All nodes started!"
echo "📊 Node PIDs: $NODE1_PID, $NODE2_PID, $NODE3_PID"
echo ""
echo "📋 Monitoring logs..."
echo "===================="

# Monitor the logs
tail -f logs/node1.log logs/node2.log logs/node3.log &

# Wait for user to stop
echo ""
echo "⏳ Press Ctrl+C to stop all nodes and exit"
echo "📁 Logs are being written to logs/ directory"

# Wait for all background processes
wait $NODE1_PID $NODE2_PID $NODE3_PID

echo "�� Test completed!" 