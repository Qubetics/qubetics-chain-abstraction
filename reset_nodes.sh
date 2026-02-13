#!/bin/bash

# Reset and setup MPC nodes script
# This script cleans up data/logs and copies fresh mpc-node binary to node1, node2, node3

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="$SCRIPT_DIR/target/release/mpc-node"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}🔄 MPC Nodes Reset Script${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}❌ Binary not found at: $BINARY_PATH${NC}"
    echo -e "${YELLOW}   Run 'cargo build --release' first${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Found binary: $BINARY_PATH${NC}"
echo ""

# Clear top-level logs folder
if [ -d "$SCRIPT_DIR/logs" ]; then
    rm -rf "$SCRIPT_DIR/logs"/*
    echo -e "${GREEN}✅ Cleared logs/ contents${NC}"
else
    echo -e "${CYAN}ℹ️  No logs/ directory found${NC}"
fi
echo ""

# Process each node
for NODE_NUM in 1 2 3 4 5 6 7 8 9 10 11 12; do
    NODE_DIR="$SCRIPT_DIR/node$NODE_NUM"

    echo -e "${YELLOW}📦 Processing node$NODE_NUM...${NC}"

    # Check if node directory exists
    if [ ! -d "$NODE_DIR" ]; then
        echo -e "${RED}   ⚠️  Directory not found: $NODE_DIR - skipping${NC}"
        continue
    fi

    # Remove data and logs directories
    if [ -d "$NODE_DIR/data" ]; then
        rm -rf "$NODE_DIR/data"
        echo -e "${GREEN}   ✅ Removed data/${NC}"
    else
        echo -e "${CYAN}   ℹ️  No data/ directory to remove${NC}"
    fi

    if [ -d "$NODE_DIR/logs" ]; then
        rm -rf "$NODE_DIR/logs"
        echo -e "${GREEN}   ✅ Removed logs/${NC}"
    else
        echo -e "${CYAN}   ℹ️  No logs/ directory to remove${NC}"
    fi

    # Remove old binary if exists
    if [ -f "$NODE_DIR/mpc-node" ]; then
        rm -f "$NODE_DIR/mpc-node"
        echo -e "${GREEN}   ✅ Removed old mpc-node binary${NC}"
    fi

    # Copy new binary
    cp "$BINARY_PATH" "$NODE_DIR/mpc-node"
    echo -e "${GREEN}   ✅ Copied fresh mpc-node binary${NC}"

    echo ""
done

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎉 All nodes reset successfully!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}💡 Next steps:${NC}"
echo -e "${CYAN}   1. Start each node in separate terminals${NC}"
echo -e "${CYAN}   2. cd node1 && ./mpc-node${NC}"
echo -e "${CYAN}   3. cd node2 && ./mpc-node${NC}"
echo -e "${CYAN}   4. cd node3 && ./mpc-node${NC}"
echo ""
