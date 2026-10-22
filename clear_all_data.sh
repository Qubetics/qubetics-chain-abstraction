#!/bin/bash

# Script to clear all database data and logs
# This will delete all RocksDB instances and log files

set -e

echo "🗑️  Clearing all database data and logs..."

# Find and remove all RocksDB directories
echo "📂 Removing RocksDB databases..."
find . -type d -name "rocksdb-*" -exec rm -rf {} + 2>/dev/null || true

# Remove data directories
echo "📂 Removing data directories..."
rm -rf ./data 2>/dev/null || true
rm -rf ./node*/data 2>/dev/null || true

# Remove logs
echo "📝 Removing log files..."
rm -rf ./logs 2>/dev/null || true
rm -rf ./node*/logs 2>/dev/null || true

# Remove any backup directories
echo "💾 Removing backup directories..."
rm -rf ./backups 2>/dev/null || true
rm -rf ./node*/backups 2>/dev/null || true

echo "✅ All data cleared!"
echo ""
echo "⚠️  Note: Make sure to stop all running nodes before clearing data."
echo "⚠️  Also check if DATABASE_PATH environment variable is set to a different location."

