#!/usr/bin/env bash
# QCA-74: Ensure calldata encoding failures hard-fail instead of silently falling back to "0x".
# Targets the pattern where encode_*_calldata() returns Option and is unwrapped with "0x" fallback.
# Run this before merging any PR that touches transaction builders.
#
# Note: eth_tx.data.unwrap_or_else(|| "0x") is intentionally excluded — that field is
# legitimately optional in already-built transaction structs (simple value transfers).
set -euo pipefail

# Find lines where a variable named *calldata* falls back to "0x"
MATCHES=$(grep -rn --include="*.rs" 'calldata.*unwrap_or_else.*"0x"\.to_string\|unwrap_or_else.*"0x"\.to_string.*calldata' src/ || true)

if [ -n "$MATCHES" ]; then
    echo "❌ QCA-74 lint failed: calldata '0x' fallback pattern detected:"
    echo "$MATCHES"
    exit 1
fi

echo "✅ QCA-74 lint passed: no calldata '0x' fallback patterns found."
