#!/bin/bash

echo "═══════════════════════════════════════════════════════════"
echo "🔍 QUICK VERIFICATION SCRIPT"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "After starting your nodes, run these commands to verify:"
echo ""

echo "1️⃣  Check if database was set at startup:"
echo "   grep 'DATABASE SET ON SIGNING NODE' logs/*.log"
echo ""

echo "2️⃣  Check if DKG stored peer indices:"
echo "   grep 'STORING COMPLETE' logs/*.log"
echo ""

echo "3️⃣  Check if peer index map was propagated:"
echo "   grep 'PEER INDEX MAP PROPAGATED' logs/*.log"
echo ""

echo "4️⃣  Check for successful index lookups:"
echo "   grep 'INDEX LOOKUP SUCCESS' logs/*.log"
echo ""

echo "5️⃣  Check for any CRITICAL errors:"
echo "   grep 'CRITICAL.*VERIFY' logs/*.log"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "💡 If you see -VERIFY tags in logs, the new code is running!"
echo "💡 If you still see old error format, rebuild didn't work"
echo "═══════════════════════════════════════════════════════════"

