const fs = require('fs');
const path = require('path');

// Log files to scan
const LOG_FILES = [
    'mpc-node.log',
    'mpc-node1.log',
    'mpc-node2.log',
    'node2/mpc-node.log',
];

// Regex to match: r=0x..., s=0x..., digest=0x...
// Matches lines like:
// Signature details: r=0xABC..., s=0xDEF..., recovery_id=0, digest=0xGHI...
const SIG_RE = /r=0x([0-9a-f]{64}),\s*s=0x([0-9a-f]{64}),\s*recovery_id=(\d),\s*digest=0x([0-9a-f]{64})/;

// Also grab the tuple_id from a nearby "Using coordinated nonce" line
const NONCE_RE = /Using coordinated nonce (\S+) for signing/;
const BTC_DIGEST_RE = /\[BTC-TX-DIGEST\].*signing digest.*input \d+: 0x([0-9a-f]{64})/;

// Map: r_hex -> [ { file, line, r, s, z, recovery_id } ]
const byR = new Map();

for (const logFile of LOG_FILES) {
    if (!fs.existsSync(logFile)) continue;

    const lines = fs.readFileSync(logFile, 'utf8').split('\n');
    console.error(`Scanning ${logFile} (${lines.length} lines)...`);

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const m = SIG_RE.exec(line);
        if (!m) continue;

        const [, r, s, recovery_id, z] = m;
        const entry = {
            file: logFile,
            lineNo: i + 1,
            r,
            s,
            z,
            recovery_id,
            rawLine: line.trim().slice(0, 200),
        };

        if (!byR.has(r)) byR.set(r, []);
        byR.get(r).push(entry);
    }
}

// Filter to only r values that appear with MORE THAN ONE DISTINCT digest
// (same r + same digest = just multi-node logging of the same signing event — not reuse)
const reused = [];

for (const [r, entries] of byR) {
    const distinctZ = new Set(entries.map(e => e.z));
    if (distinctZ.size < 2) continue; // Same digest across nodes = OK

    reused.push({ r, entries, distinctZ: [...distinctZ] });
}

// Sort by number of distinct digests (most dangerous first)
reused.sort((a, b) => b.distinctZ.length - a.distinctZ.length);

console.log('\n' + '='.repeat(70));
console.log(`NONCE REUSE REPORT — ${reused.length} distinct r values used for multiple different messages`);
console.log('='.repeat(70));

for (const { r, entries, distinctZ } of reused) {
    console.log(`\n${'─'.repeat(70)}`);
    console.log(`r = 0x${r}`);
    console.log(`  Distinct digests signed with this nonce: ${distinctZ.length}`);
    console.log(`  Total log entries: ${entries.length}`);

    // Group entries by digest for clarity
    const byZ = new Map();
    for (const e of entries) {
        if (!byZ.has(e.z)) byZ.set(e.z, []);
        byZ.get(e.z).push(e);
    }

    let idx = 1;
    for (const [z, zEntries] of byZ) {
        const e = zEntries[0]; // representative
        console.log(`\n  [Signing ${idx++}]`);
        console.log(`    digest (z) : 0x${z}`);
        console.log(`    s          : 0x${e.s}`);
        console.log(`    recovery_id: ${e.recovery_id}`);
        console.log(`    source     : ${e.file}:${e.lineNo}`);
    }
}

console.log('\n' + '='.repeat(70));
console.log(`SUMMARY`);
console.log(`  Total unique r values across all logs : ${byR.size}`);
console.log(`  r values reused for different messages: ${reused.length}`);
console.log(`  Each reused r allows full key share extraction from on-chain data`);
console.log('='.repeat(70));
