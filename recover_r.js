// Decode DER signature from scriptSig hex and extract r, s values
function extractRSFromScriptSig(sigHex) {
    let sig = Buffer.from(sigHex, 'hex');

    // Strip push opcode if present
    if (sig[0] !== 0x30) {
        const pushLen = sig[0];
        sig = sig.slice(1, 1 + pushLen);
    }

    // Strip sighash byte at end
    const der = sig.slice(0, -1);

    if (der[0] !== 0x30) throw new Error('Not a valid DER signature');

    let offset = 2;

    // Read r
    if (der[offset] !== 0x02) throw new Error('Invalid R marker');
    const rLen = der[offset + 1];
    let r = der.slice(offset + 2, offset + 2 + rLen);
    if (r[0] === 0x00) r = r.slice(1); // strip leading zero
    offset += 2 + rLen;

    // Read s
    if (der[offset] !== 0x02) throw new Error('Invalid S marker');
    const sLen = der[offset + 1];
    let s = der.slice(offset + 2, offset + 2 + sLen);
    if (s[0] === 0x00) s = s.slice(1);

    return { r: r.toString('hex'), s: s.toString('hex') };
}

// ── Two transactions ──────────────────────────────────────────────────

// Tx1: 261cd018...558c  (Reuse #1 — single input, r = 54caf9...)
const tx1 = {
    txid: '261cd0188e1716fb4eaeeabb85f466d0c7b133e271d9e978a4d2e8ea0196558c',
    inputs: [
        // Input 0 — ScriptSig from mempool.space
        '473044022054caf91a2a9b4ec90eabd5db893db8baa4d622d32770b954cb38c923c21a8317022007901e5e599e09848b79d0b251721912c891bf57044444a5f9d73e40a8919e730121026e6e41cd59e1120f2699f0fd5534c0ca00cb23178cb833ecafa431a3ce26bdaa',
    ],
};

// Tx2: fe284c3f...e986  (Reuse #2 — 2 inputs, BOTH should have r = bd8edf...)
const tx2 = {
    txid: '2e817b3c9095c624c8f9a0f2b9dd7c4573b5add961389071bf3ceff5466613e4',
    inputs: [
        // Input 0 — ScriptSig from mempool.space (replace with second if missing)
        '473044022020a8ba3ee5f315abdd7b45d24f6ff79bee42987089470c9a4bb92d1301be65ee02205a2f44e268ec9e90a93307a85297b67f58850b543dcd2b1b02329539409cbd0f01210309445242dbd1b32868de68b8f346e129a76724da373706218ec0fa4b92865e43',
        // ─── Input 1 ─── PASTE the second scriptSig from mempool.space here:
        '4830450221008b35e35466f66d9ae258f9d7da9f088150859e222f8f7f9d6eb7b0d03c586b2d02201651dc251fc29d8d9f7f67be97a9f36acadde16d1c622ff09620cae3ad93c4e401210309445242dbd1b32868de68b8f346e129a76724da373706218ec0fa4b92865e43',
    ],
};

// ── Print extracted r/s for each ────────────────────────────────────

function analyzeTransaction(tx) {
    console.log(`\nTx: ${tx.txid}`);
    const rValues = [];
    tx.inputs.forEach((scriptSig, i) => {
        try {
            const { r, s } = extractRSFromScriptSig(scriptSig);
            console.log(`  Input ${i}:`);
            console.log(`    r = 0x${r}`);
            console.log(`    s = 0x${s}`);
            rValues.push(r);
        } catch (e) {
            console.log(`  Input ${i}: ERROR — ${e.message}`);
        }
    });

    if (rValues.length > 1) {
        const allSame = rValues.every(r => r === rValues[0]);
        console.log(`\n  ⚠️  r values same across all inputs? ${allSame ? '✅ YES — NONCE REUSE CONFIRMED' : '❌ NO'}`);
    }
    return rValues;
}

console.log('='.repeat(65));
console.log('  R VALUE EXTRACTION FROM ON-CHAIN SCRIPTSIG');
console.log('='.repeat(65));

analyzeTransaction(tx1);
analyzeTransaction(tx2);

console.log('\n' + '='.repeat(65));
console.log('  HOW TO GET THE SECOND SCRIPTSIG:');
console.log('  1. Open mempool.space/tx/fe284c3fb911... (with showDetails=true)');
console.log('  2. Expand all inputs — find "ScriptSig (HEX)" for input 1');
console.log('  3. Paste it into tx2.inputs[1] above and re-run');
console.log('  4. If r from input 1 === r from input 0, key recovery works');
console.log('='.repeat(65));