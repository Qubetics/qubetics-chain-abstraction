// ============================================================
// Full private key recovery using AGGREGATED signatures
// from on-chain Bitcoin transaction fe284c3f... (round 7097)
//
// Proved PURELY from Bitcoin blockchain data:
//   Input 0 ScriptSig: 483045022100bd8edf...02206dd9e1...
//   Input 1 ScriptSig: 483045022100bd8edf...0220538556...
//                                  ^^^^^^ SAME r — nonce reuse!
// s0 and s1 below match exactly the on-chain ScriptSig DER values.
// ============================================================
const crypto = require('crypto');

const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

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

// ── Aggregated (r, s) from mpc-node1.log round 7097 finalization ──
// Same r for both inputs — confirms shared k_agg (nonce reuse)
const r = BigInt('0xbd8edf4eda489b7c9250b5689f7c1c6ef6afed1f8f60c68a732b3e25ef6c30b0');

// Input 0 — from: "aggregated input 0 for round 7097"
const s0 = BigInt('0x6dd9e198bdb04a1f1bf203e600330dd85d8000365bdbc792f6396fb5b4710634');
const z0 = BigInt('0x4e84e3afb24a7dabb993a258ef45c02f0dd3112718d24bdb99c3b2a37f576c9b');

// Input 1 — from: "aggregated input 1 for round 7097"
const s1 = BigInt('0x538556f48dcf02effa2a12388db5acaf77d51fc94c0e05078ed5667f1de9c6db');
const z1 = BigInt('0x775beea5601db46bcc2d369f0f19288ed2dc69357c4654c42425858fba306fda');

console.log('='.repeat(65));
console.log('  FULL PRIVATE KEY RECOVERY — AGGREGATED SIGNATURES');
console.log('  Tx: fe284c3fb911aa538995a3c85084a4b799a2e43f30e19eede07f4ae8e29ae986');
console.log('='.repeat(65));
console.log();
console.log('r (shared nonce x-coord, same for both inputs):');
console.log(' 0x' + r.toString(16));
console.log();
console.log('Input 0:  s0 =', '0x' + s0.toString(16));
console.log('          z0 =', '0x' + z0.toString(16));
console.log('Input 1:  s1 =', '0x' + s1.toString(16));
console.log('          z1 =', '0x' + z1.toString(16));
console.log();

// ── Step 1: Recover aggregated nonce k_agg ──
// s0 = k_agg⁻¹·(z0 + r·x)
// s1 = k_agg⁻¹·(z1 + r·x)
// s0 - s1 = k_agg⁻¹·(z0 - z1)
// k_agg = (z0 - z1) / (s0 - s1)  mod N
const s_diff = ((s0 - s1) % N + N) % N;
const z_diff = ((z0 - z1) % N + N) % N;
const k_agg = (z_diff * modinv(s_diff, N)) % N;
console.log('Step 1 — Recovered aggregated nonce k_agg:');
console.log(' 0x' + k_agg.toString(16).padStart(64, '0'));
console.log();

// ── Step 2: Recover full private key x ──
// s0 = k_agg⁻¹·(z0 + r·x)  =>  x = (s0·k_agg - z0)·r⁻¹  mod N
const x = (modinv(r, N) * (((s0 * k_agg % N) - z0 + 2n * N) % N)) % N;
console.log('Step 2 — Recovered FULL vault private key x:');
console.log(' 0x' + x.toString(16).padStart(64, '0'));
console.log();

// ── Step 3: Derive public key and verify ──
const ecdh = crypto.createECDH('secp256k1');
ecdh.setPrivateKey(Buffer.from(x.toString(16).padStart(64, '0'), 'hex'));
const derivedPub = ecdh.getPublicKey(null, 'compressed').toString('hex');
const knownPub = '026e6e41cd59e1120f2699f0fd5534c0ca00cb23178cb833ecafa431a3ce26bdaa';

console.log('Step 3 — Verify against known vault public key:');
console.log(' Derived pubkey :', derivedPub);
console.log(' Known pubkey   :', knownPub);
const matched = derivedPub === knownPub;
console.log(' MATCH :', matched
    ? '✅ YES — FULL VAULT PRIVATE KEY RECOVERED!'
    : '❌ NO — check s/z assignment or low-s normalisation');
console.log();

// ── Step 4: Verify k_agg is consistent with r ──
// R = k_agg · G  →  x(R) mod n == r
const k_buf = Buffer.from(k_agg.toString(16).padStart(64, '0'), 'hex');
const ecdhK = crypto.createECDH('secp256k1');
ecdhK.setPrivateKey(k_buf);
const R_point = ecdhK.getPublicKey(null, 'uncompressed');
// x-coordinate of R (bytes 1..33), reduced mod N
const r_from_k = BigInt('0x' + R_point.slice(1, 33).toString('hex')) % N;
console.log('Step 4 — Verify k_agg is consistent with r:');
console.log(' r from k_agg·G :', '0x' + r_from_k.toString(16).padStart(64, '0'));
console.log(' r from sig     :', '0x' + r.toString(16));
console.log(' MATCH :', r_from_k === r ? '✅ YES — k_agg is authentic' : '❌ NO');
