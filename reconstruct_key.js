const crypto = require('crypto');

// =====================================================================
// secp256k1 curve order
// =====================================================================
const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// =====================================================================
// DKG signing key shares extracted from node logs
// =====================================================================
const shares = [
    { index: 1, key: BigInt('0x66d37fd6eb8e0380748afb3cafad71ed7ce870e4607abef0a30ded7b22b92b2f') }, // mpc-node2.log
    { index: 2, key: BigInt('0x689aea1eddca7276cff21d38278c57bd6312a8f318dccfa543fb759d48e198b7') }, // mpc-node1.log
    { index: 3, key: BigInt('0x6a625466d006e16d2b593f339f6b3d8d493ce101d13ee059e4e8fdbf6f0a063f') }, // mpc-node.log
];

// Chain code from env_defaults.rs (DEFAULT_CHAIN_CODE_HEX)
const CHAIN_CODE = Buffer.from('2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194abe4', 'hex');

// =====================================================================
// BigInt helpers
// =====================================================================
function modinv(a, m) {
    a = ((a % m) + m) % m;
    let r = 1n, b = a, e = m - 2n;
    while (e > 0n) {
        if (e % 2n === 1n) r = (r * b) % m;
        b = (b * b) % m;
        e >>= 1n;
    }
    return r;
}

function bigintToBuffer32(v) {
    const hex = ((v % N) + N) % N;
    return Buffer.from(hex.toString(16).padStart(64, '0'), 'hex');
}

// =====================================================================
// Lagrange interpolation: reconstruct secret from shares at points {1,2,3}
// =====================================================================
function lagrangeCoeff(j, points) {
    let lam = 1n;
    for (const m of points) {
        if (m !== j) {
            lam = (lam * m) % N;
            lam = (lam * modinv(((m - j) % N + N) % N, N)) % N;
        }
    }
    return lam;
}

function reconstructSecret(shares) {
    const points = shares.map(s => BigInt(s.index));
    let secret = 0n;
    for (const s of shares) {
        const lam = lagrangeCoeff(BigInt(s.index), points);
        secret = (secret + lam * s.key) % N;
    }
    return (secret + N) % N;
}

// =====================================================================
// EC point operations using Node.js ECDH
// =====================================================================
function getPublicKeyFromPrivate(privKeyBigInt) {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(bigintToBuffer32(privKeyBigInt));
    return ecdh.getPublicKey(null, 'compressed');
}

function compressedPubKey(uncompressed) {
    if (uncompressed[0] === 0x04) {
        const x = uncompressed.slice(1, 33);
        const prefix = (uncompressed[64] % 2 === 0) ? 0x02 : 0x03;
        return Buffer.concat([Buffer.from([prefix]), x]);
    }
    return uncompressed; // already compressed
}

// Point addition via private key: pubA + scalar*G = (privA + scalar)*G
function addScalarToPublicKey(compressedPub, scalar) {
    // To add scalar*G to a public key, we need the private key for the public key...
    // Instead: tweaked_privkey = base_privkey + scalar => tweaked_pubkey = tweaked_privkey * G
    // This is used below where we know both the base private key and the scalar.
    throw new Error('Use addScalarToPrivateKey instead');
}

// =====================================================================
// HMAC-SHA256 based tweak (mirrors Rust hmac_scalar_mod_n)
// =====================================================================
function hmac256FromAddr(addr, key) {
    // Strip 0x prefix, decode hex address to 20 bytes
    const s = addr.startsWith('0x') ? addr.slice(2) : addr;
    if (s.length !== 40) throw new Error(`Not a 20-byte hex address: ${addr}`);
    const msg = Buffer.from(s, 'hex');
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(msg);
    return hmac.digest(); // 32 bytes
}

function hmacScalarModN(addr, chainCode) {
    const h = hmac256FromAddr(addr, chainCode);
    let x = BigInt('0x' + h.toString('hex'));
    // Reduce: x = (x % (n-1)) + 1  — ensures result in [1..n-1]
    x = (x % (N - 1n)) + 1n;
    return x;
}

function bytesToScalarModN(bytes32) {
    const x = BigInt('0x' + bytes32.toString('hex'));
    return x % N;
}

// =====================================================================
// P2PKH address derivation
// =====================================================================
function hash160(buf) {
    const sha = crypto.createHash('sha256').update(buf).digest();
    return crypto.createHash('ripemd160').update(sha).digest();
}

function base58check(payload) {
    const checksum = crypto.createHash('sha256').update(
        crypto.createHash('sha256').update(payload).digest()
    ).digest().slice(0, 4);
    const full = Buffer.concat([payload, checksum]);
    // Base58 encoding
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = BigInt('0x' + full.toString('hex'));
    let encoded = '';
    while (num > 0n) {
        encoded = ALPHABET[Number(num % 58n)] + encoded;
        num = num / 58n;
    }
    // Preserve leading zeros
    for (const byte of full) {
        if (byte === 0) encoded = '1' + encoded;
        else break;
    }
    return encoded;
}

function pubkeyToP2PKH(compressedPubKey, mainnet = true) {
    const h = hash160(compressedPubKey);
    const version = mainnet ? Buffer.from([0x00]) : Buffer.from([0x6f]);
    return base58check(Buffer.concat([version, h]));
}

// =====================================================================
// MAIN: Reconstruct and derive
// =====================================================================
console.log('='.repeat(70));
console.log(' DKG PRIVATE KEY RECONSTRUCTION FROM LOG FILES');
console.log('='.repeat(70));

// Step 1: Reconstruct the DKG network private key via Lagrange interpolation
const networkPrivateKey = reconstructSecret(shares);
const networkPKHex = networkPrivateKey.toString(16).padStart(64, '0');
console.log(`\nNetwork DKG private key: 0x${networkPKHex}`);

// Step 2: Derive the network compressed public key
const networkPubKey = getPublicKeyFromPrivate(networkPrivateKey);
console.log(`Network compressed pubkey: ${networkPubKey.toString('hex')}`);

// Step 3: Derive P2PKH (vault) address from group key
const vaultAddr = pubkeyToP2PKH(networkPubKey, true);
console.log(`Network vault P2PKH address: ${vaultAddr}`);

// Step 4: Verify against on-chain public key
const onChainPubKey = '026e6e41cd59e1120f2699f0fd5534c0ca00cb23178cb833ecafa431a3ce26bdaa';
console.log(`On-chain pubkey (expected): ${onChainPubKey}`);
console.log(`MATCH: ${networkPubKey.toString('hex') === onChainPubKey}`);

// Step 5: Verify P2PKH HASH160
const h160 = hash160(networkPubKey);
console.log(`HASH160: ${h160.toString('hex')}`);
console.log(`Expected HASH160: e08c136debeb6dddc441b05353624ed2dc888c6d`);
console.log(`HASH160 MATCH: ${h160.toString('hex') === 'e08c136debeb6dddc441b05353624ed2dc888c6d'}`);

// =====================================================================
// Step 6: Tweak share logic — derive user vault addresses
// =====================================================================
console.log('\n' + '='.repeat(70));
console.log(' USER VAULT ADDRESS DERIVATION (Tweaked Shares)');
console.log('='.repeat(70));
console.log(`\nChain code: ${CHAIN_CODE.toString('hex')}`);

function deriveUserVaultAddress(ticsAddress) {
    // 1. Compute HMAC constant: hmac_scalar_mod_n(tics_address, chain_code)
    const hmacScalar = hmacScalarModN(ticsAddress, CHAIN_CODE);

    // 2. bytes_to_scalar_mod_n on the hmac constant bytes
    const hmacBuf = bigintToBuffer32(hmacScalar);
    const hmacReduced = bytesToScalarModN(hmacBuf);

    // 3. Tweaked private key = network_private_key + hmac_reduced (mod N)
    const tweakedPrivKey = (networkPrivateKey + hmacReduced) % N;

    // 4. Derive tweaked public key (= tweaked_privkey * G)
    const tweakedPubKey = getPublicKeyFromPrivate(tweakedPrivKey);

    // 5. Derive P2PKH address
    const btcAddress = pubkeyToP2PKH(tweakedPubKey, true);

    // 6. Derive ETH address (keccak256 of uncompressed pubkey x,y)
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(bigintToBuffer32(tweakedPrivKey));
    const uncompressed = ecdh.getPublicKey(null, 'uncompressed');
    const pubBytes = uncompressed.slice(1); // remove 0x04 prefix
    // keccak256 — use sha3 via crypto (Node 18+) or manual
    let ethAddr;
    try {
        const hash = crypto.createHash('sha3-256');
        // Actually Ethereum uses keccak256 not sha3-256 — they differ!
        // Node.js doesn't have keccak256 natively. Use a workaround:
        // For demonstration, we'll note this and skip ETH address
        ethAddr = '(keccak256 not available in Node.js stdlib — use ethers.js)';
    } catch (e) {
        ethAddr = '(keccak256 not available)';
    }

    return {
        ticsAddress,
        hmacConstant: hmacScalar.toString(16).padStart(64, '0'),
        tweakedPrivKey: tweakedPrivKey.toString(16).padStart(64, '0'),
        tweakedPubKey: tweakedPubKey.toString('hex'),
        btcAddress,
        ethAddress: ethAddr,
    };
}

// Example: derive vault addresses for some TICS addresses
// Replace these with actual registered user TICS addresses
const testAddresses = [
    '0x0000000000000000000000000000000000000001', // example
];

// If you know actual registered user addresses, add them here:
// testAddresses.push('0xYourActualTicsAddress...');

for (const addr of testAddresses) {
    console.log(`\n--- User: ${addr} ---`);
    try {
        const result = deriveUserVaultAddress(addr);
        console.log(`  HMAC constant:      0x${result.hmacConstant}`);
        console.log(`  Tweaked private key: 0x${result.tweakedPrivKey}`);
        console.log(`  Tweaked public key:  ${result.tweakedPubKey}`);
        console.log(`  BTC vault (P2PKH):  ${result.btcAddress}`);
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
}

console.log('\n' + '='.repeat(70));
console.log(' To derive a specific user vault, add their TICS address to testAddresses');
console.log(' or call: node -e "require(\'./reconstruct_key\').deriveUserVaultAddress(\'0x...\')"');
console.log('='.repeat(70));

// Export for programmatic use
module.exports = { deriveUserVaultAddress, networkPrivateKey, networkPubKey, vaultAddr };
