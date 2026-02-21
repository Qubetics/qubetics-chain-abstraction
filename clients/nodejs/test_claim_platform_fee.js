#!/usr/bin/env node

/**
 * Test script for claim_platform_fee RPC endpoint
 *
 * Tests both TICS and BTC platform fee claims.
 * The request must be signed by the ADMIN_PUBLIC_ADDRESS private key.
 *
 * Usage:
 *   node test_claim_platform_fee.js              # run all tests
 *   node test_claim_platform_fee.js tics          # TICS claim only
 *   node test_claim_platform_fee.js btc           # BTC claim only
 *   node test_claim_platform_fee.js status        # check pending claims
 */

import http from 'http';
import secp256k1 from 'secp256k1';
import keccak from 'keccak';

// ─── Configuration ───────────────────────────────────────────────────────────

const RPC_BASE_URL = 'http://127.0.0.1:8082';
const API_KEY = '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

// Admin private key — must match ADMIN_PUBLIC_ADDRESS env on the node
const ADMIN_PRIVATE_KEY = '0xd9cc6693b05830c39ef09c5060c1e5bb7e2c8f02f2f2976941e6d77ca703894d';

// Target addresses for receiving the claimed fees
const TICS_TARGET_ADDRESS = '0x5634Fd6Ef4560f89FdB03858Ff4b1daEEdc29989';
const BTC_TARGET_ADDRESS = 'tb1qgazak34uzm48srpfvmuexemjfux4znvxm8fu42';

// Claim amounts (smallest units — wei for TICS, satoshis for BTC)
const TICS_CLAIM_AMOUNT = '1000000000000000000'; // 1 TICS (18 decimals)
const BTC_CLAIM_AMOUNT = '700';                // 10000 satoshis

// ─── Colours ─────────────────────────────────────────────────────────────────

const C = {
    red:    '\x1b[31m',
    green:  '\x1b[32m',
    yellow: '\x1b[33m',
    blue:   '\x1b[34m',
    cyan:   '\x1b[36m',
    dim:    '\x1b[2m',
    reset:  '\x1b[0m',
};

// ─── HTTP helper ─────────────────────────────────────────────────────────────

function request(url, body, method = 'POST') {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const data = body ? JSON.stringify(body) : '';
        const opts = {
            hostname: u.hostname,
            port: u.port,
            path: u.pathname,
            method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                'X-API-KEY': API_KEY,
            },
        };

        const req = http.request(opts, (res) => {
            let buf = '';
            res.on('data', (c) => (buf += c));
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(buf) });
                } catch {
                    resolve({ status: res.statusCode, data: buf });
                }
            });
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

// ─── Crypto helpers ──────────────────────────────────────────────────────────

function getAddress(privKeyHex) {
    const pk = privKeyHex.startsWith('0x') ? privKeyHex.slice(2) : privKeyHex;
    const pub = secp256k1.publicKeyCreate(Buffer.from(pk, 'hex'), false);
    const hash = keccak('keccak256').update(Buffer.from(pub.slice(1))).digest();
    return '0x' + hash.slice(-20).toString('hex');
}

function sign(message, privKeyHex) {
    const pk = privKeyHex.startsWith('0x') ? privKeyHex.slice(2) : privKeyHex;
    const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
    const hash = keccak('keccak256')
        .update(Buffer.from(prefix + message, 'utf8'))
        .digest();
    const sig = secp256k1.ecdsaSign(hash, Buffer.from(pk, 'hex'));
    const r = sig.signature.slice(0, 32);
    const s = sig.signature.slice(32, 64);
    const v = Buffer.from([27 + sig.recid]);
    return '0x' + Buffer.concat([r, s, v]).toString('hex');
}

// ─── Logging ─────────────────────────────────────────────────────────────────

function logSection(title) {
    console.log(`\n${C.cyan}${'═'.repeat(60)}${C.reset}`);
    console.log(`${C.cyan}  ${title}${C.reset}`);
    console.log(`${C.cyan}${'═'.repeat(60)}${C.reset}`);
}

function logResult(response) {
    console.log(`${C.dim}HTTP ${response.status}${C.reset}`);
    console.log(JSON.stringify(response.data, null, 2));

    if (response.data?.status === 'success' || response.data?.status === 'pending') {
        console.log(`${C.green}✅ Request accepted${C.reset}`);
        if (response.data.request_id) {
            console.log(`${C.green}   request_id: ${response.data.request_id}${C.reset}`);
        }
    } else {
        console.log(`${C.red}❌ ${response.data?.message || response.data?.error_message || 'Failed'}${C.reset}`);
    }
}

// ─── Test: Server status ─────────────────────────────────────────────────────

async function checkServer() {
    console.log(`${C.yellow}Checking RPC server...${C.reset}`);
    try {
        const res = await request(`${RPC_BASE_URL}/status`, null, 'GET');
        if (res.status === 200) {
            console.log(`${C.green}✅ Server is running${C.reset}`);
            return true;
        }
    } catch (e) {
        console.log(`${C.red}❌ Cannot connect: ${e.message}${C.reset}`);
    }
    return false;
}

// ─── Test: Claim TICS platform fee ───────────────────────────────────────────

async function testClaimTics() {
    logSection('TEST: Claim TICS Platform Fee');

    const adminAddr = getAddress(ADMIN_PRIVATE_KEY);
    console.log(`${C.yellow}Admin address: ${adminAddr}${C.reset}`);
    console.log(`${C.yellow}Target TICS address: ${TICS_TARGET_ADDRESS}${C.reset}`);
    console.log(`${C.yellow}Amount: ${TICS_CLAIM_AMOUNT}${C.reset}`);

    const message = `claim_platform_fee:tics:${TICS_CLAIM_AMOUNT}:${TICS_TARGET_ADDRESS}:${Date.now()}`;
    const signature = sign(message, ADMIN_PRIVATE_KEY);

    const payload = {
        amount: TICS_CLAIM_AMOUNT,
        tics_target_address: TICS_TARGET_ADDRESS,
        btc_target_address: null,
        signature,
        message,
    };

    console.log(`${C.dim}Message: ${message}${C.reset}`);
    console.log(`${C.dim}Signature: ${signature.slice(0, 20)}...${C.reset}`);
    console.log(`${C.yellow}Sending POST /claim_platform_fee ...${C.reset}`);

    try {
        const res = await request(`${RPC_BASE_URL}/claim_platform_fee`, payload);
        logResult(res);
        return res;
    } catch (e) {
        console.log(`${C.red}❌ Request failed: ${e.message}${C.reset}`);
        return null;
    }
}

// ─── Test: Claim BTC platform fee ────────────────────────────────────────────

async function testClaimBtc() {
    logSection('TEST: Claim BTC Platform Fee');

    const adminAddr = getAddress(ADMIN_PRIVATE_KEY);
    console.log(`${C.yellow}Admin address: ${adminAddr}${C.reset}`);
    console.log(`${C.yellow}Target BTC address: ${BTC_TARGET_ADDRESS}${C.reset}`);
    console.log(`${C.yellow}Amount: ${BTC_CLAIM_AMOUNT} satoshis${C.reset}`);

    const message = `claim_platform_fee:btc:${BTC_CLAIM_AMOUNT}:${BTC_TARGET_ADDRESS}:${Date.now()}`;
    const signature = sign(message, ADMIN_PRIVATE_KEY);

    const payload = {
        amount: BTC_CLAIM_AMOUNT,
        tics_target_address: null,
        btc_target_address: BTC_TARGET_ADDRESS,
        signature,
        message,
    };

    console.log(`${C.dim}Message: ${message}${C.reset}`);
    console.log(`${C.dim}Signature: ${signature.slice(0, 20)}...${C.reset}`);
    console.log(`${C.yellow}Sending POST /claim_platform_fee ...${C.reset}`);

    try {
        const res = await request(`${RPC_BASE_URL}/claim_platform_fee`, payload);
        logResult(res);
        return res;
    } catch (e) {
        console.log(`${C.red}❌ Request failed: ${e.message}${C.reset}`);
        return null;
    }
}

// ─── Test: Validation — both addresses ───────────────────────────────────────

async function testBothAddresses() {
    logSection('TEST: Both addresses (should fail)');

    const message = `claim_platform_fee:both:${Date.now()}`;
    const signature = sign(message, ADMIN_PRIVATE_KEY);

    const payload = {
        amount: TICS_CLAIM_AMOUNT,
        tics_target_address: TICS_TARGET_ADDRESS,
        btc_target_address: BTC_TARGET_ADDRESS,
        signature,
        message,
    };

    console.log(`${C.yellow}Sending with BOTH addresses (expect rejection)...${C.reset}`);

    try {
        const res = await request(`${RPC_BASE_URL}/claim_platform_fee`, payload);
        if (res.data?.status === 'error') {
            console.log(`${C.green}✅ Correctly rejected: ${res.data.message}${C.reset}`);
        } else {
            console.log(`${C.red}❌ Expected rejection but got: ${res.data?.status}${C.reset}`);
        }
        return res;
    } catch (e) {
        console.log(`${C.red}❌ Request failed: ${e.message}${C.reset}`);
        return null;
    }
}

// ─── Test: Validation — no address ───────────────────────────────────────────

async function testNoAddress() {
    logSection('TEST: No address (should fail)');

    const message = `claim_platform_fee:none:${Date.now()}`;
    const signature = sign(message, ADMIN_PRIVATE_KEY);

    const payload = {
        amount: TICS_CLAIM_AMOUNT,
        tics_target_address: null,
        btc_target_address: null,
        signature,
        message,
    };

    console.log(`${C.yellow}Sending with NO addresses (expect rejection)...${C.reset}`);

    try {
        const res = await request(`${RPC_BASE_URL}/claim_platform_fee`, payload);
        if (res.data?.status === 'error') {
            console.log(`${C.green}✅ Correctly rejected: ${res.data.message}${C.reset}`);
        } else {
            console.log(`${C.red}❌ Expected rejection but got: ${res.data?.status}${C.reset}`);
        }
        return res;
    } catch (e) {
        console.log(`${C.red}❌ Request failed: ${e.message}${C.reset}`);
        return null;
    }
}

// ─── Test: Validation — zero amount ──────────────────────────────────────────

async function testZeroAmount() {
    logSection('TEST: Zero amount (should fail)');

    const message = `claim_platform_fee:tics:0:${TICS_TARGET_ADDRESS}:${Date.now()}`;
    const signature = sign(message, ADMIN_PRIVATE_KEY);

    const payload = {
        amount: '0',
        tics_target_address: TICS_TARGET_ADDRESS,
        btc_target_address: null,
        signature,
        message,
    };

    console.log(`${C.yellow}Sending with zero amount (expect rejection)...${C.reset}`);

    try {
        const res = await request(`${RPC_BASE_URL}/claim_platform_fee`, payload);
        if (res.data?.status === 'error') {
            console.log(`${C.green}✅ Correctly rejected: ${res.data.message}${C.reset}`);
        } else {
            console.log(`${C.red}❌ Expected rejection but got: ${res.data?.status}${C.reset}`);
        }
        return res;
    } catch (e) {
        console.log(`${C.red}❌ Request failed: ${e.message}${C.reset}`);
        return null;
    }
}

// ─── Test: Validation — wrong signer ─────────────────────────────────────────

async function testWrongSigner() {
    logSection('TEST: Wrong signer (should fail)');

    // Use a random private key that doesn't match ADMIN_PUBLIC_ADDRESS
    const wrongKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
    const wrongAddr = getAddress(wrongKey);

    const message = `claim_platform_fee:tics:${TICS_CLAIM_AMOUNT}:${TICS_TARGET_ADDRESS}:${Date.now()}`;
    const signature = sign(message, wrongKey);

    const payload = {
        amount: TICS_CLAIM_AMOUNT,
        tics_target_address: TICS_TARGET_ADDRESS,
        btc_target_address: null,
        signature,
        message,
    };

    console.log(`${C.yellow}Signing with wrong key (${wrongAddr})...${C.reset}`);
    console.log(`${C.yellow}Expect rejection (signer != ADMIN_PUBLIC_ADDRESS)...${C.reset}`);

    try {
        const res = await request(`${RPC_BASE_URL}/claim_platform_fee`, payload);
        if (res.data?.status === 'error') {
            console.log(`${C.green}✅ Correctly rejected: ${res.data.message}${C.reset}`);
        } else {
            console.log(`${C.red}❌ Expected rejection but got: ${res.data?.status}${C.reset}`);
        }
        return res;
    } catch (e) {
        console.log(`${C.red}❌ Request failed: ${e.message}${C.reset}`);
        return null;
    }
}

// ─── Test: Duplicate claim (should fail on second) ───────────────────────────

async function testDuplicateTics() {
    logSection('TEST: Duplicate TICS claim (second should fail)');

    // First claim
    console.log(`${C.yellow}Sending first TICS claim...${C.reset}`);
    const msg1 = `claim_platform_fee:tics:${TICS_CLAIM_AMOUNT}:${TICS_TARGET_ADDRESS}:${Date.now()}`;
    const sig1 = sign(msg1, ADMIN_PRIVATE_KEY);
    const res1 = await request(`${RPC_BASE_URL}/claim_platform_fee`, {
        amount: TICS_CLAIM_AMOUNT,
        tics_target_address: TICS_TARGET_ADDRESS,
        btc_target_address: null,
        signature: sig1,
        message: msg1,
    });
    console.log(`First: ${res1.data?.status} — ${res1.data?.message || ''}`);

    // Second claim (same asset, should be rejected)
    console.log(`${C.yellow}Sending duplicate TICS claim...${C.reset}`);
    const msg2 = `claim_platform_fee:tics:${TICS_CLAIM_AMOUNT}:${TICS_TARGET_ADDRESS}:${Date.now()}`;
    const sig2 = sign(msg2, ADMIN_PRIVATE_KEY);
    const res2 = await request(`${RPC_BASE_URL}/claim_platform_fee`, {
        amount: TICS_CLAIM_AMOUNT,
        tics_target_address: TICS_TARGET_ADDRESS,
        btc_target_address: null,
        signature: sig2,
        message: msg2,
    });

    if (res2.data?.status === 'error') {
        console.log(`${C.green}✅ Duplicate correctly rejected: ${res2.data.message}${C.reset}`);
    } else {
        console.log(`${C.red}❌ Expected duplicate rejection but got: ${res2.data?.status}${C.reset}`);
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
    console.log(`${C.blue}╔══════════════════════════════════════════════════════════╗${C.reset}`);
    console.log(`${C.blue}║      Claim Platform Fee — Test Script                    ║${C.reset}`);
    console.log(`${C.blue}╚══════════════════════════════════════════════════════════╝${C.reset}`);

    const adminAddr = getAddress(ADMIN_PRIVATE_KEY);
    console.log(`\n${C.yellow}Admin address (derived): ${adminAddr}${C.reset}`);
    console.log(`${C.yellow}Server: ${RPC_BASE_URL}${C.reset}`);

    if (!(await checkServer())) {
        console.log(`\n${C.red}Server not reachable. Start the node first.${C.reset}`);
        process.exit(1);
    }

    const mode = process.argv[2] || 'all';

    switch (mode) {
        case 'tics':
            await testClaimTics();
            break;

        case 'btc':
            await testClaimBtc();
            break;

        case 'validate':
            await testBothAddresses();
            await testNoAddress();
            await testZeroAmount();
            await testWrongSigner();
            break;

        case 'duplicate':
            await testDuplicateTics();
            break;

        case 'all':
        default:
            // Validation tests
            await testBothAddresses();
            await testNoAddress();
            await testZeroAmount();
            await testWrongSigner();

            // Happy path tests
            await testClaimTics();
            await testClaimBtc();
            break;
    }

    console.log(`\n${C.cyan}${'═'.repeat(60)}${C.reset}`);
    console.log(`${C.green}Done.${C.reset}\n`);
}

main().catch((e) => {
    console.error(`${C.red}Fatal: ${e.message}${C.reset}`);
    process.exit(1);
});
