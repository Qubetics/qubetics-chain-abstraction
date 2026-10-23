#!/usr/bin/env node

/**
 * Simple helper to exercise the add_liquidity HTTP endpoint.
 *
 * Usage:
 *   SOLVER_PRIVATE_KEY=0x... SOLVER_ID=arpit1 node test_add_liquidity.js
 *
 * Adjust RPC url / amount env vars below as needed.
 */

import http from 'http';
import crypto from 'crypto';
import secp256k1 from 'secp256k1';
import keccak from 'keccak';

const RPC_BASE_URL = process.env.QUBETICS_RPC_URL ?? 'http://127.0.0.1:8082';
const ADD_ENDPOINT = `${RPC_BASE_URL}/solver_add_liquidity`;

// SOLVER_003 configuration - private key derives to 0xbac113cebd9CB2fBD2a01B5CBC43D0fC0EBed5e9
const SOLVER_ID = process.env.SOLVER_ID ?? 'SOLVER_003';
const TEST_PRIVATE_KEY =
  process.env.SOLVER_PRIVATE_KEY;

// // SOLVER_002 configuration:
// const SOLVER_ID = process.env.SOLVER_ID ?? 'SOLVER_002';
// const TEST_PRIVATE_KEY =
//   process.env.SOLVER_PRIVATE_KEY ??

const DEFAULT_TICS_AMOUNT = process.env.TICS_AMOUNT ?? null;  // null for BTC-only test
const DEFAULT_BTC_AMOUNT = process.env.BTC_AMOUNT ?? '10000';  // 10000 sats matching our BTC deposit

const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
};

function makeRequest(url, data, method = 'POST') {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'x-api-key': '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45',
      },
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(responseData);
          resolve({ status: res.statusCode, data: jsonData });
        } catch (e) {
          resolve({ status: res.statusCode, data: responseData });
        }
      });
    });

    req.on('error', (err) => reject(err));

    req.write(data);
    req.end();
  });
}

function createSignature(message, privateKeyHex) {
  const privateKey = privateKeyHex.startsWith('0x')
    ? privateKeyHex.slice(2)
    : privateKeyHex;
  const privateKeyBuffer = Buffer.from(privateKey, 'hex');

  const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
  const prefixedMessage = prefix + message;
  const messageHash = keccak('keccak256')
    .update(Buffer.from(prefixedMessage, 'utf8'))
    .digest();

  const signature = secp256k1.ecdsaSign(messageHash, privateKeyBuffer);
  const r = signature.signature.slice(0, 32);
  const s = signature.signature.slice(32, 64);
  const v = Buffer.from([27 + signature.recid]);
  return '0x' + Buffer.concat([r, s, v]).toString('hex');
}

// SOLVER_003 addresses
const SOLVER_ETH_ADDRESS = '0xbac113cebd9CB2fBD2a01B5CBC43D0fC0EBed5e9';
const SOLVER_BTC_ADDRESS = 'tb1qy2hqhhnv645vrfkusy5jga8pppytq3dw6awdn8';

async function runAddLiquidity() {
  console.log(`\n${colors.blue}🧪 Testing add liquidity...${colors.reset}`);

  // The message must be a JSON object with: solverId, solverAddress, amount, chainId
  // chainId: 0 = BTC, 9029 = EVM/TICS
  // Use CHAIN_ID env var to switch: CHAIN_ID=9029 for TICS, CHAIN_ID=0 for BTC (default)
  const chainId = parseInt(process.env.CHAIN_ID ?? '0');
  const isTics = chainId === 9029;
  console.log("chain id:::", chainId);

  const messagePayload = {
    solverId: SOLVER_ID,
    solverAddress: isTics ? SOLVER_ETH_ADDRESS : SOLVER_BTC_ADDRESS,
    amount: isTics ? (process.env.TICS_AMOUNT ?? '1000000000000000000') : DEFAULT_BTC_AMOUNT,  // 1 TICS = 1e18 wei
    chainId: chainId,
  };

  const message = JSON.stringify(messagePayload);
  const signature = createSignature(message, TEST_PRIVATE_KEY);

  const payload = {
    signature,
    message,
  };

  console.log(`${colors.yellow}📤 Sending request to ${ADD_ENDPOINT}${colors.reset}`);
  console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
  console.log(JSON.stringify(payload, null, 2));
  console.log(`${colors.yellow}📋 Message content:${colors.reset}`);
  console.log(JSON.stringify(messagePayload, null, 2));

  try {
    const response = await makeRequest(ADD_ENDPOINT, JSON.stringify(payload));
    console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
    console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
    console.log(JSON.stringify(response.data, null, 2));

    if (response.status === 200 && response.data.status === 'success') {
      console.log(`${colors.green}✅ Add liquidity request accepted${colors.reset}`);
    } else {
      console.log(`${colors.red}❌ Add liquidity request failed${colors.reset}`);
    }
  } catch (err) {
    console.error(`${colors.red}❌ Request error: ${err.message}${colors.reset}`);
  }
}

runAddLiquidity().catch((err) => {
  console.error(`${colors.red}❌ Unexpected error: ${err.stack}${colors.reset}`);
});


