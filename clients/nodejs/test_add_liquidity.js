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

// SOLVER_004 config
const SOLVER_ID = process.env.SOLVER_ID ?? 'SOLVER_004';
const TEST_PRIVATE_KEY =
  process.env.SOLVER_PRIVATE_KEY;

const DEFAULT_TICS_AMOUNT = process.env.TICS_AMOUNT ?? '10000000000000000000000';
const DEFAULT_BTC_AMOUNT = process.env.BTC_AMOUNT ?? null;

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

async function runAddLiquidity() {
  console.log(`\n${colors.blue}🧪 Testing add liquidity...${colors.reset}`);

  const message = `add-liquidity:${crypto.randomUUID()}`;
  const signature = createSignature(message, TEST_PRIVATE_KEY);

  const payload = {
    signature,
    message,
    solver_id: SOLVER_ID,
    amount_tics: DEFAULT_TICS_AMOUNT,
    amount_btc: DEFAULT_BTC_AMOUNT,
  };

  console.log(`${colors.yellow}📤 Sending request to ${ADD_ENDPOINT}${colors.reset}`);
  console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
  console.log(JSON.stringify(payload, null, 2));

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


