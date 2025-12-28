#!/usr/bin/env node

/**
 * Test script for withdraw liquidity RPC endpoint (Node.js version)
 * Mirrors the test_claim_reward.js setup so it can reuse the same keys.
 */

import http from 'http';
import crypto from 'crypto';
import secp256k1 from 'secp256k1';
import keccak from 'keccak';

// Configuration (update as needed)
const RPC_BASE_URL = 'http://127.0.0.1:8083';
const WITHDRAW_ENDPOINT = `${RPC_BASE_URL}/withdraw_liquidity`;

// Private key/address pair used in test_claim_reward.js (replace for real usage)
const TEST_PRIVATE_KEY =
  '93cc7fbc4bfd7fcfd83d11c85ba522f8fa1c03ece1a3b5f1782bc164996844d9';
const DEFAULT_ETH_ADDRESS = '0x002aF85c8865DE4604dF07a1105EfEF2b8e0dE05';
const DEFAULT_BTC_ADDRESS = 'mh12dZHkgTajT1H6t8FkWoNC4KucxByWBA';
const DEFAULT_TICS_WITHDRAW = null; // 1 TICS
const DEFAULT_BTC_WITHDRAW = '1000'; // set to string value if testing BTC

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

function getEthereumAddress(privateKeyHex) {
  const privateKey = privateKeyHex.startsWith('0x')
    ? privateKeyHex.slice(2)
    : privateKeyHex;
  const privateKeyBuffer = Buffer.from(privateKey, 'hex');
  const publicKey = secp256k1.publicKeyCreate(privateKeyBuffer, false);
  const publicKeyWithoutPrefix = Buffer.from(publicKey.slice(1));
  const hash = keccak('keccak256')
    .update(publicKeyWithoutPrefix)
    .digest();
  return '0x' + hash.slice(-20).toString('hex');
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

async function runWithdrawLiquidityTest() {
  console.log(`\n${colors.blue}🧪 Testing withdraw liquidity...${colors.reset}`);

  const derivedAddress = getEthereumAddress(TEST_PRIVATE_KEY);
  console.log(
    `${colors.blue}🔑 Derived address from private key: ${derivedAddress}${colors.reset}`,
  );

  const message = `withdraw-liquidity:${crypto.randomUUID()}`;
  const signature = createSignature(message, TEST_PRIVATE_KEY);

  const payload = {
    signature,
    message,
    ethereum_address: DEFAULT_ETH_ADDRESS || derivedAddress,
    btc_address: DEFAULT_BTC_ADDRESS,
    amount_tics: DEFAULT_TICS_WITHDRAW,
    amount_btc: DEFAULT_BTC_WITHDRAW,
  };

  console.log(`${colors.yellow}📤 Sending request to ${WITHDRAW_ENDPOINT}${colors.reset}`);
  console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
  console.log(JSON.stringify(payload, null, 2));

  try {
    const response = await makeRequest(WITHDRAW_ENDPOINT, JSON.stringify(payload));
    console.log(`${colors.yellow}📥 Response status: ${response.status}${colors.reset}`);
    console.log(`${colors.yellow}📥 Response body:${colors.reset}`);
    console.log(JSON.stringify(response.data, null, 2));

    if (response.status === 200 && response.data.status === 'success') {
      console.log(`${colors.green}✅ Withdraw liquidity request accepted${colors.reset}`);
      if (response.data.tics_withdraw_tx_id) {
        console.log(
          `${colors.green}↳ TICS tx_id: ${response.data.tics_withdraw_tx_id}${colors.reset}`,
        );
      }
      if (response.data.btc_withdraw_tx_id) {
        console.log(
          `${colors.green}↳ BTC tx_id: ${response.data.btc_withdraw_tx_id}${colors.reset}`,
        );
      }
    } else {
      console.log(`${colors.red}❌ Withdraw liquidity request failed${colors.reset}`);
    }
  } catch (err) {
    console.error(`${colors.red}❌ Request error: ${err.message}${colors.reset}`);
  }
}

runWithdrawLiquidityTest().catch((err) => {
  console.error(`${colors.red}❌ Unexpected error: ${err.stack}${colors.reset}`);
});

