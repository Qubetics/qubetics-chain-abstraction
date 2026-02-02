#!/usr/bin/env node

/**
 * Call the MPC withdraw_liquidity RPC endpoint.
 * The solver signs a message; MPC validates against the SolverManager contract, then queues
 * the request. Batch processing (BTC on global clock / TICS when implemented) produces tx_ids
 * later; this call returns immediately with status "success" and a request-queued message.
 *
 * Usage:
 *   # TICS withdraw (set ethereum_address for destination)
 *   SOLVER_PRIVATE_KEY=0x... QUBETICS_RPC_URL=http://127.0.0.1:8083 \
 *     AMOUNT_TICS=1000000000000000000 node test_withdraw_liquidity.js
 *
 *   # BTC withdraw (set btc_address for destination)
 *   SOLVER_PRIVATE_KEY=0x... AMOUNT_BTC=10000 node test_withdraw_liquidity.js
 *
 * Env:
 *   QUBETICS_RPC_URL - MPC RPC base URL (default http://127.0.0.1:8083)
 *   RPC_API_KEY      - optional x-api-key header
 *   SOLVER_PRIVATE_KEY - solver's key (recovered address must be a registered solver on contract)
 *   AMOUNT_TICS      - amount in wei (string) for TICS withdraw; omit or null for BTC-only
 *   AMOUNT_BTC       - amount in sats (string) for BTC withdraw; omit or null for TICS-only
 *   ETH_ADDRESS      - destination for TICS (required if AMOUNT_TICS set)
 *   BTC_ADDRESS      - destination for BTC (required if AMOUNT_BTC set)
 */

import http from 'http';
import crypto from 'crypto';
import secp256k1 from 'secp256k1';
import keccak from 'keccak';

const RPC_BASE_URL = process.env.QUBETICS_RPC_URL ?? 'http://127.0.0.1:8083';
const WITHDRAW_ENDPOINT = `${RPC_BASE_URL}/withdraw_liquidity`;
const API_KEY = process.env.RPC_API_KEY ?? '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

const SOLVER_PRIVATE_KEY =
  process.env.SOLVER_PRIVATE_KEY ??
  '0x93cc7fbc4bfd7fcfd83d11c85ba522f8fa1c03ece1a3b5f1782bc164996844d9';
const ETH_ADDRESS = process.env.ETH_ADDRESS ?? null;
const BTC_ADDRESS = process.env.BTC_ADDRESS ?? 'mhF1CH8uxvYLhMzzGGqrxWYi4cWceXMEYB';
const AMOUNT_TICS = process.env.AMOUNT_TICS ?? null;
const AMOUNT_BTC = process.env.AMOUNT_BTC ?? null;

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
        'x-api-key': API_KEY,
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
  console.log(`\n${colors.blue}🧪 MPC withdraw_liquidity (queued; tx_id after batch)${colors.reset}`);

  const derivedAddress = getEthereumAddress(SOLVER_PRIVATE_KEY);
  console.log(
    `${colors.blue}🔑 Solver address (from SOLVER_PRIVATE_KEY): ${derivedAddress}${colors.reset}`,
  );

  const message = `withdraw-liquidity:${crypto.randomUUID()}`;
  const signature = createSignature(message, SOLVER_PRIVATE_KEY);

  const payload = {
    signature,
    message,
    ethereum_address: ETH_ADDRESS || (AMOUNT_TICS ? derivedAddress : null),
    btc_address: AMOUNT_BTC ? BTC_ADDRESS : null,
    amount_tics: AMOUNT_TICS || null,
    amount_btc: AMOUNT_BTC || null,
  };

  if ((AMOUNT_TICS && !payload.ethereum_address) || (AMOUNT_BTC && !payload.btc_address)) {
    console.error(
      `${colors.red}❌ ETH_ADDRESS required for TICS withdraw; BTC_ADDRESS required for BTC withdraw${colors.reset}`,
    );
    process.exit(1);
  }
  if (!AMOUNT_TICS && !AMOUNT_BTC) {
    console.error(
      `${colors.red}❌ Set AMOUNT_TICS and/or AMOUNT_BTC (only one per request)${colors.reset}`,
    );
    process.exit(1);
  }
  if (AMOUNT_TICS && AMOUNT_BTC) {
    console.error(
      `${colors.red}❌ Only one of AMOUNT_TICS or AMOUNT_BTC per request${colors.reset}`,
    );
    process.exit(1);
  }

  console.log(`${colors.yellow}📤 POST ${WITHDRAW_ENDPOINT}${colors.reset}`);
  console.log(`${colors.yellow}📋 Payload:${colors.reset}`);
  console.log(JSON.stringify(payload, null, 2));

  try {
    const response = await makeRequest(WITHDRAW_ENDPOINT, JSON.stringify(payload));
    console.log(`${colors.yellow}📥 Status: ${response.status}${colors.reset}`);
    console.log(`${colors.yellow}📥 Body:${colors.reset}`);
    console.log(JSON.stringify(response.data, null, 2));

    if (response.status === 200 && response.data.status === 'success') {
      console.log(`${colors.green}✅ Withdraw request queued for batch processing${colors.reset}`);
      console.log(`${colors.green}   Message: ${response.data.message}${colors.reset}`);
      if (response.data.tics_withdraw_tx_id) {
        console.log(
          `${colors.green}   TICS tx_id: ${response.data.tics_withdraw_tx_id}${colors.reset}`,
        );
      }
      if (response.data.btc_withdraw_tx_id) {
        console.log(
          `${colors.green}   BTC tx_id: ${response.data.btc_withdraw_tx_id}${colors.reset}`,
        );
      }
    } else {
      console.log(`${colors.red}❌ Withdraw request failed${colors.reset}`);
      if (response.data?.error_message) {
        console.log(`${colors.red}   ${response.data.error_message}${colors.reset}`);
      }
    }
  } catch (err) {
    console.error(`${colors.red}❌ Request error: ${err.message}${colors.reset}`);
    process.exit(1);
  }
}

runWithdrawLiquidityTest().catch((err) => {
  console.error(`${colors.red}❌ ${err.stack}${colors.reset}`);
  process.exit(1);
});
