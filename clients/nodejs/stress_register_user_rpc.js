#!/usr/bin/env node
/**
 * Stress-test MPC RPC: fire many register_user requests (optionally capped concurrency).
 *
 * Usage:
 *   node stress_register_user_rpc.js [--count N] [--concurrency C] [--multi] [--url BASE_URL] [--api-key KEY]
 *
 *   --count N         Total number of requests (default: 500).
 *   --concurrency C   Max parallel requests (default: 500). Lower to avoid ECONNRESET.
 *   --multi           Use N different wallets (registers N users); else one wallet, N stress requests.
 *   --url             RPC base URL (default: http://127.0.0.1:8082).
 *   --api-key         X-API-KEY header (default from env RPC_API_KEY or hardcoded).
 *
 * Env: RPC_BASE_URL, RPC_API_KEY
 */

import axios from 'axios';
import { Wallet } from 'ethers';
import { randomBytes } from 'crypto';

const RPC_BASE_URL = process.env.RPC_BASE_URL ?? 'http://127.0.0.1:8082';
const API_KEY = process.env.RPC_API_KEY ?? '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

function parseArgs() {
  const args = process.argv.slice(2);
  let count = 500;
  let concurrency = 500;
  let multi = false;
  let url = RPC_BASE_URL;
  let apiKey = API_KEY;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--count' && args[i + 1] != null) {
      count = Math.max(1, parseInt(args[i + 1], 10) || 500);
      i++;
    } else if (args[i] === '--concurrency' && args[i + 1] != null) {
      concurrency = Math.max(1, parseInt(args[i + 1], 10) || 500);
      i++;
    } else if (args[i] === '--multi') {
      multi = true;
    } else if (args[i] === '--url' && args[i + 1] != null) {
      url = args[i + 1];
      i++;
    } else if (args[i] === '--api-key' && args[i + 1] != null) {
      apiKey = args[i + 1];
      i++;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Stress register_user RPC

  node stress_register_user_rpc.js [options]

Options:
  --count N       Total requests (default: 500)
  --concurrency C Max parallel requests (default: 500). Use lower to avoid ECONNRESET.
  --multi         Use N different wallets (registers N users); else one wallet
  --url URL       RPC base URL (default: ${RPC_BASE_URL})
  --api-key K     X-API-KEY header
  -h, --help      Show this help

Env: RPC_BASE_URL, RPC_API_KEY
`);
      process.exit(0);
    }
  }
  return { count, concurrency, multi, url, apiKey };
}

/** Run at most `concurrency` tasks in parallel; process all items in `items` with `fn`. */
async function runWithConcurrency(items, concurrency, fn) {
  const results = [];
  let index = 0;
  async function worker() {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i], i).catch((e) => ({ status: 0, error: e.code || e.message }));
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

function randomWallet() {
  const hex = '0x' + randomBytes(32).toString('hex');
  return new Wallet(hex);
}

async function registerOne(baseUrl, apiKey, wallet) {
  const ethereumAddress = await wallet.getAddress();
  const timestamp = Math.floor(Date.now() / 1000);
  const message = `register:${ethereumAddress}:${timestamp}`;
  const signature = await wallet.signMessage(message);
  try {
    const res = await axios.post(
      `${baseUrl}/register_user`,
      { ethereum_address: ethereumAddress, signature, message },
      {
        headers: { 'Content-Type': 'application/json', 'X-API-KEY': apiKey },
        timeout: 30000,
        validateStatus: () => true,
      }
    );
    return { status: res.status, data: res.data, address: ethereumAddress };
  } catch (e) {
    return { status: 0, error: e.code || e.message, address: ethereumAddress };
  }
}

async function main() {
  const { count, concurrency, multi, url, apiKey } = parseArgs();
  console.log(`Target: ${url}/register_user`);
  console.log(`Count: ${count} | Concurrency: ${concurrency} | Multi: ${multi}`);
  console.log('Sending requests...\n');

  const start = Date.now();
  let wallets;
  if (multi) {
    wallets = Array.from({ length: count }, () => randomWallet());
  } else {
    const single = randomWallet();
    wallets = Array(count).fill(single);
  }

  const results = await runWithConcurrency(wallets, concurrency, (w) => registerOne(url, apiKey, w));
  const elapsed = Date.now() - start;

  let ok = 0;
  let already = 0;
  let err = 0;
  let networkErr = 0;
  const byStatus = {};
  const byNetworkError = {};
  results.forEach((r) => {
    const s = r.status;
    byStatus[s] = (byStatus[s] || 0) + 1;
    if (s === 0) {
      networkErr++;
      const code = r.error || 'unknown';
      byNetworkError[code] = (byNetworkError[code] || 0) + 1;
    } else if (s === 200 && r.data?.status === 'success') ok++;
    else if (s === 400 && (r.data?.message || '').toLowerCase().includes('already registered')) already++;
    else err++;
  });

  console.log(`Done in ${elapsed}ms (${(count / (elapsed / 1000)).toFixed(0)} req/s)`);
  console.log(`OK (registered): ${ok} | Already registered: ${already} | Other HTTP: ${err} | Network errors: ${networkErr}`);
  console.log('Status codes:', byStatus);
  if (networkErr) console.log('Network errors by code:', byNetworkError);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
