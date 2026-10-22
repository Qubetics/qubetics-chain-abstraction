#!/usr/bin/env node
/**
 * Fetch and print solver liquidity from the RPC server.
 *
 * Endpoint:
 *   GET /solver_liquidity?solver_address=0x...
 *
 * Usage:
 *   node clients/nodejs/get_solver_liquidity.js 0xYourSolverAddress
 *
 * Optional env vars:
 *   QUBETICS_RPC_URL=http://127.0.0.1:8083
 *   X_API_KEY=...
 */

import http from 'http';

const RPC_BASE_URL = process.env.QUBETICS_RPC_URL ?? 'http://127.0.0.1:8083';
const SOLVER_ADDRESS = process.argv[2];

if (!SOLVER_ADDRESS) {
  console.error('Usage: node clients/nodejs/get_solver_liquidity.js 0xYourSolverAddress');
  process.exit(1);
}

function makeGetRequest(url) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        ...(process.env.X_API_KEY ? { 'x-api-key': process.env.X_API_KEY } : {}),
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
    req.end();
  });
}

async function main() {
  const url = `${RPC_BASE_URL}/solver_liquidity?solver_address=${encodeURIComponent(
    SOLVER_ADDRESS,
  )}`;

  const resp = await makeGetRequest(url);
  console.log(JSON.stringify(resp.data, null, 2));
}

main().catch((err) => {
  console.error(`Error: ${err?.stack ?? err}`);
  process.exit(1);
});


