/**
 * Hit MPC RPC GET /solver_rewards to fetch unclaimed rewards for a solver.
 * Usage:
 *   node get_unclaimed_rewards.js
 *   SOLVER_ETH_ADDRESS=0x... node get_unclaimed_rewards.js
 */
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../../.env') });

const MPC_RPC_URL = process.env.MPC_RPC_URL || 'http://127.0.0.1:8082';
const SOLVER_ETH_ADDRESS ="0xAb3d14Eaf3aea6d276bEcB9065eEa48C5c3e4826";

if (!SOLVER_ETH_ADDRESS) {
  console.error('Set SOLVER_ETH_ADDRESS in .env or pass it when running.');
  process.exit(1);
}

const url = `${MPC_RPC_URL.replace(/\/$/, '')}/solver_rewards?solver_address=${encodeURIComponent(SOLVER_ETH_ADDRESS)}`;

const headers = {};
const apiKey = process.env.RPC_API_KEY;
if (apiKey) headers['x-api-key'] = apiKey;

async function main() {
  console.log('GET', url);
  const res = await fetch(url, { method: 'GET', headers });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { error: text };
  }

  if (!res.ok) {
    console.error('RPC error:', res.status, data);
    process.exit(1);
  }

  console.log(JSON.stringify(data, null, 2));

  if (data.status === 'success' && data.unclaimed_rewards) {
    const n = data.unclaimed_rewards.length;
    console.log('\nUnclaimed reward requests:', n);
    data.unclaimed_rewards.forEach((r, i) => {
      console.log(`  [${i + 1}] ${r.request_id}  status=${r.status}  tx_id=${r.tx_id || '-'}`);
    });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
