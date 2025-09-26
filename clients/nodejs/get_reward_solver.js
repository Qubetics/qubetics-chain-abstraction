#!/usr/bin/env node
import axios from 'axios';

const baseUrl = process.env.RPC_BASE_URL || 'http://localhost:8082';

function usage() {
  console.log('Usage: node get_reward_solver.js <solver_address>');
  console.log('Env:   RPC_BASE_URL (default http://localhost:8082)');
}

async function main() {
  // const solver = process.argv[2];
  // if (!solver) {
  //   usage();
  //   process.exit(1);
  // }

  try {
    const res = await axios.get(`${baseUrl}/get_reward_solver`, {
      params: { solver_address: "0x84427f866Ddea4f0E140602eEE8a4b7C78d3582A" },
      timeout: 10000,
    });

    const data = res.data;
    console.log(JSON.stringify(data, null, 2));
  } catch (err) {
    if (err.response) {
      console.error(`HTTP ${err.response.status}:`, err.response.data);
    } else {
      console.error('Request error:', err.message);
    }
    process.exit(1);
  }
}

main(); 