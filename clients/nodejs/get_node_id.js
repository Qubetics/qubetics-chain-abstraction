#!/usr/bin/env node
import axios from 'axios';

const baseUrl = process.env.RPC_BASE_URL || 'http://localhost:8081';

async function main() {
  try {
    const res = await axios.get(`${baseUrl}/node_id`, { timeout: 5000 });
    console.log(`Node ID: ${res.data.node_id}`);
  } catch (err) {
    const msg = err.response ? `${err.response.status} ${err.response.statusText}` : err.message;
    console.error(`Failed to fetch node id: ${msg}`);
    process.exit(1);
  }
}

main();
