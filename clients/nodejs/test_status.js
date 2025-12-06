#!/usr/bin/env node

import axios from 'axios';

const RPC_BASE_URL = process.env.RPC_BASE_URL || 'http://127.0.0.1:8082';
const API_KEY = process.env.RPC_API_KEY || process.env.API_KEY;

function log(message) {
  console.log(message);
}

async function fetchStatus() {
  try {
    const headers = {};
    if (API_KEY) {
      headers['X-API-KEY'] = API_KEY;
    }

    const response = await axios.get(`${RPC_BASE_URL}/status`, {
      headers,
      timeout: 5000,
    });

    const { peer_id, connected_peers, dkg_status, is_ready } = response.data;
    log('✅ Node status retrieved successfully');
    log(`   Peer ID: ${peer_id}`);
    log(`   Connected peers: ${connected_peers}`);
    log(`   DKG status: ${dkg_status}`);
    log(`   Ready: ${is_ready}`);
  } catch (error) {
    if (error.response) {
      log(`❌ Request failed with status ${error.response.status}`);
      log(JSON.stringify(error.response.data, null, 2));
    } else {
      log(`❌ Error reaching node status endpoint: ${error.message}`);
    }
    process.exitCode = 1;
  }
}

fetchStatus();
