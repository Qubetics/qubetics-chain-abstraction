#!/usr/bin/env node

import axios from 'axios';

// =========================
// Configuration
// =========================
const DEFAULT_BASE_URL = process.env.RPC_BASE_URL || 'http://localhost:8081';

// =========================
// Colors for console output
// =========================
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  green: '\x1b[32m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// =========================
// Helpers
// =========================
function parseArgs(argv) {
  const args = { baseUrl: DEFAULT_BASE_URL };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') {
      args.help = true;
    } else if ((a === '--url' || a === '--base-url') && argv[i + 1]) {
      args.baseUrl = argv[++i];
    } else if (a.startsWith('--url=')) {
      args.baseUrl = a.split('=')[1];
    } else if (a.startsWith('http://') || a.startsWith('https://')) {
      args.baseUrl = a;
    }
  }
  return args;
}

function formatDuration(secondsTotal) {
  const days = Math.floor(secondsTotal / 86400);
  const hours = Math.floor((secondsTotal % 86400) / 3600);
  const minutes = Math.floor((secondsTotal % 3600) / 60);
  const seconds = secondsTotal % 60;
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  parts.push(`${seconds}s`);
  return parts.join(' ');
}

// =========================
// Requests
// =========================
async function checkHeartbeat(baseUrl) {
  try {
    const res = await axios.get(`${baseUrl}/heartbeat`, { timeout: 5000 });
    const status = res.data?.status;
    if (status === 'alive') {
      log(`✅ Heartbeat OK: status=${status}`, 'green');
      return { ok: true, data: res.data };
    }
    log(`❌ Heartbeat unexpected response: ${JSON.stringify(res.data)}`, 'red');
    return { ok: false, data: res.data };
  } catch (err) {
    const msg = err.response ? `${err.response.status} ${err.response.statusText}` : err.message;
    log(`❌ Heartbeat request failed: ${msg}`, 'red');
    return { ok: false, error: msg };
  }
}

async function checkUptime(baseUrl) {
  try {
    const res = await axios.get(`${baseUrl}/uptime`, { timeout: 5000 });
    const secs = Number(res.data?.uptime_seconds ?? NaN);
    if (!Number.isFinite(secs)) {
      log(`❌ Uptime unexpected response: ${JSON.stringify(res.data)}`, 'red');
      return { ok: false, data: res.data };
    }
    log(`✅ Uptime OK: ${secs}s (${formatDuration(secs)})`, 'green');
    return { ok: true, data: res.data };
  } catch (err) {
    const msg = err.response ? `${err.response.status} ${err.response.statusText}` : err.message;
    log(`❌ Uptime request failed: ${msg}`, 'red');
    return { ok: false, error: msg };
  }
}

// =========================
// Main
// =========================
async function main() {
  const { baseUrl, help } = parseArgs(process.argv);
  if (help) {
    log(`\n${colors.bright}Usage:${colors.reset}`, 'bright');
    log(`  node check_health.js [--url <BASE_URL>]`, 'cyan');
    log(`  node check_health.js http://localhost:${process.env.RPC_PORT || 8081}`, 'cyan');
    log(`\n${colors.bright}Env:${colors.reset}`, 'bright');
    log(`  RPC_BASE_URL can be used to set the default base URL.`, 'cyan');
    process.exit(0);
  }

  log(`\n${colors.bright}🩺 Health Check${colors.reset}`, 'bright');
  log(`📍 Target RPC: ${baseUrl}`, 'cyan');

  const hb = await checkHeartbeat(baseUrl);
  const up = await checkUptime(baseUrl);

  if (hb.ok && up.ok) {
    log(`\n${colors.bright}✅ All health checks passed${colors.reset}`, 'green');
    process.exit(0);
  } else {
    log(`\n${colors.bright}❌ Health checks failed${colors.reset}`, 'red');
    process.exit(1);
  }
}

main().catch((err) => {
  log(`\n❌ Health check crashed: ${err.message}`, 'red');
  process.exit(1);
});


