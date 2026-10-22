#!/usr/bin/env node

/**
 * Ultra-heavy load test for the MPC RPC ecosystem.
 *
 * Hammers all GET endpoints concurrently across configurable concurrency
 * levels and reports per-endpoint latency, throughput, and error rates.
 *
 * Usage:
 *   node load_test.js                        # default config
 *   node load_test.js --concurrency 200      # 200 parallel workers
 *   node load_test.js --duration 120         # run for 120 seconds
 *   node load_test.js --rpc http://x.x.x.x:8082
 *   node load_test.js --concurrency 500 --duration 60 --ramp 10
 */

import http from 'http';
import { parseArgs } from 'util';

// ─── CLI args ─────────────────────────────────────────────────────────────────

const { values: args } = parseArgs({
    options: {
        rpc:         { type: 'string',  default: 'http://124.243.185.174:8082' },
        apikey:      { type: 'string',  default: '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45' },
        concurrency: { type: 'string',  default: '300' },
        duration:    { type: 'string',  default: '60' },
        ramp:        { type: 'string',  default: '5' },   // seconds to ramp up
        timeout:     { type: 'string',  default: '10000' },
    },
    strict: false,
});

const RPC_BASE    = args.rpc;
const API_KEY     = args.apikey;
const CONCURRENCY = parseInt(args.concurrency);
const DURATION_S  = parseInt(args.duration);
const RAMP_S      = parseInt(args.ramp);
const TIMEOUT_MS  = parseInt(args.timeout);

// ─── Colours ──────────────────────────────────────────────────────────────────

const C = {
    reset:  '\x1b[0m',
    bold:   '\x1b[1m',
    red:    '\x1b[31m',
    green:  '\x1b[32m',
    yellow: '\x1b[33m',
    blue:   '\x1b[34m',
    cyan:   '\x1b[36m',
    dim:    '\x1b[2m',
    magenta:'\x1b[35m',
};

// ─── GET endpoints ────────────────────────────────────────────────────────────
// Known registered user/admin/intent from the test environment;
// parameterised paths use real-looking values so the handler actually runs.

const ADMIN_ADDR  = '0xF081639bf0d9e9d09E37dFA11c51442294948f4e';
const USER_ADDR   = '0xF081639bf0d9e9d09E37dFA11c51442294948f4e';
const INTENT_HASH = '7763a229be77d512b6bfde3fb3fe783a230a14b460d6fe5b416c315d9e301b5a';
const PEER_ID     = '12D3KooWEJK6LwRY1tX38K1QSVxsStPTqcqg3zpFd6hK629KREUn';

const ENDPOINTS = [
    '/status',
    '/heartbeat',
    '/uptime',
    '/node_id',
    '/node-info',
    '/dkg_status',
    '/get_network_addresses',
    '/intents_solved_count',
    '/pending_intents_count',
    '/user_count',
    `/user_info/${USER_ADDR}`,
    `/admin_info/${ADMIN_ADDR}`,
    `/intent_details/${INTENT_HASH}`,
    `/solver_liquidity`,
    `/solver_rewards`,
    `/rejoin-status/${PEER_ID}`,
    `/check-peer-connection/${PEER_ID}`,
];

// ─── Per-endpoint stats ───────────────────────────────────────────────────────

const stats = {};
for (const ep of ENDPOINTS) {
    stats[ep] = { ok: 0, err: 0, latencies: [], timeouts: 0 };
}

let totalRequests = 0;
let running       = true;

// ─── HTTP helper (no external deps) ──────────────────────────────────────────

function get(path) {
    return new Promise((resolve) => {
        const u    = new URL(RPC_BASE + path);
        const opts = {
            hostname: u.hostname,
            port:     u.port || 80,
            path:     u.pathname + u.search,
            method:   'GET',
            headers:  { 'X-API-KEY': API_KEY },
        };

        const start = Date.now();
        let settled = false;

        const timer = setTimeout(() => {
            if (!settled) {
                settled = true;
                req.destroy();
                resolve({ ok: false, latency: TIMEOUT_MS, timedOut: true });
            }
        }, TIMEOUT_MS);

        const req = http.request(opts, (res) => {
            res.resume(); // drain
            res.on('end', () => {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    const latency = Date.now() - start;
                    resolve({ ok: res.statusCode < 500, latency, status: res.statusCode });
                }
            });
        });

        req.on('error', () => {
            if (!settled) {
                settled = true;
                clearTimeout(timer);
                resolve({ ok: false, latency: Date.now() - start, error: true });
            }
        });

        req.end();
    });
}

// ─── Worker ──────────────────────────────────────────────────────────────────

async function worker(workerId, rampDelay) {
    // Stagger startup across ramp window
    await new Promise(r => setTimeout(r, rampDelay));

    // Each worker cycles round-robin through endpoints
    let idx = workerId % ENDPOINTS.length;

    while (running) {
        const ep     = ENDPOINTS[idx % ENDPOINTS.length];
        const result = await get(ep);
        const s      = stats[ep];

        totalRequests++;

        if (result.timedOut) {
            s.timeouts++;
            s.err++;
        } else if (result.ok) {
            s.ok++;
            s.latencies.push(result.latency);
        } else {
            s.err++;
            if (result.latency !== undefined) s.latencies.push(result.latency);
        }

        idx++;
    }
}

// ─── Stats helpers ────────────────────────────────────────────────────────────

function percentile(arr, p) {
    if (!arr.length) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx    = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
}

function avg(arr) {
    return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
}

// ─── Progress reporter ────────────────────────────────────────────────────────

let lastTotal = 0;
let elapsed   = 0;

function report(final = false) {
    const delta  = totalRequests - lastTotal;
    lastTotal    = totalRequests;
    const rps    = final ? (totalRequests / DURATION_S).toFixed(1) : delta.toString();
    const label  = final ? 'avg RPS' : 'RPS (last s)';

    process.stdout.write('\x1b[2J\x1b[H'); // clear screen

    console.log(`${C.bold}${C.blue}╔══════════════════════════════════════════════════════════╗${C.reset}`);
    console.log(`${C.bold}${C.blue}║          MPC RPC Load Test — ${final ? 'FINAL REPORT' : 'LIVE'}                    ║${C.reset}`);
    console.log(`${C.bold}${C.blue}╚══════════════════════════════════════════════════════════╝${C.reset}`);
    console.log(`  ${C.cyan}Target${C.reset}       : ${RPC_BASE}`);
    console.log(`  ${C.cyan}Concurrency${C.reset}  : ${CONCURRENCY} workers`);
    console.log(`  ${C.cyan}Elapsed${C.reset}      : ${elapsed}s / ${DURATION_S}s`);
    console.log(`  ${C.cyan}Total reqs${C.reset}   : ${C.bold}${totalRequests}${C.reset}`);
    console.log(`  ${C.cyan}${label}${C.reset}      : ${C.bold}${C.green}${rps}${C.reset}`);
    console.log('');

    // Table header
    const col = (s, w) => s.toString().padEnd(w);
    console.log(
        C.dim +
        col('ENDPOINT', 38) +
        col('OK', 8) +
        col('ERR', 8) +
        col('TIMEOUT', 9) +
        col('AVG ms', 8) +
        col('P95 ms', 8) +
        col('P99 ms', 8) +
        C.reset
    );
    console.log(C.dim + '─'.repeat(87) + C.reset);

    for (const ep of ENDPOINTS) {
        const s    = stats[ep];
        const tot  = s.ok + s.err;
        const errRate = tot ? ((s.err / tot) * 100).toFixed(1) : '0.0';
        const color   = s.err > s.ok ? C.red : s.err > 0 ? C.yellow : C.green;

        console.log(
            col(ep, 38) +
            color + col(s.ok, 8) + C.reset +
            (s.err > 0 ? C.red : C.dim) + col(s.err, 8) + C.reset +
            (s.timeouts > 0 ? C.red : C.dim) + col(s.timeouts, 9) + C.reset +
            col(avg(s.latencies).toFixed(0), 8) +
            col(percentile(s.latencies, 95), 8) +
            col(percentile(s.latencies, 99), 8)
        );
    }

    if (!final) {
        console.log(`\n${C.dim}  Ctrl+C to stop early${C.reset}`);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
    console.log(`${C.bold}${C.cyan}Starting load test: ${CONCURRENCY} workers, ${DURATION_S}s duration, ${RAMP_S}s ramp...${C.reset}`);
    console.log(`${C.dim}  Target: ${RPC_BASE}${C.reset}\n`);

    // Spawn workers with staggered ramp-up
    const workers = [];
    for (let i = 0; i < CONCURRENCY; i++) {
        const delay = Math.floor((i / CONCURRENCY) * RAMP_S * 1000);
        workers.push(worker(i, delay));
    }

    // Live reporter — every second
    const reporter = setInterval(() => {
        elapsed++;
        report(false);
    }, 1000);

    // Stop after duration
    await new Promise(r => setTimeout(r, DURATION_S * 1000));
    running = false;
    clearInterval(reporter);

    // Drain workers
    await Promise.allSettled(workers);

    // Final report
    elapsed = DURATION_S;
    report(true);

    console.log(`\n${C.bold}${C.green}Load test complete.${C.reset}\n`);
}

process.on('SIGINT', () => {
    running = false;
    console.log(`\n${C.yellow}Interrupted — finalising...${C.reset}`);
    setTimeout(() => {
        elapsed = DURATION_S;
        report(true);
        process.exit(0);
    }, 500);
});

main().catch(e => {
    console.error(`${C.red}Fatal: ${e.message}${C.reset}`);
    process.exit(1);
});
