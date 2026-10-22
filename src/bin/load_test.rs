use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use clap::Parser;
use reqwest::Client;
use tokio::time::sleep;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "load_test", about = "Ultra-heavy GET load tester for MPC RPC")]
struct Cli {
    /// RPC base URL
    #[arg(long, default_value = "https://prod-solver-mpc-network.qubetics.work")]
    rpc: String,

    /// API key
    #[arg(long, default_value = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45")]
    apikey: String,

    /// Total concurrent async tasks
    #[arg(long, default_value_t = 1000)]
    concurrency: usize,

    /// Number of Tokio worker threads (0 = number of CPU cores)
    #[arg(long, default_value_t = 8)]
    threads: usize,

    /// Test duration in seconds
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Ramp-up period in seconds (workers start gradually)
    #[arg(long, default_value_t = 5)]
    ramp: u64,

    /// Per-request timeout in milliseconds
    #[arg(long = "timeout_ms", default_value_t = 8000)]
    timeout_ms: u64,

    /// Target RPS (0 = unlimited, go as fast as possible)
    #[arg(long = "target_rps", default_value_t = 0)]
    target_rps: u64,
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

const ADMIN_ADDR:  &str = "0xF081639bf0d9e9d09E37dFA11c51442294948f4e";
const USER_ADDR:   &str = "0xF081639bf0d9e9d09E37dFA11c51442294948f4e";
const INTENT_HASH: &str = "7763a229be77d512b6bfde3fb3fe783a230a14b460d6fe5b416c315d9e301b5a";
const PEER_ID:     &str = "12D3KooWEJK6LwRY1tX38K1QSVxsStPTqcqg3zpFd6hK629KREUn";

fn endpoints() -> Vec<&'static str> {
    vec![
        // "/status",
        // "/heartbeat",
        // "/uptime",
        "/node_id",
        "/node-info",
        "/dkg_status",
        "/get_network_addresses",
        "/intents_solved_count",
        "/pending_intents_count",
        "/user_count",
        // "/solver_liquidity",
        // "/solver_rewards",
    ]
}

fn param_endpoints() -> Vec<String> {
    vec![
        format!("/user_info/{USER_ADDR}"),
        format!("/admin_info/{ADMIN_ADDR}"),
        format!("/intent_details/{INTENT_HASH}"),
        format!("/rejoin-status/{PEER_ID}"),
        format!("/check-peer-connection/{PEER_ID}"),
    ]
}

// ─── Per-endpoint counters ────────────────────────────────────────────────────

#[derive(Default)]
struct EndpointStats {
    ok:       AtomicU64,
    err:      AtomicU64,
    timeouts: AtomicU64,
    // latency buckets in ms: [0,5), [5,20), [20,100), [100,500), [500,∞)
    lat_fast:   AtomicU64,  // < 5 ms
    lat_good:   AtomicU64,  // 5–20 ms
    lat_ok:     AtomicU64,  // 20–100 ms
    lat_slow:   AtomicU64,  // 100–500 ms
    lat_vslow:  AtomicU64,  // > 500 ms
    total_ms:   AtomicU64,
}

impl EndpointStats {
    fn record(&self, ok: bool, timed_out: bool, ms: u64) {
        if timed_out {
            self.timeouts.fetch_add(1, Ordering::Relaxed);
            self.err.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if ok {
            self.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.err.fetch_add(1, Ordering::Relaxed);
        }
        self.total_ms.fetch_add(ms, Ordering::Relaxed);
        match ms {
            0..=4   => self.lat_fast.fetch_add(1, Ordering::Relaxed),
            5..=19  => self.lat_good.fetch_add(1, Ordering::Relaxed),
            20..=99 => self.lat_ok.fetch_add(1, Ordering::Relaxed),
            100..=499 => self.lat_slow.fetch_add(1, Ordering::Relaxed),
            _         => self.lat_vslow.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn ok(&self)       -> u64 { self.ok.load(Ordering::Relaxed) }
    fn err(&self)      -> u64 { self.err.load(Ordering::Relaxed) }
    fn timeouts(&self) -> u64 { self.timeouts.load(Ordering::Relaxed) }
    fn total(&self)    -> u64 { self.ok() + self.err() }
    fn avg_ms(&self)   -> u64 {
        let t = self.total();
        if t == 0 { 0 } else { self.total_ms.load(Ordering::Relaxed) / t }
    }
}

// ─── Shared state ─────────────────────────────────────────────────────────────

struct State {
    endpoint_stats: Vec<(String, EndpointStats)>,
    total_ok:       AtomicU64,
    total_err:      AtomicU64,
    stop:           AtomicBool,
}

impl State {
    fn new(paths: Vec<String>) -> Self {
        let endpoint_stats = paths
            .into_iter()
            .map(|p| (p, EndpointStats::default()))
            .collect();
        Self {
            endpoint_stats,
            total_ok:  AtomicU64::new(0),
            total_err: AtomicU64::new(0),
            stop:      AtomicBool::new(false),
        }
    }

    fn record(&self, idx: usize, ok: bool, timed_out: bool, ms: u64) {
        self.endpoint_stats[idx].1.record(ok, timed_out, ms);
        if ok {
            self.total_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.total_err.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ─── Worker ──────────────────────────────────────────────────────────────────

async fn worker(
    id:            usize,
    state:         Arc<State>,
    client:        Client,
    base_url:      String,
    api_key:       String,
    timeout_ms:    u64,
    target_rps:    u64,
    total_workers: usize,
) {
    let n = state.endpoint_stats.len();
    // Each worker starts at a different endpoint so they spread evenly
    let mut idx = id % n;

    // Per-worker rate limiter: if target_rps > 0, each worker does
    // target_rps / total_workers requests per second
    let delay_per_req = if target_rps > 0 {
        let rps_per_worker = (target_rps as f64 / total_workers as f64).max(0.001);
        Some(Duration::from_secs_f64(1.0 / rps_per_worker))
    } else {
        None
    };

    while !state.stop.load(Ordering::Relaxed) {
        let (path, _) = &state.endpoint_stats[idx];
        let url = format!("{}{}", base_url, path);

        let t0 = Instant::now();
        let result = client
            .get(&url)
            .header("X-API-KEY", &api_key)
            .send()
            .await;
        let ms = t0.elapsed().as_millis() as u64;

        let timed_out = ms >= timeout_ms;
        let ok = match &result {
            Ok(r)  => r.status().as_u16() == 200,
            Err(_) => false,
        };

        state.record(idx, ok, timed_out, ms);

        idx = (idx + 1) % n;

        if let Some(d) = delay_per_req {
            let spent = t0.elapsed();
            if d > spent {
                sleep(d - spent).await;
            }
        }
    }
}

// ─── Reporter ─────────────────────────────────────────────────────────────────

fn clear_screen() {
    print!("\x1b[2J\x1b[H");
}

fn pad(s: &str, w: usize) -> String {
    format!("{:<width$}", s, width = w)
}

fn report(state: &State, elapsed: u64, duration: u64, prev_total: u64) -> u64 {
    let total_ok  = state.total_ok.load(Ordering::Relaxed);
    let total_err = state.total_err.load(Ordering::Relaxed);
    let total     = total_ok + total_err;
    let delta     = total.saturating_sub(prev_total);

    clear_screen();

    println!("\x1b[1m\x1b[34m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1m\x1b[34m║            MPC RPC Rust Load Tester — LIVE                               ║\x1b[0m");
    println!("\x1b[1m\x1b[34m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m");
    println!("  \x1b[36mElapsed\x1b[0m  : {elapsed}s / {duration}s");
    println!("  \x1b[36mTotal\x1b[0m    : \x1b[1m{total}\x1b[0m  ✅ {total_ok}  ❌ {total_err}");
    println!("  \x1b[36mRPS\x1b[0m      : \x1b[1m\x1b[32m{delta}\x1b[0m req/s (last second)");
    println!("  \x1b[36mOverall\x1b[0m  : \x1b[1m{:.1}\x1b[0m req/s avg", if elapsed > 0 { total as f64 / elapsed as f64 } else { 0.0 });
    println!();

    println!(
        "\x1b[2m{}\x1b[0m",
        format!(
            "{} {} {} {} {} {} {}",
            pad("ENDPOINT", 40),
            pad("OK", 8),
            pad("ERR", 8),
            pad("TIMEOUT", 9),
            pad("AVG ms", 8),
            pad("ERR%", 7),
            "LATENCY DIST (<5ms | 5-20 | 20-100 | 100-500 | >500)"
        )
    );
    println!("\x1b[2m{}\x1b[0m", "─".repeat(110));

    for (path, s) in &state.endpoint_stats {
        let t   = s.total();
        let err_pct = if t > 0 { s.err() * 100 / t } else { 0 };
        let color = if s.err() > s.ok() { "\x1b[31m" }
                    else if s.err() > 0  { "\x1b[33m" }
                    else                 { "\x1b[32m" };

        let dist = format!(
            "{} | {} | {} | {} | {}",
            s.lat_fast.load(Ordering::Relaxed),
            s.lat_good.load(Ordering::Relaxed),
            s.lat_ok.load(Ordering::Relaxed),
            s.lat_slow.load(Ordering::Relaxed),
            s.lat_vslow.load(Ordering::Relaxed),
        );

        println!(
            "{}{}{} {}{}{} {}{}{} {}{}{} {} {} {}",
            color,
            pad(path, 40),
            "\x1b[0m",
            color,
            pad(&s.ok().to_string(), 8),
            "\x1b[0m",
            if s.err() > 0 { "\x1b[31m" } else { "\x1b[2m" },
            pad(&s.err().to_string(), 8),
            "\x1b[0m",
            if s.timeouts() > 0 { "\x1b[31m" } else { "\x1b[2m" },
            pad(&s.timeouts().to_string(), 9),
            "\x1b[0m",
            pad(&s.avg_ms().to_string(), 8),
            pad(&format!("{err_pct}%"), 7),
            dist,
        );
    }

    println!("\n\x1b[2m  Ctrl+C to stop early\x1b[0m");

    total
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let threads = if cli.threads == 0 {
        num_cpus()
    } else {
        cli.threads
    };

    println!("🚀 MPC Load Test");
    println!("   RPC       : {}", cli.rpc);
    println!("   Workers   : {}", cli.concurrency);
    println!("   Threads   : {threads}");
    println!("   Duration  : {}s", cli.duration);
    println!("   Ramp      : {}s", cli.ramp);
    println!("   Target RPS: {}", if cli.target_rps == 0 { "unlimited".to_string() } else { cli.target_rps.to_string() });
    println!("   Timeout   : {}ms\n", cli.timeout_ms);

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(cli));
}

async fn run(cli: Cli) {
    // Build all endpoint paths
    let mut all_paths: Vec<String> = endpoints().into_iter().map(|s| s.to_string()).collect();
    all_paths.extend(param_endpoints());

    let state = Arc::new(State::new(all_paths));

    // Build shared reqwest client — connection pool shared across all workers
    let client = Client::builder()
        .timeout(Duration::from_millis(cli.timeout_ms))
        .pool_max_idle_per_host(cli.concurrency * 2)
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client");

    let stop_flag = Arc::clone(&state);

    // Ctrl+C handler
    let stop_on_signal = Arc::clone(&stop_flag);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        stop_on_signal.stop.store(true, Ordering::Relaxed);
    });

    // Spawn workers with linear ramp-up
    let ramp_delay_each = if cli.concurrency > 1 {
        cli.ramp * 1000 / (cli.concurrency as u64)
    } else {
        0
    };

    let mut handles = Vec::with_capacity(cli.concurrency);
    for i in 0..cli.concurrency {
        let state_c  = Arc::clone(&state);
        let client_c = client.clone();
        let base_url = cli.rpc.clone();
        let api_key  = cli.apikey.clone();
        let timeout  = cli.timeout_ms;
        let trps     = cli.target_rps;
        let nw       = cli.concurrency;
        let delay_ms = ramp_delay_each * i as u64;

        handles.push(tokio::spawn(async move {
            if delay_ms > 0 {
                sleep(Duration::from_millis(delay_ms)).await;
            }
            worker(i, state_c, client_c, base_url, api_key, timeout, trps, nw).await;
        }));
    }

    // Live reporting loop
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let mut elapsed = 0u64;
    let mut prev_total = 0u64;

    while Instant::now() < deadline && !state.stop.load(Ordering::Relaxed) {
        sleep(Duration::from_secs(1)).await;
        elapsed += 1;
        prev_total = report(&state, elapsed, cli.duration, prev_total);
    }

    // Signal all workers to stop
    state.stop.store(true, Ordering::Relaxed);

    // Wait for all workers to finish
    for h in handles {
        let _ = h.await;
    }

    // Final report
        report(&state, cli.duration, cli.duration, 0);

    let total_ok  = state.total_ok.load(Ordering::Relaxed);
    let total_err = state.total_err.load(Ordering::Relaxed);
    let total     = total_ok + total_err;
    let avg_rps   = total as f64 / cli.duration as f64;

    println!("\n\x1b[1m\x1b[32m════════════════════════════════════════\x1b[0m");
    println!("\x1b[1m\x1b[32m  Load test complete\x1b[0m");
    println!("  Total requests : {total}");
    println!("  OK             : {total_ok}");
    println!("  Errors         : {total_err}");
    println!("  Avg RPS        : \x1b[1m{avg_rps:.1}\x1b[0m");
    println!("\x1b[1m\x1b[32m════════════════════════════════════════\x1b[0m\n");
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
