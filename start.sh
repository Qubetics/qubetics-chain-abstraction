#!/usr/bin/env bash
set -euo pipefail

# --- Config ---
ROOT="/data/company/qubetics-chain-abstraction"
BIN="$ROOT/target/release/mpc-node"
ROOT_LOGS="$ROOT/logs"   # your app writes main logs here
PATTERN='/ip4/127\.0\.0\.1/tcp/[0-9]+/p2p/[A-Za-z0-9]+'
WAIT_SECS=90
DELAY_SECS=5             # 5s before first peer and 5s between peers

log(){ printf '[%s] %s\n' "$(date +'%F %T')" "$*"; }

cd "$ROOT"

# --- Clean exactly as requested ---
log "Cleaning logs/, data/, node*/* ..."
rm -rf "$ROOT_LOGS" "$ROOT/data"
mkdir -p "$ROOT_LOGS"
shopt -s nullglob
for d in "$ROOT"/node*/; do rm -rf "${d:?}"/*; done
shopt -u nullglob

# --- Build ---
log "cargo build --release ..."
cargo build --release
[[ -x "$BIN" ]] || { echo "FATAL: $BIN not found"; exit 1; }

# --- Discover node directories (node1, node2, ...) in numeric order ---
readarray -t NODES < <(find "$ROOT" -maxdepth 1 -type d -name 'node*' -printf '%f\n' | sort -V)
((${#NODES[@]})) || { echo "No node*/ directories found."; exit 1; }

# --- Copy binary into each node dir ---
for n in "${NODES[@]}"; do
  cp -f "$BIN" "$ROOT/$n/mpc-node"
  chmod +x "$ROOT/$n/mpc-node"
done

# --- Start MAIN from ROOT (no log redirection; silence terminal) ---
log "Starting MAIN node ..."
"$BIN" >/dev/null 2>&1 &
MAIN_PID=$!
echo "$MAIN_PID" > "$ROOT_LOGS/main.pid"
log "MAIN PID: $MAIN_PID"

# --- Wait for localhost multiaddr by scanning app-written logs/*.log ---
log "Waiting for /ip4/127.0.0.1/... in $ROOT_LOGS (timeout ${WAIT_SECS}s) ..."
MULTIADDR=""
for _ in $(seq 1 "$WAIT_SECS"); do
  MULTIADDR="$(grep -Eo "$PATTERN" "$ROOT_LOGS"/*.log 2>/dev/null | head -n1 || true)"
  [[ -n "$MULTIADDR" ]] && break
  sleep 1
done
if [[ -z "$MULTIADDR" ]]; then
  echo "FATAL: No localhost multiaddr found in $ROOT_LOGS/*.log after ${WAIT_SECS}s."
  exit 1
fi
log "Bootstrap: $MULTIADDR"

# --- 5s pause before launching peers ---
log "Pausing ${DELAY_SECS}s before starting peers..."
sleep "$DELAY_SECS"

# --- Start peers from their node dirs (no log redirection; silence terminal) ---
for i in "${!NODES[@]}"; do
  n="${NODES[$i]}"
  log "Starting $n ..."
  (
    cd "$ROOT/$n"
    ./mpc-node "$MULTIADDR" >/dev/null 2>&1 &
    echo $! > "$ROOT/$n/$n.pid"
  )
  log "$n PID: $(cat "$ROOT/$n/$n.pid")"

  # 5s gap between peers (not after the last one)
  (( i < ${#NODES[@]} - 1 )) && sleep "$DELAY_SECS"
done

log "All nodes up."
echo "Bootstrap: $MULTIADDR"