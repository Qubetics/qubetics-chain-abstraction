#!/usr/bin/env bash
set -euo pipefail

# Repo root; override by passing a path as arg1
ROOT="${1:-/data/company/qubetics-chain-abstraction}"
BINARY_NAME="${BINARY_NAME:-mpc-node}"
LOG_DIR="$ROOT/logs"

log() { printf '[%s] %s\n' "$(date +'%F %T')" "$*"; }

if [[ ! -d "$ROOT" ]]; then
  echo "Root does not exist: $ROOT" >&2
  exit 1
fi

# 1) Collect PIDs from pidfiles (if present)
declare -a from_pidfiles
if [[ -d "$LOG_DIR" ]]; then
  while IFS= read -r f; do
    pid="$(cat "$f" 2>/dev/null || true)"
    [[ -n "${pid:-}" && -d "/proc/$pid" ]] || continue
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
    cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    if [[ "$exe" == *"/$BINARY_NAME" ]] && { [[ "$cwd" == "$ROOT"* ]] || [[ "$exe" == "$ROOT"* ]]; }; then
      from_pidfiles+=("$pid")
    fi
  done < <(find "$LOG_DIR" -maxdepth 1 -type f -name '*.pid' -print 2>/dev/null || true)
fi

# 2) Discover any other mpc-node PIDs under this repo (in case pidfiles are missing)
declare -a discovered
while IFS= read -r pid; do
  [[ -n "$pid" ]] || continue
  exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
  if [[ "$exe" == *"/$BINARY_NAME" ]] && { [[ "$cwd" == "$ROOT"* ]] || [[ "$exe" == "$ROOT"* ]]; }; then
    discovered+=("$pid")
  fi
done < <(pgrep -x "$BINARY_NAME" || true)

# 3) Merge unique PIDs
declare -A seen
pids=()
for pid in "${from_pidfiles[@]}" "${discovered[@]}"; do
  [[ -n "$pid" ]] || continue
  if [[ -z "${seen[$pid]:-}" ]]; then
    seen[$pid]=1
    pids+=("$pid")
  fi
done

if [[ ${#pids[@]} -eq 0 ]]; then
  echo "No $BINARY_NAME processes found under $ROOT."
  exit 0
fi

log "Stopping ${#pids[@]} $BINARY_NAME process(es): ${pids[*]}"

# 4) Try graceful first
kill -TERM "${pids[@]}" 2>/dev/null || true

# Wait up to ~10s for clean shutdown
for _ in {1..20}; do
  alive=()
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then alive+=("$pid"); fi
  done
  [[ ${#alive[@]} -eq 0 ]] && break
  sleep 0.5
done

# 5) Force kill any stubborn ones
if [[ ${#alive[@]} -gt 0 ]]; then
  log "Force-killing: ${alive[*]}"
  kill -KILL "${alive[@]}" 2>/dev/null || true
fi

# 6) Clean up dead pidfiles
if [[ -d "$LOG_DIR" ]]; then
  for f in "$LOG_DIR"/*.pid; do
    [[ -e "$f" ]] || continue
    pid="$(cat "$f" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$f"
    fi
  done
fi

log "All done."
