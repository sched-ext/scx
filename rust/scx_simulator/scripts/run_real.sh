#!/bin/bash
# run_real.sh - Run a workload on the real host with a sched_ext scheduler,
#               tracing ops callbacks and lifecycle events with bpftrace.
#
# Usage:
#   sudo ./scripts/run_real.sh [workload.json] [scheduler] [nr_cpus]
#
# Examples:
#   sudo ./scripts/run_real.sh workloads/two_runners.json mitosis 4
#   sudo ./scripts/run_real.sh  # defaults: two_runners.json, mitosis, 4
#
# Output:
#   /tmp/scx_real_trace.log  - raw bpftrace output
#
# Prerequisites:
#   - scx_mitosis built:  cargo build -p scx_mitosis (from repo root)
#   - rt-app installed:   ~/bin/rt-app
#   - bpftrace installed: system package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$SIM_DIR/../.." && pwd)"

WORKLOAD="${1:-$SIM_DIR/workloads/two_runners.json}"
SCHEDULER="${2:-mitosis}"
NR_CPUS="${3:-4}"
OUTFILE="${SCX_REAL_TRACE:-/tmp/scx_real_trace.log}"

SCHED_BIN="$REPO_ROOT/target/debug/scx_${SCHEDULER}"
RTAPP_BIN="${HOME}/bin/rt-app"
BPFTRACE_SCRIPT="$SCRIPT_DIR/trace_scx_ops.bt"

# --- Validation ---
if [[ ! -x "$SCHED_BIN" ]]; then
    echo "ERROR: scheduler binary not found: $SCHED_BIN"
    echo "Build it with: cargo build -p scx_${SCHEDULER}"
    exit 1
fi
if ! command -v "$RTAPP_BIN" &>/dev/null; then
    echo "ERROR: rt-app not found at $RTAPP_BIN"
    echo "Build it from ~/playground/rt-app (see CLAUDE.md)"
    exit 1
fi
if ! command -v bpftrace &>/dev/null; then
    echo "ERROR: bpftrace not installed"
    exit 1
fi
if [[ ! -f "$WORKLOAD" ]]; then
    echo "ERROR: workload not found: $WORKLOAD"
    exit 1
fi

# Build CPU list for taskset (0,1,...,NR_CPUS-1)
CPU_LIST=$(seq -s, 0 $((NR_CPUS - 1)))

echo "=== Real Trace Capture ==="
echo "  scheduler:  $SCHED_BIN"
echo "  workload:   $WORKLOAD"
echo "  cpus:       $CPU_LIST"
echo "  output:     $OUTFILE"
echo ""

cleanup() {
    echo "Cleaning up..."
    [[ -n "${BPF_PID:-}" ]] && kill "$BPF_PID" 2>/dev/null || true
    [[ -n "${SCHED_PID:-}" ]] && kill "$SCHED_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# --- Step 1: Start the scheduler ---
echo "[1/4] Starting scx_${SCHEDULER}..."
"$SCHED_BIN" &
SCHED_PID=$!
sleep 1  # Let scheduler attach to sched_ext

# Verify it's running
if ! kill -0 "$SCHED_PID" 2>/dev/null; then
    echo "ERROR: scheduler exited prematurely"
    exit 1
fi
echo "  scheduler pid=$SCHED_PID"

# --- Step 2: Start bpftrace ---
echo "[2/4] Starting bpftrace..."
bpftrace "$BPFTRACE_SCRIPT" "$NR_CPUS" > "$OUTFILE" 2>&1 &
BPF_PID=$!
sleep 1  # Let bpftrace attach probes

if ! kill -0 "$BPF_PID" 2>/dev/null; then
    echo "ERROR: bpftrace exited prematurely. Check $OUTFILE for errors."
    exit 1
fi
echo "  bpftrace pid=$BPF_PID"

# --- Step 3: Run workload ---
echo "[3/4] Running rt-app (pinned to CPUs $CPU_LIST)..."
taskset -c "$CPU_LIST" "$RTAPP_BIN" "$WORKLOAD"
echo "  workload complete"

# --- Step 4: Collect ---
echo "[4/4] Stopping traces..."
sleep 1  # Let buffered events flush
kill "$BPF_PID" 2>/dev/null || true
wait "$BPF_PID" 2>/dev/null || true
BPF_PID=""

kill "$SCHED_PID" 2>/dev/null || true
wait "$SCHED_PID" 2>/dev/null || true
SCHED_PID=""

LINES=$(wc -l < "$OUTFILE")
echo ""
echo "Done. Trace: $OUTFILE ($LINES lines)"
echo "View: less $OUTFILE"
