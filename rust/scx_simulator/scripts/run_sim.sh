#!/bin/bash
# run_sim.sh - Run a workload through the simulator and capture the trace.
#
# Usage:
#   ./scripts/run_sim.sh [workload_test] [log_level]
#
# Examples:
#   ./scripts/run_sim.sh                          # default: two_runners with debug
#   ./scripts/run_sim.sh two_runners info         # just lifecycle events
#   ./scripts/run_sim.sh two_runners debug        # lifecycle + ops callbacks
#
# Output:
#   /tmp/scx_sim_trace.log  - simulator trace output
#
# The trace shows:
#   RUST_LOG=info  -> lifecycle events (STARTED, PREEMPTED, SLEEPING, etc.)
#   RUST_LOG=debug -> lifecycle + ops callbacks (select_cpu, enqueue, dispatch, etc.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM_DIR="$(dirname "$SCRIPT_DIR")"

WORKLOAD_TEST="${1:-two_runners}"
LOG_LEVEL="${2:-debug}"
OUTFILE="${SCX_SIM_TRACE:-/tmp/scx_sim_trace.log}"

echo "=== Simulator Trace Capture ==="
echo "  test:       test_compare_${WORKLOAD_TEST}_mitosis"
echo "  log level:  $LOG_LEVEL"
echo "  output:     $OUTFILE"
echo ""

# Run the comparison test, capturing stderr (where tracing output goes)
cd "$SIM_DIR"
RUST_LOG="$LOG_LEVEL" cargo test \
    "test_compare_${WORKLOAD_TEST}_mitosis" \
    --test compare \
    -- --nocapture 2>&1 | tee "$OUTFILE"

LINES=$(wc -l < "$OUTFILE")
echo ""
echo "Done. Trace: $OUTFILE ($LINES lines)"
echo "View: less $OUTFILE"
