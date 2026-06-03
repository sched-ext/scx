#!/bin/bash
#
# Verify that --cell-exclude keeps a direct child cgroup in cell 0.
#

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP_BASE="/sys/fs/cgroup/test.slice"
INCLUDED_NAME="included_workload"
EXCLUDED_NAME="excluded_workload"
LOG_FILE="/tmp/scx_mitosis_cell_exclude.log"
MONITOR_OUTPUT="/tmp/scx_mitosis_cell_exclude_monitor.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    sudo pkill -9 scx_mitosis 2>/dev/null || true

    for child in "$INCLUDED_NAME" "$EXCLUDED_NAME"; do
        local path="$CGROUP_BASE/$child"
        if [[ -d "$path" ]]; then
            while read -r pid; do
                [[ -n "$pid" ]] && sudo kill -9 "$pid" 2>/dev/null || true
            done < <(cat "$path/cgroup.procs" 2>/dev/null || true)
            sudo rmdir "$path" 2>/dev/null || true
        fi
    done

    if [[ -d "$CGROUP_BASE" ]]; then
        while read -r pid; do
            [[ -n "$pid" ]] && sudo kill -9 "$pid" 2>/dev/null || true
        done < <(cat "$CGROUP_BASE/cgroup.procs" 2>/dev/null || true)
        sudo rmdir "$CGROUP_BASE" 2>/dev/null || true
    fi
}

trap cleanup EXIT

if [[ "$EUID" -ne 0 ]]; then
    log_error "Must run as root"
    exit 1
fi

if [[ ! -x "$SCHEDULER_BIN" ]]; then
    log_error "Scheduler binary not found: $SCHEDULER_BIN"
    log_error "Please build with: cargo build --release -p scx_mitosis"
    exit 1
fi

if [[ ! -f "/sys/kernel/sched_ext/state" ]]; then
    log_error "sched_ext not available (missing /sys/kernel/sched_ext/state)"
    exit 1
fi

log_info "Preparing cgroup hierarchy under $CGROUP_BASE"
sudo mkdir -p "$CGROUP_BASE"
if ! grep -q "cpu" "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
    echo "+cpu" | sudo tee "$CGROUP_BASE/cgroup.subtree_control" > /dev/null
fi
sudo mkdir -p "$CGROUP_BASE/$INCLUDED_NAME" "$CGROUP_BASE/$EXCLUDED_NAME"

log_info "Starting scx_mitosis with --cell-exclude $EXCLUDED_NAME"
sudo "$SCHEDULER_BIN" \
    --cell-parent-cgroup /test.slice \
    --cell-exclude "$EXCLUDED_NAME" \
    > "$LOG_FILE" 2>&1 &
SCHED_PID=$!
sleep 3

if ! ps -p "$SCHED_PID" > /dev/null 2>&1; then
    log_error "Scheduler failed to start"
    cat "$LOG_FILE"
    exit 1
fi

if [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" != "enabled" ]]; then
    log_error "sched_ext did not enable"
    cat "$LOG_FILE"
    exit 1
fi

if ! grep -q "Created cell .*${INCLUDED_NAME}" "$LOG_FILE"; then
    log_error "Included child did not receive a dedicated cell"
    cat "$LOG_FILE"
    exit 1
fi

if grep -q "Created cell .*${EXCLUDED_NAME}" "$LOG_FILE"; then
    log_error "Excluded child unexpectedly received a dedicated cell"
    cat "$LOG_FILE"
    exit 1
fi

if grep -q "(${EXCLUDED_NAME})" "$LOG_FILE"; then
    log_error "Excluded child appeared in formatted cell configuration"
    cat "$LOG_FILE"
    exit 1
fi

log_info "Capturing monitor output"
timeout 4 "$SCHEDULER_BIN" --monitor 1 > "$MONITOR_OUTPUT" 2>/dev/null || true

python3 - <<'PY'
import json
import sys

path = "/tmp/scx_mitosis_cell_exclude_monitor.json"
text = open(path, "r").read()
decoder = json.JSONDecoder()
last_obj = None
pos = 0
while pos < len(text):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    if pos >= len(text):
        break
    try:
        obj, end = decoder.raw_decode(text, pos)
    except json.JSONDecodeError:
        break
    last_obj = obj
    pos = end

if last_obj is None:
    print("no monitor data captured", file=sys.stderr)
    sys.exit(1)

num_cells = last_obj.get("num_cells")
if num_cells != 2:
    print(f"expected num_cells=2, got {num_cells}", file=sys.stderr)
    sys.exit(1)
PY

log_info "Exclude behavior looks correct"
echo -e "${GREEN}PASS${NC}: excluded child remained in cell 0 behavior"
