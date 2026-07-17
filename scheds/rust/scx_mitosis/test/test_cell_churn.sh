#!/bin/bash
# Verify that CellManager can destroy and recreate child cells without exhausting IDs.

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP_BASE="/sys/fs/cgroup/test.slice"
LOG_FILE="/tmp/scx_mitosis_exhaust.log"
MONITOR_OUTPUT="/tmp/scx_mitosis_exhaust_monitor.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

if [[ ! -x "$SCHEDULER_BIN" ]]; then
    echo -e "${RED}Scheduler binary not found: $SCHEDULER_BIN${NC}"
    echo -e "${RED}Please build with: cargo build --release -p scx_mitosis${NC}"
    exit 1
fi

if [[ ! -f "/sys/kernel/sched_ext/state" ]]; then
    echo -e "${RED}sched_ext not available (missing /sys/kernel/sched_ext/state)${NC}"
    exit 1
fi

NUM_CPUS=$(nproc)
INITIAL_CELLS=$(( NUM_CPUS > 9 ? 8 : NUM_CPUS - 1 ))
if [[ "$INITIAL_CELLS" -lt 2 ]]; then
    echo -e "${RED}Need at least 3 CPUs to run managed exhaustion test${NC}"
    exit 1
fi
REMOVE_COUNT=$(( INITIAL_CELLS / 2 ))
if [[ "$REMOVE_COUNT" -lt 1 ]]; then
    REMOVE_COUNT=1
fi

cleanup() {
    echo -e "\n${YELLOW}Cleanup...${NC}"
    pkill -9 scx_mitosis 2>/dev/null || true

    for cg in "$CGROUP_BASE"/test_exhaust_batch1_* "$CGROUP_BASE"/test_exhaust_batch2_*; do
        if [[ -d "$cg" ]]; then
            while read -r pid; do
                [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
            done < <(cat "$cg/cgroup.procs" 2>/dev/null || true)
            rmdir "$cg" 2>/dev/null || true
        fi
    done

    if [[ -d "$CGROUP_BASE" ]]; then
        while read -r pid; do
            [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
        done < <(cat "$CGROUP_BASE/cgroup.procs" 2>/dev/null || true)
        rmdir "$CGROUP_BASE" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}MANAGED CELL EXHAUSTION / REUSE TEST${NC}"
echo -e "${YELLOW}========================================${NC}\n"

mkdir -p "$CGROUP_BASE"
if ! grep -q "cpu" "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
    echo "+cpu" > "$CGROUP_BASE/cgroup.subtree_control"
fi

echo -e "${YELLOW}Starting scx_mitosis with managed parent /test.slice${NC}"
"$SCHEDULER_BIN" --cell-parent-cgroup /test.slice > "$LOG_FILE" 2>&1 &
SCHED_PID=$!
sleep 3

if ! ps -p "$SCHED_PID" > /dev/null 2>&1; then
    echo -e "${RED}scx_mitosis failed to start${NC}"
    cat "$LOG_FILE"
    exit 1
fi

if [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" != "enabled" ]]; then
    echo -e "${RED}sched_ext did not enable${NC}"
    cat "$LOG_FILE"
    exit 1
fi

echo -e "${YELLOW}PHASE 1: Creating $INITIAL_CELLS managed child cgroups${NC}"
for i in $(seq 1 "$INITIAL_CELLS"); do
    cg="$CGROUP_BASE/test_exhaust_batch1_$i"
    mkdir -p "$cg"
    echo "  Created child cgroup $i"
    sleep 0.2
done
sleep 2

created_batch1=$(grep -c "Created cell .*test_exhaust_batch1_" "$LOG_FILE" || true)
if [[ "$created_batch1" -lt "$INITIAL_CELLS" ]]; then
    echo -e "${RED}Expected $INITIAL_CELLS created cells, saw $created_batch1${NC}"
    cat "$LOG_FILE"
    exit 1
fi

echo -e "\n${YELLOW}PHASE 2: Destroying $REMOVE_COUNT child cgroups${NC}"
for i in $(seq 1 "$REMOVE_COUNT"); do
    cg="$CGROUP_BASE/test_exhaust_batch1_$i"
    rmdir "$cg"
    echo "  Removed child cgroup $i"
    sleep 0.2
done
sleep 2

destroyed_count=$(grep -c "Destroyed cell .*test_exhaust_batch1_" "$LOG_FILE" || true)
if [[ "$destroyed_count" -lt "$REMOVE_COUNT" ]]; then
    echo -e "${RED}Expected at least $REMOVE_COUNT destroyed cells, saw $destroyed_count${NC}"
    cat "$LOG_FILE"
    exit 1
fi

echo -e "\n${YELLOW}PHASE 3: Creating $REMOVE_COUNT replacement child cgroups${NC}"
for i in $(seq 1 "$REMOVE_COUNT"); do
    cg="$CGROUP_BASE/test_exhaust_batch2_$i"
    mkdir -p "$cg"
    echo "  Created replacement child cgroup $i"
    sleep 0.2
done
sleep 2

created_batch2=$(grep -c "Created cell .*test_exhaust_batch2_" "$LOG_FILE" || true)
if [[ "$created_batch2" -lt "$REMOVE_COUNT" ]]; then
    echo -e "${RED}Expected $REMOVE_COUNT replacement cells, saw $created_batch2${NC}"
    cat "$LOG_FILE"
    exit 1
fi

timeout 4 "$SCHEDULER_BIN" --monitor 1 > "$MONITOR_OUTPUT" 2>/dev/null || true

expected_cells=$(( INITIAL_CELLS + 1 ))
python3 - <<PY
import json
import sys

text = open("$MONITOR_OUTPUT", "r").read()
decoder = json.JSONDecoder()
obj = None
pos = 0
while pos < len(text):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    if pos >= len(text):
        break
    try:
        parsed, end = decoder.raw_decode(text, pos)
    except json.JSONDecodeError:
        break
    obj = parsed
    pos = end

if obj is None:
    print("no monitor data captured", file=sys.stderr)
    sys.exit(1)

num_cells = obj.get("num_cells")
expected = $expected_cells
if num_cells != expected:
    print(f"expected num_cells={expected}, got {num_cells}", file=sys.stderr)
    sys.exit(1)
PY

echo -e "\n${GREEN}PASS${NC}: managed child churn did not exhaust cells"
