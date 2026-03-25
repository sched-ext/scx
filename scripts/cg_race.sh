#!/bin/bash

# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
# Author: Changwoo Min <changwoo@igalia.com>
#
# Race test cgroup CPU bandwidth control by concurrently exercising:
#   - Task migration between cgroups
#   - Cgroup destruction with throttled tasks
#   - Task exit while throttled

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Stress test cgroup CPU bandwidth control with three concurrent loops:

  migrate:   Continuously swap worker groups between a high-quota and a
             low-quota cgroup to stress task migration under throttling.

  ephemeral: Repeatedly create a tight-quota cgroup, populate it with
             workers (which quickly become throttled), kill them with
             SIGKILL, and destroy the cgroup — racing cgroup exit with
             task exit while throttled.

  kill:      Repeatedly kill a group of workers running in a low-quota
             (throttled) cgroup with SIGKILL and restart them — stressing
             task exit while throttled.

OPTIONS:
  -s, --scheduler NAME     SCX scheduler to monitor (default: scx_lavd)
  -w, --workers N          Workers per group for migrate and kill loops
                           (default: 50)
  -e, --ephemeral-workers N  Workers for the ephemeral loop (default: 50)
  --swap-interval MS       Interval between migrations in ms (default: 5000)
  --ephemeral-interval MS  Time to hold the ephemeral cgroup before killing
                           workers and destroying it in ms (default: 60000).
                           Should be >= 60000 to allow the sched_ext watchdog
                           (30s timeout, ~50s detection) to fire within a cycle.
  --kill-interval MS       Kill-restart cycle interval in ms (default: 60000).
                           Should be >= 60000 for the same reason.
  -t, --time DURATION      Stop after DURATION; suffix: s=seconds, m=minutes,
                           h=hours, d=days (e.g. 30s, 5m; default: forever)
  -h, --help               Show this help and exit

EXAMPLES:
  sudo $(basename "$0")
  sudo $(basename "$0") --workers 100 --time 30m
  sudo $(basename "$0") --swap-interval 10

NOTES:
  Requires cgroupv2 with the cpu controller available.
  The specified SCX scheduler must be running before starting the test.
  If the scheduler stops (e.g. due to a task stall watchdog timeout),
  the test exits with an error.
EOF
}

# --- Defaults ---
CGROOT="/sys/fs/cgroup"
SCHEDULER="scx_lavd"
WORKERS=50
WORKERS_E=50
SWAP_MS=5000
EPHEMERAL_MS=60000
KILL_MS=60000
DURATION=0

parse_duration() {
    local arg="$1" num unit
    if [[ "$arg" =~ ^([0-9]+)([smhd]?)$ ]]; then
        num="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[2]:-s}"
    else
        echo "Error: invalid duration '$arg' (use e.g. 30s, 5m, 2h, 1d)" >&2
        exit 1
    fi
    case "$unit" in
        s) echo $(( num )) ;;
        m) echo $(( num * 60 )) ;;
        h) echo $(( num * 3600 )) ;;
        d) echo $(( num * 86400 )) ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--scheduler)         SCHEDULER="$2";                   shift 2 ;;
        -w|--workers)           WORKERS="$2";                     shift 2 ;;
        -e|--ephemeral-workers) WORKERS_E="$2";                   shift 2 ;;
        --swap-interval)        SWAP_MS="$2";                     shift 2 ;;
        --ephemeral-interval)   EPHEMERAL_MS="$2";                shift 2 ;;
        --kill-interval)        KILL_MS="$2";                     shift 2 ;;
        -t|--time)              DURATION="$(parse_duration "$2")"; shift 2 ;;
        -h|--help)              usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# --- Cgroup paths ---
CG_HIGH="${CGROOT}/cg_race_high_$$"         # high quota: migration "safe" side
CG_LOW="${CGROOT}/cg_race_low_$$"           # low quota:  throttled side
CG_EPH_PREFIX="${CGROOT}/cg_race_eph_$$"    # ephemeral cgroup prefix

# --- Control and counter files ---
RUN_FILE=$(mktemp)
CNT_MIGRATE=$(mktemp)
CNT_EPHEMERAL=$(mktemp)
CNT_KILL=$(mktemp)
echo 0 > "$CNT_MIGRATE"
echo 0 > "$CNT_EPHEMERAL"
echo 0 > "$CNT_KILL"

get_mem_used_kb() {
    awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{print t-a}' /proc/meminfo
}

# Move all worker children of parent PID $1 into cgroup $2.
move_to_cgroup() {
    local parent_pid="$1" cgpath="$2" pid
    for pid in $(pgrep -P "$parent_pid" 2>/dev/null); do
        echo "$pid" > "$cgpath/cgroup.procs" 2>/dev/null || true
    done
}

# Wait until cgroup.procs is empty, or up to 5 seconds.
wait_cgroup_empty() {
    local cgpath="$1"
    local deadline=$(( SECONDS + 5 ))
    while [[ -s "$cgpath/cgroup.procs" ]] && (( SECONDS < deadline )); do
        sleep 0.01
    done
}

# Wait until a stress-ng parent has spawned its worker children.
wait_for_workers() {
    local parent_pid="$1"
    local deadline=$(( SECONDS + 10 ))
    while ! pgrep -P "$parent_pid" > /dev/null 2>&1 && (( SECONDS < deadline )); do
        sleep 0.05
    done
}

# Kill a stress-ng group (parent + children) and wait for it to exit.
kill_workers() {
    local parent_pid="$1"
    kill -9 "$parent_pid" $(pgrep -P "$parent_pid" 2>/dev/null) 2>/dev/null || true
    wait "$parent_pid" 2>/dev/null || true
}

# Return 0 if the SCX scheduler is running, 1 otherwise.
check_scheduler() {
    pgrep -x "$SCHEDULER" > /dev/null 2>&1
}

# -------------------------------------------------------------------
# Loop A: continuously migrate worker groups between CG_HIGH and CG_LOW
# Targets: cgroup move and throttling races during relocation.
# -------------------------------------------------------------------
loop_migrate() {
    local swap_sec
    swap_sec="$(echo "scale=6; $SWAP_MS / 1000" | bc)"

    while [[ -f "$RUN_FILE" ]]; do
        move_to_cgroup "$GROUP1_PID" "$CG_LOW"
        move_to_cgroup "$GROUP2_PID" "$CG_HIGH"
        sleep "$swap_sec"

        [[ -f "$RUN_FILE" ]] || break

        move_to_cgroup "$GROUP1_PID" "$CG_HIGH"
        move_to_cgroup "$GROUP2_PID" "$CG_LOW"
        sleep "$swap_sec"

        echo $(( $(cat "$CNT_MIGRATE") + 1 )) > "$CNT_MIGRATE"
    done
}

# -------------------------------------------------------------------
# Loop B: ephemeral cgroup — create, populate, kill workers, destroy.
# Targets: racing cgroup exit with task exit while throttled.
# -------------------------------------------------------------------
loop_ephemeral() {
    local eph_sec eph_cg grp_pid idx=0
    eph_sec="$(echo "scale=6; $EPHEMERAL_MS / 1000" | bc)"

    while [[ -f "$RUN_FILE" ]]; do
        eph_cg="${CG_EPH_PREFIX}_${idx}"
        if ! mkdir "$eph_cg" 2>/dev/null; then
            sleep 0.1
            continue
        fi
        # 0.5 CPU: workers throttle quickly
        echo "50000 100000" > "$eph_cg/cpu.max"

        stress-ng --cpu "$WORKERS_E" --cpu-method matrixprod > /dev/null 2>&1 &
        grp_pid=$!
        wait_for_workers "$grp_pid"
        move_to_cgroup "$grp_pid" "$eph_cg"

        # Let workers run and get throttled
        sleep "$eph_sec"

        # Kill workers with SIGKILL while throttled, then destroy the
        # cgroup — races cgroup exit with task exit while throttled.
        kill_workers "$grp_pid"
        wait_cgroup_empty "$eph_cg"
        rmdir "$eph_cg" 2>/dev/null || true

        idx=$(( idx + 1 ))
        echo $(( $(cat "$CNT_EPHEMERAL") + 1 )) > "$CNT_EPHEMERAL"
    done
}

# -------------------------------------------------------------------
# Loop C: kill-restart workers in a throttled cgroup.
# Targets: task exit while throttled in the BTQ.
# -------------------------------------------------------------------
loop_kill_restart() {
    local kill_sec grp_pid
    kill_sec="$(echo "scale=6; $KILL_MS / 1000" | bc)"

    stress-ng --cpu "$WORKERS" --cpu-method matrixprod > /dev/null 2>&1 &
    grp_pid=$!
    wait_for_workers "$grp_pid"
    move_to_cgroup "$grp_pid" "$CG_LOW"

    while [[ -f "$RUN_FILE" ]]; do
        # Let workers run and get throttled.
        sleep "$kill_sec"

        [[ -f "$RUN_FILE" ]] || break

        # Kill all workers with SIGKILL while they are throttled.
        kill_workers "$grp_pid"

        # Restart a fresh group in the same throttled cgroup.
        stress-ng --cpu "$WORKERS" --cpu-method matrixprod > /dev/null 2>&1 &
        grp_pid=$!
        wait_for_workers "$grp_pid"
        move_to_cgroup "$grp_pid" "$CG_LOW"

        echo $(( $(cat "$CNT_KILL") + 1 )) > "$CNT_KILL"
    done

    kill_workers "$grp_pid"
}

# -------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------
cleanup() {
    echo ""
    echo "=== Cleaning up ==="

    # Signal all loops to stop.
    rm -f "$RUN_FILE"
    sleep 1

    # Kill all remaining stress-ng processes.
    pkill -9 stress-ng 2>/dev/null || true
    sleep 1

    wait 2>/dev/null || true

    # Remove any remaining ephemeral cgroups and the main cgroups.
    rmdir "${CG_EPH_PREFIX}"_* 2>/dev/null || true
    rmdir "$CG_HIGH" 2>/dev/null || true
    rmdir "$CG_LOW"  2>/dev/null || true

    rm -f "$CNT_MIGRATE" "$CNT_EPHEMERAL" "$CNT_KILL"
    echo "Cgroups removed."

    local trace_file
    for trace_file in /sys/kernel/debug/tracing/trace /sys/kernel/tracing/trace; do
        if [[ -r "$trace_file" ]]; then
            echo ""
            echo "=== BPF trace output (last 100 lines) ==="
            tail -n 100 "$trace_file"
            break
        fi
    done
}

trap cleanup EXIT

# -------------------------------------------------------------------
# Validate environment
# -------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    usage >&2
    echo "Error: must run as root" >&2
    exit 1
fi

if [[ ! -f "${CGROOT}/cgroup.controllers" ]]; then
    echo "Error: '${CGROOT}' is not a cgroupv2 mount" >&2
    exit 1
fi

echo "+cpu" > "${CGROOT}/cgroup.subtree_control" || {
    echo "Error: failed to enable cpu controller in '${CGROOT}'" >&2
    exit 1
}

if ! check_scheduler; then
    echo "Error: SCX scheduler '$SCHEDULER' is not running." >&2
    echo "Please start it with the cpu.max feature enabled before running" >&2
    echo "this test (e.g. sudo $SCHEDULER --enable-cpu-bw)." >&2
    exit 1
fi

# -------------------------------------------------------------------
# Setup cgroups
# -------------------------------------------------------------------
mkdir "$CG_HIGH" "$CG_LOW"
echo "max 100000"    > "$CG_HIGH/cpu.max"   # unlimited
echo "200000 100000" > "$CG_LOW/cpu.max"    # 2 CPUs — workers throttle

if (( DURATION > 0 )); then
    DUR_STR="${DURATION}s"
else
    DUR_STR="forever"
fi

echo "Configuration:"
echo "  workers (migrate/kill) : $WORKERS"
echo "  workers (ephemeral)    : $WORKERS_E"
echo "  swap interval          : ${SWAP_MS}ms"
echo "  ephemeral hold         : ${EPHEMERAL_MS}ms ($(( EPHEMERAL_MS / 1000 ))s)"
echo "  kill interval          : ${KILL_MS}ms ($(( KILL_MS / 1000 ))s)"
echo "  duration               : ${DUR_STR}"
echo ""
echo "  CG_HIGH     : $CG_HIGH  [$(cat "$CG_HIGH/cpu.max")]"
echo "  CG_LOW      : $CG_LOW   [$(cat "$CG_LOW/cpu.max")]"
echo "  CG_EPHEMERAL: ${CG_EPH_PREFIX}_N  [50000 100000]"
echo ""

# -------------------------------------------------------------------
# Start initial worker groups for the migration loop
# -------------------------------------------------------------------
echo "Starting worker groups..."

stress-ng --cpu "$WORKERS" --cpu-method matrixprod > /dev/null 2>&1 &
GROUP1_PID=$!
stress-ng --cpu "$WORKERS" --cpu-method matrixprod > /dev/null 2>&1 &
GROUP2_PID=$!

wait_for_workers "$GROUP1_PID"
wait_for_workers "$GROUP2_PID"

move_to_cgroup "$GROUP1_PID" "$CG_HIGH"
move_to_cgroup "$GROUP2_PID" "$CG_LOW"

echo "  Group 1 (PID $GROUP1_PID): $(wc -l < "$CG_HIGH/cgroup.procs") workers in CG_HIGH"
echo "  Group 2 (PID $GROUP2_PID): $(wc -l < "$CG_LOW/cgroup.procs") workers in CG_LOW"
echo ""

# -------------------------------------------------------------------
# Launch background loops
# -------------------------------------------------------------------
loop_migrate &
LOOP_MIGRATE_PID=$!
loop_ephemeral &
LOOP_EPHEMERAL_PID=$!
loop_kill_restart &
LOOP_KILL_PID=$!

echo "Loops started:"
echo "  migrate   : PID $LOOP_MIGRATE_PID"
echo "  ephemeral : PID $LOOP_EPHEMERAL_PID"
echo "  kill      : PID $LOOP_KILL_PID"
echo ""

if (( DURATION > 0 )); then
    echo "Running for ${DUR_STR}. Press Ctrl-C to stop early."
else
    echo "Running. Press Ctrl-C to stop."
fi
echo ""

# -------------------------------------------------------------------
# Main progress loop
# -------------------------------------------------------------------
START_TIME=$SECONDS
START_MEM_KB=$(get_mem_used_kb)
PREV_MEM_KB=$START_MEM_KB
PREV_MEM_MS=$(date +%s%3N)
MEM_RATE_KBS=0
SPINNER=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
COLORS=('\e[31m' '\e[33m' '\e[32m' '\e[36m' '\e[34m' '\e[35m' '\e[31m' '\e[33m')
RESET='\e[0m'

while true; do
    NOW_MS=$(date +%s%3N)
    ELAPSED=$(( SECONDS - START_TIME ))
    SPIN_IDX=$(( ( NOW_MS / 100 ) % ${#SPINNER[@]} ))

    MIGRATE=$(cat "$CNT_MIGRATE"   2>/dev/null || echo 0)
    EPHEMERAL=$(cat "$CNT_EPHEMERAL" 2>/dev/null || echo 0)
    KILLS=$(cat "$CNT_KILL"        2>/dev/null || echo 0)

    CUR_MEM_KB=$(get_mem_used_kb)
    MEM_DELTA_MS=$(( NOW_MS - PREV_MEM_MS ))
    if (( MEM_DELTA_MS >= 100 )); then
        MEM_RATE_KBS=$(( (CUR_MEM_KB - PREV_MEM_KB) * 1000 / MEM_DELTA_MS ))
        PREV_MEM_KB=$CUR_MEM_KB
        PREV_MEM_MS=$NOW_MS
    fi
    MEM_MIB=$(( CUR_MEM_KB / 1024 ))
    MEM_CHANGE_KB=$(( CUR_MEM_KB - START_MEM_KB ))

    printf "\r ${COLORS[$SPIN_IDX]}%s${RESET}  elapsed: %-5ds  migrate: %-6d  ephemeral: %-6d  kill: %-6d  mem: %d MiB  Δ: %+d kB (%+d kB/s)   " \
        "${SPINNER[$SPIN_IDX]}" "$ELAPSED" "$MIGRATE" "$EPHEMERAL" "$KILLS" \
        "$MEM_MIB" "$MEM_CHANGE_KB" "$MEM_RATE_KBS"

    if ! check_scheduler; then
        printf "\nError: SCX scheduler '%s' has stopped — possible task stall detected.\n" "$SCHEDULER"
        exit 1
    fi

    if (( DURATION > 0 && ELAPSED >= DURATION )); then
        printf "\nTime limit reached after %ds. migrate=%d ephemeral=%d kill=%d mem Δ=%+d kB\n" \
            "$ELAPSED" "$MIGRATE" "$EPHEMERAL" "$KILLS" "$MEM_CHANGE_KB"
        exit 0
    fi

    sleep 0.2
done
