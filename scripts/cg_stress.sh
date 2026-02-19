#!/bin/bash

# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
# Author: Changwoo Min <changwoo@igalia.com>
#
# Stress test cgroupv2 by repeatedly creating and deleting cgroups.

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Stress test cgroupv2 by repeatedly creating and deleting cgroups.

Each iteration:
  1. Create BATCH cgroups under PARENT, each with cpu.max set to "max 100000"
  2. Sleep for DELAY ms
  3. Delete all created cgroups
  4. Repeat

OPTIONS:
  -p, --parent PATH    Parent cgroupv2 path (default: /sys/fs/cgroup)
  -n, --prefix NAME    Cgroup name prefix (default: test_cg)
  -d, --delay MS       Delay in milliseconds between create and delete
                       phases (default: 1)
  -b, --batch N        Number of cgroups to create per iteration (default: 1000)
  -t, --time DURATION  Stop after DURATION; suffix: s=seconds, m=minutes,
                       h=hours, d=days (e.g. 30s, 5m, 2h, 1d; default: run forever)
  --no-drop-caches     Skip dropping page caches after each iteration
                       (default: drop caches to reduce noise in memory stats)
  -h, --help           Show this help and exit

EXAMPLES:
  sudo $(basename "$0")
  sudo $(basename "$0") --delay 50 --batch 20
  sudo $(basename "$0") --parent /sys/fs/cgroup/myslice --prefix stress --delay 0
  sudo $(basename "$0") --time 30s
  sudo $(basename "$0") --time 5m

NOTES:
  Requires a kernel with cgroupv2 and the cpu controller available.
  The cpu controller is enabled in PARENT via cgroup.subtree_control.
  Progress is printed every 100 iterations.
EOF
}

PARENT="/sys/fs/cgroup"
PREFIX="test_cg"
DELAY_MS=1
BATCH=1000
DURATION=0  # 0 means run forever
DROP_CACHES=1

parse_duration() {
    local arg="$1"
    local num unit
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

get_mem_used_kb() {
    awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{print t-a}' /proc/meminfo
}

drop_caches() {
    echo 3 > /proc/sys/vm/drop_caches
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--parent) PARENT="$2"; shift 2 ;;
        -n|--prefix) PREFIX="$2"; shift 2 ;;
        -d|--delay)  DELAY_MS="$2"; shift 2 ;;
        -b|--batch)  BATCH="$2"; shift 2 ;;
        -t|--time)        DURATION="$(parse_duration "$2")"; shift 2 ;;
        --no-drop-caches) DROP_CACHES=0; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done
COUNT=0

cleanup() {
    local final_mem_kb final_change_kb
    final_mem_kb=$(get_mem_used_kb)
    final_change_kb=$(( final_mem_kb - START_MEM_KB ))
    printf "\nInterrupted after %d iterations (%d cgroups). Mem change: %+d kB. Cleaning up...\n" \
        "$COUNT" "$(( COUNT * BATCH ))" "$final_change_kb"
    rmdir "${PARENT}/${PREFIX}"_* 2>/dev/null
    exit 0
}

trap cleanup INT TERM

if [[ ! -d "$PARENT" ]]; then
    echo "Error: parent path '$PARENT' does not exist" >&2
    exit 1
fi

if [[ ! -f "${PARENT}/cgroup.controllers" ]]; then
    echo "Error: '${PARENT}' is not a cgroupv2 mount (no cgroup.controllers)" >&2
    exit 1
fi

# Enable cpu controller in the parent
echo "+cpu" > "${PARENT}/cgroup.subtree_control" || {
    echo "Error: failed to enable cpu controller in '${PARENT}/cgroup.subtree_control'" >&2
    exit 1
}
echo "Enabled cpu controller in '${PARENT}/cgroup.subtree_control'"

if (( DURATION > 0 )); then
    DURATION_STR="${DURATION}s"
else
    DURATION_STR="forever"
fi

echo "Configuration:"
echo "  parent : ${PARENT}"
echo "  prefix : ${PREFIX}"
echo "  batch  : ${BATCH} cgroups/iter"
echo "  delay  : ${DELAY_MS} ms"
echo "  time   : ${DURATION_STR}"
echo "  drop_caches: $(( DROP_CACHES ? 1 : 0 ))"
echo ""
if (( DURATION > 0 )); then
    echo "Press Ctrl-C to stop early."
else
    echo "Press Ctrl-C to stop."
fi
echo ""

SLEEP_SEC="$(echo "scale=6; $DELAY_MS/1000" | bc)"
START_TIME=$SECONDS
SPINNER=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
COLORS=('\e[31m' '\e[33m' '\e[32m' '\e[36m' '\e[34m' '\e[35m' '\e[31m' '\e[33m')
RESET='\e[0m'
SPIN_IDX=0
START_MEM_KB=0
PREV_MEM_KB=0
PREV_MEM_MS=$(date +%s%3N)
MEM_RATE_KBS=0

while true; do
    # Phase 1: create BATCH cgroups
    for (( i=0; i<BATCH; i++ )); do
        CGPATH="${PARENT}/${PREFIX}_${$}_${i}"
        mkdir "$CGPATH" || { echo "mkdir failed for $CGPATH" >&2; exit 1; }
        echo "max 100000" > "${CGPATH}/cpu.max" || { echo "write cpu.max failed for $CGPATH" >&2; exit 1; }
    done

    # Phase 2: delay
    if (( DELAY_MS > 0 )); then
        sleep "$SLEEP_SEC"
    fi

    # Phase 3: delete all created cgroups, then drop caches.
    for (( i=0; i<BATCH; i++ )); do
        CGPATH="${PARENT}/${PREFIX}_${$}_${i}"
        rmdir "$CGPATH" || { echo "rmdir failed for $CGPATH" >&2; exit 1; }
    done

    if (( DROP_CACHES )); then
        drop_caches
    fi

    # After the first iteration, capture the baseline memory. This reflects
    # memory used after the necessary setup work, not before it.
    if (( COUNT == 0 )); then
        START_MEM_KB=$(get_mem_used_kb)
        PREV_MEM_KB=$START_MEM_KB
    fi

    COUNT=$((COUNT + 1))
    NOW_MS=$(date +%s%3N)
    SPIN_IDX=$(( ( NOW_MS / 100 ) % ${#SPINNER[@]} ))

    ELAPSED=$(( SECONDS - START_TIME ))
    TOTAL=$(( COUNT * BATCH ))
    if (( ELAPSED > 0 )); then
        RATE=$(( TOTAL / ELAPSED ))
    else
        RATE=0
    fi

    CUR_MEM_KB=$(get_mem_used_kb)
    MEM_DELTA_MS=$(( NOW_MS - PREV_MEM_MS ))
    if (( MEM_DELTA_MS >= 100 )); then
        MEM_RATE_KBS=$(( (CUR_MEM_KB - PREV_MEM_KB) * 1000 / MEM_DELTA_MS ))
        PREV_MEM_KB=$CUR_MEM_KB
        PREV_MEM_MS=$NOW_MS
    fi
    MEM_MIB=$(( CUR_MEM_KB / 1024 ))
    MEM_CHANGE_KB=$(( CUR_MEM_KB - START_MEM_KB ))

    printf "\r ${COLORS[$SPIN_IDX]}%s${RESET}  iters: %-8d  cgroups: %-10d  rate: %d/s  mem: %d MiB  Δstart: %+d kB (%+d kB/s)    " \
        "${SPINNER[$SPIN_IDX]}" "$COUNT" "$TOTAL" "$RATE" "$MEM_MIB" "$MEM_CHANGE_KB" "$MEM_RATE_KBS"

    if (( DURATION > 0 && ELAPSED >= DURATION )); then
        printf "\nTime limit reached after %d iterations (%d cgroups). Mem change: %+d kB.\n" \
            "$COUNT" "$TOTAL" "$MEM_CHANGE_KB"
        exit 0
    fi
done
