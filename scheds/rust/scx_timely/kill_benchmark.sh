#!/usr/bin/env bash

set -euo pipefail

RED=$(printf '\033[0;31m')
GRN=$(printf '\033[0;32m')
YLW=$(printf '\033[1;33m')
CYN=$(printf '\033[0;36m')
BLD=$(printf '\033[1m')
RST=$(printf '\033[0m')

say()  { printf "${BLD}${CYN}[kill-bench]${RST} %s\n" "$1"; }
ok()   { printf "${BLD}${GRN}[  OK  ]${RST} %s\n" "$1"; }
warn() { printf "${BLD}${YLW}[ WARN ]${RST} %s\n" "$1"; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STATE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely"
STATE_FILE="$STATE_DIR/benchmark-running.env"
MINI_LOCAL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/scx_timely/mini-benchmarker"
MINI_LOCAL_SCRIPT="$MINI_LOCAL_DIR/mini-benchmarker.sh"
CACHYOS_LOCAL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/scx_timely/cachyos-benchmarker"
CACHYOS_LOCAL_SCRIPT="$CACHYOS_LOCAL_DIR/cachyos-benchmarker"

declare -A TARGET_PIDS=()
PARENT_PID=""
BENCHMARK_PID=""

usage() {
    cat <<EOF
Usage: ./kill_benchmark.sh

Emergency-stop a running scx_timely benchmark session and the helper/scheduler
processes it launched.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

remember_pid() {
    local pid="$1"
    if [ -n "${pid:-}" ] && [ "$pid" -gt 1 ] 2>/dev/null; then
        TARGET_PIDS["$pid"]=1
    fi
}

collect_descendants() {
    local pid="$1"
    local child

    while read -r child; do
        [ -n "$child" ] || continue
        remember_pid "$child"
        collect_descendants "$child"
    done < <(pgrep -P "$pid" || true)
}

remember_tree() {
    local pid="$1"

    if ! kill -0 "$pid" >/dev/null 2>&1; then
        return
    fi

    remember_pid "$pid"
    collect_descendants "$pid"
}

remember_by_pattern() {
    local pattern="$1"
    local pid

    while read -r pid; do
        [ -n "$pid" ] || continue
        remember_tree "$pid"
    done < <(pgrep -f "$pattern" || true)
}

term_then_kill_pid() {
    local pid="$1"

    kill -TERM "$pid" >/dev/null 2>&1 || true
}

if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    say "Found benchmark runtime state at $STATE_FILE"
fi

remember_by_pattern "$SCRIPT_DIR/benchmark.sh"
remember_by_pattern "$SCRIPT_DIR/mini_benchmarker.sh"
remember_by_pattern "$MINI_LOCAL_SCRIPT"
remember_by_pattern "$CACHYOS_LOCAL_SCRIPT"

if [ -n "${PARENT_PID:-}" ]; then
    remember_tree "$PARENT_PID"
fi
if [ -n "${BENCHMARK_PID:-}" ]; then
    remember_tree "$BENCHMARK_PID"
fi

if [ "${#TARGET_PIDS[@]}" -gt 0 ]; then
    say "Stopping benchmark process tree"
    for pid in "${!TARGET_PIDS[@]}"; do
        term_then_kill_pid "$pid"
    done
    sleep 1
    for pid in "${!TARGET_PIDS[@]}"; do
        kill -KILL "$pid" >/dev/null 2>&1 || true
    done
else
    warn "No benchmark wrapper/helper process tree found."
fi

for scheduler in scx_timely scx_bpfland scx_cake; do
    if pgrep -x "$scheduler" >/dev/null 2>&1; then
        say "Stopping leftover $scheduler process(es)"
        pkill -x "$scheduler" >/dev/null 2>&1 || true
    fi
done

rm -f "$STATE_FILE"

if pgrep -af 'benchmark.sh|mini-benchmarker|cachyos-benchmarker|scx_timely|scx_bpfland|scx_cake' >/dev/null 2>&1; then
    warn "Some related processes are still alive:"
    pgrep -af 'benchmark.sh|mini-benchmarker|cachyos-benchmarker|scx_timely|scx_bpfland|scx_cake' || true
    exit 1
fi

ok "Benchmark session and leftover benchmark schedulers are gone."
