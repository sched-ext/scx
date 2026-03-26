#!/usr/bin/env bash

set -euo pipefail

RED=$(printf '\033[0;31m')
GRN=$(printf '\033[0;32m')
YLW=$(printf '\033[1;33m')
CYN=$(printf '\033[0;36m')
BLD=$(printf '\033[1m')
RST=$(printf '\033[0m')

say()  { printf "${BLD}${CYN}[reset-scx]${RST} %s\n" "$1"; }
ok()   { printf "${BLD}${GRN}[  OK  ]${RST} %s\n" "$1"; }
warn() { printf "${BLD}${YLW}[ WARN ]${RST} %s\n" "$1"; }
err()  { printf "${BLD}${RED}[ERROR ]${RST} %s\n" "$1" >&2; }

ROOT_OPS_PATH="/sys/kernel/sched_ext/root/ops"
WAIT_SECONDS=10

usage() {
    cat <<EOF
Usage: ./reset_sched_ext_state.sh

Stop scx.service if present, kill leftover scx schedulers, and wait for
sched_ext to become idle. This is useful before rerunning benchmarks after a
stuck cleanup or leftover scheduler attach.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    exec sudo -- "$0" "$@"
fi

current_sched_ext_ops() {
    if [ -r "$ROOT_OPS_PATH" ]; then
        cat "$ROOT_OPS_PATH" 2>/dev/null || true
    fi
}

wait_for_sched_ext_idle() {
    local i ops

    for ((i = 0; i < WAIT_SECONDS; i++)); do
        if [ ! -e "$ROOT_OPS_PATH" ]; then
            return 0
        fi

        ops="$(current_sched_ext_ops)"
        if [ -z "$ops" ]; then
            return 0
        fi

        sleep 1
    done

    return 1
}

stop_service_if_present() {
    if systemctl list-unit-files scx.service --no-legend >/dev/null 2>&1; then
        say "Stopping scx.service"
        systemctl stop scx.service >/dev/null 2>&1 || true
    else
        warn "scx.service is not installed on this system."
    fi
}

stop_scheduler() {
    local scheduler="$1"

    if pgrep -x "$scheduler" >/dev/null 2>&1; then
        say "Stopping leftover $scheduler process(es)"
        pkill -x "$scheduler" >/dev/null 2>&1 || true
    fi
}

report_scheduler_processes() {
    local found=0
    local scheduler

    for scheduler in scx_timely scx_bpfland scx_cake; do
        if pgrep -x "$scheduler" >/dev/null 2>&1; then
            if [ "$found" -eq 0 ]; then
                warn "Some scheduler processes still appear to be alive:"
                found=1
            fi
            pgrep -ax "$scheduler" || true
        fi
    done

    return "$found"
}

stop_service_if_present

for scheduler in scx_timely scx_bpfland scx_cake; do
    stop_scheduler "$scheduler"
done

if wait_for_sched_ext_idle; then
    ok "sched_ext is idle."
else
    ops="$(current_sched_ext_ops)"
    if [ -n "${ops:-}" ]; then
        warn "sched_ext root/ops still reports: $ops"
    else
        err "sched_ext did not become idle, but no active root/ops value was readable."
    fi
    exit 1
fi

if report_scheduler_processes; then
    exit 1
fi

ok "scx.service is stopped and leftover schedulers are gone."
