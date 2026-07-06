#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script with sudo: sudo ./perf_stat_cake.sh"
    exit 1
fi

DURATION_S="${1:-5}"
MODE="${2:-both}"
TIMEOUT_MS=$((DURATION_S * 1000))

case "${MODE}" in
    system|bpf|both) ;;
    *)
        echo "Usage: sudo ./perf_stat_cake.sh [duration_seconds] [system|bpf|both]"
        exit 1
        ;;
esac

ACTIVE_OPS="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true)"
if [[ "${ACTIVE_OPS}" != cake* ]]; then
    echo "scx_cake is not the active sched_ext scheduler."
    echo "Current ops: ${ACTIVE_OPS:-<none>}"
    exit 1
fi

join_by_comma() {
    local IFS=,
    echo "$*"
}

PERF_LIST="$(perf list 2>/dev/null || true)"

SYSTEM_EVENTS=(
    "task-clock"
    "context-switches"
    "cpu-migrations"
    "page-faults"
    "cycles"
    "instructions"
    "branches"
    "branch-misses"
    "cache-references"
    "cache-misses"
)

BPF_EVENTS=(
    "cycles"
    "instructions"
    "branches"
    "branch-misses"
)

SUPPORTED_EXTRA_EVENTS=()

append_if_supported() {
    local event="$1"
    if grep -Fq "${event}" <<< "${PERF_LIST}"; then
        SYSTEM_EVENTS+=("${event}")
        BPF_EVENTS+=("${event}")
        SUPPORTED_EXTRA_EVENTS+=("${event}")
    fi
}

# Optional cache events for grounding L1 behavior and likely local/near/far fills.
# These are PMU-specific and will be included only when the host supports them.
append_if_supported "l1-dcache-loads"
append_if_supported "l1-dcache-load-misses"
append_if_supported "l2_cache_req_stat.ls_rd_blk_c"
append_if_supported "l2_cache_req_stat.ls_rd_blk_l_hit_s"
append_if_supported "l2_cache_req_stat.ls_rd_blk_l_hit_x"
append_if_supported "l2_fill_rsp_src.local_ccx"
append_if_supported "l2_fill_rsp_src.near_cache"
append_if_supported "l2_fill_rsp_src.far_cache"

PROG_NAMES=("cake_select_cpu" "cake_enqueue" "cake_dispatch" "cake_running" "cake_stopping")

declare -a BPF_IDS=()

for name in "${PROG_NAMES[@]}"; do
    id="$(bpftool prog show name "${name}" --json 2>/dev/null | grep -o '"id":[[:space:]]*[0-9]*' | head -n1 | grep -o '[0-9]*' || true)"
    if [[ -n "${id}" ]]; then
        BPF_IDS+=("${id}")
    fi
done

if [[ "${MODE}" != "system" && "${#BPF_IDS[@]}" -eq 0 ]]; then
    echo "No active scx_cake BPF programs found."
    exit 1
fi

echo "Active scheduler: ${ACTIVE_OPS}"
echo "Duration: ${DURATION_S}s"
echo "Mode: ${MODE}"
if [[ "${#SUPPORTED_EXTRA_EVENTS[@]}" -gt 0 ]]; then
    echo "Optional cache events: ${SUPPORTED_EXTRA_EVENTS[*]}"
fi
echo

if [[ "${MODE}" == "system" || "${MODE}" == "both" ]]; then
    echo "== perf stat: system-wide =="
    perf stat -a --timeout "${TIMEOUT_MS}" -e "$(join_by_comma "${SYSTEM_EVENTS[@]}")"
    echo
fi

if [[ "${MODE}" == "bpf" || "${MODE}" == "both" ]]; then
    echo "== perf stat: scx_cake BPF programs =="
    echo "Program IDs: ${BPF_IDS[*]}"
    perf stat --bpf-prog "$(join_by_comma "${BPF_IDS[@]}")" \
        --timeout "${TIMEOUT_MS}" \
        -e "$(join_by_comma "${BPF_EVENTS[@]}")"
    echo
fi
