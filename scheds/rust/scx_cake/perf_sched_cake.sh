#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script with sudo: sudo ./perf_sched_cake.sh"
    exit 1
fi

DURATION_S="${1:-5}"
MODE="${2:-latency}"
TRACE_FILE="${3:-}"

case "${MODE}" in
    latency|timehist|both) ;;
    *)
        echo "Usage: sudo ./perf_sched_cake.sh [duration_seconds] [latency|timehist|both] [trace_file]"
        exit 1
        ;;
esac

ACTIVE_OPS="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true)"
if [[ "${ACTIVE_OPS}" != cake* ]]; then
    echo "scx_cake is not the active sched_ext scheduler."
    echo "Current ops: ${ACTIVE_OPS:-<none>}"
    exit 1
fi

if [[ -z "${TRACE_FILE}" ]]; then
    TRACE_FILE="$(mktemp -p /tmp scx_cake_perf_sched.XXXXXX.data)"
    CLEANUP_TRACE=1
else
    CLEANUP_TRACE=0
fi

echo "Active scheduler: ${ACTIVE_OPS}"
echo "Duration: ${DURATION_S}s"
echo "Mode: ${MODE}"
echo "Trace file: ${TRACE_FILE}"
echo

perf sched record -a -o "${TRACE_FILE}" -- sleep "${DURATION_S}"
echo

if [[ "${MODE}" == "latency" || "${MODE}" == "both" ]]; then
    echo "== perf sched latency =="
    perf sched latency -i "${TRACE_FILE}" -s max,avg,switch,runtime
    echo
fi

if [[ "${MODE}" == "timehist" || "${MODE}" == "both" ]]; then
    echo "== perf sched timehist summary =="
    perf sched timehist -i "${TRACE_FILE}" --summary
    echo
fi

if [[ "${CLEANUP_TRACE}" -eq 1 ]]; then
    rm -f "${TRACE_FILE}"
fi
