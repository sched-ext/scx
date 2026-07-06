#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script with sudo: sudo ./perf_wow_cake.sh"
    exit 1
fi

DURATION_S="${1:-120}"
MODE="${2:-both}"
LABEL="${3:-wow}"
OUT_DIR="${4:-/tmp}"
SAMPLE_S="${WOW_SAMPLE_S:-5}"
TIMEOUT_MS=$((DURATION_S * 1000))

case "${MODE}" in
    stat|sched|both) ;;
    *)
        echo "Usage: sudo ./perf_wow_cake.sh [duration_seconds] [stat|sched|both] [label] [output_dir]"
        echo "Example: sudo ./perf_wow_cake.sh 180 both mythic_boss /home/ritz/Benchmarks"
        exit 1
        ;;
esac

detect_wow_pid() {
    pgrep -n -x "WoW.exe" 2>/dev/null || pgrep -n -f "WoW.exe -launcherlogin" 2>/dev/null || true
}

detect_voice_pid() {
    pgrep -n -x "WowVoiceProxy.e" 2>/dev/null || pgrep -n -f "WowVoiceProxy.exe" 2>/dev/null || true
}

WOW_PID="${WOW_PID:-$(detect_wow_pid)}"
VOICE_PID="${WOW_VOICE_PID:-$(detect_voice_pid)}"

if [[ -z "${WOW_PID}" ]]; then
    echo "Could not find a live WoW.exe process."
    exit 1
fi

ACTIVE_OPS="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true)"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
RUN_DIR="${OUT_DIR%/}/wow_sched_${LABEL}_${STAMP}"

mkdir -p "${RUN_DIR}"

join_by_comma() {
    local IFS=,
    echo "$*"
}

PERF_LIST="$(perf list 2>/dev/null || true)"

STAT_EVENTS=(
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

append_if_supported() {
    local event="$1"
    if grep -Fq "${event}" <<< "${PERF_LIST}"; then
        STAT_EVENTS+=("${event}")
    fi
}

append_if_supported "l1-dcache-loads"
append_if_supported "l1-dcache-load-misses"
append_if_supported "l2_fill_rsp_src.local_ccx"
append_if_supported "l2_fill_rsp_src.near_cache"
append_if_supported "l2_fill_rsp_src.far_cache"

snapshot_threads() {
    local prefix="$1"
    ps -eLo pid,tid,ppid,cls,rtprio,pri,ni,psr,stat,comm,args --no-headers \
        | awk -v wow="${WOW_PID}" -v voice="${VOICE_PID:-0}" '$1 == wow || $1 == voice' \
        > "${RUN_DIR}/${prefix}_threads.txt"

    ps -eLo pid,tid,psr,stat,comm --no-headers \
        | awk -v wow="${WOW_PID}" -v voice="${VOICE_PID:-0}" '$1 == wow || $1 == voice' \
        > "${RUN_DIR}/${prefix}_threads_compact.txt"

    awk '{print $5}' "${RUN_DIR}/${prefix}_threads_compact.txt" \
        | sort | uniq -c | sort -nr \
        > "${RUN_DIR}/${prefix}_thread_names.txt"
}

sample_threads() {
    local end_ts="$1"
    local out_file="${RUN_DIR}/thread_samples.tsv"

    {
        echo "# ts_epoch pid tid psr stat comm"
        while (( "$(date +%s)" < end_ts )); do
            ps -eLo pid,tid,psr,stat,comm --no-headers \
                | awk -v ts="$(date +%s)" -v wow="${WOW_PID}" -v voice="${VOICE_PID:-0}" \
                    '$1 == wow || $1 == voice {print ts, $1, $2, $3, $4, $5}'
            sleep "${SAMPLE_S}"
        done
    } > "${out_file}"
}

summarize_thread_spread() {
    local samples="${RUN_DIR}/thread_samples.tsv"
    local tmp="${RUN_DIR}/thread_cpu_spread.txt"

    if [[ ! -s "${samples}" ]]; then
        return
    fi

    awk 'NF >= 6 && $1 !~ /^#/ {print $3, $6, $4}' "${samples}" \
        | sort -u \
        | awk '{key = $1 " " $2; cnt[key]++} END {for (key in cnt) print cnt[key], key}' \
        | sort -nr \
        > "${tmp}"
}

snapshot_threads "start"

cat > "${RUN_DIR}/meta.txt" <<EOF
timestamp=${STAMP}
duration_s=${DURATION_S}
mode=${MODE}
sample_s=${SAMPLE_S}
run_dir=${RUN_DIR}
active_sched_ext_ops=${ACTIVE_OPS:-<none>}
wow_pid=${WOW_PID}
voice_pid=${VOICE_PID:-<none>}
wow_cmd=$(ps -p "${WOW_PID}" -o args=)
EOF

echo "WoW capture starting"
echo "Run dir: ${RUN_DIR}"
echo "Duration: ${DURATION_S}s"
echo "Mode: ${MODE}"
echo "Active sched_ext ops: ${ACTIVE_OPS:-<none>}"
echo "WoW PID: ${WOW_PID}"
if [[ -n "${VOICE_PID}" ]]; then
    echo "Voice PID: ${VOICE_PID}"
fi
echo

declare -a JOBS=()
END_TS=$(( $(date +%s) + DURATION_S ))

if [[ "${SAMPLE_S}" -gt 0 ]]; then
    sample_threads "${END_TS}" &
    JOBS+=("$!")
fi

if [[ "${MODE}" == "stat" || "${MODE}" == "both" ]]; then
    perf stat -p "${WOW_PID}" \
        --timeout "${TIMEOUT_MS}" \
        -e "$(join_by_comma "${STAT_EVENTS[@]}")" \
        > "${RUN_DIR}/perf_stat.txt" 2>&1 &
    JOBS+=("$!")
fi

if [[ "${MODE}" == "sched" || "${MODE}" == "both" ]]; then
    perf sched record -p "${WOW_PID}" -o "${RUN_DIR}/perf_sched.data" -- sleep "${DURATION_S}" \
        > "${RUN_DIR}/perf_sched_record.txt" 2>&1 &
    JOBS+=("$!")
fi

FAIL=0
for job in "${JOBS[@]}"; do
    if ! wait "${job}"; then
        FAIL=1
    fi
done

snapshot_threads "end"
summarize_thread_spread

if [[ -f "${RUN_DIR}/perf_sched.data" ]]; then
    perf sched latency -i "${RUN_DIR}/perf_sched.data" -s max,avg,switch,runtime \
        > "${RUN_DIR}/perf_sched_latency.txt" 2>&1 || true
    perf sched timehist -i "${RUN_DIR}/perf_sched.data" --summary --wakeups \
        > "${RUN_DIR}/perf_sched_timehist.txt" 2>&1 || true
fi

{
    cat "${RUN_DIR}/meta.txt"
    echo
    echo "== thread names (start) =="
    head -n 24 "${RUN_DIR}/start_thread_names.txt"
    echo
    echo "== thread names (end) =="
    head -n 24 "${RUN_DIR}/end_thread_names.txt"
    echo
    if [[ -f "${RUN_DIR}/thread_cpu_spread.txt" ]]; then
        echo "== migratory threads (distinct CPUs seen) =="
        head -n 24 "${RUN_DIR}/thread_cpu_spread.txt"
        echo
    fi
    if [[ -f "${RUN_DIR}/perf_stat.txt" ]]; then
        echo "== perf stat (WoW pid) =="
        cat "${RUN_DIR}/perf_stat.txt"
        echo
    fi
    if [[ -s "${RUN_DIR}/perf_sched_record.txt" ]]; then
        echo "== perf sched record notes =="
        tail -n 20 "${RUN_DIR}/perf_sched_record.txt"
        echo
    fi
    if [[ -f "${RUN_DIR}/perf_sched_latency.txt" ]]; then
        echo "== perf sched latency =="
        head -n 120 "${RUN_DIR}/perf_sched_latency.txt"
        echo
    fi
    if [[ -f "${RUN_DIR}/perf_sched_timehist.txt" ]]; then
        echo "== perf sched timehist =="
        head -n 120 "${RUN_DIR}/perf_sched_timehist.txt"
        echo
    fi
} > "${RUN_DIR}/summary.txt"

echo "Capture complete: ${RUN_DIR}"
echo "Summary: ${RUN_DIR}/summary.txt"

if [[ "${FAIL}" -ne 0 ]]; then
    echo "One or more capture steps failed. Check files in ${RUN_DIR}."
    exit 1
fi
