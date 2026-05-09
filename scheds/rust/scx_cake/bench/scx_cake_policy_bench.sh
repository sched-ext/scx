#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh [--storm-guard=off|shadow|shield|full] [--all|--core]
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --all-storm-guards
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-abba
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-plan=shadow,shield,shield,shadow

One-command policy benchmark:
  - starts target/debug/scx_cake headless with --verbose
  - uses stat-only perf capture for cleaner A/B comparisons
  - runs benchmarks sequentially with cooldowns
  - waits before each diagnostic copy so cake_diag_latest.* is fresh
  - stops the scheduler when the suite is done

Common commands:
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-guard=off
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-guard=shadow
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-guard=shield
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-guard=full
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --all-storm-guards
  sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-abba

Options:
  --storm-guard=MODE  scx_cake storm-guard mode; default: off
  --all-storm-guards  run off, shadow, shield, and full sequentially
  --storm-abba        run shadow, shield, shield, shadow for cleaner policy causality
  --storm-plan=LIST   comma-separated storm-guard run order
  --report            write analysis.md after a multi-run plan; default
  --no-report         skip analysis.md generation
  --all               run full suite; default
  --core              run built-in benchmarks only
  --dry-run           print setup without starting scx_cake or perf

Environment:
  SCX_CAKE_BIN=./target/debug/scx_cake
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_CAKE_POLICY_OUT=.scx_cake_bench/policy
  SCX_CAKE_POLICY_CAPTURE=stat
  SCX_CAKE_POLICY_DIAG_PERIOD=2
  SCX_CAKE_POLICY_REPORT=1
  SCX_CAKE_POLICY_STORM_PLAN=shadow,shield,shield,shadow
  SCX_CAKE_POLICY_START_WAIT=15
  SCX_CAKE_POLICY_COOLDOWN=10
  SCX_CAKE_POLICY_DIAG_WAIT=3

Optional workload inputs are forwarded to the suite:
  XZ_INPUT, X265_INPUT, NAMD_CONFIG, YCRUNCHER_CMD, FFMPEG_BUILD_CMD,
  BLENDER_CMD, BLENDER_SCENE, PRIME_CMD, ARGON2_CMD
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

require_uint() {
    local name="$1"
    local value="$2"
    [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} must be an integer"
}

require_trusted_output_base() {
    local path="$1"
    local owner mode perm

    [[ -d "${path}" && ! -L "${path}" ]] || die "output base must be a non-symlink directory: ${path}"
    owner="$(stat -c '%u' -- "${path}" 2>/dev/null)" || die "cannot stat output base owner: ${path}"
    mode="$(stat -c '%a' -- "${path}" 2>/dev/null)" || die "cannot stat output base mode: ${path}"
    perm="${mode: -3}"
    if [[ "${EUID}" -eq 0 ]]; then
        if [[ "${owner}" != "0" && "${owner}" != "${SUDO_UID:-}" ]]; then
            die "output base must be owned by root or the sudo user: ${path}"
        fi
    elif [[ "${owner}" != "${EUID}" ]]; then
        die "output base must be owned by the current user: ${path}"
    fi
    (( (8#${perm} & 0022) == 0 )) || die "output base must not be group/world writable: ${path}"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
SUITE="${SCRIPT_DIR}/scx_cake_bench_suite.sh"
REPORTER="${SCRIPT_DIR}/scx_cake_bench_report.sh"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"

STORM_GUARD="${SCX_CAKE_POLICY_STORM_GUARD:-off}"
ALL_STORM_GUARDS=0
STORM_PLAN="${SCX_CAKE_POLICY_STORM_PLAN:-}"
MODE="${SCX_CAKE_POLICY_SUITE_MODE:-all}"
DRY_RUN="${SCX_CAKE_POLICY_DRY_RUN:-0}"
REPORT="${SCX_CAKE_POLICY_REPORT:-1}"
CAPTURE_MODE="${SCX_CAKE_POLICY_CAPTURE:-stat}"
OUT_BASE="${SCX_CAKE_POLICY_OUT:-${BENCH_ROOT}/policy}"
DIAG_PERIOD="${SCX_CAKE_POLICY_DIAG_PERIOD:-2}"
START_WAIT="${SCX_CAKE_POLICY_START_WAIT:-15}"
COOLDOWN="${SCX_CAKE_POLICY_COOLDOWN:-10}"
DIAG_WAIT="${SCX_CAKE_POLICY_DIAG_WAIT:-3}"
SCX_BIN="${SCX_CAKE_BIN:-${REPO_ROOT}/target/debug/scx_cake}"
RUN_LABEL="${SCX_CAKE_POLICY_RUN_LABEL:-}"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --storm-guard=*)
            STORM_GUARD="${1#*=}"
            ;;
        --storm-guard)
            shift
            [[ "$#" -gt 0 ]] || die "--storm-guard requires a mode"
            STORM_GUARD="$1"
            ;;
        --all-storm-guards)
            ALL_STORM_GUARDS=1
            ;;
        --storm-abba)
            STORM_PLAN="shadow,shield,shield,shadow"
            ;;
        --storm-plan=*)
            STORM_PLAN="${1#*=}"
            ;;
        --storm-plan)
            shift
            [[ "$#" -gt 0 ]] || die "--storm-plan requires a comma-separated list"
            STORM_PLAN="$1"
            ;;
        --report)
            REPORT=1
            ;;
        --no-report)
            REPORT=0
            ;;
        --all)
            MODE="all"
            ;;
        --core)
            MODE="core"
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            die "unknown argument: $1"
            ;;
    esac
    shift
done

case "${STORM_GUARD}" in
    off|shadow|shield|full) ;;
    *) die "--storm-guard must be one of: off, shadow, shield, full" ;;
esac

case "${MODE}" in
    all|core) ;;
    *) die "suite mode must be all or core" ;;
esac

case "${CAPTURE_MODE}" in
    stat|both|sched|time|none) ;;
    *) die "SCX_CAKE_POLICY_CAPTURE must be one of: stat, both, sched, time, none" ;;
esac

[[ "${DRY_RUN}" =~ ^[01]$ ]] || die "SCX_CAKE_POLICY_DRY_RUN must be 0 or 1"
[[ "${ALL_STORM_GUARDS}" =~ ^[01]$ ]] || die "ALL_STORM_GUARDS must be 0 or 1"
[[ "${REPORT}" =~ ^[01]$ ]] || die "SCX_CAKE_POLICY_REPORT must be 0 or 1"
require_uint SCX_CAKE_POLICY_DIAG_PERIOD "${DIAG_PERIOD}"
require_uint SCX_CAKE_POLICY_START_WAIT "${START_WAIT}"
require_uint SCX_CAKE_POLICY_COOLDOWN "${COOLDOWN}"
require_uint SCX_CAKE_POLICY_DIAG_WAIT "${DIAG_WAIT}"
if [[ "${DIAG_PERIOD}" -lt 1 ]]; then
    die "SCX_CAKE_POLICY_DIAG_PERIOD must be at least 1 so policy runs can wait for fresh cake_diag_latest.* output"
fi
[[ -f "${SUITE}" ]] || die "missing suite helper: ${SUITE}"

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

declare -a PLAN_GUARDS=()

parse_storm_plan() {
    local raw="$1"
    local guard

    raw="${raw// /}"
    [[ -n "${raw}" ]] || die "--storm-plan cannot be empty"
    IFS=',' read -r -a PLAN_GUARDS <<<"${raw}"
    [[ "${#PLAN_GUARDS[@]}" -gt 0 ]] || die "--storm-plan cannot be empty"
    for guard in "${PLAN_GUARDS[@]}"; do
        case "${guard}" in
            off|shadow|shield|full) ;;
            *) die "--storm-plan entries must be one of: off, shadow, shield, full (got ${guard})" ;;
        esac
    done
}

if [[ "${ALL_STORM_GUARDS}" == "1" || -n "${STORM_PLAN}" ]]; then
    if [[ "${ALL_STORM_GUARDS}" == "1" && -z "${STORM_PLAN}" ]]; then
        STORM_PLAN="off,shadow,shield,full"
    fi
    parse_storm_plan "${STORM_PLAN}"
    PLAN_LABEL="${STORM_PLAN//,/+}"
    PLAN_LABEL="${PLAN_LABEL//[^a-zA-Z0-9_.+-]/_}"
    if [[ -L "${OUT_BASE}" ]]; then
        die "output base must not be a symlink: ${OUT_BASE}"
    fi
    mkdir -p -m 0700 "${OUT_BASE}"
    require_trusted_output_base "${OUT_BASE}"
    COMPARE_DIR="$(mktemp -d -p "${OUT_BASE}" "${STAMP}_${MODE}_storm-${PLAN_LABEL}.XXXXXX")" ||
        die "failed to create comparison directory under ${OUT_BASE}"
    COMPARE_SUMMARY="${COMPARE_DIR}/summary.md"
    mkdir -p -m 0700 "${COMPARE_DIR}"
    cleanup_plan_output() {
        local status=$?
        give_output_to_sudo_user "${COMPARE_DIR}"
        return "${status}"
    }
    trap cleanup_plan_output EXIT
    {
        echo "# scx_cake Storm Guard Policy Plan"
        echo
        echo "- Started UTC: ${STAMP}"
        echo "- Suite mode: ${MODE}"
        echo "- Capture mode: ${CAPTURE_MODE}"
        echo "- Storm plan: ${STORM_PLAN}"
        echo "- Report: ${REPORT}"
        echo "- Output: ${COMPARE_DIR}"
        echo
        echo "| Seq | Storm guard | Status | Run dir |"
        echo "| ---: | --- | --- | --- |"
    } >"${COMPARE_SUMMARY}"

    echo "scx_cake storm-guard policy plan"
    echo "output: ${COMPARE_DIR}"
    echo "bench root: ${BENCH_ROOT}"
    echo "suite mode: ${MODE}"
    echo "capture mode: ${CAPTURE_MODE}"
    echo "storm plan: ${STORM_PLAN}"

    sweep_status=0
    seq=0
    for guard in "${PLAN_GUARDS[@]}"; do
        seq=$((seq + 1))
        run_label="$(printf 'seq%02d' "${seq}")"
        child_args=(--storm-guard="${guard}" "--${MODE}")
        if [[ "${DRY_RUN}" == "1" ]]; then
            child_args+=(--dry-run)
        fi
        echo
        echo "### ${run_label} storm-guard=${guard}"
        set +e
        SCX_CAKE_POLICY_OUT="${COMPARE_DIR}" \
        SCX_CAKE_POLICY_STORM_PLAN= \
        SCX_CAKE_POLICY_STORM_GUARD= \
        SCX_CAKE_POLICY_RUN_LABEL="${run_label}" \
            "${BASH_SOURCE[0]}" "${child_args[@]}"
        status=$?
        set -e
        child_run_dir="$(find "${COMPARE_DIR}" -mindepth 1 -maxdepth 1 -type d -name "*_storm-${guard}_${run_label}*" -printf '%f\n' 2>/dev/null | sort | tail -n 1)"
        [[ -n "${child_run_dir}" ]] || child_run_dir="<unknown>"
        if [[ "${status}" -eq 0 ]]; then
            echo "| ${seq} | ${guard} | passed | ${child_run_dir} |" >>"${COMPARE_SUMMARY}"
        else
            echo "| ${seq} | ${guard} | failed ${status} | ${child_run_dir} |" >>"${COMPARE_SUMMARY}"
            sweep_status=1
        fi
    done

    if [[ "${REPORT}" == "1" && "${DRY_RUN}" != "1" ]]; then
        if [[ -x "${REPORTER}" ]]; then
            echo
            echo "writing policy analysis report"
            if ! "${REPORTER}" "${COMPARE_DIR}"; then
                sweep_status=1
            fi
        else
            echo "error: report helper is not executable: ${REPORTER}" >&2
            sweep_status=1
        fi
    fi

    echo
    echo "policy plan complete"
    echo "summary: ${COMPARE_SUMMARY}"
    if [[ -f "${COMPARE_DIR}/analysis.md" ]]; then
        echo "analysis: ${COMPARE_DIR}/analysis.md"
    fi
    exit "${sweep_status}"
fi

SAFE_RUN_LABEL="${RUN_LABEL//[^a-zA-Z0-9_.-]/_}"
RUN_SUFFIX=""
if [[ -n "${SAFE_RUN_LABEL}" ]]; then
    RUN_SUFFIX="_${SAFE_RUN_LABEL}"
fi
if [[ -L "${OUT_BASE}" ]]; then
    die "output base must not be a symlink: ${OUT_BASE}"
fi
mkdir -p -m 0700 "${OUT_BASE}"
require_trusted_output_base "${OUT_BASE}"
RUN_DIR="$(mktemp -d -p "${OUT_BASE}" "${STAMP}_${MODE}_storm-${STORM_GUARD}${RUN_SUFFIX}.XXXXXX")" ||
    die "failed to create policy run directory under ${OUT_BASE}"
LOG_DIR="${RUN_DIR}/logs"
DIAG_DIR="${RUN_DIR}/diag/live"
SUITE_OUT="${RUN_DIR}/suite"
SUMMARY="${RUN_DIR}/summary.md"
mkdir -p -m 0700 "${LOG_DIR}" "${DIAG_DIR}" "${SUITE_OUT}"

SCX_PID=""

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "${SCX_PID}" ]] && kill -0 "${SCX_PID}" >/dev/null 2>&1; then
        echo "stopping scx_cake pid ${SCX_PID}"
        kill -TERM "${SCX_PID}" >/dev/null 2>&1 || true
        wait "${SCX_PID}" >/dev/null 2>&1 || true
    fi
    SCX_PID=""
    give_output_to_sudo_user "${RUN_DIR}"
    return "${status}"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

active_ops() {
    cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true
}

wait_for_scheduler() {
    local i ops
    for ((i = 0; i < START_WAIT; i++)); do
        if [[ -n "${SCX_PID}" ]] && ! kill -0 "${SCX_PID}" >/dev/null 2>&1; then
            die "scx_cake exited early; see ${LOG_DIR}/scx_cake.log"
        fi
        ops="$(active_ops)"
        if [[ "${ops}" == cake* ]]; then
            return 0
        fi
        sleep 1
    done
    die "scx_cake did not become active within ${START_WAIT}s; see ${LOG_DIR}/scx_cake.log"
}

wait_for_diag() {
    local i
    for ((i = 0; i < START_WAIT; i++)); do
        if [[ -f "${DIAG_DIR}/cake_diag_latest.txt" || -f "${DIAG_DIR}/cake_diag_latest.json" ]]; then
            return 0
        fi
        sleep 1
    done
    die "diagnostic recorder did not write cake_diag_latest.* within ${START_WAIT}s"
}

write_summary() {
    {
        echo "# scx_cake Policy Benchmark"
        echo
        echo "- Started UTC: ${STAMP}"
        echo "- Storm guard: ${STORM_GUARD}"
        echo "- Suite mode: ${MODE}"
        echo "- Capture mode: ${CAPTURE_MODE}"
        echo "- Cooldown: ${COOLDOWN}s"
        echo "- Diagnostic wait: ${DIAG_WAIT}s"
        echo "- Diagnostic period: ${DIAG_PERIOD}s"
        echo "- Run dir: ${RUN_DIR}"
        echo "- Suite output: ${SUITE_OUT}"
        echo "- Diagnostic source: ${DIAG_DIR}"
        echo "- scx_cake log: ${LOG_DIR}/scx_cake.log"
    } >"${SUMMARY}"
}

write_summary

echo "scx_cake policy benchmark"
echo "run dir: ${RUN_DIR}"
echo "bench root: ${BENCH_ROOT}"
echo "storm-guard: ${STORM_GUARD}"
echo "suite mode: ${MODE}"
echo "capture mode: ${CAPTURE_MODE}"

if [[ "${DRY_RUN}" == "1" ]]; then
    echo
    echo "dry run only"
    echo "would start: ${SCX_BIN} --verbose --storm-guard=${STORM_GUARD} --diag-dir ${DIAG_DIR} --diag-period ${DIAG_PERIOD}"
    echo "would run: SCX_CAKE_SUITE_CAPTURE=${CAPTURE_MODE} SCX_CAKE_SUITE_PAUSE_SECS=${COOLDOWN} SCX_CAKE_BENCH_POST_SLEEP=${DIAG_WAIT} ${SUITE} --${MODE}"
    echo "summary: ${SUMMARY}"
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    die "run with sudo so scx_cake can load BPF and perf can collect counters"
fi

if [[ ! -x "${SCX_BIN}" ]]; then
    die "scx_cake binary is not executable: ${SCX_BIN}; build first with cargo build -p scx_cake"
fi

preexisting_ops="$(active_ops)"
if [[ -n "${preexisting_ops}" ]]; then
    die "sched_ext is already active (${preexisting_ops}); stop the existing scheduler before this one-command benchmark"
fi

echo "starting scx_cake..."
"${SCX_BIN}" \
    --verbose \
    --storm-guard="${STORM_GUARD}" \
    --diag-dir "${DIAG_DIR}" \
    --diag-period "${DIAG_PERIOD}" \
    >"${LOG_DIR}/scx_cake.log" 2>&1 &
SCX_PID=$!

wait_for_scheduler
wait_for_diag
echo "scx_cake active; running suite"

SCX_CAKE_DIAG_DIR="${DIAG_DIR}" \
SCX_CAKE_SUITE_OUT="${SUITE_OUT}" \
SCX_CAKE_SUITE_CAPTURE="${CAPTURE_MODE}" \
SCX_CAKE_SUITE_PAUSE_SECS="${COOLDOWN}" \
SCX_CAKE_BENCH_POST_SLEEP="${DIAG_WAIT}" \
"${SUITE}" "--${MODE}"

write_summary

echo
echo "policy benchmark complete"
echo "summary: ${SUMMARY}"
echo "suite: ${SUITE_OUT}"
echo "diag: ${DIAG_DIR}"
