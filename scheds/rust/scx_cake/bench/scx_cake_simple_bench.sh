#!/usr/bin/env bash
# Minimal one-command benchmark entrypoint.
#
# This intentionally keeps the human-facing CLI small. The lower-level harness
# still owns config generation, scheduler start/stop, captures, and reports.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  sudo scheds/rust/scx_cake/bench/scx_cake_simple_bench.sh [--cake-only|--all-schedulers]

Modes:
  --cake-only       run the full benchmark suite across scx_cake profiles/flags
  --all-schedulers  run the same scx_cake sweep plus every discovered scx scheduler

Default:
  --cake-only

Output:
  .scx_cake_bench/simple/<timestamp>_<mode>/

Optional benchmark assets are still supplied through environment variables:
  XZ_INPUT, X265_INPUT, NAMD_CONFIG, YCRUNCHER_CMD, FFMPEG_BUILD_CMD,
  BLENDER_CMD, BLENDER_SCENE, PRIME_CMD, ARGON2_CMD

Storage environment:
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_CAKE_SIMPLE_BENCH_OUT=.scx_cake_bench/simple/<timestamp>_<mode>
  SCX_CAKE_SIMPLE_CAPTURE=both
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
FULL_BENCH="${SCRIPT_DIR}/scx_cake_full_bench.sh"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"

MODE="cake-only"
MODE_SET=0
CAPTURE_MODE="${SCX_CAKE_SIMPLE_CAPTURE:-both}"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --cake-only)
            MODE="cake-only"
            MODE_SET=$((MODE_SET + 1))
            ;;
        --all-schedulers)
            MODE="all-schedulers"
            MODE_SET=$((MODE_SET + 1))
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
    shift
done

[[ "${MODE_SET}" -le 1 ]] || die "choose only one mode: --cake-only or --all-schedulers"
[[ -x "${FULL_BENCH}" ]] || die "missing full benchmark helper: ${FULL_BENCH}"
case "${CAPTURE_MODE}" in
    stat|both|sched|time|none) ;;
    *) die "SCX_CAKE_SIMPLE_CAPTURE must be one of: stat, both, sched, time, none" ;;
esac

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${SCX_CAKE_SIMPLE_BENCH_OUT:-${BENCH_ROOT}/simple/${STAMP}_${MODE}}"
if [[ -L "${OUT_DIR}" ]]; then
    die "output directory must not be a symlink: ${OUT_DIR}"
fi
mkdir -p -m 0700 "${OUT_DIR}"

prepare_log_file() {
    local log_file="$1"
    local tmp

    if [[ -e "${log_file}" && ! -f "${log_file}" && ! -L "${log_file}" ]]; then
        die "refusing to use non-regular log path: ${log_file}"
    fi
    tmp="$(mktemp -p "${OUT_DIR}" ".simple_bench.log.tmp.XXXXXX")" ||
        die "failed to create temporary log file"
    if [[ -f "${log_file}" && ! -L "${log_file}" ]]; then
        if ! cat -- "${log_file}" >"${tmp}"; then
            rm -f "${tmp}"
            die "failed to preserve existing log file: ${log_file}"
        fi
    fi
    if ! mv -fT -- "${tmp}" "${log_file}"; then
        rm -f "${tmp}"
        die "failed to prepare log file: ${log_file}"
    fi
}

cleanup() {
    local status=$?
    give_output_to_sudo_user "${OUT_DIR}"
    return "${status}"
}
trap cleanup EXIT

LOG_FILE="${OUT_DIR}/simple_bench.log"
prepare_log_file "${LOG_FILE}"
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "scx_cake simple benchmark"
echo "mode: ${MODE}"
echo "output: ${OUT_DIR}"
echo "bench root: ${BENCH_ROOT}"
echo "suite: all"
echo "cake plan: wide"
echo "capture: ${CAPTURE_MODE}"
echo "bpf perf pass: enabled"
echo "sched timehist wakeups: enabled"
echo

COMMON_ENV=(
    "SCX_CAKE_BENCH_ROOT=${BENCH_ROOT}"
    "SCX_CAKE_FULL_BENCH_OUT=${OUT_DIR}/full"
    "SCX_CAKE_FULL_BENCH_PLAN=wide"
    "SCX_CAKE_FULL_BENCH_CAPTURE=${CAPTURE_MODE}"
    "SCX_CAKE_BENCH_BPF=1"
    "SCX_CAKE_BENCH_TIMEHIST_WAKEUPS=1"
    "SCX_MATRIX_DIAG_PERIOD=${SCX_MATRIX_DIAG_PERIOD:-2}"
    "SCX_MATRIX_DIAG_WAIT=${SCX_MATRIX_DIAG_WAIT:-3}"
    "SCX_MATRIX_COOLDOWN=${SCX_MATRIX_COOLDOWN:-10}"
)

case "${MODE}" in
    cake-only)
        env "${COMMON_ENV[@]}" \
            "${FULL_BENCH}" --all --plan wide --capture "${CAPTURE_MODE}" --schedulers cake --out "${OUT_DIR}/full"
        ;;
    all-schedulers)
        env "${COMMON_ENV[@]}" \
            "${FULL_BENCH}" --all --plan wide --capture "${CAPTURE_MODE}" --all-schedulers --out "${OUT_DIR}/full"
        ;;
esac
