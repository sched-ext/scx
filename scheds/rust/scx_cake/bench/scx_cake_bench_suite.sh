#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  sudo scheds/rust/scx_cake/bench/scx_cake_bench_suite.sh [--all|--core] [--dry-run]

Default:
  Runs the full known scx_cake benchmark sequence back to back.
  Asset-dependent benchmarks are skipped unless their input env vars are set.

Modes:
  --all      run core benchmarks plus optional chart workloads when configured
  --core     run only benchmarks that do not need external assets
  --list     print the suite and configuration knobs
  --dry-run  print what would run without requiring sudo or active scx_cake

Suite environment:
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_CAKE_SUITE_OUT=.scx_cake_bench/suites
  SCX_CAKE_SUITE_CAPTURE=both       # both, stat, sched, time, none
  SCX_CAKE_SUITE_PAUSE_SECS=0       # cooldown between benchmark captures
  SCX_CAKE_SUITE_STOP_ON_FAIL=0
  SCX_CAKE_SUITE_MODE=all           # all or core

Forwarded benchmark environment:
  SCX_CAKE_DIAG_DIR=.scx_cake_bench/diag/live
  SCX_CAKE_BENCH_REPEATS=1
  SCX_CAKE_BENCH_WARMUP=0
  SCX_CAKE_BENCH_POST_SLEEP=0
  SCX_CAKE_BENCH_REQUIRE_CAKE=1
  SCX_CAKE_BENCH_BPF=0
  SCX_CAKE_BENCH_TIMEHIST_WAKEUPS=0

First-class optional inputs:
  XZ_INPUT=/path/to/input.tar XZ_THREADS=0
  X265_INPUT=/path/to/input.y4m X265_ARGS="--y4m --log-level error"
  NAMD_BIN=/path/to/namd2 NAMD_CONFIG=/path/to/benchmark.namd NAMD_THREADS=$(nproc)

Custom optional commands:
  YCRUNCHER_CMD='y-cruncher bench 1b'
  PRIME_CMD='stress-ng --cpu 0 --cpu-method prime --timeout 30s --metrics-brief --no-rand-seed'
  ARGON2_CMD='printf "scx-cake-test" | argon2 somesalt -id -t 8 -m 20 -p "$(nproc)"'
  FFMPEG_BUILD_CMD='make -C /path/to/ffmpeg -j"$(nproc)"'
  BLENDER_CMD='blender -b /path/to/scene.blend -f 1'
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

require_bool() {
    local name="$1"
    local value="$2"
    [[ "${value}" =~ ^[01]$ ]] || die "${name} must be 0 or 1"
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

shell_quote() {
    printf '%q' "$1"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
CAPTURE="${SCRIPT_DIR}/scx_cake_bench_capture.sh"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"

MODE="${SCX_CAKE_SUITE_MODE:-all}"
DRY_RUN="${SCX_CAKE_SUITE_DRY_RUN:-0}"
STOP_ON_FAIL="${SCX_CAKE_SUITE_STOP_ON_FAIL:-0}"
CAPTURE_MODE="${SCX_CAKE_SUITE_CAPTURE:-${SCX_CAKE_BENCH_CAPTURE:-both}}"
PAUSE_SECS="${SCX_CAKE_SUITE_PAUSE_SECS:-0}"
OUT_BASE="${SCX_CAKE_SUITE_OUT:-${BENCH_ROOT}/suites}"
LIST_ONLY=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --all)
            MODE="all"
            ;;
        --core)
            MODE="core"
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        --list)
            LIST_ONLY=1
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

case "${MODE}" in
    all|core) ;;
    *) die "SCX_CAKE_SUITE_MODE must be all or core" ;;
esac

case "${CAPTURE_MODE}" in
    both|stat|sched|time|none) ;;
    *) die "SCX_CAKE_SUITE_CAPTURE must be one of: both, stat, sched, time, none" ;;
esac

require_bool SCX_CAKE_SUITE_DRY_RUN "${DRY_RUN}"
require_bool SCX_CAKE_SUITE_STOP_ON_FAIL "${STOP_ON_FAIL}"
[[ "${PAUSE_SECS}" =~ ^[0-9]+$ ]] || die "SCX_CAKE_SUITE_PAUSE_SECS must be an integer"
[[ -f "${CAPTURE}" ]] || die "missing capture helper: ${CAPTURE}"

print_list() {
    cat <<'LIST'
Suite order:
  stress-ng-cpu-cache-mem
  y-cruncher-pi-1b       optional: YCRUNCHER_CMD
  perf-sched-fork
  perf-sched-thread
  perf-memcpy
  namd-92k-atoms         optional: NAMD_CONFIG
  prime-numbers          optional default uses stress-ng if installed
  argon2-hashing         optional default uses argon2 if installed
  ffmpeg-compilation     optional: FFMPEG_BUILD_CMD
  xz-compression         optional: XZ_INPUT
  kernel-defconfig
  blender-render         optional: BLENDER_CMD or BLENDER_SCENE
  x265-encoding          optional: X265_INPUT

Core mode:
  stress-ng-cpu-cache-mem, perf-sched-fork, perf-sched-thread,
  perf-memcpy, kernel-defconfig
LIST
}

if [[ "${LIST_ONLY}" == "1" ]]; then
    print_list
    exit 0
fi

if [[ "${DRY_RUN}" != "1" && "${EUID}" -ne 0 ]]; then
    die "run with sudo so the capture helper can use perf and read sched_ext state"
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -L "${OUT_BASE}" ]]; then
    die "output base must not be a symlink: ${OUT_BASE}"
fi
mkdir -p -m 0700 "${OUT_BASE}"
require_trusted_output_base "${OUT_BASE}"
SUITE_DIR="$(mktemp -d -p "${OUT_BASE}" "${STAMP}_${MODE}.XXXXXX")" ||
    die "failed to create suite directory under ${OUT_BASE}"
RUNS_DIR="${SUITE_DIR}/runs"
SUMMARY="${SUITE_DIR}/summary.md"
SUITE_LOG="${SUITE_DIR}/suite.log"
mkdir -p -m 0700 "${RUNS_DIR}"

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    give_output_to_sudo_user "${SUITE_DIR}"
    return "${status}"
}
trap cleanup EXIT

if [[ "${DRY_RUN}" != "1" ]]; then
    exec > >(tee -a "${SUITE_LOG}") 2>&1
fi

PASSED=0
FAILED=0
SKIPPED=0
EXIT_STATUS=0
declare -a RESULT_ROWS=()

escape_md() {
    local value="$1"
    value="${value//|/\\|}"
    printf '%s' "${value}"
}

set_status() {
    local value="${1:-}"
    if [[ -n "${value}" ]]; then
        printf 'set'
    else
        printf '<unset>'
    fi
}

record_result() {
    local label="$1"
    local status="$2"
    local detail="$3"
    RESULT_ROWS+=("| $(escape_md "${label}") | $(escape_md "${status}") | $(escape_md "${detail}") |")
}

log_step() {
    printf '\n== %s ==\n' "$*"
}

skip_bench() {
    local label="$1"
    local reason="$2"
    SKIPPED=$((SKIPPED + 1))
    record_result "${label}" "skipped" "${reason}"
    log_step "skip ${label}"
    echo "${reason}"
}

pause_between_benchmarks() {
    if [[ "${DRY_RUN}" != "1" && "${PAUSE_SECS}" -gt 0 ]]; then
        echo "cooldown: ${PAUSE_SECS}s"
        sleep "${PAUSE_SECS}"
    fi
}

run_capture() {
    local label="$1"
    local benchmark="$2"
    local custom_cmd="${3:-}"
    local status

    log_step "run ${label}"
    if [[ -n "${custom_cmd}" ]]; then
        echo "benchmark: custom"
        echo "command: ${custom_cmd}"
    else
        echo "benchmark: ${benchmark}"
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        record_result "${label}" "dry-run" "${benchmark}"
        return 0
    fi

    set +e
    if [[ -n "${custom_cmd}" ]]; then
        env \
            SCX_CAKE_BENCH_LABEL="${label}" \
            SCX_CAKE_BENCH_CMD="${custom_cmd}" \
            SCX_CAKE_BENCH_OUT="${RUNS_DIR}" \
            SCX_CAKE_BENCH_CAPTURE="${CAPTURE_MODE}" \
            "${CAPTURE}" custom
    else
        env \
            SCX_CAKE_BENCH_LABEL="${label}" \
            SCX_CAKE_BENCH_OUT="${RUNS_DIR}" \
            SCX_CAKE_BENCH_CAPTURE="${CAPTURE_MODE}" \
            "${CAPTURE}" "${benchmark}"
    fi
    status=$?
    set -e

    if [[ "${status}" -eq 0 ]]; then
        PASSED=$((PASSED + 1))
        record_result "${label}" "passed" "${benchmark}"
        pause_between_benchmarks
        return 0
    fi

    FAILED=$((FAILED + 1))
    EXIT_STATUS=1
    record_result "${label}" "failed ${status}" "${benchmark}"
    if [[ "${STOP_ON_FAIL}" == "1" ]]; then
        write_summary
        exit "${status}"
    fi
    pause_between_benchmarks
}

write_summary() {
    {
        echo "# scx_cake Benchmark Suite"
        echo
        echo "- Started UTC: ${STAMP}"
        echo "- Mode: ${MODE}"
        echo "- Capture mode: ${CAPTURE_MODE}"
        echo "- Pause between benchmarks: ${PAUSE_SECS}s"
        echo "- Suite dir: ${SUITE_DIR}"
        echo "- Run artifacts: ${RUNS_DIR}"
        echo "- Stop on fail: ${STOP_ON_FAIL}"
        echo
        echo "## Results"
        echo
        echo "| Benchmark | Status | Detail |"
        echo "| --- | --- | --- |"
        printf '%s\n' "${RESULT_ROWS[@]}"
        echo
        echo "## Optional Inputs"
        echo
        echo "- XZ_INPUT: ${XZ_INPUT:-<unset>}"
        echo "- X265_INPUT: ${X265_INPUT:-<unset>}"
        echo "- NAMD_CONFIG: ${NAMD_CONFIG:-<unset>}"
        echo "- YCRUNCHER_CMD: $(set_status "${YCRUNCHER_CMD:-}")"
        echo "- PRIME_CMD: $(set_status "${PRIME_CMD:-}")"
        echo "- ARGON2_CMD: $(set_status "${ARGON2_CMD:-}")"
        echo "- FFMPEG_BUILD_CMD: $(set_status "${FFMPEG_BUILD_CMD:-}")"
        echo "- BLENDER_CMD: $(set_status "${BLENDER_CMD:-}")"
        echo "- BLENDER_SCENE: ${BLENDER_SCENE:-<unset>}"
    } >"${SUMMARY}"
}

echo "scx_cake benchmark suite"
echo "suite dir: ${SUITE_DIR}"
echo "bench root: ${BENCH_ROOT}"
echo "mode: ${MODE}"
echo "capture mode: ${CAPTURE_MODE}"

run_capture "stress-ng-cpu-cache-mem" "stress-ng-cpu-cache-mem"

if [[ "${MODE}" == "all" ]]; then
    if [[ -n "${YCRUNCHER_CMD:-}" ]]; then
        run_capture "y-cruncher-pi-1b" "custom" "${YCRUNCHER_CMD}"
    else
        skip_bench "y-cruncher-pi-1b" "set YCRUNCHER_CMD to the exact local y-cruncher Pi 1b command"
    fi
fi

run_capture "perf-sched-fork" "perf-sched-fork"
run_capture "perf-sched-thread" "perf-sched-thread"
run_capture "perf-memcpy" "perf-memcpy"

if [[ "${MODE}" == "all" ]]; then
    if [[ -n "${NAMD_CONFIG:-}" ]]; then
        run_capture "namd-92k-atoms" "namd"
    else
        skip_bench "namd-92k-atoms" "set NAMD_CONFIG to the exact NAMD benchmark config"
    fi

    if [[ -n "${PRIME_CMD:-}" ]]; then
        run_capture "prime-numbers" "custom" "${PRIME_CMD}"
    elif has_cmd stress-ng; then
        run_capture "prime-numbers" "custom" 'stress-ng --cpu 0 --cpu-method prime --timeout 30s --metrics-brief --no-rand-seed'
    else
        skip_bench "prime-numbers" "install stress-ng or set PRIME_CMD"
    fi

    if [[ -n "${ARGON2_CMD:-}" ]]; then
        run_capture "argon2-hashing" "custom" "${ARGON2_CMD}"
    elif has_cmd argon2; then
        run_capture "argon2-hashing" "custom" 'printf "scx-cake-test" | argon2 somesalt -id -t 8 -m 20 -p "$(nproc)"'
    else
        skip_bench "argon2-hashing" "install argon2 or set ARGON2_CMD"
    fi

    if [[ -n "${FFMPEG_BUILD_CMD:-}" ]]; then
        run_capture "ffmpeg-compilation" "custom" "${FFMPEG_BUILD_CMD}"
    else
        skip_bench "ffmpeg-compilation" "set FFMPEG_BUILD_CMD to the exact FFmpeg build command"
    fi

    if [[ -n "${XZ_INPUT:-}" ]]; then
        run_capture "xz-compression" "xz-compress"
    else
        skip_bench "xz-compression" "set XZ_INPUT to the compression input asset"
    fi
fi

run_capture "kernel-defconfig" "kernel-defconfig"

if [[ "${MODE}" == "all" ]]; then
    if [[ -n "${BLENDER_CMD:-}" ]]; then
        run_capture "blender-render" "custom" "${BLENDER_CMD}"
    elif [[ -n "${BLENDER_SCENE:-}" ]]; then
        require_uint BLENDER_FRAME "${BLENDER_FRAME:-1}"
        run_capture "blender-render" "custom" "blender -b $(shell_quote "${BLENDER_SCENE}") -f ${BLENDER_FRAME:-1}"
    else
        skip_bench "blender-render" "set BLENDER_CMD or BLENDER_SCENE"
    fi

    if [[ -n "${X265_INPUT:-}" ]]; then
        run_capture "x265-encoding" "x265"
    else
        skip_bench "x265-encoding" "set X265_INPUT to the encode input asset"
    fi
fi

write_summary

echo
echo "suite complete"
echo "passed: ${PASSED}"
echo "failed: ${FAILED}"
echo "skipped: ${SKIPPED}"
echo "summary: ${SUMMARY}"
echo "runs: ${RUNS_DIR}"

exit "${EXIT_STATUS}"
