#!/usr/bin/env bash
# One-command scx_cake benchmark workflow:
# build schedulers, generate a Cake config plan, then run the scheduler matrix.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  scheds/rust/scx_cake/bench/scx_cake_full_bench.sh [--all|--core]

What it does:
  - builds scx_cake and selected sibling schedulers
  - generates a scx_cake runtime flag plan
  - runs the same benchmark suite across every Cake config and scheduler
  - writes one reviewable output tree with config, matrix, perf, and diagnostics

Default:
  scheds/rust/scx_cake/bench/scx_cake_full_bench.sh --all

Options:
  --all                    run the full known benchmark suite; default
  --core                   run built-in benchmarks only
  --plan quick|wide|full-factorial
                           Cake config plan; default: wide
  --schedulers LIST        comma-separated list; default: cake,pandemonium,lavd,p2dq,flash
  --all-schedulers         use every scheds/rust/scx_* package found
  --capture stat|both|sched|time|none
                           benchmark capture mode; default: stat
  --out DIR                output directory; default: .scx_cake_bench/full/<timestamp>
  --no-build               skip cargo build
  --no-report              skip matrix analysis.md generation
  --dry-run                print the planned matrix without loading schedulers

Environment:
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_CAKE_FULL_BENCH_OUT
  SCX_CAKE_FULL_BENCH_PLAN=wide
  SCX_CAKE_FULL_BENCH_SCHEDULERS=cake,pandemonium,lavd,p2dq,flash
  SCX_CAKE_FULL_BENCH_CAPTURE=stat

Optional benchmark inputs are forwarded through sudo:
  XZ_INPUT, X265_INPUT, NAMD_CONFIG, YCRUNCHER_CMD, FFMPEG_BUILD_CMD,
  BLENDER_CMD, BLENDER_SCENE, PRIME_CMD, ARGON2_CMD
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

normalize_scheduler() {
    local name="$1"
    name="${name// /}"
    case "${name}" in
        cake)
            printf 'scx_cake'
            ;;
        scx_*)
            printf '%s' "${name}"
            ;;
        *)
            printf 'scx_%s' "${name}"
            ;;
    esac
}

discover_schedulers() {
    find "${REPO_ROOT}/scheds/rust" -mindepth 2 -maxdepth 2 -type f -name Cargo.toml |
        while IFS= read -r cargo; do
            awk -F'"' '/^name = "scx_/ { print $2; exit }' "${cargo}"
        done |
        sort
}

package_list_from_schedulers() {
    local raw="$1"
    local scheduler normalized
    declare -A seen=()

    IFS=',' read -r -a requested <<<"${raw}"
    for scheduler in "${requested[@]}"; do
        normalized="$(normalize_scheduler "${scheduler}")"
        [[ -n "${normalized}" ]] || continue
        if [[ -z "${seen[${normalized}]+x}" ]]; then
            seen["${normalized}"]=1
            printf '%s\n' "${normalized}"
        fi
    done
}

forward_if_set() {
    local name="$1"
    if [[ -v "${name}" ]]; then
        MATRIX_ENV+=("${name}=${!name}")
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
CONFIG_AUDIT="${SCRIPT_DIR}/scx_cake_config_audit.sh"
MATRIX="${SCRIPT_DIR}/scx_cake_scheduler_matrix.sh"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MODE="${SCX_CAKE_FULL_BENCH_MODE:-all}"
PLAN="${SCX_CAKE_FULL_BENCH_PLAN:-wide}"
SCHEDULERS="${SCX_CAKE_FULL_BENCH_SCHEDULERS:-cake,pandemonium,lavd,p2dq,flash}"
ALL_SCHEDULERS="${SCX_CAKE_FULL_BENCH_ALL_SCHEDULERS:-0}"
CAPTURE_MODE="${SCX_CAKE_FULL_BENCH_CAPTURE:-stat}"
OUT_DIR="${SCX_CAKE_FULL_BENCH_OUT:-${BENCH_ROOT}/full/${STAMP}_${MODE}_${PLAN}}"
BUILD="${SCX_CAKE_FULL_BENCH_BUILD:-1}"
REPORT="${SCX_CAKE_FULL_BENCH_REPORT:-1}"
DRY_RUN="${SCX_CAKE_FULL_BENCH_DRY_RUN:-0}"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --all)
            MODE="all"
            ;;
        --core)
            MODE="core"
            ;;
        --plan=*)
            PLAN="${1#*=}"
            ;;
        --plan)
            shift
            [[ "$#" -gt 0 ]] || die "--plan requires a value"
            PLAN="$1"
            ;;
        --schedulers=*)
            SCHEDULERS="${1#*=}"
            ;;
        --schedulers)
            shift
            [[ "$#" -gt 0 ]] || die "--schedulers requires a comma-separated list"
            SCHEDULERS="$1"
            ;;
        --all-schedulers)
            ALL_SCHEDULERS=1
            ;;
        --capture=*)
            CAPTURE_MODE="${1#*=}"
            ;;
        --capture)
            shift
            [[ "$#" -gt 0 ]] || die "--capture requires a mode"
            CAPTURE_MODE="$1"
            ;;
        --out=*)
            OUT_DIR="${1#*=}"
            ;;
        --out)
            shift
            [[ "$#" -gt 0 ]] || die "--out requires a directory"
            OUT_DIR="$1"
            ;;
        --no-build)
            BUILD=0
            ;;
        --no-report)
            REPORT=0
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

case "${MODE}" in
    all|core) ;;
    *) die "--all or --core expected" ;;
esac

case "${PLAN}" in
    quick|wide|full-factorial) ;;
    *) die "--plan must be quick, wide, or full-factorial" ;;
esac

case "${CAPTURE_MODE}" in
    stat|both|sched|time|none) ;;
    *) die "--capture must be one of: stat, both, sched, time, none" ;;
esac

require_bool SCX_CAKE_FULL_BENCH_ALL_SCHEDULERS "${ALL_SCHEDULERS}"
require_bool SCX_CAKE_FULL_BENCH_BUILD "${BUILD}"
require_bool SCX_CAKE_FULL_BENCH_REPORT "${REPORT}"
require_bool SCX_CAKE_FULL_BENCH_DRY_RUN "${DRY_RUN}"
[[ -x "${CONFIG_AUDIT}" ]] || die "missing config audit helper: ${CONFIG_AUDIT}"
[[ -x "${MATRIX}" ]] || die "missing scheduler matrix helper: ${MATRIX}"

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

if [[ -L "${OUT_DIR}" ]]; then
    die "output directory must not be a symlink: ${OUT_DIR}"
fi
mkdir -p -m 0700 "${OUT_DIR}"
cleanup() {
    local status=$?
    give_output_to_sudo_user "${OUT_DIR}"
    return "${status}"
}
trap cleanup EXIT
CONFIG_DIR="${OUT_DIR}/config"
MATRIX_DIR="${OUT_DIR}/matrix"

if [[ "${ALL_SCHEDULERS}" == "1" ]]; then
    SCHEDULERS="$(discover_schedulers | paste -sd, -)"
fi

echo "scx_cake full benchmark"
echo "output: ${OUT_DIR}"
echo "bench root: ${BENCH_ROOT}"
echo "suite mode: ${MODE}"
echo "cake plan: ${PLAN}"
echo "capture mode: ${CAPTURE_MODE}"
echo "schedulers: ${SCHEDULERS}"

if pgrep -af "[s]ashiko|target/release/review|[c]odex exec" >/dev/null 2>&1; then
    echo "warning: Sashiko/Codex review processes appear to be running; benchmark data may be noisy" >&2
fi

if [[ "${BUILD}" == "1" && "${DRY_RUN}" != "1" ]]; then
    mapfile -t packages < <(package_list_from_schedulers "${SCHEDULERS}")
    if [[ "${#packages[@]}" -eq 0 ]]; then
        die "no scheduler packages selected"
    fi

    build_cmd=(cargo build)
    for package in "${packages[@]}"; do
        build_cmd+=(-p "${package}")
    done

    echo
    echo "building schedulers: ${packages[*]}"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        sudo -u "${SUDO_USER}" env \
            HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)" \
            PATH="${PATH}" \
            "${build_cmd[@]}"
    else
        "${build_cmd[@]}"
    fi
elif [[ "${BUILD}" == "1" ]]; then
    echo
    echo "dry run: skipping cargo build"
else
    echo
    echo "skipping cargo build"
fi

echo
echo "generating Cake config plan"
"${CONFIG_AUDIT}" --plan "${PLAN}" --out "${CONFIG_DIR}"

MATRIX_ARGS=(--cake-config-plan "${CONFIG_DIR}/config_plan.tsv" "--${MODE}")
if [[ "${ALL_SCHEDULERS}" == "1" ]]; then
    MATRIX_ARGS+=(--all-schedulers)
else
    MATRIX_ARGS+=(--schedulers "${SCHEDULERS}")
fi
if [[ "${REPORT}" == "1" ]]; then
    MATRIX_ARGS+=(--report)
else
    MATRIX_ARGS+=(--no-report)
fi
if [[ "${DRY_RUN}" == "1" ]]; then
    MATRIX_ARGS+=(--dry-run)
fi

declare -a MATRIX_ENV=(
    "SCX_CAKE_BENCH_ROOT=${BENCH_ROOT}"
    "SCX_MATRIX_OUT=${MATRIX_DIR}"
    "SCX_MATRIX_CAPTURE=${CAPTURE_MODE}"
)

for name in \
    SCX_MATRIX_START_WAIT SCX_MATRIX_COOLDOWN SCX_MATRIX_DIAG_PERIOD SCX_MATRIX_DIAG_WAIT \
    XZ_INPUT XZ_THREADS X265_INPUT X265_ARGS NAMD_BIN NAMD_CONFIG NAMD_THREADS \
    YCRUNCHER_CMD PRIME_CMD ARGON2_CMD FFMPEG_BUILD_CMD BLENDER_CMD BLENDER_SCENE \
    PERF_SCHED_GROUPS PERF_SCHED_LOOPS PERF_MEMCPY_SIZE PERF_MEMCPY_LOOPS \
    STRESS_NG_TIMEOUT STRESS_NG_WORKERS LINUX_SRC; do
    forward_if_set "${name}"
done

echo
echo "running scheduler matrix"
if [[ "${DRY_RUN}" == "1" || "${EUID}" -eq 0 ]]; then
    env "${MATRIX_ENV[@]}" "${MATRIX}" "${MATRIX_ARGS[@]}"
else
    sudo env "${MATRIX_ENV[@]}" "${MATRIX}" "${MATRIX_ARGS[@]}"
fi

echo
echo "full benchmark complete"
echo "output: ${OUT_DIR}"
echo "config: ${CONFIG_DIR}"
echo "matrix: ${MATRIX_DIR}"
