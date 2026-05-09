#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  sudo scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh <benchmark>

Benchmarks:
  perf-sched-fork          perf bench sched messaging, process mode
  perf-sched-thread        perf bench sched messaging, thread mode
  perf-sched-both          fork pass followed by thread pass
  perf-memcpy              perf bench mem memcpy
  stress-ng-cache          stress-ng cache workers
  stress-ng-cpu-cache-mem  stress-ng cache + memcpy workers
  kernel-defconfig         make defconfig in /home/ritz/Documents/Repo/linux
  xz-compress              xz -T0 compression; requires XZ_INPUT=/path/file
  x265                     x265 encode; requires X265_INPUT=/path/file
  namd                     NAMD run; requires NAMD_CONFIG=/path/config
  custom                   run SCX_CAKE_BENCH_CMD through bash -lc

Default flow:
  - checks that scx_cake is the active sched_ext scheduler
  - runs one perf stat pass and one perf sched record pass
  - copies fresh scx_cake debug dumps from .scx_cake_bench/diag/live
  - writes everything under .scx_cake_bench/runs/<timestamp>_<benchmark>

Useful environment:
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_CAKE_BENCH_OUT=.scx_cake_bench/runs
  SCX_CAKE_BENCH_LABEL=optional-name
  SCX_CAKE_DIAG_DIR=.scx_cake_bench/diag/live
  SCX_CAKE_BENCH_CAPTURE=both      # both, stat, sched, time, none
  SCX_CAKE_BENCH_REPEATS=1
  SCX_CAKE_BENCH_WARMUP=0
  SCX_CAKE_BENCH_POST_SLEEP=0      # seconds to wait before copying diagnostics
  SCX_CAKE_BENCH_REQUIRE_CAKE=1
  SCX_CAKE_BENCH_REQUIRE_OPS=       # optional active sched_ext ops substring
  SCX_CAKE_BENCH_BPF=0             # set 1 for an extra BPF perf-stat pass
  SCX_CAKE_BENCH_TIMEHIST_WAKEUPS=0

Benchmark knobs:
  PERF_SCHED_GROUPS=16 PERF_SCHED_LOOPS=500
  PERF_MEMCPY_SIZE=1GB PERF_MEMCPY_LOOPS=5
  STRESS_NG_TIMEOUT=30s STRESS_NG_WORKERS=0
  LINUX_SRC=/home/ritz/Documents/Repo/linux
  XZ_INPUT=/path/file XZ_THREADS=0
  X265_INPUT=/path/file X265_ARGS="--y4m --log-level error"
  NAMD_BIN=namd2 NAMD_CONFIG=/path/file NAMD_THREADS=$(nproc)
  SCX_CAKE_BENCH_CMD='your command here'
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
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

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    die "run with sudo so perf can collect system-wide scheduler data"
fi

BENCHMARK="${1:-perf-sched-thread}"
BENCH_LABEL="${SCX_CAKE_BENCH_LABEL:-${BENCHMARK}}"
CAPTURE_MODE="${SCX_CAKE_BENCH_CAPTURE:-both}"
REPEATS="${SCX_CAKE_BENCH_REPEATS:-1}"
WARMUP="${SCX_CAKE_BENCH_WARMUP:-0}"
POST_SLEEP="${SCX_CAKE_BENCH_POST_SLEEP:-0}"
REQUIRE_CAKE="${SCX_CAKE_BENCH_REQUIRE_CAKE:-1}"
REQUIRE_OPS="${SCX_CAKE_BENCH_REQUIRE_OPS:-}"
CAPTURE_BPF="${SCX_CAKE_BENCH_BPF:-0}"
TIMEHIST_WAKEUPS="${SCX_CAKE_BENCH_TIMEHIST_WAKEUPS:-0}"

case "${CAPTURE_MODE}" in
    both|stat|sched|time|none) ;;
    *) die "SCX_CAKE_BENCH_CAPTURE must be one of: both, stat, sched, time, none" ;;
esac

require_uint SCX_CAKE_BENCH_REPEATS "${REPEATS}"
require_uint SCX_CAKE_BENCH_WARMUP "${WARMUP}"
require_uint SCX_CAKE_BENCH_POST_SLEEP "${POST_SLEEP}"
if [[ "${REPEATS}" -lt 1 ]]; then
    die "SCX_CAKE_BENCH_REPEATS must be at least 1"
fi
[[ "${CAPTURE_BPF}" =~ ^[01]$ ]] || die "SCX_CAKE_BENCH_BPF must be 0 or 1"
[[ "${TIMEHIST_WAKEUPS}" =~ ^[01]$ ]] || die "SCX_CAKE_BENCH_TIMEHIST_WAKEUPS must be 0 or 1"

require_cmd perf
require_cmd git
require_cmd date
require_cmd uname
require_cmd nproc
[[ -x /usr/bin/time ]] || die "missing required command: /usr/bin/time"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"
DIAG_DIR="${SCX_CAKE_DIAG_DIR:-${BENCH_ROOT}/diag/live}"
OUT_BASE="${SCX_CAKE_BENCH_OUT:-${BENCH_ROOT}/runs}"
SAFE_BENCH="${BENCH_LABEL//[^a-zA-Z0-9_.-]/_}"
[[ -n "${SAFE_BENCH}" ]] || SAFE_BENCH="benchmark"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -L "${OUT_BASE}" ]]; then
    die "output base must not be a symlink: ${OUT_BASE}"
fi
mkdir -p -m 0700 "${OUT_BASE}"
require_trusted_output_base "${OUT_BASE}"
RUN_DIR="$(mktemp -d -p "${OUT_BASE}" "${STAMP}_${SAFE_BENCH}.XXXXXX")" ||
    die "failed to create run directory under ${OUT_BASE}"
LOG_DIR="${RUN_DIR}/logs"
PERF_DIR="${RUN_DIR}/perf"
DIAG_OUT_DIR="${RUN_DIR}/diag"
mkdir -p -m 0700 "${LOG_DIR}" "${PERF_DIR}" "${DIAG_OUT_DIR}"

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    give_output_to_sudo_user "${RUN_DIR}"
    return "${status}"
}
trap cleanup EXIT

RUN_FAILED=0
BENCH_KIND="argv"
declare -a BENCH_CMD=()
BENCH_SHELL=""
BENCH_CWD=""
BENCH_STDOUT_NULL=0

log() {
    printf '%s\n' "$*" | tee -a "${RUN_DIR}/run.log"
}

mark_failed() {
    local status="$1"
    local label="$2"
    if [[ "${status}" -ne 0 ]]; then
        RUN_FAILED=1
        log "${label} exited with status ${status}"
    fi
}

join_by_comma() {
    local IFS=,
    echo "$*"
}

shell_quote() {
    printf '%q' "$1"
}

command_line() {
    if [[ "${BENCH_KIND}" == "shell" ]]; then
        printf '%s\n' "${BENCH_SHELL}"
    elif [[ -n "${BENCH_CWD}" ]]; then
        printf 'cd %q && ' "${BENCH_CWD}"
        printf '%q ' "${BENCH_CMD[@]}"
        printf '\n'
    else
        printf '%q ' "${BENCH_CMD[@]}"
        printf '\n'
    fi
}

run_argv_logged() {
    local log_file="$1"
    shift

    if [[ -n "${BENCH_CWD}" ]]; then
        if [[ "${BENCH_STDOUT_NULL}" == "1" ]]; then
            (cd "${BENCH_CWD}" && "$@" "${BENCH_CMD[@]}" >/dev/null) 2>"${log_file}"
        else
            (cd "${BENCH_CWD}" && "$@" "${BENCH_CMD[@]}") >"${log_file}" 2>&1
        fi
    elif [[ "${BENCH_STDOUT_NULL}" == "1" ]]; then
        "$@" "${BENCH_CMD[@]}" >/dev/null 2>"${log_file}"
    else
        "$@" "${BENCH_CMD[@]}" >"${log_file}" 2>&1
    fi
}

diag_dir_trusted() {
    local owner mode perm

    [[ -d "${DIAG_DIR}" && ! -L "${DIAG_DIR}" ]] || return 1
    owner="$(stat -c '%u' -- "${DIAG_DIR}" 2>/dev/null)" || return 1
    mode="$(stat -c '%a' -- "${DIAG_DIR}" 2>/dev/null)" || return 1
    if [[ "${owner}" != "0" && "${owner}" != "${EUID}" && "${owner}" != "${SUDO_UID:-}" ]]; then
        return 1
    fi
    perm="${mode: -3}"
    (( (8#${perm} & 0022) == 0 ))
}

require_active_scheduler() {
    local active_ops
    active_ops="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true)"
    if [[ -n "${REQUIRE_OPS}" ]]; then
        if [[ "${active_ops}" != "${REQUIRE_OPS}"* && "${active_ops}" != *"${REQUIRE_OPS}"* ]]; then
            cat >&2 <<EOF
Expected sched_ext scheduler is not active.
Expected ops containing: ${REQUIRE_OPS}
Current ops: ${active_ops:-<none>}
EOF
            exit 1
        fi
        return
    fi
    if [[ "${REQUIRE_CAKE}" == "1" && "${active_ops}" != cake* ]]; then
        cat >&2 <<EOF
scx_cake is not the active sched_ext scheduler.
Current ops: ${active_ops:-<none>}

Start a debug recorder in another terminal first, for example:
  sudo install -d -m 0700 ${DIAG_DIR}
  sudo ./target/debug/scx_cake --verbose --diag-dir ${DIAG_DIR} --diag-period 5
EOF
        exit 1
    fi
}

build_benchmark_command() {
    case "${BENCHMARK}" in
        perf-sched-fork)
            local groups="${PERF_SCHED_GROUPS:-16}"
            local loops="${PERF_SCHED_LOOPS:-500}"
            require_uint PERF_SCHED_GROUPS "${groups}"
            require_uint PERF_SCHED_LOOPS "${loops}"
            BENCH_CMD=(perf bench --format=simple sched messaging -g "${groups}" -l "${loops}")
            ;;
        perf-sched-thread)
            local groups="${PERF_SCHED_GROUPS:-16}"
            local loops="${PERF_SCHED_LOOPS:-500}"
            require_uint PERF_SCHED_GROUPS "${groups}"
            require_uint PERF_SCHED_LOOPS "${loops}"
            BENCH_CMD=(perf bench --format=simple sched messaging -t -g "${groups}" -l "${loops}")
            ;;
        perf-sched-both)
            local groups="${PERF_SCHED_GROUPS:-16}"
            local loops="${PERF_SCHED_LOOPS:-500}"
            require_uint PERF_SCHED_GROUPS "${groups}"
            require_uint PERF_SCHED_LOOPS "${loops}"
            BENCH_KIND="shell"
            BENCH_SHELL="perf bench --format=simple sched messaging -g ${groups} -l ${loops} && perf bench --format=simple sched messaging -t -g ${groups} -l ${loops}"
            ;;
        perf-memcpy)
            local loops="${PERF_MEMCPY_LOOPS:-5}"
            require_uint PERF_MEMCPY_LOOPS "${loops}"
            BENCH_CMD=(perf bench --format=simple mem memcpy -f "${PERF_MEMCPY_FUNCTION:-default}" -s "${PERF_MEMCPY_SIZE:-1GB}" -l "${loops}")
            ;;
        stress-ng-cache)
            require_cmd stress-ng
            BENCH_CMD=(stress-ng --cache "${STRESS_NG_WORKERS:-0}" --timeout "${STRESS_NG_TIMEOUT:-30s}" --metrics-brief --no-rand-seed)
            ;;
        stress-ng-cpu-cache-mem)
            require_cmd stress-ng
            BENCH_CMD=(stress-ng --cache "${STRESS_NG_CACHE_WORKERS:-${STRESS_NG_WORKERS:-0}}" --memcpy "${STRESS_NG_MEMCPY_WORKERS:-${STRESS_NG_WORKERS:-0}}" --timeout "${STRESS_NG_TIMEOUT:-30s}" --metrics-brief --no-rand-seed)
            ;;
        kernel-defconfig)
            require_cmd make
            local linux_src="${LINUX_SRC:-/home/ritz/Documents/Repo/linux}"
            [[ -d "${linux_src}" ]] || die "LINUX_SRC does not exist: ${linux_src}"
            mkdir -p "${RUN_DIR}/kbuild"
            BENCH_CMD=(make -C "${linux_src}" O="${RUN_DIR}/kbuild" defconfig)
            ;;
        xz-compress)
            require_cmd xz
            [[ -n "${XZ_INPUT:-}" ]] || die "xz-compress requires XZ_INPUT=/path/to/input"
            [[ -f "${XZ_INPUT}" ]] || die "XZ_INPUT does not exist: ${XZ_INPUT}"
            require_uint XZ_THREADS "${XZ_THREADS:-0}"
            BENCH_STDOUT_NULL=1
            BENCH_CMD=(xz "-T${XZ_THREADS:-0}" -zc "${XZ_INPUT}")
            ;;
        x265)
            require_cmd x265
            [[ -n "${X265_INPUT:-}" ]] || die "x265 requires X265_INPUT=/path/to/input"
            [[ -f "${X265_INPUT}" ]] || die "X265_INPUT does not exist: ${X265_INPUT}"
            read -r -a x265_args <<<"${X265_ARGS:---y4m --log-level error}"
            BENCH_CMD=(x265 "${x265_args[@]}" -o /dev/null "${X265_INPUT}")
            ;;
        namd)
            local namd_bin="${NAMD_BIN:-}"
            local namd_dir namd_file
            if [[ -z "${namd_bin}" ]]; then
                namd_bin="$(command -v namd2 || command -v namd3 || true)"
            fi
            [[ -n "${namd_bin}" ]] || die "namd requires NAMD_BIN or a namd2/namd3 binary in PATH"
            [[ -n "${NAMD_CONFIG:-}" ]] || die "namd requires NAMD_CONFIG=/path/to/config"
            [[ -f "${NAMD_CONFIG}" ]] || die "NAMD_CONFIG does not exist: ${NAMD_CONFIG}"
            require_uint NAMD_THREADS "${NAMD_THREADS:-$(nproc)}"
            namd_dir="$(cd "$(dirname "${NAMD_CONFIG}")" && pwd)"
            namd_file="$(basename "${NAMD_CONFIG}")"
            BENCH_CWD="${namd_dir}"
            BENCH_CMD=("${namd_bin}" "+p${NAMD_THREADS:-$(nproc)}" +setcpuaffinity "${namd_file}")
            ;;
        custom)
            [[ -n "${SCX_CAKE_BENCH_CMD:-}" ]] || die "custom requires SCX_CAKE_BENCH_CMD"
            BENCH_KIND="shell"
            BENCH_SHELL="${SCX_CAKE_BENCH_CMD}"
            ;;
        *)
            usage
            die "unknown benchmark: ${BENCHMARK}"
            ;;
    esac
}

run_plain_pass() {
    local label="$1"
    local log_file="${LOG_DIR}/${label}.log"
    local time_file="${PERF_DIR}/${label}.time.txt"
    local status

    log "running ${label}: $(command_line)"
    set +e
    if [[ "${BENCH_KIND}" == "shell" ]]; then
        /usr/bin/time -v -o "${time_file}" bash -lc "${BENCH_SHELL}" >"${log_file}" 2>&1
    else
        run_argv_logged "${log_file}" /usr/bin/time -v -o "${time_file}"
    fi
    status=$?
    set -e
    printf '%s\n' "${status}" >"${PERF_DIR}/${label}.status"
    mark_failed "${status}" "${label}"
}

run_perf_stat_pass() {
    local label="$1"
    local log_file="${LOG_DIR}/${label}.log"
    local csv_file="${PERF_DIR}/${label}.perf_stat.csv"
    local time_file="${PERF_DIR}/${label}.time.txt"
    local status
    local events

    events="$(join_by_comma "${SYSTEM_EVENTS[@]}")"
    log "running ${label}: perf stat -a over $(command_line)"
    set +e
    if [[ "${BENCH_KIND}" == "shell" ]]; then
        /usr/bin/time -v -o "${time_file}" perf stat -a -x, -o "${csv_file}" -e "${events}" -- bash -lc "${BENCH_SHELL}" >"${log_file}" 2>&1
    else
        run_argv_logged "${log_file}" /usr/bin/time -v -o "${time_file}" perf stat -a -x, -o "${csv_file}" -e "${events}" --
    fi
    status=$?
    set -e
    printf '%s\n' "${status}" >"${PERF_DIR}/${label}.status"
    mark_failed "${status}" "${label}"
}

run_bpf_stat_pass() {
    local label="$1"
    local log_file="${LOG_DIR}/${label}.log"
    local csv_file="${PERF_DIR}/${label}.bpf_perf_stat.csv"
    local time_file="${PERF_DIR}/${label}.bpf_time.txt"
    local ids
    local events
    local status

    if ! command -v bpftool >/dev/null 2>&1; then
        log "skipping ${label}: bpftool is not installed"
        return
    fi
    ids="$(find_bpf_program_ids)"
    if [[ -z "${ids}" ]]; then
        log "skipping ${label}: no active scx_cake BPF program ids found"
        return
    fi
    events="$(join_by_comma "${BPF_EVENTS[@]}")"
    log "running ${label}: perf stat --bpf-prog ${ids} over $(command_line)"
    set +e
    if [[ "${BENCH_KIND}" == "shell" ]]; then
        /usr/bin/time -v -o "${time_file}" perf stat --bpf-prog "${ids}" -x, -o "${csv_file}" -e "${events}" -- bash -lc "${BENCH_SHELL}" >"${log_file}" 2>&1
    else
        run_argv_logged "${log_file}" /usr/bin/time -v -o "${time_file}" perf stat --bpf-prog "${ids}" -x, -o "${csv_file}" -e "${events}" --
    fi
    status=$?
    set -e
    printf '%s\n' "${status}" >"${PERF_DIR}/${label}.status"
    mark_failed "${status}" "${label}"
}

run_perf_sched_pass() {
    local label="$1"
    local log_file="${LOG_DIR}/${label}.log"
    local trace_file="${PERF_DIR}/${label}.perf_sched.data"
    local time_file="${PERF_DIR}/${label}.sched_time.txt"
    local latency_file="${PERF_DIR}/${label}.perf_sched_latency.txt"
    local timehist_summary_file="${PERF_DIR}/${label}.perf_sched_timehist_summary.txt"
    local timehist_wakeups_file="${PERF_DIR}/${label}.perf_sched_timehist_wakeups.txt"
    local status
    local post_status

    log "running ${label}: perf sched record over $(command_line)"
    set +e
    if [[ "${BENCH_KIND}" == "shell" ]]; then
        /usr/bin/time -v -o "${time_file}" perf sched record -a -o "${trace_file}" -- bash -lc "${BENCH_SHELL}" >"${log_file}" 2>&1
    else
        run_argv_logged "${log_file}" /usr/bin/time -v -o "${time_file}" perf sched record -a -o "${trace_file}" --
    fi
    status=$?
    set -e
    printf '%s\n' "${status}" >"${PERF_DIR}/${label}.status"
    mark_failed "${status}" "${label}"

    if [[ -f "${trace_file}" ]]; then
        set +e
        perf sched latency -i "${trace_file}" -s max,avg,switch,runtime >"${latency_file}" 2>&1
        post_status=$?
        printf '%s\n' "${post_status}" >"${PERF_DIR}/${label}.perf_sched_latency.status"
        mark_failed "${post_status}" "${label} perf sched latency"
        perf sched timehist -i "${trace_file}" --summary >"${timehist_summary_file}" 2>&1
        post_status=$?
        printf '%s\n' "${post_status}" >"${PERF_DIR}/${label}.perf_sched_timehist_summary.status"
        mark_failed "${post_status}" "${label} perf sched timehist summary"
        if [[ "${TIMEHIST_WAKEUPS}" == "1" ]]; then
            perf sched timehist -i "${trace_file}" --wakeups >"${timehist_wakeups_file}" 2>&1
            post_status=$?
            printf '%s\n' "${post_status}" >"${PERF_DIR}/${label}.perf_sched_timehist_wakeups.status"
            mark_failed "${post_status}" "${label} perf sched timehist wakeups"
        fi
        set -e
    fi
}

find_bpf_program_ids() {
    local names=(cake_select_cpu cake_enqueue cake_dispatch cake_running cake_stopping)
    local ids=()
    local name id

    for name in "${names[@]}"; do
        id="$(bpftool prog show name "${name}" --json 2>/dev/null | grep -o '"id":[[:space:]]*[0-9]*' | head -n1 | grep -o '[0-9]*' || true)"
        if [[ -n "${id}" ]]; then
            ids+=("${id}")
        fi
    done

    if [[ "${#ids[@]}" -gt 0 ]]; then
        join_by_comma "${ids[@]}"
    fi
}

copy_diag_outputs() {
    local start_epoch="$1"
    local dest="${DIAG_OUT_DIR}/from_${start_epoch}"
    local inventory="${DIAG_OUT_DIR}/inventory_${start_epoch}.txt"
    mkdir -p -m 0700 "${dest}"

    if [[ ! -d "${DIAG_DIR}" ]]; then
        {
            echo "Diagnostic directory not found: ${DIAG_DIR}"
            echo "Start scx_cake with:"
            echo "  sudo install -d -m 0700 ${DIAG_DIR}"
            echo "  sudo ./target/debug/scx_cake --verbose --diag-dir ${DIAG_DIR} --diag-period 5"
        } >"${DIAG_OUT_DIR}/missing_diag_dir_${start_epoch}.txt"
        return
    fi
    if ! diag_dir_trusted; then
        {
            echo "Diagnostic directory is not trusted for copying: ${DIAG_DIR}"
            echo "Expected an owned, non-symlink directory that is not group/world writable."
            echo "Create it with:"
            echo "  sudo install -d -m 0700 ${DIAG_DIR}"
        } >"${DIAG_OUT_DIR}/untrusted_diag_dir_${start_epoch}.txt"
        return
    fi

    find "${DIAG_DIR}" -maxdepth 1 -type f -printf '%T@ %p\n' | sort -n >"${inventory}" 2>/dev/null || true

    while IFS= read -r -d '' file; do
        cp -p --no-dereference -- "${file}" "${dest}/"
    done < <(
        find "${DIAG_DIR}" -maxdepth 1 -type f \
            \( -name 'cake_diag_*.txt' -o -name 'cake_diag_*.json' -o -name 'cake_diag_latest.txt' -o -name 'cake_diag_latest.json' -o -name 'tui_dump_*.txt' -o -name 'tui_dump_*.json' \) \
            -newermt "@${start_epoch}" -print0 2>/dev/null || true
    )

    for latest in cake_diag_latest.txt cake_diag_latest.json; do
        if [[ -f "${DIAG_DIR}/${latest}" && ! -L "${DIAG_DIR}/${latest}" ]]; then
            mtime="$(stat -c '%Y' -- "${DIAG_DIR}/${latest}" 2>/dev/null || echo 0)"
            if [[ "${mtime}" =~ ^[0-9]+$ && "${mtime}" -ge "${start_epoch}" ]]; then
                cp -p --no-dereference -- "${DIAG_DIR}/${latest}" "${dest}/"
            else
                printf 'Skipped stale %s with mtime %s before run start %s\n' \
                    "${DIAG_DIR}/${latest}" "${mtime}" "${start_epoch}" \
                    >>"${DIAG_OUT_DIR}/stale_latest_${start_epoch}.txt"
            fi
        fi
    done
}

write_metadata() {
    local active_ops cpu_model
    active_ops="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true)"
    cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || true)"

    {
        echo "# scx_cake Benchmark Capture"
        echo
        echo "- Benchmark: ${BENCHMARK}"
        echo "- Label: ${BENCH_LABEL}"
        echo "- Started UTC: ${STAMP}"
        echo "- Active ops: ${active_ops:-<none>}"
        echo "- Kernel: $(uname -a)"
        echo "- CPU: ${cpu_model:-unknown}"
        echo "- CPUs: $(nproc)"
        echo "- Git head: $(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
        echo "- Capture mode: ${CAPTURE_MODE}"
        echo "- Repeats: ${REPEATS}"
        echo "- Warmup: ${WARMUP}"
        echo "- Post benchmark diagnostic wait: ${POST_SLEEP}s"
        echo "- BPF perf stat: ${CAPTURE_BPF}"
        echo "- Timehist wakeups: ${TIMEHIST_WAKEUPS}"
        echo "- Diagnostic source: ${DIAG_DIR}"
        echo
        echo "## Command"
        echo
        echo '```bash'
        command_line
        echo '```'
        echo
        echo "## Review Order"
        echo
        echo "1. Check logs/*.status for failed passes."
        echo "2. Read perf/*.perf_stat.csv for system-wide scheduling and cache counters."
        echo "3. Read perf/*.perf_sched_latency.txt for max/avg runtime and switch pressure."
        echo "4. Compare diag/from_*/cake_diag_latest.txt and .json to the benchmark window."
        echo "5. Use perf/*timehist_summary.txt for sched runtime summaries."
        echo "6. Use the timestamped perf sched .data file only when deeper timehist analysis is needed."
    } >"${RUN_DIR}/summary.md"
}

PERF_LIST="$(perf list 2>/dev/null || true)"
SYSTEM_EVENTS=(
    task-clock
    context-switches
    cpu-migrations
    page-faults
    cycles
    instructions
    branches
    branch-misses
    cache-references
    cache-misses
)
BPF_EVENTS=(
    cycles
    instructions
    branches
    branch-misses
)

append_if_supported() {
    local event="$1"
    if grep -Fq "${event}" <<<"${PERF_LIST}"; then
        SYSTEM_EVENTS+=("${event}")
        BPF_EVENTS+=("${event}")
    fi
}

append_if_supported l1-dcache-loads
append_if_supported l1-dcache-load-misses
append_if_supported l2_cache_req_stat.ls_rd_blk_c
append_if_supported l2_cache_req_stat.ls_rd_blk_l_hit_s
append_if_supported l2_cache_req_stat.ls_rd_blk_l_hit_x
append_if_supported l2_fill_rsp_src.local_ccx
append_if_supported l2_fill_rsp_src.near_cache
append_if_supported l2_fill_rsp_src.far_cache

require_active_scheduler
build_benchmark_command
write_metadata

RUN_START_EPOCH="$(date +%s)"
log "output: ${RUN_DIR}"
log "diagnostic source: ${DIAG_DIR}"
log "benchmark command: $(command_line)"

for ((i = 1; i <= WARMUP; i++)); do
    run_plain_pass "warmup_${i}"
done

for ((i = 1; i <= REPEATS; i++)); do
    case "${CAPTURE_MODE}" in
        both)
            run_perf_stat_pass "repeat_${i}_stat"
            if [[ "${CAPTURE_BPF}" == "1" ]]; then
                run_bpf_stat_pass "repeat_${i}_bpf"
            fi
            run_perf_sched_pass "repeat_${i}_sched"
            ;;
        stat)
            run_perf_stat_pass "repeat_${i}_stat"
            if [[ "${CAPTURE_BPF}" == "1" ]]; then
                run_bpf_stat_pass "repeat_${i}_bpf"
            fi
            ;;
        sched)
            run_perf_sched_pass "repeat_${i}_sched"
            ;;
        time|none)
            run_plain_pass "repeat_${i}_time"
            ;;
    esac
done

if [[ "${POST_SLEEP}" -gt 0 ]]; then
    log "waiting ${POST_SLEEP}s before copying diagnostics"
    sleep "${POST_SLEEP}"
fi

copy_diag_outputs "${RUN_START_EPOCH}"

log "capture complete: ${RUN_DIR}"
if [[ "${RUN_FAILED}" -ne 0 ]]; then
    log "one or more passes failed; artifacts were still preserved"
    exit 1
fi
