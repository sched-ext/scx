#!/usr/bin/env bash
# Run the same benchmark suite across scx_cake configs and sibling schedulers.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh [--schedulers cake,pandemonium,lavd] [--all|--core]
  sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh --all-schedulers --all
  sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh --cake-config-plan /tmp/.../config_plan.tsv --schedulers cake,pandemonium,lavd

What it does:
  - starts one scheduler at a time
  - runs the benchmark suite sequentially
  - stops that scheduler
  - writes an analysis.md comparison report at the end

Options:
  --schedulers LIST      comma-separated scheduler list; accepts cake or scx_cake
  --all-schedulers       use every scheds/rust/scx_* package found in this repo
  --cake-config-plan TSV replace the cake entry with every config in the plan TSV
  --all                  run full suite; default
  --core                 run core suite only
  --report               write analysis.md after the matrix; default
  --no-report            skip analysis.md
  --list                 list discovered scheduler packages and exit
  --dry-run              print commands without starting schedulers

Environment:
  SCX_MATRIX_SCHEDULERS=cake,pandemonium,lavd,p2dq,flash
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_MATRIX_OUT=.scx_cake_bench/matrix
  SCX_MATRIX_CAPTURE=stat
  SCX_MATRIX_START_WAIT=15
  SCX_MATRIX_COOLDOWN=10
  SCX_MATRIX_DIAG_PERIOD=2
  SCX_MATRIX_DIAG_WAIT=3
  SCX_MATRIX_REPORT=1

Per-scheduler overrides:
  SCX_MATRIX_COMMAND_SCX_LAVD='/path/to/scx_lavd --some-flag'
  SCX_MATRIX_ARGS_SCX_LAVD='--some-flag'
  SCX_MATRIX_ARGS_LAVD='--some-flag'
  SCX_MATRIX_CAKE_ARGS='--profile gaming --storm-guard shadow'
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

require_bool() {
    local name="$1"
    local value="$2"
    [[ "${value}" =~ ^[01]$ ]] || die "${name} must be 0 or 1"
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

safe_name() {
    local value="$1"
    value="${value//[^a-zA-Z0-9_.-]/_}"
    [[ -n "${value}" ]] || value="entry"
    printf '%s' "${value}"
}

upper_name() {
    printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
SUITE="${SCRIPT_DIR}/scx_cake_bench_suite.sh"
REPORTER="${SCRIPT_DIR}/scx_cake_bench_report.sh"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"

SCHEDULERS="${SCX_MATRIX_SCHEDULERS:-cake,pandemonium,lavd,p2dq,flash}"
ALL_SCHEDULERS=0
CAKE_CONFIG_PLAN="${SCX_MATRIX_CAKE_CONFIG_PLAN:-}"
MODE="${SCX_MATRIX_SUITE_MODE:-all}"
DRY_RUN="${SCX_MATRIX_DRY_RUN:-0}"
REPORT="${SCX_MATRIX_REPORT:-1}"
CAPTURE_MODE="${SCX_MATRIX_CAPTURE:-stat}"
OUT_BASE="${SCX_MATRIX_OUT:-${BENCH_ROOT}/matrix}"
START_WAIT="${SCX_MATRIX_START_WAIT:-15}"
COOLDOWN="${SCX_MATRIX_COOLDOWN:-10}"
DIAG_PERIOD="${SCX_MATRIX_DIAG_PERIOD:-2}"
DIAG_WAIT="${SCX_MATRIX_DIAG_WAIT:-3}"
LIST_ONLY=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
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
        --cake-config-plan=*)
            CAKE_CONFIG_PLAN="${1#*=}"
            ;;
        --cake-config-plan)
            shift
            [[ "$#" -gt 0 ]] || die "--cake-config-plan requires a TSV file"
            CAKE_CONFIG_PLAN="$1"
            ;;
        --all)
            MODE="all"
            ;;
        --core)
            MODE="core"
            ;;
        --report)
            REPORT=1
            ;;
        --no-report)
            REPORT=0
            ;;
        --list)
            LIST_ONLY=1
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
    *) die "suite mode must be all or core" ;;
esac

case "${CAPTURE_MODE}" in
    stat|both|sched|time|none) ;;
    *) die "SCX_MATRIX_CAPTURE must be one of: stat, both, sched, time, none" ;;
esac

require_bool SCX_MATRIX_DRY_RUN "${DRY_RUN}"
require_bool SCX_MATRIX_REPORT "${REPORT}"
require_uint SCX_MATRIX_START_WAIT "${START_WAIT}"
require_uint SCX_MATRIX_COOLDOWN "${COOLDOWN}"
require_uint SCX_MATRIX_DIAG_PERIOD "${DIAG_PERIOD}"
require_uint SCX_MATRIX_DIAG_WAIT "${DIAG_WAIT}"
[[ -f "${SUITE}" ]] || die "missing suite helper: ${SUITE}"
if [[ -n "${CAKE_CONFIG_PLAN}" && ! -f "${CAKE_CONFIG_PLAN}" ]]; then
    die "cake config plan not found: ${CAKE_CONFIG_PLAN}"
fi

discover_schedulers() {
    find "${REPO_ROOT}/scheds/rust" -mindepth 2 -maxdepth 2 -type f -name Cargo.toml |
        while IFS= read -r cargo; do
            awk -F'"' '/^name = "scx_/ { print $2; exit }' "${cargo}"
        done |
        sort
}

if [[ "${LIST_ONLY}" == "1" ]]; then
    discover_schedulers
    exit 0
fi

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

declare -a ENTRY_LABELS=()
declare -a ENTRY_SCHEDULERS=()
declare -a ENTRY_CAKE_ARGS=()

add_entry() {
    ENTRY_LABELS+=("$1")
    ENTRY_SCHEDULERS+=("$2")
    ENTRY_CAKE_ARGS+=("${3:-}")
}

add_cake_plan_entries() {
    local line_no=0
    local label args rationale
    while IFS=$'\t' read -r label args rationale; do
        line_no=$((line_no + 1))
        [[ "${line_no}" -eq 1 && "${label}" == "label" ]] && continue
        [[ -n "${label}" && -n "${args}" ]] || continue
        add_entry "cake-${label}" "scx_cake" "${args}"
    done <"${CAKE_CONFIG_PLAN}"
}

add_scheduler_entries() {
    local raw="$1"
    local scheduler normalized
    IFS=',' read -r -a requested <<<"${raw}"
    for scheduler in "${requested[@]}"; do
        normalized="$(normalize_scheduler "${scheduler}")"
        [[ -n "${normalized}" ]] || continue
        if [[ "${normalized}" == "scx_cake" && -n "${CAKE_CONFIG_PLAN}" ]]; then
            add_cake_plan_entries
        else
            add_entry "${normalized}" "${normalized}" ""
        fi
    done
}

if [[ "${ALL_SCHEDULERS}" == "1" ]]; then
    SCHEDULERS="$(discover_schedulers | paste -sd, -)"
fi

add_scheduler_entries "${SCHEDULERS}"

if [[ "${#ENTRY_LABELS[@]}" -eq 0 ]]; then
    die "no scheduler entries selected"
fi

active_ops() {
    cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true
}

expected_ops_for_scheduler() {
    local scheduler="$1"
    case "${scheduler}" in
        scx_cake)
            printf 'cake'
            ;;
        scx_*)
            printf '%s' "${scheduler#scx_}"
            ;;
        *)
            printf '%s' "${scheduler}"
            ;;
    esac
}

scheduler_binary() {
    local scheduler="$1"
    printf '%s/target/debug/%s' "${REPO_ROOT}" "${scheduler}"
}

declare -a SCHED_CMD=()
SCHED_CMD_IS_SHELL=0
SCHED_CMD_STRING=""

build_scheduler_command() {
    local label="$1"
    local scheduler="$2"
    local cake_args="$3"
    local diag_dir="$4"
    local upper short_upper cmd_var args_var short_args_var cmd_override args bin
    local -a extra_args=()

    upper="$(upper_name "${scheduler}")"
    short_upper="$(upper_name "${scheduler#scx_}")"
    cmd_var="SCX_MATRIX_COMMAND_${upper}"
    args_var="SCX_MATRIX_ARGS_${upper}"
    short_args_var="SCX_MATRIX_ARGS_${short_upper}"
    cmd_override="${!cmd_var-}"

    SCHED_CMD=()
    SCHED_CMD_IS_SHELL=0
    SCHED_CMD_STRING=""

    if [[ -n "${cmd_override}" ]]; then
        SCHED_CMD_IS_SHELL=1
        SCHED_CMD_STRING="${cmd_override}"
        return
    fi

    bin="$(scheduler_binary "${scheduler}")"
    args="${!args_var-}"
    if [[ -z "${args}" ]]; then
        args="${!short_args_var-}"
    fi

    if [[ "${scheduler}" == "scx_cake" ]]; then
        if [[ -z "${cake_args}" ]]; then
            cake_args="${SCX_MATRIX_CAKE_ARGS:---profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false}"
        fi
        SCHED_CMD=("${bin}" --verbose --diag-dir "${diag_dir}" --diag-period "${DIAG_PERIOD}")
        read -r -a extra_args <<<"${cake_args}"
        if [[ "${#extra_args[@]}" -gt 0 ]]; then
            SCHED_CMD+=("${extra_args[@]}")
        fi
    else
        SCHED_CMD=("${bin}")
        read -r -a extra_args <<<"${args}"
        if [[ "${#extra_args[@]}" -gt 0 ]]; then
            SCHED_CMD+=("${extra_args[@]}")
        fi
    fi
}

format_scheduler_command() {
    if [[ "${SCHED_CMD_IS_SHELL}" == "1" ]]; then
        printf '%s' "${SCHED_CMD_STRING}"
        return
    fi
    printf '%q ' "${SCHED_CMD[@]}"
}

start_scheduler_command() {
    if [[ "${SCHED_CMD_IS_SHELL}" == "1" ]]; then
        bash -lc "${SCHED_CMD_STRING}"
    else
        "${SCHED_CMD[@]}"
    fi
}

start_scheduler_background() {
    local log_file="$1"

    if [[ "${SCHED_CMD_IS_SHELL}" == "1" ]]; then
        setsid bash -lc "${SCHED_CMD_STRING}" >"${log_file}" 2>&1 &
    else
        setsid "${SCHED_CMD[@]}" >"${log_file}" 2>&1 &
    fi
    scheduler_pid=$!
}

active_ops_matches() {
    local expected="$1"
    local ops

    ops="$(active_ops)"
    [[ -n "${ops}" && ( "${ops}" == "${expected}"* || "${ops}" == *"${expected}"* ) ]]
}

wait_for_scheduler() {
    local pid="$1"
    local expected="$2"
    local log_file="$3"
    local i ops

    for ((i = 0; i < START_WAIT; i++)); do
        if ! kill -0 "${pid}" >/dev/null 2>&1; then
            return 2
        fi
        ops="$(active_ops)"
        if [[ -n "${ops}" ]]; then
            if [[ "${ops}" == "${expected}"* || "${ops}" == *"${expected}"* ]]; then
                return 0
            fi
        fi
        sleep 1
    done

    {
        echo "expected active ops containing: ${expected}"
        echo "last active ops: ${ops:-<none>}"
    } >>"${log_file}"
    return 1
}

wait_for_sched_ext_empty() {
    local label="$1"
    local i ops

    for ((i = 0; i < START_WAIT; i++)); do
        ops="$(active_ops)"
        if [[ -z "${ops}" ]]; then
            return 0
        fi
        sleep 1
    done

    echo "sched_ext still active after stopping ${label}: ${ops:-<none>}"
    return 1
}

stop_scheduler() {
    local pid="${1:-}"
    local label="${2:-scheduler}"
    local stop_status=0

    [[ -n "${pid}" ]] || return 0
    echo "stopping ${label} pid ${pid}"
    kill -TERM -- "-${pid}" >/dev/null 2>&1 || kill -TERM "${pid}" >/dev/null 2>&1 || true
    if kill -0 "${pid}" >/dev/null 2>&1; then
        wait "${pid}" >/dev/null 2>&1 || true
    fi
    wait_for_sched_ext_empty "${label}" || stop_status=1
    if [[ "${CURRENT_SCHED_PID:-}" == "${pid}" ]]; then
        CURRENT_SCHED_PID=""
        CURRENT_SCHED_LABEL=""
    fi
    return "${stop_status}"
}

run_suite_with_guard() {
    local expected="$1"
    local scheduler_pid="$2"
    local label="$3"
    local diag_dir="$4"
    local suite_out="$5"
    local require_cake="$6"
    local suite_pid suite_status guard_status

    guard_status=0
    SCX_CAKE_DIAG_DIR="${diag_dir}" \
    SCX_CAKE_SUITE_OUT="${suite_out}" \
    SCX_CAKE_SUITE_CAPTURE="${CAPTURE_MODE}" \
    SCX_CAKE_SUITE_PAUSE_SECS="${COOLDOWN}" \
    SCX_CAKE_BENCH_POST_SLEEP="${DIAG_WAIT}" \
    SCX_CAKE_BENCH_REQUIRE_CAKE="${require_cake}" \
    SCX_CAKE_BENCH_REQUIRE_OPS="${expected}" \
        setsid "${SUITE}" "--${MODE}" &
    suite_pid=$!

    while kill -0 "${suite_pid}" >/dev/null 2>&1; do
        if ! kill -0 "${scheduler_pid}" >/dev/null 2>&1; then
            echo "scheduler exited while suite was running for ${label}"
            guard_status=97
            kill -TERM -- "-${suite_pid}" >/dev/null 2>&1 || kill -TERM "${suite_pid}" >/dev/null 2>&1 || true
            break
        fi
        if ! active_ops_matches "${expected}"; then
            echo "active sched_ext ops changed while suite was running for ${label}: $(active_ops)"
            guard_status=98
            kill -TERM -- "-${suite_pid}" >/dev/null 2>&1 || kill -TERM "${suite_pid}" >/dev/null 2>&1 || true
            break
        fi
        sleep 1
    done

    wait "${suite_pid}" >/dev/null 2>&1
    suite_status=$?
    if [[ "${guard_status}" -ne 0 ]]; then
        return "${guard_status}"
    fi
    return "${suite_status}"
}

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -L "${OUT_BASE}" ]]; then
    die "output base must not be a symlink: ${OUT_BASE}"
fi
mkdir -p -m 0700 "${OUT_BASE}"
require_trusted_output_base "${OUT_BASE}"
MATRIX_DIR="$(mktemp -d -p "${OUT_BASE}" "${STAMP}_${MODE}_scheduler-matrix.XXXXXX")" ||
    die "failed to create matrix directory under ${OUT_BASE}"
SUMMARY="${MATRIX_DIR}/summary.md"
mkdir -p -m 0700 "${MATRIX_DIR}"
CURRENT_SCHED_PID=""
CURRENT_SCHED_LABEL=""
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_scheduler "${CURRENT_SCHED_PID}" "${CURRENT_SCHED_LABEL}" || true
    give_output_to_sudo_user "${MATRIX_DIR}"
    return "${status}"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

{
    echo "# scx Scheduler Matrix"
    echo
    echo "- Started UTC: ${STAMP}"
    echo "- Suite mode: ${MODE}"
    echo "- Capture mode: ${CAPTURE_MODE}"
    echo "- Output: ${MATRIX_DIR}"
    echo "- Cake config plan: ${CAKE_CONFIG_PLAN:-<none>}"
    echo
    echo "| Seq | Variant | Scheduler | Status | Run dir |"
    echo "| ---: | --- | --- | --- | --- |"
} >"${SUMMARY}"

echo "scx scheduler benchmark matrix"
echo "output: ${MATRIX_DIR}"
echo "bench root: ${BENCH_ROOT}"
echo "suite mode: ${MODE}"
echo "capture mode: ${CAPTURE_MODE}"
echo "entries: ${#ENTRY_LABELS[@]}"

if [[ "${DRY_RUN}" != "1" && "${EUID}" -ne 0 ]]; then
    die "run with sudo so schedulers can load BPF and perf can collect counters"
fi

matrix_status=0
for idx in "${!ENTRY_LABELS[@]}"; do
    seq=$((idx + 1))
    label="${ENTRY_LABELS[idx]}"
    scheduler="${ENTRY_SCHEDULERS[idx]}"
    cake_args="${ENTRY_CAKE_ARGS[idx]}"
    safe_label="$(safe_name "${label}")"
    run_dir="${MATRIX_DIR}/${STAMP}_${MODE}_scheduler-${safe_label}_seq$(printf '%02d' "${seq}")"
    log_dir="${run_dir}/logs"
    diag_dir="${run_dir}/diag/live"
    suite_out="${run_dir}/suite"
    mkdir -p -m 0700 "${log_dir}" "${diag_dir}" "${suite_out}"
    log_file="${log_dir}/${scheduler}.log"
    build_scheduler_command "${label}" "${scheduler}" "${cake_args}" "${diag_dir}"
    command_string="$(format_scheduler_command)"
    expected_ops="$(expected_ops_for_scheduler "${scheduler}")"
    scheduler_pid=""

    echo
    echo "### seq $(printf '%02d' "${seq}") ${label}"
    echo "scheduler: ${scheduler}"
    echo "command: ${command_string}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "| ${seq} | ${label} | ${scheduler} | dry-run | $(basename "${run_dir}") |" >>"${SUMMARY}"
        continue
    fi

    bin="$(scheduler_binary "${scheduler}")"
    cmd_var="SCX_MATRIX_COMMAND_$(upper_name "${scheduler}")"
    cmd_override="${!cmd_var-}"
    if [[ -z "${cmd_override}" && ! -x "${bin}" ]]; then
        echo "missing binary: ${bin}"
        echo "| ${seq} | ${label} | ${scheduler} | missing binary | $(basename "${run_dir}") |" >>"${SUMMARY}"
        matrix_status=1
        continue
    fi

    preexisting_ops="$(active_ops)"
    if [[ -n "${preexisting_ops}" ]]; then
        echo "sched_ext already active before ${label}: ${preexisting_ops}"
        echo "| ${seq} | ${label} | ${scheduler} | blocked active ${preexisting_ops} | $(basename "${run_dir}") |" >>"${SUMMARY}"
        matrix_status=1
        continue
    fi

    start_scheduler_background "${log_file}"
    CURRENT_SCHED_PID="${scheduler_pid}"
    CURRENT_SCHED_LABEL="${label}"

    set +e
    wait_for_scheduler "${scheduler_pid}" "${expected_ops}" "${log_file}"
    wait_status=$?
    set -e
    if [[ "${wait_status}" -ne 0 ]]; then
        echo "scheduler did not become active; see ${log_file}"
        stop_scheduler "${scheduler_pid}" "${label}" || true
        echo "| ${seq} | ${label} | ${scheduler} | failed start ${wait_status} | $(basename "${run_dir}") |" >>"${SUMMARY}"
        matrix_status=1
        continue
    fi

    echo "active ops: $(active_ops)"
    require_cake=0
    if [[ "${scheduler}" == "scx_cake" ]]; then
        require_cake=1
        for ((i = 0; i < START_WAIT; i++)); do
            if [[ -f "${diag_dir}/cake_diag_latest.txt" || -f "${diag_dir}/cake_diag_latest.json" ]]; then
                break
            fi
            sleep 1
        done
    fi

    set +e
    run_suite_with_guard "${expected_ops}" "${scheduler_pid}" "${label}" \
        "${diag_dir}" "${suite_out}" "${require_cake}"
    suite_status=$?
    set -e

    set +e
    stop_scheduler "${scheduler_pid}" "${label}"
    stop_status=$?
    set -e

    if [[ "${suite_status}" -eq 0 && "${stop_status}" -eq 0 ]]; then
        echo "| ${seq} | ${label} | ${scheduler} | passed | $(basename "${run_dir}") |" >>"${SUMMARY}"
    else
        echo "| ${seq} | ${label} | ${scheduler} | failed suite ${suite_status} stop ${stop_status} | $(basename "${run_dir}") |" >>"${SUMMARY}"
        matrix_status=1
    fi
done

if [[ "${REPORT}" == "1" && "${DRY_RUN}" != "1" ]]; then
    if [[ -x "${REPORTER}" ]]; then
        echo
        echo "writing matrix analysis report"
        if ! "${REPORTER}" "${MATRIX_DIR}"; then
            matrix_status=1
        fi
    else
        echo "error: report helper is not executable: ${REPORTER}" >&2
        matrix_status=1
    fi
fi

echo
echo "scheduler matrix complete"
echo "summary: ${SUMMARY}"
if [[ -f "${MATRIX_DIR}/analysis.md" ]]; then
    echo "analysis: ${MATRIX_DIR}/analysis.md"
fi
exit "${matrix_status}"
