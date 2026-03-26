#!/usr/bin/env bash
# benchmark.sh — Baseline vs cake vs bpfland vs scx_timely comparison helpers.

set -euo pipefail

RED=$(printf '\033[0;31m')
GRN=$(printf '\033[0;32m')
YLW=$(printf '\033[1;33m')
CYN=$(printf '\033[0;36m')
BLD=$(printf '\033[1m')
RST=$(printf '\033[0m')

say()  { printf "${BLD}${CYN}[benchmark]${RST} %s\n" "$1"; }
ok()   { printf "${BLD}${GRN}[  OK  ]${RST} %s\n" "$1"; }
warn() { printf "${BLD}${YLW}[ WARN ]${RST} %s\n" "$1"; }
err()  { printf "${BLD}${RED}[ERROR ]${RST} %s\n" "$1" >&2; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUITE="mini"
MODE="desktop"
RUNS=1
DROP_CACHES=0
BOOTSTRAP_PLOTTER=0
CHECK_DEPS_ONLY=0
ADAPTIVE_SCOPE=1
BENCHMARK_CMD="${BENCHMARK_CMD:-}"
PLOTTER="$SCRIPT_DIR/mini_benchmarker_plot.py"
PLOTTER_PYTHON="${PLOTTER_PYTHON:-python3}"
TIMELY_EXTRA_ARGS=()
RESULTS_DIR=""
WORKDIR=""
STATE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely"
STATE_FILE="$STATE_DIR/benchmark-running.env"

MINI_LOCAL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/scx_timely/mini-benchmarker"
MINI_LOCAL_SCRIPT="$MINI_LOCAL_DIR/mini-benchmarker.sh"
CACHYOS_LOCAL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/scx_timely/cachyos-benchmarker"
CACHYOS_LOCAL_SCRIPT="$CACHYOS_LOCAL_DIR/cachyos-benchmarker"
TIMELY_BIN=""
BPFLAND_BIN=""
CAKE_BIN=""
INITIAL_SERVICE_ACTIVE=0
RESTORE_NEEDED=0
SUDO_KEEPALIVE_PID=""
BASELINE_LABEL=""
POWER_PROFILE="unknown"
BENCHMARK_LABEL="Mini Benchmarker"
CURRENT_RUNTIME_LOG=""
CURRENT_SCHEDULER_VERSION=""
CURRENT_SCHEDULER_NAME=""
CURRENT_BENCHMARK_PID=""
CURRENT_BENCHMARK_MAX_TESTS=0
ADAPTIVE_SCOPE_LIMIT=0

write_runtime_state() {
    mkdir -p "$STATE_DIR"
    {
        printf 'PARENT_PID=%q\n' "$$"
        printf 'BENCHMARK_PID=%q\n' "${CURRENT_BENCHMARK_PID:-}"
        printf 'SCHEDULER_NAME=%q\n' "${CURRENT_SCHEDULER_NAME:-}"
        printf 'SCHEDULER_VERSION=%q\n' "${CURRENT_SCHEDULER_VERSION:-}"
        printf 'RUNTIME_LOG=%q\n' "${CURRENT_RUNTIME_LOG:-}"
        printf 'RESULTS_DIR=%q\n' "${RESULTS_DIR:-}"
        printf 'WORKDIR=%q\n' "${WORKDIR:-}"
        printf 'SCRIPT_DIR=%q\n' "$SCRIPT_DIR"
        printf 'UPDATED_AT=%q\n' "$(date -Iseconds)"
    } > "$STATE_FILE"
}

clear_runtime_state() {
    rm -f "$STATE_FILE"
}

usage() {
    cat <<EOF
Usage: ./benchmark.sh [options]

Automate scheduler comparisons for:
  1. Baseline (no sched_ext scheduler)
  2. scx_cake
  3. scx_bpfland
  4. scx_timely

Suites:
  --suite mini           Use torvic9's Mini Benchmarker (default)
  --suite cachyos        Use the full CachyOS benchmark wrapper
  --suite cachyos-quick  Use a reduced CachyOS RT-pressure screening run

Options:
  --suite mini|cachyos|cachyos-quick
                                 Benchmark suite to run
  --workdir DIR                 Benchmark asset/work directory
  --results-dir DIR             Directory for copied logs, chart, and CSV summary
  --mode desktop|powersave|server
                                 scx_timely profile for the scheduler run (default: desktop)
  --timely-arg VALUE             Extra argument passed through to scx_timely (repeatable)
  --runs N                      Number of repeated runs per variant (default: 1)
  --drop-caches                 Answer "yes" to the benchmark page-cache prompt
  --benchmark-cmd PATH          Path to the suite runner
  --bootstrap-plotter           Create a local venv with matplotlib if needed
  --check-deps                  Report benchmark prerequisites and exit
  --no-adaptive-scope           Always run the full suite for every variant
  -h, --help                    Show this help

Environment overrides:
  BENCHMARK_CMD                 Same as --benchmark-cmd
  PLOTTER_PYTHON                Python interpreter used for chart generation
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --suite)
            SUITE="$2"
            shift 2
            ;;
        --workdir)
            WORKDIR="$2"
            shift 2
            ;;
        --results-dir)
            RESULTS_DIR="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --timely-arg)
            TIMELY_EXTRA_ARGS+=("$2")
            shift 2
            ;;
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --drop-caches)
            DROP_CACHES=1
            shift
            ;;
        --benchmark-cmd)
            BENCHMARK_CMD="$2"
            shift 2
            ;;
        --bootstrap-plotter)
            BOOTSTRAP_PLOTTER=1
            shift
            ;;
        --check-deps)
            CHECK_DEPS_ONLY=1
            shift
            ;;
        --no-adaptive-scope)
            ADAPTIVE_SCOPE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

case "$SUITE" in
    mini|cachyos|cachyos-quick) ;;
    *)
        err "Unsupported suite '$SUITE'. Expected mini, cachyos, or cachyos-quick."
        exit 1
        ;;
esac

case "$MODE" in
    desktop|powersave|server) ;;
    *)
        err "Unsupported mode '$MODE'. Expected desktop, powersave, or server."
        exit 1
        ;;
esac

case "$RUNS" in
    ''|*[!0-9]*|0)
        err "--runs must be a positive integer"
        exit 1
        ;;
esac

if [ -z "$WORKDIR" ]; then
    case "$SUITE" in
        mini) WORKDIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely/mini-benchmarker-workdir" ;;
        cachyos|cachyos-quick) WORKDIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely/cachyos-benchmarker-workdir" ;;
    esac
fi

if [ -z "$RESULTS_DIR" ]; then
    RESULTS_DIR="$SCRIPT_DIR/benchmark-results/${SUITE}-benchmarker-$(date +%Y%m%d-%H%M%S)"
fi

case "$SUITE" in
    mini) BENCHMARK_LABEL="Mini Benchmarker" ;;
    cachyos) BENCHMARK_LABEL="CachyOS Benchmarker" ;;
    cachyos-quick) BENCHMARK_LABEL="CachyOS Quick RT Bench" ;;
esac

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo -n "$@"
    fi
}

ensure_sudo_ready() {
    if [ "$(id -u)" -eq 0 ]; then
        return
    fi
    command -v sudo >/dev/null 2>&1 || {
        err "sudo is required to stop/start schedulers when running as a non-root user."
        exit 1
    }
    say "Refreshing sudo credentials for scheduler stop/start"
    sudo -v
}

start_sudo_keepalive() {
    if [ "$(id -u)" -eq 0 ]; then
        return
    fi
    if [ -n "$SUDO_KEEPALIVE_PID" ] && kill -0 "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1; then
        return
    fi
    (
        while true; do
            sudo -n true >/dev/null 2>&1 || exit 0
            sleep 60
        done
    ) &
    SUDO_KEEPALIVE_PID=$!
}

stop_sudo_keepalive() {
    if [ -n "$SUDO_KEEPALIVE_PID" ] && kill -0 "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1; then
        kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
        wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    fi
    SUDO_KEEPALIVE_PID=""
}

detect_baseline_label() {
    local kernel_name
    kernel_name=$(uname -sr 2>/dev/null || true)
    if [ -n "$kernel_name" ]; then
        BASELINE_LABEL="$kernel_name"
    else
        BASELINE_LABEL="Baseline"
    fi
}

count_completed_benchmarks_from_log() {
    local log_path="$1"
    [ -f "$log_path" ] || {
        printf '%s\n' 0
        return
    }

    "$PLOTTER_PYTHON" - "$log_path" "$SUITE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
suite = sys.argv[2]
text = path.read_text(encoding="utf-8", errors="replace")

full = [
    "stress-ng cpu-cache-mem",
    "y-cruncher pi 1b",
    "perf sched msg fork thread",
    "perf memcpy",
    "namd 92K atoms",
    "calculating prime numbers",
    "argon2 hashing",
    "ffmpeg compilation",
    "xz compression",
    "kernel defconfig",
    "blender render",
    "x265 encoding",
]

if suite == "cachyos-quick":
    names = full[:5]
else:
    names = full

count = 0
for name in names:
    if re.search(rf'^(?:\*\s+)?{re.escape(name)}:\s+[0-9]', text, re.M):
        count += 1
    else:
        break

print(count)
PY
}

update_adaptive_scope_limit() {
    local completed="$1"
    case "$completed" in
        ''|*[!0-9]*) completed=0 ;;
    esac
    [ "$completed" -gt 0 ] || return 0

    if [ "$ADAPTIVE_SCOPE_LIMIT" -eq 0 ] || [ "$completed" -lt "$ADAPTIVE_SCOPE_LIMIT" ]; then
        ADAPTIVE_SCOPE_LIMIT="$completed"
    fi
}

detect_power_profile() {
    local profile=""
    if command -v powerprofilesctl >/dev/null 2>&1; then
        profile=$(powerprofilesctl get 2>/dev/null || true)
    elif command -v tuned-adm >/dev/null 2>&1; then
        profile=$(tuned-adm active 2>/dev/null | sed 's/^Current active profile: //')
    fi
    if [ -n "$profile" ]; then
        POWER_PROFILE="$profile"
    fi
}

detect_binary_version() {
    local bin="$1"
    local version_line=""

    version_line=$("$bin" --version 2>/dev/null | head -n 1 || true)
    if [ -z "$version_line" ]; then
        printf '%s\n' ""
        return
    fi

    case "$version_line" in
        *" "*)
            printf '%s\n' "${version_line#* }"
            ;;
        *)
            printf '%s\n' "$version_line"
            ;;
    esac
}

warn_if_running_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        warn "Running the whole benchmark as root changes HOME and benchmark cache paths."
        warn "Prefer running ./benchmark.sh as your normal user and let it prompt for sudo when needed."
    fi
}

current_sched_ext_ops() {
    if [ -r /sys/kernel/sched_ext/root/ops ]; then
        cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true
    fi
}

scheduler_is_active() {
    local name="$1"
    case "$(current_sched_ext_ops)" in
        *"$name"*) return 0 ;;
    esac
    pgrep -x "scx_${name}" >/dev/null 2>&1
}

service_exists() {
    command -v systemctl >/dev/null 2>&1 && systemctl cat scx.service >/dev/null 2>&1
}

service_is_active() {
    service_exists && systemctl is-active --quiet scx.service
}

patch_local_mini_script() {
    [ -f "$MINI_LOCAL_SCRIPT" ] || return 0
    if ! grep -q 'MB_TIME_BIN=' "$MINI_LOCAL_SCRIPT"; then
        sed -i '/^TMP="\/tmp"$/a\
MB_TIME_BIN=""\
for candidate in /usr/bin/time /bin/time /usr/local/bin/time /opt/homebrew/bin/gtime /usr/local/bin/gtime; do\
\tif [ -x "$candidate" ]; then\
\t\tMB_TIME_BIN="$candidate"\
\t\tbreak\
\tfi\
done\
[[ -z "$MB_TIME_BIN" ]] && echo "GNU time executable not found. Please install the time package." && exit 3\
' "$MINI_LOCAL_SCRIPT"
        sed -i 's#/usr/bin/time #$MB_TIME_BIN #g' "$MINI_LOCAL_SCRIPT"
    fi

    if grep -q 'MB_MAX_TESTS=' "$MINI_LOCAL_SCRIPT"; then
        return 0
    fi

    "$PLOTTER_PYTHON" - "$MINI_LOCAL_SCRIPT" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

old_vars = """VER="v2.3"
CDATE=$(date +%F-%H%M)
RAMSIZE=$(awk '/MemTotal/{print int($2 / 1000)}' /proc/meminfo)
CPUCORES=$(nproc)
CPUFREQ=$(awk '{print $1 / 1000000}' /sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq)
COEFF="$(python -c "print(round((($CPUCORES + 1) / 2 * $CPUFREQ / 2) ** (1/3),2))")"
KERNVER="6.18.16"
YCVER="v0.8.7.9547"
FFMVER="8.0.1"
"""

new_vars = """VER="v2.3"
CDATE=$(date +%F-%H%M)
RAMSIZE=$(awk '/MemTotal/{print int($2 / 1000)}' /proc/meminfo)
CPUCORES=$(nproc)
CPUFREQ=$(awk '{print $1 / 1000000}' /sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq)
COEFF="$(python -c "print(round((($CPUCORES + 1) / 2 * $CPUFREQ / 2) ** (1/3),2))")"
KERNVER="6.18.16"
YCVER="v0.8.7.9547"
FFMVER="8.0.1"
MB_MAX_TESTS="${MB_MAX_TESTS:-12}"
"""

old_run = """# run
NRTESTS=12
declare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.85 0.85 0.8 0.95 0.95 1 0.95 1)
checkfiles && checksys && header || exit 8
runstress && sleep 2 || exit 8
runyc && sleep 2 || exit 8
runperf_sch && sleep 2 || exit 8
runperf_mem && sleep 2 || exit 8
runnamd && sleep 2 || exit 8
runprime && sleep 2 || exit 8
runargon && sleep 2 || exit 8
runffm && sleep 2 || exit 8
runxz && sleep 2 || exit 8
runkern && sleep 2 || exit 8
runblend && sleep 2 || exit 8
runx265 && sleep 2 || exit 8
"""

new_run = """# run
NRTESTS=$MB_MAX_TESTS
[[ $NRTESTS -lt 1 ]] && NRTESTS=1
[[ $NRTESTS -gt 12 ]] && NRTESTS=12
declare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.85 0.85 0.8 0.95 0.95 1 0.95 1)
checkfiles && checksys && header || exit 8
[[ $NRTESTS -ge 1 ]] && runstress && sleep 2 || [[ $NRTESTS -lt 1 ]] || exit 8
[[ $NRTESTS -ge 2 ]] && runyc && sleep 2 || [[ $NRTESTS -lt 2 ]] || exit 8
[[ $NRTESTS -ge 3 ]] && runperf_sch && sleep 2 || [[ $NRTESTS -lt 3 ]] || exit 8
[[ $NRTESTS -ge 4 ]] && runperf_mem && sleep 2 || [[ $NRTESTS -lt 4 ]] || exit 8
[[ $NRTESTS -ge 5 ]] && runnamd && sleep 2 || [[ $NRTESTS -lt 5 ]] || exit 8
[[ $NRTESTS -ge 6 ]] && runprime && sleep 2 || [[ $NRTESTS -lt 6 ]] || exit 8
[[ $NRTESTS -ge 7 ]] && runargon && sleep 2 || [[ $NRTESTS -lt 7 ]] || exit 8
[[ $NRTESTS -ge 8 ]] && runffm && sleep 2 || [[ $NRTESTS -lt 8 ]] || exit 8
[[ $NRTESTS -ge 9 ]] && runxz && sleep 2 || [[ $NRTESTS -lt 9 ]] || exit 8
[[ $NRTESTS -ge 10 ]] && runkern && sleep 2 || [[ $NRTESTS -lt 10 ]] || exit 8
[[ $NRTESTS -ge 11 ]] && runblend && sleep 2 || [[ $NRTESTS -lt 11 ]] || exit 8
[[ $NRTESTS -ge 12 ]] && runx265 && sleep 2 || [[ $NRTESTS -lt 12 ]] || exit 8
"""

if old_vars not in text:
    raise SystemExit(f"Could not find variable block in {path}")
if old_run not in text:
    raise SystemExit(f"Could not find run block in {path}")

text = text.replace(old_vars, new_vars, 1)
text = text.replace(old_run, new_run, 1)
path.write_text(text, encoding="utf-8")
PY
}

patch_local_cachyos_script() {
    [ -f "$CACHYOS_LOCAL_SCRIPT" ] || return 0
    if ! grep -q 'CB_TIME_BIN=' "$CACHYOS_LOCAL_SCRIPT"; then
        sed -i '/^TMP="\/tmp"$/a\
CB_TIME_BIN=""\
for candidate in /usr/bin/time /bin/time /usr/local/bin/time /opt/homebrew/bin/gtime /usr/local/bin/gtime; do\
\tif [ -x "$candidate" ]; then\
\t\tCB_TIME_BIN="$candidate"\
\t\tbreak\
\tfi\
done\
[[ -z "$CB_TIME_BIN" ]] && echo "GNU time executable not found. Please install the time package." && exit 3\
' "$CACHYOS_LOCAL_SCRIPT"
        sed -i 's#/usr/bin/time #$CB_TIME_BIN #g' "$CACHYOS_LOCAL_SCRIPT"
        sed -i 's/VERSION=$(pacman -Qi cachyos-benchmarker | grep "Version         :")/VERSION=$(pacman -Qi cachyos-benchmarker 2>\/dev\/null | grep "Version         :" || true)/' "$CACHYOS_LOCAL_SCRIPT"
        sed -i 's#python /usr/bin/benchmark_scraper.py#[ -x /usr/bin/benchmark_scraper.py ] \&\& python /usr/bin/benchmark_scraper.py || true#' "$CACHYOS_LOCAL_SCRIPT"
    fi

    if ! grep -q 'SCX_BIN_VERSION=' "$CACHYOS_LOCAL_SCRIPT"; then
        "$PLOTTER_PYTHON" - "$CACHYOS_LOCAL_SCRIPT" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = """# Set defaults as none
SCX=\"none\"
SCX_VERSION=\"\"
# update if we find them below

if [ -f \"/sys/kernel/sched_ext/root/ops\" ]; then
\tTMP=$(cat \"/sys/kernel/sched_ext/root/ops\")
\tif [ -n \"$TMP\" ]; then
\t\tSCX=$(awk -F'[[:digit:]]' '{print $1}' \"/sys/kernel/sched_ext/root/ops\" | sed -rn 's/^(.*)_$/\\1/p')
\t\tSCX_VERSION=$(sed -rn 's/^[^0-9]*([0-9]+(\\.[0-9]+)+).*$/\\1/p' \"/sys/kernel/sched_ext/root/ops\")
\tfi
fi
"""
new = """# Set defaults as none
SCX=\"none\"
SCX_VERSION=\"\"
SCX_BIN_VERSION=\"\"
# update if we find them below

if [ -f \"/sys/kernel/sched_ext/root/ops\" ]; then
\tTMP=$(cat \"/sys/kernel/sched_ext/root/ops\")
\tif [ -n \"$TMP\" ]; then
\t\tSCX=\"$TMP\"
\t\tPARSED_NAME=$(printf '%s\\n' \"$TMP\" | sed -rn 's/^([[:alnum:]-]+)_.*/\\1/p')
\t\tPARSED_VERSION=$(printf '%s\\n' \"$TMP\" | sed -rn 's/^[^0-9]*([0-9]+(\\.[0-9]+)+).*$/\\1/p')
\t\t[ -n \"$PARSED_NAME\" ] && SCX=\"$PARSED_NAME\"
\t\t[ -n \"$PARSED_VERSION\" ] && SCX_VERSION=\"$PARSED_VERSION\"
\tfi
fi

if [ \"$SCX\" != \"none\" ] && [ -z \"$SCX_VERSION\" ]; then
\tSCX_BIN=\"scx_${SCX}\"
\tif command -v \"$SCX_BIN\" >/dev/null 2>&1; then
\t\tSCX_BIN_VERSION=$($SCX_BIN --version 2>/dev/null | head -n 1)
\t\tSCX_VERSION=$(printf '%s\\n' \"$SCX_BIN_VERSION\" | awk '{print $2}')
\tfi
fi
"""
if old not in text:
    raise SystemExit(f"Could not find scheduler detection block in {path}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
    fi

    if grep -q 'CB_QUICK_MODE=' "$CACHYOS_LOCAL_SCRIPT" && grep -q 'CB_MAX_TESTS=' "$CACHYOS_LOCAL_SCRIPT"; then
        return 0
    fi

    "$PLOTTER_PYTHON" - "$CACHYOS_LOCAL_SCRIPT" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

old_vars = """VER="v2.2"
FFMPEGVER="7.0.1"
YCRUNCHER_VER="0.8.6.9545"
CDATE=$(date +%F-%H%M)
RAMSIZE=$(awk '/MemTotal/{print int($2 / 1000)}' /proc/meminfo)
CPUCORES=$(nproc)
CPUFREQ=$(awk '{print $1 / 1000000}' /sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq)
COEFF="$(python -c "print(round((($CPUCORES + 1) / 2 * $CPUFREQ / 2) ** (1/3),2))")"
KERNVER="6.14.7"
"""

old_vars_quick = """VER="v2.2"
FFMPEGVER="7.0.1"
YCRUNCHER_VER="0.8.6.9545"
CDATE=$(date +%F-%H%M)
RAMSIZE=$(awk '/MemTotal/{print int($2 / 1000)}' /proc/meminfo)
CPUCORES=$(nproc)
CPUFREQ=$(awk '{print $1 / 1000000}' /sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq)
COEFF="$(python -c "print(round((($CPUCORES + 1) / 2 * $CPUFREQ / 2) ** (1/3),2))")"
KERNVER="6.14.7"
CB_QUICK_MODE="${CB_QUICK_MODE:-0}"
CB_QUICK_LABEL="${CB_QUICK_LABEL:-CachyOS Quick RT Bench}"
"""

new_vars = """VER="v2.2"
FFMPEGVER="7.0.1"
YCRUNCHER_VER="0.8.6.9545"
CDATE=$(date +%F-%H%M)
RAMSIZE=$(awk '/MemTotal/{print int($2 / 1000)}' /proc/meminfo)
CPUCORES=$(nproc)
CPUFREQ=$(awk '{print $1 / 1000000}' /sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq)
COEFF="$(python -c "print(round((($CPUCORES + 1) / 2 * $CPUFREQ / 2) ** (1/3),2))")"
KERNVER="6.14.7"
CB_QUICK_MODE="${CB_QUICK_MODE:-0}"
CB_QUICK_LABEL="${CB_QUICK_LABEL:-CachyOS Quick RT Bench}"
CB_MAX_TESTS="${CB_MAX_TESTS:-0}"
"""

old_run = """# run
NRTESTS=12
declare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.85 0.85 0.8 0.95 0.95 1 0.95 1)
checkfiles && checksys && header || exit 8
runstress && sleep 2 || exit 8
runyc && sleep 2 || exit 8
runperf_sch && sleep 2 || exit 8
runperf_mem && sleep 2 || exit 8
runnamd && sleep 2 || exit 8
runprime && sleep 2 || exit 8
runargon && sleep 2 || exit 8
runffm && sleep 2 || exit 8
runxz && sleep 2 || exit 8
runkern && sleep 2 || exit 8
runblend && sleep 2 || exit 8
runx265 && sleep 2 || exit 8
"""

old_run_quick = """# run
if [[ "$CB_QUICK_MODE" = "1" ]]; then
\techo -e "\\n${TB}${CB_QUICK_LABEL}:${TN} running the early RT-pressure-heavy subset only.\\n"
\tNRTESTS=5
\tdeclare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.95)
else
\tNRTESTS=12
\tdeclare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.85 0.85 0.8 0.95 0.95 1 0.95 1)
fi
checkfiles && checksys && header || exit 8
runstress && sleep 2 || exit 8
runyc && sleep 2 || exit 8
runperf_sch && sleep 2 || exit 8
runperf_mem && sleep 2 || exit 8
runnamd && sleep 2 || exit 8
if [[ "$CB_QUICK_MODE" != "1" ]]; then
\trunprime && sleep 2 || exit 8
\trunargon && sleep 2 || exit 8
\trunffm && sleep 2 || exit 8
\trunxz && sleep 2 || exit 8
\trunkern && sleep 2 || exit 8
\trunblend && sleep 2 || exit 8
\trunx265 && sleep 2 || exit 8
fi
"""

new_run = """# run
if [[ "$CB_QUICK_MODE" = "1" ]]; then
\techo -e "\\n${TB}${CB_QUICK_LABEL}:${TN} running the early RT-pressure-heavy subset only.\\n"
\tNRTESTS=5
\tdeclare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.95)
else
\tNRTESTS=12
\tdeclare -a WEIGHTS=(0.9 0.9 0.85 0.85 0.85 0.85 0.8 0.95 0.95 1 0.95 1)
fi
if [[ "$CB_MAX_TESTS" -gt 0 && "$CB_MAX_TESTS" -lt "$NRTESTS" ]]; then
\tNRTESTS=$CB_MAX_TESTS
fi
checkfiles && checksys && header || exit 8
[[ $NRTESTS -ge 1 ]] && runstress && sleep 2 || [[ $NRTESTS -lt 1 ]] || exit 8
[[ $NRTESTS -ge 2 ]] && runyc && sleep 2 || [[ $NRTESTS -lt 2 ]] || exit 8
[[ $NRTESTS -ge 3 ]] && runperf_sch && sleep 2 || [[ $NRTESTS -lt 3 ]] || exit 8
[[ $NRTESTS -ge 4 ]] && runperf_mem && sleep 2 || [[ $NRTESTS -lt 4 ]] || exit 8
[[ $NRTESTS -ge 5 ]] && runnamd && sleep 2 || [[ $NRTESTS -lt 5 ]] || exit 8
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 6 ]]; then
\trunprime && sleep 2 || exit 8
fi
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 7 ]]; then
\trunargon && sleep 2 || exit 8
fi
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 8 ]]; then
\trunffm && sleep 2 || exit 8
fi
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 9 ]]; then
\trunxz && sleep 2 || exit 8
fi
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 10 ]]; then
\trunkern && sleep 2 || exit 8
fi
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 11 ]]; then
\trunblend && sleep 2 || exit 8
fi
if [[ "$CB_QUICK_MODE" != "1" && $NRTESTS -ge 12 ]]; then
\trunx265 && sleep 2 || exit 8
fi
"""

if old_vars in text:
    text = text.replace(old_vars, new_vars, 1)
elif old_vars_quick in text:
    text = text.replace(old_vars_quick, new_vars, 1)
else:
    raise SystemExit(f"Could not find benchmark variable block in {path}")

if old_run in text:
    text = text.replace(old_run, new_run, 1)
elif old_run_quick in text:
    text = text.replace(old_run_quick, new_run, 1)
else:
    raise SystemExit(f"Could not find benchmark run block in {path}")
path.write_text(text, encoding="utf-8")
PY
}

find_benchmark_runner() {
    local candidate

    if [ -n "$BENCHMARK_CMD" ]; then
        [ -x "$BENCHMARK_CMD" ] || {
            err "Benchmark command '$BENCHMARK_CMD' is not executable."
            exit 1
        }
        return
    fi

    case "$SUITE" in
        mini)
            for candidate in "$MINI_LOCAL_SCRIPT" mini-benchmarker.sh mini-benchmarker; do
                if command -v "$candidate" >/dev/null 2>&1; then
                    BENCHMARK_CMD=$(command -v "$candidate")
                    break
                elif [ -x "$candidate" ]; then
                    BENCHMARK_CMD="$candidate"
                    break
                fi
            done
            [ -n "$BENCHMARK_CMD" ] || {
                err "mini-benchmarker.sh was not found in PATH."
                say "Install it with ./install_benchmark_deps.sh --mini-benchmarker or set --benchmark-cmd."
                exit 1
            }
            if [ "$BENCHMARK_CMD" = "$MINI_LOCAL_SCRIPT" ]; then
                patch_local_mini_script
            fi
            ;;
        cachyos|cachyos-quick)
            for candidate in "$CACHYOS_LOCAL_SCRIPT" cachyos-benchmarker; do
                if command -v "$candidate" >/dev/null 2>&1; then
                    BENCHMARK_CMD=$(command -v "$candidate")
                    break
                elif [ -x "$candidate" ]; then
                    BENCHMARK_CMD="$candidate"
                    break
                fi
            done
            [ -n "$BENCHMARK_CMD" ] || {
                err "cachyos-benchmarker was not found."
                say "Install it with ./install_benchmark_deps.sh --cachyos-benchmarker or set --benchmark-cmd."
                exit 1
            }
            if [ "$BENCHMARK_CMD" = "$CACHYOS_LOCAL_SCRIPT" ]; then
                patch_local_cachyos_script
            fi
            ;;
    esac
}

find_scheduler_binaries() {
    local candidate

    for candidate in \
        scx_timely \
        "$SCRIPT_DIR/target/release/scx_timely" \
        /usr/bin/scx_timely \
        /usr/local/bin/scx_timely
    do
        if [ -x "$candidate" ]; then
            TIMELY_BIN="$candidate"
            break
        fi
    done
    [ -n "$TIMELY_BIN" ] || {
        err "Could not find an executable scx_timely binary."
        say "Build or install scx_timely first."
        exit 1
    }

    for candidate in \
        scx_bpfland \
        /usr/bin/scx_bpfland \
        /usr/local/bin/scx_bpfland
    do
        if [ -x "$candidate" ]; then
            BPFLAND_BIN="$candidate"
            break
        fi
    done
    [ -n "$BPFLAND_BIN" ] || {
        err "Could not find an executable scx_bpfland binary."
        say "Install scx_bpfland first so the comparison can include the upstream baseline scheduler."
        exit 1
    }

    for candidate in \
        scx_cake \
        /usr/bin/scx_cake \
        /usr/local/bin/scx_cake
    do
        if [ -x "$candidate" ]; then
            CAKE_BIN="$candidate"
            break
        fi
    done
    [ -n "$CAKE_BIN" ] || {
        err "Could not find an executable scx_cake binary."
        say "Install scx_cake first so the comparison can include the upstream scheduler."
        exit 1
    }
}

check_plot_deps() {
    command -v "$PLOTTER_PYTHON" >/dev/null 2>&1 || {
        err "Python interpreter '$PLOTTER_PYTHON' was not found."
        exit 1
    }
    [ -f "$PLOTTER" ] || {
        err "Missing plot helper: $PLOTTER"
        exit 1
    }
    if "$PLOTTER_PYTHON" - <<'PY'
import matplotlib  # noqa: F401
PY
    then
        return
    fi

    if [ "$BOOTSTRAP_PLOTTER" -eq 1 ]; then
        local venv_dir="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely/mini-benchmarker-venv"
        python3 -m venv "$venv_dir"
        # shellcheck disable=SC1090
        . "$venv_dir/bin/activate"
        pip install --quiet matplotlib
        PLOTTER_PYTHON="$venv_dir/bin/python"
        return
    fi

    err "matplotlib is required for chart generation."
    say "Re-run with --bootstrap-plotter to install it in a local virtualenv."
    exit 1
}

ensure_results_path_writable() {
    local parent
    parent=$(dirname "$RESULTS_DIR")
    mkdir -p "$parent" 2>/dev/null || {
        err "Cannot create benchmark results parent directory: $parent"
        exit 1
    }
    if [ ! -w "$parent" ]; then
        err "Benchmark results parent directory is not writable: $parent"
        exit 1
    fi
}

prune_empty_dirs() {
    local root="$1"
    [ -n "$root" ] || return 0
    [ -d "$root" ] || return 0

    find "$root" -depth -mindepth 1 -type d -empty -delete 2>/dev/null || true
}

cleanup_benchmark_artifacts() {
    prune_empty_dirs "$WORKDIR"
    prune_empty_dirs "$RESULTS_DIR"
    prune_empty_dirs "$SCRIPT_DIR/benchmark-results"
}

print_install_hints() {
    cat <<'EOF'
Install hints:
  - Mini Benchmarker helper: ./install_benchmark_deps.sh --mini-benchmarker --plotter
  - CachyOS helper         : ./install_benchmark_deps.sh --cachyos-benchmarker --plotter
  - local fetched helpers are searched under ~/.local/share/scx_timely/
  - install scx_cake separately so the comparison can include the upstream scheduler
EOF
}

check_runtime_command() {
    local label="$1"
    shift
    local candidate
    for candidate in "$@"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            ok "$label available: $(command -v "$candidate")"
            return 0
        fi
    done
    err "$label missing"
    return 1
}

check_gnu_time_binary() {
    local candidate
    for candidate in /usr/bin/time /bin/time /usr/local/bin/time /opt/homebrew/bin/gtime /usr/local/bin/gtime; do
        if [ -x "$candidate" ]; then
            ok "GNU time executable available: $candidate"
            return 0
        fi
    done
    err "GNU time executable missing"
    return 1
}

check_runtime_prereqs() {
    local missing=0
    check_gnu_time_binary || missing=1
    check_runtime_command "stress-ng" stress-ng || missing=1
    check_runtime_command "perf" perf || missing=1
    check_runtime_command "blender" blender || missing=1
    check_runtime_command "primesieve" primesieve || missing=1
    check_runtime_command "argon2" argon2 || missing=1
    check_runtime_command "x265" x265 || missing=1
    check_runtime_command "7z" 7z || missing=1
    check_runtime_command "wget" wget || missing=1
    check_runtime_command "tar" tar || missing=1
    check_runtime_command "xz" xz || missing=1
    check_runtime_command "make" make || missing=1
    check_runtime_command "cmake" cmake || missing=1
    check_runtime_command "nasm" nasm || missing=1
    check_runtime_command "C compiler" cc gcc clang || missing=1
    check_runtime_command "python shim for benchmark scripts" python || missing=1
    check_runtime_command "inxi" inxi || missing=1
    return "$missing"
}

check_dependency_status() {
    local missing=0
    say "Checking benchmark prerequisites for $BENCHMARK_LABEL"

    if command -v python3 >/dev/null 2>&1; then
        ok "python3 available"
    else
        err "python3 missing"
        missing=1
    fi

    if [ -f "$PLOTTER" ]; then
        ok "plot helper present: $(basename "$PLOTTER")"
    else
        err "plot helper missing: $PLOTTER"
        missing=1
    fi

    if command -v "$PLOTTER_PYTHON" >/dev/null 2>&1 && \
       "$PLOTTER_PYTHON" - <<'PY' >/dev/null 2>&1
import matplotlib  # noqa: F401
PY
    then
        ok "matplotlib import works"
    else
        warn "matplotlib not available for $PLOTTER_PYTHON"
    fi

    find_benchmark_runner || missing=1
    find_scheduler_binaries || missing=1

    if [ -r /sys/kernel/sched_ext/root/ops ]; then
        ok "sched_ext sysfs present"
    else
        warn "sched_ext sysfs not visible; benchmarking may not work on this kernel"
    fi

    if [ "$(id -u)" -eq 0 ]; then
        ok "running as root; sudo ticket not required"
    elif command -v sudo >/dev/null 2>&1; then
        if sudo -n true >/dev/null 2>&1; then
            ok "sudo ticket already valid"
        else
            warn "sudo ticket not cached; the runner will prompt before starting benchmark runs"
        fi
    else
        err "sudo missing; non-root benchmark orchestration cannot stop/start schedulers"
        missing=1
    fi

    say "Checking benchmark runtime tools"
    check_runtime_prereqs || missing=1
    print_install_hints
    return "$missing"
}

ensure_supported_scheduler_state() {
    local ops
    ops=$(current_sched_ext_ops || true)
    if [ -n "$ops" ] && ! printf '%s' "$ops" | grep -Eqi 'timely|bpfland|cake'; then
        err "Another sched_ext scheduler is active: $ops"
        say "Disable it first, then rerun benchmark.sh."
        exit 1
    fi
}

wait_for_scheduler_state() {
    local scheduler="$1"
    local want="$2"
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if [ "$want" = "active" ] && scheduler_is_active "$scheduler"; then
            return 0
        fi
        if [ "$want" = "inactive" ] && ! scheduler_is_active "$scheduler"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_sched_ext_idle() {
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if [ -z "$(current_sched_ext_ops || true)" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

stop_all_schedulers() {
    if service_is_active; then
        say "Stopping scx.service"
        run_privileged systemctl stop scx.service
    fi
    if pgrep -x scx_timely >/dev/null 2>&1; then
        say "Stopping running scx_timely processes"
        run_privileged pkill -x scx_timely || true
    fi
    if pgrep -x scx_bpfland >/dev/null 2>&1; then
        say "Stopping running scx_bpfland processes"
        run_privileged pkill -x scx_bpfland || true
    fi
    if pgrep -x scx_cake >/dev/null 2>&1; then
        say "Stopping running scx_cake processes"
        run_privileged pkill -x scx_cake || true
    fi
    wait_for_scheduler_state timely inactive || true
    wait_for_scheduler_state bpfland inactive || true
    wait_for_scheduler_state cake inactive || true
    if ! wait_for_sched_ext_idle; then
        warn "sched_ext root/ops still reports: $(current_sched_ext_ops || true)"
    fi
}

start_cake_manual() {
    local run_name="${1:-}"
    local runtime_log="$RESULTS_DIR/console/scx_cake.log"
    if [ -n "$run_name" ]; then
        runtime_log="$RESULTS_DIR/console/scx_cake_${run_name}.log"
    fi
    say "Starting scx_cake"
    CURRENT_RUNTIME_LOG="$runtime_log"
    write_runtime_state
    run_privileged env RUST_LOG=info "$CAKE_BIN" >"$runtime_log" 2>&1 &
    wait_for_scheduler_state cake active || {
        err "scx_cake did not become active."
        exit 1
    }
}

start_bpfland_manual() {
    local run_name="${1:-}"
    local runtime_log="$RESULTS_DIR/console/scx_bpfland.log"
    if [ -n "$run_name" ]; then
        runtime_log="$RESULTS_DIR/console/scx_bpfland_${run_name}.log"
    fi
    say "Starting scx_bpfland"
    CURRENT_RUNTIME_LOG="$runtime_log"
    write_runtime_state
    run_privileged env RUST_LOG=info "$BPFLAND_BIN" >"$runtime_log" 2>&1 &
    wait_for_scheduler_state bpfland active || {
        err "scx_bpfland did not become active."
        exit 1
    }
}

start_timely_manual() {
    local run_name="${1:-}"
    local runtime_log="$RESULTS_DIR/console/scx_timely-${MODE}.log"
    if [ -n "$run_name" ]; then
        runtime_log="$RESULTS_DIR/console/scx_timely-${MODE}_${run_name}.log"
    fi
    say "Starting scx_timely in ${MODE} mode"
    CURRENT_RUNTIME_LOG="$runtime_log"
    write_runtime_state
    run_privileged env RUST_LOG=info "$TIMELY_BIN" --mode "$MODE" "${TIMELY_EXTRA_ARGS[@]}" >"$runtime_log" 2>&1 &
    wait_for_scheduler_state timely active || {
        err "scx_timely did not become active."
        exit 1
    }
}

cleanup_exit() {
    local status="$1"
    trap - EXIT
    clear_runtime_state
    stop_sudo_keepalive
    if [ "$RESTORE_NEEDED" -eq 1 ]; then
        restore_initial_state || true
    fi
    exit "$status"
}

restore_initial_state() {
    if [ "$INITIAL_SERVICE_ACTIVE" -eq 1 ]; then
        stop_all_schedulers || true
        say "Restoring scx.service"
        run_privileged systemctl start scx.service || true
        return
    fi
    stop_all_schedulers || true
}

tag_log_copy() {
    local source_log="$1"
    local tagged_log="$2"
    local label="$3"
    local variant_slug="$4"
    local power_profile="$5"
    local scheduler_status="$6"
    local scheduler_issue="$7"
    local scheduler_version="$8"
    local scheduler_metrics="$9"
    local default_kernel="${10}"

    "$PLOTTER_PYTHON" - "$source_log" "$tagged_log" "$label" "$variant_slug" "$power_profile" "$scheduler_status" "$scheduler_issue" "$scheduler_version" "$scheduler_metrics" "$default_kernel" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
label = sys.argv[3]
variant = sys.argv[4]
power_profile = sys.argv[5]
scheduler_status = sys.argv[6]
scheduler_issue = sys.argv[7]
scheduler_version = sys.argv[8]
scheduler_metrics = sys.argv[9]
default_kernel = sys.argv[10]
text = source.read_text(encoding="utf-8", errors="replace")

ansi_re = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
backspace_re = re.compile(r".\x08")

while True:
    cleaned = backspace_re.sub("", text)
    if cleaned == text:
        break
    text = cleaned

text = ansi_re.sub("", text).replace("\x08", "").replace("\r", "")
match = re.search(r"Kernel:\s+(\S+)", text)
if match:
    kernel = match.group(1)
else:
    kernel = default_kernel
tagged = f"Kernel: {kernel}__{variant}"
if match:
    text = re.sub(r"Kernel:\s+\S+", tagged, text, count=1)
else:
    text = f"Kernel: {kernel}\n{text}"
text += (
    f"\nBenchmark label: {label}\n"
    f"Original kernel: {kernel}\n"
    f"Benchmark variant: {variant}\n"
    f"Power profile: {power_profile}\n"
    f"Scheduler version: {scheduler_version}\n"
    f"Scheduler status: {scheduler_status}\n"
    f"Scheduler issue: {scheduler_issue}\n"
    f"Scheduler metrics: {scheduler_metrics}\n"
)
target.write_text(text, encoding="utf-8")
PY
}

detect_scheduler_status() {
    local runtime_log="$1"
    local status="clean"
    local issue=""

    if [ -n "$runtime_log" ] && [ -f "$runtime_log" ]; then
        if grep -q 'Error: EXIT:' "$runtime_log"; then
            status="exited"
            issue=$(sed -n 's/^Error: EXIT: //p' "$runtime_log" | head -n 1)
        elif grep -q 'BPF scheduler exited' "$runtime_log"; then
            status="exited"
            issue=$(
                sed -n \
                    -e 's/.*EXIT: \(.*\))$/\1/p' \
                    -e 's/.*BPF scheduler exited[: ]*//p' \
                    "$runtime_log" | head -n 1
            )
        elif grep -q 'triggered exit kind' "$runtime_log"; then
            status="exited"
            issue=$(sed -n '/triggered exit kind/{n;p;}' "$runtime_log" | sed 's/^  *//' | head -n 1)
        fi
    fi

    printf '%s\n%s\n' "$status" "$issue"
}

detect_scheduler_metrics() {
    local runtime_log="$1"
    local metrics=""

    if [ -n "$runtime_log" ] && [ -f "$runtime_log" ]; then
        metrics=$(sed -n 's/^.*Scheduler metrics .*: //p' "$runtime_log" | tail -n 1)
    fi

    printf '%s\n' "$metrics"
}

stop_process_group() {
    local leader_pid="$1"

    kill -TERM -- "-$leader_pid" >/dev/null 2>&1 || true
    sleep 1
    kill -KILL -- "-$leader_pid" >/dev/null 2>&1 || true
}

run_benchmark_command() {
    local run_name="$1"
    local cache_answer="$2"
    local console_log="$3"
    local max_tests="$4"
    local max_tests_env=""

    if [ "${max_tests:-0}" -gt 0 ]; then
        max_tests_env="$max_tests"
    fi

    BENCHMARK_CMD_PATH="$BENCHMARK_CMD" \
    WORKDIR_PATH="$WORKDIR" \
    CACHE_ANSWER="$cache_answer" \
    RUN_NAME="$run_name" \
    CONSOLE_LOG="$console_log" \
    MAX_TESTS="$max_tests_env" \
    SUITE_NAME="$SUITE" \
    BENCHMARK_LABEL_ENV="$BENCHMARK_LABEL" \
    setsid bash -lc '
        set -o pipefail
        if [ "$SUITE_NAME" = "mini" ]; then
            printf "%s\n%s\n" "$CACHE_ANSWER" "$RUN_NAME" | \
                env MB_MAX_TESTS="$MAX_TESTS" \
                "$BENCHMARK_CMD_PATH" "$WORKDIR_PATH" | tee "$CONSOLE_LOG"
        elif [ "$SUITE_NAME" = "cachyos-quick" ]; then
            printf "%s\n%s\n" "$CACHE_ANSWER" "$RUN_NAME" | \
                env CB_QUICK_MODE=1 CB_QUICK_LABEL="$BENCHMARK_LABEL_ENV" CB_MAX_TESTS="$MAX_TESTS" \
                "$BENCHMARK_CMD_PATH" "$WORKDIR_PATH" | tee "$CONSOLE_LOG"
        else
            printf "%s\n%s\n" "$CACHE_ANSWER" "$RUN_NAME" | \
                env CB_MAX_TESTS="$MAX_TESTS" \
                "$BENCHMARK_CMD_PATH" "$WORKDIR_PATH" | tee "$CONSOLE_LOG"
        fi
    ' &
    CURRENT_BENCHMARK_PID="$!"
    write_runtime_state
}

wait_for_benchmark_or_scheduler_exit() {
    local bench_pid="$1"
    local runtime_log="$2"
    local scheduler_name="$3"
    local label="$4"
    local stopped_early=0

    if [ -n "$runtime_log" ] && [ -n "$scheduler_name" ]; then
        while kill -0 "$bench_pid" >/dev/null 2>&1; do
            local detected_status
            local scheduler_status
            local scheduler_issue

            detected_status=$(detect_scheduler_status "$runtime_log")
            scheduler_status=$(printf '%s\n' "$detected_status" | sed -n '1p')
            scheduler_issue=$(printf '%s\n' "$detected_status" | sed -n '2p')

            if [ "$scheduler_status" != "clean" ]; then
                warn "${label} scheduler exited during benchmark run: ${scheduler_issue}"
                stop_process_group "$bench_pid"
                stopped_early=1
                break
            fi

            sleep 1
        done
    fi

    set +e
    wait "$bench_pid"
    local bench_rc=$?
    set -e
    CURRENT_BENCHMARK_PID=""
    write_runtime_state

    if [ "$stopped_early" -eq 1 ]; then
        return 0
    fi

    if [ "$bench_rc" -ne 0 ]; then
        err "Benchmark command failed for ${label} (exit ${bench_rc})"
        exit 1
    fi
}

run_one_benchmark() {
    local variant_slug="$1"
    local label="$2"
    local run_index="$3"
    local runtime_log="${4:-}"
    local run_name
    local cache_answer
    local raw_log
    local tagged_log
    local scheduler_status
    local scheduler_issue
    local scheduler_metrics
    local detected_status
    local console_log
    local bench_pid

    run_name="${variant_slug}_run$(printf '%02d' "$run_index")"
    cache_answer="n"
    if [ "$DROP_CACHES" -eq 1 ]; then
        cache_answer="y"
    fi

    say "Running ${BENCHMARK_LABEL}: ${label} (run ${run_index}/${RUNS})"
    mkdir -p "$WORKDIR"
    console_log="$RESULTS_DIR/console/${run_name}.out"
    run_benchmark_command "$run_name" "$cache_answer" "$console_log" "$CURRENT_BENCHMARK_MAX_TESTS"
    bench_pid="$CURRENT_BENCHMARK_PID"
    wait_for_benchmark_or_scheduler_exit "$bench_pid" "$runtime_log" "$CURRENT_SCHEDULER_NAME" "$label"

    raw_log=$(find "$WORKDIR" -maxdepth 1 -type f -name "benchie_${run_name}_*.log" | sort | tail -n 1)
    if [ -z "$raw_log" ]; then
        raw_log="$RESULTS_DIR/raw/${run_name}.console.log"
        cp "$console_log" "$raw_log"
    else
        cp "$raw_log" "$RESULTS_DIR/raw/"
    fi

    tagged_log="$RESULTS_DIR/tagged/$(basename "$raw_log")"
    case "$tagged_log" in
        *.log) ;;
        *) tagged_log="${tagged_log}.log" ;;
    esac
    scheduler_status="clean"
    scheduler_issue=""
    scheduler_metrics=""
    if [ -n "$runtime_log" ]; then
        detected_status=$(detect_scheduler_status "$runtime_log")
        scheduler_status=$(printf '%s\n' "$detected_status" | sed -n '1p')
        scheduler_issue=$(printf '%s\n' "$detected_status" | sed -n '2p')
        scheduler_metrics=$(detect_scheduler_metrics "$runtime_log")
        if [ "$scheduler_status" != "clean" ]; then
            warn "${label} scheduler status: ${scheduler_status} (${scheduler_issue})"
        fi
    fi
    tag_log_copy "$raw_log" "$tagged_log" "$label" "$variant_slug" "$POWER_PROFILE" "$scheduler_status" "$scheduler_issue" "$CURRENT_SCHEDULER_VERSION" "$scheduler_metrics" "$(uname -sr)"

    if [ "$ADAPTIVE_SCOPE" -eq 1 ] && [ "$CURRENT_SCHEDULER_NAME" = "timely" ]; then
        local completed_tests
        completed_tests=$(count_completed_benchmarks_from_log "$raw_log")
        update_adaptive_scope_limit "$completed_tests"
        if [ "$ADAPTIVE_SCOPE_LIMIT" -gt 0 ]; then
            say "Adaptive benchmark ceiling learned from Timely: ${ADAPTIVE_SCOPE_LIMIT} completed test(s)"
        fi
    fi

    cleanup_benchmark_artifacts
    ok "Saved $(basename "$raw_log")"
}

run_variant() {
    local variant_slug="$1"
    local label="$2"
    local action="$3"
    local run_index

    CURRENT_BENCHMARK_MAX_TESTS=0
    if [ "$ADAPTIVE_SCOPE" -eq 1 ] && [ "$ADAPTIVE_SCOPE_LIMIT" -gt 0 ] && [ "$action" != "timely" ]; then
        CURRENT_BENCHMARK_MAX_TESTS="$ADAPTIVE_SCOPE_LIMIT"
        say "Limiting ${label} to ${CURRENT_BENCHMARK_MAX_TESTS} test(s) based on Timely's completed scope"
    fi

    for run_index in $(seq 1 "$RUNS"); do
        local run_name
        run_name="${variant_slug}_run$(printf '%02d' "$run_index")"

        case "$action" in
            baseline)
                stop_all_schedulers
                CURRENT_RUNTIME_LOG=""
                CURRENT_SCHEDULER_VERSION=""
                CURRENT_SCHEDULER_NAME=""
                write_runtime_state
                ;;
            cake)
                stop_all_schedulers
                CURRENT_SCHEDULER_VERSION=$(detect_binary_version "$CAKE_BIN")
                CURRENT_SCHEDULER_NAME="cake"
                write_runtime_state
                start_cake_manual "$run_name"
                ;;
            bpfland)
                stop_all_schedulers
                CURRENT_SCHEDULER_VERSION=$(detect_binary_version "$BPFLAND_BIN")
                CURRENT_SCHEDULER_NAME="bpfland"
                write_runtime_state
                start_bpfland_manual "$run_name"
                ;;
            timely)
                stop_all_schedulers
                CURRENT_SCHEDULER_VERSION=$(detect_binary_version "$TIMELY_BIN")
                CURRENT_SCHEDULER_NAME="timely"
                write_runtime_state
                start_timely_manual "$run_name"
                ;;
            *)
                err "Unsupported run action: $action"
                exit 1
                ;;
        esac

        run_one_benchmark "$variant_slug" "$label" "$run_index" "$CURRENT_RUNTIME_LOG"
    done
}

main() {
    warn_if_running_as_root
    ensure_results_path_writable
    mkdir -p "$WORKDIR" "$RESULTS_DIR/raw" "$RESULTS_DIR/tagged" "$RESULTS_DIR/console"
    trap 'cleanup_exit $?' EXIT
    write_runtime_state

    find_benchmark_runner

    if [ "$CHECK_DEPS_ONLY" -eq 1 ]; then
        check_dependency_status
        exit 0
    fi

    find_scheduler_binaries
    check_plot_deps
    check_runtime_prereqs || {
        err "Benchmark runtime prerequisites are incomplete."
        say "Run ./benchmark.sh --check-deps or ./install_benchmark_deps.sh first."
        exit 1
    }
    detect_baseline_label
    detect_power_profile
    ensure_sudo_ready
    start_sudo_keepalive
    ensure_supported_scheduler_state

    if service_is_active; then
        INITIAL_SERVICE_ACTIVE=1
    fi
    RESTORE_NEEDED=1

    say "Benchmark suite          : $BENCHMARK_LABEL"
    say "Benchmark command        : $BENCHMARK_CMD"
    say "scx_cake binary          : $CAKE_BIN"
    say "scx_bpfland binary       : $BPFLAND_BIN"
    say "scx_timely binary        : $TIMELY_BIN"
    say "Work directory           : $WORKDIR"
    say "Results directory        : $RESULTS_DIR"
    say "Timely benchmark mode    : $MODE"
    if [ "${#TIMELY_EXTRA_ARGS[@]}" -gt 0 ]; then
        say "Timely extra args        : ${TIMELY_EXTRA_ARGS[*]}"
    else
        say "Timely extra args        : (none)"
    fi
    say "Runs per variant         : $RUNS"
    say "Power profile            : $POWER_PROFILE"
    if [ "$ADAPTIVE_SCOPE" -eq 1 ]; then
        say "Adaptive scope           : enabled (Timely-first ceiling)"
    else
        say "Adaptive scope           : disabled"
    fi

    run_variant "timely-${MODE}" "Timely (${MODE})" timely
    run_variant "bpfland" "bpfland" bpfland
    run_variant "cake" "cake" cake
    run_variant "baseline" "$BASELINE_LABEL" baseline

    "$PLOTTER_PYTHON" "$PLOTTER" "$RESULTS_DIR/tagged" \
        --title "${BENCHMARK_LABEL} Comparison (${MODE} mode)"

    cleanup_benchmark_artifacts

    restore_initial_state
    RESTORE_NEEDED=0

    ok "${BENCHMARK_LABEL} comparison complete."
    say "Chart: $RESULTS_DIR/tagged/mini_benchmarker_comparison.png"
    say "Chart: $RESULTS_DIR/tagged/mini_benchmarker_comparison.svg"
    say "CSV  : $RESULTS_DIR/tagged/mini_benchmarker_summary.csv"
}

main "$@"
