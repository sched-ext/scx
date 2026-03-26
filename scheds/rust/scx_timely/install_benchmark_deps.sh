#!/usr/bin/env bash
# install_benchmark_deps.sh — Best-effort bootstrap for scx_timely benchmark helpers.

set -euo pipefail

RED=$(printf '\033[0;31m')
GRN=$(printf '\033[0;32m')
YLW=$(printf '\033[1;33m')
CYN=$(printf '\033[0;36m')
BLD=$(printf '\033[1m')
RST=$(printf '\033[0m')

say()  { printf "${BLD}${CYN}[bench-deps]${RST} %s\n" "$1"; }
ok()   { printf "${BLD}${GRN}[  OK  ]${RST} %s\n" "$1"; }
warn() { printf "${BLD}${YLW}[ WARN ]${RST} %s\n" "$1"; }
err()  { printf "${BLD}${RED}[ERROR ]${RST} %s\n" "$1" >&2; }

INSTALL_MINI=0
INSTALL_CACHYOS=0
INSTALL_PLOTTER=0
REMOVE_MINI=0
REMOVE_CACHYOS=0
REMOVE_PLOTTER=0
REMOVE_WORKDIR=0
REMOVE_RESULTS=0

MINI_LOCAL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/scx_timely/mini-benchmarker"
MINI_LOCAL_SCRIPT="$MINI_LOCAL_DIR/mini-benchmarker.sh"
MINI_SOURCE_URL="https://gitlab.com/torvic9/mini-benchmarker/-/raw/master/mini-benchmarker.sh"

CACHYOS_LOCAL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/scx_timely/cachyos-benchmarker"
CACHYOS_LOCAL_SCRIPT="$CACHYOS_LOCAL_DIR/cachyos-benchmarker"
CACHYOS_SOURCE_URL="https://raw.githubusercontent.com/CachyOS/cachyos-benchmarker/master/cachyos-benchmarker"

PLOTTER_VENV_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely/mini-benchmarker-venv"
MINI_WORKDIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely/mini-benchmarker-workdir"
CACHYOS_WORKDIR="${XDG_CACHE_HOME:-$HOME/.cache}/scx_timely/cachyos-benchmarker-workdir"
RESULTS_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/benchmark-results"

usage() {
    cat <<'EOF'
Usage: ./install_benchmark_deps.sh [options]

Best-effort bootstrap for benchmark helper dependencies.

Options:
  --mini-benchmarker     Fetch torvic9's Mini Benchmarker locally
  --cachyos-benchmarker  Fetch CachyOS's benchmark script locally
  --plotter              Install Python matplotlib dependencies for chart rendering
  --remove-mini-benchmarker
                         Remove the fetched local Mini Benchmarker script
  --remove-cachyos-benchmarker
                         Remove the fetched local CachyOS benchmark script
  --remove-plotter       Remove the local matplotlib virtualenv
  --remove-workdir       Remove cached benchmark asset/work directories
  --remove-results       Remove generated benchmark result directories
  --remove-all           Remove all benchmark helper leftovers above
  -h, --help             Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mini-benchmarker)
            INSTALL_MINI=1
            shift
            ;;
        --cachyos-benchmarker)
            INSTALL_CACHYOS=1
            shift
            ;;
        --plotter)
            INSTALL_PLOTTER=1
            shift
            ;;
        --remove-mini-benchmarker)
            REMOVE_MINI=1
            shift
            ;;
        --remove-cachyos-benchmarker)
            REMOVE_CACHYOS=1
            shift
            ;;
        --remove-plotter)
            REMOVE_PLOTTER=1
            shift
            ;;
        --remove-workdir)
            REMOVE_WORKDIR=1
            shift
            ;;
        --remove-results)
            REMOVE_RESULTS=1
            shift
            ;;
        --remove-all)
            REMOVE_MINI=1
            REMOVE_CACHYOS=1
            REMOVE_PLOTTER=1
            REMOVE_WORKDIR=1
            REMOVE_RESULTS=1
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

if [ "$INSTALL_MINI" -eq 0 ] && [ "$INSTALL_CACHYOS" -eq 0 ] && [ "$INSTALL_PLOTTER" -eq 0 ] && \
   [ "$REMOVE_MINI" -eq 0 ] && [ "$REMOVE_CACHYOS" -eq 0 ] && [ "$REMOVE_PLOTTER" -eq 0 ] && \
   [ "$REMOVE_WORKDIR" -eq 0 ] && [ "$REMOVE_RESULTS" -eq 0 ]; then
    usage
    exit 0
fi

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

detect_distro() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        printf '%s\n' "${ID:-unknown}"
        return
    fi
    printf '%s\n' unknown
}

install_plotter() {
    command -v python3 >/dev/null 2>&1 || {
        err "python3 is required to install plotter dependencies."
        exit 1
    }
    say "Installing matplotlib into $PLOTTER_VENV_DIR"
    python3 -m venv "$PLOTTER_VENV_DIR"
    # shellcheck disable=SC1090
    . "$PLOTTER_VENV_DIR/bin/activate"
    pip install --quiet matplotlib
    ok "Plotter environment ready at $PLOTTER_VENV_DIR"
}

patch_mini_script() {
    [ -f "$MINI_LOCAL_SCRIPT" ] || return 0
    if grep -q 'MB_TIME_BIN=' "$MINI_LOCAL_SCRIPT"; then
        ok "Mini Benchmarker compatibility patch already present"
        return 0
    fi
    say "Patching Mini Benchmarker for portable GNU time lookup"
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
    ok "Applied local compatibility patch to $MINI_LOCAL_SCRIPT"
}

patch_cachyos_script() {
    [ -f "$CACHYOS_LOCAL_SCRIPT" ] || return 0
    if ! grep -q 'CB_TIME_BIN=' "$CACHYOS_LOCAL_SCRIPT"; then
        say "Patching CachyOS benchmarker for portable GNU time lookup and non-fatal extras"
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
        say "Patching CachyOS benchmarker for generic sched_ext version detection"
        python3 - "$CACHYOS_LOCAL_SCRIPT" <<'PY'
from pathlib import Path
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

    if ! grep -q 'CB_QUICK_MODE=' "$CACHYOS_LOCAL_SCRIPT"; then
        say "Patching CachyOS benchmarker for quick RT-pressure screening mode"
        python3 - "$CACHYOS_LOCAL_SCRIPT" <<'PY'
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

if old_vars not in text:
    raise SystemExit(f"Could not find benchmark variable block in {path}")
if old_run not in text:
    raise SystemExit(f"Could not find benchmark run block in {path}")

text = text.replace(old_vars, new_vars, 1)
text = text.replace(old_run, new_run, 1)
path.write_text(text, encoding="utf-8")
PY
    fi

    ok "Applied local compatibility patch to $CACHYOS_LOCAL_SCRIPT"
}

fetch_script() {
    local url="$1"
    local dest="$2"
    local parent
    parent=$(dirname "$dest")
    mkdir -p "$parent"
    if command -v curl >/dev/null 2>&1; then
        say "Fetching $(basename "$dest") from $url"
        curl -L --fail --silent --show-error "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        say "Fetching $(basename "$dest") from $url"
        wget -qO "$dest" "$url"
    else
        err "Need curl or wget to fetch benchmark scripts."
        exit 1
    fi
    chmod +x "$dest"
}

install_common_packages() {
    local distro
    distro=$(detect_distro)
    case "$distro" in
        cachyos|arch)
            if command -v pacman >/dev/null 2>&1; then
                say "Trying common benchmark dependencies from pacman first."
                run_privileged pacman -S --needed --noconfirm \
                    python python-pip python-matplotlib stress-ng perf blender x265 argon2 \
                    wget git p7zip primesieve inxi bc unzip xz gcc make cmake nasm time || true
            fi
            ;;
        ubuntu|debian)
            if command -v apt-get >/dev/null 2>&1; then
                say "Installing common benchmark dependencies via apt"
                run_privileged apt-get update -qq
                run_privileged apt-get install -y --no-install-recommends \
                    python3 python3-venv python3-pip python3-matplotlib stress-ng linux-perf \
                    blender xz-utils wget git p7zip-full build-essential cmake nasm bc unzip \
                    time inxi || true
            fi
            ;;
        *)
            warn "No supported automatic package install path for this distro."
            ;;
    esac
}

remove_tree() {
    local path="$1"
    if [ -e "$path" ]; then
        rm -rf -- "$path"
        ok "Removed $path"
    else
        warn "Nothing to remove at $path"
    fi
}

remove_results() {
    local found=0
    local result_dir
    if [ -d "$RESULTS_ROOT" ]; then
        for result_dir in "$RESULTS_ROOT"/mini-benchmarker-* "$RESULTS_ROOT"/cachyos-benchmarker-*; do
            if [ -e "$result_dir" ]; then
                found=1
                rm -rf -- "$result_dir"
                ok "Removed $result_dir"
            fi
        done
    fi
    if [ "$found" -eq 0 ]; then
        warn "No benchmark result directories found under $RESULTS_ROOT"
    fi
}

if [ "$INSTALL_PLOTTER" -eq 1 ]; then
    install_plotter
fi

if [ "$INSTALL_MINI" -eq 1 ] || [ "$INSTALL_CACHYOS" -eq 1 ]; then
    install_common_packages
fi

if [ "$INSTALL_MINI" -eq 1 ]; then
    fetch_script "$MINI_SOURCE_URL" "$MINI_LOCAL_SCRIPT"
    patch_mini_script
    ok "Installed Mini Benchmarker to $MINI_LOCAL_SCRIPT"
fi

if [ "$INSTALL_CACHYOS" -eq 1 ]; then
    fetch_script "$CACHYOS_SOURCE_URL" "$CACHYOS_LOCAL_SCRIPT"
    patch_cachyos_script
    ok "Installed CachyOS benchmarker to $CACHYOS_LOCAL_SCRIPT"
fi

if [ "$REMOVE_MINI" -eq 1 ]; then
    remove_tree "$MINI_LOCAL_DIR"
fi

if [ "$REMOVE_CACHYOS" -eq 1 ]; then
    remove_tree "$CACHYOS_LOCAL_DIR"
fi

if [ "$REMOVE_PLOTTER" -eq 1 ]; then
    remove_tree "$PLOTTER_VENV_DIR"
fi

if [ "$REMOVE_WORKDIR" -eq 1 ]; then
    remove_tree "$MINI_WORKDIR"
    remove_tree "$CACHYOS_WORKDIR"
fi

if [ "$REMOVE_RESULTS" -eq 1 ]; then
    remove_results
fi
