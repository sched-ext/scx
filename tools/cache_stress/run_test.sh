#!/bin/bash
#
# run_test.sh — automated cache-aware verification test for scx_lavd
#
# Runs cache_stress twice: once without --cache-aware, once with,
# then compares cross-domain migration rate, L3 cache hit rate, and throughput.
#
# On AMD Zen CPUs, uses amd_l3 PMU events for precise L3 hit/miss/lookup.
# Falls back to generic cache-misses/LLC-load-misses on other architectures.
#
# Requirements:
#   - scx_lavd built (default: target/debug/scx_lavd)
#   - cache_stress built (make in this directory)
#   - perf stat, bpftool (for mm_ca_map dump)
#   - root privileges (for scx_lavd and perf)
#
# Usage: sudo ./run_test.sh [options]
#   -d <sec>   duration per run (default 30)
#   -t <thr>   number of stress threads (default 8)
#   -s <mb>    shared array size in MiB (default 4)
#   -p <path>  path to scx_lavd binary
#   -n         skip perf (if perf hardware events unavailable)
#   -h         show help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STRESS="${SCRIPT_DIR}/cache_stress"
LAVD="${LAVD_PATH:-$(realpath "$SCRIPT_DIR/../../target/release/scx_lavd" 2>/dev/null || echo "$SCRIPT_DIR/../../target/release/scx_lavd")}"

DURATION=30
NTHREADS=8
SIZE_MB=4
SKIP_PERF=0
TMPDIR=""

# Detect perf events: prefer AMD L3 events, fall back to generic
PERF_MODE="unknown"
SCHED_EVENTS="context-switches,cpu-migrations"
AMD_L3_EVENTS="amd_l3/l3_lookup_state.all_coherent_accesses_to_l3/,amd_l3/l3_lookup_state.l3_hit/,amd_l3/l3_lookup_state.l3_miss/"
GENERIC_EVENTS="cache-misses,LLC-load-misses"
PERF_EVENTS=""

detect_perf_events() {
    if [ "$SKIP_PERF" -eq 1 ]; then
        PERF_MODE="none"
        return
    fi
    # Try AMD L3 events first
    if perf stat -a -e "$AMD_L3_EVENTS" sleep 0.01 > /dev/null 2>&1; then
        PERF_MODE="amd_l3"
        PERF_EVENTS="$AMD_L3_EVENTS,$SCHED_EVENTS"
        echo "  perf: AMD L3 events detected"
    elif perf stat -a -e "$GENERIC_EVENTS" sleep 0.01 > /dev/null 2>&1; then
        PERF_MODE="generic"
        PERF_EVENTS="$GENERIC_EVENTS,$SCHED_EVENTS"
        echo "  perf: generic cache events (non-AMD fallback)"
    else
        PERF_MODE="none"
        echo "  perf: WARNING — no suitable events found, skipping perf"
    fi
}

cleanup() {
    if [ -n "$TMPDIR" ]; then
        pkill -f "scx_lavd" 2>/dev/null || true
        sleep 1
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

usage() {
    echo "Usage: sudo $0 [-d dur] [-t threads] [-s size_mb] [-p lavd_path] [-n] [-h]"
    echo "  -d  duration per run in seconds (default: 30)"
    echo "  -t  number of stress threads (default: 8)"
    echo "  -s  shared array size in MiB (default: 4)"
    echo "  -p  path to scx_lavd (default: auto-detect)"
    echo "  -n  skip perf stat collection"
    echo "  -h  this help"
    exit "${1:-0}"
}

while getopts "d:t:s:p:nh" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        t) NTHREADS="$OPTARG" ;;
        s) SIZE_MB="$OPTARG" ;;
        p) LAVD="$OPTARG" ;;
        n) SKIP_PERF=1 ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this script must run as root (for scx_lavd and perf)" >&2
    exit 1
fi

if ! [ -x "$STRESS" ]; then
    echo "cache_stress not found, building..." >&2
    make -C "$SCRIPT_DIR" || { echo "ERROR: build failed" >&2; exit 1; }
fi

if ! [ -x "$LAVD" ]; then
    echo "ERROR: scx_lavd not found at: $LAVD" >&2
    echo "       Build it first: cargo build -p scx_lavd" >&2
    exit 1
fi

TMPDIR="$(mktemp -d /tmp/cache_stress_XXXXXX)"
echo "============================================"
echo " scx_lavd cache-aware verification test"
echo "============================================"
echo "  lavd:      $LAVD"
echo "  stress:    $STRESS"
echo "  threads:   $NTHREADS"
echo "  size:      ${SIZE_MB} MiB"
echo "  duration:  ${DURATION} s per run"
echo "  tmpdir:    $TMPDIR"
echo ""

detect_perf_events

echo "============================================"
echo ""

# ── Helper functions ──────────────────────────────────────────────

# Parse X-MIG% from lavd stats output
# Stats format: | MSEQ | ... | X-MIG% | ... |  (X-MIG% is the 8th data column, $9 in awk)
# Log contains ANSI color codes which must be stripped first.
extract_x_mig() {
    local logfile="$1"
    sed 's/\x1b\[[0-9;]*m//g' "$logfile" 2>/dev/null \
      | grep '^|' \
      | tail -5 \
      | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$9); print $9}' \
      | grep -v '^$' \
      | tail -1 \
      || echo "N/A"
}

# Parse perf stat output for a specific event name
extract_perf_event() {
    local logfile="$1"
    local event="$2"
    grep "$event" "$logfile" 2>/dev/null \
      | head -1 \
      | awk '{print $1}' \
      | tr -d ',' \
      || echo "N/A"
}

# ── Run one scenario ─────────────────────────────────────────────

run_scenario() {
    local label="$1"
    local lavd_extra_flags="$2"
    local out_prefix="$3"

    echo ""
    echo ">>> Starting scenario: $label"
    echo "    lavd flags: $lavd_extra_flags"

    # Kill any lingering scheduler
    pkill -f "scx_lavd" 2>/dev/null || true
    sleep 1

    # Start scx_lavd with --stats 1 (1-second interval)
    "$LAVD" $lavd_extra_flags --stats 1 2>"${out_prefix}_lavd.log" &
    local lavd_pid=$!
    sleep 2

    # Verify it's running
    if ! kill -0 "$lavd_pid" 2>/dev/null; then
        echo "ERROR: scx_lavd failed to start. Log:" >&2
        cat "${out_prefix}_lavd.log" >&2
        exit 1
    fi

    # Start perf stat collection
    if [ "$PERF_MODE" != "none" ]; then
        perf stat -a \
            -e "$PERF_EVENTS" \
            -o "${out_prefix}_perf.log" \
            sleep "$DURATION" &
        local perf_pid=$!
    fi

    # Run stress test
    echo "    Running cache_stress for ${DURATION}s..."
    "$STRESS" -t "$NTHREADS" -d "$DURATION" -s "$SIZE_MB" \
        > "${out_prefix}_stress.log" 2>&1

    # Stop perf
    if [ "$PERF_MODE" != "none" ]; then
        wait "$perf_pid" 2>/dev/null || true
    fi

    # Grab X-MIG% from the last few lines of lavd stats
    sleep 2
    local xmig
    xmig=$(extract_x_mig "${out_prefix}_lavd.log")

    # Dump mm_ca_map if cache-aware is enabled
    if echo "$lavd_extra_flags" | grep -q "cache-aware"; then
        bpftool map dump name mm_ca_map 2>/dev/null \
            > "${out_prefix}_mm_ca_map.log" || true
    fi

    # Stop scheduler
    kill "$lavd_pid" 2>/dev/null || true
    wait "$lavd_pid" 2>/dev/null || true
    sleep 1

    echo "    X-MIG%: $xmig"

    # Save throughput
    local ops_s
    ops_s=$(grep "^total:" "${out_prefix}_stress.log" 2>/dev/null \
        | awk '{print $8}' || echo "N/A")

    echo "$xmig"  > "${out_prefix}_xmig"
    echo "$ops_s" > "${out_prefix}_ops_s"

    echo "    ops/s: $ops_s"

    # Save perf results per mode
    local ctx_sw cpu_mig
    ctx_sw=$(extract_perf_event "${out_prefix}_perf.log" "context-switches")
    cpu_mig=$(extract_perf_event "${out_prefix}_perf.log" "cpu-migrations")
    echo "$ctx_sw"  > "${out_prefix}_ctx_sw"
    echo "$cpu_mig" > "${out_prefix}_cpu_mig"
    echo "    context-switches: $ctx_sw"
    echo "    cpu-migrations:   $cpu_mig"

    if [ "$PERF_MODE" = "amd_l3" ]; then
        local l3_all l3_hit l3_miss l3_hit_rate
        l3_all=$(extract_perf_event "${out_prefix}_perf.log" "l3_lookup_state.all_coherent_accesses_to_l3")
        l3_hit=$(extract_perf_event "${out_prefix}_perf.log" "l3_lookup_state.l3_hit")
        l3_miss=$(extract_perf_event "${out_prefix}_perf.log" "l3_lookup_state.l3_miss")

        # Compute hit rate
        if [ "$l3_all" != "N/A" ] && [ "$l3_all" != "0" ] && [ "$l3_hit" != "N/A" ]; then
            l3_hit_rate=$(awk "BEGIN { printf \"%.2f\", ($l3_hit / $l3_all) * 100 }")
        else
            l3_hit_rate="N/A"
        fi

        echo "$l3_all"      > "${out_prefix}_l3_all"
        echo "$l3_hit"      > "${out_prefix}_l3_hit"
        echo "$l3_miss"     > "${out_prefix}_l3_miss"
        echo "$l3_hit_rate" > "${out_prefix}_l3_hit_rate"

        echo "    L3 accesses:  $l3_all"
        echo "    L3 hits:      $l3_hit"
        echo "    L3 misses:    $l3_miss"
        echo "    L3 hit rate:  ${l3_hit_rate}%"

    elif [ "$PERF_MODE" = "generic" ]; then
        local cache_misses llc_misses
        cache_misses=$(extract_perf_event "${out_prefix}_perf.log" "cache-misses")
        llc_misses=$(extract_perf_event "${out_prefix}_perf.log" "LLC-load-misses")

        echo "$cache_misses" > "${out_prefix}_cache_misses"
        echo "$llc_misses"   > "${out_prefix}_llc_misses"

        echo "    cache-misses: $cache_misses"
        echo "    LLC-misses:   $llc_misses"
    fi
}

# ── Main ──────────────────────────────────────────────────────────

echo "=== Phase 1: Baseline (no cache-aware) ==="
run_scenario "baseline" "" "${TMPDIR}/baseline"

echo ""
echo "=== Phase 2: Cache-aware ON ==="
run_scenario "cache-aware" "--performance --cache-aware" "${TMPDIR}/ca_on"

# ── Summary ──────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " RESULTS SUMMARY"
echo "============================================"

fmt_val() {
    local v="$1"
    if [ "$v" = "N/A" ] || [ -z "$v" ]; then
        printf "%14s" "N/A"
    else
        printf "%14s" "$v"
    fi
}

BL_XMIG=$(cat "${TMPDIR}/baseline_xmig" 2>/dev/null || echo "N/A")
BL_OPS=$(cat "${TMPDIR}/baseline_ops_s" 2>/dev/null || echo "N/A")
CA_XMIG=$(cat "${TMPDIR}/ca_on_xmig" 2>/dev/null || echo "N/A")
CA_OPS=$(cat "${TMPDIR}/ca_on_ops_s" 2>/dev/null || echo "N/A")
BL_CTX=$(cat "${TMPDIR}/baseline_ctx_sw" 2>/dev/null || echo "N/A")
BL_MIG=$(cat "${TMPDIR}/baseline_cpu_mig" 2>/dev/null || echo "N/A")
CA_CTX=$(cat "${TMPDIR}/ca_on_ctx_sw" 2>/dev/null || echo "N/A")
CA_MIG=$(cat "${TMPDIR}/ca_on_cpu_mig" 2>/dev/null || echo "N/A")

printf "%-18s %14s %14s\n" "Metric" "Baseline" "CA-on"
printf "%-18s %14s %14s\n" "------------------" "--------------" "--------------"
printf "%-18s " "X-MIG%"
fmt_val "$BL_XMIG"; printf " "
fmt_val "$CA_XMIG"; printf "\n"

printf "%-18s " "ops/s"
fmt_val "$BL_OPS"; printf " "
fmt_val "$CA_OPS"; printf "\n"

printf "%-18s " "context-switches"
fmt_val "$BL_CTX"; printf " "
fmt_val "$CA_CTX"; printf "\n"

printf "%-18s " "cpu-migrations"
fmt_val "$BL_MIG"; printf " "
fmt_val "$CA_MIG"; printf "\n"

if [ "$PERF_MODE" = "amd_l3" ]; then
    BL_L3_HR=$(cat "${TMPDIR}/baseline_l3_hit_rate" 2>/dev/null || echo "N/A")
    BL_L3_MISS=$(cat "${TMPDIR}/baseline_l3_miss" 2>/dev/null || echo "N/A")
    CA_L3_HR=$(cat "${TMPDIR}/ca_on_l3_hit_rate" 2>/dev/null || echo "N/A")
    CA_L3_MISS=$(cat "${TMPDIR}/ca_on_l3_miss" 2>/dev/null || echo "N/A")

    printf "%-18s " "L3 hit rate %"
    fmt_val "${BL_L3_HR}%"; printf " "
    fmt_val "${CA_L3_HR}%"; printf "\n"

    printf "%-18s " "L3 misses"
    fmt_val "$BL_L3_MISS"; printf " "
    fmt_val "$CA_L3_MISS"; printf "\n"

elif [ "$PERF_MODE" = "generic" ]; then
    BL_CM=$(cat "${TMPDIR}/baseline_cache_misses" 2>/dev/null || echo "N/A")
    BL_LLC=$(cat "${TMPDIR}/baseline_llc_misses" 2>/dev/null || echo "N/A")
    CA_CM=$(cat "${TMPDIR}/ca_on_cache_misses" 2>/dev/null || echo "N/A")
    CA_LLC=$(cat "${TMPDIR}/ca_on_llc_misses" 2>/dev/null || echo "N/A")

    printf "%-18s " "cache-misses"
    fmt_val "$BL_CM"; printf " "
    fmt_val "$CA_CM"; printf "\n"

    printf "%-18s " "LLC-load-misses"
    fmt_val "$BL_LLC"; printf " "
    fmt_val "$CA_LLC"; printf "\n"
fi

echo ""
echo "Detailed logs in: $TMPDIR/"
echo "  baseline_*  — no cache-aware"
echo "  ca_on_*     — --performance --cache-aware"

if [ -f "${TMPDIR}/ca_on_mm_ca_map.log" ]; then
    echo ""
    echo "mm_ca_map dump (cache-aware ON):"
    cat "${TMPDIR}/ca_on_mm_ca_map.log"
fi

echo ""
echo "============================================"
echo " Interpretation:"
echo "   X-MIG%:     lower is better (less cross-domain migration)"
echo "   ctx-sw:     lower is better (fewer context switches)"
echo "   cpu-mig:    lower is better (fewer CPU migrations)"
if [ "$PERF_MODE" = "amd_l3" ]; then
    echo "   L3 hit rate: higher is better (better cache locality)"
    echo "   L3 misses:  lower is better"
else
    echo "   cache-misses:    lower is better"
    echo "   LLC-load-misses: lower is better (better cache locality)"
fi
echo "   ops/s:      higher is better (more throughput)"
echo ""
echo " NOTE: Results are only meaningful on multi-LLC machines."
echo "       On a single-LLC system, cache-aware has no effect."
echo "============================================"