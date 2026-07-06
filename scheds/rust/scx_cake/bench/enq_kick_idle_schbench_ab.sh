#!/usr/bin/env bash
# enq_kick_idle_schbench_ab.sh — automated schbench A/B for the SCX_ENQ_KICK_IDLE fold.
#
# Companion to enq_kick_idle_ab.sh (which is the interactive/game harness).
# Runs N interleaved `cakebench one schbench` captures per arm:
#   fold      SCX_CAKE_ENQ_KICK_IDLE=1  (insert carries the idle-kick, 1 kfunc)
#   explicit  knob unset                (insert + scx_bpf_kick_cpu, 2 kfuncs)
# Arms are interleaved ABBA (fold,explicit,explicit,fold,fold,explicit) so slow
# thermal/cache drift can't masquerade as an arm effect (see the 2026-06-08
# game A/B order-artifact finding).
#
# SCX_CAKE_CHANGE_ID=baseline on both arms: the two arms run IDENTICAL code —
# the knob is env-only — so this is a baseline kernel-feature measurement, not
# a cake code mutation; lineage taxonomy is deliberately skipped.
#
# Per run, kernel bpf_stats is enabled and `cake-bpfstats show` is polled every
# 5s while cake is loaded; the LAST snapshot before unload (cumulative
# run_time_ns/run_cnt per struct_ops prog) is kept as <arm>_<seq>_bpfstats.json.
# bpf_stats taxes both arms equally; ns/call deltas between arms stay valid.
#
# GATE: every fold-arm run's scx_cake.log MUST contain "SCX_ENQ_KICK_IDLE on";
# every explicit-arm run MUST NOT. Violations are recorded in gate_failures.txt
# and invalidate the A/B.
#
# Usage: ./enq_kick_idle_schbench_ab.sh   (sudo NOPASSWD paths used internally)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ASSETS="$(cd "$REPO/../scx_cake_bench_assets" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ASSETS/runs/enq_kick_idle_ab/$TS"
BPFSTATS=/usr/local/libexec/cake-bpfstats
mkdir -p "$OUT"

SEQ=(fold explicit explicit fold fold explicit)

echo "out: $OUT"
: > "$OUT/gate_failures.txt"

for i in "${!SEQ[@]}"; do
    arm="${SEQ[$i]}"
    tag="${arm}_$i"
    log="$OUT/${tag}_cakebench.log"
    snap="$OUT/${tag}_bpfstats.json"
    echo "=== run $i arm=$arm ==="

    sudo -n "$BPFSTATS" enable

    if [ "$arm" = fold ]; then
        sudo SCX_CAKE_CHANGE_ID=baseline SCX_CAKE_ENQ_KICK_IDLE=1 \
            "$REPO/cakebench" one schbench >"$log" 2>&1 &
    else
        sudo SCX_CAKE_CHANGE_ID=baseline \
            "$REPO/cakebench" one schbench >"$log" 2>&1 &
    fi
    pid=$!

    # Poll bpf_stats while cake is loaded; last cake-bearing snapshot wins.
    while kill -0 "$pid" 2>/dev/null; do
        sleep 5
        s="$(sudo -n "$BPFSTATS" show 2>/dev/null || true)"
        if [[ "$s" == *'"name":"cake_'* ]]; then
            printf '%s' "$s" > "$snap"
        fi
    done
    wait "$pid" || echo "run $i ($arm): cakebench exit nonzero" >> "$OUT/gate_failures.txt"

    sudo -n "$BPFSTATS" disable

    # Locate the run dir this iteration produced and gate the arm engagement.
    rdir="$(grep -oE '/[^ ]*runs/single/[0-9TZ]+_schbench[^ /]*' "$log" | head -1)"
    echo "$tag $rdir" >> "$OUT/run_dirs.txt"
    clog="$rdir/logs/scx_cake.log"
    if [ -f "$clog" ]; then
        if [ "$arm" = fold ] && ! grep -q 'SCX_ENQ_KICK_IDLE on' "$clog"; then
            echo "run $i (fold): MISSING 'SCX_ENQ_KICK_IDLE on' startup line" >> "$OUT/gate_failures.txt"
        fi
        if [ "$arm" = explicit ] && grep -q 'SCX_ENQ_KICK_IDLE on' "$clog"; then
            echo "run $i (explicit): fold line present, knob leaked" >> "$OUT/gate_failures.txt"
        fi
    else
        echo "run $i ($arm): no scx_cake.log at $clog" >> "$OUT/gate_failures.txt"
    fi
done

echo "=== done ==="
[ -s "$OUT/gate_failures.txt" ] && { echo "GATE FAILURES:"; cat "$OUT/gate_failures.txt"; }
echo "results in $OUT"
