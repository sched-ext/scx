#!/bin/bash
# Full level-2 verifier log of lavd_dispatch (every instruction with its state,
# every call with the caller state, N: safe for pruned arrivals), cpu.max off
# or on. The log is 500 MB to 800 MB; the guest needs a few GB. To use the
# kernel branch's pruning diagnostic, write the instruction index first:
#   echo 598 > /sys/module/kernel/parameters/bpf_prune_dbg_insn
# Then: calls.py LOG consume_task; prune-summary.py <(grep PRUNE_DBG LOG).
# Runs as root. Usage: level2-log.sh VERISTAT OBJ BLOB SCALAR(0/1) nobw|bw OUT_LOG
set -u
VS="$1"; OBJ="$2"; BLOB="$3"; SCALAR="$4"; CFG="$5"; LOG="$6"
if [ "$SCALAR" = 1 ]; then export VERISTAT_ARENA_SCALAR=1; else unset VERISTAT_ARENA_SCALAR; fi
export VERISTAT_RODATA="$BLOB"
BW=(-G "enable_cpu_bw = 1" -G "nr_cgrp_max = 2048" -G "tree_height_max = 32" -G "bw_set_sleepable = 1")
OPTS=(-v -l 2 --log-size 1073741823 --log-fixed)
if [ "$CFG" = bw ]; then "$VS" "${OPTS[@]}" "${BW[@]}" "$OBJ" > "$LOG.all" 2>&1
else "$VS" "${OPTS[@]}" "$OBJ" > "$LOG.all" 2>&1; fi
grep -E "lavd_dispatch .*(success|failure)" "$LOG.all" | head -1
# keep lavd_dispatch's section only
awk '/^PROCESSING /{p=index($0,"/lavd_dispatch,")>0} p' "$LOG.all" > "$LOG"
rm -f "$LOG.all"
wc -l "$LOG"
