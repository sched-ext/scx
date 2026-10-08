#!/bin/bash
# Verifier cost of lavd_dispatch with the live rodata, cpu.max off and on,
# plus the per-subprogram table's consume_task line. Needs the veristat from
# the kernel branch (VERISTAT_RODATA / VERISTAT_ARENA_SCALAR hooks) and a
# blob from dump-rodata.sh. Runs as root on the target kernel.
# Usage: veristat-cpu-max.sh VERISTAT OBJ BLOB SCALAR(0/1) [OUT_DIR]
set -u
VS="$1"; OBJ="$2"; BLOB="$3"; SCALAR="$4"; OUT="${5:-.}"
mkdir -p "$OUT"
if [ "$SCALAR" = 1 ]; then export VERISTAT_ARENA_SCALAR=1; else unset VERISTAT_ARENA_SCALAR; fi
export VERISTAT_RODATA="$BLOB"
# the rodata the loader sets for --enable-cpu-bw --cpu-bw-max-cgroups 2048
BW=(-G "enable_cpu_bw = 1" -G "nr_cgrp_max = 2048" -G "tree_height_max = 32" -G "bw_set_sleepable = 1")
# level 1 plus the stats log; the default log size probes 1 GiB and segfaults in a small VM
LOG=(-v -l 1 --log-size 268435456 --log-fixed)
for cfg in nobw bw; do
	if [ $cfg = bw ]; then "$VS" "${LOG[@]}" "${BW[@]}" "$OBJ" > "$OUT/log-$cfg.txt" 2>&1
	else "$VS" "${LOG[@]}" "$OBJ" > "$OUT/log-$cfg.txt" 2>&1; fi
	row=$(grep -E "lavd_dispatch .*(success|failure)" "$OUT/log-$cfg.txt" | head -1 | awk '{print $3, "insns=" $5, "states=" $6}')
	n=$(grep -n "^PROCESSING.*lavd_dispatch" "$OUT/log-$cfg.txt" | cut -d: -f1)
	ct=$(awk -v s="$n" 'NR>s && /^PROCESSING/ {exit} NR>s && /^subprog .*\(consume_task\)/' "$OUT/log-$cfg.txt" | awk '{print "insns_self=" $6}')
	printf "%-5s lavd_dispatch %-30s consume_task %s\n" "$cfg" "$row" "${ct:-?}"
done
