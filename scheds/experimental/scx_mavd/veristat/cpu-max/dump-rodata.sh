#!/bin/bash
# Dump the .rodata map of a running scheduler into a blob that veristat can
# load (VERISTAT_RODATA, see the kernel branch's veristat). Start the
# scheduler in a configuration that loads, wait for it, dump, stop it.
# Runs as root. Usage: dump-rodata.sh OUT_BLOB SCHED_BIN [sched args...]
set -u
OUT="$1"; shift
"$@" > "$OUT.sched.log" 2>&1 &
pid=$!
for i in $(seq 1 120); do
	[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" = enabled ] && break
	kill -0 "$pid" 2>/dev/null || { echo "scheduler exited, see $OUT.sched.log"; exit 1; }
	sleep 0.5
done
[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" = enabled ] || { echo "scheduler did not come up"; kill -INT "$pid"; exit 1; }
# libbpf names the map after the object: bpf_bpf.rodata for the Rust schedulers
bpftool -j map dump name bpf_bpf.rodata > "$OUT.json"
bpftool map dump name bpf_bpf.rodata > "$OUT.txt"
kill -INT "$pid"; wait "$pid" 2>/dev/null
python3 - "$OUT.json" "$OUT" <<'EOF'
import json, sys
e = json.load(open(sys.argv[1]))[0]
b = bytes(int(x, 16) for x in e["value"])
open(sys.argv[2], "wb").write(b)
print("rodata blob:", sys.argv[2], len(b), "bytes; formatted dump:", sys.argv[2] + ".txt")
EOF
