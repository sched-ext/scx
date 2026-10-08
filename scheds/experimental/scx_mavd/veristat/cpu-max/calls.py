#!/usr/bin/env python3
# Count the visits to every call target in a level-2 verifier log section
# (level2-log.sh output) and, for the target whose callee source line matches
# PATTERN, dump the call sites and the distinct caller states.
# Usage: calls.py LOG PATTERN
import re, sys
from collections import Counter, defaultdict

log, pat = sys.argv[1], sys.argv[2]
call_re = re.compile(r"^(\d+): \(85\) call pc\+(\d+)")
visits = Counter()
callee_line = {}
caller_states = defaultdict(Counter)
callsites = defaultdict(Counter)
last_linfo = ""
pending = None
state = 0
with open(log, errors="replace") as f:
	for line in f:
		if line.startswith("; "):
			last_linfo = line.strip()
			if state == 2 and pending is not None:
				callee_line.setdefault(pending[0], last_linfo)
				pending = None; state = 0
			continue
		m = call_re.match(line)
		if m:
			idx, off = int(m.group(1)), int(m.group(2))
			tgt = idx + 1 + off
			visits[tgt] += 1
			callsites[tgt][f"{idx} {last_linfo[:70]}"] += 1
			pending = (tgt, idx); state = 0
			continue
		if pending is None:
			continue
		if line.startswith("caller:"):
			state = 1; continue
		if state == 1:
			caller_states[pending[0]][line.strip()] += 1
			state = 0; continue
		if line.startswith("callee:"):
			state = 2; continue

print(f"== {log}: top call targets by visits")
for tgt, n in visits.most_common(18):
	print(f"{n:7d}  pc {tgt:5d}  {callee_line.get(tgt, '?')[:90]}")
for tgt, n in visits.most_common():
	if pat in callee_line.get(tgt, ""):
		print(f"\n== target pc {tgt} ({callee_line[tgt][:80]}): {n} visits")
		print("-- call sites:")
		for k, c in callsites[tgt].most_common(6):
			print(f"{c:6d}  {k}")
		print("-- distinct caller states (count, state):")
		for s, c in caller_states[tgt].most_common(12):
			print(f"{c:6d}  {s[:400]}")
		break
