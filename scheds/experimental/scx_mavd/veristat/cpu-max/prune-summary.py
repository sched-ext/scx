#!/usr/bin/env python3
# Summarize the PRUNE_DBG blocks the kernel branch's pruning diagnostic writes
# into a level-2 log: per miss, the set of failing checks, then the old/cur
# values of the failing registers. Usage: prune-summary.py LOG
import re, sys
from collections import Counter

blocks = []; cur = None
for line in open(sys.argv[1], errors="replace"):
	line = line.split(":", 1)[1] if re.match(r"^\d+:", line) else line
	if line.startswith("PRUNE_DBG miss at"):
		cur = {"hdr": line.strip(), "fails": [], "old": "", "cur": ""}; blocks.append(cur)
	elif cur is None:
		continue
	elif line.startswith("PRUNE_DBG fail"):
		cur["fails"].append(line.strip()[15:])
	elif line.startswith("PRUNE_DBG old:"):
		cur["old"] = line.strip()[14:]
	elif line.startswith("PRUNE_DBG cur:"):
		cur["cur"] = line.strip()[14:]

print(f"misses: {len(blocks)}")
combo = Counter(tuple(re.sub(r"\(.*", "", f).strip() for f in b["fails"]) for b in blocks)
print("-- failing-check combinations per miss:")
for k, c in combo.most_common(10):
	print(f"{c:5d}  {' + '.join(k) if k else '(none)'}")
print("-- register pairs (old vs cur) for failing registers:")
seen = Counter()
for b in blocks:
	for f in b["fails"]:
		m = re.match(r"frame(\d+) (r\d+) ", f)
		if not m:
			continue
		reg = m.group(2).upper()
		o = re.search(reg + r"=(\S+)", b["old"]); c = re.search(reg + r"=(\S+)", b["cur"])
		seen[(reg, o.group(1)[:60] if o else "NOT_INIT", c.group(1)[:60] if c else "NOT_INIT")] += 1
for (reg, o, c), n in seen.most_common(10):
	print(f"{n:5d}  {reg}: old={o}  cur={c}")
