#!/usr/bin/env python3
"""Attribute kernel-mode perf samples to cake BPF functions, resolving IPs against a kallsyms snapshot."""
import bisect, collections, re, sys
from pathlib import Path

O = Path(sys.argv[1])
addrs, names = [], []
for l in open(O / "kallsyms.txt"):
    a, t, n = l.split()[:3]
    if t in "tTwW":
        addrs.append(int(a, 16)); names.append(n)
order = sorted(range(len(addrs)), key=addrs.__getitem__)
addrs = [addrs[i] for i in order]; names = [names[i] for i in order]


def sym(ip):
    i = bisect.bisect_right(addrs, ip) - 1
    return names[i] if i >= 0 and ip - addrs[i] < (1 << 20) else "?"


BPF = re.compile(r"bpf_prog_[0-9a-f]+_(\S+)")
total = 0
cb, self_, kern, incl = (collections.Counter() for _ in range(4))
cache = {}
for blk in open(O / "script.txt").read().split("\n\n"):
    lines = blk.strip().splitlines()
    if len(lines) < 2:
        continue
    try:
        period = int(lines[0].split()[0])
    except ValueError:
        continue
    total += period
    frames = []
    for l in lines[1:]:
        ip = int(l.split()[0], 16)
        if ip < 0xffff800000000000:
            break
        s = cache.get(ip)
        if s is None:
            s = cache[ip] = sym(ip)
        frames.append(s)
    idx = [i for i, f in enumerate(frames) if BPF.match(f) and BPF.match(f).group(1).startswith("cake_")]
    if not idx:
        continue
    nm = [BPF.match(frames[i]).group(1) for i in idx]
    cb[nm[-1]] += period
    for n in set(nm):
        incl[n] += period
    if idx[0] == 0:
        self_[nm[0]] += period
    else:
        kern[(nm[0], frames[idx[0] - 1], frames[0])] += period
tb = sum(cb.values())
print(f"kernel-mode cycles sampled {total:,}; inside cake_-named programs {tb:,} ({100 * tb / max(1, total):.2f} % of kernel time)")
print("\n## by callback (outermost cake frame), % of cake_-named time")
for k, v in cb.most_common(25):
    print(f"{100 * v / tb:6.2f}  {k}")
print("\n## inclusive per cake function")
for k, v in incl.most_common(45):
    print(f"{100 * v / tb:6.2f}  {k}")
print("\n## cake function self (BPF instructions)")
for k, v in self_.most_common(30):
    print(f"{100 * v / tb:6.2f}  {k}")
print("\n## kernel under a cake function: function -> kfunc/helper entry -> leaf")
for (f, e, leaf), v in kern.most_common(50):
    print(f"{100 * v / tb:6.2f}  {f:28} -> {e:36} -> {leaf}")

# Full leaf aggregation, not only the rounded top-50 display.
import json
leaf_period = collections.Counter()
for (_, _, leaf), period in kern.items():
    leaf_period[leaf] += period
out = {"source_directory": str(O), "kernel_sample_period": total,
       "cake_named_sample_period": tb,
       "kernel_leaves": {k: {"sample_period": v, "pct_cake_named": 100*v/tb}
                          for k, v in leaf_period.most_common()},
       "limits": "Archived 2026-09-27 samples; name filter, original nearest-symbol resolver; not a current measurement or exact symbol-range proof."}
Path(sys.argv[2]).write_text(json.dumps(out, indent=2)+"\n")
