#!/usr/bin/env python3
"""Deepest call chains of a BPF object the way the verifier sums them.

Usage: stack-chains.py OBJECT ROOT [ROOT...]

Per function: stack depth is the deepest r10-relative access, rounded up to
16 as check_max_stack_depth() does with a JIT; the may_goto slot is added
only after that check. Edges come from call relocations to defined
functions and from relative calls resolved to function starts; calls to
undefined symbols are kfuncs and add no frame. Prints the six deepest
chains from each root. The result is an upper bound: the verifier counts
only the accesses it reaches, this script counts every emitted one.
"""
import re
import subprocess
import sys

obj = sys.argv[1]
roots = sys.argv[2:]
out = subprocess.run(["llvm-objdump", "-dr", "--no-show-raw-insn", obj],
                     capture_output=True, text=True, check=True).stdout

depth = {}
start = {}          # function -> (section, first insn index)
may_goto = set()
rel_calls = []      # (caller, (section, target insn index))
reloc_calls = []    # (caller, symbol)
fn = None
pending = None
section = None
for line in out.splitlines():
    m = re.match(r"^Disassembly of section (.*):$", line)
    if m:
        section = m.group(1)
        continue
    m = re.match(r"^([0-9a-f]+) <(.*)>:$", line)
    if m:
        name = m.group(2)
        if not name.startswith("LBB"):
            fn = name
            depth.setdefault(fn, 0)
            start[fn] = (section, int(m.group(1), 16) // 8)
        pending = None
        continue
    if fn is None:
        continue
    m = re.search(r"r10 - 0x([0-9a-f]+)", line)
    if m:
        depth[fn] = max(depth[fn], int(m.group(1), 16))
    if "may_goto" in line:
        may_goto.add(fn)
    m = re.match(r"\s*(\d+):\tcall (-?0x[0-9a-f]+|-?\d+)", line)
    if m:
        idx = int(m.group(1))
        imm = int(m.group(2), 0)
        if imm == -1:
            pending = fn
        else:
            rel_calls.append((fn, (section, idx + 1 + imm)))
            pending = None
        continue
    m = re.search(r"R_BPF_64_32\t(\S+)", line)
    if m and pending:
        reloc_calls.append((pending, m.group(1)))
    pending = None

by_start = {v: f for f, v in start.items()}
calls = {f: set() for f in depth}
for caller, target in rel_calls:
    if target in by_start:
        calls[caller].add(by_start[target])
    else:
        print(f"warning: unresolved relative call from {caller} to insn {target}",
              file=sys.stderr)
for caller, sym in reloc_calls:
    if sym in depth:
        calls[caller].add(sym)


def frame(f):
    # check_max_stack_depth() runs before the may_goto fixup adds its slot
    # and rounds to 16 with a JIT
    d = depth.get(f, 0)
    return (max(d, 1) + 15) // 16 * 16


def chains(f, seen):
    res = [[f]]
    for c in sorted(calls.get(f, ())):
        if c in seen:
            continue
        for ch in chains(c, seen | {f}):
            res.append([f] + ch)
    return res


for root in roots:
    allc = chains(root, frozenset())
    allc.sort(key=lambda ch: -sum(frame(x) for x in ch))
    print(f"== {root}")
    for ch in allc[:6]:
        total = sum(frame(x) for x in ch)
        parts = " > ".join(f"{x}[{depth.get(x, 0)}{'+mg' if x in may_goto else ''}={frame(x)}]"
                           for x in ch)
        print(f"{total:5d} {len(ch)} calls: {parts}")
