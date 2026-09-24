#!/usr/bin/env python3
"""Model the BPF verifier's combined stack check on a linked BPF object.

Usage: stack-chains.py OBJECT ROOT [ROOT...]

  OBJECT  a linked BPF ELF; for scx_mavd, run from the repository root,
          target/debug/build/scx_mavd-*/out/bpf.bpf.o after
          `cargo build -p scx_mavd`
  ROOT    the name of a program or function to start from, usually the
          struct_ops callbacks lavd_select_cid and lavd_enqueue

Requires llvm-objdump on PATH. Nothing is loaded into the kernel.

What it computes. check_max_stack_depth() in kernel/bpf/verifier.c walks
every call chain of a program, adds each subprogram's stack depth rounded up
to 16 bytes under the JIT, and rejects the program when a chain exceeds
MAX_BPF_STACK, 512 bytes. This script reproduces that walk from the emitted
code. A function's depth is its deepest r10-relative access, rounded up to
16. The extra slot that a may_goto instruction reserves is added by a later
fixup, so it is not counted, but a function containing one is marked. Call
edges come from the object's pseudo calls: a call relocated against a
defined function, a call relocated against a section, whose target is the
function starting at instruction imm + 1 of that section, and an unrelocated
call, whose target is relative to the call site within its section. Helper
calls and calls to undefined symbols, the kfuncs, add no frame. Static and
global functions are on a chain alike.

Output. For each root, the six deepest chains, one per line:

  544 6 calls: lavd_enqueue[160+mg=160] > pick_idle_cpu[104+mg=112] > ...

The first number is the chain's total, then the number of frames, then the
frames from the root down. In each frame, the first number is the deepest
r10 offset in the object, "+mg" marks a may_goto, and the number after "="
is the rounded frame the verifier adds.

How to read it. The total is an upper bound: the verifier charges a
subprogram only for the accesses it actually verifies, so code it never
reaches does not count, and its total for the same chain can be lower. A
chain over 512 here means measure, not rejected: load the object and read
the verifier's own `stack depth ... max N` line at log level 4, which is the
number that decides. A chain that the verifier does reject is always over
512 here as well. A warning names a pseudo call the script could not map to
a function start. The model of that caller is then incomplete, and every
chain through it is short by the unmapped callee. None is expected on the
scx_mavd object.
"""
import re
import subprocess
import sys

if len(sys.argv) < 3:
    sys.exit(__doc__.split("\n\n")[1])

obj = sys.argv[1]
roots = sys.argv[2:]
try:
    out = subprocess.run(["llvm-objdump", "-dr", obj],
                         capture_output=True, text=True, check=True).stdout
except FileNotFoundError:
    sys.exit("error: llvm-objdump not found on PATH")
except subprocess.CalledProcessError as e:
    sys.exit(f"error: llvm-objdump failed on {obj}:\n{e.stderr.rstrip()}")

depth = {}
start = {}          # function -> (section, first insn index)
sections = set()
may_goto = set()
calls_raw = []      # (caller, section, insn index, imm, relocation symbol or None)
fn = None
pending = None      # the last pseudo call, until the line after it says whether
                    # it carries a relocation
section = None
for line in out.splitlines():
    m = re.search(r"R_BPF_64_32\t(\S+)", line)
    if m:
        if pending:
            calls_raw.append(pending + (m.group(1),))
            pending = None
        continue
    if pending:
        calls_raw.append(pending + (None,))
        pending = None
    m = re.match(r"^Disassembly of section (.*):$", line)
    if m:
        section = m.group(1)
        sections.add(section)
        continue
    m = re.match(r"^([0-9a-f]+) <(.*)>:$", line)
    if m:
        name = m.group(2)
        if not name.startswith("LBB"):
            fn = name
            depth.setdefault(fn, 0)
            start[fn] = (section, int(m.group(1), 16) // 8)
        continue
    if fn is None:
        continue
    m = re.search(r"r10 - 0x([0-9a-f]+)", line)
    if m:
        depth[fn] = max(depth[fn], int(m.group(1), 16))
    if "may_goto" in line:
        may_goto.add(fn)
    # opcode 0x85 with src_reg 1 is a pseudo call; src_reg 0 is a helper call
    m = re.match(r"^\s*(\d+):\t85 (\d\d)(?: [0-9a-f]{2}){6}\tcall (-?0x[0-9a-f]+|-?\d+)",
                 line)
    if m and m.group(2) == "10":
        pending = (fn, section, int(m.group(1)), int(m.group(3), 0))

by_start = {v: f for f, v in start.items()}
calls = {f: set() for f in depth}
for caller, sec, idx, imm, sym in calls_raw:
    if sym is None:
        target = (sec, idx + 1 + imm)
    elif sym in depth:
        calls[caller].add(sym)
        continue
    elif sym in sections:
        target = (sym, imm + 1)
    else:
        continue        # an undefined symbol is a kfunc
    if target in by_start:
        calls[caller].add(by_start[target])
    else:
        print(f"warning: call from {caller} at insn {idx} maps to no function start",
              file=sys.stderr)


def frame(f):
    # check_max_stack_depth() runs before the may_goto fixup adds its slot
    # and rounds to 16 with a JIT
    d = depth.get(f, 0)
    return (d + 15) // 16 * 16


def chains(f, seen):
    res = [[f]]
    for c in sorted(calls.get(f, ())):
        if c in seen:
            continue
        for ch in chains(c, seen | {f}):
            res.append([f] + ch)
    return res


for root in roots:
    if root not in depth:
        sys.exit(f"error: {root} is not a function in {obj}")
    allc = chains(root, frozenset())
    allc.sort(key=lambda ch: -sum(frame(x) for x in ch))
    print(f"== {root}")
    for ch in allc[:6]:
        total = sum(frame(x) for x in ch)
        parts = " > ".join(f"{x}[{depth.get(x, 0)}{'+mg' if x in may_goto else ''}"
                           f"={frame(x)}]" for x in ch)
        print(f"{total:5d} {len(ch)} calls: {parts}")
