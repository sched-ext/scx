#!/usr/bin/env python3
"""Per-FUNCTION stack-spill census of a BPF object.

Counts r10-relative stores (spills) and loads (fills) inside each function
body, NOT per ELF section: a section-level census merges the addr-taken set
across every function in it, so an ABI slot in one masks a real spill at the
same offset in another. Usage: fnspills.py <obj.bpf.o> [name-substring]
"""
import re, subprocess, sys, collections

obj = sys.argv[1]
want = sys.argv[2] if len(sys.argv) > 2 else ""
out = subprocess.run(["llvm-objdump", "-d", "-r", obj],
                     capture_output=True, text=True).stdout

# store: *(u64 *)(r10 - N) = rX      fill: rX = *(u64 *)(r10 - N)
# llvm-objdump >= 17 prints the offset in hex ("r10 - 0x8"); older builds printed
# decimal. Accept both — a decimal-only regex silently reports ZERO spills for
# every function on a hex toolchain (found 2026-08-07).
_OFF = r"(?:0x[0-9a-fA-F]+|\d+)"
st = re.compile(rf"\*\(u\d+ \*\)\(r10 [-+] {_OFF}\)\s*=")
ld = re.compile(rf"=\s*\*\(u\d+ \*\)\(r10 [-+] {_OFF}\)")
fn = re.compile(r"^[0-9a-f]+ <(.+)>:")

cur, rows = None, collections.OrderedDict()
for line in out.splitlines():
    m = fn.match(line)
    if m:
        cur = m.group(1)
        rows[cur] = [0, 0, 0]
        continue
    if cur is None:
        continue
    if re.match(r"^\s*[0-9a-f]+:", line):
        rows[cur][2] += 1
        if st.search(line):
            rows[cur][0] += 1
        elif ld.search(line):
            rows[cur][1] += 1

tot = [0, 0, 0]
print(f"{'function':38s} {'spill':>6s} {'fill':>6s} {'ops':>6s} {'insns':>7s}")
for k, (s, f, n) in rows.items():
    if want and want not in k:
        continue
    tot[0] += s; tot[1] += f; tot[2] += n
    flag = "" if s + f == 0 else "  <-"
    print(f"{k:38s} {s:6d} {f:6d} {s+f:6d} {n:7d}{flag}")
print(f"{'TOTAL':38s} {tot[0]:6d} {tot[1]:6d} {tot[0]+tot[1]:6d} {tot[2]:7d}")
