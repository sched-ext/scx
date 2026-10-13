#!/usr/bin/env python3
"""Reproduce offline compiler/correctness research without loading any BPF."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
OUT = ROOT / "target/cake_isa_research_20261001"
OUT.mkdir(parents=True, exist_ok=True)
COMMANDS = []


def run(args, output):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    (OUT / output).write_text(result.stdout)
    (OUT / (output + ".stderr")).write_text(result.stderr)
    COMMANDS.append({"argv": [str(a) for a in args], "exit_code": result.returncode,
                     "stdout": output, "stderr": output + ".stderr"})
    if result.returncode:
        raise RuntimeError(f"Command failed: {args}: {result.stderr}")
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def counts(disassembly):
    result, name = {}, None
    for line in disassembly.splitlines():
        match = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if match:
            name = match[1]
            result[name] = {"static_disassembly_instructions": 0, "stack_accesses": 0,
                            "calls": 0, "conditional_branches": 0}
            continue
        match = re.match(r"^\s*[0-9a-f]+:\s+(\S.*)$", line)
        if name and match:
            text = match[1]
            result[name]["static_disassembly_instructions"] += 1
            result[name]["stack_accesses"] += int("r10 -" in text or "(%rsp)" in text or "(%rbp)" in text)
            result[name]["calls"] += int("call" in text)
            result[name]["conditional_branches"] += int(text.startswith("if ") or bool(re.match(r"j(?!mp)\w+", text)))
    return result


def main():
    header = ROOT / "scheds/rust/scx_cake/src/bpf/quotient.bpf.h"
    (OUT / "quotient.snapshot.h").write_bytes(header.read_bytes())
    run(["clang", "--version"], "clang-version.txt")
    run(["uname", "-r"], "running-kernel.txt")
    run(["git", "rev-parse", "HEAD"], "scx-head.txt")
    run(["git", "status", "--short"], "scx-status.txt")
    run(["clang", "-target", "bpf", "-mcpu=v3", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
         "-c", str(HERE / "probes.c"), "-o", str(OUT / "probes.bpf.o")], "compile-bpf.log")
    bpf = run(["llvm-objdump", "-d", "--no-show-raw-insn", str(OUT / "probes.bpf.o")], "probes.bpf.asm")
    run(["clang", "-O2", "-march=znver5", "-Wall", "-Wextra", "-Werror", "-c",
         str(HERE / "probes.c"), "-o", str(OUT / "probes.x86.o")], "compile-x86.log")
    native = run(["llvm-objdump", "-d", "--no-show-raw-insn", str(OUT / "probes.x86.o")], "probes.x86.asm")
    run(["clang", "-O2", "-march=znver5", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
         "-fno-sanitize-recover=all", "-I", str(OUT), str(HERE / "validate.c"),
         "-o", str(OUT / "validate")], "compile-validation.log")
    validation = json.loads(run([str(OUT / "validate")], "validation.json"))
    sources = [HERE / "probes.c", HERE / "validate.c", HERE / "run_research.py", header,
               ROOT / "scheds/rust/scx_cake/src/bpf/cake.bpf.c",
               ROOT / "scheds/rust/scx_cake/src/main.rs",
               ROOT / "scheds/rust/scx_cake/src/bpf/intf.h",
               ROOT.parent / "experimental-patches/kernel/sched-ext/research/jit-bitops-prototype/0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch"]
    base = ROOT / "target/cake_jit_bitops_20260929/cachyos-7.2.8-port/linux"
    sources += [base / name for name in ("kernel/bpf/verifier.c", "include/linux/btf.h", "arch/x86/net/bpf_jit_comp.c")]
    summary = {"created_utc": datetime.now(timezone.utc).isoformat(),
               "scope": "standalone compiler probes and offline correctness only",
               "bpf_loaded": False, "scheduler_activated": False, "performance_measured": False,
               "kernel_sources": "retained CachyOS 7.2.8 source; not fresh proof of running-image equivalence",
               "validation": validation, "bpf_counts": counts(bpf), "x86_counts": counts(native),
               "source_sha256": {str(p): digest(p) for p in sources}, "commands": COMMANDS}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"output": str(OUT), "validation": validation, "bpf_counts": summary["bpf_counts"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    finally:
        (OUT / "commands.json").write_text(json.dumps(COMMANDS, indent=2) + "\n")
