#!/usr/bin/env python3
"""Collect a standalone primitive experiment; does not attach a scheduler."""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path

from analyze import summarize


def read(path):
    try:
        return Path(path).read_text()
    except OSError as exc:
        return {"unavailable": str(exc)}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot():
    paths = ["/proc/cpuinfo", "/proc/cmdline", "/proc/loadavg", "/proc/interrupts",
             "/proc/sys/kernel/random/boot_id", "/proc/sys/net/core/bpf_jit_enable",
             "/proc/sys/net/core/bpf_jit_harden", "/sys/kernel/sched_ext/state"]
    for pattern in ("devices/system/cpu/cpu*/cpufreq/scaling_governor",
                    "devices/system/cpu/cpu*/cpufreq/scaling_cur_freq",
                    "class/hwmon/hwmon*/temp*_input"):
        paths.extend(str(p) for p in Path("/sys").glob(pattern))
    return {path: read(path) for path in paths}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", type=Path, help="new directory; existing results are never overwritten")
    ap.add_argument("--binary", type=Path, default=Path("build/bitops-run"))
    ap.add_argument("--environment", choices=("hardware", "kvm", "tcg"), required=True)
    ap.add_argument("--expect", choices=("native", "fallback"), default="native")
    ap.add_argument("--repeat", type=int, default=10000)
    ap.add_argument("--blocks", type=int, default=12)
    ap.add_argument("--cpu", type=int, required=True)
    args = ap.parse_args()
    if not 1 <= args.repeat <= 1000000 or not 1 <= args.blocks <= 100 or args.cpu not in os.sched_getaffinity(0):
        ap.error("invalid repeat, blocks, or CPU outside current affinity")
    binary = args.binary.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir()
    metadata = {"environment_declared": args.environment, "expected_path": args.expect,
                "uname": list(platform.uname()), "binary": str(binary), "binary_sha256": sha(binary),
                "before": snapshot(), "command": [str(binary), str(out / "programs"),
                    str(args.repeat), str(args.blocks), str(args.cpu)]}
    try:
        metadata["kernel_btf_sha256"] = sha("/sys/kernel/btf/vmlinux")
    except OSError as exc:
        metadata["kernel_btf_unavailable"] = str(exc)
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2))
    with (out / "raw.jsonl").open("x") as stdout, (out / "stderr.log").open("x") as stderr:
        result = subprocess.run(metadata["command"], stdout=stdout, stderr=stderr)
    metadata["exit_code"] = result.returncode
    metadata["after"] = snapshot()
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2))
    if result.returncode:
        raise SystemExit(f"Run failed; inspect {out / 'stderr.log'}. No performance summary produced.")
    paths = {}
    for name, mnemonic in (("hw_ctz", "tzcnt"), ("hw_pop", "popcnt")):
        dump = out / "programs" / f"{name}.jit.bin"
        asm = subprocess.check_output(["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", str(dump)], text=True)
        (out / f"{name}.jit.asm").write_text(asm)
        present = bool(re.search(r"\b" + mnemonic + r"\s", asm))
        if present != (args.expect == "native"):
            raise SystemExit(f"Unexpected JIT path for {name}; refusing summary")
        paths[name] = {"instruction": mnemonic, "present": present, "sha256": sha(dump)}
    rows = [json.loads(line) for line in (out / "raw.jsonl").read_text().splitlines()]
    report = {"environment": args.environment,
              "hardware_performance_evidence": args.environment == "hardware" and args.expect == "native",
              "jit": paths, "measurement": "whole primitive loop, including iterator and test-run overhead",
              "results": summarize(rows)}
    (out / "summary.json").write_text(json.dumps(report, indent=2))
    print(out / "summary.json")


if __name__ == "__main__":
    main()
