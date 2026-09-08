#!/usr/bin/env python3
"""Compile current Cake functions against deterministic kernel-helper models.

Offline correctness only: no verifier, activation, timing, or kernel-race proof.
Generated inputs and binaries stay in the requested repository artifact folder.
"""
import argparse
import hashlib
import re
import subprocess
from pathlib import Path


def function(source, name):
    pattern = rf"^(?:static .*|(?:s32|void) BPF_STRUCT_OPS\(){name}[,(]"
    # Static definitions contain a return type before the function name.
    match = re.search(pattern, source, re.M)
    if match is None:
        raise ValueError(f"missing function {name}")
    start = source.index("{", match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    result = source[match.start():end]
    return re.sub(rf"(s32|void) BPF_STRUCT_OPS\({name},", rf"\1 {name}(", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    out = args.output.resolve()
    if not out.is_relative_to(root):
        parser.error("output must be inside the scx repository")
    out.mkdir(parents=True, exist_ok=True)
    bpf = Path(__file__).resolve().parents[1] / "src/bpf"
    source = (bpf / "cake.bpf.c").read_text()
    names = ["cake_stage", "cake_cross_llc", "cake_dispatch_search", "cake_select_cpu"]
    code = [function(source, name) for name in names]
    stats = sorted(set(re.findall(r"\bCAKE_(?:STAT|SITE)_\w+", "\n".join(code))))
    (out / "stats.h").write_text("enum {" + ",".join(stats) + "};\n")
    (out / "functions.h").write_text("\n\n".join(code))
    fixture = Path(__file__).with_name("review_regressions.c")
    binary = out / "review_regressions"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                    f"-I{out}", f"-I{bpf}", str(fixture), "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    print(result.stdout, end="")
    (out / "result.txt").write_text(
        "source sha256 " + hashlib.sha256(source.encode()).hexdigest() + "\n" + result.stdout)


if __name__ == "__main__":
    main()
