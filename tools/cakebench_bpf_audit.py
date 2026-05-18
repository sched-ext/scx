#!/usr/bin/env python3
"""Audit scx_cake BPF object hot-function instruction shape.

This is intentionally lightweight: it parses ``llvm-objdump -d`` output and
counts the hazards we repeatedly inspect during Cake scheduler mutations:
instructions, branches, calls, stack references, loads, and stores per function.
It is not a verifier substitute and it does not claim benchmark improvement.
Its job is to make codegen deltas reproducible before spending live benchmark
budget.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_FUNCTIONS = [
    "cake_select_cpu_fast_scan",
    "cake_dispatch",
    "cake_dispatch_try_cache_simple_lane",
    "cake_dispatch_try_single_llc_pull",
    "cake_dispatch_try_throughput_lane",
    "cake_try_insert_throughput_lane",
    "enqueue_body",
]

FUNC_RE = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:")
INSN_RE = re.compile(r"^\s*\d+:")
STACK_LOAD_RE = re.compile(
    r"^\s*(?P<insn>\d+):.*\b(?P<dst>r\d+)\s*=\s*"
    r"\*\(u(?P<bits>\d+)\s+\*\)\(r10\s*-\s*(?P<off>0x[0-9a-fA-F]+)\)"
)
STACK_STORE_RE = re.compile(
    r"^\s*(?P<insn>\d+):.*\*\(u(?P<bits>\d+)\s+\*\)"
    r"\(r10\s*-\s*(?P<off>0x[0-9a-fA-F]+)\)\s*="
)


def run_objdump(path: Path | str) -> str:
    return subprocess.check_output(
        ["llvm-objdump", "-d", "--no-show-raw-insn", str(path)],
        text=True,
    )


def parse_objdump(text: str) -> dict[str, list[str]]:
    functions: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = FUNC_RE.match(line)
        if match:
            current = match.group(1)
            functions.setdefault(current, [])
            continue
        if current and INSN_RE.match(line):
            functions[current].append(line.rstrip())
    return functions


def stack_range(off: int, bits: int) -> tuple[int, int]:
    """Return the positive stack-byte range touched by a BPF r10 access.

    BPF disassembly prints stack slots as ``r10 - off``. A ``u64`` access at
    ``r10 - 0x8`` touches bytes ``[0, 8)`` in this normalized coordinate; a
    ``u32`` access at ``r10 - 0x4`` touches ``[0, 4)``. This lets the audit
    classify exact, contained, and partial-overlap store-to-load shapes.
    """

    width = bits // 8
    return off - width, off


def stack_relation(store: dict[str, Any] | None, load: dict[str, Any]) -> str:
    if store is None:
        return "no_prior_store"
    s0, s1 = stack_range(store["off"], store["bits"])
    l0, l1 = stack_range(load["off"], load["bits"])
    if s1 <= l0 or l1 <= s0:
        return "no_overlap"
    if store["off"] == load["off"] and store["bits"] == load["bits"]:
        return "exact"
    if s0 <= l0 and l1 <= s1:
        return "load_contained_in_store"
    if l0 <= s0 and s1 <= l1:
        return "store_contained_in_load"
    return "partial_overlap"


def stack_access_shape(lines: list[str]) -> dict[str, Any]:
    """Classify r10 stack access producer/consumer shapes.

    This is intentionally a shape audit, not a full data-flow engine. It tracks
    the nearest preceding stack store that overlaps each stack load. The result
    highlights store-to-load-forwarding-friendly shapes (exact or contained
    loads from wider stores) and riskier partial-overlap shapes such as a
    narrow store followed by a wider overlapping load.
    """

    accesses: list[dict[str, Any]] = []
    prior_stores: list[dict[str, Any]] = []
    relation_counts: dict[str, int] = {}
    risk_count = 0
    for line in lines:
        store_match = STACK_STORE_RE.match(line)
        if store_match:
            access = {
                "op": "store",
                "insn": int(store_match.group("insn")),
                "bits": int(store_match.group("bits")),
                "off": int(store_match.group("off"), 16),
                "line": line,
            }
            accesses.append(access)
            prior_stores.append(access)
            continue

        load_match = STACK_LOAD_RE.match(line)
        if not load_match:
            continue
        load = {
            "op": "load",
            "insn": int(load_match.group("insn")),
            "bits": int(load_match.group("bits")),
            "off": int(load_match.group("off"), 16),
            "line": line,
        }
        producer = None
        for candidate in reversed(prior_stores):
            rel = stack_relation(candidate, load)
            if rel != "no_overlap":
                producer = candidate
                break
        relation = stack_relation(producer, load)
        load["producer_insn"] = producer["insn"] if producer else None
        load["producer_bits"] = producer["bits"] if producer else None
        load["producer_off"] = producer["off"] if producer else None
        load["relation"] = relation
        if relation in {"store_contained_in_load", "partial_overlap"}:
            risk_count += 1
        relation_counts[relation] = relation_counts.get(relation, 0) + 1
        accesses.append(load)

    return {
        "accesses": accesses,
        "relation_counts": relation_counts,
        "stlf_risk_loads": risk_count,
    }


def count_function(lines: list[str]) -> dict[str, int]:
    branches = 0
    calls = 0
    stack_refs = 0
    loads = 0
    stores = 0
    exits = 0
    for line in lines:
        lhs = line.split("=", 1)[0]
        if re.search(r"\bif\b|\bgoto\b", line):
            branches += 1
        if re.search(r"\bcall\b", line):
            calls += 1
        if "r10" in line:
            stack_refs += 1
        # BPF objdump load/store syntax is regular enough for a useful hazard
        # count. Avoid pretending this is a full instruction decoder.
        if re.search(r"=\s*\*\(", line):
            loads += 1
        if "*" in lhs:
            stores += 1
        if re.search(r"\bexit\b", line):
            exits += 1
    shape = stack_access_shape(lines)
    return {
        "instructions": len(lines),
        "branches": branches,
        "calls": calls,
        "stack_refs": stack_refs,
        "stack_load_refs": sum(1 for access in shape["accesses"] if access["op"] == "load"),
        "stack_store_refs": sum(1 for access in shape["accesses"] if access["op"] == "store"),
        "stlf_risk_loads": shape["stlf_risk_loads"],
        "loads": loads,
        "stores": stores,
        "exits": exits,
    }


def audit_objdump_text(text: str, functions: list[str]) -> dict[str, dict[str, int]]:
    parsed = parse_objdump(text)
    return {name: count_function(parsed.get(name, [])) for name in functions}


def audit_object(path: Path | str, functions: list[str]) -> dict[str, Any]:
    path = Path(path)
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "functions": audit_objdump_text(run_objdump(path), functions),
    }


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def delta_counts(
    baseline: dict[str, dict[str, int]], candidate: dict[str, dict[str, int]]
) -> dict[str, dict[str, int]]:
    deltas: dict[str, dict[str, int]] = {}
    for func in sorted(set(baseline) | set(candidate)):
        keys = sorted(set(baseline.get(func, {})) | set(candidate.get(func, {})))
        deltas[func] = {
            key: candidate.get(func, {}).get(key, 0) - baseline.get(func, {}).get(key, 0)
            for key in keys
        }
    return deltas


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    functions = args.function or DEFAULT_FUNCTIONS
    report: dict[str, Any] = {
        "created_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "functions": functions,
    }
    if args.obj:
        report["object"] = audit_object(args.obj, functions)
    if args.baseline or args.candidate:
        if not args.baseline or not args.candidate:
            raise ValueError("--baseline and --candidate must be provided together")
        baseline = audit_object(args.baseline, functions)
        candidate = audit_object(args.candidate, functions)
        report["baseline"] = baseline
        report["candidate"] = candidate
        report["delta"] = {
            "size_bytes": candidate["size_bytes"] - baseline["size_bytes"],
            "functions": delta_counts(baseline["functions"], candidate["functions"]),
        }
    if "object" not in report and "baseline" not in report:
        raise ValueError("provide --obj or --baseline/--candidate")
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# scx_cake BPF Hot-Function Audit",
        "",
        f"- Created UTC: `{report['created_utc']}`",
        f"- Functions: `{', '.join(report['functions'])}`",
    ]
    if "object" in report:
        obj = report["object"]
        lines.extend(
            [
                "",
                f"## Object `{obj['path']}`",
                "",
                f"- Size: `{obj['size_bytes']}` bytes",
                f"- SHA256: `{obj['sha256']}`",
                "",
            ]
        )
        lines.extend(function_table(obj["functions"]))
    if "baseline" in report:
        base = report["baseline"]
        cand = report["candidate"]
        lines.extend(
            [
                "",
                "## Comparison",
                "",
                f"- Baseline: `{base['path']}` (`{base['size_bytes']}` bytes)",
                f"- Baseline SHA256: `{base['sha256']}`",
                f"- Candidate: `{cand['path']}` (`{cand['size_bytes']}` bytes)",
                f"- Candidate SHA256: `{cand['sha256']}`",
                f"- Size delta: `{report['delta']['size_bytes']:+d}` bytes",
                "",
            ]
        )
        lines.extend(delta_table(base["functions"], cand["functions"], report["delta"]["functions"]))
    return "\n".join(lines) + "\n"


def function_table(functions: dict[str, dict[str, int]]) -> list[str]:
    lines = [
        "| Function | Insns | Branches | Calls | Stack refs | Stack L/S | STLF-risk loads | Loads | Stores |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, counts in functions.items():
        lines.append(
            f"| `{name}` | {counts['instructions']} | {counts['branches']} | "
            f"{counts['calls']} | {counts['stack_refs']} | "
            f"{counts.get('stack_load_refs', 0)}/{counts.get('stack_store_refs', 0)} | "
            f"{counts.get('stlf_risk_loads', 0)} | {counts['loads']} | {counts['stores']} |"
        )
    return lines


def delta_table(
    baseline: dict[str, dict[str, int]],
    candidate: dict[str, dict[str, int]],
    delta: dict[str, dict[str, int]],
) -> list[str]:
    lines = [
        "| Function | Insns | Branches | Calls | Stack refs | Stack L/S | STLF-risk loads | Loads | Stores |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, counts in delta.items():
        lines.append(
            f"| `{name}` | {candidate[name]['instructions']} ({counts['instructions']:+d}) | "
            f"{candidate[name]['branches']} ({counts['branches']:+d}) | "
            f"{candidate[name]['calls']} ({counts['calls']:+d}) | "
            f"{candidate[name]['stack_refs']} ({counts['stack_refs']:+d}) | "
            f"{candidate[name].get('stack_load_refs', 0)}/{candidate[name].get('stack_store_refs', 0)} "
            f"({counts.get('stack_load_refs', 0):+d}/{counts.get('stack_store_refs', 0):+d}) | "
            f"{candidate[name].get('stlf_risk_loads', 0)} ({counts.get('stlf_risk_loads', 0):+d}) | "
            f"{candidate[name]['loads']} ({counts['loads']:+d}) | "
            f"{candidate[name]['stores']} ({counts['stores']:+d}) |"
        )
    return lines


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit scx_cake BPF hot-function instruction shape.")
    parser.add_argument("--obj", help="single BPF object to audit")
    parser.add_argument("--baseline", help="baseline BPF object for comparison")
    parser.add_argument("--candidate", help="candidate BPF object for comparison")
    parser.add_argument("--function", action="append", help="function to include; repeatable")
    parser.add_argument("--out-json", help="write JSON report")
    parser.add_argument("--out-md", help="write Markdown report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    report = build_report(args)
    if args.out_json:
        path = Path(args.out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = render_markdown(report)
    if args.out_md:
        path = Path(args.out_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
    if not args.out_json and not args.out_md:
        print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
