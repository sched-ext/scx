#!/usr/bin/env python3
"""Summarize complete paired blocks; never treat emulation as hardware data."""
import argparse
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path


def summarize(rows):
    environments = [r for r in rows if r.get("type") == "environment"]
    correct = [r for r in rows if r.get("type") == "correctness"]
    if len(environments) != 1 or environments[0].get("check_only"):
        raise ValueError("expected one complete timing run")
    if len(correct) != 1 or correct[0].get("mismatches") != 0 or correct[0].get("program_runs") != 5780:
        raise ValueError("missing successful correctness record")
    env = environments[0]
    groups = defaultdict(lambda: defaultdict(dict))
    for r in rows:
        if r.get("type") != "timing":
            continue
        if r["name"] not in {"sw_ctz", "hw_ctz", "sw_pop", "hw_pop"}:
            raise ValueError("unknown timing arm")
        if r["repeat"] != env["repeat"]:
            raise ValueError("repeat differs from run metadata")
        key = (r["name"][3:], r["chain"], r["batch"])
        block = groups[key][r["block"]]
        if r["slot"] in block:
            raise ValueError("duplicate timing slot")
        block[r["slot"]] = r
    result = []
    rng = random.Random(29092026)
    expected = {(op, chain, batch) for op in ("ctz", "pop") for chain in (0, 1) for batch in (64, 256, 1024)}
    if set(groups) != expected:
        raise ValueError("incomplete measurement matrix")
    for key, blocks in sorted(groups.items()):
        if set(blocks) != set(range(env["blocks"])):
            raise ValueError("missing measurement blocks")
        differences = []
        sws, hws = [], []
        for block_id, slots in sorted(blocks.items()):
            if set(slots) != {0, 1, 2, 3}:
                raise ValueError(f"incomplete block: {key} {block_id}")
            sw, hw = [], []
            seeds = set()
            for slot, r in sorted(slots.items()):
                expected_arm = bool(slot in (1, 2)) ^ bool(block_id & 1)
                if r["name"].startswith("hw_") != expected_arm:
                    raise ValueError("unexpected arm order")
                if r["repeat"] <= 0 or r["batch"] <= 0 or r["wall_ns"] <= 0:
                    raise ValueError("invalid timing denominator/value")
                seeds.add((r["seed"], r["checksum"], r["repeat"]))
                (hw if expected_arm else sw).append(r["wall_ns"] / (r["repeat"] * r["batch"]))
            if len(seeds) != 1:
                raise ValueError("inputs, checksums or repeat differ within pair")
            a, b = statistics.mean(sw), statistics.mean(hw)
            sws.append(a)
            hws.append(b)
            differences.append(a - b)
        boot = sorted(statistics.mean(rng.choices(differences, k=len(differences))) for _ in range(10000))
        result.append({"operation": key[0], "dependent": bool(key[1]), "batch": key[2],
                       "blocks": len(differences), "software_wall_ns_per_op": statistics.mean(sws),
                       "native_wall_ns_per_op": statistics.mean(hws),
                       "saving_ns_per_op": statistics.mean(differences),
                       "paired_bootstrap_95_ci": [boot[250], boot[9749]] if len(differences) >= 8 else None,
                       "block_savings_ns": differences})
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", type=Path)
    ap.add_argument("--environment", choices=("hardware", "kvm", "tcg"), required=True)
    args = ap.parse_args()
    rows = [json.loads(line) for line in args.jsonl.read_text().splitlines() if line.strip()]
    if not any(r.get("type") == "correctness" and r.get("mismatches") == 0 for r in rows):
        raise SystemExit("No successful correctness record; refusing summary")
    print(json.dumps({"environment": args.environment,
                      "hardware_performance_evidence": args.environment == "hardware",
                      "measurement": "full BPF test-run wall time / repeat / batch; no overhead subtraction",
                      "results": summarize(rows)}, indent=2))


if __name__ == "__main__":
    main()
