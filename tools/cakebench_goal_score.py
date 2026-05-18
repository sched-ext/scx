#!/usr/bin/env python3
"""Equal-weight scx_cake goal scoring.

This helper implements the Cake-first scoring contract from ``docs/goals.md``:
each benchmark receives one equal-weight bucket, multi-metric benchmarks are
combined inside that bucket, and wallclock is reported separately from score.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


VALID_MUTATION_SIZES = {"S", "M", "L", "XL"}
VALID_MUTATION_DECISIONS = {"keep", "mutate", "park", "revert", ""}
CAPTURE_WALL_TIME_BACKFILL_BENCHMARKS = {
    "perf-sched-fork",
    "perf-sched-thread",
}


def parse_float(value: Any) -> float:
    if value is None or value == "":
        return math.nan
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan


def read_tsv_rows(path: Path | str) -> list[dict[str, str]]:
    path = resolve_metrics_path(Path(path))
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def read_goal_rows(path: Path | str) -> list[dict[str, str]]:
    """Read primary score rows plus goal-relevant native companion metrics."""
    input_path = Path(path)
    primary_path = resolve_metrics_path(input_path)
    rows = read_tsv_rows(primary_path)
    if input_path.is_file():
        native_path = input_path.with_name("analysis_native_metrics.tsv")
    else:
        native_path = input_path / "analysis_native_metrics.tsv"
    rows.extend(goal_native_rows(native_path))
    return filter_cake_goal_rows(rows)


def filter_cake_goal_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep Cake rows when a scheduler/config matrix contains multiple variants.

    ``goal-score`` is a Cake-first scorer.  All-scheduler matrices use the same
    benchmark/metric keys for every scheduler, so comparing them directly would
    let later sibling/native rows overwrite Cake's baseline row.  Prefer the
    current default release Cake variant when present; otherwise leave the input
    untouched so single captures and hand-written unit rows still work.
    """
    variants = {row.get("variant", "") for row in rows if row.get("variant", "")}
    if len(variants) <= 1:
        return rows
    if "cake-release-default" in variants:
        return [row for row in rows if row.get("variant", "") == "cake-release-default"]
    return rows


def goal_native_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    selected: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            benchmark = row.get("benchmark", "")
            metric = row.get("metric", "")
            if (
                benchmark == "stress-ng-cpu-cache-mem"
                and metric == "stress_memcpy_bogo_ops_per_s_realtime"
            ):
                selected.append(
                    {
                        "seq": row.get("seq", ""),
                        "variant": row.get("variant", ""),
                        "benchmark": benchmark,
                        "subcase": "memcpy",
                        "metric": "memcpy_ops",
                        "value": row.get("value", ""),
                        "direction": row.get("direction", "higher") or "higher",
                        "unit": row.get("unit", "bogo_ops/s") or "bogo_ops/s",
                        "source": row.get("source", ""),
                        "wall_seconds": "",
                        "repeat": row.get("repeat", ""),
                        "run_dir": row.get("run_dir", ""),
                    }
                )
    return selected


def resolve_metrics_path(path: Path) -> Path:
    if path.is_file():
        return path
    candidates = [
        path / "analysis_metrics.tsv",
        path / "capture_metrics.tsv",
        path / "release_matrix_metrics.tsv",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"no metrics TSV found at {path}")


def canonical_subcase(row: dict[str, str]) -> str:
    subcase = row.get("subcase", "")
    benchmark = row.get("benchmark", "")
    metric = row.get("metric", "")
    if benchmark == "schbench" and metric == "request_p99":
        return ""
    if benchmark != "stress-ng-cpu-cache-mem":
        return subcase
    if subcase:
        return subcase
    if metric == "cache_ops":
        return "cache"
    if metric == "memcpy_ops":
        return "memcpy"
    return subcase


def row_key(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    return (
        row.get("benchmark", ""),
        canonical_subcase(row),
        row.get("metric", ""),
        row.get("direction", ""),
        row.get("unit", ""),
    )


def expand_goal_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    expanded = list(rows)
    existing = {row_key(row) for row in expanded}
    for row in rows:
        benchmark = row.get("benchmark", "")
        if benchmark not in CAPTURE_WALL_TIME_BACKFILL_BENCHMARKS:
            continue
        if row.get("metric", "") == "wall_time":
            continue
        wall = parse_float(row.get("wall_seconds"))
        if math.isnan(wall) or wall <= 0:
            continue
        backfill = dict(row)
        backfill.update(
            {
                "metric": "wall_time",
                "value": row.get("wall_seconds", ""),
                "direction": "lower",
                "unit": "s",
            }
        )
        key = row_key(backfill)
        if key not in existing:
            existing.add(key)
            expanded.append(backfill)
    return expanded


def metric_ratio(baseline: float, candidate: float, direction: str) -> float:
    if baseline <= 0 or candidate <= 0 or math.isnan(baseline) or math.isnan(candidate):
        return math.nan
    if direction == "higher":
        return candidate / baseline
    return baseline / candidate


def geometric_mean(values: Iterable[float]) -> float:
    clean = [value for value in values if value > 0 and not math.isnan(value)]
    if not clean:
        return math.nan
    return math.exp(sum(math.log(value) for value in clean) / len(clean))


def goal_score_label(row: dict[str, str]) -> str:
    if row.get("benchmark", "") == "stress-ng-cpu-cache-mem":
        return "stress-ng-cpu-cache-mem"
    subcase = row.get("subcase", "")
    base = row.get("benchmark", "")
    return f"{base}/{subcase}" if subcase else base


def summarize_wallclock(
    baseline_rows: list[dict[str, str]], candidate_rows: list[dict[str, str]]
) -> dict[str, float]:
    baseline_wall = sum(
        value for value in (parse_float(row.get("wall_seconds")) for row in baseline_rows) if not math.isnan(value)
    )
    candidate_wall = sum(
        value for value in (parse_float(row.get("wall_seconds")) for row in candidate_rows) if not math.isnan(value)
    )
    baseline_primary_lower = sum(
        parse_float(row.get("value"))
        for row in baseline_rows
        if row.get("direction") == "lower"
        and row.get("metric") in {"wall_time", "wall_seconds", "elapsed_seconds"}
        and not math.isnan(parse_float(row.get("value")))
    )
    candidate_primary_lower = sum(
        parse_float(row.get("value"))
        for row in candidate_rows
        if row.get("direction") == "lower"
        and row.get("metric") in {"wall_time", "wall_seconds", "elapsed_seconds"}
        and not math.isnan(parse_float(row.get("value")))
    )
    return {
        "baseline_wall_seconds_sum": baseline_wall,
        "candidate_wall_seconds_sum": candidate_wall,
        "wall_seconds_delta": candidate_wall - baseline_wall,
        "wall_seconds_delta_pct": (
            (candidate_wall / baseline_wall - 1.0) * 100.0 if baseline_wall else math.nan
        ),
        "baseline_primary_lower_wall_sum": baseline_primary_lower,
        "candidate_primary_lower_wall_sum": candidate_primary_lower,
        "primary_lower_wall_delta": candidate_primary_lower - baseline_primary_lower,
        "primary_lower_wall_delta_pct": (
            (candidate_primary_lower / baseline_primary_lower - 1.0) * 100.0
            if baseline_primary_lower
            else math.nan
        ),
    }


def compare_metric_rows(
    baseline_rows: list[dict[str, str]], candidate_rows: list[dict[str, str]]
) -> dict[str, Any]:
    baseline_rows = expand_goal_rows(baseline_rows)
    candidate_rows = expand_goal_rows(candidate_rows)
    baseline_by_key = {row_key(row): row for row in baseline_rows}
    candidate_by_key = {row_key(row): row for row in candidate_rows}
    common_keys = sorted(set(baseline_by_key).intersection(candidate_by_key))
    missing_in_candidate = sorted(set(baseline_by_key).difference(candidate_by_key))
    extra_in_candidate = sorted(set(candidate_by_key).difference(baseline_by_key))

    metric_rows: list[dict[str, Any]] = []
    bucket_ratios: dict[str, list[float]] = {}
    for key in common_keys:
        baseline = baseline_by_key[key]
        candidate = candidate_by_key[key]
        direction = baseline.get("direction", "")
        baseline_value = parse_float(baseline.get("value"))
        candidate_value = parse_float(candidate.get("value"))
        ratio = metric_ratio(baseline_value, candidate_value, direction)
        benchmark = goal_score_label(baseline)
        bucket_ratios.setdefault(benchmark, []).append(ratio)
        metric_rows.append(
            {
                "benchmark": benchmark,
                "metric": baseline.get("metric", ""),
                "direction": direction,
                "unit": baseline.get("unit", ""),
                "baseline": baseline_value,
                "candidate": candidate_value,
                "ratio": ratio,
                "delta_pct": (ratio - 1.0) * 100.0 if not math.isnan(ratio) else math.nan,
            }
        )

    benchmark_scores = {
        benchmark: {
            "score": geometric_mean(ratios),
            "delta_pct": (geometric_mean(ratios) - 1.0) * 100.0,
            "metric_count": len(ratios),
        }
        for benchmark, ratios in sorted(bucket_ratios.items())
    }
    equal_weight_score = geometric_mean(
        bucket["score"] for bucket in benchmark_scores.values()
    )
    return {
        "created_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "equal_weight_score": equal_weight_score,
        "equal_weight_delta_pct": (equal_weight_score - 1.0) * 100.0,
        "benchmark_scores": benchmark_scores,
        "metrics": metric_rows,
        "wallclock": summarize_wallclock(baseline_rows, candidate_rows),
        "coverage": {
            "baseline_rows": len(baseline_rows),
            "candidate_rows": len(candidate_rows),
            "common_rows": len(common_keys),
            "missing_in_candidate": ["|".join(key) for key in missing_in_candidate],
            "extra_in_candidate": ["|".join(key) for key in extra_in_candidate],
        },
    }


def validate_mutation_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    mutation = {
        "id": str(raw.get("id", "")).strip(),
        "size": str(raw.get("size", "")).strip(),
        "kind": str(raw.get("kind", "")).strip(),
        "subsystem": str(raw.get("subsystem", "")).strip(),
        "concepts": list(raw.get("concepts", [])),
        "decision": str(raw.get("decision", "")).strip(),
    }
    if mutation["size"] not in VALID_MUTATION_SIZES:
        raise ValueError(
            f"mutation size must be one of {sorted(VALID_MUTATION_SIZES)}"
        )
    if not mutation["id"]:
        raise ValueError("mutation id is required")
    if not mutation["kind"]:
        raise ValueError("mutation kind is required")
    if not mutation["subsystem"]:
        raise ValueError("mutation subsystem is required")
    if not mutation["concepts"]:
        raise ValueError("at least one mutation concept is required")
    if mutation["decision"] not in VALID_MUTATION_DECISIONS:
        raise ValueError(
            f"mutation decision must be one of {sorted(VALID_MUTATION_DECISIONS)}"
        )
    return mutation


def format_pct(value: float) -> str:
    if math.isnan(value):
        return "n/a"
    return f"{value:+.2f}%"


def render_markdown(report: dict[str, Any]) -> str:
    mutation = report.get("mutation", {})
    lines = [
        "# scx_cake Goal Score",
        "",
        f"- Created UTC: `{report.get('created_utc', '')}`",
        f"- Equal-weight score: `{report['equal_weight_score']:.6f}` ({format_pct(report['equal_weight_delta_pct'])})",
    ]
    if mutation:
        lines.extend(
            [
                f"- Mutation: `{mutation.get('id', '')}`",
                f"- Mutation kind/size: `{mutation.get('kind', '')}` / `{mutation.get('size', '')}`",
                f"- Mutation subsystem: `{mutation.get('subsystem', '')}`",
                f"- Mutation concepts: `{', '.join(mutation.get('concepts', []))}`",
                f"- Decision: `{mutation.get('decision', '')}`",
            ]
        )
    wall = report["wallclock"]
    lines.extend(
        [
            "",
            "## Wallclock",
            "",
            "| Field | Baseline | Candidate | Delta |",
            "|---|---:|---:|---:|",
            f"| summed wall_seconds | {wall['baseline_wall_seconds_sum']:.6f} | {wall['candidate_wall_seconds_sum']:.6f} | {format_pct(wall['wall_seconds_delta_pct'])} |",
            f"| primary lower wall rows | {wall['baseline_primary_lower_wall_sum']:.6f} | {wall['candidate_primary_lower_wall_sum']:.6f} | {format_pct(wall['primary_lower_wall_delta_pct'])} |",
            "",
            "## Equal-Weight Benchmark Buckets",
            "",
            "| Benchmark | Score | Delta | Metrics |",
            "|---|---:|---:|---:|",
        ]
    )
    for benchmark, bucket in report["benchmark_scores"].items():
        lines.append(
            f"| `{benchmark}` | {bucket['score']:.6f} | {format_pct(bucket['delta_pct'])} | {bucket['metric_count']} |"
        )
    return "\n".join(lines) + "\n"


def append_ledger(path: Path | str, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "created_utc": report.get("created_utc", ""),
        "mutation": report.get("mutation", {}),
        "decision": report.get("mutation", {}).get("decision", ""),
        "equal_weight_score": report.get("equal_weight_score", math.nan),
        "equal_weight_delta_pct": report.get("equal_weight_delta_pct", math.nan),
        "wallclock": report.get("wallclock", {}),
        "benchmark_scores": report.get("benchmark_scores", {}),
        "coverage": report.get("coverage", {}),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Cake runs with equal benchmark weighting.")
    parser.add_argument("--baseline", required=True, help="baseline analysis_metrics.tsv or directory")
    parser.add_argument("--candidate", required=True, help="candidate analysis_metrics.tsv or directory")
    parser.add_argument("--out-json", help="write JSON report")
    parser.add_argument("--out-md", help="write Markdown report")
    parser.add_argument("--append-ledger", help="append compact mutation score JSONL")
    parser.add_argument("--mutation-id", default="")
    parser.add_argument("--mutation-size", default="")
    parser.add_argument("--mutation-kind", default="")
    parser.add_argument("--mutation-subsystem", default="")
    parser.add_argument("--mutation-concept", action="append", default=[])
    parser.add_argument("--decision", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    report = compare_metric_rows(read_goal_rows(args.baseline), read_goal_rows(args.candidate))
    if args.mutation_id or args.mutation_size or args.mutation_kind or args.mutation_subsystem or args.mutation_concept:
        report["mutation"] = validate_mutation_metadata(
            {
                "id": args.mutation_id,
                "size": args.mutation_size,
                "kind": args.mutation_kind,
                "subsystem": args.mutation_subsystem,
                "concepts": args.mutation_concept,
                "decision": args.decision,
            }
        )
    if args.out_json:
        path = Path(args.out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = render_markdown(report)
    if args.out_md:
        path = Path(args.out_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
    if args.append_ledger:
        if "mutation" not in report:
            raise ValueError("--append-ledger requires mutation metadata")
        append_ledger(args.append_ledger, report)
    if not args.out_json and not args.out_md:
        print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
