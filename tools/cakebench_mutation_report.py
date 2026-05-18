#!/usr/bin/env python3
"""Summarize scx_cake mutation ledger patterns.

The goal ledger is intentionally experiment-shaped rather than only
scoreboard-shaped. This helper turns it into a compact view of which mutation
styles, subsystems, and concepts are producing reliable full-suite wins versus
noisy single-benchmark or reverted results.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


FULL_SUITE_MIN_COMMON_ROWS = 14


def parse_float(value: Any, default: float = math.nan) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def read_ledger(path: Path | str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            record["_lineno"] = lineno
            records.append(record)
    return records


def normalize_tokens(values: Iterable[Any]) -> list[str]:
    tokens: list[str] = []
    for value in values:
        if value is None:
            continue
        if not isinstance(value, str):
            value = str(value)
        for token in value.split(","):
            token = token.strip()
            if token:
                tokens.append(token)
    return tokens


def mutation_field(record: dict[str, Any], field: str) -> str:
    mutation = record.get("mutation", {})
    value = mutation.get(field, "") if isinstance(mutation, dict) else ""
    return str(value).strip()


def mutation_concepts(record: dict[str, Any]) -> list[str]:
    mutation = record.get("mutation", {})
    raw = mutation.get("concepts", []) if isinstance(mutation, dict) else []
    if isinstance(raw, list):
        return normalize_tokens(raw)
    return normalize_tokens([raw])


def record_delta(record: dict[str, Any]) -> float:
    return parse_float(record.get("equal_weight_delta_pct"))


def wall_delta(record: dict[str, Any], key: str = "primary_lower_wall_delta_pct") -> float:
    wall = record.get("wallclock", {})
    if not isinstance(wall, dict):
        return math.nan
    return parse_float(wall.get(key))


def coverage_common_rows(record: dict[str, Any]) -> int:
    coverage = record.get("coverage", {})
    if not isinstance(coverage, dict):
        return 0
    try:
        return int(coverage.get("common_rows", 0) or 0)
    except (TypeError, ValueError):
        return 0


def has_benchmark_data(record: dict[str, Any]) -> bool:
    return coverage_common_rows(record) > 0


def is_full_suite(record: dict[str, Any]) -> bool:
    coverage = record.get("coverage", {})
    if not isinstance(coverage, dict):
        return False
    missing = coverage.get("missing_in_candidate", [])
    return coverage_common_rows(record) >= FULL_SUITE_MIN_COMMON_ROWS and not missing


def is_positive_full_keep(record: dict[str, Any]) -> bool:
    return is_positive_full_keep_active(record, None)


def mutation_family(record: dict[str, Any]) -> str:
    mutation_id = mutation_field(record, "id")
    match = re.match(r"^(s\d+)", mutation_id)
    return match.group(1) if match else mutation_id


def latest_decision_by_family(records: list[dict[str, Any]]) -> dict[str, str]:
    latest: dict[str, str] = {}
    for record in records:
        family = mutation_family(record)
        if family:
            latest[family] = str(record.get("decision") or mutation_field(record, "decision"))
    return latest


def is_positive_full_keep_active(
    record: dict[str, Any], latest_decisions: dict[str, str] | None
) -> bool:
    decision = str(record.get("decision") or mutation_field(record, "decision"))
    if latest_decisions is not None:
        family = mutation_family(record)
        if latest_decisions.get(family, decision) == "revert":
            return False
    primary_wall = wall_delta(record, "primary_lower_wall_delta_pct")
    summed_wall = wall_delta(record, "wall_seconds_delta_pct")
    neutral_wall = (
        math.isnan(primary_wall)
        or primary_wall <= 0.25
        or (not math.isnan(summed_wall) and summed_wall <= 0.25)
    )
    return (
        decision == "keep"
        and is_full_suite(record)
        and record_delta(record) > 0.0
        and neutral_wall
    )


def add_group(groups: dict[str, list[dict[str, Any]]], prefix: str, key: str, record: dict[str, Any]) -> None:
    if key:
        groups[f"{prefix}:{key}"].append(record)


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    latest_decisions = latest_decision_by_family(records)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        add_group(groups, "kind", mutation_field(record, "kind"), record)
        add_group(groups, "size", mutation_field(record, "size"), record)
        add_group(groups, "subsystem", mutation_field(record, "subsystem"), record)
        for concept in mutation_concepts(record):
            add_group(groups, "concept", concept, record)

    return {
        "created_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "total_records": len(records),
        "benchmark_records": sum(1 for record in records if has_benchmark_data(record)),
        "full_suite_records": sum(1 for record in records if is_full_suite(record)),
        "historical_positive_full_keep_records": sum(
            1 for record in records if is_positive_full_keep(record)
        ),
        "positive_full_keep_records": sum(
            1 for record in records if is_positive_full_keep_active(record, latest_decisions)
        ),
        "latest_decisions_by_family": latest_decisions,
        "decisions": Counter(str(record.get("decision") or mutation_field(record, "decision")) for record in records),
        "groups": {
            name: summarize_group(name, members, latest_decisions)
            for name, members in sorted(groups.items())
        },
        "historical_positive_full_keeps": [
            brief_record(record) for record in records if is_positive_full_keep(record)
        ],
        "positive_full_keeps": [
            brief_record(record)
            for record in records
            if is_positive_full_keep_active(record, latest_decisions)
        ],
        "recent_records": [brief_record(record) for record in records[-10:]],
    }


def summarize_group(
    name: str, records: list[dict[str, Any]], latest_decisions: dict[str, str] | None = None
) -> dict[str, Any]:
    deltas = [record_delta(record) for record in records if not math.isnan(record_delta(record))]
    bench_records = [record for record in records if has_benchmark_data(record)]
    full_records = [record for record in records if is_full_suite(record)]
    historical_positive = [record for record in records if is_positive_full_keep(record)]
    positive = [
        record for record in records if is_positive_full_keep_active(record, latest_decisions)
    ]
    decisions = Counter(str(record.get("decision") or mutation_field(record, "decision")) for record in records)
    scored_deltas = [record_delta(record) for record in bench_records if not math.isnan(record_delta(record))]
    full_deltas = [record_delta(record) for record in full_records if not math.isnan(record_delta(record))]
    rank_records, rank_scope = representative_rank_records(records, bench_records, full_records)
    return {
        "name": name,
        "records": len(records),
        "benchmark_records": len(bench_records),
        "full_suite_records": len(full_records),
        "historical_positive_full_keep_records": len(historical_positive),
        "positive_full_keep_records": len(positive),
        "decisions": dict(sorted(decisions.items())),
        "avg_delta_pct": mean(deltas),
        "avg_scored_delta_pct": mean(scored_deltas),
        "avg_full_suite_delta_pct": mean(full_deltas),
        "representative_rank_scope": rank_scope,
        "best": brief_record(max(rank_records, key=lambda record: safe_sort_delta(record))),
        "worst": brief_record(min(rank_records, key=lambda record: safe_sort_delta(record))),
    }


def representative_rank_records(
    records: list[dict[str, Any]],
    bench_records: list[dict[str, Any]] | None = None,
    full_records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Choose records for best/worst examples without letting singles dominate.

    Mutation groups can contain full-suite decisions, targeted single-benchmark
    probes, and static-only notes. A single noisy probe with a huge delta is
    useful history, but it should not be the headline "Best" example for a
    style when full-suite evidence exists. Prefer the broadest scored evidence
    available and only fall back to narrower records when the group has no
    full-suite rows.
    """

    if full_records is None:
        full_records = [record for record in records if is_full_suite(record)]
    if full_records:
        return full_records, "full-suite"

    if bench_records is None:
        bench_records = [record for record in records if has_benchmark_data(record)]
    if bench_records:
        return bench_records, "benchmark"

    return records, "all"


def safe_sort_delta(record: dict[str, Any]) -> float:
    delta = record_delta(record)
    return delta if not math.isnan(delta) else float("-inf")


def mean(values: list[float]) -> float:
    clean = [value for value in values if not math.isnan(value)]
    if not clean:
        return math.nan
    return sum(clean) / len(clean)


def brief_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": mutation_field(record, "id"),
        "decision": str(record.get("decision") or mutation_field(record, "decision")),
        "kind": mutation_field(record, "kind"),
        "size": mutation_field(record, "size"),
        "subsystem": mutation_field(record, "subsystem"),
        "concepts": mutation_concepts(record),
        "equal_weight_delta_pct": record_delta(record),
        "coverage_common_rows": coverage_common_rows(record),
        "full_suite": is_full_suite(record),
        "primary_lower_wall_delta_pct": wall_delta(record, "primary_lower_wall_delta_pct"),
    }


def format_pct(value: float) -> str:
    if math.isnan(value):
        return "n/a"
    return f"{value:+.2f}%"


def render_markdown(summary: dict[str, Any], *, top: int = 20) -> str:
    groups = list(summary["groups"].values())
    ranked = sorted(
        groups,
        key=lambda group: (
            group["positive_full_keep_records"],
            group["full_suite_records"],
            group["avg_full_suite_delta_pct"]
            if not math.isnan(group["avg_full_suite_delta_pct"])
            else -999.0,
        ),
        reverse=True,
    )
    lines = [
        "# scx_cake Mutation Style Summary",
        "",
        f"- Created UTC: `{summary['created_utc']}`",
        f"- Total records: `{summary['total_records']}`",
        f"- Benchmark-backed records: `{summary['benchmark_records']}`",
        f"- Full-suite records: `{summary['full_suite_records']}`",
        f"- Active positive full-suite keeps: `{summary['positive_full_keep_records']}`",
        f"- Historical positive full-suite keeps: `{summary['historical_positive_full_keep_records']}`",
        f"- Decisions: `{dict(summary['decisions'])}`",
        "",
        "## Ranked Style / Concept Groups",
        "",
        "| Group | Records | Full | Active positive keeps | Avg full delta | Best | Worst |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    for group in ranked[:top]:
        best = group["best"]
        worst = group["worst"]
        lines.append(
            f"| `{group['name']}` | {group['records']} | {group['full_suite_records']} | "
            f"{group['positive_full_keep_records']} | {format_pct(group['avg_full_suite_delta_pct'])} | "
            f"`{best['id']}` {format_pct(best['equal_weight_delta_pct'])} | "
            f"`{worst['id']}` {format_pct(worst['equal_weight_delta_pct'])} |"
        )

    lines.extend(["", "## Active Positive Full-Suite Keeps", ""])
    if summary["positive_full_keeps"]:
        lines.extend(["| Mutation | Kind | Subsystem | Delta | Wall | Concepts |", "|---|---|---|---:|---:|---|"])
        for record in summary["positive_full_keeps"]:
            lines.append(
                f"| `{record['id']}` | `{record['kind']}` | `{record['subsystem']}` | "
                f"{format_pct(record['equal_weight_delta_pct'])} | "
                f"{format_pct(record['primary_lower_wall_delta_pct'])} | "
                f"{', '.join(record['concepts'])} |"
            )
    else:
        lines.append("No active positive full-suite keeps meet the wallclock gate yet.")

    if summary["historical_positive_full_keeps"]:
        latest = summary.get("latest_decisions_by_family", {})
        lines.extend(["", "## Historical Positive Full-Suite Keeps", ""])
        lines.extend(["| Mutation | Latest family decision | Delta | Wall | Concepts |", "|---|---|---:|---:|---|"])
        for record in summary["historical_positive_full_keeps"]:
            family = record["id"].split("_", 1)[0]
            lines.append(
                f"| `{record['id']}` | `{latest.get(family, '')}` | "
                f"{format_pct(record['equal_weight_delta_pct'])} | "
                f"{format_pct(record['primary_lower_wall_delta_pct'])} | "
                f"{', '.join(record['concepts'])} |"
            )

    lines.extend(["", "## Recent Records", ""])
    lines.extend(["| Mutation | Decision | Coverage | Delta | Concepts |", "|---|---|---:|---:|---|"])
    for record in summary["recent_records"]:
        lines.append(
            f"| `{record['id']}` | `{record['decision']}` | {record['coverage_common_rows']} | "
            f"{format_pct(record['equal_weight_delta_pct'])} | {', '.join(record['concepts'])} |"
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize scx_cake mutation ledger patterns.")
    parser.add_argument(
        "--ledger",
        default="docs/goal_scores/mutation_ledger.jsonl",
        help="mutation ledger JSONL path",
    )
    parser.add_argument("--out-json", help="write JSON summary")
    parser.add_argument("--out-md", help="write Markdown summary")
    parser.add_argument("--top", type=int, default=20, help="number of groups in Markdown table")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    summary = summarize_records(read_ledger(args.ledger))
    if args.out_json:
        path = Path(args.out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = render_markdown(summary, top=args.top)
    if args.out_md:
        path = Path(args.out_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
    if not args.out_json and not args.out_md:
        print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
