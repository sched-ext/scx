#!/usr/bin/env python3
"""Reduced-state HELIOS-style service-readiness oracle for scx_cake.

The oracle is intentionally conservative. It does not try to prove a permanent
policy from a single run. It converts bounded state/outcome samples into a
candidate 256-entry action table so the release-gated experiment can be built,
audited, and benchmarked with provenance.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SERVICE_CLASSES = {
    "none": 0,
    "futex": 1,
    "pipe": 2,
    "messaging": 3,
    "kthread": 4,
    "cache": 5,
    "bulk": 6,
    "other": 7,
}

TARGET_STATUSES = {
    "idle": 0,
    "busy": 1,
    "local_busy": 2,
    "remote_busy": 3,
}

OWNER_CLASSES = {
    "none": 0,
    "default": 1,
    "bulk": 2,
    "cache_hot": 3,
}

ACTIONS = {
    "local_insert": "CAKE_READY_ACT_LOCAL_INSERT",
    "idle_kick": "CAKE_READY_ACT_IDLE_KICK",
    "preempt_kick": "CAKE_READY_ACT_PREEMPT_KICK",
    "keep_owner": "CAKE_READY_ACT_KEEP_OWNER",
    "throughput_lane": "CAKE_READY_ACT_THROUGHPUT_LANE",
    "shared_escape": "CAKE_READY_ACT_SHARED_ESCAPE",
    "core_steal_probe": "CAKE_READY_ACT_CORE_STEAL_PROBE",
}

ACTION_ORDER = tuple(ACTIONS)
PROMOTE_ACTIONS = {"local_insert", "idle_kick", "preempt_kick"}
AGGRESSIVE_ACTIONS = {"preempt_kick", "idle_kick"}
CONSERVATIVE_ACTIONS = {"keep_owner", "throughput_lane", "shared_escape"}
WAKE_SENSITIVE_SERVICES = {"futex", "pipe", "messaging", "kthread"}
GUARDRAIL_SERVICES = {"cache", "bulk"}

CAKE_SERVICE_READINESS_TABLE_SIZE = 256
cache_memcpy_regression_penalty = 12.0
migration_or_preempt_penalty = 2.0
action_cost_penalty = 0.25


@dataclass(frozen=True)
class Sample:
    service_class: str
    target_status: str
    owner_class: str
    fairness_due: bool
    observed_action: str
    outcome_bucket: str
    weight: float
    source: str

    @property
    def index(self) -> int:
        return table_index(
            self.service_class,
            self.target_status,
            self.owner_class,
            self.fairness_due,
        )


def table_index(
    service_class: str, target_status: str, owner_class: str, fairness_due: bool
) -> int:
    return (
        SERVICE_CLASSES[service_class]
        | (TARGET_STATUSES[target_status] << 3)
        | (OWNER_CLASSES[owner_class] << 5)
        | ((1 if fairness_due else 0) << 7)
    )


def state_from_index(index: int) -> tuple[str, str, str, bool]:
    service_value = index & 0x7
    target_value = (index >> 3) & 0x3
    owner_value = (index >> 5) & 0x3
    fairness_due = bool((index >> 7) & 0x1)
    service = next(k for k, v in SERVICE_CLASSES.items() if v == service_value)
    target = next(k for k, v in TARGET_STATUSES.items() if v == target_value)
    owner = next(k for k, v in OWNER_CLASSES.items() if v == owner_value)
    return service, target, owner, fairness_due


def validate_name(kind: str, value: str, allowed: dict[str, object]) -> str:
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise ValueError(f"unknown {kind} {value!r}; expected one of {allowed_values}")
    return value


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "due"}:
            return True
        if lowered in {"0", "false", "no", "n", "clear"}:
            return False
    raise ValueError(f"cannot parse boolean from {value!r}")


def parse_sample(record: dict[str, object], line_no: int) -> Sample:
    try:
        service_class = validate_name(
            "service_class",
            str(record.get("service_class", "other")),
            SERVICE_CLASSES,
        )
        target_status = validate_name(
            "target_status",
            str(record.get("target_status", "busy")),
            TARGET_STATUSES,
        )
        owner_class = validate_name(
            "owner_class",
            str(record.get("owner_class", "default")),
            OWNER_CLASSES,
        )
        fairness_due = parse_bool(record.get("fairness_due", False))
        observed_action = validate_name(
            "action",
            str(record.get("action", record.get("observed_action", "keep_owner"))),
            ACTIONS,
        )
        outcome_bucket = str(record.get("outcome_bucket", "unknown"))
        weight = float(record.get("weight", 1.0))
        if weight <= 0:
            raise ValueError("weight must be positive")
    except (TypeError, ValueError) as err:
        raise ValueError(f"line {line_no}: {err}") from err

    return Sample(
        service_class=service_class,
        target_status=target_status,
        owner_class=owner_class,
        fairness_due=fairness_due,
        observed_action=observed_action,
        outcome_bucket=outcome_bucket,
        weight=weight,
        source=str(record.get("source", f"line:{line_no}")),
    )


def load_samples(path: Path) -> list[Sample]:
    samples: list[Sample] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as err:
                raise ValueError(f"line {line_no}: invalid JSON: {err}") from err
            if not isinstance(record, dict):
                raise ValueError(f"line {line_no}: expected JSON object")
            samples.append(parse_sample(record, line_no))
    return samples


def default_samples() -> list[dict[str, object]]:
    """Conservative seed samples for smoke testing the oracle wiring."""

    return [
        {
            "service_class": "futex",
            "target_status": "idle",
            "owner_class": "default",
            "fairness_due": False,
            "action": "idle_kick",
            "outcome_bucket": "lt100us",
            "weight": 4,
            "source": "default:wake_idle",
        },
        {
            "service_class": "pipe",
            "target_status": "remote_busy",
            "owner_class": "default",
            "fairness_due": False,
            "action": "preempt_kick",
            "outcome_bucket": "lt100us",
            "weight": 3,
            "source": "default:pipe_remote_busy",
        },
        {
            "service_class": "cache",
            "target_status": "busy",
            "owner_class": "cache_hot",
            "fairness_due": False,
            "action": "preempt_kick",
            "outcome_bucket": "ge1ms",
            "weight": 5,
            "source": "default:cache_guardrail",
        },
        {
            "service_class": "bulk",
            "target_status": "busy",
            "owner_class": "bulk",
            "fairness_due": True,
            "action": "preempt_kick",
            "outcome_bucket": "ge1ms",
            "weight": 5,
            "source": "default:bulk_fairness_guardrail",
        },
    ]


def base_policy(service: str, target: str, owner: str, fairness_due: bool) -> str:
    if fairness_due:
        return "keep_owner"
    if service in GUARDRAIL_SERVICES or owner in {"bulk", "cache_hot"}:
        return "throughput_lane"
    if target == "idle":
        return "idle_kick" if service in WAKE_SENSITIVE_SERVICES else "local_insert"
    if service in WAKE_SENSITIVE_SERVICES and target in {"busy", "remote_busy"}:
        return "preempt_kick"
    if target == "local_busy":
        return "local_insert"
    return "keep_owner"


def observed_action_bonus(candidate: str, sample: Sample) -> float:
    if candidate != sample.observed_action:
        return 0.0
    if sample.outcome_bucket in {"lt10us", "lt100us", "under_100us"}:
        return 1.5 * sample.weight
    if sample.outcome_bucket in {"lt1ms", "under_1ms"}:
        return 0.5 * sample.weight
    if sample.outcome_bucket in {"ge1ms", "over_1ms", "slow"}:
        return -1.0 * sample.weight
    return 0.1 * sample.weight


def score_action_for_state(
    candidate: str, service: str, target: str, owner: str, fairness_due: bool
) -> float:
    score = 0.0
    if candidate == base_policy(service, target, owner, fairness_due):
        score += 3.0

    if service in WAKE_SENSITIVE_SERVICES:
        if target == "idle" and candidate == "idle_kick":
            score += 4.0
        if target in {"busy", "remote_busy"} and candidate == "preempt_kick":
            score += 3.0
        if candidate in CONSERVATIVE_ACTIONS and target != "idle":
            score -= 1.0

    if service in GUARDRAIL_SERVICES:
        if candidate in AGGRESSIVE_ACTIONS:
            score -= cache_memcpy_regression_penalty
        if candidate == "throughput_lane":
            score += 5.0

    if owner in {"bulk", "cache_hot"}:
        if candidate in AGGRESSIVE_ACTIONS:
            score -= cache_memcpy_regression_penalty * 0.75
        if candidate == "throughput_lane":
            score += 3.0

    if fairness_due:
        if candidate in PROMOTE_ACTIONS:
            score -= 6.0
        if candidate in CONSERVATIVE_ACTIONS:
            score += 4.0

    if candidate == "preempt_kick":
        score -= migration_or_preempt_penalty
    if candidate in {"core_steal_probe", "shared_escape"}:
        score -= action_cost_penalty + 1.0
    else:
        score -= action_cost_penalty

    return score


def score_action(candidate: str, samples: Iterable[Sample], index: int) -> float:
    service, target, owner, fairness_due = state_from_index(index)
    score = score_action_for_state(candidate, service, target, owner, fairness_due)
    for sample in samples:
        if sample.index != index:
            continue
        score += observed_action_bonus(candidate, sample)
        if sample.service_class in GUARDRAIL_SERVICES and candidate in AGGRESSIVE_ACTIONS:
            score -= cache_memcpy_regression_penalty * sample.weight
        if sample.fairness_due and candidate in PROMOTE_ACTIONS:
            score -= 3.0 * sample.weight
        if sample.outcome_bucket in {"ge1ms", "over_1ms", "slow"}:
            if candidate == sample.observed_action and candidate in AGGRESSIVE_ACTIONS:
                score -= 2.0 * sample.weight
            if candidate in CONSERVATIVE_ACTIONS and sample.service_class in GUARDRAIL_SERVICES:
                score += 1.0 * sample.weight
    return score


def choose_table(samples: list[Sample]) -> tuple[list[str], list[dict[str, object]]]:
    table: list[str] = []
    rows: list[dict[str, object]] = []
    for index in range(CAKE_SERVICE_READINESS_TABLE_SIZE):
        scores = {action: score_action(action, samples, index) for action in ACTION_ORDER}
        chosen = max(ACTION_ORDER, key=lambda action: (scores[action], -ACTION_ORDER.index(action)))
        service, target, owner, fairness_due = state_from_index(index)
        table.append(chosen)
        rows.append(
            {
                "index": index,
                "service_class": service,
                "target_status": target,
                "owner_class": owner,
                "fairness_due": fairness_due,
                "action": chosen,
                "score": scores[chosen],
                "all_scores": scores,
                "sample_count": sum(1 for sample in samples if sample.index == index),
            }
        )
    return table, rows


def render_header(table: list[str], rows: list[dict[str, object]]) -> str:
    lines = [
        "/* SPDX-License-Identifier: GPL-2.0 */",
        "/* Generated by tools/service_readiness_oracle.py.",
        " * Experimental HELIOS-style service-readiness action table.",
        " * Keep behind SCX_CAKE_SERVICE_READINESS until benchmark proof exists.",
        " */",
        "#ifndef SCX_CAKE_SERVICE_READINESS_TABLE_H",
        "#define SCX_CAKE_SERVICE_READINESS_TABLE_H",
        "",
        "#define CAKE_SERVICE_READINESS_TABLE_SIZE 256",
        "",
        "static const u8 cake_service_readiness_action_table[256] = {",
    ]
    for action, row in zip(table, rows):
        fairness = 1 if row["fairness_due"] else 0
        lines.append(
            "        /* [{index:03d}] svc={service_class} target={target_status} "
            "owner={owner_class} fair={fairness} samples={sample_count} */ {symbol},"
            .format(symbol=ACTIONS[action], fairness=fairness, **row)
        )
    lines.extend(
        [
            "};",
            "",
            "static __always_inline u8 cake_service_readiness_table_action(u8 idx)",
            "{",
            "        return cake_service_readiness_action_table[idx & 0xff];",
            "}",
            "",
            "#endif /* SCX_CAKE_SERVICE_READINESS_TABLE_H */",
            "",
        ]
    )
    return "\n".join(lines)


def action_histogram(table: list[str]) -> dict[str, int]:
    hist = {action: 0 for action in ACTION_ORDER}
    for action in table:
        hist[action] += 1
    return hist


def render_explanation(samples: list[Sample], rows: list[dict[str, object]]) -> str:
    table = [str(row["action"]) for row in rows]
    hist = action_histogram(table)
    sampled_rows = [row for row in rows if int(row["sample_count"]) > 0]
    lines = [
        "# Service-Readiness Oracle Output",
        "",
        "This file explains the reduced-state oracle table generated for the",
        "HELIOS-style `scx_cake` service-readiness experiment.",
        "",
        "## Objective",
        "",
        "The objective is conservative and additive per table index:",
        "",
        "```text",
        "score = futex_pipe_schbench_tail_improvement",
        "      - cache_memcpy_regression_penalty",
        "      - action_cost_penalty",
        "      - migration_or_preempt_penalty",
        "```",
        "",
        "Guardrail penalties are intentionally large so the table does not simply",
        "preempt every urgent wake.",
        "",
        "## Inputs",
        "",
        f"- samples: {len(samples)}",
        f"- sampled table indexes: {len(sampled_rows)}",
        "- state tuple: service_class,target_status,owner_class,fairness_due",
        "",
        "## Action histogram",
        "",
    ]
    for action, count in hist.items():
        lines.append(f"- {action}: {count}")
    lines.extend(
        [
            "",
            "## Guardrail penalties",
            "",
            f"- cache_memcpy_regression_penalty: {cache_memcpy_regression_penalty}",
            f"- migration_or_preempt_penalty: {migration_or_preempt_penalty}",
            f"- action_cost_penalty: {action_cost_penalty}",
            "",
            "## Sampled rows",
            "",
        ]
    )
    if not sampled_rows:
        lines.append("- none")
    else:
        for row in sampled_rows:
            lines.append(
                "- [{index:03d}] service={service_class} target={target_status} "
                "owner={owner_class} fair={fairness_due} action={action} "
                "score={score:.2f} samples={sample_count}".format(**row)
            )
    lines.extend(
        [
            "",
            "## action table stability",
            "",
            "Treat this table as stable only after at least two targeted debug runs",
            "produce compatible sampled-row actions and guardrail penalties remain",
            "dominant for cache/memcpy/bulk states. If the sampled rows flip between",
            "preempt and guardrail actions, stop before release integration.",
            "",
        ]
    )
    return "\n".join(lines)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a bounded 256-entry scx_cake service-readiness action "
            "table from reduced-state JSONL samples."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="JSONL samples with service_class,target_status,owner_class,fairness_due,action,outcome_bucket",
    )
    parser.add_argument("--out", type=Path, help="Output C header path")
    parser.add_argument(
        "--explain",
        type=Path,
        help="Optional markdown explanation path for the generated table",
    )
    parser.add_argument(
        "--emit-default-samples",
        action="store_true",
        help="Print conservative JSONL smoke-test samples to stdout and exit unless --out is also supplied",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.emit_default_samples and not args.out:
        for record in default_samples():
            print(json.dumps(record, sort_keys=True))
        return 0

    if args.input:
        try:
            samples = load_samples(args.input)
        except (OSError, ValueError) as err:
            print(f"service_readiness_oracle: {err}", file=sys.stderr)
            return 2
    else:
        samples = [parse_sample(record, i + 1) for i, record in enumerate(default_samples())]

    table, rows = choose_table(samples)

    if args.out:
        write_text(args.out, render_header(table, rows))
    else:
        print(render_header(table, rows))

    if args.explain:
        write_text(args.explain, render_explanation(samples, rows))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
