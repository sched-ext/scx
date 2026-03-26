#!/usr/bin/env python3
"""Render comparison charts from tagged Mini Benchmarker logs."""

from __future__ import annotations

import argparse
import csv
import re
import statistics
from pathlib import Path

import matplotlib.pyplot as plt

TEST_ORDER = [
    "stress-ng cpu-cache-mem",
    "y-cruncher pi 1b",
    "perf sched msg fork thread",
    "perf memcpy",
    "namd 92K atoms",
    "calculating prime numbers",
    "argon2 hashing",
    "ffmpeg compilation",
    "xz compression",
    "kernel defconfig",
    "blender render",
    "x265 encoding",
    "Total time (s)",
    "Total score",
]

TEST_PATTERN = re.compile(
    r"^(stress-ng cpu-cache-mem|y-cruncher pi 1b|perf sched msg fork thread|"
    r"perf memcpy|namd 92K atoms|calculating prime numbers|argon2 hashing|"
    r"ffmpeg compilation|xz compression|kernel defconfig|blender render|"
    r"x265 encoding|Total time \(s\)|Total score):\s+([0-9]+\.[0-9]+)$",
    re.MULTILINE,
)
KERNEL_PATTERN = re.compile(r"Kernel:\s+(\S+)")
LABEL_PATTERN = re.compile(r"^Benchmark label:[ \t]*(.*)$", re.MULTILINE)
POWER_PROFILE_PATTERN = re.compile(r"^Power profile:[ \t]*(.*)$", re.MULTILINE)
SCHEDULER_VERSION_PATTERN = re.compile(r"^Scheduler version:[ \t]*(.*)$", re.MULTILINE)
SCHEDULER_STATUS_PATTERN = re.compile(r"^Scheduler status:[ \t]*(.*)$", re.MULTILINE)
SCHEDULER_ISSUE_PATTERN = re.compile(r"^Scheduler issue:[ \t]*(.*)$", re.MULTILINE)
SCHEDULER_METRICS_PATTERN = re.compile(r"^Scheduler metrics:[ \t]*(.*)$", re.MULTILINE)
ANSI_PATTERN = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
BACKSPACE_PATTERN = re.compile(r".\x08")


def sanitize_text(text: str) -> str:
    while True:
        cleaned = BACKSPACE_PATTERN.sub("", text)
        if cleaned == text:
            break
        text = cleaned
    return ANSI_PATTERN.sub("", text).replace("\x08", "").replace("\r", "")


def parse_log(path: Path) -> tuple[str, str | None, str | None, str, str | None, str | None, dict[str, float]]:
    text = sanitize_text(path.read_text(encoding="utf-8", errors="replace"))
    label_match = LABEL_PATTERN.search(text)
    if label_match:
        label = label_match.group(1).strip()
    else:
        kernel_match = KERNEL_PATTERN.search(text)
        if not kernel_match:
            raise ValueError(f"Could not find Kernel: line in {path}")
        label = kernel_match.group(1)

    power_profile_match = POWER_PROFILE_PATTERN.search(text)
    power_profile = None
    if power_profile_match:
        parsed = power_profile_match.group(1).strip()
        if parsed and parsed.lower() != "unknown":
            power_profile = parsed

    scheduler_version_match = SCHEDULER_VERSION_PATTERN.search(text)
    scheduler_version = None
    if scheduler_version_match:
        parsed = scheduler_version_match.group(1).strip()
        if parsed:
            scheduler_version = parsed

    scheduler_status_match = SCHEDULER_STATUS_PATTERN.search(text)
    scheduler_status = "unknown"
    if scheduler_status_match:
        parsed = scheduler_status_match.group(1).strip()
        if parsed:
            scheduler_status = parsed

    scheduler_issue_match = SCHEDULER_ISSUE_PATTERN.search(text)
    scheduler_issue = None
    if scheduler_issue_match:
        parsed = scheduler_issue_match.group(1).strip()
        if parsed:
            scheduler_issue = parsed

    scheduler_metrics_match = SCHEDULER_METRICS_PATTERN.search(text)
    scheduler_metrics = None
    if scheduler_metrics_match:
        parsed = scheduler_metrics_match.group(1).strip()
        if parsed:
            scheduler_metrics = parsed

    values: dict[str, float] = {}
    for test_name, value in TEST_PATTERN.findall(text):
        values[test_name] = float(value)

    if not values:
        raise ValueError(f"{path} does not contain any benchmark values")

    return (
        label,
        power_profile,
        scheduler_version,
        scheduler_status,
        scheduler_issue,
        scheduler_metrics,
        values,
    )


def aggregate_logs(log_dir: Path) -> tuple[
    list[str],
    list[str],
    dict[str, dict[str, float]],
    dict[str, int],
    dict[str, str | None],
    dict[str, str | None],
    dict[str, str],
    dict[str, str | None],
    dict[str, str | None],
]:
    ordered_tests = list(TEST_ORDER)
    grouped: dict[str, dict[str, list[float]]] = {}
    run_counts: dict[str, int] = {}
    power_profiles: dict[str, str | None] = {}
    scheduler_versions: dict[str, str | None] = {}
    scheduler_statuses: dict[str, str] = {}
    scheduler_issues: dict[str, str | None] = {}
    scheduler_metrics: dict[str, str | None] = {}

    for path in sorted(log_dir.glob("*.log")):
        (
            label,
            power_profile,
            scheduler_version,
            scheduler_status,
            scheduler_issue,
            scheduler_metric,
            values,
        ) = parse_log(path)
        ordered_tests = [name for name in ordered_tests if name in values]
        if label not in grouped:
            grouped[label] = {name: [] for name in ordered_tests}
            run_counts[label] = 0
            power_profiles[label] = power_profile
            scheduler_versions[label] = scheduler_version
            scheduler_statuses[label] = scheduler_status
            scheduler_issues[label] = scheduler_issue
            scheduler_metrics[label] = scheduler_metric
        run_counts[label] += 1
        for test_name in ordered_tests:
            grouped[label][test_name].append(values[test_name])

    if not grouped:
        raise ValueError(f"No .log files found in {log_dir}")
    if not ordered_tests:
        raise ValueError(f"No shared benchmark values found in {log_dir}")

    labels = list(grouped.keys())
    averages = {
        label: {
            test_name: statistics.fmean(samples)
            for test_name, samples in grouped[label].items()
        }
        for label in labels
    }
    return (
        ordered_tests,
        labels,
        averages,
        run_counts,
        power_profiles,
        scheduler_versions,
        scheduler_statuses,
        scheduler_issues,
        scheduler_metrics,
    )


def write_csv(
    out_dir: Path,
    tests: list[str],
    labels: list[str],
    averages: dict[str, dict[str, float]],
    run_counts: dict[str, int],
    power_profiles: dict[str, str | None],
    scheduler_versions: dict[str, str | None],
    scheduler_statuses: dict[str, str],
    scheduler_issues: dict[str, str | None],
    scheduler_metrics: dict[str, str | None],
) -> None:
    csv_path = out_dir / "mini_benchmarker_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "label",
                "power_profile",
                "scheduler_version",
                "scheduler_status",
                "scheduler_issue",
                "scheduler_metrics",
                "runs",
                "benchmark",
                "mean_seconds",
            ]
        )
        for label in labels:
            for test_name in tests:
                writer.writerow([
                    label,
                    power_profiles[label] or "",
                    scheduler_versions[label] or "",
                    scheduler_statuses[label],
                    scheduler_issues[label] or "",
                    scheduler_metrics[label] or "",
                    run_counts[label],
                    test_name,
                    f"{averages[label][test_name]:.2f}",
                ])


def display_label(label: str, power_profile: str | None, scheduler_version: str | None, scheduler_status: str) -> str:
    if scheduler_version:
        label = f"{label} [ver: {scheduler_version}]"
    if scheduler_status != "clean":
        label = f"{label} [status: {scheduler_status}]"
    if power_profile:
        return f"{label} [power: {power_profile}]"
    return label


def render_chart(
    out_dir: Path,
    tests: list[str],
    labels: list[str],
    averages: dict[str, dict[str, float]],
    power_profiles: dict[str, str | None],
    scheduler_versions: dict[str, str | None],
    scheduler_statuses: dict[str, str],
    title: str,
) -> None:
    tests = list(reversed(tests))
    series_count = len(labels)
    figure_height = max(8.0, len(tests) * 0.85 + series_count * 0.6)
    fig, ax = plt.subplots(figsize=(14, figure_height))

    bar_height = 0.8 / max(series_count, 1)
    positions = list(range(len(tests)))

    for index, label in enumerate(labels):
        offset = (index - (series_count - 1) / 2.0) * bar_height
        values = [averages[label][test_name] for test_name in tests]
        ys = [pos + offset for pos in positions]
        bars = ax.barh(
            ys,
            values,
            height=bar_height,
            label=display_label(label, power_profiles[label], scheduler_versions[label], scheduler_statuses[label]),
        )
        for bar, value in zip(bars, values):
            ax.text(
                bar.get_width(),
                bar.get_y() + bar.get_height() / 2.0,
                f"{value:.2f}",
                va="center",
                ha="left",
                fontsize=9,
            )

    ax.set_yticks(positions)
    ax.set_yticklabels(tests)
    ax.set_xlabel("Average Time (s). Less is better")
    ax.set_ylabel("Benchmark")
    ax.set_title(title)
    ax.grid(axis="x", alpha=0.4)
    ax.legend(loc="lower right")
    fig.tight_layout()

    fig.savefig(out_dir / "mini_benchmarker_comparison.png", dpi=200)
    fig.savefig(out_dir / "mini_benchmarker_comparison.svg")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_dir", type=Path, help="Directory containing tagged Mini Benchmarker .log files")
    parser.add_argument(
        "--title",
        default="Mini Benchmarker Comparison",
        help="Chart title",
    )
    args = parser.parse_args()

    log_dir = args.log_dir.resolve()
    (
        tests,
        labels,
        averages,
        run_counts,
        power_profiles,
        scheduler_versions,
        scheduler_statuses,
        scheduler_issues,
        scheduler_metrics,
    ) = aggregate_logs(log_dir)
    write_csv(
        log_dir,
        tests,
        labels,
        averages,
        run_counts,
        power_profiles,
        scheduler_versions,
        scheduler_statuses,
        scheduler_issues,
        scheduler_metrics,
    )
    render_chart(
        log_dir,
        tests,
        labels,
        averages,
        power_profiles,
        scheduler_versions,
        scheduler_statuses,
        args.title,
    )
    print(f"Wrote chart and CSV summary to {log_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
