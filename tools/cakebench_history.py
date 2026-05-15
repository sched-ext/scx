#!/usr/bin/env python3
"""Daemonless cakebench run ledger.

The JSONL ledger is intentionally boring: every benchmark run gets one append-only
record that points back to the raw artifact directory. Generated JSON/HTML files
are convenience indexes and can be rebuilt from the ledger.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCX_REPO = ROOT
DEFAULT_BENCH_REPO = (ROOT / ".." / "scx_cake_bench_assets").resolve()
DEFAULT_HISTORY_ROOT = DEFAULT_BENCH_REPO / "history"
DUAL_CACHE_TARGET = 5_484_539.37
DUAL_MEMCPY_TARGET = 5_859.61


def add_dual_score_metrics(metrics: dict[str, Any]) -> None:
    cache = metrics.get("stress_cache_bogo_ops_per_s")
    memcpy = metrics.get("stress_memcpy_bogo_ops_per_s")
    if not isinstance(cache, (int, float)) or not isinstance(memcpy, (int, float)):
        return
    cache_ratio = float(cache) / DUAL_CACHE_TARGET
    memcpy_ratio = float(memcpy) / DUAL_MEMCPY_TARGET
    metrics["stress_cache_vs_best_ratio"] = cache_ratio
    metrics["stress_memcpy_vs_best_ratio"] = memcpy_ratio
    metrics["stress_cache_mem_dual_score"] = min(cache_ratio, memcpy_ratio)
    metrics["stress_cache_mem_geomean_score"] = (cache_ratio * memcpy_ratio) ** 0.5
    metrics["stress_cache_mem_goal_pass"] = cache_ratio >= 1.0 and memcpy_ratio >= 1.0


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_git(repo: Path, args: list[str], default: str = "") -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return default


def parse_summary(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^-\s+([^:]+):\s*(.*)$", line)
        if match:
            key = match.group(1).strip().lower().replace(" ", "_")
            data[key] = match.group(2).strip()
    return data


def find_run_dir(out_dir: Path) -> Path | None:
    runs_root = out_dir / "runs"
    if not runs_root.is_dir():
        return None
    candidates = [p for p in runs_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def parse_stress_ng_log(path: Path) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {}
    if not path.is_file():
        return metrics
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "stress-ng: metrc:" not in line:
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        stressor = parts[3]
        if stressor not in {"cache", "memcpy"}:
            continue
        try:
            bogo_ops = int(float(parts[4]))
            real_time = float(parts[5])
            usr_time = float(parts[6])
            sys_time = float(parts[7])
            realtime_rate = float(parts[-2])
            cpu_rate = float(parts[-1])
        except ValueError:
            continue
        prefix = "stress_cache" if stressor == "cache" else "stress_memcpy"
        metrics[f"{prefix}_bogo_ops"] = bogo_ops
        metrics[f"{prefix}_real_time_secs"] = real_time
        metrics[f"{prefix}_usr_time_secs"] = usr_time
        metrics[f"{prefix}_sys_time_secs"] = sys_time
        metrics[f"{prefix}_bogo_ops_per_s"] = realtime_rate
        metrics[f"{prefix}_bogo_ops_per_s_cpu_time"] = cpu_rate
    return metrics


def parse_perf_csv(path: Path) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {}
    if not path.is_file():
        return metrics
    event_map = {
        "context-switches": "context_switches",
        "cpu-migrations": "cpu_migrations",
        "task-clock": "task_clock_ms",
    }
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            event = row[2].strip()
            key = event_map.get(event)
            if not key:
                continue
            raw = row[0].strip()
            try:
                value = float(raw)
            except ValueError:
                continue
            if value.is_integer() and key != "task_clock_ms":
                metrics[key] = int(value)
            else:
                metrics[key] = value
    return metrics


def read_json_file(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None


def parse_noise_artifacts(out_dir: Path | str) -> dict[str, Any]:
    out_path = Path(out_dir).resolve()
    noise_dir = out_path / "noise"
    candidates = [
        noise_dir / "summary.json",
        noise_dir / "monitor.json",
        noise_dir / "post.json",
        noise_dir / "manual.json",
        noise_dir / "pre.json",
    ]
    summary = next((data for data in (read_json_file(path) for path in candidates) if isinstance(data, dict)), None)
    if not summary:
        return {}
    artifact_paths = {
        "summary_json": str((noise_dir / "summary.json").resolve()) if (noise_dir / "summary.json").is_file() else "",
        "summary_md": str((noise_dir / "summary.md").resolve()) if (noise_dir / "summary.md").is_file() else "",
        "timeline_jsonl": str((noise_dir / "timeline.jsonl").resolve()) if (noise_dir / "timeline.jsonl").is_file() else "",
        "pre_json": str((noise_dir / "pre.json").resolve()) if (noise_dir / "pre.json").is_file() else "",
        "post_json": str((noise_dir / "post.json").resolve()) if (noise_dir / "post.json").is_file() else "",
    }
    return {
        "schema_version": summary.get("schema_version", 1),
        "severity": summary.get("severity", "unknown"),
        "score": summary.get("score", 0),
        "sample_count": summary.get("sample_count", 0),
        "sampled_secs": summary.get("sampled_secs", 0),
        "max_external_cpu_pct": summary.get("max_external_cpu_pct", 0),
        "avg_external_cpu_pct": summary.get("avg_external_cpu_pct", 0),
        "max_kernel_cpu_pct": summary.get("max_kernel_cpu_pct", 0),
        "avg_kernel_cpu_pct": summary.get("avg_kernel_cpu_pct", 0),
        "max_cpu_psi_avg10": summary.get("max_cpu_psi_avg10", 0),
        "benchmark_saturated": summary.get("benchmark_saturated", False),
        "cpu_psi_counted_as_noise": summary.get("cpu_psi_counted_as_noise", True),
        "max_io_psi_avg10": summary.get("max_io_psi_avg10", 0),
        "max_memory_psi_avg10": summary.get("max_memory_psi_avg10", 0),
        "max_procs_blocked": summary.get("max_procs_blocked", 0),
        "max_load1_per_cpu": summary.get("max_load1_per_cpu", 0),
        "top_external": summary.get("top_external", [])[:5],
        "known_noise": summary.get("known_noise", [])[:8],
        "top_tooling": summary.get("top_tooling", [])[:5],
        "artifact_paths": artifact_paths,
    }


def compact_utc_to_iso(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if re.match(r"^\d{8}T\d{6}Z$", value):
        parsed = dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.UTC)
        return parsed.isoformat().replace("+00:00", "Z")
    if value.endswith("Z") or re.match(r".*[+-]\d\d:\d\d$", value):
        return value
    return value


def timestamp_from_name(name: str) -> str:
    match = re.match(r"^(\d{8}T\d{6}Z)", name)
    return compact_utc_to_iso(match.group(1)) if match else ""


def scheduler_from_single_out_dir(path: Path | str) -> str:
    name = Path(path).name
    if "debug-cake" in name:
        return "scx_cake_debug"
    match = re.search(r"_release-([^_/]+(?:_[^_/]+)*)$", name)
    if not match:
        return "scx_cake"
    scheduler = match.group(1)
    if scheduler == "cake":
        return "scx_cake"
    if scheduler.startswith("scx_"):
        return scheduler
    return f"scx_{scheduler}"


def parse_run_artifacts(out_dir: Path | str) -> dict[str, Any]:
    out_path = Path(out_dir).resolve()
    run_dir = find_run_dir(out_path)
    summary = parse_summary(run_dir / "summary.md") if run_dir else parse_summary(out_path / "summary.md")
    if run_dir is None:
        run_dir = out_path

    metrics: dict[str, Any] = {}
    metrics.update(parse_stress_ng_log(run_dir / "logs" / "repeat_1_stat.log"))
    metrics.update(parse_perf_csv(run_dir / "perf" / "repeat_1_stat.perf_stat.csv"))
    add_dual_score_metrics(metrics)

    benchmark = summary.get("benchmark")
    if not benchmark:
        name = run_dir.name
        match = re.match(r"^\d{8}T\d{6}Z_(.+?)(?:_release|_debug|\.|$)", name)
        benchmark = match.group(1) if match else ""

    return {
        "out_dir": str(out_path),
        "run_dir": str(run_dir.resolve()),
        "summary": summary,
        "benchmark": benchmark,
        "label": summary.get("label", ""),
        "started_utc": summary.get("started_utc", ""),
        "active_ops": summary.get("active_ops", ""),
        "capture_mode": summary.get("capture_mode", summary.get("capture", "")),
        "metrics": metrics,
        "noise": parse_noise_artifacts(out_path),
        "artifact_paths": {
            "summary": str((run_dir / "summary.md").resolve()),
            "stress_log": str((run_dir / "logs" / "repeat_1_stat.log").resolve()),
            "perf_stat_csv": str((run_dir / "perf" / "repeat_1_stat.perf_stat.csv").resolve()),
        },
    }


def read_key_value_tsv(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) >= 2 and row[0] != "key":
                data[row[0]] = row[1]
    return data


def read_tsv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def coerce_scalar(value: str) -> str | int | float:
    value = value.strip()
    if value == "":
        return ""
    try:
        number = float(value)
    except ValueError:
        return value
    if number.is_integer() and not re.search(r"[.eE]", value):
        return int(number)
    return number


def normalize_native_metric(name: str) -> str:
    mapping = {
        "stress_cache_real_time": "stress_cache_real_time_secs",
        "stress_cache_user_time": "stress_cache_usr_time_secs",
        "stress_cache_sys_time": "stress_cache_sys_time_secs",
        "stress_cache_bogo_ops_per_s_realtime": "stress_cache_bogo_ops_per_s",
        "stress_cache_bogo_ops_per_s_cpu_time": "stress_cache_bogo_ops_per_s_cpu_time",
        "stress_memcpy_real_time": "stress_memcpy_real_time_secs",
        "stress_memcpy_user_time": "stress_memcpy_usr_time_secs",
        "stress_memcpy_sys_time": "stress_memcpy_sys_time_secs",
        "stress_memcpy_bogo_ops_per_s_realtime": "stress_memcpy_bogo_ops_per_s",
        "stress_memcpy_bogo_ops_per_s_cpu_time": "stress_memcpy_bogo_ops_per_s_cpu_time",
    }
    return mapping.get(name, re.sub(r"[^a-zA-Z0-9_]+", "_", name).strip("_"))


def latest_build_outputs(scx_repo: Path) -> tuple[Path | None, Path | None]:
    build_root = scx_repo / "target" / "release" / "build"
    if not build_root.is_dir():
        return None, None
    constants = sorted(build_root.glob("scx_cake-*/out/cake_constants.rs"), key=lambda p: p.stat().st_mtime)
    objects = sorted(build_root.glob("scx_cake-*/out/cake.bpf.o"), key=lambda p: p.stat().st_mtime)
    return (constants[-1] if constants else None, objects[-1] if objects else None)


def parse_baked_constants(path: Path | None) -> dict[str, Any]:
    constants: dict[str, Any] = {}
    if path is None or not path.is_file():
        return constants
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"pub const (BAKED_[A-Z0-9_]+): [^=]+ = (.+);", line)
        if not match:
            continue
        key, raw_value = match.groups()
        raw_value = raw_value.strip()
        if raw_value.startswith('"') and raw_value.endswith('"'):
            constants[key] = raw_value[1:-1]
        else:
            try:
                constants[key] = int(raw_value)
            except ValueError:
                constants[key] = raw_value
    return constants


def git_metadata(scx_repo: Path, history_root: Path, run_id: str) -> dict[str, Any]:
    branch = run_git(scx_repo, ["rev-parse", "--abbrev-ref", "HEAD"], "unknown")
    head = run_git(scx_repo, ["rev-parse", "HEAD"], "unknown")
    short = run_git(scx_repo, ["rev-parse", "--short", "HEAD"], "unknown")
    subject = run_git(scx_repo, ["show", "-s", "--format=%s", "HEAD"], "")
    status = run_git(scx_repo, ["status", "--short"], "")
    diff = run_git(scx_repo, ["diff", "--", "scheds/rust/scx_cake", "cakebench", "tools"], "")
    diff_bytes = diff.encode("utf-8")
    diff_hash = sha256_bytes(diff_bytes) if diff else ""
    patch_path = ""
    if diff:
        patches_dir = history_root / "patches"
        patches_dir.mkdir(parents=True, exist_ok=True)
        patch_file = patches_dir / f"{run_id}.patch"
        patch_file.write_text(diff, encoding="utf-8")
        patch_path = str(patch_file.resolve())

    changed_files = [
        line[3:] for line in status.splitlines() if len(line) > 3 and line[3:].startswith(("scheds/rust/scx_cake/", "cakebench", "tools/"))
    ]
    return {
        "branch": branch,
        "head": head,
        "short_head": short,
        "subject": subject,
        "dirty": bool(status),
        "status_count": len([line for line in status.splitlines() if line.strip()]),
        "dirty_diff_sha256": diff_hash,
        "dirty_patch_path": patch_path,
        "changed_files": changed_files,
    }


def imported_git_metadata(parsed: dict[str, Any] | None = None, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    summary = parsed.get("summary", {}) if parsed else {}
    metadata = metadata or {}
    head = summary.get("git_head", "") or metadata.get("git_commit", "") or "unknown"
    branch = metadata.get("git_branch", "unknown")
    state = metadata.get("git_state", "")
    short = head[:12] if head and head != "unknown" else "unknown"
    dirty = state.startswith("dirty") if state else None
    return {
        "branch": branch,
        "head": head,
        "short_head": short,
        "subject": "",
        "dirty": dirty,
        "status_count": int(state.split(":", 1)[1]) if state.startswith("dirty:") and state.split(":", 1)[1].isdigit() else 0,
        "dirty_diff_sha256": "",
        "dirty_patch_path": "",
        "changed_files": [],
        "imported_git_only": True,
    }


def read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            source_type = record.get("source", {}).get("type")
            if source_type == "single_import":
                record["scheduler"] = scheduler_from_single_out_dir(record.get("out_dir", ""))
            add_dual_score_metrics(record.get("metrics", {}))
            record.setdefault("mutation", {}).setdefault("kind", "")
            if not record.get("noise") and record.get("out_dir"):
                record["noise"] = parse_noise_artifacts(record["out_dir"])
            else:
                record.setdefault("noise", {})
            records.append(record)
        except json.JSONDecodeError:
            continue
    return records


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sort_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records, key=lambda r: (r.get("created_utc", ""), r.get("run_id", "")))


def best_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    best: dict[str, Any] = {}
    metric_specs = {
        "stress_cache_bogo_ops_per_s": "higher",
        "stress_memcpy_bogo_ops_per_s": "higher",
        "stress_cache_mem_dual_score": "higher",
        "stress_cache_mem_geomean_score": "higher",
        "context_switches": "lower",
        "cpu_migrations": "lower",
    }
    for metric, direction in metric_specs.items():
        winner = None
        for record in records:
            value = record.get("metrics", {}).get(metric)
            if not isinstance(value, (int, float)):
                continue
            if winner is None:
                winner = record
                continue
            old = winner["metrics"][metric]
            if (direction == "higher" and value > old) or (direction == "lower" and value < old):
                winner = record
        if winner:
            best[metric] = {
                "direction": direction,
                "value": winner["metrics"][metric],
                "run_id": winner["run_id"],
                "scheduler": winner.get("scheduler", ""),
                "benchmark": winner.get("benchmark", ""),
                "git": winner.get("git", {}),
                "out_dir": winner.get("out_dir", ""),
            }
    return best


def catalog_summary(records: list[dict[str, Any]], best: dict[str, Any]) -> dict[str, Any]:
    benchmarks: dict[str, int] = {}
    schedulers: dict[str, int] = {}
    sources: dict[str, int] = {}
    mutation_kinds: dict[str, int] = {}
    noise: dict[str, int] = {}
    best_by_benchmark: dict[str, dict[str, Any]] = {}
    for record in records:
        benchmark = record.get("benchmark", "") or "unknown"
        benchmarks[benchmark] = benchmarks.get(benchmark, 0) + 1
        schedulers[record.get("scheduler", "") or "unknown"] = schedulers.get(record.get("scheduler", "") or "unknown", 0) + 1
        source = record.get("source", {}).get("type", "current")
        sources[source] = sources.get(source, 0) + 1
        kind = record.get("mutation", {}).get("kind", "") or "unspecified"
        mutation_kinds[kind] = mutation_kinds.get(kind, 0) + 1
        severity = record.get("noise", {}).get("severity", "") or "unknown"
        noise[severity] = noise.get(severity, 0) + 1
    for benchmark in sorted(benchmarks):
        subset = [record for record in records if (record.get("benchmark", "") or "unknown") == benchmark]
        bench_best = best_summary(subset)
        if bench_best:
            best_by_benchmark[benchmark] = bench_best
    return {
        "records": len(records),
        "benchmarks": dict(sorted(benchmarks.items())),
        "schedulers": dict(sorted(schedulers.items())),
        "sources": dict(sorted(sources.items())),
        "mutation_kinds": dict(sorted(mutation_kinds.items())),
        "noise": dict(sorted(noise.items())),
        "best": best,
        "best_by_benchmark": best_by_benchmark,
    }


def render_dashboard(records: list[dict[str, Any]], best: dict[str, Any]) -> str:
    payload = json.dumps(records, sort_keys=True)
    catalog = json.dumps(catalog_summary(records, best), sort_keys=True)
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>scx_cake Benchmark History</title>
  <style>
    :root {
      --bg: #0f1317;
      --panel: #171d23;
      --panel-2: #1d242b;
      --line: #303943;
      --text: #e7edf3;
      --muted: #9aa8b4;
      --accent: #67c1ff;
      --good: #79d38a;
      --warn: #ffd27d;
      --bad: #ff8b8b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }
    code, table, input, select, button {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    header {
      border-bottom: 1px solid var(--line);
      padding: 18px 22px 14px;
      background: #12171c;
      position: sticky;
      top: 0;
      z-index: 4;
    }
    h1 { margin: 0 0 4px; font-size: 20px; font-weight: 680; letter-spacing: 0; }
    .sub { color: var(--muted); font-size: 13px; }
    main { padding: 18px 22px 28px; }
    .stats, .controls, .summary-grid {
      display: grid;
      gap: 10px;
    }
    .stats { grid-template-columns: repeat(4, minmax(130px, 1fr)); margin-bottom: 14px; }
    .stat, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .stat { padding: 12px; min-width: 0; }
    .label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .value { margin-top: 4px; font-size: 20px; font-weight: 700; overflow-wrap: anywhere; }
    .controls {
      grid-template-columns: minmax(180px, 1.4fr) repeat(4, minmax(140px, 1fr));
      margin-bottom: 14px;
    }
    input, select, button {
      width: 100%;
      min-height: 36px;
      padding: 8px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel-2);
      color: var(--text);
      font-size: 12px;
    }
    button { cursor: pointer; }
    .panel { padding: 14px; margin-bottom: 14px; }
    .panel h2 {
      margin: 0 0 10px;
      font-size: 14px;
      font-weight: 680;
    }
    .chart {
      width: 100%;
      height: 320px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #10161b;
      overflow: hidden;
    }
    .summary-grid { grid-template-columns: 1fr 1fr; }
    .mini-table { max-height: 260px; overflow: auto; border: 1px solid var(--line); border-radius: 6px; }
    .table-wrap { height: 560px; overflow: auto; border: 1px solid var(--line); border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 7px 8px;
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }
    th {
      position: sticky;
      top: 0;
      background: #182029;
      color: var(--accent);
      z-index: 2;
      font-weight: 700;
    }
    td.path, td.note { white-space: normal; min-width: 260px; }
    .muted { color: var(--muted); }
    .clean { color: var(--good); }
    .low { color: var(--accent); }
    .good { color: var(--good); }
    .warn { color: var(--warn); }
    .bad { color: var(--bad); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    @media (max-width: 900px) {
      header, main { padding-left: 12px; padding-right: 12px; }
      .stats, .controls, .summary-grid { grid-template-columns: 1fr; }
      .table-wrap { height: 480px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>scx_cake Benchmark History</h1>
    <div class="sub">Imported and live benchmark records from the local cakebench artifact tree.</div>
  </header>
  <main>
    <section class="stats">
      <div class="stat"><div class="label">Visible</div><div class="value" id="visibleCount">0</div></div>
      <div class="stat"><div class="label">Total Records</div><div class="value" id="totalCount">0</div></div>
      <div class="stat"><div class="label">Benchmarks</div><div class="value" id="benchmarkCount">0</div></div>
      <div class="stat"><div class="label">Schedulers</div><div class="value" id="schedulerCount">0</div></div>
    </section>

    <section class="controls">
      <input id="search" type="search" placeholder="Search run id, path, git, kind, hypothesis">
      <select id="benchmark"></select>
      <select id="scheduler"></select>
      <select id="kind"></select>
      <select id="source"></select>
      <select id="metric"></select>
    </section>

    <section class="panel">
      <h2>Score Trend</h2>
      <div id="chart" class="chart"></div>
    </section>

    <section class="summary-grid">
      <div class="panel">
        <h2>Best Scores</h2>
        <div class="mini-table">
          <table>
            <thead><tr><th>Metric</th><th>Value</th><th>Run</th><th>Scheduler</th></tr></thead>
            <tbody id="bestRows"></tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <h2>Benchmark Counts</h2>
        <div class="mini-table">
          <table>
            <thead><tr><th>Benchmark</th><th>Records</th></tr></thead>
            <tbody id="benchmarkRows"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>All Runs</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>UTC</th><th>Benchmark</th><th>Scheduler</th><th>Kind</th><th>Metric</th>
              <th>Noise</th><th>Dual</th><th>Cache ops/s</th><th>Memcpy ops/s</th><th>Ctx sw</th><th>Migrations</th>
              <th>Git</th><th>Source</th><th>Run</th><th>Path</th>
            </tr>
          </thead>
          <tbody id="runRows"></tbody>
        </table>
      </div>
    </section>
  </main>
  <script>
    const records = __RECORDS__;
    const catalog = __CATALOG__;
    const metrics = [
      ['stress_cache_bogo_ops_per_s', 'Cache ops/s'],
      ['stress_memcpy_bogo_ops_per_s', 'Memcpy ops/s'],
      ['stress_cache_mem_dual_score', 'Dual score'],
      ['stress_cache_mem_geomean_score', 'Dual geomean'],
      ['context_switches', 'Context switches'],
      ['cpu_migrations', 'CPU migrations'],
      ['primary_value', 'Primary value'],
      ['wall_seconds', 'Wall seconds'],
      ['task_clock_ms', 'Task clock ms']
    ];
    const state = {
      search: '',
      benchmark: 'all',
      scheduler: 'all',
      kind: 'all',
      source: 'all',
      metric: 'stress_cache_mem_dual_score'
    };
    const fmt = value => {
      if (value === null || value === undefined || value === '') return '';
      if (typeof value === 'number') return Math.abs(value) >= 1000 ? value.toLocaleString(undefined, {maximumFractionDigits: 2}) : String(value);
      return String(value);
    };
    const shortText = (value, limit = 44) => {
      const text = String(value ?? '');
      return text.length > limit ? text.slice(0, limit - 1) + '.' : text;
    };
    const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    const uniq = values => [...new Set(values.filter(Boolean))].sort();
    function fillSelect(id, values, label) {
      const el = document.getElementById(id);
      el.innerHTML = `<option value="all">All ${label}</option>` + values.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
    }
    function metricValue(record, name) {
      const m = record.metrics || {};
      const value = m[name];
      return typeof value === 'number' ? value : null;
    }
    function sourceType(record) {
      return record.source && record.source.type || 'current';
    }
    function mutationKind(record) {
      return record.mutation && record.mutation.kind || 'unspecified';
    }
    function noise(record) {
      return record.noise || {};
    }
    function noiseClass(severity) {
      if (severity === 'clean') return 'clean';
      if (severity === 'low') return 'low';
      if (severity === 'warn') return 'warn';
      if (severity === 'noisy') return 'bad';
      return 'muted';
    }
    function noiseLabel(record) {
      const n = noise(record);
      if (!n.severity) return '';
      return `${n.severity} ${fmt(n.max_external_cpu_pct || 0)}%`;
    }
    function noiseTitle(record) {
      const n = noise(record);
      const top = [...(n.top_external || []), ...(n.known_noise || [])]
        .slice(0, 5)
        .map(row => `${row.comm || ''} ${fmt(row.max_cpu_pct || 0)}% ${row.reason || ''}`.trim())
        .join(' | ');
      return [
        `severity=${n.severity || 'unknown'}`,
        `external_max=${fmt(n.max_external_cpu_pct || 0)}%`,
        `cpu_psi=${fmt(n.max_cpu_psi_avg10 || 0)}`,
        top
      ].filter(Boolean).join(' | ');
    }
    function filteredRecords() {
      const q = state.search.toLowerCase();
      return records.filter(record => {
        if (state.benchmark !== 'all' && record.benchmark !== state.benchmark) return false;
        if (state.scheduler !== 'all' && record.scheduler !== state.scheduler) return false;
        if (state.kind !== 'all' && mutationKind(record) !== state.kind) return false;
        if (state.source !== 'all' && sourceType(record) !== state.source) return false;
        if (q) {
          const n = noise(record);
          const noiseText = [
            n.severity,
            ...(n.top_external || []).map(row => `${row.comm || ''} ${row.reason || ''} ${row.cmdline || ''}`),
            ...(n.known_noise || []).map(row => `${row.comm || ''} ${row.reason || ''} ${row.cmdline || ''}`)
          ].join(' ');
          const hay = [record.run_id, record.benchmark, record.scheduler, mutationKind(record), record.out_dir, record.run_dir, record.git && record.git.short_head, record.mutation && record.mutation.hypothesis, noiseText].join(' ').toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });
    }
    function renderBest(list) {
      const best = {};
      const spec = {
        stress_cache_bogo_ops_per_s: 'higher',
        stress_memcpy_bogo_ops_per_s: 'higher',
        stress_cache_mem_dual_score: 'higher',
        stress_cache_mem_geomean_score: 'higher',
        context_switches: 'lower',
        cpu_migrations: 'lower'
      };
      for (const [metric, direction] of Object.entries(spec)) {
        for (const record of list) {
          const value = metricValue(record, metric);
          if (value === null) continue;
          if (!best[metric] || (direction === 'higher' ? value > best[metric].value : value < best[metric].value)) {
            best[metric] = {value, record};
          }
        }
      }
      document.getElementById('bestRows').innerHTML = Object.entries(best).map(([metric, item]) => `
        <tr><td>${escapeHtml(metric)}</td><td class="good">${fmt(item.value)}</td><td>${escapeHtml(item.record.run_id)}</td><td>${escapeHtml(item.record.scheduler || '')}</td></tr>
      `).join('');
    }
    function renderBenchmarks() {
      document.getElementById('benchmarkRows').innerHTML = Object.entries(catalog.benchmarks || {})
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => `<tr><td>${escapeHtml(name)}</td><td>${count}</td></tr>`).join('');
    }
    function renderRows(list) {
      const rows = [...list].reverse().map(record => {
        const m = record.metrics || {};
        const git = record.git || {};
        const source = sourceType(record);
        const n = noise(record);
        return `
          <tr>
            <td>${escapeHtml(record.created_utc || '')}</td>
            <td>${escapeHtml(record.benchmark || '')}</td>
            <td>${escapeHtml(record.scheduler || '')}</td>
            <td>${escapeHtml(mutationKind(record))}</td>
            <td>${escapeHtml(m.primary_metric || '')}</td>
            <td class="${noiseClass(n.severity)}" title="${escapeHtml(noiseTitle(record))}">${escapeHtml(noiseLabel(record))}</td>
            <td class="${m.stress_cache_mem_goal_pass ? 'good' : 'warn'}">${fmt(m.stress_cache_mem_dual_score)}</td>
            <td class="good">${fmt(m.stress_cache_bogo_ops_per_s)}</td>
            <td class="good">${fmt(m.stress_memcpy_bogo_ops_per_s)}</td>
            <td>${fmt(m.context_switches)}</td>
            <td>${fmt(m.cpu_migrations)}</td>
            <td>${escapeHtml(git.short_head || '')}${git.dirty ? ' <span class="warn">dirty</span>' : ''}</td>
            <td>${escapeHtml(source)}</td>
            <td class="mono">${escapeHtml(record.run_id || '')}</td>
            <td class="path">${escapeHtml(record.run_dir || record.out_dir || '')}</td>
          </tr>
        `;
      }).join('');
      document.getElementById('runRows').innerHTML = rows;
    }
    function renderChart(list) {
      const el = document.getElementById('chart');
      const points = list.map((record, index) => ({record, index, value: metricValue(record, state.metric)})).filter(p => p.value !== null);
      if (points.length === 0) {
        el.innerHTML = '<div class="muted" style="padding:18px">No numeric values for this metric/filter.</div>';
        return;
      }
      const width = Math.max(760, el.clientWidth || 760);
      const height = 320;
      const pad = {left: 76, right: 18, top: 28, bottom: 52};
      const min = Math.min(...points.map(p => p.value));
      const max = Math.max(...points.map(p => p.value));
      const span = max === min ? 1 : max - min;
      const x = i => pad.left + (points.length === 1 ? 0 : i * (width - pad.left - pad.right) / (points.length - 1));
      const y = value => pad.top + (max - value) * (height - pad.top - pad.bottom) / span;
      const line = points.map((p, i) => `${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(' ');
      const last = points[points.length - 1];
      el.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" width="100%" height="100%" role="img" aria-label="Benchmark metric chart">
          <rect x="0" y="0" width="${width}" height="${height}" fill="#10161b"></rect>
          <line x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${height - pad.bottom}" stroke="#303943"></line>
          <line x1="${pad.left}" y1="${height - pad.bottom}" x2="${width - pad.right}" y2="${height - pad.bottom}" stroke="#303943"></line>
          <text x="${pad.left}" y="18" fill="#9aa8b4" font-size="12">${escapeHtml(metrics.find(m => m[0] === state.metric)?.[1] || state.metric)}</text>
          <text x="10" y="${pad.top + 4}" fill="#9aa8b4" font-size="11">${fmt(max)}</text>
          <text x="10" y="${height - pad.bottom}" fill="#9aa8b4" font-size="11">${fmt(min)}</text>
          <polyline points="${line}" fill="none" stroke="#67c1ff" stroke-width="2.5"></polyline>
          <circle cx="${x(points.length - 1)}" cy="${y(last.value)}" r="4" fill="#79d38a"></circle>
          <text x="${width - pad.right}" y="${height - 18}" fill="#d9e2ec" font-size="12" text-anchor="end">${escapeHtml(shortText(last.record.run_id))}: ${fmt(last.value)}</text>
        </svg>
      `;
    }
    function render() {
      const list = filteredRecords();
      document.getElementById('visibleCount').textContent = list.length.toLocaleString();
      document.getElementById('totalCount').textContent = records.length.toLocaleString();
      document.getElementById('benchmarkCount').textContent = Object.keys(catalog.benchmarks || {}).length;
      document.getElementById('schedulerCount').textContent = Object.keys(catalog.schedulers || {}).length;
      renderBest(list);
      renderBenchmarks();
      renderChart(list);
      renderRows(list);
    }
    fillSelect('benchmark', uniq(records.map(r => r.benchmark)), 'benchmarks');
    fillSelect('scheduler', uniq(records.map(r => r.scheduler)), 'schedulers');
    fillSelect('kind', uniq(records.map(mutationKind)), 'kinds');
    fillSelect('source', uniq(records.map(sourceType)), 'sources');
    document.getElementById('metric').innerHTML = metrics.map(([value, label]) => `<option value="${value}">${label}</option>`).join('');
    for (const id of ['search', 'benchmark', 'scheduler', 'kind', 'source', 'metric']) {
      document.getElementById(id).addEventListener('input', event => {
        state[id] = event.target.value;
        render();
      });
    }
    render();
    window.addEventListener('resize', () => renderChart(filteredRecords()));
  </script>
</body>
</html>
""".replace("__RECORDS__", payload).replace("__CATALOG__", catalog)


def rebuild(history_root: Path) -> dict[str, Any]:
    history_root.mkdir(parents=True, exist_ok=True)
    ledger = history_root / "runs.jsonl"
    records = sort_records(read_ledger(ledger))
    latest = records[-1] if records else {}
    best = best_summary(records)
    write_json(history_root / "latest.json", latest)
    write_json(history_root / "best.json", best)
    write_json(history_root / "catalog.json", catalog_summary(records, best))
    (history_root / "index.html").write_text(render_dashboard(records, best), encoding="utf-8")
    return {"records": len(records), "latest": latest.get("run_id", ""), "history_root": str(history_root)}


def append_record(history: Path, record: dict[str, Any], *, rebuild_after: bool = True) -> dict[str, Any]:
    history.mkdir(parents=True, exist_ok=True)
    ledger = history / "runs.jsonl"
    with ledger.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    if rebuild_after:
        rebuild(history)
    return record


def record_run(
    *,
    out_dir: Path | str,
    history_root: Path | str = DEFAULT_HISTORY_ROOT,
    scx_repo: Path | str = DEFAULT_SCX_REPO,
    bench_repo: Path | str = DEFAULT_BENCH_REPO,
    benchmark: str = "",
    scheduler: str = "scx_cake",
    capture: str = "",
    command: list[str] | None = None,
    hypothesis: str = "",
    mutation_id: str = "",
    mutation_kind: str = "",
    imported: bool = False,
    rebuild_after: bool = True,
) -> dict[str, Any]:
    out_path = Path(out_dir).resolve()
    history = Path(history_root).resolve()
    scx_path = Path(scx_repo).resolve()
    bench_path = Path(bench_repo).resolve()
    parsed = parse_run_artifacts(out_path)
    run_dir = Path(parsed["run_dir"])
    run_id = run_dir.name if run_dir.exists() else out_path.name
    constants_path, bpf_obj = (None, None) if imported else latest_build_outputs(scx_path)
    git = imported_git_metadata(parsed) if imported else git_metadata(scx_path, history, run_id)
    created_utc = (
        compact_utc_to_iso(str(parsed.get("started_utc", "")))
        or timestamp_from_name(run_id)
        or utc_now()
        if imported
        else utc_now()
    )

    record = {
        "schema_version": 1,
        "run_id": run_id,
        "history_key": f"single:{run_dir}" if imported else f"current:{run_id}",
        "created_utc": created_utc,
        "benchmark": benchmark or parsed.get("benchmark", ""),
        "scheduler": scheduler,
        "capture": capture or parsed.get("capture_mode", ""),
        "out_dir": str(out_path),
        "run_dir": str(run_dir),
        "scx_repo": str(scx_path),
        "bench_repo": str(bench_path),
        "command": command or [],
        "metrics": parsed["metrics"],
        "noise": parsed["noise"],
        "summary": parsed["summary"],
        "artifact_paths": parsed["artifact_paths"],
        "baked_constants": parse_baked_constants(constants_path),
        "build_artifacts": {
            "cake_constants_rs": str(constants_path.resolve()) if constants_path else "",
            "cake_bpf_o": str(bpf_obj.resolve()) if bpf_obj else "",
            "cake_bpf_o_sha256": sha256_file(bpf_obj) if bpf_obj else None,
        },
        "git": git,
        "mutation": {
            "id": mutation_id,
            "hypothesis": hypothesis,
            "kind": mutation_kind,
        },
        "source": {
            "type": "single_import" if imported else "current",
            "imported": imported,
        },
    }
    return append_record(history, record, rebuild_after=rebuild_after)


def existing_history_keys(records: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for record in records:
        history_key = record.get("history_key")
        if history_key:
            keys.add(str(history_key))
        run_id = record.get("run_id")
        if run_id:
            keys.add(f"run_id:{run_id}")
    return keys


def discover_single_out_dirs(runs_root: Path) -> list[Path]:
    single_root = runs_root / "single"
    if not single_root.is_dir():
        return []
    out_dirs: set[Path] = set()
    for summary in single_root.glob("*/runs/*/summary.md"):
        out_dirs.add(summary.parents[2])
    return sorted(out_dirs)


def discover_matrix_metric_files(runs_root: Path) -> list[Path]:
    return sorted(path for path in runs_root.rglob("analysis_metrics.tsv") if path.is_file())


def nearest_run_metadata(path: Path) -> dict[str, str]:
    for parent in [path.parent, *path.parents]:
        metadata = read_key_value_tsv(parent / "cakebench_run.tsv")
        if metadata:
            return metadata
    return {}


def native_metrics_by_run_dir(native_file: Path) -> dict[str, dict[str, Any]]:
    by_run: dict[str, dict[str, Any]] = {}
    for row in read_tsv_rows(native_file):
        run_dir = row.get("run_dir", "")
        metric = row.get("metric", "")
        value = row.get("value", "")
        if not run_dir or not metric:
            continue
        by_run.setdefault(run_dir, {})[normalize_native_metric(metric)] = coerce_scalar(value)
    return by_run


def matrix_record_from_row(
    row: dict[str, str],
    *,
    metrics_file: Path,
    metadata: dict[str, str],
    native_metrics: dict[str, dict[str, Any]],
    scx_repo: Path,
    bench_repo: Path,
) -> dict[str, Any] | None:
    run_dir = row.get("run_dir", "")
    benchmark = row.get("benchmark", "")
    if not run_dir or not benchmark:
        return None

    run_path = Path(run_dir)
    run_id = run_path.name
    primary_metric = row.get("metric", "")
    primary_value = coerce_scalar(row.get("value", ""))
    metrics: dict[str, Any] = {
        "primary_metric": primary_metric,
        "primary_value": primary_value,
        "primary_direction": row.get("direction", ""),
        "primary_unit": row.get("unit", ""),
        "wall_seconds": coerce_scalar(row.get("wall_seconds", "")),
        "output_metric": row.get("output_metric", ""),
        "output_value": coerce_scalar(row.get("output_value", "")),
        "output_direction": row.get("output_direction", ""),
        "output_unit": row.get("output_unit", ""),
        "task_clock_ms": coerce_scalar(row.get("task_clock_ms", "")),
        "context_switches": coerce_scalar(row.get("context_switches", "")),
        "cpu_migrations": coerce_scalar(row.get("cpu_migrations", "")),
    }
    if benchmark == "stress-ng-cpu-cache-mem" and primary_metric == "cache_ops":
        metrics["stress_cache_bogo_ops_per_s"] = primary_value
    metrics.update(native_metrics.get(run_dir, {}))
    add_dual_score_metrics(metrics)

    history_key_src = f"matrix:{metrics_file}:{row.get('seq', '')}:{row.get('variant', '')}:{benchmark}:{primary_metric}:{run_dir}"
    history_key = "matrix:" + sha256_bytes(history_key_src.encode("utf-8"))[:16]
    return {
        "schema_version": 1,
        "run_id": run_id,
        "history_key": history_key,
        "created_utc": timestamp_from_name(run_id) or compact_utc_to_iso(metadata.get("created_utc", "")) or utc_now(),
        "benchmark": benchmark,
        "scheduler": row.get("variant", ""),
        "capture": metadata.get("capture", ""),
        "out_dir": str(metrics_file.parent.resolve()),
        "run_dir": str(run_path.resolve()),
        "scx_repo": str(scx_repo.resolve()),
        "bench_repo": str(bench_repo.resolve()),
        "command": [],
        "metrics": metrics,
        "noise": parse_noise_artifacts(run_path.parent),
        "summary": {
            "seq": row.get("seq", ""),
            "variant": row.get("variant", ""),
            "repeat": row.get("repeat", ""),
            "source": row.get("source", ""),
        },
        "artifact_paths": {
            "analysis_metrics_tsv": str(metrics_file.resolve()),
            "analysis_native_metrics_tsv": str((metrics_file.parent / "analysis_native_metrics.tsv").resolve()),
            "run_dir": str(run_path.resolve()),
        },
        "baked_constants": {},
        "build_artifacts": {},
        "git": imported_git_metadata(metadata=metadata),
        "mutation": {
            "id": "",
            "hypothesis": metadata.get("preset", "") or metrics_file.parent.name,
            "kind": "preset",
        },
        "source": {
            "type": "matrix_import",
            "imported": True,
            "metrics_file": str(metrics_file.resolve()),
        },
    }


def import_old_runs(
    *,
    runs_root: Path | str,
    history_root: Path | str = DEFAULT_HISTORY_ROOT,
    scx_repo: Path | str = DEFAULT_SCX_REPO,
    bench_repo: Path | str = DEFAULT_BENCH_REPO,
    include_single: bool = True,
    include_matrix: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    runs_path = Path(runs_root).resolve()
    history = Path(history_root).resolve()
    scx_path = Path(scx_repo).resolve()
    bench_path = Path(bench_repo).resolve()
    records = read_ledger(history / "runs.jsonl")
    seen = existing_history_keys(records)
    added = 0
    skipped = 0
    errors: list[str] = []

    if include_single:
        for out_dir in discover_single_out_dirs(runs_path):
            try:
                parsed = parse_run_artifacts(out_dir)
                run_key = f"single:{Path(parsed['run_dir'])}"
                if run_key in seen or f"run_id:{Path(parsed['run_dir']).name}" in seen:
                    skipped += 1
                    continue
                if not dry_run:
                    record = record_run(
                        out_dir=out_dir,
                        history_root=history,
                        scx_repo=scx_path,
                        bench_repo=bench_path,
                        benchmark=parsed.get("benchmark", ""),
                        scheduler=scheduler_from_single_out_dir(out_dir),
                        capture=parsed.get("capture_mode", ""),
                        imported=True,
                        rebuild_after=False,
                    )
                    seen.add(str(record["history_key"]))
                    seen.add(f"run_id:{record['run_id']}")
                added += 1
            except Exception as exc:  # pragma: no cover - defensive importer
                errors.append(f"{out_dir}: {exc}")

    if include_matrix:
        for metrics_file in discover_matrix_metric_files(runs_path):
            metadata = nearest_run_metadata(metrics_file)
            native = native_metrics_by_run_dir(metrics_file.parent / "analysis_native_metrics.tsv")
            for row in read_tsv_rows(metrics_file):
                try:
                    record = matrix_record_from_row(
                        row,
                        metrics_file=metrics_file,
                        metadata=metadata,
                        native_metrics=native,
                        scx_repo=scx_path,
                        bench_repo=bench_path,
                    )
                    if not record:
                        skipped += 1
                        continue
                    if record["history_key"] in seen or f"run_id:{record['run_id']}" in seen:
                        skipped += 1
                        continue
                    if not dry_run:
                        append_record(history, record, rebuild_after=False)
                        seen.add(str(record["history_key"]))
                        seen.add(f"run_id:{record['run_id']}")
                    added += 1
                except Exception as exc:  # pragma: no cover - defensive importer
                    errors.append(f"{metrics_file}: {exc}")

    if not dry_run:
        rebuild(history)
    return {
        "runs_root": str(runs_path),
        "history_root": str(history),
        "added": added,
        "skipped": skipped,
        "errors": errors,
        "dry_run": dry_run,
    }


def cmd_record(args: argparse.Namespace) -> int:
    command = args.command if args.command else []
    record = record_run(
        out_dir=args.out_dir,
        history_root=args.history_root,
        scx_repo=args.scx_repo,
        bench_repo=args.bench_repo,
        benchmark=args.benchmark,
        scheduler=args.scheduler,
        capture=args.capture,
        command=command,
        hypothesis=args.hypothesis or os.environ.get("SCX_CAKE_BENCH_HYPOTHESIS", ""),
        mutation_id=args.mutation_id or os.environ.get("SCX_CAKE_BENCH_MUTATION_ID", ""),
        mutation_kind=args.mutation_kind or os.environ.get("SCX_CAKE_BENCH_MUTATION_KIND", ""),
    )
    print(f"history record: {record['run_id']}")
    print(f"history: {Path(args.history_root).resolve()}")
    return 0


def cmd_rebuild(args: argparse.Namespace) -> int:
    result = rebuild(Path(args.history_root))
    print(f"rebuilt history: {result['records']} records")
    print(result["history_root"])
    return 0


def cmd_import_old(args: argparse.Namespace) -> int:
    result = import_old_runs(
        runs_root=args.runs_root,
        history_root=args.history_root,
        scx_repo=args.scx_repo,
        bench_repo=args.bench_repo,
        include_single=not args.matrix_only,
        include_matrix=not args.single_only,
        dry_run=args.dry_run,
    )
    print(f"import-old added: {result['added']}")
    print(f"import-old skipped: {result['skipped']}")
    print(f"history: {result['history_root']}")
    if result["errors"]:
        print(f"errors: {len(result['errors'])}", file=sys.stderr)
        for error in result["errors"][:20]:
            print(error, file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command_name", required=True)

    record = sub.add_parser("record", help="append one cakebench run to history")
    record.add_argument("--out-dir", required=True)
    record.add_argument("--history-root", default=str(DEFAULT_HISTORY_ROOT))
    record.add_argument("--scx-repo", default=str(DEFAULT_SCX_REPO))
    record.add_argument("--bench-repo", default=str(DEFAULT_BENCH_REPO))
    record.add_argument("--benchmark", default="")
    record.add_argument("--scheduler", default="scx_cake")
    record.add_argument("--capture", default="")
    record.add_argument("--hypothesis", default="")
    record.add_argument("--mutation-id", default="")
    record.add_argument("--mutation-kind", default="")
    record.add_argument("command", nargs=argparse.REMAINDER)
    record.set_defaults(func=cmd_record)

    rebuild_cmd = sub.add_parser("rebuild", help="rebuild generated JSON and HTML from runs.jsonl")
    rebuild_cmd.add_argument("--history-root", default=str(DEFAULT_HISTORY_ROOT))
    rebuild_cmd.set_defaults(func=cmd_rebuild)

    import_cmd = sub.add_parser("import-old", help="backfill existing runs/single and matrix analysis TSVs")
    import_cmd.add_argument("--runs-root", default=str(DEFAULT_BENCH_REPO / "runs"))
    import_cmd.add_argument("--history-root", default=str(DEFAULT_HISTORY_ROOT))
    import_cmd.add_argument("--scx-repo", default=str(DEFAULT_SCX_REPO))
    import_cmd.add_argument("--bench-repo", default=str(DEFAULT_BENCH_REPO))
    import_cmd.add_argument("--single-only", action="store_true")
    import_cmd.add_argument("--matrix-only", action="store_true")
    import_cmd.add_argument("--dry-run", action="store_true")
    import_cmd.set_defaults(func=cmd_import_old)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
