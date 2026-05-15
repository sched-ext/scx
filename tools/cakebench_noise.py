#!/usr/bin/env python3
"""Capture host-noise evidence around cakebench runs.

The sampler is intentionally local and daemonless. It reads /proc twice per
sample, estimates per-process CPU use from tick deltas, and writes compact JSON
and Markdown artifacts under <run>/noise so the benchmark history can explain
likely background interference.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any


CLK_TCK = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK"))
CPU_COUNT = os.cpu_count() or 1
SCHEMA_VERSION = 1

BENCHMARK_MARKERS = (
    "stress-ng",
    "perf ",
    "/perf",
    "cakebench",
    "scx_cake_bench",
    "scx_cake",
    "scx_cosmos",
    "scx_flash",
    "scx_pandemonium",
    "scx_lavd",
    "scx_bpfland",
    "scx_rusty",
    "sched_ext",
)

TOOLING_MARKERS = (
    "cargo",
    "rustc",
    "clang",
    "gcc",
    "cc1",
    "ld.lld",
    "lld",
    "mold",
    "make",
    "ninja",
    "cmake",
)

KNOWN_NOISE_MARKERS = {
    "browser": ("firefox", "chrome", "chromium", "brave", "vivaldi", "librewolf", "web content"),
    "chat": ("discord", "vesktop", "slack", "teams"),
    "ide": (" code ", "/code", "codium", "jetbrains", "idea", "clion", "rustrover"),
    "game": ("steam", "gamescope", "wine", "proton", "lutris", "heroic", "mangohud"),
    "media": ("obs", "ffmpeg", "handbrake", "blender", "vlc", "mpv"),
    "vm_container": ("qemu", "virtualbox", "docker", "podman", "containerd", "buildkitd"),
    "ai_local": ("ollama", "llama-server", "comfyui", "python launch.py"),
    "index_backup": (
        "baloo",
        "tracker",
        "updatedb",
        "packagekit",
        "pacman",
        "rsync",
        "borg",
        "restic",
        "snapper",
        "timeshift",
    ),
}

KERNEL_MARKERS = (
    "kworker",
    "ksoftirqd",
    "rcu",
    "migration",
    "watchdog",
    "kswapd",
    "kcompactd",
    "irq/",
    "jbd2",
)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return ""


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return b""


def parse_status(path: Path) -> dict[str, int]:
    data: dict[str, int] = {"rss_kib": 0, "threads": 0, "uid": -1}
    for line in read_text(path).splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                data["rss_kib"] = int(parts[1])
        elif line.startswith("Threads:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                data["threads"] = int(parts[1])
        elif line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                data["uid"] = int(parts[1])
    return data


def parse_proc_stat(pid_dir: Path) -> dict[str, Any] | None:
    raw = read_text(pid_dir / "stat")
    if not raw:
        return None
    try:
        left, right = raw.rsplit(")", 1)
        comm = left.split("(", 1)[1]
        fields = right.strip().split()
        state = fields[0]
        ppid = int(fields[1])
        utime = int(fields[11])
        stime = int(fields[12])
    except (IndexError, ValueError):
        return None

    cmdline_bytes = read_bytes(pid_dir / "cmdline")
    cmdline = cmdline_bytes.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
    status = parse_status(pid_dir / "status")
    return {
        "pid": int(pid_dir.name),
        "ppid": ppid,
        "comm": comm,
        "cmdline": cmdline,
        "state": state,
        "ticks": utime + stime,
        "rss_kib": status["rss_kib"],
        "threads": status["threads"],
        "uid": status["uid"],
        "kernel_thread": not bool(cmdline),
    }


def read_proc_snapshot() -> dict[int, dict[str, Any]]:
    procs: dict[int, dict[str, Any]] = {}
    proc = Path("/proc")
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        parsed = parse_proc_stat(pid_dir)
        if parsed is not None:
            procs[parsed["pid"]] = parsed
    return procs


def read_loadavg() -> dict[str, Any]:
    raw = read_text(Path("/proc/loadavg")).split()
    if len(raw) < 5:
        return {}
    running = raw[3].split("/", 1)
    return {
        "load1": float(raw[0]),
        "load5": float(raw[1]),
        "load15": float(raw[2]),
        "load1_per_cpu": float(raw[0]) / CPU_COUNT,
        "running_tasks": int(running[0]) if running and running[0].isdigit() else None,
        "total_tasks": int(running[1]) if len(running) > 1 and running[1].isdigit() else None,
        "last_pid": int(raw[4]) if raw[4].isdigit() else None,
    }


def read_proc_stat_pressure() -> dict[str, int]:
    data = {"procs_running": 0, "procs_blocked": 0}
    for line in read_text(Path("/proc/stat")).splitlines():
        if line.startswith("procs_running "):
            data["procs_running"] = int(line.split()[1])
        elif line.startswith("procs_blocked "):
            data["procs_blocked"] = int(line.split()[1])
    return data


def read_meminfo() -> dict[str, int]:
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    data: dict[str, int] = {}
    for line in read_text(Path("/proc/meminfo")).splitlines():
        key, _, rest = line.partition(":")
        if key not in wanted:
            continue
        parts = rest.split()
        if parts and parts[0].isdigit():
            data[f"{key}_kib"] = int(parts[0])
    return data


def read_psi(kind: str) -> dict[str, dict[str, float | int]]:
    path = Path("/proc/pressure") / kind
    data: dict[str, dict[str, float | int]] = {}
    for line in read_text(path).splitlines():
        parts = line.split()
        if not parts:
            continue
        bucket = parts[0]
        values: dict[str, float | int] = {}
        for item in parts[1:]:
            key, _, raw = item.partition("=")
            if key == "total":
                try:
                    values[key] = int(raw)
                except ValueError:
                    pass
            else:
                try:
                    values[key] = float(raw)
                except ValueError:
                    pass
        data[bucket] = values
    return data


def contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def categorize_process(proc: dict[str, Any], *, benchmark: str, scheduler: str, self_pid: int) -> tuple[str, str]:
    pid = int(proc.get("pid", -1))
    comm = str(proc.get("comm", ""))
    cmdline = str(proc.get("cmdline", ""))
    text = f" {comm} {cmdline} ".lower()
    scheduler_text = scheduler.lower()
    benchmark_text = benchmark.lower()

    if pid == self_pid:
        return "sampler", "cakebench_noise"
    if proc.get("kernel_thread") or contains_any(comm.lower(), KERNEL_MARKERS):
        return "kernel", "kernel_thread"
    if scheduler_text and scheduler_text in text:
        return "benchmark", "scheduler"
    if benchmark_text and benchmark_text in text:
        return "benchmark", "benchmark"
    if contains_any(text, BENCHMARK_MARKERS):
        return "benchmark", "benchmark_tool"
    if contains_any(text, TOOLING_MARKERS):
        return "tooling", "build_tool"
    for label, markers in KNOWN_NOISE_MARKERS.items():
        if contains_any(text, markers):
            return "external", label
    return "external", "other"


def collect_sample(sample_secs: float, *, benchmark: str, scheduler: str) -> dict[str, Any]:
    sample_secs = max(0.05, sample_secs)
    before = read_proc_snapshot()
    start = time.monotonic()
    time.sleep(sample_secs)
    elapsed = max(time.monotonic() - start, 0.001)
    after = read_proc_snapshot()

    self_pid = os.getpid()
    totals = {"benchmark": 0.0, "tooling": 0.0, "kernel": 0.0, "external": 0.0, "sampler": 0.0}
    processes: list[dict[str, Any]] = []
    for pid, proc in after.items():
        old = before.get(pid)
        delta_ticks = max(0, int(proc["ticks"]) - int(old["ticks"])) if old else 0
        cpu_pct = (delta_ticks / CLK_TCK) / elapsed * 100.0
        category, reason = categorize_process(proc, benchmark=benchmark, scheduler=scheduler, self_pid=self_pid)
        totals[category] = totals.get(category, 0.0) + cpu_pct
        if cpu_pct < 0.10 and category not in {"external", "kernel"}:
            continue
        processes.append(
            {
                "pid": pid,
                "ppid": proc.get("ppid", 0),
                "comm": proc.get("comm", ""),
                "cmdline": proc.get("cmdline", "") or f"[{proc.get('comm', '')}]",
                "state": proc.get("state", ""),
                "cpu_pct": round(cpu_pct, 3),
                "rss_kib": proc.get("rss_kib", 0),
                "threads": proc.get("threads", 0),
                "category": category,
                "reason": reason,
            }
        )

    processes.sort(key=lambda row: row["cpu_pct"], reverse=True)
    return {
        "created_utc": utc_now(),
        "elapsed_secs": round(elapsed, 4),
        "cpu_count": CPU_COUNT,
        "totals_cpu_pct": {key: round(value, 3) for key, value in totals.items()},
        "loadavg": read_loadavg(),
        "proc_stat": read_proc_stat_pressure(),
        "memory": read_meminfo(),
        "psi": {
            "cpu": read_psi("cpu"),
            "memory": read_psi("memory"),
            "io": read_psi("io"),
        },
        "processes": processes[:80],
    }


def aggregate_processes(samples: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for sample in samples:
        for proc in sample.get("processes", []):
            if proc.get("category") != category:
                continue
            key = f"{proc.get('comm', '')}|{str(proc.get('cmdline', ''))[:180]}"
            item = by_key.setdefault(
                key,
                {
                    "comm": proc.get("comm", ""),
                    "cmdline": proc.get("cmdline", ""),
                    "reason": proc.get("reason", ""),
                    "pid": proc.get("pid", 0),
                    "samples": 0,
                    "sum_cpu_pct": 0.0,
                    "max_cpu_pct": 0.0,
                    "max_rss_kib": 0,
                },
            )
            cpu_pct = float(proc.get("cpu_pct", 0.0))
            item["samples"] += 1
            item["sum_cpu_pct"] += cpu_pct
            item["max_cpu_pct"] = max(float(item["max_cpu_pct"]), cpu_pct)
            item["max_rss_kib"] = max(int(item["max_rss_kib"]), int(proc.get("rss_kib", 0)))

    rows = []
    for item in by_key.values():
        samples_count = max(1, int(item.pop("samples")))
        sum_cpu = float(item.pop("sum_cpu_pct"))
        item["samples"] = samples_count
        item["avg_cpu_pct"] = round(sum_cpu / samples_count, 3)
        item["max_cpu_pct"] = round(float(item["max_cpu_pct"]), 3)
        rows.append(item)
    rows.sort(key=lambda row: (row["max_cpu_pct"], row["avg_cpu_pct"]), reverse=True)
    return rows[:12]


def psi_value(sample: dict[str, Any], kind: str, pressure: str, field: str) -> float:
    try:
        return float(sample.get("psi", {}).get(kind, {}).get(pressure, {}).get(field, 0.0))
    except (TypeError, ValueError):
        return 0.0


def max_metric(samples: list[dict[str, Any]], getter) -> float:
    values = [float(getter(sample) or 0.0) for sample in samples]
    return max(values) if values else 0.0


def avg_metric(samples: list[dict[str, Any]], getter) -> float:
    values = [float(getter(sample) or 0.0) for sample in samples]
    return sum(values) / len(values) if values else 0.0


def summarize_samples(
    samples: list[dict[str, Any]],
    *,
    phase: str,
    benchmark: str,
    scheduler: str,
    started_utc: str | None = None,
) -> dict[str, Any]:
    started = started_utc or (samples[0]["created_utc"] if samples else utc_now())
    ended = samples[-1]["created_utc"] if samples else started
    duration = sum(float(sample.get("elapsed_secs", 0.0)) for sample in samples)
    top_external = aggregate_processes(samples, "external")
    top_kernel = aggregate_processes(samples, "kernel")
    top_tooling = aggregate_processes(samples, "tooling")

    max_external = max_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("external", 0.0))
    avg_external = avg_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("external", 0.0))
    max_kernel = max_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("kernel", 0.0))
    avg_kernel = avg_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("kernel", 0.0))
    max_benchmark = max_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("benchmark", 0.0))
    avg_benchmark = avg_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("benchmark", 0.0))
    max_tooling = max_metric(samples, lambda s: s.get("totals_cpu_pct", {}).get("tooling", 0.0))
    top_external_cpu = top_external[0]["max_cpu_pct"] if top_external else 0.0
    cpu_psi_avg10 = max_metric(samples, lambda s: psi_value(s, "cpu", "some", "avg10"))
    mem_psi_avg10 = max_metric(samples, lambda s: psi_value(s, "memory", "some", "avg10"))
    io_psi_avg10 = max_metric(samples, lambda s: psi_value(s, "io", "some", "avg10"))
    blocked = max_metric(samples, lambda s: s.get("proc_stat", {}).get("procs_blocked", 0))
    load1_per_cpu = max_metric(samples, lambda s: s.get("loadavg", {}).get("load1_per_cpu", 0.0))
    benchmark_saturated = avg_benchmark >= (CPU_COUNT * 50.0)
    cpu_psi_noise = 0.0 if benchmark_saturated else cpu_psi_avg10

    severity = "clean"
    if (
        max_external >= 100.0
        or top_external_cpu >= 75.0
        or io_psi_avg10 >= 5.0
        or cpu_psi_noise >= 10.0
        or mem_psi_avg10 >= 5.0
        or blocked >= 2.0
    ):
        severity = "noisy"
    elif (
        max_external >= 25.0
        or top_external_cpu >= 20.0
        or io_psi_avg10 >= 1.0
        or cpu_psi_noise >= 3.0
        or mem_psi_avg10 >= 1.0
        or (max_external >= 5.0 and load1_per_cpu >= 1.10)
    ):
        severity = "warn"
    elif max_external >= 5.0 or top_external_cpu >= 5.0 or max_kernel >= 50.0:
        severity = "low"

    score = max_external + top_external_cpu + io_psi_avg10 * 8.0 + mem_psi_avg10 * 8.0 + cpu_psi_noise * 4.0
    known_noise = [
        {
            "comm": row["comm"],
            "reason": row["reason"],
            "max_cpu_pct": row["max_cpu_pct"],
            "cmdline": row["cmdline"],
        }
        for row in top_external
        if row.get("reason") not in {"other", ""}
    ][:8]

    return {
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now(),
        "started_utc": started,
        "ended_utc": ended,
        "hostname": socket.gethostname(),
        "phase": phase,
        "benchmark": benchmark,
        "scheduler": scheduler,
        "cpu_count": CPU_COUNT,
        "sample_count": len(samples),
        "sampled_secs": round(duration, 3),
        "severity": severity,
        "score": round(score, 3),
        "max_external_cpu_pct": round(max_external, 3),
        "avg_external_cpu_pct": round(avg_external, 3),
        "max_kernel_cpu_pct": round(max_kernel, 3),
        "avg_kernel_cpu_pct": round(avg_kernel, 3),
        "max_benchmark_cpu_pct": round(max_benchmark, 3),
        "avg_benchmark_cpu_pct": round(avg_benchmark, 3),
        "max_tooling_cpu_pct": round(max_tooling, 3),
        "max_top_external_cpu_pct": round(top_external_cpu, 3),
        "benchmark_saturated": benchmark_saturated,
        "cpu_psi_counted_as_noise": not benchmark_saturated,
        "max_cpu_psi_avg10": round(cpu_psi_avg10, 3),
        "max_memory_psi_avg10": round(mem_psi_avg10, 3),
        "max_io_psi_avg10": round(io_psi_avg10, 3),
        "max_procs_blocked": int(blocked),
        "max_load1_per_cpu": round(load1_per_cpu, 3),
        "top_external": top_external,
        "top_kernel": top_kernel,
        "top_tooling": top_tooling,
        "known_noise": known_noise,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# cakebench Noise Summary",
        "",
        f"- Phase: {summary.get('phase', '')}",
        f"- Severity: {summary.get('severity', 'unknown')}",
        f"- Noise score: {summary.get('score', 0)}",
        f"- Samples: {summary.get('sample_count', 0)} over {summary.get('sampled_secs', 0)}s",
        f"- External CPU max/avg: {summary.get('max_external_cpu_pct', 0)}% / {summary.get('avg_external_cpu_pct', 0)}%",
        f"- Kernel CPU max/avg: {summary.get('max_kernel_cpu_pct', 0)}% / {summary.get('avg_kernel_cpu_pct', 0)}%",
        f"- Benchmark CPU max/avg: {summary.get('max_benchmark_cpu_pct', 0)}% / {summary.get('avg_benchmark_cpu_pct', 0)}%",
        f"- Benchmark saturated: {summary.get('benchmark_saturated', False)}",
        f"- CPU PSI counted as noise: {summary.get('cpu_psi_counted_as_noise', True)}",
        f"- CPU PSI avg10 max: {summary.get('max_cpu_psi_avg10', 0)}",
        f"- IO PSI avg10 max: {summary.get('max_io_psi_avg10', 0)}",
        f"- Memory PSI avg10 max: {summary.get('max_memory_psi_avg10', 0)}",
        f"- Load1 per CPU max: {summary.get('max_load1_per_cpu', 0)}",
        "",
    ]
    for key, title in (
        ("top_external", "Top External CPU"),
        ("known_noise", "Known Noise Matches"),
        ("top_tooling", "Benchmark Tooling / Build CPU"),
        ("top_kernel", "Kernel Thread CPU"),
    ):
        rows = summary.get(key, [])
        lines.extend([f"## {title}", ""])
        if not rows:
            lines.extend(["None observed.", ""])
            continue
        lines.append("| max cpu % | avg cpu % | reason | command |")
        lines.append("|---:|---:|---|---|")
        for row in rows[:8]:
            command = str(row.get("cmdline", row.get("comm", ""))).replace("|", "\\|")
            if len(command) > 140:
                command = command[:137] + "..."
            lines.append(
                f"| {row.get('max_cpu_pct', '')} | {row.get('avg_cpu_pct', '')} | "
                f"{row.get('reason', '')} | `{command}` |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary(out_dir: Path, phase: str, summary: dict[str, Any]) -> None:
    noise_dir = out_dir / "noise"
    noise_dir.mkdir(parents=True, exist_ok=True)
    write_json(noise_dir / f"{phase}.json", summary)
    (noise_dir / f"{phase}.md").write_text(render_markdown(summary), encoding="utf-8")
    if phase in {"monitor", "summary"}:
        write_json(noise_dir / "summary.json", summary)
        (noise_dir / "summary.md").write_text(render_markdown(summary), encoding="utf-8")


def run_snapshot(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    sample = collect_sample(args.sample_secs, benchmark=args.benchmark, scheduler=args.scheduler)
    summary = summarize_samples(
        [sample],
        phase=args.phase,
        benchmark=args.benchmark,
        scheduler=args.scheduler,
    )
    write_summary(out_dir, args.phase, summary)
    print(f"noise {summary['severity']}: {out_dir / 'noise' / (args.phase + '.md')}")
    return 0


def run_monitor(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    noise_dir = out_dir / "noise"
    noise_dir.mkdir(parents=True, exist_ok=True)
    timeline = noise_dir / "timeline.jsonl"
    samples: list[dict[str, Any]] = []
    stopped = False
    started_utc = utc_now()

    def request_stop(signum, frame) -> None:  # noqa: ARG001
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    with timeline.open("a", encoding="utf-8") as f:
        while not stopped:
            loop_start = time.monotonic()
            sample = collect_sample(args.sample_secs, benchmark=args.benchmark, scheduler=args.scheduler)
            samples.append(sample)
            f.write(json.dumps(sample, sort_keys=True) + "\n")
            f.flush()
            remaining = args.interval - (time.monotonic() - loop_start)
            if remaining > 0:
                time.sleep(remaining)

    if not samples:
        samples.append(collect_sample(args.sample_secs, benchmark=args.benchmark, scheduler=args.scheduler))
    summary = summarize_samples(
        samples,
        phase="monitor",
        benchmark=args.benchmark,
        scheduler=args.scheduler,
        started_utc=started_utc,
    )
    write_summary(out_dir, "monitor", summary)
    return 0


def run_summarize(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    timeline = out_dir / "noise" / "timeline.jsonl"
    samples: list[dict[str, Any]] = []
    if timeline.is_file():
        for line in timeline.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not samples:
        print(f"error: no timeline samples found at {timeline}", file=sys.stderr)
        return 1
    summary = summarize_samples(
        samples,
        phase="monitor",
        benchmark=args.benchmark,
        scheduler=args.scheduler,
        started_utc=samples[0].get("created_utc", utc_now()),
    )
    write_summary(out_dir, "monitor", summary)
    print(f"noise {summary['severity']}: {out_dir / 'noise' / 'summary.md'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    snapshot = sub.add_parser("snapshot", help="take one short host-noise sample")
    snapshot.add_argument("--out-dir", required=True)
    snapshot.add_argument("--phase", default="manual")
    snapshot.add_argument("--sample-secs", type=float, default=1.0)
    snapshot.add_argument("--benchmark", default="")
    snapshot.add_argument("--scheduler", default="")
    snapshot.set_defaults(func=run_snapshot)

    monitor = sub.add_parser("monitor", help="sample host noise until SIGTERM")
    monitor.add_argument("--out-dir", required=True)
    monitor.add_argument("--interval", type=float, default=1.0)
    monitor.add_argument("--sample-secs", type=float, default=0.25)
    monitor.add_argument("--benchmark", default="")
    monitor.add_argument("--scheduler", default="")
    monitor.set_defaults(func=run_monitor)

    summarize = sub.add_parser("summarize", help="rebuild summary from an existing timeline.jsonl")
    summarize.add_argument("--out-dir", required=True)
    summarize.add_argument("--benchmark", default="")
    summarize.add_argument("--scheduler", default="")
    summarize.set_defaults(func=run_summarize)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
