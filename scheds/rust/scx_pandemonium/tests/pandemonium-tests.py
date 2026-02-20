#!/usr/bin/env python3
"""
PANDEMONIUM bench-scale orchestrator.

Unified throughput + latency benchmark with Prometheus metrics output.

Usage:
    ./tests/pandemonium-tests.py bench-scale
    ./tests/pandemonium-tests.py bench-scale --iterations 3
    ./tests/pandemonium-tests.py bench-scale --schedulers scx_rusty,scx_bpfland
"""

import argparse
import math
import os
import traceback
import re
import signal
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
from pandemonium_common import (
    SCRIPT_DIR, TARGET_DIR, LOG_DIR, ARCHIVE_DIR, BINARY, SOURCE_PATTERNS,
    get_version, get_git_info,
    log_info, log_warn, log_error, run_cmd,
    has_root_owned_files, clean_root_files, check_sources_changed, build,
)


# CONFIGURATION

SCX_OPS = Path("/sys/kernel/sched_ext/root/ops")
DEFAULT_EXTERNALS = ["scx_bpfland"]


# DMESG CAPTURE

def dmesg_baseline() -> int:
    """Snapshot current dmesg line count for later diffing."""
    r = subprocess.run(["sudo", "dmesg"], capture_output=True, text=True)
    if r.returncode != 0:
        return 0
    return len(r.stdout.splitlines())


def capture_dmesg(baseline: int, stamp: str) -> None:
    """Capture new dmesg lines since baseline, save to file, print summary."""
    r = subprocess.run(["sudo", "dmesg"], capture_output=True, text=True)
    if r.returncode != 0:
        log_warn("Could not capture dmesg")
        return

    lines = r.stdout.splitlines()
    new_lines = lines[baseline:] if baseline < len(lines) else lines

    if not new_lines:
        log_info("dmesg: no new kernel messages")
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    dmesg_path = LOG_DIR / f"dmesg-{stamp}.log"
    dmesg_path.write_text("\n".join(new_lines) + "\n")

    keywords = ["sched_ext", "pandemonium", "non-existent DSQ", "zero slice",
                "panic", "BUG:", "RIP:", "Oops", "Call Trace"]
    filtered = [l for l in new_lines
                if any(kw in l for kw in keywords)]

    if not filtered:
        log_info(f"dmesg: {len(new_lines)} messages, no scheduler issues")
        return

    crashes = sum(1 for l in filtered
                  if "non-existent DSQ" in l or "runtime error" in l)
    zero_slices = sum(1 for l in filtered if "zero slice" in l)
    panics = sum(1 for l in filtered
                 if "panic" in l or "BUG:" in l or "RIP:" in l)

    if panics:
        log_error(f"dmesg: KERNEL PANIC/BUG -- see {dmesg_path}")
    if crashes:
        log_warn(f"dmesg: {crashes} scheduler crash(es)")
    if zero_slices:
        log_warn(f"dmesg: {zero_slices} zero-slice warning(s)")

    for line in filtered:
        log_info(f"  {line.strip()}")

    log_info(f"dmesg: {len(new_lines)} messages saved to {dmesg_path}")


# BUILD HELPERS

def fix_ownership():
    uid = os.getuid()
    gid = os.getgid()
    log_info(f"Fixing ownership to {uid}:{gid}...")
    for d in [TARGET_DIR, LOG_DIR]:
        if d.exists():
            subprocess.run(
                ["sudo", "chown", "-R", f"{uid}:{gid}", str(d)],
                capture_output=True,
            )


def nuke_stale_build():
    """Nuke the build dir if any source file is newer than the binary."""
    if not TARGET_DIR.exists():
        return
    if not BINARY.exists():
        log_info(f"Nuking build directory (no binary): {TARGET_DIR}")
        subprocess.run(["sudo", "rm", "-rf", str(TARGET_DIR)],
                       capture_output=True)
        return
    bin_mtime = BINARY.stat().st_mtime
    for pattern in SOURCE_PATTERNS:
        for src in SCRIPT_DIR.glob(pattern):
            if src.stat().st_mtime > bin_mtime:
                log_warn(f"Source changed: {src.relative_to(SCRIPT_DIR)}")
                log_info(f"Nuking stale build directory: {TARGET_DIR}")
                subprocess.run(["sudo", "rm", "-rf", str(TARGET_DIR)],
                               capture_output=True)
                return


# SCHEDULER PROCESS MANAGEMENT

def is_scx_active() -> bool:
    try:
        return bool(SCX_OPS.read_text().strip())
    except (FileNotFoundError, PermissionError):
        return False


def scx_scheduler_name() -> str:
    try:
        return SCX_OPS.read_text().strip()
    except (FileNotFoundError, PermissionError):
        return ""


def wait_for_activation(timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_scx_active():
            return True
        time.sleep(0.1)
    return False


def wait_for_deactivation(timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not is_scx_active():
            return True
        time.sleep(0.2)
    return False


def find_scheduler(name: str) -> str | None:
    return shutil.which(name)


class SchedulerProcess:
    """RAII-style guard for a running sched_ext scheduler."""

    def __init__(self, proc: subprocess.Popen, name: str,
                 stdout_path: str | None = None,
                 stderr_path: str | None = None):
        self.proc = proc
        self.name = name
        self.pgid = os.getpgid(proc.pid)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path

    def stop(self):
        if self.proc.poll() is not None:
            return
        try:
            os.killpg(self.pgid, signal.SIGINT)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return
            time.sleep(0.05)
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait()

    def drain_stdout(self) -> str:
        """Read all stdout captured to file (call after stop)."""
        if self.stdout_path:
            try:
                return Path(self.stdout_path).read_text()
            except (FileNotFoundError, PermissionError):
                pass
        return ""

    def read_stderr(self, limit: int = 4000) -> str:
        if self.stderr_path:
            try:
                return Path(self.stderr_path).read_text()[:limit]
            except (FileNotFoundError, PermissionError):
                pass
        return ""

    def cleanup(self):
        for p in [self.stdout_path, self.stderr_path]:
            if p:
                try:
                    os.unlink(p)
                except (FileNotFoundError, PermissionError):
                    pass

    def __del__(self):
        self.stop()
        self.cleanup()


def start_scheduler(cmd: list[str], name: str) -> SchedulerProcess:
    """Spawn a scheduler subprocess in its own process group.
    Stdout and stderr go to files to avoid pipe buffer overflow."""
    full_cmd = ["sudo"] + cmd
    log_info(f"Starting: {' '.join(full_cmd)}")
    bin_path = cmd[0] if cmd else ""
    if bin_path and not os.path.exists(bin_path):
        log_error(f"Binary not found: {bin_path}")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = str(LOG_DIR / f"sched-{name}-{os.getpid()}.stdout")
    stdout_f = open(stdout_path, "w")
    stderr_path = str(LOG_DIR / f"sched-{name}-{os.getpid()}.stderr")
    stderr_f = open(stderr_path, "w")
    proc = subprocess.Popen(
        full_cmd,
        stdout=stdout_f,
        stderr=stderr_f,
        preexec_fn=os.setpgrp,
    )
    stdout_f.close()
    stderr_f.close()
    return SchedulerProcess(proc, name, stdout_path, stderr_path)


def start_and_wait(cmd: list[str], name: str,
                   settle_secs: float = 2.0) -> SchedulerProcess | None:
    """Start a scheduler, wait for sched_ext activation. Returns None on failure."""
    guard = start_scheduler(cmd, name)
    if not wait_for_activation(10.0):
        log_warn(f"{name} did not activate within 10s -- skipping")
        exited = guard.proc.poll() is not None
        if exited:
            log_error(f"{name} process exited early (code {guard.proc.returncode})")
        else:
            log_warn(f"{name} process still running but sched_ext not active")
        stderr = guard.read_stderr()
        if stderr.strip():
            for line in stderr.strip().splitlines()[:30]:
                log_error(f"  {line}")
        guard.stop()
        wait_for_deactivation(5.0)
        return None
    log_info(f"{name} is active")
    time.sleep(settle_secs)
    return guard


def stop_and_wait(guard: SchedulerProcess | None) -> str:
    """Stop a scheduler, wait for deactivation. Returns captured stdout."""
    if guard is None:
        return ""
    guard.stop()
    stdout = guard.drain_stdout()
    if not wait_for_deactivation(5.0):
        log_warn(f"sched_ext still active after stopping {guard.name}")
    time.sleep(1)
    return stdout


# CPU HOTPLUG

def _parse_cpu_range(path: str) -> int:
    try:
        raw = Path(path).read_text().strip()
    except (FileNotFoundError, PermissionError):
        return os.cpu_count() or 1
    count = 0
    for r in raw.split(","):
        parts = r.split("-")
        if len(parts) == 1 and parts[0].strip().isdigit():
            count += 1
        elif len(parts) == 2:
            try:
                count += int(parts[1]) - int(parts[0]) + 1
            except ValueError:
                pass
    return count


def get_possible_cpus() -> int:
    return _parse_cpu_range("/sys/devices/system/cpu/possible")


def get_online_cpus() -> int:
    return _parse_cpu_range("/sys/devices/system/cpu/online")


def set_cpu_online(cpu: int, online: bool) -> bool:
    if cpu == 0:
        return True
    path = f"/sys/devices/system/cpu/cpu{cpu}/online"
    value = "1" if online else "0"
    ret = subprocess.run(
        ["sudo", "tee", path],
        input=value, capture_output=True, text=True,
    )
    return ret.returncode == 0


def restrict_cpus(count: int, max_cpus: int) -> bool:
    for cpu in range(count, max_cpus):
        if not set_cpu_online(cpu, False):
            log_warn(f"Failed to offline CPU {cpu}")
            return False
    return True


def restore_all_cpus(max_cpus: int):
    for cpu in range(1, max_cpus):
        set_cpu_online(cpu, True)


class CpuGuard:
    """Context manager that restores all CPUs on exit."""
    def __init__(self, max_cpus: int):
        self.max_cpus = max_cpus

    def __enter__(self):
        return self

    def __exit__(self, *args):
        restore_all_cpus(self.max_cpus)


def compute_core_counts(max_cpus: int) -> list[int]:
    points = [n for n in [2, 4, 8, 16, 32, 64] if n <= max_cpus]
    if max_cpus not in points:
        points.append(max_cpus)
    return points


# STATISTICS

def mean_stdev(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, math.sqrt(variance)


def percentile(values: list[float], pct: float) -> float:
    """Compute percentile (0-100) using nearest-rank method."""
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(int(math.ceil(pct / 100.0 * len(s))) - 1, len(s) - 1))
    return s[k]


# MEASUREMENT

def timed_run(cmd: str, clean_cmd: str | None = None) -> float | None:
    """Run a shell command, return wall-clock seconds or None on failure."""
    if clean_cmd:
        subprocess.run(["sh", "-c", clean_cmd],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_info(f"Running: {cmd}")
    start = time.monotonic()
    result = subprocess.run(["sh", "-c", cmd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    elapsed = time.monotonic() - start
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")[:500]
        log_error(f"Command failed (exit {result.returncode}): {stderr}")
        return None
    log_info(f"Completed in {elapsed:.2f}s")
    return elapsed


def parse_probe_output(stdout_text: str) -> dict:
    """Parse probe stdout (one overshoot_us per line) into latency stats."""
    values = []
    for line in stdout_text.splitlines():
        line = line.strip()
        if line and line.lstrip("-").isdigit():
            values.append(float(line))
    if not values:
        return {"samples": 0, "median_us": 0, "p99_us": 0, "worst_us": 0}
    return {
        "samples": len(values),
        "median_us": int(percentile(values, 50)),
        "p99_us": int(percentile(values, 99)),
        "worst_us": int(max(values)),
    }


def measure_latency(binary: Path, n_cpus: int, iterations: int = 1,
                    duration_secs: int = 15, warmup_secs: int = 3) -> dict:
    """Spawn pinned stress workers on all cores + unpinned probe.

    Stress workers saturate every CPU. Probe floats -- the scheduler
    decides where to place it, measuring real preemption latency under
    full load (no reserved core).

    Multiple iterations pool all samples for final percentile calculation.
    """
    if n_cpus < 1:
        log_warn("Need at least 1 CPU for latency measurement")
        return {"samples": 0, "median_us": 0, "p99_us": 0, "worst_us": 0}

    stress_cpus = list(range(0, n_cpus))

    log_info(f"Latency: {len(stress_cpus)} stress workers, probe unpinned, "
             f"{iterations} iteration(s)")

    workers = []
    for cpu in stress_cpus:
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    # Warmup probe (discard output, let scheduler classify workload)
    log_info(f"Warmup: {warmup_secs}s")
    warmup = subprocess.Popen(
        [str(binary), "probe"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    time.sleep(warmup_secs)
    warmup.send_signal(signal.SIGINT)
    try:
        warmup.wait(timeout=5)
    except subprocess.TimeoutExpired:
        warmup.kill()
        warmup.wait()

    # Measurement iterations (pool all samples)
    all_values: list[float] = []
    for i in range(iterations):
        log_info(f"Latency iteration {i + 1}/{iterations}: {duration_secs}s")
        probe = subprocess.Popen(
            [str(binary), "probe"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        time.sleep(duration_secs)
        probe.send_signal(signal.SIGINT)
        try:
            stdout, _ = probe.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            probe.kill()
            stdout, _ = probe.communicate()

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if line and line.lstrip("-").isdigit():
                all_values.append(float(line))

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    if not all_values:
        result = {"samples": 0, "median_us": 0, "p99_us": 0, "worst_us": 0}
    else:
        result = {
            "samples": len(all_values),
            "median_us": int(percentile(all_values, 50)),
            "p99_us": int(percentile(all_values, 99)),
            "worst_us": int(max(all_values)),
        }

    log_info(f"Latency: {result['samples']} samples, "
             f"median={result['median_us']}us, "
             f"p99={result['p99_us']}us, "
             f"worst={result['worst_us']}us")
    return result


# TELEMETRY PARSING

def parse_tick_lines(stdout_text: str) -> list[dict]:
    """Parse d/s: tick lines from scheduler stdout.

    Handles both BPF-only format (ends with [BPF]) and adaptive format
    (ends with [Light/Mixed/Heavy]).
    """
    ticks = []
    for line in stdout_text.splitlines():
        if not line.startswith("d/s:"):
            continue

        tick = {}

        # Common fields
        m = re.search(r"d/s:\s*(\d+)", line)
        if m:
            tick["dispatches"] = int(m.group(1))
        m = re.search(r"idle:\s*(\d+)%", line)
        if m:
            tick["idle_pct"] = int(m.group(1))
        m = re.search(r"shared:\s*(\d+)", line)
        if m:
            tick["shared"] = int(m.group(1))
        m = re.search(r"preempt:\s*(\d+)", line)
        if m:
            tick["preempt"] = int(m.group(1))
        m = re.search(r"keep:\s*(\d+)", line)
        if m:
            tick["keep"] = int(m.group(1))
        m = re.search(r"kick:\s*H=(\d+)\s*S=(\d+)", line)
        if m:
            tick["kick_hard"] = int(m.group(1))
            tick["kick_soft"] = int(m.group(2))
        m = re.search(r"enq:\s*W=(\d+)\s*R=(\d+)", line)
        if m:
            tick["enq_wake"] = int(m.group(1))
            tick["enq_requeue"] = int(m.group(2))
        m = re.search(r"wake:\s*(\d+)us", line)
        if m:
            tick["wake_avg_us"] = int(m.group(1))
        m = re.search(r"lat_idle:\s*(\d+)us", line)
        if m:
            tick["lat_idle_us"] = int(m.group(1))
        m = re.search(r"lat_kick:\s*(\d+)us", line)
        if m:
            tick["lat_kick_us"] = int(m.group(1))
        m = re.search(r"l2:\s*B=(\d+)%\s*I=(\d+)%\s*L=(\d+)%", line)
        if m:
            tick["l2_pct_batch"] = int(m.group(1))
            tick["l2_pct_interactive"] = int(m.group(2))
            tick["l2_pct_latcrit"] = int(m.group(3))

        # BPF-only specific
        if "[BPF]" in line:
            tick["regime"] = "BPF"
            m = re.search(r"procdb:\s*(\d+)\s", line)
            if m:
                tick["procdb_hits"] = int(m.group(1))
            m = re.search(r"guard:\s*(\d+)", line)
            if m:
                tick["guard_clamps"] = int(m.group(1))

        # Adaptive specific
        elif re.search(r"\[(Light|Mixed|Heavy)\]", line, re.IGNORECASE):
            m = re.search(r"\[(Light|Mixed|Heavy)\]", line, re.IGNORECASE)
            tick["regime"] = m.group(1)
            m = re.search(r"p99:\s*(\d+)us", line)
            if m:
                tick["p99_us"] = int(m.group(1))
            m = re.search(r"p99:.*?\[B:(\d+)\s*I:(\d+)\s*L:(\d+)\]", line)
            if m:
                tick["tier_p99_batch"] = int(m.group(1))
                tick["tier_p99_interactive"] = int(m.group(2))
                tick["tier_p99_latcrit"] = int(m.group(3))
            m = re.search(r"procdb:\s*(\d+)/(\d+)", line)
            if m:
                tick["procdb_total"] = int(m.group(1))
                tick["procdb_confident"] = int(m.group(2))
            m = re.search(r"sleep:\s*io=(\d+)%", line)
            if m:
                tick["io_pct"] = int(m.group(1))
            m = re.search(r"slice:\s*(\d+)us", line)
            if m:
                tick["slice_us"] = int(m.group(1))
            m = re.search(r"batch:\s*(\d+)us", line)
            if m:
                tick["batch_us"] = int(m.group(1))
            m = re.search(r"guard:\s*(\d+)", line)
            if m:
                tick["guard_clamps"] = int(m.group(1))

        if tick:
            ticks.append(tick)

    return ticks


def parse_knobs_line(stdout_text: str) -> dict:
    """Parse [KNOBS] summary line from scheduler stdout."""
    for line in stdout_text.splitlines():
        if "[KNOBS]" not in line:
            continue

        knobs = {}
        for m in re.finditer(r"(\w+)=(\S+)", line.split("[KNOBS]")[1]):
            k, v = m.group(1), m.group(2)
            if v == "true":
                knobs[k] = True
            elif v == "false":
                knobs[k] = False
            else:
                try:
                    knobs[k] = int(v)
                except ValueError:
                    knobs[k] = v

        # Expand ticks=L:5/M:12/H:3
        if "ticks" in knobs and isinstance(knobs["ticks"], str):
            ticks_str = knobs.pop("ticks")
            for part in ticks_str.split("/"):
                if ":" in part:
                    prefix, val = part.split(":", 1)
                    label = {"L": "ticks_light", "M": "ticks_mixed",
                             "H": "ticks_heavy"}.get(prefix)
                    if label:
                        try:
                            knobs[label] = int(val)
                        except ValueError:
                            pass

        # Expand l2_hit=B:75%/I:60%/L:80%
        if "l2_hit" in knobs and isinstance(knobs["l2_hit"], str):
            l2_str = knobs.pop("l2_hit")
            for part in l2_str.split("/"):
                if ":" in part:
                    prefix, val = part.split(":", 1)
                    label = {"B": "l2_hit_batch", "I": "l2_hit_interactive",
                             "L": "l2_hit_latcrit"}.get(prefix)
                    if label:
                        try:
                            knobs[label] = int(val.rstrip("%"))
                        except ValueError:
                            pass

        return knobs

    return {}


def aggregate_ticks(ticks: list[dict]) -> dict:
    """Aggregate tick data into summary statistics."""
    if not ticks:
        return {}

    agg = {}
    numeric_keys = set()
    for t in ticks:
        for k, v in t.items():
            if isinstance(v, (int, float)) and k != "regime":
                numeric_keys.add(k)

    for key in sorted(numeric_keys):
        values = [float(t[key]) for t in ticks if key in t]
        if not values:
            continue
        agg[key] = {
            "mean": round(sum(values) / len(values), 1),
            "p99": round(percentile(values, 99), 1),
            "last": values[-1],
        }

    # Regime distribution
    regimes = [t.get("regime", "") for t in ticks if t.get("regime")]
    if regimes:
        agg["regime_counts"] = {}
        for r in regimes:
            agg["regime_counts"][r] = agg["regime_counts"].get(r, 0) + 1

    return agg


# PROMETHEUS OUTPUT

def write_prometheus(data: dict, stamp: str) -> Path:
    """Write Prometheus exposition format (.prom) to ~/.cache/pandemonium/."""
    lines = []
    emitted_types = set()

    def gauge(name: str, help_text: str, value, labels: dict | None = None):
        if name not in emitted_types:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            emitted_types.add(name)
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

    # Metadata
    version = data.get("version", "unknown")
    git_commit = data.get("git_commit", "unknown")
    git_dirty = "true" if data.get("git_dirty") else "false"
    gauge("pandemonium_bench_info", "Build and run metadata", 1,
          {"version": version, "git_commit": git_commit, "git_dirty": git_dirty})
    gauge("pandemonium_bench_timestamp_seconds", "Benchmark start time",
          int(datetime.strptime(stamp, "%Y%m%d-%H%M%S").timestamp()))
    gauge("pandemonium_bench_iterations", "Number of throughput iterations",
          data.get("iterations", 0))
    gauge("pandemonium_bench_max_cpus", "Maximum CPUs available",
          data.get("max_cpus", 0))

    results = data.get("results", {})
    for cores_str, schedulers in sorted(results.items(), key=lambda x: int(x[0])):
        cores = cores_str

        for sched_name, sched_data in schedulers.items():
            labels = {"scheduler": sched_name, "cores": cores}

            # Latency metrics
            lat = sched_data.get("latency", {})
            if lat.get("samples", 0) > 0:
                gauge("pandemonium_bench_latency_samples",
                      "Number of latency samples collected",
                      lat["samples"], labels)
                gauge("pandemonium_bench_latency_median_us",
                      "Median wakeup latency",
                      lat["median_us"], labels)
                gauge("pandemonium_bench_latency_p99_us",
                      "P99 wakeup latency",
                      lat["p99_us"], labels)
                gauge("pandemonium_bench_latency_worst_us",
                      "Worst-case wakeup latency",
                      lat["worst_us"], labels)

            # Throughput metrics
            tp = sched_data.get("throughput", {})
            if "mean_s" in tp:
                gauge("pandemonium_bench_throughput_seconds",
                      "Wall-clock workload time (mean)",
                      tp["mean_s"], labels)
                if "stdev_s" in tp:
                    gauge("pandemonium_bench_throughput_stdev_seconds",
                          "Throughput standard deviation",
                          tp["stdev_s"], labels)
                if "vs_eevdf_pct" in tp:
                    gauge("pandemonium_bench_throughput_vs_eevdf_pct",
                          "Throughput delta vs EEVDF",
                          tp["vs_eevdf_pct"], labels)

            # Scheduler telemetry (PANDEMONIUM only)
            telem = sched_data.get("telemetry", {})
            knobs = telem.get("knobs", {})
            tick_agg = telem.get("tick_aggregate", {})

            if not knobs and not tick_agg:
                continue

            mode = "BPF" if "BPF" in sched_name else "ADAPTIVE"
            telem_labels = {"mode": mode, "cores": cores}

            if knobs:
                knob_map = {
                    "slice_ns": "slice_ns",
                    "batch_slice_ns": "batch_ns",
                    "preempt_thresh_ns": "preempt_ns",
                    "cpu_bound_thresh_ns": "demotion_ns",
                    "lag_scale": "lag",
                }
                for src_key, prom_suffix in knob_map.items():
                    if src_key in knobs:
                        gauge(f"pandemonium_bench_knob_{prom_suffix}",
                              f"Final tuning knob: {prom_suffix}",
                              knobs[src_key], telem_labels)

                if "reflex" in knobs:
                    gauge("pandemonium_bench_reflex_events",
                          "Reflex tighten events",
                          knobs["reflex"], telem_labels)
                if "tightened" in knobs:
                    val = 1 if knobs["tightened"] else 0
                    gauge("pandemonium_bench_tightened",
                          "Graduated relax tighten active",
                          val, telem_labels)

                for regime_key in ["ticks_light", "ticks_mixed", "ticks_heavy"]:
                    if regime_key in knobs:
                        regime_name = regime_key.replace("ticks_", "")
                        gauge("pandemonium_bench_regime_ticks",
                              "Ticks spent in each regime",
                              knobs[regime_key],
                              {**telem_labels, "regime": regime_name})

                for l2_key in ["l2_hit_batch", "l2_hit_interactive",
                               "l2_hit_latcrit"]:
                    if l2_key in knobs:
                        tier = l2_key.replace("l2_hit_", "")
                        gauge("pandemonium_bench_l2_hit_pct",
                              "L2 cache hit rate by tier",
                              knobs[l2_key],
                              {**telem_labels, "tier": tier})

            if tick_agg:
                for field in ["idle_pct", "preempt", "guard_clamps",
                              "wake_avg_us", "p99_us"]:
                    if field in tick_agg:
                        stats = tick_agg[field]
                        gauge(f"pandemonium_bench_{field}_mean",
                              f"Mean {field} during measurement",
                              stats["mean"], telem_labels)

                regime_counts = tick_agg.get("regime_counts", {})
                for regime, count in regime_counts.items():
                    gauge("pandemonium_bench_regime_observed",
                          "Observed regime ticks during measurement",
                          count, {**telem_labels, "regime": regime})

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    version = data.get("version", "unknown")
    path = ARCHIVE_DIR / f"{version}-{stamp}.prom"
    path.write_text("\n".join(lines) + "\n")
    return path


# PROMETHEUS LIVE OUTPUT (BENCH-SYS)

_SYS_TICK_FIELDS = [
    ("dispatches", "pandemonium_bench_dispatches"),
    ("idle_pct", "pandemonium_bench_idle_pct"),
    ("shared", "pandemonium_bench_shared"),
    ("preempt", "pandemonium_bench_preempt"),
    ("keep", "pandemonium_bench_keep"),
    ("kick_hard", "pandemonium_bench_kick_hard"),
    ("kick_soft", "pandemonium_bench_kick_soft"),
    ("enq_wake", "pandemonium_bench_enq_wake"),
    ("enq_requeue", "pandemonium_bench_enq_requeue"),
    ("wake_avg_us", "pandemonium_bench_wake_us"),
    ("lat_idle_us", "pandemonium_bench_lat_idle_us"),
    ("lat_kick_us", "pandemonium_bench_lat_kick_us"),
    ("guard_clamps", "pandemonium_bench_guard_clamps"),
    ("p99_us", "pandemonium_bench_p99_us"),
    ("slice_us", "pandemonium_bench_slice_us"),
    ("batch_us", "pandemonium_bench_batch_us"),
    ("io_pct", "pandemonium_bench_io_pct"),
    ("procdb_total", "pandemonium_bench_procdb_total"),
    ("procdb_confident", "pandemonium_bench_procdb_confident"),
    ("procdb_hits", "pandemonium_bench_procdb_total"),
]

_SYS_TICK_TIERED = [
    ("pandemonium_bench_l2_hit_pct",
     [("l2_pct_batch", "batch"), ("l2_pct_interactive", "interactive"),
      ("l2_pct_latcrit", "latcrit")]),
    ("pandemonium_bench_tier_p99_us",
     [("tier_p99_batch", "batch"), ("tier_p99_interactive", "interactive"),
      ("tier_p99_latcrit", "latcrit")]),
]


def prom_sys_create(path: Path, version: str, git: dict, max_cpus: int):
    """Create .prom with metadata header and all HELP/TYPE declarations."""
    dirty = "true" if git.get("dirty") else "false"
    commit = git.get("commit", "unknown")

    decls = [
        ("pandemonium_bench_dispatches", "Dispatches per second"),
        ("pandemonium_bench_idle_pct", "Idle hit percentage"),
        ("pandemonium_bench_shared", "Shared dispatches"),
        ("pandemonium_bench_preempt", "Preemptions"),
        ("pandemonium_bench_keep", "Keep running count"),
        ("pandemonium_bench_kick_hard", "Hard kick count"),
        ("pandemonium_bench_kick_soft", "Soft kick count"),
        ("pandemonium_bench_enq_wake", "Enqueue wakeup count"),
        ("pandemonium_bench_enq_requeue", "Enqueue requeue count"),
        ("pandemonium_bench_wake_us", "Mean wakeup latency us"),
        ("pandemonium_bench_lat_idle_us", "Idle path latency us"),
        ("pandemonium_bench_lat_kick_us", "Kick path latency us"),
        ("pandemonium_bench_guard_clamps", "Guard clamp events"),
        ("pandemonium_bench_p99_us", "P99 wakeup latency us"),
        ("pandemonium_bench_slice_us", "Current time slice us"),
        ("pandemonium_bench_batch_us", "Current batch slice us"),
        ("pandemonium_bench_io_pct", "IO sleep percentage"),
        ("pandemonium_bench_procdb_total", "ProcDb profiles"),
        ("pandemonium_bench_procdb_confident", "Confident ProcDb profiles"),
        ("pandemonium_bench_l2_hit_pct", "L2 cache hit rate by tier"),
        ("pandemonium_bench_tier_p99_us", "Per-tier P99 latency us"),
        ("pandemonium_bench_knob_slice_ns", "Final knob: time slice ns"),
        ("pandemonium_bench_knob_batch_ns", "Final knob: batch slice ns"),
        ("pandemonium_bench_knob_preempt_ns", "Final knob: preempt thresh ns"),
        ("pandemonium_bench_knob_demotion_ns", "Final knob: demotion thresh ns"),
        ("pandemonium_bench_knob_lag", "Final knob: lag scale"),
        ("pandemonium_bench_reflex_events", "Reflex tighten events"),
        ("pandemonium_bench_tightened", "Graduated relax tighten active"),
        ("pandemonium_bench_regime_ticks", "Ticks spent in each regime"),
        ("pandemonium_bench_latency_samples", "Latency probe samples"),
        ("pandemonium_bench_latency_median_us", "Median probe latency us"),
        ("pandemonium_bench_latency_p99_us", "P99 probe latency us"),
        ("pandemonium_bench_latency_worst_us", "Worst probe latency us"),
    ]

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("# HELP pandemonium_bench_info Build and run metadata\n")
        f.write("# TYPE pandemonium_bench_info gauge\n")
        f.write(f'pandemonium_bench_info{{version="{version}",'
                f'git_commit="{commit}",git_dirty="{dirty}"}} 1\n')
        f.write("# HELP pandemonium_bench_max_cpus Maximum CPUs available\n")
        f.write("# TYPE pandemonium_bench_max_cpus gauge\n")
        f.write(f"pandemonium_bench_max_cpus {max_cpus}\n")
        for name, help_text in decls:
            f.write(f"# HELP {name} {help_text}\n")
            f.write(f"# TYPE {name} gauge\n")


def prom_sys_append_ticks(path: Path, ticks: list[dict],
                          label_str: str, base_ts_ms: int):
    """Append tick metrics to .prom file. Returns lines written."""
    if not ticks:
        return 0
    with open(path, "a") as f:
        for i, tick in enumerate(ticks):
            ts = base_ts_ms - (len(ticks) - 1 - i) * 1000
            regime = tick.get("regime", "")
            if regime:
                f.write(f"# tick regime={regime}\n")
            for tick_key, prom_name in _SYS_TICK_FIELDS:
                if tick_key in tick:
                    f.write(f"{prom_name}{{{label_str}}} "
                            f"{tick[tick_key]} {ts}\n")
            for prom_name, tiers in _SYS_TICK_TIERED:
                for tier_key, tier_name in tiers:
                    if tier_key in tick:
                        f.write(f'{prom_name}{{{label_str},'
                                f'tier="{tier_name}"}} '
                                f'{tick[tier_key]} {ts}\n')
    return len(ticks)


def prom_sys_append_knobs(path: Path, knobs: dict, label_str: str):
    """Append [KNOBS] shutdown metrics to .prom file."""
    if not knobs:
        return
    knob_map = [
        ("slice_ns", "pandemonium_bench_knob_slice_ns"),
        ("batch_slice_ns", "pandemonium_bench_knob_batch_ns"),
        ("preempt_thresh_ns", "pandemonium_bench_knob_preempt_ns"),
        ("cpu_bound_thresh_ns", "pandemonium_bench_knob_demotion_ns"),
        ("lag_scale", "pandemonium_bench_knob_lag"),
    ]
    with open(path, "a") as f:
        f.write("# shutdown knobs\n")
        for src, prom in knob_map:
            if src in knobs:
                f.write(f"{prom}{{{label_str}}} {knobs[src]}\n")
        if "reflex" in knobs:
            f.write(f"pandemonium_bench_reflex_events{{{label_str}}} "
                    f"{knobs['reflex']}\n")
        if "tightened" in knobs:
            val = 1 if knobs["tightened"] else 0
            f.write(f"pandemonium_bench_tightened{{{label_str}}} {val}\n")
        for rk in ["ticks_light", "ticks_mixed", "ticks_heavy"]:
            if rk in knobs:
                rname = rk.replace("ticks_", "")
                f.write(f'pandemonium_bench_regime_ticks{{{label_str},'
                        f'regime="{rname}"}} {knobs[rk]}\n')
        for lk in ["l2_hit_batch", "l2_hit_interactive", "l2_hit_latcrit"]:
            if lk in knobs:
                tier = lk.replace("l2_hit_", "")
                f.write(f'pandemonium_bench_l2_hit_pct{{{label_str},'
                        f'tier="{tier}"}} {knobs[lk]}\n')


def prom_sys_append_probe(path: Path, lat: dict, label_str: str):
    """Append latency probe results to .prom file."""
    if not lat or lat.get("samples", 0) == 0:
        return
    with open(path, "a") as f:
        f.write("# latency probe\n")
        f.write(f"pandemonium_bench_latency_samples{{{label_str}}} "
                f"{lat['samples']}\n")
        f.write(f"pandemonium_bench_latency_median_us{{{label_str}}} "
                f"{lat['median_us']}\n")
        f.write(f"pandemonium_bench_latency_p99_us{{{label_str}}} "
                f"{lat['p99_us']}\n")
        f.write(f"pandemonium_bench_latency_worst_us{{{label_str}}} "
                f"{lat['worst_us']}\n")


# REPORT

def format_report(data: dict) -> str:
    """Format benchmark results into a human-readable report."""
    lines = []
    lines.append("PANDEMONIUM BENCH-SCALE")
    lines.append(f"VERSION:     {data.get('version', '?')}")
    lines.append(f"ITERATIONS:  {data.get('iterations', '?')}")
    lines.append(f"MAX CPUS:    {data.get('max_cpus', '?')}")
    lines.append("")

    results = data.get("results", {})
    sorted_cores = sorted(results.keys(), key=int)

    for cores_str in sorted_cores:
        schedulers = results[cores_str]
        lines.append(f"[{cores_str} CORES]")

        # Throughput table
        lines.append(f"{'SCHEDULER':<28} {'MEAN':>10} {'STDEV':>10} "
                     f"{'VS EEVDF':>12}")
        for sched_name, sched_data in schedulers.items():
            tp = sched_data.get("throughput", {})
            if "mean_s" not in tp:
                continue
            delta = tp.get("vs_eevdf_pct")
            delta_str = f"{delta:+.1f}%" if delta is not None else "(baseline)"
            lines.append(f"{sched_name:<28} {tp['mean_s']:>9.2f}s "
                        f"{tp.get('stdev_s', 0):>9.2f}s {delta_str:>12}")

        # Latency table
        has_latency = any(s.get("latency", {}).get("samples", 0) > 0
                         for s in schedulers.values())
        if has_latency:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'SAMPLES':>8} {'MEDIAN':>10} "
                        f"{'P99':>10} {'WORST':>10}")
            for sched_name, sched_data in schedulers.items():
                lat = sched_data.get("latency", {})
                if lat.get("samples", 0) == 0:
                    continue
                lines.append(
                    f"{sched_name:<28} {lat['samples']:>8} "
                    f"{lat['median_us']:>9}us {lat['p99_us']:>9}us "
                    f"{lat['worst_us']:>9}us")

        lines.append("")

    # Summary matrix: throughput delta vs EEVDF
    all_schedulers = []
    for cores_str in sorted_cores:
        for name in results[cores_str]:
            if name not in all_schedulers:
                all_schedulers.append(name)

    if len(all_schedulers) > 1 and len(sorted_cores) > 1:
        lines.append("THROUGHPUT VS EEVDF (NEGATIVE = FASTER)")
        header = f"{'SCHEDULER':<28}"
        for c in sorted_cores:
            header += f" {c + 'C':>8}"
        lines.append(header)

        for sched in all_schedulers:
            if sched == all_schedulers[0]:
                continue
            row = f"{sched:<28}"
            for c in sorted_cores:
                tp = results.get(c, {}).get(sched, {}).get("throughput", {})
                delta = tp.get("vs_eevdf_pct")
                if delta is not None:
                    row += f" {delta:>+7.1f}%"
                else:
                    row += f" {'--':>8}"
            lines.append(row)

        lines.append("")

        lines.append("LATENCY P99 (us)")
        header = f"{'SCHEDULER':<28}"
        for c in sorted_cores:
            header += f" {c + 'C':>8}"
        lines.append(header)

        for sched in all_schedulers:
            row = f"{sched:<28}"
            for c in sorted_cores:
                lat = results.get(c, {}).get(sched, {}).get("latency", {})
                p99 = lat.get("p99_us")
                if p99 is not None and lat.get("samples", 0) > 0:
                    row += f" {p99:>8}"
                else:
                    row += f" {'--':>8}"
            lines.append(row)

        lines.append("")

    return "\n".join(lines)


# BENCH-SCALE COMMAND

def entries_for_cores(
    base_entries: list[tuple[str, list[str] | None]],
    n: int,
) -> list[tuple[str, list[str] | None]]:
    """Adjust scheduler commands for a specific core count.

    PANDEMONIUM variants get --nr-cpus N.
    External schedulers see the online CPUs via kernel.
    EEVDF is None (no scheduler process).
    """
    adjusted = []
    for name, cmd in base_entries:
        if cmd is None:
            adjusted.append((name, None))
        elif "PANDEMONIUM" in name:
            adjusted.append((name, cmd + ["--nr-cpus", str(n)]))
        else:
            adjusted.append((name, list(cmd)))
    return adjusted


def cmd_bench_scale(args) -> int:
    """Unified benchmark: throughput + latency at each core count."""

    subprocess.run(["sudo", "true"])

    dmesg_start = dmesg_baseline()

    nuke_stale_build()

    if not build():
        return 1

    # Stop any active sched_ext scheduler
    if is_scx_active():
        name = scx_scheduler_name()
        log_warn(f"sched_ext is active ({name}) -- stopping pandemonium service")
        subprocess.run(["sudo", "systemctl", "stop", "pandemonium"],
                       capture_output=True)
        if not wait_for_deactivation(5.0):
            log_error("Could not deactivate sched_ext -- is another scheduler running?")
            return 1

    # Restore all CPUs (previous run may have left some offline)
    possible = get_possible_cpus()
    restore_all_cpus(possible)
    time.sleep(0.5)

    # Pre-flight: verify PANDEMONIUM can load BPF and activate
    log_info("Pre-flight: verifying PANDEMONIUM can activate...")
    preflight = start_and_wait([str(BINARY)], "PANDEMONIUM")
    if preflight is None:
        log_error("Pre-flight FAILED -- PANDEMONIUM cannot activate")
        log_error("Fix the error above before running bench-scale")
        capture_dmesg(dmesg_start, datetime.now().strftime("%Y%m%d-%H%M%S"))
        return 1
    stop_and_wait(preflight)
    log_info("Pre-flight PASSED")
    print()

    # Build entry list: EEVDF + PANDEMONIUM (BPF) + PANDEMONIUM (ADAPTIVE) + externals
    base_entries: list[tuple[str, list[str] | None]] = [
        ("EEVDF", None),
        ("PANDEMONIUM (BPF)", [str(BINARY), "--verbose", "--no-adaptive"]),
        ("PANDEMONIUM (ADAPTIVE)", [str(BINARY), "--verbose"]),
    ]

    for name in args.schedulers:
        path = find_scheduler(name)
        if path:
            log_info(f"Found: {name} ({path})")
            base_entries.append((name, [name]))
        else:
            log_warn(f"SKIPPING {name} (not installed)")

    # Workload
    workload_cmd = args.cmd or f"CARGO_TARGET_DIR={TARGET_DIR} cargo build --release"
    clean_cmd = args.clean_cmd
    if not args.cmd:
        clean_cmd = f"cargo clean --target-dir {TARGET_DIR}"

    # Core counts
    max_cpus = get_online_cpus()
    if args.core_counts:
        core_counts = [int(c.strip()) for c in args.core_counts.split(",")]
        core_counts = [c for c in core_counts if 2 <= c <= max_cpus]
        if max_cpus not in core_counts:
            core_counts.append(max_cpus)
        core_counts.sort()
    else:
        core_counts = compute_core_counts(max_cpus)

    print()
    log_info(f"Schedulers: {', '.join(name for name, _ in base_entries)}")
    log_info(f"Core counts: {core_counts}")
    log_info(f"Iterations: {args.iterations}")
    log_info(f"Workload: {workload_cmd}")
    print()

    # Data structure for all results
    version = get_version()
    git = get_git_info()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    data = {
        "version": version,
        "git_commit": git["commit"],
        "git_dirty": git["dirty"],
        "timestamp": stamp,
        "iterations": args.iterations,
        "max_cpus": max_cpus,
        "results": {},
    }

    eevdf_mean = {}  # {cores_str: mean_s} for vs_eevdf calculation

    with CpuGuard(max_cpus):
        restore_all_cpus(max_cpus)
        time.sleep(0.5)

        for n in core_counts:
            cores_str = str(n)
            data["results"][cores_str] = {}

            log_info(f"[{n} CORES]")

            if n < max_cpus:
                log_info(f"Restricting to {n} CPUs via hotplug...")
                if not restrict_cpus(n, max_cpus):
                    log_error(f"CPU hotplug failed for {n} cores -- skipping")
                    restore_all_cpus(max_cpus)
                    time.sleep(0.5)
                    continue
                time.sleep(0.5)

            online = get_online_cpus()
            log_info(f"Online: {online} CPUs")
            print()

            entries = entries_for_cores(base_entries, n)

            for sched_name, sched_cmd in entries:
                log_info(f"Scheduler: {sched_name}")

                sched_result: dict = {
                    "throughput": {},
                    "latency": {},
                    "telemetry": {},
                }

                # Start scheduler (EEVDF = no-op)
                guard = None
                if sched_cmd is not None:
                    settle = 10.0 if "ADAPTIVE" in sched_name else 5.0
                    guard = start_and_wait(sched_cmd, sched_name,
                                          settle_secs=settle)
                    if guard is None:
                        print()
                        continue

                # Latency measurement
                latency = measure_latency(BINARY, n, iterations=args.iterations)
                sched_result["latency"] = latency

                # Throughput measurement
                times = []
                for i in range(args.iterations):
                    log_info(f"Throughput iteration {i + 1}/{args.iterations}")
                    t = timed_run(workload_cmd, clean_cmd)
                    if t is None:
                        log_warn(f"Workload failed under {sched_name}")
                        break
                    times.append(t)

                if times:
                    m, std = mean_stdev(times)
                    tp = {"times": [round(t, 2) for t in times],
                          "mean_s": round(m, 2),
                          "stdev_s": round(std, 2)}
                    if sched_name == "EEVDF":
                        eevdf_mean[cores_str] = m
                    elif cores_str in eevdf_mean and eevdf_mean[cores_str] > 0:
                        delta = ((m - eevdf_mean[cores_str])
                                 / eevdf_mean[cores_str]) * 100.0
                        tp["vs_eevdf_pct"] = round(delta, 1)
                    sched_result["throughput"] = tp

                # Stop scheduler, capture telemetry
                stdout = stop_and_wait(guard)
                if stdout and "PANDEMONIUM" in sched_name:
                    ticks = parse_tick_lines(stdout)
                    knobs = parse_knobs_line(stdout)
                    sched_result["telemetry"] = {
                        "tick_count": len(ticks),
                        "tick_aggregate": aggregate_ticks(ticks),
                        "knobs": knobs,
                    }

                data["results"][cores_str][sched_name] = sched_result
                print()

            # Restore CPUs for next round
            if n < max_cpus:
                restore_all_cpus(max_cpus)
                time.sleep(0.5)

    # Report
    report = format_report(data)
    print()
    print(report)

    # Save log
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    report_path = LOG_DIR / f"bench-scale-{stamp}.log"
    report_path.write_text(report)
    log_info(f"Report saved to {report_path}")

    # Write Prometheus metrics
    prom_path = write_prometheus(data, stamp)
    log_info(f"Prometheus metrics saved to {prom_path}")

    # Capture dmesg
    capture_dmesg(dmesg_start, stamp)

    # Restart PANDEMONIUM service if it was running
    ret = subprocess.run(["systemctl", "is-enabled", "pandemonium"],
                         capture_output=True).returncode
    if ret == 0:
        log_info("Re-starting PANDEMONIUM service...")
        subprocess.run(["sudo", "systemctl", "start", "pandemonium"],
                       capture_output=True)
        if wait_for_activation(5.0):
            log_info("PANDEMONIUM service restored")
        else:
            log_warn("Failed to restart PANDEMONIUM service")

    fix_ownership()

    if not data["results"]:
        return 1
    return 0


# BENCH-SYS COMMAND

def cmd_bench_sys(args) -> int:
    """Live system telemetry capture. Run a scheduler, use your desktop,
    Ctrl+C when done. Writes Prometheus metrics from the session.

    --scheduler values:
        adaptive     PANDEMONIUM with adaptive control loop (default)
        no-adaptive  PANDEMONIUM BPF-only
        eevdf        No scheduler (kernel default)
        <name>       Any installed sched_ext scheduler (e.g. scx_bpfland)
    """

    scheduler = args.scheduler
    is_pandemonium = scheduler in ("adaptive", "no-adaptive")
    is_eevdf = scheduler == "eevdf"
    is_external = not is_pandemonium and not is_eevdf

    subprocess.run(["sudo", "true"])

    dmesg_start = dmesg_baseline()

    # Only build PANDEMONIUM binary when we need it (pandemonium modes or probe)
    if is_pandemonium or args.with_probe:
        nuke_stale_build()
        if not build():
            return 1

    # Resolve external scheduler
    if is_external:
        ext_path = find_scheduler(scheduler)
        if not ext_path:
            log_error(f"Scheduler not found: {scheduler}")
            return 1
        log_info(f"Found: {scheduler} ({ext_path})")

    # Stop any active sched_ext scheduler
    if is_scx_active():
        name = scx_scheduler_name()
        log_warn(f"sched_ext is active ({name}) -- stopping")
        subprocess.run(["sudo", "systemctl", "stop", "pandemonium"],
                       capture_output=True)
        subprocess.run(["sudo", "killall", "-INT", "pandemonium"],
                       capture_output=True)
        if not wait_for_deactivation(5.0):
            subprocess.run(["sudo", "killall", "-KILL", "pandemonium"],
                           capture_output=True)
            if not wait_for_deactivation(3.0):
                log_error("Could not deactivate sched_ext")
                return 1

    max_cpus = get_online_cpus()

    # Build scheduler command
    guard = None
    if is_pandemonium:
        sched_cmd = [str(BINARY), "--verbose"]
        if scheduler == "no-adaptive":
            sched_cmd.append("--no-adaptive")
        for comp in (args.compositor or []):
            sched_cmd.extend(["--compositor", comp])
        sched_display = f"PANDEMONIUM ({'BPF' if scheduler == 'no-adaptive' else 'ADAPTIVE'})"
    elif is_external:
        sched_cmd = [scheduler]
        sched_display = scheduler
    else:
        sched_cmd = None
        sched_display = "EEVDF"

    # Start scheduler (EEVDF = no-op)
    if sched_cmd is not None:
        settle = 10.0 if scheduler == "adaptive" else 5.0
        guard = start_and_wait(sched_cmd, sched_display, settle_secs=settle)
        if guard is None:
            log_error(f"{sched_display} failed to activate")
            capture_dmesg(dmesg_start, datetime.now().strftime("%Y%m%d-%H%M%S"))
            return 1

    # Optionally start latency probe
    probe_proc = None
    if args.with_probe:
        if not BINARY.exists():
            log_error("Probe requires PANDEMONIUM binary "
                      "-- build failed or skipped")
            if guard:
                stop_and_wait(guard)
            return 1
        log_info("Starting latency probe (unpinned)")
        probe_proc = subprocess.Popen(
            [str(BINARY), "probe"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )

    # Create .prom file immediately with header
    version = get_version()
    git = get_git_info()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    prom_path = ARCHIVE_DIR / f"{version}-{stamp}.prom"
    labels = {"scheduler": sched_display, "cores": str(max_cpus)}
    label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())

    prom_sys_create(prom_path, version, git, max_cpus)
    log_info(f"Prometheus: {prom_path}")

    log_info(f"{sched_display} is active ({max_cpus} CPUs)")
    log_info("Use your system normally. Ctrl+C to stop and collect.")
    print()

    # Live loop: append ticks to .prom as they arrive
    ticks_written = 0
    try:
        while True:
            if guard is not None and guard.proc.poll() is not None:
                log_warn(f"{sched_display} exited unexpectedly")
                break
            time.sleep(1)

            if is_pandemonium and guard is not None and guard.stdout_path:
                try:
                    stdout_text = Path(guard.stdout_path).read_text()
                except (FileNotFoundError, PermissionError):
                    continue
                ticks = parse_tick_lines(stdout_text)
                new_count = len(ticks) - ticks_written
                if new_count > 0:
                    now_ms = int(time.time() * 1000)
                    prom_sys_append_ticks(
                        prom_path, ticks[ticks_written:],
                        label_str, now_ms)
                    ticks_written = len(ticks)
    except KeyboardInterrupt:
        print()
        log_info("Stopping...")

    # Block SIGINT during final cleanup
    prev_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        # Collect probe data
        if probe_proc is not None:
            probe_proc.send_signal(signal.SIGINT)
            try:
                stdout_bytes, _ = probe_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                probe_proc.kill()
                stdout_bytes, _ = probe_proc.communicate()
            probe_latency = parse_probe_output(
                stdout_bytes.decode(errors="replace"))
            prom_sys_append_probe(prom_path, probe_latency, label_str)
            log_info(f"Probe: {probe_latency['samples']} samples, "
                     f"median={probe_latency['median_us']}us, "
                     f"p99={probe_latency['p99_us']}us, "
                     f"worst={probe_latency['worst_us']}us")

        # Stop scheduler, flush remaining ticks + knobs
        sched_stdout = stop_and_wait(guard)
        if is_pandemonium and sched_stdout:
            ticks = parse_tick_lines(sched_stdout)
            if len(ticks) > ticks_written:
                now_ms = int(time.time() * 1000)
                prom_sys_append_ticks(
                    prom_path, ticks[ticks_written:],
                    label_str, now_ms)
                ticks_written = len(ticks)
            knobs = parse_knobs_line(sched_stdout)
            prom_sys_append_knobs(prom_path, knobs, label_str)

        # Console summary
        print()
        log_info(f"SESSION: {sched_display}, {max_cpus} CPUs, "
                 f"{ticks_written} ticks")
        log_info(f"Prometheus: {prom_path}")

        capture_dmesg(dmesg_start, stamp)
        fix_ownership()

    except Exception:
        log_error("Cleanup failed:")
        traceback.print_exc()
        if guard is not None:
            try:
                guard.stop()
            except Exception:
                pass

    signal.signal(signal.SIGINT, prev_handler)

    # Restart PANDEMONIUM service if it was enabled
    ret = subprocess.run(["systemctl", "is-enabled", "pandemonium"],
                         capture_output=True).returncode
    if ret == 0:
        log_info("Re-starting PANDEMONIUM service...")
        subprocess.run(["sudo", "systemctl", "start", "pandemonium"],
                       capture_output=True)
        if wait_for_activation(5.0):
            log_info("PANDEMONIUM service restored")
        else:
            log_warn("Failed to restart PANDEMONIUM service")

    return 0


# MAIN

def main() -> int:
    parser = argparse.ArgumentParser(
        description="PANDEMONIUM test orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    bench = sub.add_parser("bench-scale",
                           help="Unified throughput + latency benchmark")
    bench.add_argument("--cmd", type=str, default=None,
                       help="Custom workload command (default: self-build)")
    bench.add_argument("--clean-cmd", type=str, default=None,
                       help="Clean command between iterations")
    bench.add_argument("--iterations", type=int, default=1,
                       help="Iterations per scheduler (default: 1)")
    bench.add_argument("--schedulers", type=str,
                       default=",".join(DEFAULT_EXTERNALS),
                       help=f"Comma-separated external schedulers "
                            f"(default: {','.join(DEFAULT_EXTERNALS)})")
    bench.add_argument("--core-counts", type=str, default=None,
                       help="Comma-separated core counts "
                            "(default: auto 2,4,8,...,max)")

    sys_bench = sub.add_parser("bench-sys",
                               help="Live system telemetry capture")
    sys_bench.add_argument("--scheduler", type=str, default="adaptive",
                           help="Scheduler to run: adaptive (default), "
                                "no-adaptive, eevdf, or external name "
                                "(e.g. scx_bpfland)")
    sys_bench.add_argument("--with-probe", action="store_true",
                           help="Run latency probe during session")
    sys_bench.add_argument("--compositor", action="append",
                           help="Additional compositor process names "
                                "(PANDEMONIUM modes only)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if hasattr(args, "schedulers") and isinstance(args.schedulers, str):
        args.schedulers = [s.strip() for s in args.schedulers.split(",")
                           if s.strip()]

    if args.command == "bench-scale":
        return cmd_bench_scale(args)
    if args.command == "bench-sys":
        return cmd_bench_sys(args)

    log_error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
