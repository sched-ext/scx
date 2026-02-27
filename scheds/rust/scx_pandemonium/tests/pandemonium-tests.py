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
import os
import threading
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
    SCX_OPS, is_scx_active, scx_scheduler_name,
    wait_for_activation, wait_for_deactivation, wait_for_no_scheduler,
    set_cpu_online, restrict_cpus, restore_all_cpus, CpuGuard,
    get_possible_cpus, get_online_cpus, compute_core_counts,
    mean_stdev, percentile,
    find_trace_pipe,
)


# CONFIGURATION

DEFAULT_EXTERNALS = ["scx_bpfland"]


# DMESG MONITORING

class DmesgMonitor:
    """Active crash detection via dmesg polling.

    Snapshots dmesg at construction, .check() polls for crash patterns,
    .save() writes new lines to log file with keyword-filtered summary.
    """

    CRASH_PATTERNS = [
        "failed to run for",
        "runnable task stall",
    ]
    KEYWORDS = ["sched_ext", "pandemonium", "non-existent DSQ", "zero slice",
                "panic", "BUG:", "RIP:", "Oops", "Call Trace"]

    def __init__(self):
        r = subprocess.run(["sudo", "dmesg"], capture_output=True, text=True)
        self.baseline = len(r.stdout.splitlines()) if r.returncode == 0 else 0
        self.crashed = False
        self.crash_msg = ""

    def _new_lines(self) -> list[str]:
        r = subprocess.run(["sudo", "dmesg"], capture_output=True, text=True)
        if r.returncode != 0:
            return []
        lines = r.stdout.splitlines()
        return lines[self.baseline:] if self.baseline < len(lines) else []

    def check(self) -> bool:
        """Poll for crash patterns. Returns True if crash detected."""
        for line in self._new_lines():
            if "sched_ext" in line:
                log_info(f"  dmesg: {line.strip()}")
            for pattern in self.CRASH_PATTERNS:
                if pattern in line:
                    self.crashed = True
                    self.crash_msg = line.strip()
                    return True
            if "disabled" in line and "sched_ext" in line:
                self.crashed = True
                self.crash_msg = line.strip()
                return True
        return False

    def save(self, stamp: str | None = None) -> None:
        """Save new dmesg lines to log file, print keyword-filtered summary."""
        new_lines = self._new_lines()
        if not new_lines:
            log_info("dmesg: no new kernel messages")
            return

        if stamp is None:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        dmesg_path = LOG_DIR / f"dmesg-{stamp}.log"
        dmesg_path.write_text("\n".join(new_lines) + "\n")

        filtered = [l for l in new_lines
                    if any(kw in l for kw in self.KEYWORDS)]

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


# TRACE CAPTURE

class TraceCapture:
    """Background thread reading trace_pipe, filtering for PAND: lines."""

    def __init__(self, path: Path):
        self.path = path
        self.proc = None
        self.outfile = None
        self.count = 0
        self.error = None

    def start(self) -> bool:
        pipe = find_trace_pipe()
        if not pipe.exists():
            log_info("tracefs not found, attempting mounts...")
            subprocess.run(
                ["mount", "-t", "tracefs", "none", "/sys/kernel/tracing"],
                capture_output=True, text=True,
            )
            subprocess.run(
                ["mount", "-t", "debugfs", "none", "/sys/kernel/debug"],
                capture_output=True, text=True,
            )
            pipe = find_trace_pipe()
            if not pipe.exists():
                self.error = "trace_pipe not found at any known path"
                log_error(self.error)
                return False
            log_info(f"Found trace_pipe at {pipe}")

        try:
            fd = os.open(str(pipe), os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError as e:
            self.error = f"trace_pipe not readable: {e}"
            log_error(self.error)
            return False

        tracedir = pipe.parent

        tracing_on = tracedir / "tracing_on"
        try:
            val = tracing_on.read_text().strip()
            if val != "1":
                tracing_on.write_text("1")
                log_info("tracing_on set to 1")
        except (PermissionError, OSError) as e:
            log_warn(f"could not enable tracing_on: {e}")

        buf_size = tracedir / "buffer_size_kb"
        try:
            buf_size.write_text("16384")
        except (PermissionError, OSError) as e:
            log_warn(f"could not set buffer_size_kb: {e}")

        trace_file = tracedir / "trace"
        try:
            trace_file.write_text("")
        except (PermissionError, OSError):
            pass

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.outfile = open(self.path, "w")
        self.proc = subprocess.Popen(
            ["cat", str(pipe)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        time.sleep(0.3)
        if self.proc.poll() is not None:
            err = self.proc.stderr.read()
            self.error = f"trace_pipe reader exited immediately: {err.strip()}"
            log_error(self.error)
            return False
        log_info(f"Trace capture started -> {self.path}")
        return True

    def _reader(self):
        try:
            for line in self.proc.stdout:
                if "PAND:" in line:
                    self.outfile.write(line)
                    self.outfile.flush()
                    self.count += 1
        except (ValueError, OSError):
            pass

    def stop(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait()
        if self.outfile:
            self.outfile.close()
        log_info(f"Trace capture stopped: {self.count} PAND events")


# BUILD HELPERS

BPF_SRC = SCRIPT_DIR / "src" / "bpf" / "main.bpf.c"


def patch_bpf_trace_filter(target: str) -> str | None:
    """Patch is_sched_task() in main.bpf.c to trace `target` instead of 'pand'.
    Returns the original content for restoration, or None on error."""
    original = BPF_SRC.read_text()

    # Match the exact two-line return statement in is_sched_task():
    #   \treturn p->comm[0] == 'p' && p->comm[1] == 'a' &&
    #   \t       p->comm[2] == 'n' && p->comm[3] == 'd';
    old_body = ("\treturn p->comm[0] == 'p' && p->comm[1] == 'a' &&\n"
                "\t       p->comm[2] == 'n' && p->comm[3] == 'd';")

    if old_body not in original:
        log_error("Could not find is_sched_task() trace filter in main.bpf.c")
        return None

    checks = [f"p->comm[{i}] == '{c}'" for i, c in enumerate(target)]
    if len(checks) <= 2:
        new_body = "\treturn " + " && ".join(checks) + ";"
    else:
        line1 = checks[:2]
        line2 = checks[2:]
        new_body = ("\treturn " + " && ".join(line1) + " &&\n"
                    "\t       " + " && ".join(line2) + ";")

    patched = original.replace(old_body, new_body, 1)
    BPF_SRC.write_text(patched)
    log_info(f"Patched trace filter: 'pand' -> '{target}'")
    return original


def restore_bpf_source(original: str):
    """Restore main.bpf.c to its original content."""
    BPF_SRC.write_text(original)
    log_info("Restored main.bpf.c")


def fix_ownership():
    uid = os.environ.get("SUDO_UID", str(os.getuid()))
    gid = os.environ.get("SUDO_GID", str(os.getgid()))
    log_info(f"Fixing ownership to {uid}:{gid}...")
    for d in [TARGET_DIR, LOG_DIR]:
        if d.exists():
            subprocess.run(
                ["chown", "-R", f"{uid}:{gid}", str(d)],
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
    # Detect stale struct_ops registration before starting
    try:
        stale = SCX_OPS.read_text().strip()
        if stale:
            log_warn(f"Stale scheduler detected: '{stale}', waiting for cleanup...")
            if not wait_for_no_scheduler(timeout=15):
                log_error("stale scheduler did not unregister")
                return None
            log_info("Stale scheduler cleared")
    except (FileNotFoundError, PermissionError):
        pass
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


def measure_struct_ops_cleanup():
    """Time how long the kernel takes to fully unregister struct_ops."""
    try:
        name = SCX_OPS.read_text().strip()
        if not name:
            return
    except (FileNotFoundError, PermissionError):
        return
    t0 = time.monotonic()
    while True:
        try:
            name = SCX_OPS.read_text().strip()
            if not name:
                elapsed_ms = (time.monotonic() - t0) * 1000
                log_info(f"  struct_ops cleanup: {elapsed_ms:.0f}ms")
                return
        except (FileNotFoundError, PermissionError):
            elapsed_ms = (time.monotonic() - t0) * 1000
            log_info(f"  struct_ops cleanup: {elapsed_ms:.0f}ms (ops disappeared)")
            return
        if time.monotonic() - t0 > 30:
            log_error("struct_ops cleanup: STILL REGISTERED AFTER 30s")
            return
        time.sleep(0.01)


def stop_and_wait(guard: SchedulerProcess | None) -> str:
    """Stop a scheduler, wait for deactivation. Returns captured stdout."""
    if guard is None:
        return ""
    guard.stop()
    stdout = guard.drain_stdout()
    if not wait_for_deactivation(5.0):
        log_warn(f"sched_ext still active after stopping {guard.name}")
    measure_struct_ops_cleanup()
    time.sleep(1)
    return stdout


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


# BURST MEASUREMENT

def fire_burst(count: int, work_secs: float = 0.5) -> list[subprocess.Popen]:
    """Spawn count short-lived CPU-bound processes as fast as possible.

    Simulates application launch: fork/exec storm of processes that each
    do CPU work for work_secs then exit. Python startup overhead (~50ms)
    is intentional -- it mirrors real app initialization."""
    script = (
        "import time,hashlib\n"
        f"end=time.monotonic()+{work_secs}\n"
        "while time.monotonic()<end:\n"
        " hashlib.sha256(b'x'*4096).hexdigest()\n"
    )
    procs = []
    for _ in range(count):
        p = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p)
    return procs


def measure_burst(binary: Path, n_cpus: int, burst_size: int,
                  burst_work_secs: float = 0.5,
                  baseline_secs: int = 5,
                  burst_measure_secs: int = 10,
                  warmup_secs: int = 2) -> dict:
    """Measure scheduling latency before and during a process burst under load.

    1. Stress workers saturate all CPUs
    2. Baseline probe (steady-state latency reference)
    3. Fire burst + measure through burst and settling
    4. Compare baseline vs burst P99
    """
    if n_cpus < 1:
        return {"survived": True, "baseline": {}, "burst": {}}

    stress_cpus = list(range(n_cpus))
    log_info(f"Burst test: {len(stress_cpus)} stress workers, "
             f"{burst_size} burst processes ({burst_work_secs}s each)")

    # Start stress workers on all CPUs
    workers = []
    for cpu in stress_cpus:
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    # Warmup (discard output)
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

    # Baseline measurement
    log_info(f"Baseline: {baseline_secs}s")
    baseline_probe = subprocess.Popen(
        [str(binary), "probe"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    time.sleep(baseline_secs)
    baseline_probe.send_signal(signal.SIGINT)
    try:
        baseline_out, _ = baseline_probe.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        baseline_probe.kill()
        baseline_out, _ = baseline_probe.communicate()
    baseline = parse_probe_output(baseline_out.decode(errors="replace"))
    log_info(f"Baseline: {baseline['samples']} samples, "
             f"median={baseline['median_us']}us, "
             f"p99={baseline['p99_us']}us")

    # Burst measurement: start probe, fire burst, measure during + after
    burst_probe = subprocess.Popen(
        [str(binary), "probe"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)

    log_info(f"Firing burst: {burst_size} processes")
    burst_start = time.monotonic()
    burst_procs = fire_burst(burst_size, burst_work_secs)

    # Wait for all burst processes to exit
    for p in burst_procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    burst_duration = time.monotonic() - burst_start
    log_info(f"Burst complete: {burst_duration:.1f}s")

    # Continue measuring through settling period
    remaining = burst_measure_secs - burst_duration
    if remaining > 0:
        log_info(f"Settling: {remaining:.0f}s")
        time.sleep(remaining)

    burst_probe.send_signal(signal.SIGINT)
    try:
        burst_out, _ = burst_probe.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        burst_probe.kill()
        burst_out, _ = burst_probe.communicate()
    burst_stats = parse_probe_output(burst_out.decode(errors="replace"))
    log_info(f"Burst: {burst_stats['samples']} samples, "
             f"median={burst_stats['median_us']}us, "
             f"p99={burst_stats['p99_us']}us, "
             f"worst={burst_stats['worst_us']}us")

    # POST-BURST RECOVERY: MEASURE HOW QUICKLY LATENCY RETURNS TO NORMAL
    # DSQ COLLAPSE ROUTES EVERYTHING TO INTERACTIVE DSQ DURING BURST.
    # WHEN BURST CLEARS, ROUTING SNAPS BACK. TASKS ENQUEUED DURING BURST
    # ARE STILL IN THE INTERACTIVE DSQ. interactive_run MAY BE IN AN
    # ARBITRARY STATE. THIS MEASURES THE SETTLING BEHAVIOR.
    log_info("Recovery: 5s")
    recovery_probe = subprocess.Popen(
        [str(binary), "probe"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    time.sleep(5)
    recovery_probe.send_signal(signal.SIGINT)
    try:
        recovery_out, _ = recovery_probe.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        recovery_probe.kill()
        recovery_out, _ = recovery_probe.communicate()
    recovery_stats = parse_probe_output(recovery_out.decode(errors="replace"))
    log_info(f"Recovery: {recovery_stats['samples']} samples, "
             f"p99={recovery_stats['p99_us']}us")

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    return {
        "survived": True,
        "burst_size": burst_size,
        "burst_duration_s": round(burst_duration, 1),
        "baseline": baseline,
        "burst": burst_stats,
        "recovery": recovery_stats,
    }


# LONG-RUNNING PROCESS MEASUREMENT

def spawn_longrunners(count: int, duration_secs: float) -> list[subprocess.Popen]:
    """Spawn persistent CPU-bound processes that report work completed.

    Each process does SHA256 hashing in a tight loop for duration_secs,
    then prints the number of iterations completed before exiting.
    This lets us measure whether long-runners actually get CPU time
    or starve under the scheduler."""
    script = (
        "import time,hashlib,sys\n"
        f"end=time.monotonic()+{duration_secs}\n"
        "iters=0\n"
        "while time.monotonic()<end:\n"
        " hashlib.sha256(b'x'*4096).hexdigest()\n"
        " iters+=1\n"
        "print(iters,flush=True)\n"
    )
    procs = []
    for _ in range(count):
        p = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p)
    return procs


def measure_longrun(binary: Path, n_cpus: int,
                    longrun_count: int = 4,
                    longrun_secs: float = 20.0,
                    warmup_secs: int = 2) -> dict:
    """Measure scheduling behavior with persistent long-running CPU-bound processes.

    Simulates real desktop contention: a few heavy background processes (builds,
    Steam updates, video encoding) competing against interactive workloads.

    Measures two things:
    1. Interactive latency while long-runners are active (probe P99/worst)
    2. Long-runner throughput (SHA256 iterations completed -- starvation = 0 or near-0)

    Phases:
    1. Stress workers saturate all CPUs (same as burst/latency tests)
    2. Warmup period (discard)
    3. Spawn long-runners + start latency probe simultaneously
    4. Let everything run for longrun_secs
    5. Collect probe latency and long-runner work counts
    """
    if n_cpus < 1:
        return {"survived": True, "latency": {}, "longrun_work": []}

    stress_cpus = list(range(n_cpus))
    log_info(f"Long-run test: {len(stress_cpus)} stress workers, "
             f"{longrun_count} long-runners for {longrun_secs}s")

    # Start stress workers on all CPUs
    workers = []
    for cpu in stress_cpus:
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    # Warmup
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

    # Start latency probe + long-runners simultaneously
    probe = subprocess.Popen(
        [str(binary), "probe"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    longrunners = spawn_longrunners(longrun_count, longrun_secs)
    log_info(f"Running: {longrun_count} long-runners + probe for {longrun_secs}s")

    # Wait for long-runners to finish (they self-terminate after longrun_secs)
    work_counts = []
    for lr in longrunners:
        try:
            stdout, _ = lr.communicate(timeout=longrun_secs + 10)
            line = stdout.decode(errors="replace").strip()
            work_counts.append(int(line) if line.isdigit() else 0)
        except (subprocess.TimeoutExpired, ValueError):
            lr.kill()
            lr.wait()
            work_counts.append(0)

    # Stop probe
    probe.send_signal(signal.SIGINT)
    try:
        probe_out, _ = probe.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        probe.kill()
        probe_out, _ = probe.communicate()
    latency = parse_probe_output(probe_out.decode(errors="replace"))

    total_work = sum(work_counts)
    min_work = min(work_counts) if work_counts else 0
    max_work = max(work_counts) if work_counts else 0

    log_info(f"Long-run latency: {latency['samples']} samples, "
             f"median={latency['median_us']}us, "
             f"p99={latency['p99_us']}us, "
             f"worst={latency['worst_us']}us")
    log_info(f"Long-run work: total={total_work}, "
             f"min={min_work}, max={max_work}, "
             f"per-process={work_counts}")

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    return {
        "survived": True,
        "longrun_count": longrun_count,
        "longrun_secs": longrun_secs,
        "latency": latency,
        "work_total": total_work,
        "work_min": min_work,
        "work_max": max_work,
        "work_per_process": work_counts,
    }


# MIXED WORKLOAD MEASUREMENT (BURST + LONGRUN SIMULTANEOUS)

def measure_mixed(binary: Path, n_cpus: int,
                  longrun_count: int = 4,
                  longrun_secs: float = 30.0,
                  burst_size: int = 0,
                  burst_delay_secs: float = 5.0,
                  burst_work_secs: float = 0.5,
                  warmup_secs: int = 2) -> dict:
    """Measure scheduling under combined burst + long-running load.

    Simulates the Steam scenario: background updates (long-runners) are
    already active when the user launches an app (burst of child processes).

    Phases:
    1. Stress workers saturate all CPUs
    2. Warmup (discard)
    3. Spawn long-runners + start latency probe simultaneously
    4. Wait burst_delay_secs for long-runners to establish vtime
    5. Fire burst while long-runners are still running
    6. Wait for burst to clear, continue through long-runner completion
    7. Collect probe latency + long-runner work counts
    """
    if n_cpus < 1:
        return {"survived": True, "latency": {}, "work_total": 0}

    if burst_size < 1:
        burst_size = max(8, n_cpus * 4)

    stress_cpus = list(range(n_cpus))
    log_info(f"Mixed test: {len(stress_cpus)} stress workers, "
             f"{longrun_count} long-runners ({longrun_secs}s), "
             f"{burst_size} burst procs after {burst_delay_secs}s delay")

    # Start stress workers on all CPUs
    workers = []
    for cpu in stress_cpus:
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    # Warmup
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

    # Start long-runners + probe simultaneously
    probe = subprocess.Popen(
        [str(binary), "probe"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    longrunners = spawn_longrunners(longrun_count, longrun_secs)
    log_info(f"Running: {longrun_count} long-runners + probe")

    # Wait for long-runners to establish vtime, then fire burst
    log_info(f"Delay: {burst_delay_secs}s (establishing long-runner vtime)")
    time.sleep(burst_delay_secs)

    log_info(f"Firing burst: {burst_size} processes")
    burst_start = time.monotonic()
    burst_procs = fire_burst(burst_size, burst_work_secs)

    # Wait for burst processes to exit
    for bp in burst_procs:
        try:
            bp.wait(timeout=10)
        except subprocess.TimeoutExpired:
            bp.kill()
            bp.wait()
    burst_duration = time.monotonic() - burst_start
    log_info(f"Burst complete: {burst_duration:.1f}s")

    # Wait for long-runners to finish
    work_counts = []
    for lr in longrunners:
        try:
            stdout, _ = lr.communicate(timeout=longrun_secs + 10)
            line = stdout.decode(errors="replace").strip()
            work_counts.append(int(line) if line.isdigit() else 0)
        except (subprocess.TimeoutExpired, ValueError):
            lr.kill()
            lr.wait()
            work_counts.append(0)

    # Stop probe
    probe.send_signal(signal.SIGINT)
    try:
        probe_out, _ = probe.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        probe.kill()
        probe_out, _ = probe.communicate()
    latency = parse_probe_output(probe_out.decode(errors="replace"))

    total_work = sum(work_counts)
    min_work = min(work_counts) if work_counts else 0
    max_work = max(work_counts) if work_counts else 0

    log_info(f"Mixed latency: {latency['samples']} samples, "
             f"median={latency['median_us']}us, "
             f"p99={latency['p99_us']}us, "
             f"worst={latency['worst_us']}us")
    log_info(f"Mixed long-run work: total={total_work}, "
             f"min={min_work}, max={max_work}, "
             f"per-process={work_counts}")

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    return {
        "survived": True,
        "longrun_count": longrun_count,
        "longrun_secs": longrun_secs,
        "burst_size": burst_size,
        "burst_duration_s": round(burst_duration, 1),
        "latency": latency,
        "work_total": total_work,
        "work_min": min_work,
        "work_max": max_work,
        "work_per_process": work_counts,
    }


# PERIODIC DEADLINE MEASUREMENT

def measure_deadline(binary: Path, n_cpus: int,
                     target_fps: int = 60,
                     duration_secs: int = 15,
                     warmup_secs: int = 3,
                     threshold_us: int = 500) -> dict:
    """Measure frame scheduling jitter under full CPU load.

    Simulates a game/compositor frame loop: workers wake on a periodic
    timer (16.6ms for 60fps), do a small fixed work unit (~1ms SHA256),
    then sleep until the next frame. Jitter = actual wake time minus
    expected wake time.

    A deadline miss is any frame where jitter exceeds threshold_us.
    """
    if n_cpus < 1:
        return {"survived": True, "total_frames": 0, "missed_frames": 0}

    period_us = 1_000_000 // target_fps
    period_secs = period_us / 1_000_000.0
    worker_count = min(4, n_cpus)

    log_info(f"Deadline test: {worker_count} frame workers @ {target_fps}fps "
             f"({period_us}us period), {n_cpus} stress workers, "
             f"threshold={threshold_us}us")

    # Start stress workers on all CPUs
    workers = []
    for cpu in range(n_cpus):
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    # Deadline worker script: periodic wake, record jitter, do small work
    script = (
        "import time,hashlib,sys\n"
        f"period={period_secs}\n"
        f"duration={duration_secs}\n"
        "end=time.monotonic()+duration\n"
        "next_wake=time.monotonic()+period\n"
        "while time.monotonic()<end:\n"
        " time.sleep(max(0,next_wake-time.monotonic()))\n"
        " actual=time.monotonic()\n"
        " jitter_us=int((actual-next_wake)*1e6)\n"
        " print(jitter_us,flush=True)\n"
        " for _ in range(50):\n"
        "  hashlib.sha256(b'x'*4096).hexdigest()\n"
        " next_wake+=period\n"
    )

    # Warmup phase (discard)
    log_info(f"Warmup: {warmup_secs}s")
    warmup_workers = []
    for _ in range(worker_count):
        p = subprocess.Popen(
            [sys.executable, "-c", script.replace(f"duration={duration_secs}",
                                                   f"duration={warmup_secs}")],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        warmup_workers.append(p)
    for p in warmup_workers:
        try:
            p.wait(timeout=warmup_secs + 10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    # Measurement phase
    log_info(f"Measuring: {duration_secs}s")
    deadline_workers = []
    for _ in range(worker_count):
        p = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        deadline_workers.append(p)

    all_jitter: list[int] = []
    for p in deadline_workers:
        try:
            stdout, _ = p.communicate(timeout=duration_secs + 10)
            for line in stdout.decode(errors="replace").splitlines():
                line = line.strip()
                if line and line.lstrip("-").isdigit():
                    all_jitter.append(int(line))
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    total = len(all_jitter)
    missed = sum(1 for j in all_jitter if j > threshold_us) if all_jitter else 0
    miss_ratio = missed / total if total > 0 else 0.0

    result = {
        "survived": True,
        "target_fps": target_fps,
        "period_us": period_us,
        "threshold_us": threshold_us,
        "workers": worker_count,
        "total_frames": total,
        "missed_frames": missed,
        "miss_ratio": round(miss_ratio, 4),
        "jitter_median_us": int(percentile(all_jitter, 50)) if all_jitter else 0,
        "jitter_p99_us": int(percentile(all_jitter, 99)) if all_jitter else 0,
        "jitter_worst_us": int(max(all_jitter)) if all_jitter else 0,
    }

    log_info(f"Deadline: {total} frames, {missed} missed "
             f"({miss_ratio:.1%}), "
             f"jitter p99={result['jitter_p99_us']}us, "
             f"worst={result['jitter_worst_us']}us")
    return result


# IPC ROUND-TRIP MEASUREMENT

def measure_ipc(binary: Path, n_cpus: int,
                pair_count: int = 0,
                rounds: int = 10000,
                warmup_secs: int = 3) -> dict:
    """Measure IPC round-trip latency via pipe ping-pong under CPU load.

    Each pair: parent writes 1 byte to pipe, child reads and writes back,
    parent reads. Measures the scheduling round-trip (two wakeups per round).
    """
    if n_cpus < 1:
        return {"survived": True, "pairs": 0}

    if pair_count < 1:
        pair_count = max(2, n_cpus // 2)

    log_info(f"IPC test: {pair_count} pipe pairs, {rounds} rounds each, "
             f"{n_cpus} stress workers")

    # Start stress workers on all CPUs
    workers = []
    for cpu in range(n_cpus):
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    # IPC pair script: forks internally, does pipe ping-pong, prints avg_us
    pair_script = (
        "import os,time,sys\n"
        f"rounds={rounds}\n"
        "r1,w1=os.pipe()\n"
        "r2,w2=os.pipe()\n"
        "pid=os.fork()\n"
        "if pid==0:\n"
        " os.close(w1)\n"
        " os.close(r2)\n"
        " for _ in range(rounds):\n"
        "  os.read(r1,1)\n"
        "  os.write(w2,b'x')\n"
        " os._exit(0)\n"
        "os.close(r1)\n"
        "os.close(w2)\n"
        "latencies=[]\n"
        "for _ in range(rounds):\n"
        " t=time.monotonic()\n"
        " os.write(w1,b'x')\n"
        " os.read(r2,1)\n"
        " latencies.append(time.monotonic()-t)\n"
        "os.waitpid(pid,0)\n"
        "for l in latencies:\n"
        " print(int(l*1e6),flush=True)\n"
    )

    # Warmup (one pair, discard)
    log_info(f"Warmup: {warmup_secs}s (1 pair)")
    warmup_script = pair_script.replace(f"rounds={rounds}",
                                         f"rounds={min(1000, rounds)}")
    warmup = subprocess.Popen(
        [sys.executable, "-c", warmup_script],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        warmup.wait(timeout=warmup_secs + 10)
    except subprocess.TimeoutExpired:
        warmup.kill()
        warmup.wait()

    # Measurement: launch all pairs simultaneously
    log_info(f"Measuring: {pair_count} pairs x {rounds} rounds")
    pairs = []
    for _ in range(pair_count):
        p = subprocess.Popen(
            [sys.executable, "-c", pair_script],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        pairs.append(p)

    all_rtt: list[int] = []
    for p in pairs:
        try:
            stdout, _ = p.communicate(timeout=120)
            for line in stdout.decode(errors="replace").splitlines():
                line = line.strip()
                if line and line.isdigit():
                    all_rtt.append(int(line))
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    result = {
        "survived": True,
        "pairs": pair_count,
        "rounds_per_pair": rounds,
        "total_ops": len(all_rtt),
        "rtt_median_us": int(percentile(all_rtt, 50)) if all_rtt else 0,
        "rtt_p99_us": int(percentile(all_rtt, 99)) if all_rtt else 0,
        "rtt_worst_us": int(max(all_rtt)) if all_rtt else 0,
    }

    log_info(f"IPC: {len(all_rtt)} round-trips, "
             f"median={result['rtt_median_us']}us, "
             f"p99={result['rtt_p99_us']}us, "
             f"worst={result['rtt_worst_us']}us")
    return result


# APPLICATION LAUNCH MEASUREMENT

def measure_launch(binary: Path, n_cpus: int,
                   launch_count: int = 100,
                   warmup_secs: int = 3) -> dict:
    """Measure fork+exec latency under full CPU load.

    Sequentially launches short-lived processes (/usr/bin/true) and measures
    wall-clock time from subprocess.run() start to completion. Simulates
    opening apps while the system is under compile load.
    """
    if n_cpus < 1:
        return {"survived": True, "launches": 0}

    log_info(f"Launch test: {launch_count} launches, {n_cpus} stress workers")

    # Start stress workers on all CPUs
    workers = []
    for cpu in range(n_cpus):
        p = subprocess.Popen(
            [str(binary), "stress-worker", "--cpu", str(cpu)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        workers.append(p)

    launch_cmd = ["/usr/bin/true"]
    if not os.path.exists("/usr/bin/true"):
        launch_cmd = [sys.executable, "-c", ""]

    # Warmup (a few launches, discard)
    log_info(f"Warmup: {warmup_secs}s")
    warmup_end = time.monotonic() + warmup_secs
    while time.monotonic() < warmup_end:
        subprocess.run(launch_cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    # Measurement
    log_info(f"Measuring: {launch_count} launches")
    latencies_us: list[int] = []
    for _ in range(launch_count):
        start = time.monotonic()
        subprocess.run(launch_cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        elapsed_us = int((time.monotonic() - start) * 1_000_000)
        latencies_us.append(elapsed_us)

    # Stop stress workers
    for w in workers:
        w.send_signal(signal.SIGINT)
    for w in workers:
        try:
            w.wait(timeout=5)
        except subprocess.TimeoutExpired:
            w.kill()
            w.wait()

    m, std = mean_stdev([float(x) for x in latencies_us])
    result = {
        "survived": True,
        "launches": launch_count,
        "launch_mean_us": int(m),
        "launch_median_us": int(percentile(latencies_us, 50)) if latencies_us else 0,
        "launch_p99_us": int(percentile(latencies_us, 99)) if latencies_us else 0,
        "launch_worst_us": int(max(latencies_us)) if latencies_us else 0,
    }

    log_info(f"Launch: {launch_count} runs, "
             f"mean={result['launch_mean_us']}us, "
             f"p99={result['launch_p99_us']}us, "
             f"worst={result['launch_worst_us']}us")
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

        # REGIME + FLAGS: [BPF], [BPF BURST], [BPF LONGRUN],
        # [BPF BURST LONGRUN], [MIXED], [MIXED BURST], [HEAVY LONGRUN], etc.
        regime_match = re.search(
            r'\[(BPF|Light|Mixed|Heavy|LIGHT|MIXED|HEAVY)((?:\s+(?:BURST|LONGRUN))*)\]', line)
        if regime_match:
            tick["regime"] = regime_match.group(1)
            flags = regime_match.group(2).upper()
            tick["burst_active"] = "BURST" in flags
            tick["longrun_active"] = "LONGRUN" in flags

            if tick["regime"] == "BPF":
                m = re.search(r"procdb:\s*(\d+)\s", line)
                if m:
                    tick["procdb_hits"] = int(m.group(1))
            else:
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

            # Burst metrics
            br = sched_data.get("burst", {})
            if br:
                survived = 1 if br.get("survived", True) else 0
                gauge("pandemonium_bench_burst_survived",
                      "Whether scheduler survived burst (1=OK, 0=CRASHED)",
                      survived, labels)
                baseline = br.get("baseline", {})
                if baseline.get("samples", 0) > 0:
                    gauge("pandemonium_bench_burst_baseline_p99_us",
                          "Baseline P99 before burst",
                          baseline["p99_us"], labels)
                burst = br.get("burst", {})
                if burst.get("samples", 0) > 0:
                    gauge("pandemonium_bench_burst_p99_us",
                          "P99 during burst",
                          burst["p99_us"], labels)
                    gauge("pandemonium_bench_burst_worst_us",
                          "Worst-case latency during burst",
                          burst["worst_us"], labels)
                    gauge("pandemonium_bench_burst_samples",
                          "Latency samples collected during burst",
                          burst["samples"], labels)

            # Long-running metrics
            lr = sched_data.get("longrun", {})
            if lr:
                survived = 1 if lr.get("survived", True) else 0
                gauge("pandemonium_bench_longrun_survived",
                      "Whether scheduler survived long-run test (1=OK, 0=CRASHED)",
                      survived, labels)
                lr_lat = lr.get("latency", {})
                if lr_lat.get("samples", 0) > 0:
                    gauge("pandemonium_bench_longrun_latency_p99_us",
                          "P99 latency during long-running process test",
                          lr_lat["p99_us"], labels)
                    gauge("pandemonium_bench_longrun_latency_worst_us",
                          "Worst-case latency during long-running process test",
                          lr_lat["worst_us"], labels)
                if lr.get("work_total", 0) > 0:
                    gauge("pandemonium_bench_longrun_work_total",
                          "Total SHA256 iterations across all long-runners",
                          lr["work_total"], labels)
                    gauge("pandemonium_bench_longrun_work_min",
                          "Minimum work by any single long-runner (starvation detector)",
                          lr["work_min"], labels)

            # Mixed workload metrics
            mx = sched_data.get("mixed", {})
            if mx:
                survived = 1 if mx.get("survived", True) else 0
                gauge("pandemonium_bench_mixed_survived",
                      "Whether scheduler survived mixed test (1=OK, 0=CRASHED)",
                      survived, labels)
                mx_lat = mx.get("latency", {})
                if mx_lat.get("samples", 0) > 0:
                    gauge("pandemonium_bench_mixed_latency_p99_us",
                          "P99 latency during mixed workload test",
                          mx_lat["p99_us"], labels)
                    gauge("pandemonium_bench_mixed_latency_worst_us",
                          "Worst-case latency during mixed workload test",
                          mx_lat["worst_us"], labels)
                if mx.get("work_total", 0) > 0:
                    gauge("pandemonium_bench_mixed_work_total",
                          "Total SHA256 iterations in mixed test",
                          mx["work_total"], labels)
                    gauge("pandemonium_bench_mixed_work_min",
                          "Minimum work by any long-runner in mixed test",
                          mx["work_min"], labels)
                if mx.get("work_max", 0) > 0:
                    gauge("pandemonium_bench_mixed_work_max",
                          "Maximum work by any long-runner in mixed test",
                          mx["work_max"], labels)

            # Deadline metrics
            dl = sched_data.get("deadline", {})
            if dl and dl.get("total_frames", 0) > 0:
                survived = 1 if dl.get("survived", True) else 0
                gauge("pandemonium_bench_deadline_survived",
                      "Whether scheduler survived deadline test (1=OK, 0=CRASHED)",
                      survived, labels)
                gauge("pandemonium_bench_deadline_total_frames",
                      "Total frame cycles measured",
                      dl["total_frames"], labels)
                gauge("pandemonium_bench_deadline_missed_frames",
                      "Frames exceeding jitter threshold",
                      dl["missed_frames"], labels)
                gauge("pandemonium_bench_deadline_miss_ratio",
                      "Fraction of frames missed",
                      dl["miss_ratio"], labels)
                gauge("pandemonium_bench_deadline_jitter_p99_us",
                      "P99 frame scheduling jitter",
                      dl["jitter_p99_us"], labels)
                gauge("pandemonium_bench_deadline_jitter_worst_us",
                      "Worst-case frame scheduling jitter",
                      dl["jitter_worst_us"], labels)

            # IPC metrics
            ipc = sched_data.get("ipc", {})
            if ipc and ipc.get("total_ops", 0) > 0:
                survived = 1 if ipc.get("survived", True) else 0
                gauge("pandemonium_bench_ipc_survived",
                      "Whether scheduler survived IPC test (1=OK, 0=CRASHED)",
                      survived, labels)
                gauge("pandemonium_bench_ipc_rtt_median_us",
                      "Median pipe round-trip latency",
                      ipc["rtt_median_us"], labels)
                gauge("pandemonium_bench_ipc_rtt_p99_us",
                      "P99 pipe round-trip latency",
                      ipc["rtt_p99_us"], labels)
                gauge("pandemonium_bench_ipc_rtt_worst_us",
                      "Worst-case pipe round-trip latency",
                      ipc["rtt_worst_us"], labels)

            # Launch metrics
            lnch = sched_data.get("launch", {})
            if lnch and lnch.get("launches", 0) > 0:
                survived = 1 if lnch.get("survived", True) else 0
                gauge("pandemonium_bench_launch_survived",
                      "Whether scheduler survived launch test (1=OK, 0=CRASHED)",
                      survived, labels)
                gauge("pandemonium_bench_launch_mean_us",
                      "Mean fork+exec latency under load",
                      lnch["launch_mean_us"], labels)
                gauge("pandemonium_bench_launch_p99_us",
                      "P99 fork+exec latency under load",
                      lnch["launch_p99_us"], labels)
                gauge("pandemonium_bench_launch_worst_us",
                      "Worst-case fork+exec latency under load",
                      lnch["launch_worst_us"], labels)

            # Post-burst recovery metrics
            br = sched_data.get("burst", {})
            if br:
                br_recovery = br.get("recovery", {})
                if br_recovery.get("samples", 0) > 0:
                    gauge("pandemonium_bench_burst_recovery_p99_us",
                          "P99 latency during post-burst recovery",
                          br_recovery["p99_us"], labels)
                    gauge("pandemonium_bench_burst_recovery_worst_us",
                          "Worst-case latency during post-burst recovery",
                          br_recovery["worst_us"], labels)

                # CUSUM burst detection verification
                if "cusum_activated" in br:
                    gauge("pandemonium_bench_burst_cusum_activated",
                          "Whether CUSUM burst detection fired (1=yes, 0=no)",
                          1 if br["cusum_activated"] else 0, labels)
                if "cusum_ticks" in br:
                    gauge("pandemonium_bench_burst_cusum_ticks",
                          "Number of scheduler ticks with burst_mode active",
                          br["cusum_ticks"], labels)

            # Longrun detection verification
            lr_ticks = sched_data.get("longrun_ticks", 0)
            if lr_ticks > 0:
                gauge("pandemonium_bench_longrun_ticks",
                      "Number of scheduler ticks with longrun_mode active",
                      lr_ticks, labels)

            # Long-run work distribution
            lr = sched_data.get("longrun", {})
            if lr and lr.get("work_max", 0) > 0:
                gauge("pandemonium_bench_longrun_work_max",
                      "Maximum work by any single long-runner",
                      lr["work_max"], labels)

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
                for field in ["idle_pct", "preempt",
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
    if data.get("deadline_only"):
        mode = "DEADLINE ONLY"
    elif data.get("ipc_only"):
        mode = "IPC ONLY"
    elif data.get("launch_only"):
        mode = "LAUNCH ONLY"
    elif data.get("mixed_only"):
        mode = "MIXED ONLY"
    elif data.get("longrun_only"):
        mode = "LONG-RUN ONLY"
    elif data.get("burst_only"):
        mode = "BURST ONLY"
    else:
        mode = "BENCH-SCALE"
    lines.append(f"PANDEMONIUM {mode}")
    lines.append(f"VERSION:     {data.get('version', '?')}")
    if not data.get("burst_only"):
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

        # Burst table
        has_burst = any(
            s.get("burst", {}).get("burst", {}).get("samples", 0) > 0
            for s in schedulers.values())
        if has_burst:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'STATUS':>8} "
                        f"{'BASE P99':>10} {'BURST P99':>10} "
                        f"{'WORST':>10} {'RECV P99':>10} {'SAMPLES':>8}")
            for sched_name, sched_data in schedulers.items():
                br = sched_data.get("burst", {})
                if not br:
                    continue
                status = "OK" if br.get("survived", True) else "CRASHED"
                base = br.get("baseline", {})
                burst = br.get("burst", {})
                recovery = br.get("recovery", {})
                bp99 = (f"{base['p99_us']}us"
                        if base.get("samples", 0) > 0 else "--")
                brp99 = (f"{burst['p99_us']}us"
                         if burst.get("samples", 0) > 0 else "--")
                worst = (f"{burst['worst_us']}us"
                         if burst.get("samples", 0) > 0 else "--")
                rp99 = (f"{recovery['p99_us']}us"
                        if recovery.get("samples", 0) > 0 else "--")
                samples = (str(burst.get("samples", 0))
                           if burst.get("samples", 0) > 0 else "--")
                lines.append(f"{sched_name:<28} {status:>8} "
                             f"{bp99:>10} {brp99:>10} "
                             f"{worst:>10} {rp99:>10} {samples:>8}")

        # Long-running table
        has_longrun = any(
            s.get("longrun", {}).get("latency", {}).get("samples", 0) > 0
            for s in schedulers.values())
        if has_longrun:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'STATUS':>8} "
                        f"{'LAT P99':>10} {'WORST':>10} "
                        f"{'WORK TOT':>10} {'WORK MIN':>10} {'WORK MAX':>10}")
            for sched_name, sched_data in schedulers.items():
                lr = sched_data.get("longrun", {})
                if not lr:
                    continue
                status = "OK" if lr.get("survived", True) else "CRASHED"
                lat = lr.get("latency", {})
                lp99 = (f"{lat['p99_us']}us"
                        if lat.get("samples", 0) > 0 else "--")
                lworst = (f"{lat['worst_us']}us"
                          if lat.get("samples", 0) > 0 else "--")
                work_tot = str(lr.get("work_total", 0))
                work_min = str(lr.get("work_min", 0))
                work_max = str(lr.get("work_max", 0))
                lines.append(f"{sched_name:<28} {status:>8} "
                             f"{lp99:>10} {lworst:>10} "
                             f"{work_tot:>10} {work_min:>10} {work_max:>10}")

        # Mixed workload table
        has_mixed = any(
            s.get("mixed", {}).get("latency", {}).get("samples", 0) > 0
            for s in schedulers.values())
        if has_mixed:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'STATUS':>8} "
                        f"{'LAT P99':>10} {'WORST':>10} "
                        f"{'WORK TOT':>10} {'WORK MIN':>10} {'WORK MAX':>10}")
            for sched_name, sched_data in schedulers.items():
                mx = sched_data.get("mixed", {})
                if not mx:
                    continue
                status = "OK" if mx.get("survived", True) else "CRASHED"
                lat = mx.get("latency", {})
                mp99 = (f"{lat['p99_us']}us"
                        if lat.get("samples", 0) > 0 else "--")
                mworst = (f"{lat['worst_us']}us"
                          if lat.get("samples", 0) > 0 else "--")
                work_tot = str(mx.get("work_total", 0))
                work_min = str(mx.get("work_min", 0))
                work_max = str(mx.get("work_max", 0))
                lines.append(f"{sched_name:<28} {status:>8} "
                             f"{mp99:>10} {mworst:>10} "
                             f"{work_tot:>10} {work_min:>10} {work_max:>10}")

        # Deadline table
        has_deadline = any(
            s.get("deadline", {}).get("total_frames", 0) > 0
            for s in schedulers.values())
        if has_deadline:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'STATUS':>8} "
                        f"{'MISSES':>8} {'TOTAL':>8} "
                        f"{'RATIO':>8} {'JIT P99':>10} {'WORST':>10}")
            for sched_name, sched_data in schedulers.items():
                dl = sched_data.get("deadline", {})
                if not dl or dl.get("total_frames", 0) == 0:
                    continue
                status = "OK" if dl.get("survived", True) else "CRASHED"
                missed = str(dl.get("missed_frames", 0))
                total = str(dl.get("total_frames", 0))
                ratio = f"{dl.get('miss_ratio', 0):.1%}"
                jp99 = f"{dl['jitter_p99_us']}us"
                jworst = f"{dl['jitter_worst_us']}us"
                lines.append(f"{sched_name:<28} {status:>8} "
                             f"{missed:>8} {total:>8} "
                             f"{ratio:>8} {jp99:>10} {jworst:>10}")

        # IPC table
        has_ipc = any(
            s.get("ipc", {}).get("total_ops", 0) > 0
            for s in schedulers.values())
        if has_ipc:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'STATUS':>8} "
                        f"{'PAIRS':>8} {'MEDIAN':>10} "
                        f"{'P99':>10} {'WORST':>10}")
            for sched_name, sched_data in schedulers.items():
                ipc = sched_data.get("ipc", {})
                if not ipc or ipc.get("total_ops", 0) == 0:
                    continue
                status = "OK" if ipc.get("survived", True) else "CRASHED"
                pairs = str(ipc.get("pairs", 0))
                median = f"{ipc['rtt_median_us']}us"
                p99 = f"{ipc['rtt_p99_us']}us"
                worst = f"{ipc['rtt_worst_us']}us"
                lines.append(f"{sched_name:<28} {status:>8} "
                             f"{pairs:>8} {median:>10} "
                             f"{p99:>10} {worst:>10}")

        # Launch table
        has_launch = any(
            s.get("launch", {}).get("launches", 0) > 0
            for s in schedulers.values())
        if has_launch:
            lines.append("")
            lines.append(f"{'SCHEDULER':<28} {'STATUS':>8} "
                        f"{'COUNT':>8} {'MEAN':>10} "
                        f"{'P99':>10} {'WORST':>10}")
            for sched_name, sched_data in schedulers.items():
                lnch = sched_data.get("launch", {})
                if not lnch or lnch.get("launches", 0) == 0:
                    continue
                status = "OK" if lnch.get("survived", True) else "CRASHED"
                count = str(lnch.get("launches", 0))
                mean = f"{lnch['launch_mean_us']}us"
                p99 = f"{lnch['launch_p99_us']}us"
                worst = f"{lnch['launch_worst_us']}us"
                lines.append(f"{sched_name:<28} {status:>8} "
                             f"{count:>8} {mean:>10} "
                             f"{p99:>10} {worst:>10}")

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

        # Burst summary matrix
        has_any_burst = any(
            results.get(c, {}).get(s, {}).get("burst", {})
            .get("burst", {}).get("samples", 0) > 0
            for c in sorted_cores for s in all_schedulers)
        if has_any_burst:
            lines.append("BURST P99 (us)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    br = results.get(c, {}).get(sched, {}).get("burst", {})
                    burst = br.get("burst", {})
                    p99 = burst.get("p99_us")
                    if p99 is not None and burst.get("samples", 0) > 0:
                        survived = br.get("survived", True)
                        tag = "" if survived else "*"
                        row += f" {str(p99) + tag:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

        # Long-run summary matrix
        has_any_longrun = any(
            results.get(c, {}).get(s, {}).get("longrun", {})
            .get("latency", {}).get("samples", 0) > 0
            for c in sorted_cores for s in all_schedulers)
        if has_any_longrun:
            lines.append("LONG-RUN LATENCY P99 (us)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    lr = results.get(c, {}).get(sched, {}).get("longrun", {})
                    lat = lr.get("latency", {})
                    p99 = lat.get("p99_us")
                    if p99 is not None and lat.get("samples", 0) > 0:
                        survived = lr.get("survived", True)
                        tag = "" if survived else "*"
                        row += f" {str(p99) + tag:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

            lines.append("LONG-RUN WORK (MIN PER-PROCESS)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    lr = results.get(c, {}).get(sched, {}).get("longrun", {})
                    work_min = lr.get("work_min")
                    if work_min is not None and work_min > 0:
                        row += f" {work_min:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

            lines.append("LONG-RUN WORK (MAX PER-PROCESS)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    lr = results.get(c, {}).get(sched, {}).get("longrun", {})
                    work_max = lr.get("work_max")
                    if work_max is not None and work_max > 0:
                        row += f" {work_max:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

        # Mixed summary matrix
        has_any_mixed = any(
            results.get(c, {}).get(s, {}).get("mixed", {})
            .get("latency", {}).get("samples", 0) > 0
            for c in sorted_cores for s in all_schedulers)
        if has_any_mixed:
            lines.append("MIXED LATENCY P99 (us)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    mx = results.get(c, {}).get(sched, {}).get("mixed", {})
                    lat = mx.get("latency", {})
                    p99 = lat.get("p99_us")
                    if p99 is not None and lat.get("samples", 0) > 0:
                        survived = mx.get("survived", True)
                        tag = "" if survived else "*"
                        row += f" {str(p99) + tag:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

            lines.append("MIXED WORK MIN (PER-PROCESS)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    mx = results.get(c, {}).get(sched, {}).get("mixed", {})
                    work_min = mx.get("work_min")
                    if work_min is not None and work_min > 0:
                        row += f" {work_min:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

            lines.append("MIXED WORK MAX (PER-PROCESS)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    mx = results.get(c, {}).get(sched, {}).get("mixed", {})
                    work_max = mx.get("work_max")
                    if work_max is not None and work_max > 0:
                        row += f" {work_max:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

        # Deadline jitter summary matrix
        has_any_deadline = any(
            results.get(c, {}).get(s, {}).get("deadline", {})
            .get("total_frames", 0) > 0
            for c in sorted_cores for s in all_schedulers)
        if has_any_deadline:
            lines.append("DEADLINE JITTER P99 (us)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    dl = results.get(c, {}).get(sched, {}).get("deadline", {})
                    jp99 = dl.get("jitter_p99_us")
                    if jp99 is not None and dl.get("total_frames", 0) > 0:
                        survived = dl.get("survived", True)
                        tag = "" if survived else "*"
                        row += f" {str(jp99) + tag:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

            lines.append("DEADLINE MISS RATIO")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    dl = results.get(c, {}).get(sched, {}).get("deadline", {})
                    ratio = dl.get("miss_ratio")
                    if ratio is not None and dl.get("total_frames", 0) > 0:
                        row += f" {ratio:>7.1%}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

        # IPC round-trip summary matrix
        has_any_ipc = any(
            results.get(c, {}).get(s, {}).get("ipc", {})
            .get("total_ops", 0) > 0
            for c in sorted_cores for s in all_schedulers)
        if has_any_ipc:
            lines.append("IPC ROUND-TRIP P99 (us)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    ipc = results.get(c, {}).get(sched, {}).get("ipc", {})
                    rp99 = ipc.get("rtt_p99_us")
                    if rp99 is not None and ipc.get("total_ops", 0) > 0:
                        survived = ipc.get("survived", True)
                        tag = "" if survived else "*"
                        row += f" {str(rp99) + tag:>8}"
                    else:
                        row += f" {'--':>8}"
                lines.append(row)

            lines.append("")

        # App launch summary matrix
        has_any_launch = any(
            results.get(c, {}).get(s, {}).get("launch", {})
            .get("launches", 0) > 0
            for c in sorted_cores for s in all_schedulers)
        if has_any_launch:
            lines.append("APP LAUNCH P99 (us)")
            header = f"{'SCHEDULER':<28}"
            for c in sorted_cores:
                header += f" {c + 'C':>8}"
            lines.append(header)

            for sched in all_schedulers:
                row = f"{sched:<28}"
                for c in sorted_cores:
                    lnch = results.get(c, {}).get(sched, {}).get("launch", {})
                    lp99 = lnch.get("launch_p99_us")
                    if lp99 is not None and lnch.get("launches", 0) > 0:
                        survived = lnch.get("survived", True)
                        tag = "" if survived else "*"
                        row += f" {str(lp99) + tag:>8}"
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

    dmesg = DmesgMonitor()

    # Trace capture (optional)
    trace = None
    trace_path = None
    if getattr(args, "trace", False):
        stamp_early = datetime.now().strftime("%Y%m%d-%H%M%S")
        trace_path = LOG_DIR / f"trace-{stamp_early}.log"
        trace = TraceCapture(trace_path)
        if not trace.start():
            log_warn("trace capture unavailable, continuing without")
            trace = None

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
        dmesg.save()
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
    if args.deadline:
        log_info("Mode: DEADLINE ONLY (periodic frame jitter)")
    elif args.ipc:
        log_info("Mode: IPC ONLY (pipe round-trip latency)")
    elif args.launch:
        log_info("Mode: LAUNCH ONLY (fork+exec latency)")
    elif args.mixed:
        log_info("Mode: MIXED ONLY (burst + long-run combined)")
    elif args.longrun:
        log_info("Mode: LONG-RUN ONLY (skipping latency, throughput, burst)")
    elif args.burst:
        log_info("Mode: BURST ONLY (skipping latency + throughput)")
    else:
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
        "burst_only": args.burst,
        "longrun_only": args.longrun,
        "mixed_only": args.mixed,
        "deadline_only": args.deadline,
        "ipc_only": args.ipc,
        "launch_only": args.launch,
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

                any_single = (args.burst or args.longrun or args.mixed
                              or args.deadline or args.ipc or args.launch)
                run_full = not any_single

                if run_full:
                    # Latency measurement
                    latency = measure_latency(BINARY, n,
                                              iterations=args.iterations)
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
                        elif (cores_str in eevdf_mean
                              and eevdf_mean[cores_str] > 0):
                            delta = ((m - eevdf_mean[cores_str])
                                     / eevdf_mean[cores_str]) * 100.0
                            tp["vs_eevdf_pct"] = round(delta, 1)
                        sched_result["throughput"] = tp

                if run_full or args.burst:
                    # Burst measurement (app launch under full load)
                    burst_size = n * 4
                    if burst_size < 8:
                        burst_size = 8
                    burst_result = measure_burst(BINARY, n, burst_size)
                    if guard is not None and guard.proc.poll() is not None:
                        burst_result["survived"] = False
                        log_error(f"{sched_name} CRASHED during burst "
                                  f"(exit {guard.proc.returncode})")
                    sched_result["burst"] = burst_result

                if run_full or args.longrun:
                    # Long-running process test
                    longrun_count = max(4, n // 2)
                    longrun_result = measure_longrun(BINARY, n,
                                                     longrun_count=longrun_count)
                    if guard is not None and guard.proc.poll() is not None:
                        longrun_result["survived"] = False
                        log_error(f"{sched_name} CRASHED during long-run "
                                  f"(exit {guard.proc.returncode})")
                    sched_result["longrun"] = longrun_result

                if run_full or args.mixed:
                    # Mixed workload test (burst + longrun combined)
                    mixed_burst_size = n * 4
                    if mixed_burst_size < 8:
                        mixed_burst_size = 8
                    mixed_result = measure_mixed(BINARY, n,
                                                 longrun_count=max(4, n // 2),
                                                 burst_size=mixed_burst_size)
                    if guard is not None and guard.proc.poll() is not None:
                        mixed_result["survived"] = False
                        log_error(f"{sched_name} CRASHED during mixed test "
                                  f"(exit {guard.proc.returncode})")
                    sched_result["mixed"] = mixed_result

                if run_full or args.deadline:
                    # Periodic deadline (frame scheduling jitter)
                    deadline_result = measure_deadline(BINARY, n)
                    if guard is not None and guard.proc.poll() is not None:
                        deadline_result["survived"] = False
                        log_error(f"{sched_name} CRASHED during deadline test "
                                  f"(exit {guard.proc.returncode})")
                    sched_result["deadline"] = deadline_result

                if run_full or args.ipc:
                    # IPC round-trip (pipe ping-pong)
                    ipc_result = measure_ipc(BINARY, n)
                    if guard is not None and guard.proc.poll() is not None:
                        ipc_result["survived"] = False
                        log_error(f"{sched_name} CRASHED during IPC test "
                                  f"(exit {guard.proc.returncode})")
                    sched_result["ipc"] = ipc_result

                if run_full or args.launch:
                    # Application launch under load
                    launch_result = measure_launch(BINARY, n)
                    if guard is not None and guard.proc.poll() is not None:
                        launch_result["survived"] = False
                        log_error(f"{sched_name} CRASHED during launch test "
                                  f"(exit {guard.proc.returncode})")
                    sched_result["launch"] = launch_result

                # Stop scheduler, capture telemetry
                stdout = stop_and_wait(guard)
                if stdout and "PANDEMONIUM" in sched_name:
                    ticks = parse_tick_lines(stdout)
                    knobs = parse_knobs_line(stdout)

                    # BURST ACTIVATION VERIFICATION
                    if "burst" in sched_result:
                        burst_ticks = [t for t in ticks if t.get("burst_active")]
                        if burst_ticks:
                            log_info(f"Burst verification: CUSUM activated in "
                                     f"{len(burst_ticks)}/{len(ticks)} ticks")
                        else:
                            log_warn(f"Burst verification: CUSUM NEVER ACTIVATED "
                                     f"(burst test may be ineffective at {n} cores)")
                        sched_result["burst"]["cusum_activated"] = len(burst_ticks) > 0
                        sched_result["burst"]["cusum_ticks"] = len(burst_ticks)

                    # LONGRUN ACTIVATION VERIFICATION
                    longrun_ticks = [t for t in ticks if t.get("longrun_active")]
                    if longrun_ticks:
                        log_info(f"Longrun verification: detected in "
                                 f"{len(longrun_ticks)}/{len(ticks)} ticks")
                    sched_result["longrun_ticks"] = len(longrun_ticks)

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

    # Dmesg
    dmesg.save(stamp)

    # Trace teardown
    if trace is not None:
        trace.stop()
        log_info(f"Trace log: {trace_path}")
        if trace_path and trace_path.exists():
            lines = trace_path.read_text().splitlines()
            if lines:
                tail = lines[-20:]
                log_info(f"Last {len(tail)} trace events:")
                for line in tail:
                    log_info(f"  {line.rstrip()}")

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

    dmesg = DmesgMonitor()

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
            dmesg.save()
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

        dmesg.save(stamp)
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


# BENCH-TRACE WORKLOAD GENERATORS

class _StressWorkers:
    """Background CPU stress saturating all cores (for bench-trace)."""

    def __init__(self, n_cpus):
        self.procs = []
        self.n = n_cpus

    def start(self):
        script = (
            "import hashlib\n"
            "d = b'stress' * 1000\n"
            "while True:\n"
            "    d = hashlib.sha256(d).digest()\n"
        )
        for _ in range(self.n):
            p = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.procs.append(p)

    def stop(self):
        for p in self.procs:
            p.kill()
        for p in self.procs:
            p.wait()
        self.procs.clear()


class _LatencyProbe:
    """Wakeup latency via sleep/wake cycles (for bench-trace)."""

    def __init__(self, duration_secs):
        self.duration = duration_secs
        self.proc = None

    def start(self):
        script = (
            f"import time, sys\n"
            f"end = time.monotonic() + {self.duration}\n"
            "while time.monotonic() < end:\n"
            "    t0 = time.monotonic()\n"
            "    time.sleep(0.001)\n"
            "    lat = (time.monotonic() - t0 - 0.001) * 1e6\n"
            "    if lat > 0:\n"
            "        print(f'{lat:.0f}', flush=True)\n"
        )
        self.proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )

    def collect(self) -> list[float]:
        if self.proc is None:
            return []
        out, _ = self.proc.communicate(timeout=self.duration + 10)
        return [float(x) for x in out.strip().splitlines() if x.strip()]


class _LongRunners:
    """Persistent CPU-bound processes that count work iterations (for bench-trace)."""

    def __init__(self, count):
        self.count = count
        self.procs = []

    def start(self, duration_secs):
        script = (
            f"import hashlib, time, sys\n"
            f"end = time.monotonic() + {duration_secs}\n"
            "iters = 0\n"
            "d = b'longrun' * 1000\n"
            "while time.monotonic() < end:\n"
            "    for _ in range(100):\n"
            "        d = hashlib.sha256(d).digest()\n"
            "    iters += 100\n"
            "print(iters, flush=True)\n"
        )
        for _ in range(self.count):
            p = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            self.procs.append(p)

    def collect(self, timeout=60) -> list[int]:
        results = []
        for p in self.procs:
            try:
                out, _ = p.communicate(timeout=timeout)
                results.append(int(out.strip()))
            except (subprocess.TimeoutExpired, ValueError):
                p.kill()
                results.append(0)
        self.procs.clear()
        return results


def _burst_processes(count):
    """Spawn count short-lived CPU-bound processes."""
    script = (
        "import hashlib\n"
        "d = b'burst' * 1000\n"
        "for _ in range(2000):\n"
        "    d = hashlib.sha256(d).digest()\n"
    )
    procs = []
    for _ in range(count):
        p = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append(p)
    return procs


# BENCH-TRACE PHASES

def _trace_phase_latency(nr_cpus, dmesg, sched_alive_fn, duration=15):
    log_info(f"PHASE: latency ({duration}s)")
    probe = _LatencyProbe(duration)
    probe.start()
    samples = probe.collect()
    if samples:
        p99 = percentile(samples, 99)
        log_info(f"  latency: {len(samples)} samples, P99={p99:.0f}us")
    if dmesg.check():
        return False
    return sched_alive_fn()


def _trace_phase_burst(nr_cpus, dmesg, sched_alive_fn):
    burst_size = nr_cpus * 4
    log_info(f"PHASE: burst (size={burst_size})")
    probe_base = _LatencyProbe(5)
    probe_base.start()
    probe_base.collect()
    if dmesg.check() or not sched_alive_fn():
        return False
    burst_procs = _burst_processes(burst_size)
    probe_burst = _LatencyProbe(10)
    probe_burst.start()
    burst_samples = probe_burst.collect()
    for p in burst_procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    if dmesg.check() or not sched_alive_fn():
        return False
    probe_recv = _LatencyProbe(5)
    probe_recv.start()
    recv_samples = probe_recv.collect()
    bp99 = percentile(burst_samples, 99) if burst_samples else 0
    rp99 = percentile(recv_samples, 99) if recv_samples else 0
    log_info(f"  burst P99={bp99:.0f}us, recovery P99={rp99:.0f}us")
    if dmesg.check():
        return False
    return sched_alive_fn()


def _trace_phase_longrun(nr_cpus, dmesg, sched_alive_fn, duration=20):
    n_runners = max(2, nr_cpus // 2)
    log_info(f"PHASE: longrun ({n_runners} runners, {duration}s)")
    runners = _LongRunners(n_runners)
    runners.start(duration)
    probe = _LatencyProbe(duration)
    probe.start()
    samples = probe.collect()
    work = runners.collect(timeout=duration + 15)
    p99 = percentile(samples, 99) if samples else 0
    min_work = min(work) if work else 0
    log_info(f"  longrun P99={p99:.0f}us, min_work={min_work}")
    if dmesg.check():
        return False
    return sched_alive_fn()


def _trace_phase_mixed(nr_cpus, dmesg, sched_alive_fn, duration=30):
    n_runners = max(2, nr_cpus // 2)
    burst_size = nr_cpus * 4
    log_info(f"PHASE: mixed ({n_runners} runners + {burst_size} burst, {duration}s)")
    runners = _LongRunners(n_runners)
    runners.start(duration)
    probe = _LatencyProbe(duration)
    probe.start()
    time.sleep(5)
    if dmesg.check() or not sched_alive_fn():
        runners.collect(timeout=5)
        return False
    burst_procs = _burst_processes(burst_size)
    samples = probe.collect()
    work = runners.collect(timeout=duration + 15)
    for p in burst_procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    p99 = percentile(samples, 99) if samples else 0
    min_work = min(work) if work else 0
    log_info(f"  mixed P99={p99:.0f}us, min_work={min_work}")
    if dmesg.check():
        return False
    return sched_alive_fn()


def _trace_phase_deadline(nr_cpus, dmesg, sched_alive_fn, duration=15):
    log_info(f"PHASE: deadline ({duration}s)")
    script = (
        f"import time, sys\n"
        f"target_ns = 16_666_667\n"
        f"misses = 0\n"
        f"total = 0\n"
        f"end = time.monotonic() + {duration}\n"
        "while time.monotonic() < end:\n"
        "    t0 = time.monotonic()\n"
        "    time.sleep(target_ns / 1e9)\n"
        "    actual = (time.monotonic() - t0) * 1e9\n"
        "    jitter = actual - target_ns\n"
        "    total += 1\n"
        "    if jitter > 500_000:\n"
        "        misses += 1\n"
        "print(f'{misses}/{total}', flush=True)\n"
    )
    p = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    try:
        out, _ = p.communicate(timeout=duration + 10)
        log_info(f"  deadline: {out.strip()}")
    except subprocess.TimeoutExpired:
        p.kill()
    if dmesg.check():
        return False
    return sched_alive_fn()


def _trace_phase_ipc(nr_cpus, dmesg, sched_alive_fn):
    n_pairs = max(2, nr_cpus // 2)
    rounds = 10000
    log_info(f"PHASE: ipc ({n_pairs} pairs, {rounds} rounds)")
    script = (
        "import os, time, sys\n"
        "r1, w1 = os.pipe()\n"
        "r2, w2 = os.pipe()\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        f"    for _ in range({rounds}):\n"
        "        os.read(r1, 1)\n"
        "        os.write(w2, b'x')\n"
        "    os._exit(0)\n"
        "else:\n"
        "    t0 = time.monotonic()\n"
        f"    for _ in range({rounds}):\n"
        "        os.write(w1, b'x')\n"
        "        os.read(r2, 1)\n"
        "    elapsed = time.monotonic() - t0\n"
        "    os.waitpid(pid, 0)\n"
        f"    rtt = elapsed / {rounds} * 1e6\n"
        "    print(f'{rtt:.1f}', flush=True)\n"
    )
    procs = []
    for _ in range(n_pairs):
        p = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        procs.append(p)
    rtts = []
    for p in procs:
        try:
            out, _ = p.communicate(timeout=30)
            rtts.append(float(out.strip()))
        except (subprocess.TimeoutExpired, ValueError):
            p.kill()
    if rtts:
        log_info(f"  ipc: median={sorted(rtts)[len(rtts)//2]:.1f}us")
    if dmesg.check():
        return False
    return sched_alive_fn()


def _trace_phase_launch(nr_cpus, dmesg, sched_alive_fn, count=100):
    log_info(f"PHASE: launch ({count} launches)")
    times = []
    for _ in range(count):
        t0 = time.monotonic()
        subprocess.run(["/usr/bin/true"], capture_output=True)
        times.append((time.monotonic() - t0) * 1e6)
    if times:
        p99 = percentile(times, 99)
        log_info(f"  launch P99={p99:.0f}us")
    if dmesg.check():
        return False
    return sched_alive_fn()


# BENCH-TRACE COMMAND

def _trace_start_scheduler(nr_cpus=None):
    """Start PANDEMONIUM with stale detection and settle verification."""
    try:
        stale = SCX_OPS.read_text().strip()
        if stale:
            log_warn(f"Stale scheduler detected: '{stale}', waiting for cleanup...")
            if not wait_for_no_scheduler(timeout=15):
                log_error("stale scheduler did not unregister")
                return None
            log_info("Stale scheduler cleared")
    except (FileNotFoundError, PermissionError):
        pass

    cmd = ["sudo", str(BINARY), "--verbose"]
    if nr_cpus is not None:
        cmd.extend(["--nr-cpus", str(nr_cpus)])
    log_info(f"Starting: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setpgrp,
        text=True,
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            log_error(f"scheduler exited early (code {proc.returncode})")
            for line in err.strip().splitlines()[-5:]:
                log_error(f"  stderr: {line.rstrip()}")
            return None
        try:
            name = SCX_OPS.read_text().strip()
            if name == "pandemonium":
                log_info("Scheduler activated")
                time.sleep(2.0)
                if proc.poll() is not None:
                    err = proc.stderr.read() if proc.stderr else ""
                    log_error(f"scheduler died during settle (code {proc.returncode})")
                    for line in err.strip().splitlines()[-5:]:
                        log_error(f"  stderr: {line.rstrip()}")
                    return None
                return proc
        except (FileNotFoundError, PermissionError):
            pass
        time.sleep(0.1)
    log_error("scheduler did not activate within 10s")
    return None


def _trace_stop_scheduler(proc):
    if proc is None:
        return
    if proc.poll() is not None:
        log_warn(f"Scheduler already exited (code {proc.returncode})")
        measure_struct_ops_cleanup()
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGINT)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            measure_struct_ops_cleanup()
            return
        time.sleep(0.1)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait()
    measure_struct_ops_cleanup()


def _trace_run_iteration(iteration, total, nr_cpus):
    """Run one full workload iteration. Returns True if scheduler survived."""
    dmesg = DmesgMonitor()

    label = f"[{iteration}/{total}] " if total > 1 else ""
    log_info(f"{label}Starting scheduler")

    sched_proc = _trace_start_scheduler(nr_cpus=nr_cpus)
    if sched_proc is None:
        return False

    def sched_alive():
        return sched_proc is not None and sched_proc.poll() is None

    log_info(f"{label}Starting workload sequence at {nr_cpus}C")
    stress = _StressWorkers(nr_cpus)
    stress.start()
    time.sleep(2)

    phases = [
        ("latency",  lambda: _trace_phase_latency(nr_cpus, dmesg, sched_alive)),
        ("burst",    lambda: _trace_phase_burst(nr_cpus, dmesg, sched_alive)),
        ("longrun",  lambda: _trace_phase_longrun(nr_cpus, dmesg, sched_alive)),
        ("mixed",    lambda: _trace_phase_mixed(nr_cpus, dmesg, sched_alive)),
        ("deadline", lambda: _trace_phase_deadline(nr_cpus, dmesg, sched_alive)),
        ("ipc",      lambda: _trace_phase_ipc(nr_cpus, dmesg, sched_alive)),
        ("launch",   lambda: _trace_phase_launch(nr_cpus, dmesg, sched_alive)),
    ]

    crashed = False
    for name, fn in phases:
        alive = fn()
        if not alive:
            crashed = True
            if dmesg.crashed:
                log_error(f"{label}CRASH DETECTED during '{name}': {dmesg.crash_msg}")
            else:
                log_error(f"{label}Scheduler died during '{name}' (no dmesg crash)")
            break
        log_info(f"  '{name}' passed, scheduler alive")
    else:
        log_info(f"{label}ALL PHASES COMPLETE -- scheduler survived")

    stress.stop()
    _trace_stop_scheduler(sched_proc)
    dmesg.save()

    return not crashed


def cmd_bench_trace(args) -> int:
    """Crash-detection stress test with trace capture.

    Iterates core counts, runs all 7 workload phases per core count,
    live crash detection via DmesgMonitor between phases, TraceCapture
    always active. Reports survived/crashed per core count.
    """

    subprocess.run(["sudo", "true"])

    nuke_stale_build()

    if not build():
        return 1

    max_cpus = os.cpu_count() or 2

    if args.core_counts:
        core_counts = [int(c.strip()) for c in args.core_counts.split(",")]
        core_counts = [c for c in core_counts if 2 <= c <= max_cpus]
        core_counts = sorted(set(core_counts))
    else:
        core_counts = compute_core_counts(max_cpus)

    if not core_counts:
        log_error(f"no valid core counts (host has {max_cpus} CPUs, minimum is 2)")
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    trace_path = LOG_DIR / f"trace-{stamp}.log"
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    ver = get_version()
    git = get_git_info()
    dirty = " (dirty)" if git["dirty"] else ""
    log_info(f"bench-trace v{ver} [{git['commit']}{dirty}], "
             f"core_counts={core_counts}, iterations={args.iterations}, "
             f"host_cpus={max_cpus}")

    trace = TraceCapture(trace_path)
    results = {}

    try:
        trace_ok = trace.start()
        if not trace_ok:
            log_warn("trace capture unavailable, continuing with dmesg monitoring only")

        for nr_cpus in core_counts:
            log_info(f"[{nr_cpus}C] Restricting to {nr_cpus} cores")
            if nr_cpus < max_cpus:
                if not restrict_cpus(nr_cpus, max_cpus):
                    log_error(f"[{nr_cpus}C] failed to offline CPUs, skipping")
                    results[nr_cpus] = (0, args.iterations)
                    restore_all_cpus(max_cpus)
                    continue
            time.sleep(1)

            survived = 0
            crashed = 0

            for i in range(1, args.iterations + 1):
                if args.iterations > 1:
                    log_info(f"[{nr_cpus}C] ITERATION {i}/{args.iterations}")
                ok = _trace_run_iteration(i, args.iterations, nr_cpus)
                if ok:
                    survived += 1
                else:
                    crashed += 1
                if i < args.iterations:
                    log_info("Settling 3s before next iteration...")
                    time.sleep(3)

            results[nr_cpus] = (survived, crashed)
            log_info(f"[{nr_cpus}C] RESULTS: {survived}/{args.iterations} survived")

            if nr_cpus < max_cpus:
                restore_all_cpus(max_cpus)
                time.sleep(1)

    except KeyboardInterrupt:
        log_info("Interrupted")
    finally:
        restore_all_cpus(max_cpus)
        trace.stop()

        total_survived = 0
        total_crashed = 0
        if results:
            log_info("SUMMARY")
            for nr_cpus in sorted(results.keys()):
                s, c = results[nr_cpus]
                total_survived += s
                total_crashed += c
                status = "PASS" if c == 0 else "FAIL"
                log_info(f"  {nr_cpus:>3}C: {s}/{s+c} survived  {status}")
            log_info(f"  TOTAL: {total_survived}/{total_survived+total_crashed}")

        log_info(f"Trace events: {trace.count}")
        log_info(f"Trace log:    {trace_path}")

        if trace_path.exists():
            lines = trace_path.read_text().splitlines()
            if lines:
                tail = lines[-20:]
                log_info(f"Last {len(tail)} trace events:")
                for line in tail:
                    log_info(f"  {line.rstrip()}")

    return 0 if total_crashed == 0 else 1


# BENCH-CONTENTION PHASES

def _contention_phase_regime_sweep(nr_cpus, dmesg, sched_alive_fn, duration=30):
    """Force regime transitions under load: LIGHT -> HEAVY -> MIXED -> LIGHT, 3 cycles."""
    cycles = 3
    log_info(f"PHASE: regime-sweep ({cycles} cycles, {duration}s)")
    per_phase = duration // (cycles * 3)

    for cycle in range(1, cycles + 1):
        if not sched_alive_fn():
            return {"survived": False, "cycles": cycle - 1}

        # LIGHT: IDLE
        log_info(f"  cycle {cycle}/{cycles}: LIGHT ({per_phase}s idle)")
        time.sleep(per_phase)
        if dmesg.check():
            return {"survived": False, "cycles": cycle - 1}

        # HEAVY: SATURATE ALL CPUS
        log_info(f"  cycle {cycle}/{cycles}: HEAVY ({per_phase}s saturated)")
        stress = _StressWorkers(nr_cpus)
        stress.start()
        time.sleep(per_phase)
        if dmesg.check() or not sched_alive_fn():
            stress.stop()
            return {"survived": False, "cycles": cycle - 1}

        # MIXED: KILL HALF
        half = max(1, nr_cpus // 2)
        log_info(f"  cycle {cycle}/{cycles}: MIXED (kill {half}/{nr_cpus} stress)")
        for p in stress.procs[:half]:
            p.kill()
            p.wait()
        time.sleep(per_phase)
        if dmesg.check() or not sched_alive_fn():
            stress.stop()
            return {"survived": False, "cycles": cycle - 1}

        stress.stop()

    log_info(f"  regime-sweep: {cycles} cycles complete, scheduler alive")
    alive = sched_alive_fn()
    return {"survived": alive, "cycles": cycles}


def _contention_phase_deficit_storm(nr_cpus, dmesg, sched_alive_fn, duration=20):
    """Saturate deficit counter: ncpu interactive + ncpu*2 batch."""
    n_interactive = nr_cpus
    n_batch = nr_cpus * 2
    log_info(f"PHASE: deficit-storm ({n_interactive} interactive + {n_batch} batch, {duration}s)")

    # BATCH: TIGHT CPU SPIN
    batch_workers = _StressWorkers(n_batch)
    batch_workers.start()

    # INTERACTIVE: 1MS SLEEP CYCLES (HIGH WAKEUP RATE)
    interactive_probe = _LatencyProbe(duration)
    interactive_probe.start()

    # ALSO SPAWN EXTRA INTERACTIVE THREADS FOR WAKE PRESSURE
    extra_script = (
        f"import time\n"
        f"end = time.monotonic() + {duration}\n"
        "while time.monotonic() < end:\n"
        "    time.sleep(0.001)\n"
    )
    extras = []
    for _ in range(n_interactive - 1):
        p = subprocess.Popen(
            [sys.executable, "-c", extra_script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        extras.append(p)

    samples = interactive_probe.collect()
    batch_workers.stop()
    for p in extras:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    if dmesg.check():
        return {"survived": False, "samples": 0}

    result = {"survived": sched_alive_fn(), "samples": len(samples)}
    if samples:
        p99 = percentile(samples, 99)
        med = percentile(samples, 50)
        result["median_us"] = med
        result["p99_us"] = p99
        log_info(f"  deficit-storm: {len(samples)} samples, median={med:.0f}us P99={p99:.0f}us")
    else:
        log_info("  deficit-storm: no latency samples collected")

    return result


def _contention_phase_sojourn_pressure(nr_cpus, dmesg, sched_alive_fn, duration=15):
    """Deep batch queuing to stress sojourn rescue."""
    n_batch = nr_cpus * 4
    log_info(f"PHASE: sojourn-pressure ({n_batch} batch, {duration}s)")

    # PHASE A: PURE BATCH FLOOD (10S)
    batch_duration = duration - 5
    runners = _LongRunners(n_batch)
    runners.start(batch_duration)
    time.sleep(batch_duration - 5)

    if dmesg.check() or not sched_alive_fn():
        runners.collect(timeout=5)
        return {"survived": False, "samples": 0}

    # PHASE B: ADD 4 INTERACTIVE PROBES INTO THE BATCH FLOOD (5S)
    log_info(f"  adding 4 interactive probes into batch flood")
    probe = _LatencyProbe(5)
    probe.start()
    samples = probe.collect()
    work = runners.collect(timeout=batch_duration + 10)

    if dmesg.check():
        return {"survived": False, "samples": 0}

    min_work = min(work) if work else 0
    max_work = max(work) if work else 0
    result = {
        "survived": sched_alive_fn(), "samples": len(samples),
        "work_min": min_work, "work_max": max_work,
    }
    if samples:
        p99 = percentile(samples, 99)
        result["p99_us"] = p99
        log_info(f"  sojourn-pressure: P99={p99:.0f}us, batch_work=[{min_work}..{max_work}]")
    else:
        log_info(f"  sojourn-pressure: no latency samples, batch_work=[{min_work}..{max_work}]")

    return result


def _contention_phase_longrun_interactive(nr_cpus, dmesg, sched_alive_fn, duration=20):
    """Sustained long-runners + interactive probe. Triggers longrun_mode."""
    n_runners = max(2, nr_cpus // 2)
    log_info(f"PHASE: longrun-interactive ({n_runners} runners + probe, {duration}s)")

    runners = _LongRunners(n_runners)
    runners.start(duration)

    # LET LONGRUN_MODE ACTIVATE (NEEDS >2S OF SUSTAINED BATCH)
    time.sleep(3)
    if dmesg.check() or not sched_alive_fn():
        runners.collect(timeout=5)
        return {"survived": False, "samples": 0}

    # INTERACTIVE PROBE DURING LONGRUN MODE
    probe_duration = duration - 5
    probe = _LatencyProbe(probe_duration)
    probe.start()
    samples = probe.collect()
    work = runners.collect(timeout=duration + 10)

    if dmesg.check():
        return {"survived": False, "samples": 0}

    min_work = min(work) if work else 0
    max_work = max(work) if work else 0
    fairness = min_work / max_work if max_work > 0 else 0

    result = {
        "survived": sched_alive_fn(), "samples": len(samples),
        "work_min": min_work, "work_max": max_work, "fairness": fairness,
    }
    if samples:
        p99 = percentile(samples, 99)
        med = percentile(samples, 50)
        result["median_us"] = med
        result["p99_us"] = p99
        log_info(f"  longrun-interactive: median={med:.0f}us P99={p99:.0f}us "
                 f"work=[{min_work}..{max_work}] fairness={fairness:.2f}")
    else:
        log_info(f"  longrun-interactive: no samples, work=[{min_work}..{max_work}]")

    return result


def _contention_phase_burst_recovery(nr_cpus, dmesg, sched_alive_fn):
    """Burst with explicit recovery verification."""
    burst_size = nr_cpus * 8
    log_info(f"PHASE: burst-recovery ({burst_size} burst processes)")

    # BASELINE (5S)
    baseline_probe = _LatencyProbe(5)
    baseline_probe.start()
    baseline_samples = baseline_probe.collect()
    if dmesg.check() or not sched_alive_fn():
        return {"survived": False}

    baseline_p99 = percentile(baseline_samples, 99) if baseline_samples else 0
    log_info(f"  baseline: P99={baseline_p99:.0f}us ({len(baseline_samples)} samples)")

    # FIRE BURST
    log_info(f"  firing {burst_size} burst processes")
    burst_procs = _burst_processes(burst_size)
    burst_probe = _LatencyProbe(10)
    burst_probe.start()
    burst_samples = burst_probe.collect()
    for p in burst_procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()

    if dmesg.check() or not sched_alive_fn():
        return {"survived": False}

    burst_p99 = percentile(burst_samples, 99) if burst_samples else 0
    log_info(f"  burst: P99={burst_p99:.0f}us ({len(burst_samples)} samples)")

    # RECOVERY (5S)
    recovery_probe = _LatencyProbe(5)
    recovery_probe.start()
    recovery_samples = recovery_probe.collect()

    if dmesg.check():
        return {"survived": False}

    recovery_p99 = percentile(recovery_samples, 99) if recovery_samples else 0
    within_2x = recovery_p99 <= max(baseline_p99 * 2, 500)
    log_info(f"  recovery: P99={recovery_p99:.0f}us "
             f"(baseline*2={baseline_p99*2:.0f}us) {'OK' if within_2x else 'ELEVATED'}")

    return {
        "survived": sched_alive_fn(),
        "baseline_p99_us": baseline_p99, "baseline_samples": len(baseline_samples),
        "burst_p99_us": burst_p99, "burst_samples": len(burst_samples),
        "recovery_p99_us": recovery_p99, "recovery_samples": len(recovery_samples),
        "recovery_within_2x": within_2x,
    }


def _contention_phase_mixed_storm(nr_cpus, dmesg, sched_alive_fn, duration=30):
    """Everything at once: long-runners + burst + interactive + deadline."""
    n_runners = max(2, nr_cpus // 2)
    burst_size = nr_cpus * 4
    n_interactive = nr_cpus
    log_info(f"PHASE: mixed-storm ({n_runners} longrun + {burst_size} burst + "
             f"{n_interactive} interactive + deadline, {duration}s)")

    # LONG-RUNNERS (FULL DURATION)
    runners = _LongRunners(n_runners)
    runners.start(duration)

    # INTERACTIVE PROBES
    probe = _LatencyProbe(duration)
    probe.start()

    # EXTRA INTERACTIVE THREADS
    extra_script = (
        f"import time\n"
        f"end = time.monotonic() + {duration}\n"
        "while time.monotonic() < end:\n"
        "    time.sleep(0.001)\n"
    )
    extras = []
    for _ in range(n_interactive - 1):
        p = subprocess.Popen(
            [sys.executable, "-c", extra_script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        extras.append(p)

    # DEADLINE THREAD (16.6MS FRAME TARGET)
    deadline_script = (
        f"import time, sys\n"
        f"target_ns = 16_666_667\n"
        f"misses = 0\n"
        f"total = 0\n"
        f"end = time.monotonic() + {duration}\n"
        "while time.monotonic() < end:\n"
        "    t0 = time.monotonic()\n"
        "    time.sleep(target_ns / 1e9)\n"
        "    actual = (time.monotonic() - t0) * 1e9\n"
        "    jitter = actual - target_ns\n"
        "    total += 1\n"
        "    if jitter > 500_000:\n"
        "        misses += 1\n"
        "print(f'{misses}/{total}', flush=True)\n"
    )
    deadline_proc = subprocess.Popen(
        [sys.executable, "-c", deadline_script],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )

    # WAIT 5S, THEN FIRE BURST INTO THE STORM
    time.sleep(5)
    if dmesg.check() or not sched_alive_fn():
        runners.collect(timeout=5)
        for p in extras:
            p.kill()
        deadline_proc.kill()
        return {"survived": False}

    log_info(f"  firing {burst_size} burst into storm")
    burst_procs = _burst_processes(burst_size)

    # WAIT FOR REMAINING DURATION
    time.sleep(max(1, duration - 10))

    # COLLECT EVERYTHING
    samples = probe.collect()
    work = runners.collect(timeout=duration + 15)
    for p in burst_procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    for p in extras:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    deadline_out = ""
    try:
        deadline_out, _ = deadline_proc.communicate(timeout=duration + 10)
    except subprocess.TimeoutExpired:
        deadline_proc.kill()

    if dmesg.check():
        return {"survived": False}

    # REPORT
    min_work = min(work) if work else 0
    max_work = max(work) if work else 0
    result = {
        "survived": sched_alive_fn(), "samples": len(samples),
        "work_min": min_work, "work_max": max_work,
    }
    if samples:
        p99 = percentile(samples, 99)
        med = percentile(samples, 50)
        result["median_us"] = med
        result["p99_us"] = p99
        log_info(f"  mixed-storm: median={med:.0f}us P99={p99:.0f}us "
                 f"work=[{min_work}..{max_work}]")
    else:
        log_info(f"  mixed-storm: no samples, work=[{min_work}..{max_work}]")

    if deadline_out.strip():
        log_info(f"  deadline: {deadline_out.strip()}")
        try:
            parts = deadline_out.strip().split("/")
            result["deadline_misses"] = int(parts[0])
            result["deadline_total"] = int(parts[1])
            if int(parts[1]) > 0:
                result["deadline_miss_ratio"] = int(parts[0]) / int(parts[1])
        except (ValueError, IndexError):
            pass

    return result


# BENCH-CONTENTION ORCHESTRATOR

def _contention_run_iteration(iteration, total, nr_cpus):
    """Run one full contention iteration. Returns (survived: bool, phase_results: dict)."""
    dmesg = DmesgMonitor()
    phase_results = {}

    label = f"[{iteration}/{total}] " if total > 1 else ""
    log_info(f"{label}Starting scheduler")

    sched_proc = _trace_start_scheduler(nr_cpus=nr_cpus)
    if sched_proc is None:
        return False, phase_results

    def sched_alive():
        return sched_proc is not None and sched_proc.poll() is None

    log_info(f"{label}Starting contention sequence at {nr_cpus}C")

    phases = [
        ("regime-sweep",        lambda: _contention_phase_regime_sweep(nr_cpus, dmesg, sched_alive)),
        ("deficit-storm",       lambda: _contention_phase_deficit_storm(nr_cpus, dmesg, sched_alive)),
        ("sojourn-pressure",    lambda: _contention_phase_sojourn_pressure(nr_cpus, dmesg, sched_alive)),
        ("longrun-interactive", lambda: _contention_phase_longrun_interactive(nr_cpus, dmesg, sched_alive)),
        ("burst-recovery",      lambda: _contention_phase_burst_recovery(nr_cpus, dmesg, sched_alive)),
        ("mixed-storm",         lambda: _contention_phase_mixed_storm(nr_cpus, dmesg, sched_alive)),
    ]

    crashed = False
    for name, fn in phases:
        result = fn()
        phase_results[name] = result
        if not result.get("survived", False):
            crashed = True
            if dmesg.crashed:
                log_error(f"{label}CRASH DETECTED during '{name}': {dmesg.crash_msg}")
            else:
                log_error(f"{label}Scheduler died during '{name}' (no dmesg crash)")
            break
        log_info(f"  '{name}' passed, scheduler alive")
    else:
        log_info(f"{label}ALL PHASES COMPLETE -- scheduler survived")

    _trace_stop_scheduler(sched_proc)
    dmesg.save()

    return not crashed, phase_results


def _write_contention_prometheus(version, git, stamp, max_cpus, iterations,
                                  core_counts, results, all_phase_data) -> Path:
    """Write Prometheus exposition format (.prom) for bench-contention."""
    lines = []
    emitted = set()

    def gauge(name, help_text, value, labels=None):
        if name not in emitted:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            emitted.add(name)
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

    dirty = "true" if git["dirty"] else "false"
    gauge("pandemonium_contention_info", "Build and run metadata", 1,
          {"version": version, "git_commit": git["commit"], "git_dirty": dirty})
    gauge("pandemonium_contention_timestamp_seconds", "Test start time",
          int(datetime.strptime(stamp, "%Y%m%d-%H%M%S").timestamp()))
    gauge("pandemonium_contention_iterations", "Iterations per core count", iterations)
    gauge("pandemonium_contention_max_cpus", "Maximum CPUs available", max_cpus)

    for nr_cpus in sorted(results.keys()):
        s, c = results[nr_cpus]
        cl = {"cores": str(nr_cpus)}
        gauge("pandemonium_contention_survived", "Iterations survived", s, cl)
        gauge("pandemonium_contention_crashed", "Iterations crashed", c, cl)

        phases = all_phase_data.get(nr_cpus, {})
        for phase_name, pd in phases.items():
            pl = {"cores": str(nr_cpus), "phase": phase_name}
            survived = 1 if pd.get("survived") else 0
            gauge("pandemonium_contention_phase_survived",
                  "Phase survived (1=OK, 0=CRASH)", survived, pl)

            if "samples" in pd:
                gauge("pandemonium_contention_phase_samples",
                      "Latency samples collected", pd["samples"], pl)
            if "p99_us" in pd:
                gauge("pandemonium_contention_phase_p99_us",
                      "P99 wakeup latency", pd["p99_us"], pl)
            if "median_us" in pd:
                gauge("pandemonium_contention_phase_median_us",
                      "Median wakeup latency", pd["median_us"], pl)
            if "work_min" in pd:
                gauge("pandemonium_contention_phase_work_min",
                      "Minimum work by any worker", pd["work_min"], pl)
            if "work_max" in pd:
                gauge("pandemonium_contention_phase_work_max",
                      "Maximum work by any worker", pd["work_max"], pl)
            if "fairness" in pd:
                gauge("pandemonium_contention_phase_fairness",
                      "Work fairness ratio (min/max)", f"{pd['fairness']:.4f}", pl)
            if "baseline_p99_us" in pd:
                gauge("pandemonium_contention_phase_baseline_p99_us",
                      "Baseline P99 before burst", pd["baseline_p99_us"], pl)
            if "burst_p99_us" in pd:
                gauge("pandemonium_contention_phase_burst_p99_us",
                      "P99 during burst", pd["burst_p99_us"], pl)
            if "recovery_p99_us" in pd:
                gauge("pandemonium_contention_phase_recovery_p99_us",
                      "P99 during post-burst recovery", pd["recovery_p99_us"], pl)
            if "recovery_within_2x" in pd:
                gauge("pandemonium_contention_phase_recovery_ok",
                      "Recovery within 2x baseline (1=OK, 0=ELEVATED)",
                      1 if pd["recovery_within_2x"] else 0, pl)
            if "deadline_misses" in pd:
                gauge("pandemonium_contention_phase_deadline_misses",
                      "Frame deadline misses", pd["deadline_misses"], pl)
            if "deadline_total" in pd:
                gauge("pandemonium_contention_phase_deadline_total",
                      "Total frame cycles", pd["deadline_total"], pl)
            if "deadline_miss_ratio" in pd:
                gauge("pandemonium_contention_phase_deadline_miss_ratio",
                      "Fraction of frames missed", f"{pd['deadline_miss_ratio']:.4f}", pl)

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    path = ARCHIVE_DIR / f"contention-{version}-{stamp}.prom"
    path.write_text("\n".join(lines) + "\n")
    return path


def cmd_bench_contention(args) -> int:
    """Contention stress test targeting v5.4.x adaptive features.

    6 phases per core count: regime-sweep, deficit-storm, sojourn-pressure,
    longrun-interactive, burst-recovery, mixed-storm. Each phase targets
    a specific adaptive mechanism.
    """

    subprocess.run(["sudo", "true"])

    nuke_stale_build()

    if not build():
        return 1

    max_cpus = os.cpu_count() or 2

    if args.core_counts:
        core_counts = [int(c.strip()) for c in args.core_counts.split(",")]
        core_counts = [c for c in core_counts if 2 <= c <= max_cpus]
        core_counts = sorted(set(core_counts))
    else:
        core_counts = compute_core_counts(max_cpus)

    if not core_counts:
        log_error(f"no valid core counts (host has {max_cpus} CPUs, minimum is 2)")
        return 1

    # FILTER PHASES IF --phase SPECIFIED
    phase_filter = getattr(args, "phase", None)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    ver = get_version()
    git = get_git_info()
    dirty = " (dirty)" if git["dirty"] else ""
    log_info(f"bench-contention v{ver} [{git['commit']}{dirty}], "
             f"core_counts={core_counts}, iterations={args.iterations}, "
             f"host_cpus={max_cpus}")
    if phase_filter:
        log_info(f"Phase filter: {phase_filter}")
    print()

    results = {}
    all_phase_data = {}
    total_survived = 0
    total_crashed = 0

    try:
        for nr_cpus in core_counts:
            log_info(f"[{nr_cpus}C] Restricting to {nr_cpus} cores")
            if nr_cpus < max_cpus:
                if not restrict_cpus(nr_cpus, max_cpus):
                    log_error(f"[{nr_cpus}C] failed to offline CPUs, skipping")
                    results[nr_cpus] = (0, args.iterations)
                    restore_all_cpus(max_cpus)
                    continue
            time.sleep(1)

            survived = 0
            crashed = 0
            core_phases = {}

            for i in range(1, args.iterations + 1):
                if args.iterations > 1:
                    log_info(f"[{nr_cpus}C] ITERATION {i}/{args.iterations}")
                ok, phase_results = _contention_run_iteration(i, args.iterations, nr_cpus)
                if ok:
                    survived += 1
                else:
                    crashed += 1
                # KEEP LAST ITERATION'S PHASE DATA FOR THIS CORE COUNT
                core_phases = phase_results
                if i < args.iterations:
                    log_info("Settling 3s before next iteration...")
                    time.sleep(3)

            results[nr_cpus] = (survived, crashed)
            all_phase_data[nr_cpus] = core_phases
            log_info(f"[{nr_cpus}C] RESULTS: {survived}/{args.iterations} survived")

            if nr_cpus < max_cpus:
                restore_all_cpus(max_cpus)
                time.sleep(1)

    except KeyboardInterrupt:
        log_info("Interrupted")
    finally:
        restore_all_cpus(max_cpus)

        if results:
            print()
            log_info("SUMMARY")
            for nr_cpus in sorted(results.keys()):
                s, c = results[nr_cpus]
                total_survived += s
                total_crashed += c
                status = "PASS" if c == 0 else "FAIL"
                log_info(f"  {nr_cpus:>3}C: {s}/{s+c} survived  {status}")
            log_info(f"  TOTAL: {total_survived}/{total_survived+total_crashed}")

        # WRITE PROMETHEUS .prom
        prom_path = _write_contention_prometheus(
            ver, git, stamp, max_cpus, args.iterations,
            core_counts, results, all_phase_data,
        )
        log_info(f"Prometheus: {prom_path}")

        # WRITE HUMAN-READABLE .log
        report_path = LOG_DIR / f"bench-contention-{stamp}.log"
        report_lines = [f"bench-contention v{ver} [{git['commit']}]",
                        f"cores: {core_counts}  iterations: {args.iterations}  host: {max_cpus}C",
                        ""]
        for nr_cpus in sorted(results.keys()):
            s, c = results[nr_cpus]
            status = "PASS" if c == 0 else "FAIL"
            report_lines.append(f"{nr_cpus:>3}C: {s}/{s+c} survived  {status}")
            phases = all_phase_data.get(nr_cpus, {})
            for phase_name, pd in phases.items():
                surv = "OK" if pd.get("survived") else "CRASH"
                extras = []
                if "p99_us" in pd:
                    extras.append(f"P99={pd['p99_us']:.0f}us")
                if "median_us" in pd:
                    extras.append(f"med={pd['median_us']:.0f}us")
                if "samples" in pd:
                    extras.append(f"n={pd['samples']}")
                if "work_min" in pd:
                    extras.append(f"work=[{pd['work_min']}..{pd.get('work_max', 0)}]")
                if "fairness" in pd:
                    extras.append(f"fair={pd['fairness']:.2f}")
                if "baseline_p99_us" in pd:
                    extras.append(f"base={pd['baseline_p99_us']:.0f}us")
                    extras.append(f"burst={pd.get('burst_p99_us', 0):.0f}us")
                    extras.append(f"recov={pd.get('recovery_p99_us', 0):.0f}us")
                if "deadline_misses" in pd:
                    extras.append(f"dl={pd['deadline_misses']}/{pd['deadline_total']}")
                detail = "  ".join(extras)
                report_lines.append(f"    {phase_name}: {surv}  {detail}")
        report_lines.append("")
        report_lines.append(f"TOTAL: {total_survived}/{total_survived+total_crashed}")
        report = "\n".join(report_lines) + "\n"
        report_path.write_text(report)
        log_info(f"Report: {report_path}")

    return 0 if total_crashed == 0 else 1


# BENCH-CS2: AUTOMATED GAME WORKLOAD DIAGNOSIS

CS2_CAPTURE_S = 120     # DEFAULT CAPTURE DURATION
CS2_LAUNCH_TIMEOUT = 120  # MAX WAIT FOR CS2 PROCESS TO APPEAR
GAP_THRESH_MS = 50      # SCHEDULING GAPS ABOVE THIS ARE FLAGGED (1 FRAME @ 20FPS)


def _find_process(name: str) -> int | None:
    """Find PID of a running process by name. Returns None if not found."""
    try:
        r = subprocess.run(["pgrep", "-x", name],
                           capture_output=True, text=True)
        if r.returncode == 0:
            pids = r.stdout.strip().splitlines()
            return int(pids[0]) if pids else None
    except (ValueError, FileNotFoundError):
        pass
    return None


def _wait_for_process(name: str, timeout: float) -> int | None:
    """Poll until process appears. Returns PID or None on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid = _find_process(name)
        if pid is not None:
            return pid
        time.sleep(0.5)
    return None


def _kill_process(name: str):
    """Gracefully kill a process by name (SIGTERM, then SIGKILL)."""
    pid = _find_process(name)
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _find_process(name) is None:
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _cs2_parse_trace(trace_path: Path) -> dict:
    """Parse a trace log into structured event data."""
    events = []       # (timestamp_s, event_type, raw_line)
    type_counts = {}  # event_type -> count

    if not trace_path.exists():
        return {"events": events, "type_counts": type_counts}

    # trace_pipe: "<task>-<pid> [<cpu>] <flags> <timestamp>: ... PAND: <type> <rest>"
    ts_pattern = re.compile(r"\s+([\d.]+):\s+.*PAND:\s+(.+)")

    for line in trace_path.read_text().splitlines():
        m = ts_pattern.search(line)
        if m:
            ts = float(m.group(1))
            msg = m.group(2).strip()
            # Full event type: "enq tier1 cpu=3" -> "enq tier1"
            parts = msg.split()
            if len(parts) >= 2 and parts[0] == "enq":
                etype = f"{parts[0]} {parts[1]}"
            else:
                etype = parts[0] if parts else msg
            events.append((ts, etype, msg))
            type_counts[etype] = type_counts.get(etype, 0) + 1

    events.sort(key=lambda e: e[0])
    return {"events": events, "type_counts": type_counts}


def _cs2_write_prometheus(version, git, stamp, target, elapsed,
                          trace_data, latency_samples, crashed,
                          crash_msg) -> Path:
    """Write Prometheus .prom for bench-cs2."""
    lines = []
    emitted = set()

    def gauge(name, help_text, value, labels=None):
        if name not in emitted:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            emitted.add(name)
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

    dirty = "true" if git["dirty"] else "false"
    gauge("pandemonium_cs2_info", "Build and run metadata", 1,
          {"version": version, "git_commit": git["commit"],
           "git_dirty": dirty, "target": target})
    gauge("pandemonium_cs2_timestamp_seconds", "Test start time",
          int(time.time()))
    gauge("pandemonium_cs2_elapsed_seconds", "Total capture duration",
          f"{elapsed:.1f}")
    gauge("pandemonium_cs2_crashed", "Scheduler crashed (1=yes 0=no)",
          1 if crashed else 0)

    # Trace event counts
    events = trace_data["events"]
    type_counts = trace_data["type_counts"]
    gauge("pandemonium_cs2_trace_total", "Total trace events", len(events))

    for etype, count in sorted(type_counts.items()):
        gauge("pandemonium_cs2_trace_by_type", "Trace events by type",
              count, {"type": etype})

    # Event rate
    if len(events) >= 2:
        t0 = events[0][0]
        duration_s = events[-1][0] - t0
        if duration_s > 0:
            gauge("pandemonium_cs2_trace_rate_avg",
                  "Average trace events per second",
                  f"{len(events) / duration_s:.1f}")

    # Gaps
    gap_thresh = GAP_THRESH_MS / 1000.0
    gaps = []
    for i in range(1, len(events)):
        dt = events[i][0] - events[i - 1][0]
        if dt > gap_thresh:
            gaps.append(dt)
    gauge("pandemonium_cs2_gaps_total",
          f"Scheduling gaps >{GAP_THRESH_MS}ms", len(gaps))
    if gaps:
        gauge("pandemonium_cs2_gap_max_ms", "Largest scheduling gap (ms)",
              f"{max(gaps) * 1000:.1f}")
        gauge("pandemonium_cs2_gap_median_ms", "Median scheduling gap (ms)",
              f"{percentile(gaps, 50) * 1000:.1f}")

    # Latency probe
    if latency_samples:
        p50 = percentile(latency_samples, 50)
        p99 = percentile(latency_samples, 99)
        worst = max(latency_samples)
        gauge("pandemonium_cs2_latency_samples", "Wakeup latency samples",
              len(latency_samples))
        gauge("pandemonium_cs2_latency_p50_us", "Median wakeup latency (us)",
              f"{p50:.0f}")
        gauge("pandemonium_cs2_latency_p99_us", "P99 wakeup latency (us)",
              f"{p99:.0f}")
        gauge("pandemonium_cs2_latency_worst_us", "Worst wakeup latency (us)",
              f"{worst:.0f}")

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    path = ARCHIVE_DIR / f"cs2-{version}-{stamp}.prom"
    path.write_text("\n".join(lines) + "\n")
    return path


def cmd_bench_cs2(args) -> int:
    """Automated game workload diagnosis.

    Patches BPF trace filter at build time, waits for the game to launch,
    captures trace + latency data, produces Prometheus + human-readable output.
    """
    subprocess.run(["sudo", "true"])
    nuke_stale_build()

    target = args.target
    capture_duration = args.duration or CS2_CAPTURE_S

    # ---- PHASE 1: PATCH + BUILD + RESTORE ----

    original = patch_bpf_trace_filter(target)
    if original is None:
        return 1
    try:
        ok = build(force=True)
    finally:
        restore_bpf_source(original)
    if not ok:
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    ver = get_version()
    git = get_git_info()
    dirty = " (dirty)" if git["dirty"] else ""
    log_info(f"bench-cs2 v{ver} [{git['commit']}{dirty}]  "
             f"target='{target}'  capture={capture_duration}s")
    print()

    # ---- PHASE 2: START SCHEDULER + MONITORING ----

    dmesg = DmesgMonitor()
    trace_path = LOG_DIR / f"cs2-trace-{stamp}.log"
    sched_proc = None
    trace = None
    probe = None
    crashed = False
    game_exited = False
    total_elapsed = 0
    latency_samples = []

    try:
        sched_proc = _trace_start_scheduler()
        if sched_proc is None:
            return 1

        trace = TraceCapture(trace_path)
        if not trace.start():
            log_warn("Trace capture failed, continuing without trace data")

        # ---- PHASE 3: WAIT FOR GAME ----

        already_running = _find_process(target) is not None
        if already_running:
            log_info(f"'{target}' already running")
        else:
            print()
            log_info(f">>> Please launch '{target}' now. <<<")
            log_info(f"Waiting for '{target}' process "
                     f"(timeout {CS2_LAUNCH_TIMEOUT}s)...")
            print()

        pid = _wait_for_process(target, CS2_LAUNCH_TIMEOUT)
        if pid is None:
            log_error(f"'{target}' did not appear "
                      f"within {CS2_LAUNCH_TIMEOUT}s")
            return 1
        log_info(f"'{target}' detected (PID {pid})")

        # ---- PHASE 4: CAPTURE (STARTS IMMEDIATELY) ----

        log_info(f"CAPTURING: {capture_duration}s with latency probe")
        probe = _LatencyProbe(capture_duration)
        probe.start()

        t0 = time.monotonic()
        while time.monotonic() - t0 < capture_duration:
            time.sleep(2)
            elapsed = time.monotonic() - t0

            if dmesg.check():
                log_error(f"SCHEDULER CRASH at {elapsed:.0f}s: "
                          f"{dmesg.crash_msg}")
                crashed = True
                break

            if sched_proc.poll() is not None:
                log_error(f"Scheduler exited at {elapsed:.0f}s "
                          f"(code {sched_proc.returncode})")
                crashed = True
                break

            if _find_process(target) is None:
                log_warn(f"'{target}' exited at {elapsed:.0f}s")
                game_exited = True
                break

            log_info(f"  [{elapsed:.0f}s] events={trace.count}")

        total_elapsed = time.monotonic() - t0

    except KeyboardInterrupt:
        log_info("Interrupted by user")
    finally:
        # ---- CLEANUP (ALWAYS RUNS) ----

        log_info("Stopping...")

        if probe and probe.proc and probe.proc.poll() is None:
            probe.proc.kill()
        if probe:
            latency_samples = probe.collect()

        if trace:
            trace.stop()
        _trace_stop_scheduler(sched_proc)

        if _find_process(target):
            log_info(f"Killing '{target}'")
            _kill_process(target)

        # ---- REPORT (ALWAYS RUNS) ----

        print()
        trace_data = _cs2_parse_trace(trace_path)
        events = trace_data["events"]
        type_counts = trace_data["type_counts"]

        report_lines = []
        report_lines.append(f"bench-cs2 v{ver} [{git['commit']}{dirty}]")
        if crashed:
            report_lines.append(
                f"SCHEDULER CRASHED at {total_elapsed:.1f}s")
            if dmesg.crash_msg:
                report_lines.append(f"  dmesg: {dmesg.crash_msg}")
        elif game_exited:
            report_lines.append(f"GAME EXITED at {total_elapsed:.1f}s")
        else:
            report_lines.append(
                f"Completed: {total_elapsed:.1f}s capture")
        report_lines.append("")

        report_lines.append(f"Trace events: {len(events)}")
        for etype in sorted(type_counts, key=type_counts.get,
                            reverse=True):
            report_lines.append(
                f"  {etype:30s} {type_counts[etype]:>8d}")
        report_lines.append("")

        if len(events) >= 2:
            t_start = events[0][0]
            t_end = events[-1][0]
            duration_s = t_end - t_start
            if duration_s > 0:
                buckets = {}
                for ts, _, _ in events:
                    sec = int(ts - t_start)
                    buckets[sec] = buckets.get(sec, 0) + 1
                rates = list(buckets.values())
                report_lines.append(
                    f"Event rate: avg={len(events)/duration_s:.1f}/s  "
                    f"min={min(rates)}/s  max={max(rates)}/s  "
                    f"over {duration_s:.1f}s")
                total_secs = int(duration_s) + 1
                dead = total_secs - len(buckets)
                if dead > 0:
                    report_lines.append(
                        f"Dead seconds (0 events): {dead}/{total_secs}")
                report_lines.append("")

        gap_thresh = GAP_THRESH_MS / 1000.0
        gaps = []
        if len(events) >= 2:
            t_start = events[0][0]
            for i in range(1, len(events)):
                dt = events[i][0] - events[i - 1][0]
                if dt > gap_thresh:
                    gaps.append((events[i - 1][0] - t_start,
                                 events[i][0] - t_start, dt))

        if gaps:
            report_lines.append(
                f"GAPS (>{GAP_THRESH_MS}ms): {len(gaps)} detected")
            for start, end, dt in gaps[:30]:
                report_lines.append(
                    f"  {start:8.3f}s .. {end:8.3f}s  "
                    f"gap={dt*1000:.0f}ms")
            if len(gaps) > 30:
                report_lines.append(
                    f"  ... and {len(gaps) - 30} more")
        else:
            report_lines.append(
                f"No gaps >{GAP_THRESH_MS}ms detected.")
        report_lines.append("")

        if latency_samples:
            p50 = percentile(latency_samples, 50)
            p99 = percentile(latency_samples, 99)
            worst = max(latency_samples)
            report_lines.append(
                f"Wakeup latency: n={len(latency_samples)}  "
                f"med={p50:.0f}us  P99={p99:.0f}us  "
                f"worst={worst:.0f}us")
        else:
            report_lines.append(
                "Wakeup latency: no samples collected")
        report_lines.append("")

        for line in report_lines:
            log_info(line)

        report_path = LOG_DIR / f"bench-cs2-{stamp}.log"
        report_path.write_text("\n".join(report_lines) + "\n")
        log_info(f"Report: {report_path}")
        log_info(f"Raw trace: {trace_path}")

        prom_path = _cs2_write_prometheus(
            ver, git, stamp, target, total_elapsed,
            trace_data, latency_samples, crashed,
            dmesg.crash_msg if crashed else "")
        log_info(f"Prometheus: {prom_path}")

        dmesg.save(stamp)

        if crashed:
            status = "CRASH"
        elif game_exited:
            status = "GAME EXITED"
        else:
            status = "PASS"
        print()
        log_info(f"RESULT: {status}")

        fix_ownership()

    return 1 if crashed else 0


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
    bench.add_argument("--burst", action="store_true",
                       help="Burst-only mode: skip latency and throughput, "
                            "run only burst measurement")
    bench.add_argument("--longrun", action="store_true",
                       help="Long-run only mode: skip latency, throughput, "
                            "and burst; run only long-running process test")
    bench.add_argument("--mixed", action="store_true",
                       help="Mixed-only mode: skip latency, throughput; "
                            "run only burst+longrun combined test")
    bench.add_argument("--deadline", action="store_true",
                       help="Deadline-only mode: run only periodic frame "
                            "scheduling jitter test")
    bench.add_argument("--ipc", action="store_true",
                       help="IPC-only mode: run only pipe round-trip "
                            "latency test")
    bench.add_argument("--launch", action="store_true",
                       help="Launch-only mode: run only fork+exec latency "
                            "test under load")
    bench.add_argument("--trace", action="store_true",
                       help="Enable bpf_printk trace capture during benchmark")

    trace_bench = sub.add_parser("bench-trace",
                                  help="Crash-detection stress test with trace capture")
    trace_bench.add_argument("--iterations", type=int, default=1,
                             help="Full workload iterations per core count (default: 1)")
    trace_bench.add_argument("--core-counts", type=str, default=None,
                             help="Comma-separated core counts "
                                  "(default: auto 2,4,8,...,max)")

    contention_bench = sub.add_parser("bench-contention",
                                      help="Contention stress test for v5.4.x adaptive features")
    contention_bench.add_argument("--iterations", type=int, default=1,
                                  help="Full workload iterations per core count (default: 1)")
    contention_bench.add_argument("--core-counts", type=str, default=None,
                                  help="Comma-separated core counts "
                                       "(default: auto 2,4,8,...,max)")
    contention_bench.add_argument("--phase", type=str, default=None,
                                  help="Run single phase: regime-sweep, deficit-storm, "
                                       "sojourn-pressure, longrun-interactive, "
                                       "burst-recovery, mixed-storm")

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

    cs2_bench = sub.add_parser("bench-cs2",
                                help="Automated game workload diagnosis")
    cs2_bench.add_argument("--target", type=str, default="cs2",
                           help="Process name to trace and detect (default: cs2)")
    cs2_bench.add_argument("--duration", type=int, default=0,
                           help="Capture duration in seconds (default: 120)")


    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if hasattr(args, "schedulers") and isinstance(args.schedulers, str):
        args.schedulers = [s.strip() for s in args.schedulers.split(",")
                           if s.strip()]

    if args.command == "bench-scale":
        return cmd_bench_scale(args)
    if args.command == "bench-trace":
        return cmd_bench_trace(args)
    if args.command == "bench-contention":
        return cmd_bench_contention(args)
    if args.command == "bench-sys":
        return cmd_bench_sys(args)
    if args.command == "bench-cs2":
        return cmd_bench_cs2(args)

    log_error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
