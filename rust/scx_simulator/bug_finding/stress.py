#!/usr/bin/env python3
"""
Stress test for scx_simulator.

Runs randomized simulation configurations in parallel, searching for stalls,
BPF errors, crashes, and other failures. All findings are reported immediately
and written to bug_finding/output/ for later analysis.

Usage:
    python3 stress.py                  # Run for 10 minutes (default)
    python3 stress.py --duration 30    # Run for 30 minutes
    python3 stress.py --jobs 8         # Use 8 parallel workers
"""

import argparse
import logging
import os
import random
import signal
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
SCXSIM = PROJECT_ROOT / "target" / "release" / "scxsim"
WORKLOADS_DIR = PROJECT_ROOT / "crates" / "scx_simulator" / "workloads"
OUTPUT_DIR = Path(__file__).parent / "output"

SCHEDULERS = ["simple", "lavd", "cosmos", "tickless", "mitosis"]
CPU_COUNTS = [1, 2, 4, 8]
INTERLEAVE_MODES = ["off", "cooperative", "preemptive"]

# Defaults for stall detection
DEFAULT_WATCHDOG_TIMEOUT = "2s"
DEFAULT_SIM_DURATION = "4s"

# Process timeout (wall-clock) — generous to avoid false positives
PROCESS_TIMEOUT_SEC = 120

# Runtime config (set from CLI args in main)
WATCHDOG_TIMEOUT = DEFAULT_WATCHDOG_TIMEOUT
SIM_DURATION = DEFAULT_SIM_DURATION

# Global logger (configured in main)
log: logging.Logger = logging.getLogger("stress")


def setup_logging() -> Path:
    """Set up logging to both console and a timestamped file."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    log_path = OUTPUT_DIR / f"stress_{timestamp}.log"

    # Configure root logger
    log.setLevel(logging.DEBUG)

    # File handler - detailed
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    log.addHandler(file_handler)

    # Console handler - minimal (we do our own progress display)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console_handler)

    return log_path


@dataclass
class TestConfig:
    """A single stress test configuration."""

    scheduler: str
    workload: Path
    cpus: int
    seed: int
    interleave_mode: str  # "off", "cooperative", "preemptive"
    iteration: int

    @property
    def label(self) -> str:
        wl = self.workload.stem
        return (
            f"{self.scheduler}/{wl}/c{self.cpus}"
            f"/s{self.seed}/{self.interleave_mode}"
        )


@dataclass
class Finding:
    """A bug finding from a stress test run."""

    config: TestConfig
    error_type: str  # "crash", "stall", "bpf_error", "timeout", "other"
    exit_code: int
    stderr: str
    stdout: str
    wall_time_sec: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def summary(self) -> str:
        return f"[{self.error_type}] {self.config.label} (exit={self.exit_code})"

    def report(self) -> str:
        lines = [
            f"Finding: {self.error_type}",
            f"Timestamp: {self.timestamp}",
            f"Wall time: {self.wall_time_sec:.2f}s",
            f"Exit code: {self.exit_code}",
            "",
            f"Scheduler: {self.config.scheduler}",
            f"Workload: {self.config.workload.name}",
            f"CPUs: {self.config.cpus}",
            f"Seed: {self.config.seed}",
            f"Interleave: {self.config.interleave_mode}",
            "",
            "--- Reproduction command ---",
            self.repro_command(),
            "",
            "--- stderr ---",
            self.stderr or "(empty)",
            "",
            "--- stdout ---",
            self.stdout or "(empty)",
        ]
        return "\n".join(lines)

    def repro_command(self) -> str:
        cmd = [
            str(SCXSIM),
            str(self.config.workload),
            "-s", self.config.scheduler,
            "-c", str(self.config.cpus),
            "--seed", str(self.config.seed),
            "--watchdog-timeout", WATCHDOG_TIMEOUT,
            "--end-time", SIM_DURATION,
        ]
        if self.config.interleave_mode == "cooperative":
            cmd.append("--interleave")
        elif self.config.interleave_mode == "preemptive":
            cmd.append("--preemptive")
        return " ".join(cmd)


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------


def run_one(config: TestConfig) -> Optional[Finding]:
    """Run a single simulation and return a Finding if it fails."""
    cmd = [
        str(SCXSIM),
        str(config.workload),
        "-s", config.scheduler,
        "-c", str(config.cpus),
        "--seed", str(config.seed),
        "--watchdog-timeout", WATCHDOG_TIMEOUT,
        "--end-time", SIM_DURATION,
    ]
    if config.interleave_mode == "cooperative":
        cmd.append("--interleave")
    elif config.interleave_mode == "preemptive":
        cmd.append("--preemptive")

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SEC,
        )
        elapsed = time.monotonic() - start

        if result.returncode == 0:
            return None

        # Classify the error
        stderr = result.stderr
        if result.returncode < 0:
            signum = -result.returncode
            sig_name = signal.Signals(signum).name
            error_type = f"crash({sig_name})"
        elif "ErrorStall" in stderr:
            error_type = "stall"
        elif "ErrorBpf" in stderr:
            error_type = "bpf_error"
        elif "ErrorDispatchLoopExhausted" in stderr:
            error_type = "dispatch_loop"
        elif "ErrorCgroupExhausted" in stderr:
            error_type = "cgroup_exhausted"
        else:
            error_type = "other"

        return Finding(
            config=config,
            error_type=error_type,
            exit_code=result.returncode,
            stderr=stderr.strip(),
            stdout=result.stdout.strip(),
            wall_time_sec=elapsed,
        )

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return Finding(
            config=config,
            error_type="timeout",
            exit_code=-1,
            stderr=f"process timed out after {PROCESS_TIMEOUT_SEC}s",
            stdout="",
            wall_time_sec=elapsed,
        )
    except Exception as e:
        elapsed = time.monotonic() - start
        return Finding(
            config=config,
            error_type="other",
            exit_code=-1,
            stderr=str(e),
            stdout="",
            wall_time_sec=elapsed,
        )


def generate_configs(rng: random.Random, schedulers: list[str]) -> TestConfig:
    """Generate a random test configuration."""
    workloads = sorted(WORKLOADS_DIR.glob("*.json"))
    if not workloads:
        print(f"error: no workloads found in {WORKLOADS_DIR}", file=sys.stderr)
        sys.exit(1)

    return TestConfig(
        scheduler=rng.choice(schedulers),
        workload=rng.choice(workloads),
        cpus=rng.choice(CPU_COUNTS),
        seed=rng.randint(0, 2**32 - 1),
        interleave_mode=rng.choice(INTERLEAVE_MODES),
        iteration=0,
    )


def save_finding(finding: Finding, finding_num: int) -> Path:
    """Write a finding report to disk."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"finding_{finding_num:04d}_{finding.error_type}.txt"
    path = OUTPUT_DIR / filename
    path.write_text(finding.report())
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Stress test scx_simulator")
    parser.add_argument(
        "--duration",
        type=float,
        default=10,
        help="Duration in minutes (default: 10). Supports fractions like 0.5 for 30s.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=os.cpu_count(),
        help=f"Parallel workers (default: {os.cpu_count()})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Master PRNG seed for reproducibility",
    )
    parser.add_argument(
        "--schedulers",
        type=str,
        default=None,
        help=f"Comma-separated list of schedulers (default: all: {','.join(SCHEDULERS)})",
    )
    parser.add_argument(
        "--sim-duration",
        type=str,
        default=DEFAULT_SIM_DURATION,
        help=f"Simulation duration in virtual time (default: {DEFAULT_SIM_DURATION})",
    )
    parser.add_argument(
        "--watchdog",
        type=str,
        default=DEFAULT_WATCHDOG_TIMEOUT,
        help=f"Watchdog timeout for stall detection (default: {DEFAULT_WATCHDOG_TIMEOUT})",
    )
    args = parser.parse_args()

    # Set global config from CLI args
    global WATCHDOG_TIMEOUT, SIM_DURATION
    WATCHDOG_TIMEOUT = args.watchdog
    SIM_DURATION = args.sim_duration

    # Set up logging first
    log_path = setup_logging()

    if args.schedulers:
        schedulers = [s.strip() for s in args.schedulers.split(",")]
        unknown = [s for s in schedulers if s not in SCHEDULERS]
        if unknown:
            print(f"error: unknown scheduler(s): {', '.join(unknown)}", file=sys.stderr)
            print(f"available: {', '.join(SCHEDULERS)}", file=sys.stderr)
            sys.exit(1)
    else:
        schedulers = SCHEDULERS

    if not SCXSIM.exists():
        print(f"error: {SCXSIM} not found; run 'cargo build --release' first",
              file=sys.stderr)
        sys.exit(1)

    master_seed = args.seed if args.seed is not None else random.randint(0, 2**32 - 1)
    rng = random.Random(master_seed)
    deadline = time.monotonic() + args.duration * 60
    start_time = time.monotonic()

    print(f"Stress test: {args.duration}min, {args.jobs} workers, "
          f"master seed={master_seed}")
    print(f"Schedulers: {', '.join(schedulers)}")
    print(f"Watchdog: {WATCHDOG_TIMEOUT}, sim duration: {SIM_DURATION}")
    print(f"Output: {OUTPUT_DIR}")
    print(f"Log: {log_path}")
    print()

    log.info("=" * 60)
    log.info("Stress test started")
    log.info("=" * 60)
    log.info(f"Duration: {args.duration} minutes")
    log.info(f"Workers: {args.jobs}")
    log.info(f"Master seed: {master_seed}")
    log.info(f"Schedulers: {', '.join(schedulers)}")
    log.info(f"Watchdog timeout: {WATCHDOG_TIMEOUT}")
    log.info(f"Sim duration: {SIM_DURATION}")

    findings: list[Finding] = []
    total_runs = 0
    completed_runs = 0

    # Pre-generate a batch of configs
    batch_size = args.jobs * 4

    try:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            pending = {}
            iteration = 0

            while time.monotonic() < deadline or pending:
                # Submit new work while under deadline
                while len(pending) < batch_size and time.monotonic() < deadline:
                    config = generate_configs(rng, schedulers)
                    config.iteration = iteration
                    iteration += 1
                    future = pool.submit(run_one, config)
                    pending[future] = config
                    total_runs += 1

                # Collect results
                done = []
                for future in list(pending.keys()):
                    if future.done():
                        done.append(future)

                if not done and pending:
                    # Wait for at least one to complete
                    try:
                        next_done = next(as_completed(pending, timeout=5))
                        done.append(next_done)
                    except StopIteration:
                        pass
                    except TimeoutError:
                        continue

                for future in done:
                    config = pending.pop(future)
                    completed_runs += 1
                    try:
                        finding = future.result()
                    except Exception as e:
                        finding = Finding(
                            config=config,
                            error_type="executor_error",
                            exit_code=-1,
                            stderr=str(e),
                            stdout="",
                            wall_time_sec=0,
                        )

                    if finding is not None:
                        findings.append(finding)
                        num = len(findings)
                        path = save_finding(finding, num)
                        log.warning(f"BUG #{num}: {finding.summary()} -> {path.name}")
                        print(
                            f"  BUG #{num}: {finding.summary()}"
                            f"  -> {path.name}"
                        )
                    else:
                        log.debug(f"PASS: {config.label}")

                # Progress update every batch
                elapsed_min = (time.monotonic() - start_time) / 60
                remaining_min = max(0, (deadline - time.monotonic()) / 60)
                rate = completed_runs / max(elapsed_min, 0.01)
                sys.stdout.write(
                    f"\r  {completed_runs} runs, "
                    f"{len(findings)} bugs, "
                    f"{rate:.0f} runs/min, "
                    f"{remaining_min:.1f}min left"
                )
                sys.stdout.flush()

                # Log progress periodically (roughly every 100 runs)
                if completed_runs % 100 < len(done):
                    log.info(
                        f"Progress: {completed_runs} runs, {len(findings)} bugs, "
                        f"{rate:.0f} runs/min, {remaining_min:.1f}min left"
                    )

    except KeyboardInterrupt:
        log.info("Interrupted by user")
        print("\n\nInterrupted by user.")

    # Final report
    elapsed_total = (time.monotonic() - start_time) / 60
    print(f"\n\n{'=' * 60}")
    print(f"Stress test complete")
    print(f"{'=' * 60}")
    print(f"  Total runs:  {completed_runs}")
    print(f"  Findings:    {len(findings)}")
    print(f"  Master seed: {master_seed}")
    print(f"  Elapsed:     {elapsed_total:.1f} minutes")

    log.info("=" * 60)
    log.info("Stress test complete")
    log.info("=" * 60)
    log.info(f"Total runs: {completed_runs}")
    log.info(f"Findings: {len(findings)}")
    log.info(f"Master seed: {master_seed}")
    log.info(f"Elapsed: {elapsed_total:.1f} minutes")

    if findings:
        print(f"\n  Findings by type:")
        type_counts: dict[str, int] = {}
        for f in findings:
            type_counts[f.error_type] = type_counts.get(f.error_type, 0) + 1
        for error_type, count in sorted(type_counts.items()):
            print(f"    {error_type}: {count}")
            log.info(f"  {error_type}: {count}")
        print(f"\n  Reports written to: {OUTPUT_DIR}")
    else:
        print(f"\n  No bugs found.")
        log.info("No bugs found.")

    log.info(f"Log file: {log_path}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
