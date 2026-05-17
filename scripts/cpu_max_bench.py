#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
# Author: Changwoo Min <changwoo@igalia.com>
#
# cpu_max_bench.py - Benchmark for measuring cpu.max cgroup bandwidth overhead
#
# Runs stress-ng --cpu inside a deep cgroup hierarchy with cpu.max enforced at
# every level, measuring kernel-mode cycle overhead via "perf stat -a".
#
# Usage:
#   sudo ./cpu_max_bench.py [OPTIONS] [CONFIG_FILE]
#
# See --help for full option list and CONFIG_FILE format.

import argparse
import atexit
import configparser
import fnmatch
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

NPROC = os.cpu_count() or 1
CGROUP_ROOT = Path('/sys/fs/cgroup')
PERIOD_US = 100_000   # 100 ms cgroup period
BENCH_ID_PREFIX = 'cpu_max_bench'

# Sleep durations used inside run_benchmark(); kept as constants so the
# estimated run-time printed at startup stays in sync with actual behaviour.
SLEEP_PERF_ARM    = 0.3   # let perf arm before stress-ng starts
SLEEP_CGROUP_MOVE = 0.5   # let stress-ng spawn workers before cgroup move
SLEEP_SCX_STARTUP = 20.0  # wait for scx_lavd to become active

# Per-process monotonic counter so two run_benchmark() calls in the same
# millisecond still produce distinct cgroup names.  Combined with PID and
# wall-clock millisecond it makes the bench_id collision-free.
_bench_seq = 0


def _next_bench_id() -> str:
    global _bench_seq
    _bench_seq += 1
    return f'{BENCH_ID_PREFIX}_{os.getpid()}_{int(time.time() * 1000)}_{_bench_seq}'


# Cleanup registry: every CgroupManager that is currently set up registers
# itself here so that a SIGTERM / SIGINT / unhandled exception triggers a
# best-effort teardown.  This is the safety net for hard-exits where the
# normal try/finally in run_benchmark does not get a chance to run.
_active_cleanups: list = []


def _register_cleanup(cg) -> None:
    _active_cleanups.append(cg)


def _unregister_cleanup(cg) -> None:
    try:
        _active_cleanups.remove(cg)
    except ValueError:
        pass


def _run_emergency_cleanup() -> None:
    """Tear down any cgroups still registered.  Called from atexit and from
    the SIGTERM/SIGINT handler installed in main()."""
    while _active_cleanups:
        cg = _active_cleanups.pop()
        try:
            cg.teardown()
        except Exception as exc:
            print(f'emergency teardown of {cg.leaf}: {exc}', file=sys.stderr)


def _signal_handler(signum, frame) -> None:
    print(f'\nReceived signal {signum}; cleaning up cgroups...',
          file=sys.stderr)
    _run_emergency_cleanup()
    sys.exit(128 + signum)


atexit.register(_run_emergency_cleanup)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    """Parameters for one benchmark run."""

    def __init__(self, name, depth=32, quota=None, load_factor=100,
                 duration=60, scheduler='eevdf',
                 scx_path='/usr/bin/scx_lavd',
                 scx_args='--performance --enable-cpu-bw'):
        self.name = name
        self.depth = int(depth)
        # quota: None  -> "max" (unlimited)
        #        float -> percent of NPROC; e.g., 100 == NPROC CPUs,
        #                  50 == NPROC/2 CPUs.
        self.quota = quota
        self.load_factor = int(load_factor)
        self.duration = int(duration)
        self.scheduler = scheduler
        self.scx_path = scx_path
        self.scx_args = scx_args

    # -- derived properties --------------------------------------------------

    @property
    def workers(self):
        return max(1, int(NPROC * self.load_factor / 100))

    @property
    def quota_cpus(self):
        """Quota expressed in CPUs (percent of NPROC), or None for "max"."""
        if self.quota is None:
            return None
        return self.quota * NPROC / 100.0

    @property
    def quota_us(self):
        """Quota in microseconds per PERIOD_US period, or None for "max"."""
        if self.quota is None:
            return None
        return int(self.quota_cpus * PERIOD_US)

    @property
    def quota_str(self):
        if self.quota is None:
            return 'max'
        return f'{self.quota:g}%'

    @property
    def group_key(self):
        """Configurations that share these three values belong to one report group."""
        return (self.depth, self.quota, self.load_factor)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

class BenchmarkResult:
    """All data collected from a single benchmark run."""

    def __init__(self, config: Config):
        self.config = config
        # perf stat counters
        self.cycles: int = 0
        self.cycles_k: int = 0
        self.cache_misses: int = 0
        self.stalled_cycles_backend: int = 0
        self.instructions: int = 0
        # stress-ng summary
        self.bogo_ops: int = 0
        self.bogo_ops_per_sec: float = 0.0
        # per-second CPU utilisation from cgroup cpu.stat
        self.cpu_util_samples: list = []   # [(elapsed_s, cpu_used_cpus), ...]
        # raw text from each tool
        self.perf_raw: str = ''
        self.stress_ng_raw: str = ''
        # directory where per-run files are saved
        self.output_dir: Path = Path('.')

    @property
    def overhead_cpus(self) -> float:
        """Kernel-mode overhead expressed as equivalent number of CPUs."""
        if self.cycles == 0:
            return 0.0
        return (self.cycles_k / self.cycles) * NPROC


# ---------------------------------------------------------------------------
# Cgroup hierarchy management
# ---------------------------------------------------------------------------

class CgroupManager:
    """Creates and tears down a linear cgroup chain of the requested depth."""

    def __init__(self, config: Config, bench_id: str):
        self.config = config
        # Per-run cgroup chain placed directly under the system root, so
        # that cgroup_depth == N means the leaf is at kernel cgrp->level N
        # (system root is level 0).  cgroup_depth = 0 is a special case:
        # no per-run cgroup is created and the workload runs in the system
        # root cgroup itself, used as a "no-cgroup-overhead" baseline.
        self._run_root = CGROUP_ROOT / bench_id
        self._all_levels = self._build_level_paths()
        self.leaf = self._all_levels[-1] if self._all_levels else CGROUP_ROOT

    def _build_level_paths(self) -> list:
        """Return list of Path objects from run root down to the leaf.

        depth=0 -> empty chain; the workload runs in the system root.
        depth=N (N >= 1) -> chain of N nodes, leaf at kernel level N.
        """
        if self.config.depth <= 0:
            return []
        paths = [self._run_root]
        for i in range(1, self.config.depth):
            paths.append(paths[-1] / f'l{i}')
        return paths

    @staticmethod
    def _write(path: Path, content: str):
        try:
            path.write_text(content + '\n')
        except OSError as exc:
            _warn(f'write {content!r} -> {path}: {exc}')

    def setup(self):
        """Enable the cpu controller and create the full cgroup chain."""
        # Enable cpu at the system root (idempotent)
        self._write(CGROUP_ROOT / 'cgroup.subtree_control', '+cpu')

        # depth=0: no per-run cgroup; cpu.max on the system root is left
        # untouched.  Any non-"max" quota in the config is silently
        # ignored in this mode.
        if not self._all_levels:
            return

        quota_content = (
            f'max {PERIOD_US}'
            if self.config.quota is None
            else f'{self.config.quota_us} {PERIOD_US}'
        )

        for idx, path in enumerate(self._all_levels):
            path.mkdir(exist_ok=True)
            self._write(path / 'cpu.max', quota_content)
            # Enable cpu controller for children unless this is the leaf
            if idx < len(self._all_levels) - 1:
                self._write(path / 'cgroup.subtree_control', '+cpu')

    def move_pid(self, pid: int):
        """Assign a process to the leaf cgroup."""
        self._write(self.leaf / 'cgroup.procs', str(pid))

    def read_usage_usec(self) -> int:
        """Return cumulative CPU usage (us) from the leaf cgroup.

        For depth=0 the leaf is the system root; cpu.stat there reports
        SYSTEM-WIDE usage (not isolated to the workload).  Acceptable
        for the root_* baseline as long as stress-ng dominates the load.
        """
        try:
            for line in (self.leaf / 'cpu.stat').read_text().splitlines():
                if line.startswith('usage_usec'):
                    return int(line.split()[1])
        except (OSError, ValueError):
            pass
        return 0

    def teardown(self):
        """Remove the per-run cgroup subtree (leaf to root).

        Steps:
          1. Write 1 to leaf/cgroup.kill to terminate any leftover
             processes (cgroupv2 feature, kernel >= 5.14).
          2. Wait briefly for the leaf to become unpopulated so that
             rmdir() sees an empty cgroup; otherwise rmdir() fails with
             EBUSY and the cgroup leaks across runs.
          3. rmdir() bottom-up.  Any rmdir failure is logged loudly so
             that a leaked cgroup never goes unnoticed.

        depth=0 has no chain to remove.
        """
        if not self._all_levels:
            return
        leaf = self.leaf
        try:
            (leaf / 'cgroup.kill').write_text('1\n')
        except OSError:
            # cgroup.kill missing or write failed (e.g. older kernel);
            # fall back to relying on already-exited workers.
            pass
        self._wait_unpopulated(leaf, timeout=30.0)
        for path in reversed(self._all_levels):
            try:
                path.rmdir()
            except OSError as exc:
                _warn(f'rmdir({path}) failed: {exc}')

    @staticmethod
    def _wait_unpopulated(path: Path, timeout: float):
        """Spin on cgroup.events until populated == 0 or timeout."""
        deadline = time.monotonic() + timeout
        events_path = path / 'cgroup.events'
        while time.monotonic() < deadline:
            try:
                content = events_path.read_text()
            except OSError:
                return
            if 'populated 0' in content.splitlines():
                return
            time.sleep(0.05)


# ---------------------------------------------------------------------------
# Scheduler management
# ---------------------------------------------------------------------------

class SchedulerManager:
    """Ensures the requested CPU scheduler is active for the benchmark."""

    def __init__(self, config: Config):
        self.config = config
        self._proc = None

    def setup(self):
        if self.config.scheduler == 'eevdf':
            self._kill_scx_lavd()
        elif self.config.scheduler == 'scx_lavd':
            self._start_scx_lavd()

    def teardown(self):
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _kill_scx_lavd(self):
        try:
            r = subprocess.run(['pgrep', '-x', 'scx_lavd'],
                               capture_output=True, text=True)
            for pid_s in r.stdout.split():
                try:
                    os.kill(int(pid_s), signal.SIGTERM)
                except (ProcessLookupError, ValueError):
                    pass
            if r.stdout.strip():
                time.sleep(1)
        except FileNotFoundError:
            pass

    def _start_scx_lavd(self):
        self._kill_scx_lavd()
        cmd = [self.config.scx_path] + self.config.scx_args.split()
        self._proc = subprocess.Popen(cmd,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        time.sleep(SLEEP_SCX_STARTUP)
        if self._proc.poll() is not None:
            raise RuntimeError(
                f'scx_lavd exited early (code {self._proc.returncode})')


# ---------------------------------------------------------------------------
# Per-second CPU utilisation monitor
# ---------------------------------------------------------------------------

class CpuUtilMonitor:
    """Reads cgroup cpu.stat every second and records utilisation samples."""

    def __init__(self, cg: CgroupManager):
        self._cg = cg
        self.samples: list = []   # [(elapsed_s, cpu_used_cpus)]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        prev_usec = self._cg.read_usage_usec()
        prev_mono = time.monotonic()
        elapsed = 0.0

        while not self._stop.wait(1.0):
            cur_usec = self._cg.read_usage_usec()
            cur_mono = time.monotonic()
            delta_usec = cur_usec - prev_usec
            delta_sec = cur_mono - prev_mono
            elapsed += delta_sec
            if delta_sec > 0:
                cpu_used = (delta_usec / 1_000_000) / delta_sec
                self.samples.append((elapsed, cpu_used))
            prev_usec = cur_usec
            prev_mono = cur_mono


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

_PERF_NUM_RE = re.compile(
    r'^\s*([\d,]+(?:\.\d+)?)\s+'   # numeric value (possibly with commas)
    r'([\w:/-]+)'                  # event name
)

def parse_perf_output(text: str) -> dict:
    """Extract counter values from ``perf stat`` stderr."""
    result = {
        'cycles': 0,
        'cycles_k': 0,
        'cache_misses': 0,
        'stalled_cycles_backend': 0,
        'instructions': 0,
    }
    for line in text.splitlines():
        m = _PERF_NUM_RE.match(line)
        if not m:
            continue
        raw_val = m.group(1).replace(',', '')
        event = m.group(2).strip().rstrip('#').lower()
        try:
            val = int(float(raw_val))
        except ValueError:
            continue

        if event == 'cycles':
            result['cycles'] = val
        elif event in ('cycles:k', 'cycles:ku'):
            result['cycles_k'] = val
        elif event in ('cache-misses', 'llc-load-misses'):
            result['cache_misses'] = val
        elif event in ('stalled-cycles-backend',
                       'cpu/stalled-cycles-backend/'):
            result['stalled_cycles_backend'] = val
        elif event == 'instructions':
            result['instructions'] = val

    return result


def parse_stress_ng_output(text: str) -> tuple:
    """Return (bogo_ops, bogo_ops_per_sec) from stress-ng output."""
    bogo_ops = 0
    bogo_ops_per_sec = 0.0

    for line in text.splitlines():
        # Modern stress-ng --metrics-brief format:
        #   stress-ng: info:  [PID] cpu    N  60.00s  <bogo/s-real>  <bogo/s-usr>  ...
        # Older format may differ.  We look for the "cpu" stressor summary line.
        m = re.search(
            r'\bcpu\b\s+\d+\s+[\d.]+s\s+([\d.]+)\s+([\d.]+)', line)
        if m:
            bogo_ops_per_sec = float(m.group(1))
            bogo_ops = int(float(m.group(2)))
            break

        # Fallback: "N bogo ops"
        m = re.search(r'([\d,]+)\s+bogo ops.*?([\d.]+)\s+bogo ops/s', line)
        if m:
            bogo_ops = int(m.group(1).replace(',', ''))
            bogo_ops_per_sec = float(m.group(2))
            break

    return bogo_ops, bogo_ops_per_sec


# ---------------------------------------------------------------------------
# Single-run execution
# ---------------------------------------------------------------------------

def run_benchmark(config: Config, output_dir: Path) -> BenchmarkResult:
    """Execute one benchmark configuration and return a populated result."""
    result = BenchmarkResult(config)
    result.output_dir = output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    cg = CgroupManager(config, _next_bench_id())
    sched = SchedulerManager(config)
    monitor = CpuUtilMonitor(cg)

    print(f'  cgroup: depth={config.depth}, quota={config.quota_str}, '
          f'workers={config.workers}, duration={config.duration}s, '
          f'scheduler={config.scheduler}')

    cg.setup()
    _register_cleanup(cg)
    sched.setup()

    perf_proc = stress_proc = None
    try:
        # --- start perf stat (system-wide, runs for exactly duration seconds) ---
        perf_cmd = [
            'perf', 'stat', '-a',
            '-e', 'cycles',
            '-e', 'cycles:k',
            '-e', 'cache-misses',
            '-e', 'stalled-cycles-backend',
            '-e', 'instructions',
            '--', 'sleep', str(config.duration),
        ]
        perf_proc = subprocess.Popen(perf_cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

        # Give perf a moment to arm before stress-ng starts
        time.sleep(SLEEP_PERF_ARM)

        # --- start stress-ng ---
        stress_cmd = [
            'stress-ng',
            '--cpu', str(config.workers),
            '--timeout', f'{config.duration}s',
            '--metrics-brief',
        ]
        stress_proc = subprocess.Popen(stress_cmd,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)

        # Move stress-ng master and worker children into the leaf cgroup
        time.sleep(SLEEP_CGROUP_MOVE)
        _move_proc_tree(stress_proc.pid, cg)

        # --- start per-second CPU utilisation monitor ---
        monitor.start()

        # --- wait for stress-ng ---
        s_out, s_err = stress_proc.communicate(timeout=config.duration + 60)
        result.stress_ng_raw = (s_out + s_err).decode('utf-8', errors='replace')

        # --- wait for perf ---
        p_out, p_err = perf_proc.communicate(timeout=30)
        result.perf_raw = (p_out + p_err).decode('utf-8', errors='replace')

        monitor.stop()

        # --- parse results ---
        pm = parse_perf_output(result.perf_raw)
        result.cycles                  = pm['cycles']
        result.cycles_k                = pm['cycles_k']
        result.cache_misses            = pm['cache_misses']
        result.stalled_cycles_backend  = pm['stalled_cycles_backend']
        result.instructions            = pm['instructions']

        result.bogo_ops, result.bogo_ops_per_sec = \
            parse_stress_ng_output(result.stress_ng_raw)
        result.cpu_util_samples = list(monitor.samples)

        # --- save raw outputs ---
        (output_dir / 'perf_stat.txt').write_text(result.perf_raw)
        (output_dir / 'stress_ng.txt').write_text(result.stress_ng_raw)

    except Exception:
        monitor.stop()
        if perf_proc and perf_proc.poll() is None:
            perf_proc.kill()
        if stress_proc and stress_proc.poll() is None:
            stress_proc.kill()
        raise
    finally:
        sched.teardown()
        cg.teardown()
        _unregister_cleanup(cg)

    return result


def _move_proc_tree(pid: int, cg: CgroupManager):
    """Move a process and its direct children into the leaf cgroup."""
    try:
        cg.move_pid(pid)
    except OSError as exc:
        _warn(f'move_pid({pid}): {exc}')

    try:
        r = subprocess.run(['pgrep', '-P', str(pid)],
                           capture_output=True, text=True)
        for child in r.stdout.split():
            try:
                cg.move_pid(int(child))
            except (OSError, ValueError):
                pass
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Reporting & graphs
# ---------------------------------------------------------------------------

def generate_report(groups: dict, output_dir: Path):
    """Write report.md (Markdown) and per-group CPU utilisation graphs."""
    lines = []
    lines += [
        '# cpu.max Overhead Benchmark Report',
        '',
        f'- **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'- **CPUs**: {NPROC}',
        '',
    ]

    for group_key, results in groups.items():
        depth, quota, load_factor = group_key
        quota_display = ('max (unlimited)' if quota is None
                         else f'{quota:g}% ({quota * NPROC / 100:.2f} CPUs)')

        lines += [
            '---',
            '',
            f'## Group: cgroup_depth={depth}  quota={quota_display}  load={load_factor}%',
            '',
        ]

        # Perf metrics table
        lines += [
            '| config | cycles:k | cycles | overhead (CPUs) | bogo ops/s |',
            '|--------|----------|--------|-----------------|------------|',
        ]
        for r in results:
            lines.append(
                f'| `{r.config.name}` '
                f'| {r.cycles_k:,} '
                f'| {r.cycles:,} '
                f'| {r.overhead_cpus:.4f} '
                f'| {r.bogo_ops_per_sec:.1f} |'
            )
        lines.append('')

        # Extra perf counters as a detail table (only rows with data)
        extra_headers = []
        extra_rows = {r.config.name: {} for r in results}
        for r in results:
            if r.cache_misses:
                extra_headers.append('cache misses')
                extra_rows[r.config.name]['cache misses'] = f'{r.cache_misses:,}'
            if r.stalled_cycles_backend:
                extra_headers.append('stalled cycles (backend)')
                extra_rows[r.config.name]['stalled cycles (backend)'] = \
                    f'{r.stalled_cycles_backend:,}'
            if r.instructions:
                extra_headers.append('instructions')
                extra_rows[r.config.name]['instructions'] = f'{r.instructions:,}'

        extra_headers = list(dict.fromkeys(extra_headers))  # deduplicate, keep order
        if extra_headers:
            hdr = '| config | ' + ' | '.join(extra_headers) + ' |'
            sep = '|--------|' + '|'.join(['-----'] * len(extra_headers)) + '|'
            lines += [hdr, sep]
            for r in results:
                row_vals = [extra_rows[r.config.name].get(h, '-')
                            for h in extra_headers]
                lines.append(f'| `{r.config.name}` | ' +
                              ' | '.join(row_vals) + ' |')
            lines.append('')

        # Generate graph and embed it
        slug = _make_cpu_util_graph(group_key, results, output_dir)
        if slug:
            lines += [
                '### CPU Utilisation',
                '',
                f'![CPU utilisation graph]({slug}.png)',
                '',
            ]

    report_text = '\n'.join(lines)
    report_path = output_dir / 'report.md'
    report_path.write_text(report_text)
    print(f'\nReport written to: {report_path}')
    print('\n' + report_text)


def _make_cpu_util_graph(group_key: tuple, results: list, output_dir: Path):
    """Generate PNG and SVG graphs; return the slug (filename without extension)."""
    depth, quota, load_factor = group_key
    quota_str = 'max' if quota is None else f'{quota:g}pct'
    slug = f'group_d{depth}_{quota_str}_l{load_factor}'

    if not HAS_MATPLOTLIB:
        _warn('matplotlib not installed - skipping graphs')
        return None

    fig, ax = plt.subplots(figsize=(14, 6))
    colors = plt.cm.tab10.colors

    # Distinct point glyph per scheduler so overlapping lines remain
    # distinguishable; runs of the same scheduler are still separated by
    # color.
    scheduler_markers = {
        'eevdf':    'o',
        'scx_lavd': 's',
    }
    default_marker = 'D'

    # Samples are stored as CPU-equivalents (1.0 == one CPU fully busy).
    # Convert to percent of nproc for the y-axis.
    pct_per_cpu = 100.0 / NPROC

    for i, r in enumerate(results):
        if not r.cpu_util_samples:
            continue
        ts = [s[0] for s in r.cpu_util_samples]
        vs = [s[1] * pct_per_cpu for s in r.cpu_util_samples]
        marker = scheduler_markers.get(r.config.scheduler, default_marker)
        ax.plot(ts, vs, label=r.config.name,
                color=colors[i % len(colors)], linewidth=1.5,
                marker=marker, markersize=5,
                markevery=max(1, len(ts) // 30))

    # Quota reference line (already in percent of nproc).
    if quota is not None:
        ax.axhline(y=quota, color='red', linestyle='--', linewidth=2,
                   label=f'quota ({quota:g}%)')

    ax.set_xlabel('Time (s)')
    ax.set_ylabel('CPU utilisation (% of nproc)')
    quota_title = 'max' if quota is None else f'{quota:g}%'
    ax.set_title(
        f'CPU utilisation  |  depth={depth}  quota={quota_title}  load={load_factor}%')
    ax.legend(loc='lower right')
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)

    for fmt in ('png', 'svg'):
        path = output_dir / f'{slug}.{fmt}'
        fig.savefig(path, format=fmt, dpi=150, bbox_inches='tight')
        print(f'  graph -> {path}')

    plt.close(fig)
    return slug


# ---------------------------------------------------------------------------
# Configuration file loader
# ---------------------------------------------------------------------------

def load_config_file(path: str, select: list = None) -> list:
    """
    Parse an INI config file.  Each section is one benchmark run.

    Keys (all optional, defaults shown):
      cgroup_depth  = 32
      quota         = max         # "max" or a float (percent of nproc)
      load_factor   = 100         # percent of nproc
      duration      = 60          # seconds
      scheduler     = eevdf       # eevdf | scx_lavd
      scx_path      = /usr/bin/scx_lavd
      scx_args      = --performance --enable-cpu-bw

    @select: optional list of fnmatch globs.  If non-empty, only sections
             whose name matches at least one pattern are loaded.
    """
    cp = configparser.ConfigParser()
    if not cp.read(path):
        _die(f'cannot read config file: {path}')

    sections = cp.sections()
    if select:
        sections = [s for s in sections
                    if any(fnmatch.fnmatchcase(s, p) for p in select)]
        if not sections:
            available = ', '.join(cp.sections()) or '(none)'
            _die(f'no config sections match {select!r}\n'
                 f'available sections: {available}')

    configs = []
    for section in sections:
        quota = _parse_quota(cp.get(section, 'quota', fallback='max'))
        configs.append(Config(
            name        = section,
            depth       = cp.getint(section, 'cgroup_depth', fallback=32),
            quota       = quota,
            load_factor = cp.getint(section, 'load_factor', fallback=100),
            duration    = cp.getint(section, 'duration', fallback=60),
            scheduler   = cp.get(section, 'scheduler', fallback='eevdf'),
            scx_path    = cp.get(section, 'scx_path',
                                 fallback='/usr/bin/scx_lavd'),
            scx_args    = cp.get(section, 'scx_args',
                                 fallback='--performance --enable-cpu-bw'),
        ))
    return configs


def _parse_quota(s: str):
    """Convert quota string to float (percent of NPROC) or None for "max"."""
    s = s.strip()
    if s == 'max':
        return None
    try:
        return float(s)
    except ValueError:
        _die(f'invalid quota value: {s!r}  (expected "max" or a number in percent)')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f'{h}h {m:02d}m {s:02d}s'
    if m:
        return f'{m}m {s:02d}s'
    return f'{s}s'


def print_estimated_time(configs: list):
    """Print per-config and total estimated run time."""
    print('\nEstimated run time:')
    total = 0.0
    for cfg in configs:
        per_run = (
            cfg.duration
            + SLEEP_PERF_ARM
            + SLEEP_CGROUP_MOVE
            + (SLEEP_SCX_STARTUP if cfg.scheduler == 'scx_lavd' else 0)
        )
        total += per_run
        scx_note = f' (includes {SLEEP_SCX_STARTUP:.0f}s scx_lavd startup)' \
                   if cfg.scheduler == 'scx_lavd' else ''
        print(f'  [{cfg.name}]  {_fmt_duration(per_run)}{scx_note}')
    print(f'  {"---"}')
    print(f'  Total  {_fmt_duration(total)}')
    print()


def _warn(msg: str):
    print(f'Warning: {msg}', file=sys.stderr)

def _die(msg: str):
    print(f'Error: {msg}', file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='cpu_max_bench.py',
        description=(
            'Measure cpu.max cgroup bandwidth overhead using stress-ng + perf stat.\n'
            'Must be run as root.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
defaults: depth=32, quota=max, load=100%, duration=60s, scheduler=eevdf

QUOTA  (percent of nproc; this machine has {NPROC} CPUs)
  max        no cpu.max enforcement (baseline)
  100        nproc CPUs (quota matches the machine)
  N          N percent of nproc (float accepted, e.g. 12.5 ~= {NPROC * 0.125:g} CPUs)

CONFIG FILE (INI format)
  Each section defines one run; section name becomes the config label.
  Example:

    [baseline]
    quota = max
    scheduler = eevdf

    [cpumax_eevdf]
    quota = 100
    scheduler = eevdf

    [cpumax_lavd]
    quota = 100
    scheduler = scx_lavd

EXAMPLES
  sudo {sys.argv[0]}
  sudo {sys.argv[0]} --quota 100 --scheduler eevdf
  sudo {sys.argv[0]} -o /tmp/bench cpu_max_bench.ini
  sudo {sys.argv[0]} -o /tmp/bench --scx-path ../target/release/scx_lavd cpu_max_bench.ini
  sudo {sys.argv[0]} -o /tmp/bench -S 'baseline_*' cpu_max_bench.ini
  sudo {sys.argv[0]} -o /tmp/bench -S 'q50pct_load_010_*' -S 'depth_01_*' cpu_max_bench.ini
""")

    p.add_argument('config_file', nargs='?',
                   help='INI file with multiple benchmark configurations')
    p.add_argument('-S', '--select', metavar='PATTERN', action='append',
                   default=[],
                   help='only run config sections whose name matches PATTERN '
                        '(fnmatch glob); may be repeated to select the union '
                        '(e.g. -S "baseline_*" -S q50pct_load_010_eevdf)')
    p.add_argument('-d', '--depth', type=int, default=32, metavar='N',
                   help='cgroup hierarchy depth (default: 32)')
    p.add_argument('-q', '--quota', default='max', metavar='QUOTA',
                   help='CPU quota: max | <percent of nproc>  (default: max)')
    p.add_argument('-l', '--load-factor', type=int, default=100, metavar='PCT',
                   help='stress-ng workers as %% of nproc (default: 100)')
    p.add_argument('-t', '--duration', type=int, default=60, metavar='SECS',
                   help='benchmark duration in seconds (default: 60)')
    p.add_argument('-s', '--scheduler', choices=['eevdf', 'scx_lavd'],
                   default='eevdf',
                   help='CPU scheduler to use (default: eevdf)')
    p.add_argument('--scx-path', default=None, metavar='PATH',
                   help='path to scx_lavd binary (default: /usr/bin/scx_lavd); '
                        'overrides scx_path in the config file for all configurations')
    p.add_argument('--scx-args',
                   default='--performance --enable-cpu-bw', metavar='ARGS',
                   help='arguments for scx_lavd '
                        '(default: --performance --enable-cpu-bw)')
    p.add_argument('-o', '--output', default=None, metavar='DIR',
                   help='output directory (default: YYYY-MM-DDTHH:MM:SS)')
    return p


_DISTROS = [
    # (display name, install command prefix, package-key in _TOOLS / _PY_PKGS)
    ('Ubuntu',                 'sudo apt install',  'ubuntu'),
    ('Arch Linux',             'sudo pacman -S',    'arch'),
    ('Fedora or Amazon Linux', 'sudo dnf install',  'fedora'),  # AL2023; on AL2 swap dnf -> yum
]

_TOOLS = {
    'perf': {
        'binary': 'perf',
        'extra_args': None,
        'ubuntu': 'linux-tools-common linux-tools-generic',
        'arch':   'perf',
        'fedora': 'perf',
    },
    'perf stat': {
        'binary': 'perf',
        'extra_args': ['stat', '--help'],
        'ubuntu': 'linux-tools-common linux-tools-generic',
        'arch':   'perf',
        'fedora': 'perf',
    },
    'stress-ng': {
        'binary': 'stress-ng',
        'extra_args': None,
        'ubuntu': 'stress-ng',
        'arch':   'stress-ng',
        'fedora': 'stress-ng',
    },
}

_PY_PKGS = {
    'matplotlib': {
        'ubuntu': 'python3-matplotlib',
        'arch':   'python-matplotlib',
        'fedora': 'python3-matplotlib',
    },
}


def check_dependencies():
    """Verify required tools and Python packages are available."""
    missing_tools = []
    for name, info in _TOOLS.items():
        # First check the binary is on PATH
        r = subprocess.run(['which', info['binary']], capture_output=True)
        if r.returncode != 0:
            missing_tools.append(name)
            continue
        # For "perf stat", also verify the subcommand is available
        if info['extra_args']:
            r2 = subprocess.run([info['binary']] + info['extra_args'],
                                capture_output=True)
            if r2.returncode != 0:
                missing_tools.append(name)

    missing_py = []
    if not HAS_MATPLOTLIB:
        missing_py.append('matplotlib')

    if not missing_tools and not missing_py:
        return

    print('ERROR: missing required dependencies\n', file=sys.stderr)

    if missing_tools:
        print('Missing tools:', ', '.join(missing_tools), file=sys.stderr)
        for display, cmd, key in _DISTROS:
            pkgs = list(dict.fromkeys(
                _TOOLS[t][key] for t in missing_tools if t in _TOOLS))
            print(f'\nInstall on {display}:', file=sys.stderr)
            print(f'  {cmd} {" ".join(pkgs)}', file=sys.stderr)

    if missing_py:
        print('\nMissing Python packages:', ', '.join(missing_py),
              file=sys.stderr)
        for display, cmd, key in _DISTROS:
            pkgs = list(dict.fromkeys(
                _PY_PKGS[p][key] for p in missing_py if p in _PY_PKGS))
            print(f'\nInstall on {display}:', file=sys.stderr)
            print(f'  {cmd} {" ".join(pkgs)}', file=sys.stderr)
        print('\nOr via pip:', file=sys.stderr)
        print(f'  pip3 install {" ".join(missing_py)}', file=sys.stderr)

    sys.exit(1)


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # Install handlers so a SIGTERM / SIGINT mid-run still tears down
    # any cgroups currently set up.  atexit covers normal/exception
    # exits; the signal handler covers external termination.
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT,  _signal_handler)

    check_dependencies()

    if os.geteuid() != 0:
        _die('must be run as root (needs cgroup writes and perf_event access)')

    # Resolve output directory
    out_root = Path(args.output) if args.output else \
        Path(datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
    out_root.mkdir(parents=True, exist_ok=True)
    print(f'Output directory: {out_root}')

    # Build configuration list
    if args.config_file:
        configs = load_config_file(args.config_file, select=args.select)
        if not configs:
            _die(f'no configurations found in {args.config_file}')
        if args.scx_path is not None:
            for cfg in configs:
                cfg.scx_path = args.scx_path
    elif args.select:
        _die('--select can only be used with a config file')
    else:
        configs = [Config(
            name        = 'benchmark',
            depth       = args.depth,
            quota       = _parse_quota(args.quota),
            load_factor = args.load_factor,
            duration    = args.duration,
            scheduler   = args.scheduler,
            scx_path    = args.scx_path or '/usr/bin/scx_lavd',
            scx_args    = args.scx_args,
        )]

    print_estimated_time(configs)

    # Run benchmarks
    all_results = []
    for idx, cfg in enumerate(configs, 1):
        print(f'\n[{idx}/{len(configs)}] {cfg.name}')
        cfg_dir = out_root / f'config_{cfg.name}'
        result = run_benchmark(cfg, cfg_dir)
        all_results.append(result)
        print(f'  cycles:k / cycles   = {result.cycles_k:,} / {result.cycles:,}')
        print(f'  overhead            = {result.overhead_cpus:.4f} CPUs')
        print(f'  bogo ops/s          = {result.bogo_ops_per_sec:.1f}')

    # Group and report
    groups: dict = {}
    for r in all_results:
        groups.setdefault(r.config.group_key, []).append(r)

    print(f'\n{"=" * 80}')
    print('Generating report...')
    generate_report(groups, out_root)
    print(f'\nDone.  Results in: {out_root}/  (report: {out_root}/report.md)')


if __name__ == '__main__':
    main()
