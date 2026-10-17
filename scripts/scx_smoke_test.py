#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
#
# scx_smoke_test.py — install scx schedulers from crates.io and verify they run.
#
# Two-phase design:
#
#   Phase 1 (discover):
#     - Walk the scx workspace Cargo.toml for scheduler crates under
#       scheds/rust/* and scheds/experimental/*.
#     - Cross-check each crate against the crates.io API to record the latest
#       stable version actually published. Crates with no published release
#       (e.g. scx_mitosis as of 1.1.1) are still listed but flagged
#       ``published: false`` so they can be hand-enabled if desired.
#     - Layer in per-crate metadata: extra runtime args (e.g. scx_layered's
#       --run-example flag), known-fragile classification (e.g. scx_rlfifo), and
#       fallback versions for crates whose canonical release has a known
#       packaging bug (e.g. scx_cosmos 1.1.1 → 1.1.2 fallback).
#     - Emit a JSON manifest. The manifest is the unit of input/output for
#       Phase 2: users can inspect it, hand-edit versions, remove crates, or
#       commit it alongside results.
#
#   Phase 2 (run):
#     - Read a manifest.
#     - For each crate: cargo install --locked --version <ver> <crate>
#       (with optional fallback version), then sudo-run the resulting binary
#       for ``duration`` seconds.
#     - Classify each scheduler as PASS / FAIL / KNOWN_FRAGILE / ERROR.
#     - Write per-crate stdout/stderr/install logs and a SUMMARY.tsv into a
#       timestamped output directory; copy the effective manifest in too.
#
# CLI:
#   scx_smoke_test.py discover [--out FILE | -]      [--version VER]
#                              [--scx-root DIR]      [--no-network]
#   scx_smoke_test.py run      [--manifest FILE]     [--duration SEC]
#                              [--out-dir DIR]       [--schedulers "a b c"]
#                              [--no-fallback]       [--no-color]
#                              [--vm [--kernel PATH]]
#   scx_smoke_test.py list     [--manifest FILE]
#
# The default ``run`` flow with no --manifest auto-runs discover first.
#
# Host requirements: sched_ext-capable kernel (CONFIG_SCHED_CLASS_EXT, >=6.12),
# /sys/kernel/sched_ext present and 'disabled', passwordless sudo, cargo on
# PATH. Only one scheduler can be attached at a time, so runs are strictly
# sequential. A SIGINT/SIGTERM/EXIT handler detaches any leftover scheduler so
# Ctrl+C never leaves the host in a degraded state.
#
# VM mode (--vm): when the host kernel rejects 1.1.x BPF skeletons (e.g. a
# hardened 6.9 kernel rejecting 6.16-era BPF features), the install pass runs
# on the host (cargo + crates.io) and the run pass is delegated to a single
# `vng` (virtme-ng) session booted with the requested --kernel image. Inside
# the VM the script re-execs itself with --in-vm so it skips the install pass
# and runs binaries directly as root (no sudo). The output directory is bound
# RW into the VM via `vng --rwdir` so the per-crate logs and SUMMARY.tsv
# persist on the host. Requires: `vng` on PATH (apt/pip install virtme-ng);
# a host-readable kernel image; cargo on the host; sched_ext-capable kernel
# image (we do NOT require sched_ext on the host kernel in --vm mode).

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

DEFAULT_VERSION = "1.1.1"
DEFAULT_DURATION_S = 300
DEFAULT_FRAGILE_DURATION_S = 30
USER_AGENT = "scx_smoke_test/0.1 (https://github.com/sched-ext/scx)"

# Crates that are scheduler binaries but are documented "not for production"
# demos whose --help warns about runnable-task watchdog stalls under load.
# Install-success + attach-success + graceful-exit is the bar; a watchdog
# trip during the window is NOT a release-blocking FAIL.
KNOWN_FRAGILE: dict[str, str] = {
    "scx_rlfifo": (
        "userspace FIFO demo (rustland_core); runnable-task watchdog under "
        "load is documented expected behavior — see 'scx_rlfifo --help'"
    ),
}

# Per-crate version override. If a crate's canonical release version was
# never successfully published, was yanked, or has a packaging bug, pin to a
# known-good version here. Used as the FALLBACK attempted after the manifest
# version fails to install.
#
# scx_cosmos: 1.1.1 has a build.rs packaging bug ('../../../lib/pmu.bpf.c'
# relative path breaks under `cargo install`'s flattened source layout).
# 1.1.2 ships the fix.
VERSION_FALLBACK: dict[str, str] = {
    "scx_cosmos": "1.1.2",
}

# Per-crate extra arguments passed to the scheduler binary at runtime.
# scx_layered REQUIRES at least one layer spec; without it the binary exits
# with 'Error: No layer spec' before attaching. Use the built-in
# `--run-example` flag, which loads scx_layered's bundled example layer
# specifications (documented as "useful for e.g. CI pipelines" in
# `scx_layered --help`). This avoids shipping our own JSON spec.
SCRIPT_DIR = Path(__file__).resolve().parent
EXTRA_ARGS: dict[str, list[str]] = {
    "scx_layered": ["--run-example"],
}

# Crates we discover from workspace but should not even attempt to install
# (e.g. published under names that mean something other than a runnable
# scheduler binary). Keep empty by default; users can hand-edit the manifest.
EXCLUDE_BY_DEFAULT: set[str] = set()


# ---------------------------------------------------------------------------
# Color helpers (auto-disable when stdout is not a TTY or NO_COLOR is set).
# ---------------------------------------------------------------------------


class Color:
    """Lazy ANSI color wrapper. Disabled when ``enabled`` is False."""

    enabled: bool = False
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"

    @classmethod
    def configure(cls, mode: str) -> None:
        if mode == "never" or os.environ.get("NO_COLOR"):
            cls.enabled = False
            return
        if mode == "always":
            cls.enabled = True
            return
        # auto
        cls.enabled = sys.stdout.isatty()

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"{code}{text}{cls.RESET}"

    @classmethod
    def status(cls, status: str) -> str:
        codes = {
            "PASS": cls.GREEN + cls.BOLD,
            "FAIL": cls.RED + cls.BOLD,
            "KNOWN_FRAGILE": cls.YELLOW + cls.BOLD,
            "ERROR": cls.RED + cls.BOLD,
        }
        return cls.wrap(codes.get(status, ""), status) if cls.enabled else status

    @classmethod
    def section(cls, msg: str) -> None:
        print()
        print(cls.wrap(cls.BLUE + cls.BOLD, f"━━━ {msg} ━━━"))


# ---------------------------------------------------------------------------
# Workspace + crates.io discovery
# ---------------------------------------------------------------------------


def find_scx_root(start: Path) -> Path:
    """Walk upward from ``start`` until we find an scx workspace Cargo.toml.

    Heuristic: Cargo.toml at the same level as scheds/rust/ and the file
    contains '[workspace]'. Falls back to ``start`` if nothing matches.
    """
    p = start.resolve()
    for parent in [p, *p.parents]:
        ct = parent / "Cargo.toml"
        if ct.is_file() and (parent / "scheds" / "rust").is_dir():
            try:
                if "[workspace]" in ct.read_text():
                    return parent
            except OSError:
                continue
    return start


def workspace_scheduler_crates(scx_root: Path) -> list[str]:
    """Parse top-level Cargo.toml for scheduler crate names.

    We use a tolerant text scan rather than a TOML parser so the script
    works on Python <3.11 without tomllib. Format is stable: every member
    is a quoted relative path on its own line.
    """
    cargo = scx_root / "Cargo.toml"
    if not cargo.is_file():
        raise SystemExit(f"no Cargo.toml at {cargo}")
    crates: list[str] = []
    pat = re.compile(r'"\s*scheds/(?:rust|experimental)/([A-Za-z0-9_]+)\s*"')
    for m in pat.finditer(cargo.read_text()):
        crates.append(m.group(1))
    # Drop duplicates while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for c in crates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def crates_io_lookup(name: str, *, timeout: float = 10.0) -> dict[str, Any] | None:
    """Return the ``crate`` payload from crates.io for ``name``, or None.

    Returns None on 404 or network error; surfaces 5xx as None too. The
    discovery phase tolerates missing crates so an unpublished workspace
    member shows up in the manifest with ``published: false`` rather than
    aborting the run.
    """
    url = f"https://crates.io/api/v1/crates/{name}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("crate")  # type: ignore[no-any-return]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        sys.stderr.write(f"warn: crates.io HTTP {e.code} for {name}: {e.reason}\n")
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        sys.stderr.write(f"warn: crates.io fetch failed for {name}: {e}\n")
        return None


def discover_manifest(
    scx_root: Path,
    *,
    pinned_version: str | None = None,
    use_network: bool = True,
) -> dict[str, Any]:
    """Build a manifest dict for Phase 2.

    Each crate entry has stable, hand-editable shape::

        {
          "name": "scx_lavd",
          "version": "1.1.1",
          "type": "scheduler" | "fragile",
          "published": true,
          "fallback_version": "1.1.2" | null,
          "extra_args": ["file:..."],
          "fragile_reason": "..." | null,
          "fragile_duration_s": 30 | null,
          "source_path": "scheds/rust/scx_lavd",
          "notes": "..."        # optional human note
        }
    """
    crate_names = workspace_scheduler_crates(scx_root)

    # Compute source_path lookup once.
    src_path_for: dict[str, str] = {}
    for member in (scx_root / "scheds").glob("*/*"):
        if member.is_dir() and member.name.startswith("scx_"):
            src_path_for[member.name] = str(member.relative_to(scx_root))

    entries: list[dict[str, Any]] = []
    for name in crate_names:
        info = crates_io_lookup(name) if use_network else None
        max_stable = (info or {}).get("max_stable_version") if info else None
        latest = (info or {}).get("max_version") if info else None
        version = pinned_version or max_stable or latest
        published = info is not None and (max_stable is not None or latest is not None)
        is_fragile = name in KNOWN_FRAGILE
        entry: dict[str, Any] = {
            "name": name,
            "version": version,
            "type": "fragile" if is_fragile else "scheduler",
            "published": published,
            "fallback_version": VERSION_FALLBACK.get(name),
            "extra_args": EXTRA_ARGS.get(name, []),
            "fragile_reason": KNOWN_FRAGILE.get(name),
            "fragile_duration_s": DEFAULT_FRAGILE_DURATION_S if is_fragile else None,
            "source_path": src_path_for.get(name, f"scheds/rust/{name}"),
            "notes": None,
        }
        if not published:
            entry["notes"] = "not published to crates.io; skipped by Phase 2 unless edited"
        entries.append(entry)

    return {
        "schema_version": 1,
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "scx_root": str(scx_root),
        "pinned_version_request": pinned_version,
        "default_duration_s": DEFAULT_DURATION_S,
        "default_fragile_duration_s": DEFAULT_FRAGILE_DURATION_S,
        "crates": entries,
    }


# ---------------------------------------------------------------------------
# Pre-flight + run-phase machinery
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    crate: str
    status: str  # PASS|FAIL|KNOWN_FRAGILE|ERROR
    exit_code: int | None
    runtime_s: int
    installed_version: str
    notes: str = ""


@dataclass
class RunContext:
    out_dir: Path
    duration_s: int
    use_fallback: bool
    summary_path: Path
    current_sched_bin: Path | None = None
    results: list[RunResult] = field(default_factory=list)


def preflight(*, in_vm: bool = False, vm_mode: bool = False, kernel_path: Path | None = None) -> None:
    """Pre-flight checks.

    Three modes (mutually exclusive):

    - bare-metal (default): host kernel must have sched_ext attached and be
      disabled; passwordless sudo required; cargo on PATH.
    - vm_mode (``--vm`` on the host): vng must be present; kernel image must
      exist and be readable; cargo on PATH (install happens on host); host
      sched_ext is NOT required and we do NOT need sudo (the VM runs as root).
    - in_vm (``--in-vm`` inside the VM): sched_ext must be present and
      disabled inside the VM; we run as root so no sudo required; cargo not
      required (binaries pre-installed on host and visible via 9p overlay).
    """
    kernel = subprocess.run(["uname", "-r"], capture_output=True, text=True, check=False).stdout.strip()
    print(f"kernel:    {kernel}")

    if vm_mode:
        if shutil.which("vng") is None:
            raise SystemExit(
                f"{Color.wrap(Color.RED, 'ERROR:')} vng (virtme-ng) not found on PATH. "
                f"Install with 'pip install virtme-ng' or your distro package manager."
            )
        if kernel_path is None or not kernel_path.is_file():
            raise SystemExit(
                f"{Color.wrap(Color.RED, 'ERROR:')} --kernel must point at a readable "
                f"kernel image (got: {kernel_path})."
            )
        print(f"vm kernel: {kernel_path}")
        if shutil.which("cargo") is None:
            raise SystemExit(
                f"{Color.wrap(Color.RED, 'ERROR:')} cargo not found in PATH "
                f"(install happens on the host even in --vm mode)."
            )
        return

    if not Path("/sys/kernel/sched_ext").is_dir():
        raise SystemExit(
            f"{Color.wrap(Color.RED, 'ERROR:')} /sys/kernel/sched_ext missing. "
            f"Kernel lacks sched_ext support (need CONFIG_SCHED_CLASS_EXT=y, >=6.12)."
        )
    state = read_sched_ext_state()
    print(f"sched_ext: {state}")
    if state != "disabled":
        raise SystemExit(
            f"{Color.wrap(Color.RED, 'ERROR:')} sched_ext is already active "
            f"('{state}'). Disable it first."
        )
    if in_vm:
        # Inside the VM we're already root (vng default); no sudo needed.
        if os.geteuid() != 0:
            raise SystemExit(
                f"{Color.wrap(Color.RED, 'ERROR:')} --in-vm expected to run as root "
                f"inside the VM (got uid={os.geteuid()})."
            )
        return
    if subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0:
        raise SystemExit(
            f"{Color.wrap(Color.RED, 'ERROR:')} passwordless sudo required "
            f"(schedulers must run as root)."
        )
    if shutil.which("cargo") is None:
        raise SystemExit(
            f"{Color.wrap(Color.RED, 'ERROR:')} cargo not found in PATH."
        )


def read_sched_ext_state() -> str:
    try:
        return Path("/sys/kernel/sched_ext/state").read_text().strip()
    except OSError:
        return "unknown"


def wait_for_disabled(timeout_s: int = 10) -> bool:
    for _ in range(timeout_s):
        if read_sched_ext_state() == "disabled":
            return True
        time.sleep(1)
    return False


def binary_version_string(binary: Path) -> str:
    try:
        out = subprocess.run(
            [str(binary), "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        first = out.stdout.splitlines()[:1]
        return first[0] if first else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def try_cargo_install(crate: str, version: str, log_path: Path) -> bool:
    cmd = ["cargo", "install", "--locked", "--version", version, crate]
    with log_path.open("a") as fh:
        fh.write(f"\n$ {' '.join(shlex.quote(c) for c in cmd)}\n")
        fh.flush()
        rc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, check=False).returncode
    return rc == 0


def install_one(crate: dict[str, Any], ctx: RunContext) -> str | None:
    """Install crate at primary version; on failure fall back if allowed.

    Returns the installed version string, or None on hard failure.
    """
    name = crate["name"]
    primary = crate.get("version")
    fallback = crate.get("fallback_version")
    bin_path = Path.home() / ".cargo" / "bin" / name
    log_path = ctx.out_dir / f"{name}.install.log"
    log_path.write_text("")

    if primary is None:
        print(f"  {Color.wrap(Color.RED, 'no version pinned')} for {name}; skipping")
        return None

    # Already installed at one of the acceptable versions?
    if bin_path.is_file() and os.access(bin_path, os.X_OK):
        cur = binary_version_string(bin_path)
        if primary in cur:
            print(f"  already installed: {cur}")
            return primary
        if fallback and fallback in cur:
            print(f"  already installed (fallback): {cur}")
            return fallback
        print(f"  installed '{cur}' != {primary}, reinstalling")

    print(f"  installing {name} {primary}  (log: {log_path.relative_to(ctx.out_dir)})")
    if try_cargo_install(name, primary, log_path):
        return primary

    if ctx.use_fallback and fallback:
        print(f"  {Color.wrap(Color.YELLOW, f'primary install failed; trying fallback {fallback}')}")
        log_path.open("a").write(f"\n----- fallback to {fallback} -----\n")
        if try_cargo_install(name, fallback, log_path):
            return fallback

    print(f"  {Color.wrap(Color.RED, 'INSTALL FAILED')} — see {log_path}")
    return None


_PANIC_RE = re.compile(r"BPF program load failed|panicked at|FATAL|libbpf:.*error")


def run_one(crate: dict[str, Any], installed_version: str, ctx: RunContext,
            *, use_sudo: bool = True, bin_dir: Path | None = None) -> RunResult:
    """Run a single scheduler binary and classify the outcome.

    ``use_sudo``: prefix the timeout-wrapped command with ``sudo`` (bare-metal
    default). Inside the VM we already run as root, so the in-VM caller sets
    ``use_sudo=False``.

    ``bin_dir``: directory holding the cargo-installed scheduler binaries.
    Defaults to ``~/.cargo/bin``. Inside the VM ``$HOME`` is /run/tmp/roothome,
    so the host user's cargo bin must be passed explicitly.
    """
    name = crate["name"]
    bin_root = bin_dir if bin_dir is not None else Path.home() / ".cargo" / "bin"
    bin_path = bin_root / name
    out_log = ctx.out_dir / f"{name}.stdout.log"
    err_log = ctx.out_dir / f"{name}.stderr.log"

    if not bin_path.is_file():
        print(f"  {Color.wrap(Color.RED, 'binary missing:')} {bin_path}")
        return RunResult(name, "ERROR", None, 0, installed_version, "binary not installed")

    if not wait_for_disabled():
        pre = read_sched_ext_state()
        print(f"  {Color.wrap(Color.RED, 'SKIPPED:')} sched_ext stuck in '{pre}'")
        return RunResult(name, "ERROR", None, 0, installed_version,
                         f"sched_ext stuck in '{pre}' before run")

    fragile_reason = crate.get("fragile_reason") if crate.get("type") == "fragile" else None
    run_dur = (
        crate.get("fragile_duration_s") or DEFAULT_FRAGILE_DURATION_S
        if fragile_reason
        else ctx.duration_s
    )
    if fragile_reason:
        print(f"  {Color.wrap(Color.YELLOW, 'KNOWN_FRAGILE:')} {fragile_reason}")
        print(f"  running for {run_dur}s (reduced)")
    else:
        print(f"  running for {run_dur}s")

    extra = list(crate.get("extra_args") or [])
    if extra:
        print(f"  args: {' '.join(shlex.quote(a) for a in extra)}")

    prefix: list[str] = ["sudo"] if use_sudo else []
    cmd = [*prefix, "timeout", "--signal=TERM", "--kill-after=10", str(run_dur), str(bin_path), *extra]
    ctx.current_sched_bin = bin_path
    t0 = time.monotonic()
    try:
        with out_log.open("w") as outfh, err_log.open("w") as errfh:
            rc = subprocess.run(cmd, stdout=outfh, stderr=errfh, check=False).returncode
    finally:
        ctx.current_sched_bin = None
    runtime = int(time.monotonic() - t0)

    # Let sched_ext fully release before the next iteration.
    wait_for_disabled()

    # Classify. timeout(1): 124 = SIGTERM-on-timeout (= scheduler kept running
    # the full window, the PASS condition); 137 = SIGKILL escalation; 143 =
    # SIGTERM clean shutdown; 130 = SIGINT.
    status: str
    notes: str = ""
    if rc in (124, 137, 143):
        if runtime >= run_dur - 5:
            status = "PASS"
        else:
            status = "FAIL"
            notes = f"terminated early at {runtime}s (rc={rc})"
    elif rc == 0:
        if runtime >= run_dur - 5:
            status = "PASS"
            notes = "clean exit at full duration"
        else:
            status = "FAIL"
            notes = f"exited 0 early at {runtime}s"
    else:
        status = "FAIL"
        notes = f"exit rc={rc} at {runtime}s"

    # Panic / load-error surfacing regardless of exit code.
    try:
        err_text = err_log.read_text(errors="replace")
        if _PANIC_RE.search(err_text):
            tail = "stderr has panic/load-error pattern"
            notes = f"{notes}; {tail}" if notes else tail
            if status == "PASS":
                status = "FAIL"
    except OSError:
        pass

    if fragile_reason and status == "FAIL":
        notes = (notes + "; " if notes else "") + f"soft-passed: {fragile_reason}"
        status = "KNOWN_FRAGILE"

    pretty = Color.status(status)
    print(f"  -> {pretty} (rc={rc}, {runtime}s)")
    if notes:
        print(f"     {notes}")

    return RunResult(name, status, rc, runtime, installed_version, notes)


def write_summary_row(ctx: RunContext, r: RunResult) -> None:
    notes_safe = r.notes.replace("\t", " ")
    rc_str = "-" if r.exit_code is None else str(r.exit_code)
    runtime_str = "-" if r.runtime_s == 0 and r.exit_code is None else str(r.runtime_s)
    with ctx.summary_path.open("a") as fh:
        fh.write(
            f"{r.crate}\t{r.status}\t{rc_str}\t{runtime_str}\t"
            f"{r.installed_version or '-'}\t{notes_safe}\n"
        )


def print_summary(ctx: RunContext, manifest_version_label: str) -> None:
    print()
    bar = "═" * 71
    print(Color.wrap(Color.BLUE + Color.BOLD, bar))
    print(
        Color.wrap(Color.BOLD, "SCX SMOKE TEST SUMMARY")
        + f"  ({manifest_version_label}, {ctx.duration_s}s each)"
    )
    print(Color.wrap(Color.BLUE + Color.BOLD, bar))

    # Pretty-print the TSV with status colorization.
    rows = ctx.summary_path.read_text().splitlines()
    widths: list[int] = []
    parsed = [r.split("\t") for r in rows]
    for row in parsed:
        for i, cell in enumerate(row):
            if i >= len(widths):
                widths.append(len(cell))
            else:
                widths[i] = max(widths[i], len(cell))
    for row in parsed:
        out_cells = []
        for i, cell in enumerate(row):
            padded = cell.ljust(widths[i])
            if i == 1 and cell in {"PASS", "FAIL", "KNOWN_FRAGILE", "ERROR"}:
                padded = Color.status(cell) + padded[len(cell):]
            out_cells.append(padded)
        print("  ".join(out_cells))

    counts = {"PASS": 0, "FAIL": 0, "KNOWN_FRAGILE": 0, "ERROR": 0}
    for r in ctx.results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print(Color.wrap(Color.DIM, "-" * 71))
    print(
        f"{Color.status('PASS')}: {counts['PASS']}   "
        f"{Color.status('FAIL')}: {counts['FAIL']}   "
        f"{Color.status('KNOWN_FRAGILE')}: {counts['KNOWN_FRAGILE']}   "
        f"{Color.status('ERROR')}: {counts['ERROR']}"
    )
    print(f"logs: {ctx.out_dir}")


# ---------------------------------------------------------------------------
# VM mode: install on host, then re-exec inside vng for the actual run pass.
# ---------------------------------------------------------------------------


def detect_vm_kernel_release(kernel_path: Path) -> str:
    """Pull the kernel version string out of a bzImage with ``file(1)``.

    Returns the empty string on failure. Used purely for the run dir name +
    summary header — the actual uname inside the VM is the source of truth.
    """
    try:
        out = subprocess.run(
            ["file", str(kernel_path)], capture_output=True, text=True,
            timeout=5, check=False,
        ).stdout
        m = re.search(r"version (\S+)", out)
        return m.group(1) if m else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def launch_in_vm(
    crates: list[dict[str, Any]],
    ctx: RunContext,
    kernel_path: Path,
    vng_extra: list[str],
) -> int:
    """Boot ``vng`` once, re-exec this script inside it with ``--in-vm``.

    The output directory is mounted RW into the VM via ``--rwdir`` so the
    in-VM run pass can write per-crate logs and SUMMARY.tsv that persist on
    the host. The host user's cargo bin path is passed explicitly so the
    in-VM script knows where to find the pre-installed scheduler binaries
    (it can't rely on ``~/.cargo`` because vng resets HOME to
    /run/tmp/roothome).
    """
    # Selected schedulers, by name; the in-VM invocation reads the same
    # manifest the host wrote into ``out_dir`` and applies the same filter.
    selected = " ".join(c["name"] for c in crates)
    host_cargo_bin = (Path.home() / ".cargo" / "bin").resolve()

    inner_cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        # global flags must come BEFORE the subcommand name.
        "--no-color",
        "run",
        "--in-vm",
        "--manifest", str((ctx.out_dir / "manifest.json").resolve()),
        "--out-dir", str(ctx.out_dir.resolve()),
        "--duration", str(ctx.duration_s),
        "--schedulers", selected,
        "--bin-dir", str(host_cargo_bin),
    ]
    inner_str = " ".join(shlex.quote(s) for s in inner_cmd)

    vng_cmd = [
        "vng",
        "--run", str(kernel_path),
        "--rwdir", str(ctx.out_dir.resolve()),
        *vng_extra,
        "--exec", inner_str,
    ]
    Color.section(f"vm phase (vng → {kernel_path.name})")
    print("  $ " + " ".join(shlex.quote(c) for c in vng_cmd))
    proc = subprocess.run(vng_cmd, check=False)
    return proc.returncode


# ---------------------------------------------------------------------------
# Cleanup trap — make sure no scheduler is left attached on Ctrl+C / abort.
# ---------------------------------------------------------------------------


def install_cleanup_trap(ctx: RunContext) -> None:
    def cleanup(*_: Any) -> None:
        bin_path = ctx.current_sched_bin
        if bin_path is not None:
            print()
            print(
                Color.wrap(Color.YELLOW, "cleanup:")
                + f" stopping leftover {bin_path.name}",
                file=sys.stderr,
            )
            subprocess.run(["sudo", "pkill", "-TERM", "-f", f"^{bin_path}"],
                           check=False)
            time.sleep(2)
            subprocess.run(["sudo", "pkill", "-KILL", "-f", f"^{bin_path}"],
                           check=False)
        wait_for_disabled()

    def handler(signum: int, _frame: Any) -> None:
        cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    import atexit
    atexit.register(cleanup)


# ---------------------------------------------------------------------------
# CLI sub-commands
# ---------------------------------------------------------------------------


def cmd_discover(args: argparse.Namespace) -> int:
    scx_root = Path(args.scx_root).resolve() if args.scx_root else find_scx_root(SCRIPT_DIR)
    manifest = discover_manifest(
        scx_root,
        pinned_version=args.version,
        use_network=not args.no_network,
    )
    text = json.dumps(manifest, indent=2) + "\n"
    if args.out is None or args.out == "-":
        sys.stdout.write(text)
    else:
        Path(args.out).write_text(text)
        print(f"manifest: {args.out}  ({len(manifest['crates'])} crates)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text())
    else:
        scx_root = find_scx_root(SCRIPT_DIR)
        manifest = discover_manifest(scx_root, use_network=not args.no_network)
    print(Color.wrap(Color.BOLD, f"scx schedulers ({len(manifest['crates'])}):"))
    for c in manifest["crates"]:
        marks: list[str] = []
        if c.get("fallback_version"):
            marks.append(Color.wrap(Color.DIM, f"fallback: {c['fallback_version']}"))
        if c.get("extra_args"):
            marks.append(Color.wrap(Color.DIM, f"args: {' '.join(c['extra_args'])}"))
        if c.get("type") == "fragile":
            marks.append(Color.wrap(Color.YELLOW, "KNOWN_FRAGILE"))
        if not c.get("published", True):
            marks.append(Color.wrap(Color.DIM, "UNPUBLISHED"))
        suffix = ("  " + "  ".join(marks)) if marks else ""
        print(f"  {c['name']}  v{c.get('version', '?')}{suffix}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    # Phase 1: obtain manifest.
    if args.manifest:
        manifest_path = Path(args.manifest)
        manifest = json.loads(manifest_path.read_text())
        manifest_source = f"loaded from {manifest_path}"
    else:
        scx_root = Path(args.scx_root).resolve() if args.scx_root else find_scx_root(SCRIPT_DIR)
        manifest = discover_manifest(scx_root, pinned_version=args.version)
        manifest_source = "discovered from workspace + crates.io"

    # Optional --schedulers filter (whitelist by name).
    crates: list[dict[str, Any]] = list(manifest["crates"])
    if args.schedulers:
        wanted = set(args.schedulers.split())
        crates = [c for c in crates if c["name"] in wanted]
    # Skip unpublished crates unless they were explicitly included via --schedulers.
    if not args.schedulers:
        crates = [c for c in crates if c.get("published", True)]

    if not crates:
        print(f"{Color.wrap(Color.RED, 'no crates to run')} after filtering manifest", file=sys.stderr)
        return 2

    duration = args.duration if args.duration is not None else manifest.get("default_duration_s", DEFAULT_DURATION_S)

    # --- in-VM path (re-exec'd inside vng by the host launcher) -----------
    if args.in_vm:
        Color.section("pre-flight (in-VM)")
        print(f"manifest:  {manifest_source}")
        preflight(in_vm=True)
        out_dir = Path(args.out_dir) if args.out_dir else Path.cwd()
        out_dir.mkdir(parents=True, exist_ok=True)
        # The host-launcher already wrote a SUMMARY.tsv header; append to it
        # so the host invocation sees a single canonical file. Truncate only
        # if it's missing (defensive).
        summary = out_dir / "SUMMARY.tsv"
        if not summary.exists():
            summary.write_text("scheduler\tstatus\texit_code\truntime_s\tinstalled_version\tnotes\n")
        print(f"out_dir:   {out_dir}")
        print(f"duration:  {duration}s")
        print(f"crates ({len(crates)}): {' '.join(c['name'] for c in crates)}")
        ctx = RunContext(out_dir=out_dir, duration_s=duration,
                         use_fallback=False, summary_path=summary)
        # No cleanup trap inside the VM — the VM tears down on exec exit.
        bin_dir = Path(args.bin_dir) if args.bin_dir else Path.home() / ".cargo" / "bin"
        for idx, crate in enumerate(crates, 1):
            Color.section(f"[{idx}/{len(crates)}] {crate['name']}")
            installed = crate.get("version", "?")
            r = run_one(crate, installed, ctx, use_sudo=False, bin_dir=bin_dir)
            ctx.results.append(r)
            write_summary_row(ctx, r)
        # Don't print the host-style summary box — the host launcher will
        # render the final table after vng returns.
        bad = any(r.status in ("FAIL", "ERROR") for r in ctx.results)
        return 1 if bad else 0

    # --- host path (bare-metal OR vm-mode launcher) -----------------------
    kernel_path: Path | None = None
    if args.vm:
        if not args.kernel:
            print(f"{Color.wrap(Color.RED, '--vm requires --kernel PATH')}", file=sys.stderr)
            return 2
        kernel_path = Path(args.kernel).resolve()

    Color.section("pre-flight")
    print(f"manifest:  {manifest_source}")
    preflight(vm_mode=bool(args.vm), kernel_path=kernel_path)

    # Output dir. Include kernel release label in --vm mode so reruns against
    # different kernels don't collide.
    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        label = args.version or _label_for_manifest(crates)
        if args.vm and kernel_path is not None:
            release = detect_vm_kernel_release(kernel_path) or kernel_path.stem
            out_dir = Path(f"./scx-smoke-{label}-vm-{release}-{stamp}")
        else:
            out_dir = Path(f"./scx-smoke-{label}-{stamp}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = out_dir / "SUMMARY.tsv"
    summary.write_text("scheduler\tstatus\texit_code\truntime_s\tinstalled_version\tnotes\n")
    # Copy the effective manifest into the run directory for provenance.
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"out_dir:   {out_dir}")
    print(f"duration:  {duration}s  (KNOWN_FRAGILE crates use their per-crate duration)")
    print(f"crates ({len(crates)}): {' '.join(c['name'] for c in crates)}")
    if args.vm:
        print(f"mode:      VM (vng) — install on host, run inside vng({kernel_path})")

    ctx = RunContext(
        out_dir=out_dir,
        duration_s=duration,
        use_fallback=not args.no_fallback,
        summary_path=summary,
    )
    install_cleanup_trap(ctx)

    if args.vm:
        # Phase 2a: install on host. Skip published=false crates only if the
        # user did not whitelist them via --schedulers (already filtered above).
        Color.section("install phase (host)")
        installed_map: dict[str, str | None] = {}
        for idx, crate in enumerate(crates, 1):
            print(f"  [{idx}/{len(crates)}] {crate['name']}")
            installed_map[crate["name"]] = install_one(crate, ctx)

        # Record ERROR rows on host for any install failure; subset crates list
        # passed to VM to those that have a binary.
        runnable: list[dict[str, Any]] = []
        for crate in crates:
            v = installed_map[crate["name"]]
            if v is None:
                r = RunResult(
                    crate["name"], "ERROR", None, 0, "",
                    notes=f"cargo install failed (primary={crate.get('version')}"
                          + (f", fallback={crate.get('fallback_version')}" if crate.get('fallback_version') else "")
                          + ")",
                )
                ctx.results.append(r)
                write_summary_row(ctx, r)
            else:
                runnable.append(crate)

        # Phase 2b: launch vng with --in-vm re-exec.
        assert kernel_path is not None  # vm_mode preflight already validated
        rc = launch_in_vm(runnable, ctx, kernel_path, vng_extra=args.vng_arg or [])
        Color.section(f"vng exited rc={rc}")
        # Read back the SUMMARY.tsv rows that the in-VM pass wrote and
        # rebuild ctx.results so the host summary box renders.
        ctx.results = _reload_results_from_summary(ctx)
    else:
        # Phase 2 main loop (bare-metal): interleave install + run per crate.
        for idx, crate in enumerate(crates, 1):
            Color.section(f"[{idx}/{len(crates)}] {crate['name']}")
            installed = install_one(crate, ctx)
            if installed is None:
                r = RunResult(crate["name"], "ERROR", None, 0, "",
                              notes=f"cargo install failed (primary={crate.get('version')}"
                                    + (f", fallback={crate.get('fallback_version')}" if crate.get('fallback_version') else "")
                                    + ")")
                ctx.results.append(r)
                write_summary_row(ctx, r)
                continue
            r = run_one(crate, installed, ctx)
            ctx.results.append(r)
            write_summary_row(ctx, r)

    label = args.version or _label_for_manifest(crates)
    label_with_mode = f"v{label}" + (f", vm:{kernel_path.name}" if args.vm and kernel_path else "")
    print_summary(ctx, manifest_version_label=label_with_mode)

    # Exit non-zero only on real FAIL or ERROR. KNOWN_FRAGILE is soft-pass.
    bad = any(r.status in ("FAIL", "ERROR") for r in ctx.results)
    return 1 if bad else 0


def _reload_results_from_summary(ctx: RunContext) -> list[RunResult]:
    """After the VM in-VM pass appends rows, re-parse SUMMARY.tsv.

    Used to render the host-side final summary box.
    """
    out: list[RunResult] = []
    for line in ctx.summary_path.read_text().splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 6:
            continue
        name, status, rc_s, rt_s, ver, *rest = fields
        try:
            rc = int(rc_s) if rc_s != "-" else None
        except ValueError:
            rc = None
        try:
            rt = int(rt_s) if rt_s != "-" else 0
        except ValueError:
            rt = 0
        out.append(RunResult(name, status, rc, rt, ver, "\t".join(rest)))
    return out


def _label_for_manifest(crates: list[dict[str, Any]]) -> str:
    """Best-effort single-version label (e.g. "1.1.1") for naming."""
    versions = {c.get("version") for c in crates if c.get("version")}
    if len(versions) == 1:
        return next(iter(versions))
    return "mixed"


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scx_smoke_test.py",
        description="Two-phase scx scheduler release-validation harness.",
    )
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="emit a JSON manifest of scx scheduler crates")
    d.add_argument("--out", "-o", default="-",
                   help="output path for manifest, or '-' for stdout (default: stdout)")
    d.add_argument("--version", default=None,
                   help=f"override discovered version with VER for every crate "
                        f"(default: latest stable per crate; or '{DEFAULT_VERSION}' "
                        f"if --no-network is used)")
    d.add_argument("--scx-root", default=None,
                   help="path to scx workspace root (default: auto-detect from script location)")
    d.add_argument("--no-network", action="store_true",
                   help="skip crates.io API and use --version (or DEFAULT_VERSION) verbatim")

    r = sub.add_parser("run", help="install + run schedulers per manifest")
    r.add_argument("--manifest", default=None,
                   help="use this JSON manifest verbatim (skip Phase 1 discovery)")
    r.add_argument("--duration", type=int, default=None,
                   help=f"per-scheduler run window in seconds "
                        f"(default: manifest.default_duration_s={DEFAULT_DURATION_S})")
    r.add_argument("--out-dir", default=None,
                   help="output directory (default: ./scx-smoke-<ver>-<stamp>)")
    r.add_argument("--schedulers", default=None,
                   help="space-separated whitelist of scheduler names to run")
    r.add_argument("--version", default=None,
                   help="pin every crate to VER when discovering on the fly "
                        "(no effect when --manifest is given)")
    r.add_argument("--scx-root", default=None,
                   help="scx workspace root for on-the-fly discovery")
    r.add_argument("--no-fallback", action="store_true",
                   help="disable per-crate fallback-version retries")
    r.add_argument("--vm", action="store_true",
                   help="run schedulers inside a vng (virtme-ng) VM instead of "
                        "directly on the host (install still happens on host)")
    r.add_argument("--kernel", default=None,
                   help="path to a kernel image (bzImage / vmlinuz-*) for --vm mode")
    r.add_argument("--vng-arg", action="append", default=None,
                   help="additional flag to pass to `vng` (repeatable, e.g. "
                        "--vng-arg --memory --vng-arg 4G)")
    # Hidden self-invocation flags used by --vm to re-exec inside the VM.
    r.add_argument("--in-vm", action="store_true",
                   help=argparse.SUPPRESS)
    r.add_argument("--bin-dir", default=None,
                   help=argparse.SUPPRESS)

    lst = sub.add_parser("list", help="print the manifest in human form")
    lst.add_argument("--manifest", default=None,
                     help="read this manifest instead of discovering")
    lst.add_argument("--no-network", action="store_true",
                     help="when discovering on the fly, skip crates.io")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    Color.configure("never" if args.no_color else "auto")
    if args.cmd == "discover":
        return cmd_discover(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "run":
        return cmd_run(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
