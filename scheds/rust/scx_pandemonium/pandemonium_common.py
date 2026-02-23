"""
Shared infrastructure for PANDEMONIUM build/test scripts.

Used by pandemonium.py (build manager) and tests/pandemonium-tests.py (test orchestrator).
"""

import glob
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


# CONFIGURATION

SCRIPT_DIR = Path(__file__).parent.resolve()
TARGET_DIR = Path("/tmp/pandemonium-build")
LOG_DIR = Path("/tmp/pandemonium")
ARCHIVE_DIR = Path.home() / ".cache" / "pandemonium"
BINARY = TARGET_DIR / "release" / "pandemonium"
VMLINUX_CACHE = ARCHIVE_DIR / "vmlinux.h"
MIN_KERNEL = (6, 12)

SOURCE_PATTERNS = [
    "src/**/*.rs", "src/**/*.c", "src/**/*.h",
    "tests/**/*.rs",
    "Cargo.toml", "build.rs",
]


def get_version() -> str:
    """Read version from Cargo.toml."""
    try:
        for line in (SCRIPT_DIR / "Cargo.toml").read_text().splitlines():
            if line.startswith("version"):
                return line.split('"')[1]
    except (FileNotFoundError, IndexError):
        pass
    return "?.?.?"


def get_git_info() -> dict:
    """Return git commit hash and dirty status."""
    info = {"commit": "unknown", "dirty": False}
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=SCRIPT_DIR,
        )
        if r.returncode == 0:
            info["commit"] = r.stdout.strip()
        r = subprocess.run(
            ["git", "diff", "--quiet", "HEAD"],
            capture_output=True, cwd=SCRIPT_DIR,
        )
        info["dirty"] = r.returncode != 0
    except FileNotFoundError:
        pass
    return info


# =============================================================================
# LOGGING
# =============================================================================

def _timestamp() -> str:
    return datetime.now().strftime("[%H:%M:%S]")


def log_info(msg: str) -> None:
    print(f"{_timestamp()} [INFO]   {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"{_timestamp()} [WARN]   {msg}", flush=True)


def log_error(msg: str) -> None:
    print(f"{_timestamp()} [ERROR]  {msg}", flush=True)


def run_cmd(cmd: list, cwd: Path | None = None,
            env: dict | None = None) -> int:
    """Run a command with real-time output to terminal."""
    print(f">>> {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, cwd=cwd, env=env)
    return result.returncode


def run_cmd_capture(cmd: list, cwd: Path | None = None,
                    env: dict | None = None) -> tuple[int, str, str]:
    """Run a command and capture output."""
    result = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=cwd, env=env)
    return result.returncode, result.stdout, result.stderr


# =============================================================================
# BUILD
# =============================================================================

def has_root_owned_files() -> bool:
    """Check if sudo left root-owned files anywhere in the build tree."""
    if not TARGET_DIR.exists():
        return False
    result = subprocess.run(
        ["find", str(TARGET_DIR), "-user", "root", "-maxdepth", "4",
         "-print", "-quit"],
        capture_output=True, text=True,
    )
    return bool(result.stdout.strip())


def clean_root_files() -> bool:
    """Prompt and nuke root-owned build artifacts. Returns True if resolved."""
    log_warn(f"Root-owned build files detected in {TARGET_DIR}")
    resp = input("CLEAN ENTIRE BUILD DIR? [Y/N] ").strip().lower()
    if resp == "y":
        log_info("Cleaning build directory...")
        run_cmd(["sudo", "rm", "-rf", str(TARGET_DIR)])
        log_info("Build directory cleaned")
        return True
    log_error("Cannot build with root-owned files, aborting")
    return False


def check_sources_changed() -> list[str]:
    """Return list of source files newer than the binary (empty = up to date)."""
    if not BINARY.exists():
        return ["(binary not found)"]
    bin_mtime = BINARY.stat().st_mtime
    changed = []
    for pattern in SOURCE_PATTERNS:
        for src in SCRIPT_DIR.glob(pattern):
            if src.stat().st_mtime > bin_mtime:
                changed.append(str(src.relative_to(SCRIPT_DIR)))
    return changed


def check_kernel_version() -> bool:
    """Verify kernel >= 6.12 (sched_ext requirement). Returns True if OK."""
    release = platform.release()
    try:
        parts = release.split(".")
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        log_error(f"Cannot parse kernel version from '{release}'")
        return False
    if (major, minor) < MIN_KERNEL:
        log_error(f"Kernel {major}.{minor} is too old. PANDEMONIUM requires {MIN_KERNEL[0]}.{MIN_KERNEL[1]}+.")
        log_error("sched_ext (CONFIG_SCHED_CLASS_EXT) was merged in Linux 6.12.")
        log_error("Upgrade your kernel to use PANDEMONIUM.")
        return False
    log_info(f"Kernel {release} OK (>= {MIN_KERNEL[0]}.{MIN_KERNEL[1]})")
    return True


def ensure_vmlinux_h() -> bool:
    """Check vmlinux.h cache. Generated by bpftool on first build if missing."""
    if VMLINUX_CACHE.exists() and VMLINUX_CACHE.stat().st_size > 1000:
        log_info(f"vmlinux.h cached ({VMLINUX_CACHE.stat().st_size // 1024} KB)")
        return True
    log_info("vmlinux.h not cached (bpftool will generate on first build)")
    return True


def build(force: bool = False) -> bool:
    """Build PANDEMONIUM release binary. Returns True on success."""
    if not check_kernel_version():
        return False
    if not ensure_vmlinux_h():
        return False

    if has_root_owned_files():
        if not clean_root_files():
            return False

    if not force:
        changed = check_sources_changed()
        if not changed:
            size = BINARY.stat().st_size // 1024
            log_info(f"Binary up to date ({size} KB), skipping build")
            return True
        if changed[0] != "(binary not found)":
            log_info(f"Source changes detected ({len(changed)} file(s))")
        else:
            log_info("No existing binary, full build required")

    if force:
        log_info("Forced rebuild, cleaning package + BPF artifacts...")
        subprocess.run(
            ["cargo", "clean", "-p", "pandemonium"],
            env={**os.environ, "CARGO_TARGET_DIR": str(TARGET_DIR)},
            cwd=str(SCRIPT_DIR),
            capture_output=True,
        )
        # NUKE BPF BUILD SCRIPT OUTPUT SO SKELETON GETS REGENERATED.
        # cargo clean -p only removes Rust artifacts, not OUT_DIR.
        for d in glob.glob(str(TARGET_DIR / "release" / "build" / "pandemonium-*")):
            shutil.rmtree(d, ignore_errors=True)

    log_info("Building (release)...")
    ret = run_cmd(
        ["cargo", "build", "--release"],
        env={**os.environ, "CARGO_TARGET_DIR": str(TARGET_DIR)},
        cwd=SCRIPT_DIR,
    )

    if ret != 0:
        log_error("Build failed!")
        return False

    if BINARY.exists():
        size = BINARY.stat().st_size // 1024
        log_info(f"Build complete: {BINARY} ({size} KB)")
    return True
