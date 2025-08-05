#!/usr/bin/env python3

import argparse
import asyncio
import glob
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional


async def run_command(
    cmd: List[str], cwd: Optional[str] = None, no_capture: bool = False
) -> Optional[str]:
    print(f"Running: {' '.join(cmd)}", flush=True)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=None if no_capture else asyncio.subprocess.PIPE,
        stderr=None if no_capture else asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        if stderr:
            print(
                f"Command failed with stderr: {stderr.decode()}",
                file=sys.stderr,
                flush=True,
            )
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, output=stdout, stderr=stderr
        )

    return stdout.decode() if stdout else None


async def get_kernel_path(kernel_name: str) -> str:
    """Get the kernel path from Nix store for the given kernel name."""
    stdout = await run_command(
        [
            "nix",
            "build",
            "--no-link",
            "--print-out-paths",
            f"./.github/include#kernel_{kernel_name}",
        ]
    )
    return stdout.strip() + "/bzImage"


async def run_command_in_vm(
    kernel: str,
    command: List[str],
    memory: int = 1024 * 1024 * 1024,
    cpus: int = 2,
    no_capture: bool = False,
) -> Optional[str]:
    mem_mb = int(memory / 1024 / 1024)

    cmd = [
        "vng",
        "-r",
        await get_kernel_path(kernel),
        "--memory",
        f"{mem_mb}M",
        "--cpus",
        str(cpus),
    ]
    if os.environ.get("CI") == "true":
        # verbose in CI but not locally
        cmd += ["-v"]

        # CI runs in /var/cache/private which fails the usual cwd stuff. mount
        # it elsewhere and use that as the root.
        cmd += [
            "--overlay-rwdir=/tmp",
            "--rodir=/tmp/workspace=.",
            "--cwd=/tmp/workspace",
        ]

    # virtme-ng passes the commands on the kernel command line which has a short
    # maximum length. write all commands to a shell script and run that instead,
    # allowing us to bypass this restriction.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh") as file:
        # VM gets a different PATH to this program so fix the path of the binary.
        # Other args left to the caller.
        arg0 = shutil.which(command[0])
        cmd_quoted = " ".join(shlex.quote(arg) for arg in [arg0] + command[1:])

        file.write(f"exec {cmd_quoted}\n")
        file.flush()

        cmd += ["--", shutil.which("bash"), file.name]
        return await run_command(cmd, no_capture=no_capture)


async def get_clippy_packages() -> List[str]:
    """Get list of packages that should be linted with clippy."""
    stdout = await run_command(["cargo", "metadata", "--format-version", "1"])
    metadata = json.loads(stdout)

    clippy_packages = []
    for pkg in metadata.get("packages", []):
        pkg_metadata = pkg.get("metadata")
        if pkg_metadata:
            scx_metadata = pkg_metadata.get("scx")
            if scx_metadata and scx_metadata.get("ci", {}).get("use_clippy") == True:
                clippy_packages.append(pkg["name"])

    return clippy_packages


async def run_format():
    """Format all targets."""
    print("Running format...", flush=True)

    py_files = glob.glob(".github/include/**/*.py", recursive=True)
    if py_files:
        await run_command(["black"] + py_files, no_capture=True)
        await run_command(["isort"] + py_files, no_capture=True)

    await run_command(["cargo", "fmt"], no_capture=True)

    nix_files = glob.glob("**/*.nix", root_dir=".github/include/", recursive=True)
    if nix_files:
        await run_command(
            ["nix", "--extra-experimental-features", "nix-command flakes", "fmt"]
            + nix_files,
            cwd=".github/include",
            no_capture=True,
        )

    await run_command(["git", "diff", "--exit-code"], no_capture=True)
    print("✓ Format completed successfully", flush=True)


async def run_build():
    """Build all targets."""
    print("Running build...", flush=True)

    await run_command(["cargo", "build", "--all-targets", "--locked"], no_capture=True)
    print("✓ Build completed successfully", flush=True)


async def run_clippy():
    """Run clippy on packages marked for CI linting."""
    print("Running clippy...", flush=True)

    clippy_packages = await get_clippy_packages()
    for package in clippy_packages:
        await run_command(
            ["cargo", "clippy", "--no-deps", "-p", package, "--", "-Dwarnings"],
            no_capture=True,
        )

    print("✓ Clippy checks passed", flush=True)


async def run_tests():
    """Run the test suite."""
    print("Running tests...", flush=True)

    await run_command(
        [
            "cargo",
            "nextest",
            "archive",
            "--archive-file",
            "target/nextest-archive.tar.zst",
        ],
        no_capture=True,
    )

    # Get CPU count
    cpu_count = min(os.cpu_count(), 16)

    await run_command_in_vm(
        "sched_ext/for-next",
        [
            sys.argv[0],
            "test-in-vm",
        ],
        memory=10 * 1024 * 1024 * 1024,
        cpus=min(os.cpu_count(), 16),
        no_capture=True,
    )

    print("✓ Tests completed successfully", flush=True)


def run_tests_in_vm():
    """Run tests when already inside the VM."""

    subprocess.run(
        [
            "cargo-nextest",
            "nextest",
            "run",
            "--archive-file",
            "target/nextest-archive.tar.zst",
            "--workspace-remap",
            ".",
            "--no-fail-fast",
        ],
        check=True,
    )

    subprocess.run(["target/debug/scx_lib_selftests"], check=True)


async def run_all():
    """Run all CI steps in the correct order."""
    await run_format()
    await run_build()
    await run_clippy()
    await run_tests()


async def main():
    parser = argparse.ArgumentParser(description="SCX CI Script")

    subparsers = parser.add_subparsers(
        dest="command", description="Command to run (default: all)"
    )
    subparsers.required = True

    parser_format = subparsers.add_parser("format", help="Perform formatting checks")
    parser_build = subparsers.add_parser("build", help="Build Rust crates")
    parser_clippy = subparsers.add_parser(
        "clippy", help="Run Clippy on crates that request it"
    )
    parser_test = subparsers.add_parser("test", help="Run Rust tests")

    parser_all = subparsers.add_parser("all", help="Run all commands")

    parser_test_in_vm = subparsers.add_parser(
        "test-in-vm",
        help="Run Rust tests in VM (intended to be invoked by this script)",
    )

    args = parser.parse_args()

    if args.command == "format":
        await run_format()
    elif args.command == "build":
        await run_build()
    elif args.command == "clippy":
        await run_clippy()
    elif args.command == "test":
        await run_tests()
    elif args.command == "test-in-vm":
        run_tests_in_vm()
    elif args.command == "all":
        await run_all()


if __name__ == "__main__":
    asyncio.run(main())
