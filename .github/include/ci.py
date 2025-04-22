#!/usr/bin/env python3

import argparse
import json
import os
import random
import subprocess
import sys
from typing import List, Optional


def run_command(
    cmd: List[str],
    check: bool = True,
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}", flush=True)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(cmd, check=check, env=merged_env, cwd=cwd)


def get_clippy_packages() -> List[str]:
    """Get list of packages that should be linted with clippy."""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)

    clippy_packages = []
    for pkg in metadata.get("packages", []):
        pkg_metadata = pkg.get("metadata")
        if pkg_metadata:
            scx_metadata = pkg_metadata.get("scx")
            if scx_metadata and scx_metadata.get("ci", {}).get("use_clippy") == True:
                clippy_packages.append(pkg["name"])

    return clippy_packages


def run_format():
    """Format all targets."""
    print("Running format...", flush=True)

    run_command(["black", ".github/include/ci.py"])
    run_command(["isort", ".github/include/ci.py"])

    run_command(["cargo", "fmt"])

    run_command(["nix", "fmt"], cwd=".github/include")

    run_command(["git", "diff", "--exit-code"])
    print("✓ Format completed successfully", flush=True)


def run_build():
    """Build all targets."""
    print("Running build...", flush=True)

    run_command(["cargo", "build", "--all-targets"])
    print("✓ Build completed successfully", flush=True)


def run_clippy():
    """Run clippy on packages marked for CI linting."""
    print("Running clippy...", flush=True)

    clippy_packages = get_clippy_packages()
    for package in clippy_packages:
        run_command(["cargo", "clippy", "--no-deps", "-p", package, "--", "-Dwarnings"])

    print("✓ Clippy checks passed", flush=True)


def run_tests():
    """Run the test suite."""
    print("Running tests...", flush=True)

    result = subprocess.run(
        [
            "cargo",
            "nextest",
            "archive",
            "--archive-file",
            "target/nextest-archive.tar.zst",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
    )

    # Get CPU count
    cpu_count = min(os.cpu_count(), 16)

    # Find kernel image
    kernel_path = "linux/arch/x86/boot/bzImage"
    if not os.path.exists(kernel_path):
        print(f"Error: Kernel image not found at {kernel_path}")
        print("Make sure to run the build-kernel job first")
        sys.exit(1)

    cmd = [
        "vng",
        "--memory",
        "10G",
        "--cpu",
        str(cpu_count),
        "-r",
        kernel_path,
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

    cmd += [
        "--",
        sys.argv[0],
        "test-in-vm",
    ]

    # Run tests in VM
    run_command(cmd)

    print("✓ Tests completed successfully", flush=True)


def run_tests_in_vm():
    """Run tests when already inside the VM."""

    run_command(
        [
            "cargo-nextest",
            "nextest",
            "run",
            "--archive-file",
            "target/nextest-archive.tar.zst",
            "--workspace-remap",
            ".",
            "--no-fail-fast",
        ]
    )


def run_all():
    """Run all CI steps in the correct order."""
    run_format()
    run_build()
    run_clippy()
    run_tests()


def main():
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
        run_format()
    elif args.command == "build":
        run_build()
    elif args.command == "clippy":
        run_clippy()
    elif args.command == "test":
        run_tests()
    elif args.command == "test-in-vm":
        run_tests_in_vm()
    elif args.command == "all":
        run_all()


if __name__ == "__main__":
    main()
