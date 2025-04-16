#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
from typing import List, Optional
import random


def run_command(
    cmd: List[str], check: bool = True, env: Optional[dict] = None
) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}", flush=True)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(cmd, check=check, env=merged_env)


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


def test_binary_has_tests(binary_path: str) -> bool:
    """Test whether a test binary contains any tests."""
    result = subprocess.run(
        [binary_path, "--list"],
        check=True,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip() != "0 tests, 0 benchmarks"


def run_format():
    """Format all targets."""
    print("Running format...", flush=True)

    run_command(["cargo", "fmt"])
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
        ["cargo", "test", "--no-run", "--message-format", "json"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
    )
    cargo_results = [
        json.loads(line) for line in result.stdout.splitlines() if line.strip()
    ]
    test_binaries = [
        x["executable"]
        for x in cargo_results
        if x["reason"] == "compiler-artifact"
        if x["profile"].get("test", False)
        if x["executable"] is not None
    ]

    test_binaries = [x for x in test_binaries if test_binary_has_tests(x)]
    random.shuffle(test_binaries)

    # If vng needs to traverse a path that's inaccessible to the user (like
    # /var/cache/private/...) it can't run these binaries with their absolute
    # paths. Make them relative to CWD to solve this.
    test_binaries = [os.path.relpath(x) for x in test_binaries]

    # Get CPU count
    cpu_count = min(os.cpu_count(), 8)

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
    cmd += test_binaries

    # Run tests in VM
    run_command(cmd)

    print("✓ Tests completed successfully", flush=True)


def run_tests_in_vm(test_bins):
    """Run tests when already inside the VM."""

    for cmd in test_bins:
        run_command([cmd])


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
    parser_test_in_vm.add_argument(
        "test_bins", nargs="*", help="Test binaries to execute in order"
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
        run_tests_in_vm(args.test_bins)
    elif args.command == "all":
        run_all()


if __name__ == "__main__":
    main()
