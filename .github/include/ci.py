#!/usr/bin/env python3

import argparse
import asyncio
import csv
import fnmatch
import glob
import io
import itertools
import json
import os
import random
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional


def rglob_no_symlinks(pattern):
    for base, dirs, files in os.walk(".", followlinks=False):
        for name in files:
            path = os.path.join(base, name)
            # skip symlinked files too (optional)
            if not os.path.islink(path):
                # Convert to relative path and normalize separators
                rel_path = os.path.relpath(path, ".")
                # Match against the full relative path using fnmatch
                if fnmatch.fnmatch(rel_path, pattern):
                    yield rel_path


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
            f"./.nix#kernel_{kernel_name}",
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


def parse_scheduler_kernel_requirements(
    scheduler_metadata: dict, default_kernel: str = "sched_ext/for-next"
) -> dict:
    """Parse kernel requirements from scheduler metadata."""
    kernel_config = scheduler_metadata.get("ci", {}).get("kernel", {})

    return {
        "default": kernel_config.get("default", default_kernel),
        "allowlist": kernel_config.get("allowlist", []),
        "blocklist": kernel_config.get("blocklist", []),
    }


def get_available_kernels() -> List[str]:
    """Get list of available kernels from kernel-versions.json."""
    with open("kernel-versions.json", "r") as f:
        kernel_data = json.load(f)
    return list(kernel_data.keys())


async def generate_scheduler_kernel_matrix(
    default_kernel: str = "sched_ext/for-next",
) -> List[dict]:
    schedulers = await get_scheduler_packages()
    available_kernels = get_available_kernels()

    matrix = []

    for scheduler in schedulers:
        kernel_reqs = parse_scheduler_kernel_requirements(
            scheduler["metadata"], default_kernel
        )

        for kernel in available_kernels:
            if kernel in kernel_reqs["blocklist"]:
                continue

            # For non-default kernels, check allowlist if it exists
            if kernel != kernel_reqs["default"] and kernel_reqs["allowlist"]:
                if kernel not in kernel_reqs["allowlist"]:
                    continue

            matrix.append(
                {
                    "scheduler": scheduler["name"],
                    "kernel": kernel,
                    "disable_veristat": scheduler["metadata"]
                    .get("ci", {})
                    .get("disable_veristat", False),
                }
            )

    return matrix


async def get_scheduler_packages() -> List[dict]:
    """Get list of scheduler packages from cargo metadata."""
    stdout = await run_command(["cargo", "metadata", "--format-version", "1"])
    metadata = json.loads(stdout)

    schedulers = []
    for pkg in metadata.get("packages", []):
        # Look for schedulers in scheds/ directory
        manifest_path = pkg.get("manifest_path", "")
        if "scheds/" in manifest_path:
            pkg_metadata = pkg.get("metadata") or {}
            scx_metadata = pkg_metadata.get("scx", {})
            schedulers.append(
                {
                    "name": pkg["name"],
                    "path": pkg["manifest_path"],
                    "metadata": scx_metadata,
                }
            )

    return schedulers


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

    py_files = list(rglob_no_symlinks(".github/include/**/*.py"))
    if py_files:
        await run_command(["black"] + py_files, no_capture=True)
        await run_command(["isort"] + py_files, no_capture=True)

    await run_command(["cargo", "fmt"], no_capture=True)

    nix_files = list(rglob_no_symlinks("**/*.nix"))
    if nix_files:
        await run_command(
            ["nix", "--extra-experimental-features", "nix-command flakes", "fmt"]
            + [os.path.join("../", x) for x in nix_files],
            cwd=".nix",
            no_capture=True,
        )

    c_patterns = [
        "tools/scxtop/**/*.h",
        "tools/scxtop/**/*.c",
        "scheds/rust/scx_chaos/**/*.c",
        "scheds/rust/scx_chaos/**/*.h",
        "scheds/rust/scx_mitosis/**/*.c",
        "scheds/rust/scx_mitosis/**/*.h",
    ]
    c_files = []
    for pattern in c_patterns:
        c_files.extend(list(rglob_no_symlinks(pattern)))

    if c_files:
        await run_command(["clang-format", "-i"] + c_files, no_capture=True)

    await run_command(["git", "diff", "--exit-code"], no_capture=True)
    print("✓ Format completed successfully", flush=True)


async def run_build():
    """Build all targets."""
    print("Running build...", flush=True)

    print("Building C schedulers...", flush=True)
    await run_command(["make", "all"], no_capture=True)

    # Run Cargo and Nix builds in parallel
    print("Building Rust schedulers and scx_chaos with Nix in parallel...", flush=True)

    # Start both builds concurrently
    cargo_coro = run_command(["cargo", "build", "--all-targets", "--locked"], no_capture=True)
    nix_coro = run_command(["nix", "build", "--print-build-logs", "--no-link", "./.nix#scx_chaos"])

    # Wait for both to complete (nix output will only appear on failure)
    await asyncio.gather(cargo_coro, nix_coro)

    print("✓ All builds completed successfully", flush=True)


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
    print("Checking that vmlinux.tar.zst is in sync...", flush=True)

    with tempfile.TemporaryDirectory() as tempdir:
        await run_command(
            ["tar", "-xf", "rust/scx_utils/vmlinux.tar.zst", "-C", tempdir],
            no_capture=True,
        )
        await run_command(
            [
                "diff",
                "--no-dereference",
                "-qr",
                "scheds/vmlinux/",
                f"{tempdir}/vmlinux/",
            ],
            no_capture=True,
        )

    print("Running tests...", flush=True)

    # Make sure the selftest is built in case the build was not already run.
    await run_command(["cargo", "build", "-p", "scx_arena_selftests"], no_capture=True)

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
    cpu_count = min(os.cpu_count() or 16, 16)

    await run_command_in_vm(
        "sched_ext/for-next",
        [
            sys.argv[0],
            "test-in-vm",
        ],
        memory=16 * 1024 * 1024 * 1024,
        cpus=cpu_count,
        no_capture=True,
    )

    print("✓ Tests completed successfully", flush=True)


async def run_veristat():
    """Run veristat verification on all schedulers across all compatible kernels."""
    print("Running veristat verification...", flush=True)

    async def get_veristat_result(kernel: str, bpf_objects: List[str]):
        try:
            stdout = await run_command_in_vm(
                kernel,
                [
                    "veristat",
                    "-o",
                    "csv",
                ]
                + bpf_objects,
            )

            return {"success": True, "csv": stdout}
        except subprocess.CalledProcessError as e:
            return {
                "success": False,
                "return_code": e.returncode,
                "stdout": e.stdout,
                "stderr": e.stderr,
            }

    async def generate_readable_output(result):
        """Generate human-readable output for a verification result using veristat -R."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv") as f:
            f.write(result["csv_data"])
            f.flush()

            result["output"] = await run_command(["veristat", "-R", f.name])
            return result

    matrix = await generate_scheduler_kernel_matrix()
    matrix = [x for x in matrix if not x["disable_veristat"]]

    print(f"Testing {len(matrix)} scheduler-kernel combinations:")
    for item in matrix:
        print(f"  - {item['scheduler']} on {item['kernel']}")

    # Group by kernel to reuse VMs
    kernels_to_test = {}
    for item in matrix:
        kernel = item["kernel"]
        if kernel not in kernels_to_test:
            kernels_to_test[kernel] = []
        kernels_to_test[kernel].append(item["scheduler"])

    # Create temporary directory for BPF object extraction
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract BPF objects for all schedulers (parallelise over scheds)
        schedulers = list({item["scheduler"] for item in matrix})
        extractors = []
        for sched in schedulers:
            d = os.path.join(temp_dir, sched)
            os.makedirs(d, exist_ok=True)
            extractors.append(extract_bpf_objects(sched, d))

        scheduler_bpf_objects = {
            sched: bpf_objects
            for sched, bpf_objects in zip(schedulers, await asyncio.gather(*extractors))
        }
        print(f"scheduler_bpf_objects mapping: {scheduler_bpf_objects}")

        # Veristat only shows the basename of each file in the CSV output. Ensure
        # each path name is unique before passing them to veristat so we can
        # reverse map them later.
        unique_bpf_object_names = set()
        for objs in scheduler_bpf_objects.values():
            for i, obj in enumerate(objs):
                mod = False
                while os.path.basename(obj) in unique_bpf_object_names:
                    mod = True
                    obj = obj + random.choice(string.ascii_lowercase)
                if mod:
                    print(f"Found duplicate BPF object, renaming {objs[i]}->{obj}")
                    os.rename(objs[i], obj)
                objs[i] = obj
                unique_bpf_object_names.add(os.path.basename(obj))

        bpf_object_to_scheduler = {
            os.path.basename(path): scheduler
            for scheduler, paths in scheduler_bpf_objects.items()
            for path in paths
        }
        print(f"bpf_object_to_scheduler mapping: {bpf_object_to_scheduler}")

        # Start veristat VMs (parallelise over kernels)
        running_processes = {}
        total_tests = len(matrix)

        print(f"\n=== Starting parallel veristat VMs ===")

        veristat_vms = list()
        for kernel, schedulers in kernels_to_test.items():
            # Collect all BPF objects for this kernel
            all_bpf_objects = []
            valid_schedulers = []

            for scheduler in schedulers:
                bpf_objects = scheduler_bpf_objects[scheduler]
                all_bpf_objects.extend(bpf_objects)
                valid_schedulers.append(scheduler)

            veristat_vms.append(get_veristat_result(kernel, all_bpf_objects))

        print(f"Starting {len(veristat_vms)} parallel veristat VMs")

        veristat_results = {
            kernel: result
            for kernel, result in zip(
                kernels_to_test.keys(), await asyncio.gather(*veristat_vms)
            )
        }

        print(f"\n=== Processing results ===")

        veristat_failures = [
            (k, r) for k, r in veristat_results.items() if not r["success"]
        ]
        if veristat_failures:
            for kernel, res in veristat_failures:
                print(
                    f"✗ Veristat failed for kernel {kernel} with return code {res['return_code']} and stdout:"
                )
                print(res["stdout"])
                print("And stderr:")
                print(res["stderr"])
            raise Exception(
                f"vmtest failed to complete on {len(veristat_failures)} kernels"
            )

        veristat_csvs = {k: r["csv"] for k, r in veristat_results.items()}
        print(f"Raw veristat_csvs keys: {list(veristat_csvs.keys())}")

        # Process CSV data for successful results
        print(f"\n=== Processing CSV data ===")

        # Create unified list of verification results: [{'scheduler': str, 'kernel': str, 'failed': bool, 'csv_data': str}, ...]
        verification_results = []

        for kernel, csv_content in veristat_csvs.items():
            print(f"\nProcessing kernel {kernel}")
            if not csv_content.strip():
                print(f"  Skipping {kernel} - empty CSV content")
                continue

            # Parse CSV content line by line to group by scheduler
            lines = csv_content.strip().split("\n")
            if len(lines) < 2:  # Need at least header + 1 data row
                print(f"  Skipping {kernel} - insufficient CSV data")
                continue

            header_line = lines[0]
            print(f"  CSV header: {header_line}")

            # Parse and group rows by scheduler
            import csv
            import io

            reader = csv.DictReader(io.StringIO(csv_content.strip()))

            scheduler_data = {}  # scheduler -> {'lines': [str], 'has_failure': bool}
            row_count = 0

            # Process each data row
            for row in reader:
                row_count += 1
                cleaned_row = {
                    key.strip(): value.strip() if isinstance(value, str) else value
                    for key, value in row.items()
                }

                file_name = cleaned_row.get("file_name", "")
                verdict = cleaned_row.get("verdict", "").lower()

                scheduler = bpf_object_to_scheduler[os.path.basename(file_name)]

                if scheduler not in scheduler_data:
                    scheduler_data[scheduler] = {"lines": [], "has_failure": False}

                line_values = [
                    cleaned_row.get(field.strip(), "") for field in reader.fieldnames
                ]
                csv_line = ",".join(
                    f'"{val}"' if "," in str(val) or '"' in str(val) else str(val)
                    for val in line_values
                )
                scheduler_data[scheduler]["lines"].append(csv_line)

                if verdict != "success":
                    scheduler_data[scheduler]["has_failure"] = True

            print(
                f"  Processed {row_count} rows, found schedulers: {list(scheduler_data.keys())}"
            )

            # Create CSV data for each scheduler
            for scheduler, data in scheduler_data.items():
                if not data["lines"]:
                    continue

                # Combine header with scheduler's data lines
                scheduler_csv = header_line + "\n" + "\n".join(data["lines"])

                verification_results.append(
                    {
                        "scheduler": scheduler,
                        "kernel": kernel,
                        "failed": data["has_failure"],
                        "csv_data": scheduler_csv,
                    }
                )

                print(
                    f"  Created CSV for {scheduler} on {kernel}: {len(scheduler_csv)} chars, failed={data['has_failure']}"
                )

        print(
            f"\nCreated {len(verification_results)} scheduler-kernel verification results"
        )

        # Split into successes and failures
        success_results = [r for r in verification_results if not r["failed"]]
        failure_results = [r for r in verification_results if r["failed"]]

        print(f"\nVerification summary:")
        print(f"  Successes: {len(success_results)}")
        print(f"  Failures: {len(failure_results)}")

        print(f"\n=== Generating human-readable output ===")

        readable_results = await asyncio.gather(
            *[generate_readable_output(result) for result in verification_results]
        )

        readable_results.sort(key=lambda x: x["scheduler"])

        readable_successes = [r for r in readable_results if not r["failed"]]
        readable_failures = [r for r in readable_results if r["failed"]]

        # Display successful results first
        print(f"\n" + "=" * 80)
        print(f"SUCCESSFUL VERIFICATIONS ({len(readable_successes)} results)")
        print("=" * 80)

        for result in readable_successes:
            print(f"\n📈 {result['scheduler']} on {result['kernel']}")
            print("-" * 60)
            print(result["output"])

        # Display failure results
        print(f"\n" + "=" * 80)
        print(f"FAILED VERIFICATIONS ({len(readable_failures)} results)")
        print("=" * 80)

        for result in readable_failures:
            print(f"\n❌ {result['scheduler']} on {result['kernel']}")
            print("-" * 60)
            print(result["output"])

        # Generate reproduction commands for failed symbols
        if readable_failures:
            print(f"\n" + "=" * 80)
            print("REPRODUCTION COMMANDS FOR FAILED SYMBOLS")
            print("=" * 80)
            print("Run these commands to debug specific symbol failures locally:")
            print()

            reproduction_cmds = set()
            for result in failure_results:
                # Parse CSV to extract failed symbols
                reader = csv.DictReader(io.StringIO(result["csv_data"].strip()))
                for row in reader:
                    cleaned_row = {
                        key.strip(): value.strip() if isinstance(value, str) else value
                        for key, value in row.items()
                    }

                    verdict = cleaned_row.get("verdict", "").lower()
                    if verdict != "success":
                        prog_name = cleaned_row.get("prog_name", "")
                        if prog_name:
                            reproduction_cmd = f"nix run \".nix#ci\" veristat {result['kernel']} {result['scheduler']} {prog_name}"
                            reproduction_cmds.add(reproduction_cmd)

            for cmd in sorted(reproduction_cmds):
                print(f"  $ {cmd}")

            print()

        # Print final status and throw if there were failures
        if readable_failures:
            print(
                f"\n✗ Veristat verification failed ({len(readable_failures)} schedulers had failures)",
                flush=True,
            )
            raise Exception(
                f"Veristat verification failed for {len(readable_failures)} scheduler-kernel combinations"
            )
        else:
            print(
                f"\n✓ Veristat verification completed successfully ({len(readable_successes)} schedulers passed)",
                flush=True,
            )


async def extract_bpf_objects(scheduler_name: str, output_dir: str) -> List[str]:
    """Extract BPF objects from scheduler binary using existing script."""

    if scheduler_name == "scx_chaos":
        # Use Nix-built binary for scx_chaos
        print(f"Building {scheduler_name} with Nix for BPF extraction...", flush=True)
        stdout = await run_command(
            [
                "nix",
                "build",
                "--no-link",
                "--print-out-paths",
                f"./.nix#{scheduler_name}",
            ]
        )
        nix_store_path = stdout.strip()
        binary_path = f"{nix_store_path}/bin/{scheduler_name}"
    else:
        # Find the scheduler binary in target/debug for other schedulers
        binary_path = f"target/debug/{scheduler_name}"
        if not os.path.exists(binary_path):
            raise Exception(f"Warning: Scheduler binary {binary_path} not found")

    result = await run_command(
        ["./scripts/extract_bpf_objects.sh", binary_path, output_dir]
    )

    # Find extracted .bpf.o files
    bpf_objects = []
    for file in os.listdir(output_dir):
        if not file.endswith(".bpf.o"):
            raise Exception(f"unexpected file {file} in extract dir")
        bpf_objects.append(os.path.join(output_dir, file))

    if not bpf_objects:
        raise Exception(f"No BPF objects found for {scheduler_name}")

    return bpf_objects


async def run_veristat_debug(kernel_name: str, scheduler_name: str, symbol_name: str):
    """Run veristat in debug mode for a specific kernel/scheduler/symbol combination."""
    print(
        f"Running veristat debug mode for {scheduler_name} on {kernel_name}, symbol: {symbol_name}",
        flush=True,
    )

    # Build the specific scheduler first
    if scheduler_name == "scx_chaos":
        # For scx_chaos, building is handled in extract_bpf_objects using Nix
        pass
    else:
        await run_command(["cargo", "build", "-p", scheduler_name], no_capture=True)

    # Create temporary directory for BPF object extraction
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract BPF objects for the specific scheduler
        scheduler_dir = os.path.join(temp_dir, scheduler_name)
        os.makedirs(scheduler_dir)

        bpf_objects = await extract_bpf_objects(scheduler_name, scheduler_dir)

        # Run veristat with debug flags
        await run_command_in_vm(
            kernel_name,
            [
                "veristat",
                "-f",
                symbol_name,
                "-vl2",
            ]
            + bpf_objects,
            memory=2
            * 1024
            * 1024
            * 1024,  # gets impossible to understand SEGVs with less RAM
            no_capture=True,
        )
        print(
            f"✓ Debug veristat completed for {scheduler_name}/{symbol_name} on {kernel_name}",
            flush=True,
        )


async def run_tests_in_vm():
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

    subprocess.run(["target/debug/scx_arena_selftests"], check=True)


async def run_all():
    """Run all CI steps in the correct order."""
    await run_format()
    await run_build()
    await run_clippy()
    await run_veristat()
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
    parser_veristat = subparsers.add_parser(
        "veristat", help="Run veristat verification on all schedulers"
    )
    parser_veristat.add_argument(
        "kernel_name", nargs="?", help="Kernel name for debug mode (optional)"
    )
    parser_veristat.add_argument(
        "scheduler_name", nargs="?", help="Scheduler name for debug mode (optional)"
    )
    parser_veristat.add_argument(
        "symbol_name", nargs="?", help="Symbol name for debug mode (optional)"
    )

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
    elif args.command == "veristat":
        # Check if any debug mode arguments are provided
        debug_args = [args.kernel_name, args.scheduler_name, args.symbol_name]
        provided_args = [arg for arg in debug_args if arg is not None]

        if provided_args:
            if len(provided_args) != len(debug_args):
                parser.error(
                    "veristat debug mode requires all three arguments: kernel_name, scheduler_name, symbol_name"
                )
            await run_veristat_debug(
                args.kernel_name, args.scheduler_name, args.symbol_name
            )
        else:
            await run_veristat()
    elif args.command == "test-in-vm":
        await run_tests_in_vm()
    elif args.command == "all":
        await run_all()


if __name__ == "__main__":
    asyncio.run(main())
