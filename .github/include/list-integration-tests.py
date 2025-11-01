#!/usr/bin/env python3
"""
Generate a test matrix for integration tests, filtering based on changed files.

This script determines which schedulers need to be tested based on:
1. Files changed in the PR (for pull_request events)
2. Dependency relationships from Cargo.toml
3. Kernel requirements from package metadata

Behavior:
- In non-PR contexts (push to main, scheduled runs): Tests all schedulers
- When core files change (rust/scx_utils, .github/, etc.): Tests all schedulers
- When only specific scheduler directories change: Tests only those schedulers
- When a library changes: Tests all schedulers that depend on it

To force testing specific schedulers, use commit trailers:
  CI-Test-Kernel: <kernel-name>

This will test all schedulers against the specified kernel in addition to the
filtered matrix.
"""

import itertools
import json
import os
import subprocess
import sys
from pathlib import Path


def get_package_kernel_requirements():
    """Get list of Rust crates with specific kernel requirements"""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)

    kernel_requirements = {}
    for pkg in metadata.get("packages", []):
        pkg_metadata = pkg.get("metadata")
        if not pkg_metadata:
            continue
        scx_metadata = pkg_metadata.get("scx")
        if not scx_metadata:
            continue
        ci_metadata = scx_metadata.get("ci")
        if not ci_metadata:
            continue
        kernel_metadata = ci_metadata.get("kernel")
        if not kernel_metadata:
            continue
        kernel_requirements[pkg["name"]] = kernel_metadata

    return kernel_requirements


def get_kernel_trailers_from_commits():
    """Get CI-Test-Kernel trailers from commits between current HEAD and base branch."""
    # In GitHub Actions, GITHUB_BASE_REF contains the target branch name for PRs
    # For push events, it's empty, so we need to determine the base differently
    base_ref = os.environ.get("GITHUB_BASE_REF", "main")
    if not base_ref:
        base_ref = "main"

    result = subprocess.run(
        ["git", "merge-base", "HEAD", f"origin/{base_ref}"],
        capture_output=True,
        text=True,
        check=True,
    )
    merge_base = result.stdout.strip()
    print(f"Merge base with origin/{base_ref}: {merge_base}", file=sys.stderr)

    log_range = f"{merge_base}..HEAD"
    print(f"Searching for trailers in commit range: {log_range}", file=sys.stderr)

    result = subprocess.run(
        ["git", "log", "--format=%B%n---ENDOFCOMMIT---", log_range],
        capture_output=True,
        text=True,
        check=True,
    )

    if not result.stdout.strip():
        return set()

    kernels = set()

    commit_messages = result.stdout.split("---ENDOFCOMMIT---")
    print(
        f"Found {len([msg for msg in commit_messages if msg.strip()])} commits to search",
        file=sys.stderr,
    )

    for commit_message in commit_messages:
        commit_message = commit_message.strip()
        if not commit_message:
            continue

        lines = commit_message.split("\n")
        commit_subject = lines[0] if lines else "Unknown commit"

        # Start from the last line and work backwards, collecting trailers
        for i in range(len(lines) - 1, -1, -1):
            line = lines[i].strip()

            if not line:
                continue

            if ":" not in line:
                break

            if line.startswith("CI-Test-Kernel:"):
                kernel = line.split(":", 1)[1].strip()
                kernels.add(kernel)
                print(
                    f"Found CI-Test-Kernel trailer '{kernel}' in commit: {commit_subject}",
                    file=sys.stderr,
                )

    print(f"Total kernels found from trailers: {kernels}", file=sys.stderr)
    return kernels


def get_changed_files():
    """Get list of files changed in this PR relative to the base branch."""
    # In GitHub Actions, GITHUB_BASE_REF contains the target branch name for PRs
    # For non-PR contexts (push to main, scheduled runs), return None to test everything
    base_ref = os.environ.get("GITHUB_BASE_REF", "")
    if not base_ref:
        print("Not a pull request context, will test all schedulers", file=sys.stderr)
        return None

    result = subprocess.run(
        ["git", "merge-base", "HEAD", f"origin/{base_ref}"],
        capture_output=True,
        text=True,
        check=True,
    )
    merge_base = result.stdout.strip()
    print(f"Merge base with origin/{base_ref}: {merge_base}", file=sys.stderr)

    # Get list of changed files
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{merge_base}...HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )

    changed_files = [
        line.strip() for line in result.stdout.strip().split("\n") if line.strip()
    ]
    print(f"Found {len(changed_files)} changed files", file=sys.stderr)

    return changed_files


def should_test_all_schedulers(changed_files):
    """
    Determine if we should test all schedulers based on changed files.
    Returns True if core/shared files changed, False if only specific scheduler files changed.
    """
    if changed_files is None:
        # Not a PR context (push to main, scheduled run, etc.)
        return True

    if not changed_files:
        # No files changed (shouldn't happen, but be safe)
        print("No changed files detected, testing all schedulers", file=sys.stderr)
        return True

    # Patterns that trigger full test suite
    core_patterns = [
        "rust/scx_utils/",
        "rust/scx_stats/",
        "rust/scx_cargo/",
        "rust/scx_arena/",
        "rust/scx_userspace_arena/",
        "rust/scx_bpf_compat/",
        "rust/scx_raw_pmu/",
        "scheds/include/",
        ".github/",
        ".nix/",
        "Cargo.toml",  # Root workspace Cargo.toml
        "Cargo.lock",
        "meson.build",
        "kernel-versions.json",
    ]

    for changed_file in changed_files:
        for pattern in core_patterns:
            if changed_file.startswith(pattern):
                print(
                    f"Core file changed: {changed_file} (matches {pattern})",
                    file=sys.stderr,
                )
                print("Testing all schedulers due to core changes", file=sys.stderr)
                return True

    print("Only specific directories changed, will filter test matrix", file=sys.stderr)
    return False


def build_scheduler_dependency_map():
    """
    Build a map of library path -> list of schedulers that depend on it.
    Uses cargo metadata to determine dependencies.
    """
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)

    # Map package names to their filesystem paths
    pkg_name_to_path = {}
    for pkg in metadata.get("packages", []):
        manifest_path = Path(pkg["manifest_path"])
        # Get the directory containing Cargo.toml
        pkg_dir = manifest_path.parent
        pkg_name_to_path[pkg["name"]] = str(pkg_dir)

    # Build dependency map: library_path -> [scheduler_names]
    dependency_map = {}

    # List of scheduler package names we care about
    scheduler_names = [
        "scx_bpfland",
        "scx_chaos",
        "scx_cosmos",
        "scx_flash",
        "scx_lavd",
        "scx_layered",
        "scx_p2dq",
        "scx_rlfifo",
        "scx_rustland",
        "scx_rusty",
        "scx_tickless",
    ]

    for pkg in metadata.get("packages", []):
        pkg_name = pkg["name"]

        # Only process scheduler packages
        if pkg_name not in scheduler_names:
            continue

        # Get all dependencies (both regular and build dependencies)
        for dep in pkg.get("dependencies", []):
            dep_name = dep.get("name")

            # Only track workspace-local dependencies (have a path)
            if dep_name in pkg_name_to_path:
                dep_path = pkg_name_to_path[dep_name]

                # Only track dependencies in rust/ directory (core libraries)
                if "/rust/" in dep_path:
                    if dep_path not in dependency_map:
                        dependency_map[dep_path] = set()
                    dependency_map[dep_path].add(pkg_name)

    # Convert sets to lists for easier handling
    for key in dependency_map:
        dependency_map[key] = list(dependency_map[key])

    print(
        f"Built dependency map with {len(dependency_map)} library dependencies",
        file=sys.stderr,
    )
    for lib_path, schedulers in dependency_map.items():
        print(f"  {lib_path} -> {schedulers}", file=sys.stderr)

    return dependency_map


def get_affected_schedulers(changed_files):
    """
    Determine which schedulers are affected by the changed files.
    Returns a set of scheduler names, or None if all should be tested.
    """
    if should_test_all_schedulers(changed_files):
        return None  # Test all schedulers

    affected = set()
    dependency_map = build_scheduler_dependency_map()

    for changed_file in changed_files:
        # Check if a scheduler directory changed
        if changed_file.startswith("scheds/rust/"):
            # Extract scheduler name from path like "scheds/rust/scx_bpfland/..."
            parts = changed_file.split("/")
            if len(parts) >= 3:
                scheduler_name = parts[2]  # e.g., "scx_bpfland"
                affected.add(scheduler_name)
                print(f"Scheduler directly changed: {scheduler_name}", file=sys.stderr)

        # Check if a library dependency changed
        for lib_path, dependent_schedulers in dependency_map.items():
            # Normalize paths for comparison
            changed_path = str(Path(changed_file).parent)

            # Check if the changed file is within this library path
            if changed_file.startswith(lib_path) or changed_path == lib_path:
                affected.update(dependent_schedulers)
                print(
                    f"Library changed: {lib_path}, affects: {dependent_schedulers}",
                    file=sys.stderr,
                )

    if not affected:
        # Edge case: files changed but no schedulers matched
        # This might happen with tools/ or other directories
        # Be conservative and test everything
        print("No specific schedulers matched, testing all", file=sys.stderr)
        return None

    print(f"Affected schedulers: {affected}", file=sys.stderr)
    return affected


def main():
    if len(sys.argv) != 2:
        print("Usage: list-integration-tests.py <default-kernel>", file=sys.stderr)
        sys.exit(1)

    default_kernel = sys.argv[1]

    kernel_reqs = get_package_kernel_requirements()
    trailer_kernels = get_kernel_trailers_from_commits()

    kernels_to_test = {default_kernel}
    kernels_to_test.update(trailer_kernels)

    # NEW: Detect changed files and affected schedulers
    changed_files = get_changed_files()
    affected_schedulers = get_affected_schedulers(changed_files)

    # List of all schedulers (same as before, but now we can filter it)
    all_schedulers = [
        "scx_bpfland",
        "scx_chaos",
        "scx_cosmos",
        "scx_flash",
        "scx_lavd",
        "scx_p2dq",
        "scx_rlfifo",
        "scx_rustland",
        "scx_rusty",
        "scx_tickless",
    ]

    # NEW: Filter schedulers if needed
    if affected_schedulers is not None:
        schedulers_to_test = [s for s in all_schedulers if s in affected_schedulers]
        print(f"Filtered scheduler list: {schedulers_to_test}", file=sys.stderr)
    else:
        schedulers_to_test = all_schedulers
        print(f"Testing all schedulers: {schedulers_to_test}", file=sys.stderr)

    matrix = set()
    for kernel in kernels_to_test:
        for scheduler in schedulers_to_test:
            reqs = kernel_reqs.get(scheduler, {})
            allowlist = reqs.get("allowlist", [])
            blocklist = reqs.get("blocklist", [])
            if kernel in blocklist:
                continue
            # always allow the default kernel through, crates should specify
            # kernel.default if they want a different one
            if kernel != "" and allowlist and kernel not in allowlist:
                continue

            # use a blank kernel name for the default, as the common case is to
            # have no trailers and it makes the matrix names harder to read.
            this_default = reqs.get("default", "sched_ext/for-next")
            matrix.add(
                (
                    scheduler,
                    "",
                    "" if kernel == this_default else kernel,
                )
            )

        # NEW: Only test scx_layered if it's affected or we're testing all
        if affected_schedulers is None or "scx_layered" in affected_schedulers:
            for flags in itertools.product(
                ["--disable-topology=false", "--disable-topology=true"],
                ["", "--disable-antistall"],
            ):
                # use a blank kernel name for the default, as the common case is to
                # have no trailers and it makes the matrix names harder to read.
                this_default = "sched_ext/for-next"
                matrix.add(
                    (
                        "scx_layered",
                        " ".join(flags),
                        "" if kernel == this_default else kernel,
                    )
                )

    matrix = [{"name": n, "flags": f, "kernel": k} for n, f, k in matrix]

    # NEW: Output count for visibility
    print(f"Generated matrix with {len(matrix)} entries", file=sys.stderr)
    print(f"matrix={json.dumps(matrix)}")


if __name__ == "__main__":
    main()
