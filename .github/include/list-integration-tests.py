#!/usr/bin/env python3

import itertools
import json
import os
import subprocess
import sys


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


def main():
    if len(sys.argv) != 2:
        print("Usage: list-integration-tests.py <default-kernel>", file=sys.stderr)
        sys.exit(1)

    default_kernel = sys.argv[1]

    kernel_reqs = get_package_kernel_requirements()

    trailer_kernels = get_kernel_trailers_from_commits()

    kernels_to_test = {default_kernel}
    kernels_to_test.update(trailer_kernels)

    matrix = set()
    for kernel in kernels_to_test:

        for scheduler in [
            "scx_beerland",
            "scx_bpfland",
            "scx_cake",
            "scx_chaos",
            "scx_cosmos",
            "scx_flash",
            "scx_lavd",
            "scx_pandemonium",
            "scx_p2dq",
            "scx_rlfifo",
            "scx_rustland",
            "scx_rusty",
            "scx_tickless",
        ]:
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
    print(f"matrix={json.dumps(matrix)}")


if __name__ == "__main__":
    main()
