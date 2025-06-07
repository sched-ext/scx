#!/usr/bin/env python3

import itertools
import json
import os
import subprocess
import sys


def get_kernel_trailers_from_commits():
    """Get CI-Test-Kernel trailers from commits between current HEAD and base branch."""
    # In GitHub Actions, GITHUB_BASE_REF contains the target branch name
    # Default to main branch if not in a PR context
    base_ref = os.environ.get("GITHUB_BASE_REF", "main")
    if not base_ref:
        base_ref = "main"

    result = subprocess.run(
        ["git", "log", "--format=%B%n---ENDOFCOMMIT---", f"origin/{base_ref}..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )

    if not result.stdout.strip():
        return set()

    kernels = set()

    commit_messages = result.stdout.split("---ENDOFCOMMIT---")
    for commit_message in commit_messages:
        commit_message = commit_message.strip()
        if not commit_message:
            continue

        lines = commit_message.split("\n")

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

    return kernels


def main():
    if len(sys.argv) != 2:
        print("Usage: list-integration-tests.py <default-kernel>", file=sys.stderr)
        sys.exit(1)

    default_kernel = sys.argv[1]

    trailer_kernels = get_kernel_trailers_from_commits()

    kernels_to_test = {default_kernel}
    kernels_to_test.update(trailer_kernels)

    matrix = []

    for kernel in kernels_to_test:
        # use a blank kernel name for the default, as the common case is to have
        # no trailers and it makes the matrix names harder to read.
        kernel_name = "" if kernel == default_kernel else kernel

        for scheduler in [
            "scx_bpfland",
            "scx_chaos",
            "scx_lavd",
            "scx_rlfifo",
            "scx_rustland",
            "scx_rusty",
            "scx_tickless",
        ]:
            matrix.append({"name": scheduler, "flags": "", "kernel": kernel_name})

        # p2dq fails on 6.12, see https://github.com/sched-ext/scx/issues/2075 for more info
        if kernel != "stable/6_12":
            matrix.append({"name": "scx_p2dq", "flags": "", "kernel": kernel_name})

        for flags in itertools.product(
            ["--disable-topology=false", "--disable-topology=true"],
            ["", "--disable-antistall"],
        ):
            matrix.append(
                {"name": "scx_layered", "flags": " ".join(flags), "kernel": kernel_name}
            )

    print(f"matrix={json.dumps(matrix)}")


if __name__ == "__main__":
    main()
