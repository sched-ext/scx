#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time


def get_hash_for_repo_branch(repo, branch):
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", repo, f"heads/{branch}"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.split("\t")[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update kernel locks")
    parser.add_argument(
        "versions", nargs="*", help="Named version(s) to update (default=all)"
    )
    args = parser.parse_args()

    try:
        with open("kernel-versions.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise Exception(
            "kernel-versions.json not found. Are you running this script from the root of the scx repo?"
        ) from exc

    diff = False

    if args.versions:
        versions_set = set(args.versions)

    for k, v in data.items():
        if args.versions and k not in versions_set:
            continue

        new_hash = get_hash_for_repo_branch(v["repo"], v["branch"])
        old_hash = v.get("commitHash", "")
        if new_hash == old_hash:
            continue

        print(f"Updating {k} from {old_hash} -> {new_hash}")

        v["commitHash"] = new_hash
        v["lastModified"] = int(time.time())

        diff = True

    if not diff:
        print("No changes made, exiting.")
        sys.exit(0)

    content = json.dumps(data, indent=2)
    with open("kernel-versions.json", "w") as f:
        f.write(content)
