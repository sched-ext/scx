#!/usr/bin/env python3
"""Remove excluded file entries from vendor .cargo-checksum.json files.

The orig tarball is generated after running ``cargo vendor``. Files listed in
debian/copyright's Files-Excluded field are removed before archiving, so their
checksums must be removed as well. Quilt and other patch tools can also create
.orig backup files; those are sanitized for the same reason.
"""
import json
import shutil
import sys
from pathlib import Path


def read_files_excluded():
    copyright = Path("debian/copyright")
    if not copyright.is_file():
        return []

    entries = []
    in_files_excluded = False
    for line in copyright.read_text().splitlines():
        if line.startswith("Files-Excluded:"):
            entries.extend(line.split(":", 1)[1].split())
            in_files_excluded = True
            continue
        if in_files_excluded and line.startswith((" ", "\t")):
            entries.extend(line.split())
            continue
        in_files_excluded = False
    return entries


def remove_files_excluded():
    removed = 0
    for pattern in read_files_excluded():
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                removed += 1
            elif path.exists():
                path.unlink()
                removed += 1
    return removed


def main():
    vendor = Path("vendor")
    if not vendor.is_dir():
        return 0
    remove_files_excluded()
    changed = 0
    for cksum in vendor.rglob(".cargo-checksum.json"):
        try:
            data = json.loads(cksum.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: {cksum}: {e}", file=sys.stderr)
            continue
        if "files" not in data:
            continue
        removed_keys = [
            k for k in data["files"]
            if k.endswith(".orig") or not (cksum.parent / k).exists()
        ]
        if not removed_keys:
            continue
        for k in removed_keys:
            del data["files"][k]
        cksum.write_text(json.dumps(data, sort_keys=True) + "\n")
        changed += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
