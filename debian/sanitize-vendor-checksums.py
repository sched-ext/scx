#!/usr/bin/env python3
"""
Remove .orig file entries from vendor .cargo-checksum.json files.

Quilt and other patch tools can create .orig backup files. If vendor/ was
ever created or modified while such files were present, the checksum files
will reference them. When building from a source package that doesn't
include those backups (e.g. on a different machine), Cargo fails with
"failed to calculate checksum of: .../Cargo.toml.orig". This script
removes those entries so the build can proceed.
"""
import json
import sys
from pathlib import Path


def main():
    vendor = Path("vendor")
    if not vendor.is_dir():
        return 0
    changed = 0
    for cksum in vendor.rglob(".cargo-checksum.json"):
        try:
            data = json.loads(cksum.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: {cksum}: {e}", file=sys.stderr)
            continue
        if "files" not in data:
            continue
        orig_keys = [k for k in data["files"] if k.endswith(".orig")]
        if not orig_keys:
            continue
        for k in orig_keys:
            del data["files"][k]
        cksum.write_text(json.dumps(data))
        changed += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
