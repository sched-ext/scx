#!/usr/bin/env python3
"""Exercise Cake's pool callbacks with deterministic deferred DSQ insertions."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from review_regressions import function


def main():
    bench = Path(__file__).resolve().parent
    bpf = bench.parent / "src" / "bpf"
    source = (bpf / "cake.bpf.c").read_text()
    callbacks = [
        "cake_pool_pending_inc", "cake_pool_claim", "cake_pool_serve",
        "cake_pool_unserved", "cake_pool_pending_dec", "cake_pool_tag",
        "cake_pool_retire", "cake_pool_retire_task", "cake_pool_seen", "cake_pool_insert",
        "cake_quiescent", "cake_idle_interlock",
    ]
    with tempfile.TemporaryDirectory(prefix="cake-pool-test-") as directory:
        scratch = Path(directory)
        (scratch / "callbacks.h").write_text(
            "\n\n".join(function(source, name) for name in callbacks)
        )
        binary = scratch / "pool_regressions"
        subprocess.run([
            "cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(bpf),
            "-I", str(scratch), str(bench / "pool_regressions.c"), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
