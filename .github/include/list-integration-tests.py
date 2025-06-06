#!/usr/bin/env python3

import itertools
import json
import os
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: list-integration-tests.py <kernel>", file=sys.stderr)
        sys.exit(1)

    kernel = sys.argv[1]

    matrix = [
        {"name": x, "flags": ""}
        for x in [
            "scx_bpfland",
            "scx_chaos",
            "scx_lavd",
            "scx_rlfifo",
            "scx_rustland",
            "scx_rusty",
            "scx_tickless",
        ]
    ]

    # p2dq fails on 6.12, see https://github.com/sched-ext/scx/issues/2075 for more info
    if kernel != "stable/6_12":
        matrix.append({"name": "scx_p2dq", "flags": ""})

    for flags in itertools.product(
        ["--disable-topology=false", "--disable-topology=true"],
        ["", "--disable-antistall"],
    ):
        matrix.append({"name": "scx_layered", "flags": " ".join(flags)})

    print(f"matrix={json.dumps(matrix)}")


if __name__ == "__main__":
    main()
