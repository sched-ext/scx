#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
from argparse import ArgumentParser
import os
from tempfile import NamedTemporaryFile


def fixup_vmlinux_h(src, dst):
    struct_cpumask_found = False
    while True:
        line = src.readline()
        if line == "":
            break
        if line == "struct cpumask {\n":
            struct_cpumask_found = True
            dst.write(line)
            line = src.readline()
            if not line.startswith("\tlong unsigned int bits["):
                raise RuntimeError(
                    "Unexpected struct cpumask layout " + str(line.encode())
                )
            line = "\tlong unsigned int bits[128];\n"
        dst.write(line)
    if not struct_cpumask_found:
        raise RuntimeError("Could not find struct cpumask")


def main():
    parser = ArgumentParser(description="Applies fixups to bpftool-generated vmlinux.h")
    parser.add_argument("vmlinux_h", help="Path to vmlinux.h")
    args = parser.parse_args()
    with open(args.vmlinux_h) as src, NamedTemporaryFile(
        mode="w", dir=os.path.dirname(args.vmlinux_h), delete=False
    ) as dst:
        ok = False
        try:
            fixup_vmlinux_h(src, dst)
            os.rename(dst.name, args.vmlinux_h)
            ok = True
        finally:
            if not ok:
                os.unlink(dst.name)


if __name__ == "__main__":
    main()
