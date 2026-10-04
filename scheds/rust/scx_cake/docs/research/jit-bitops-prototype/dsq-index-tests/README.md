# Direct DSQ index validation sources

Source snapshot for [the October 2 experiment](../DSQ_DIRECT_INDEX_2026-10-02.md).
These programs are for a disposable VM, not host scheduler activation.
`dsq-test` attaches a test scheduler, including concurrent queue destruction.
`vm-init.c` is guest PID 1 and powers the guest off on completion.

The retained, runnable workspace is
`target/cake_dsq_index_20261002T201929Z/`, relative to the scx repository root.
The Python scripts derive their paths from that workspace; do not execute the
documentation copies in place. Measurements are in the sibling
`scx_cake_bench/runs/cake_dsq_index_20261002T201929Z/` directory.

## Reproduction on this checkout

The retained workspace includes the compiled test object, loader, initramfs,
ordinary and debug kernel images, build logs, BTF-derived `vmlinux.h`, original
plan, source variants and exact file hashes. A unique run name preserves receipts:

```sh
python3 target/cake_dsq_index_20261002T201929Z/run-vm.py review-direct --cpus 4
python3 target/cake_dsq_index_20261002T201929Z/run-vm.py review-hash --cpus 4 --hash-only
```

`--baseline` selects the earlier typed-comparison kernel; `--debug-kernel`
selects an immutable KASAN/lockdep image. `--poc-off` disables the POC selector
inside the guest only. Read the report's debug failures before interpreting
those runs. A warning causes the runner to fail even if workload assertions pass.

`simulate.py` runs 20 unique slots across five alternating ABBA/BAAB blocks.
Its fixed names intentionally refuse to overwrite existing slot directories.
For another series, use a new workspace/run namespace and preserve the originals.

## Build inputs

`build-vm.py` packages the existing repo release, test binaries and a minimal
dynamic-loader/libc/libbpf filesystem retained from
`target/cake_scalar_bounds_20261002T082205Z/vm-root`. This source snapshot is
not a standalone portable kernel build system. On another machine, supply
matching userspace libraries, headers and kernel/BTF inputs in an isolated
workspace first. It needs QEMU, clang/LLVM, libbpf development files, a C compiler
and cpio; no host kernel install is involved.

The BPF test is compiled with `clang -O2 -g -target bpf -D__TARGET_ARCH_x86`
and the workspace's generated `vmlinux.h`. The userspace test uses
`cc -O2 -Wall -Wextra -Werror` with `-lbpf -lelf -lz -lpthread` and libraries
compatible with the guest. `build-vm.py` builds the guest init with warnings
treated as errors. See the retained build logs and `vm-files.json` for the
actual binary identities.

## Meaning of the results

- Queue tests cover duplicate/missing/boundary IDs, recreation, concurrent
  lifecycle operations, and count/peek/insert/move on real scheduling queues.
- The boot option tests an absent index; actual allocator fault injection and
  simultaneous nested-scheduler namespace isolation remain untested.
- Fixed-work checksums are validated per worker. All slots must finish and
  restore the guest to `sched_ext=disabled`.
- QEMU TCG timing does not model this host's physical cache/coherence costs.
  `wake_late_max_ns` is iteration completion lateness after an absolute sleep
  deadline, including computation overruns. It is not scheduler wake-to-run
  latency or game frame time.
