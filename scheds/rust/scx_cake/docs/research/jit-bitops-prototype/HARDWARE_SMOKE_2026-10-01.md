# Combined scalar patch: live Cake smoke — 2026-10-01

**Passed on this host:** verifier loading, native scalar-path selection, a
15-second Cake run and clean restoration to native scheduling. This was a
functionality diagnostic, with no performance measurements or promotion claim.

## Identity

- Kernel: `7.2.8-1-cachyos-custom`, build timestamp September 30, 17:06:35 UTC.
- Boot ID: `e4d51516-9170-4a66-b0bd-1e47327fab05`.
- Live BTF SHA256: `89a1b85967adce8f1057d312cf79db44a9c853e1d19015a4aba8ec4b436cea2f`.
- CPU: Ryzen 7 9800X3D, 8 cores / 16 threads, one LLC; BMI1, POPCNT and LZCNT available.
- Live BTF exposes `bpf_ctz64`, `bpf_popcnt64`, `bpf_clz64` and `bpf_mulhi64`.
- Cake HEAD: `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a`, with retained dirty scalar/quotient changes.
- Binary SHA256: `0c27e5613b3d2d28517ad40bbf7e30d7a49a0f2eb232e1c6576e846710e6c708`.
  This and the implementation sources match the September 30 validation record.
- The linked BPF object occurs byte-for-byte exactly once in the executable.
  Basic diagnostic path/pair validation passed; this is not a v5 scoring receipt.

## Execution

The scoped helper provisioned a copy of the existing release binary in
`target/cake_receipt_builds/native_scalar_smoke_20261001T201401Z/`.
The original release executable was unchanged. The diagnostic copy used
`--division-free --native-bitops` and ran from 20:14:44 to 20:14:59 UTC.

Startup reported `Native bitops true` and
`Division-free true (CLZ/MULHI kernel)`. The verifier accepted the programs.
There were 59 enabled-state samples identifying
`cake_1.2.1_x86_64_unknown_linux_gnu`; the kernel journal independently records
that scheduler's enable and disable. The initial checker expected bare `cake`,
so its boolean was corrected against the retained versioned sysfs samples and
journal, with the correction recorded in `result.json`.

SIGINT stopped only the diagnostic process, which exited zero with
`EXIT: unregistered from user space`. sched_ext was `disabled` before and after.
The journal includes deprecation notices for direct slice/vtime writes and
cpu_acquire/release callbacks. No stall or abnormal scheduler exit was observed.
The scoped diagnostic executable was removed after testing, removing its
temporary file capabilities; hashes, BPF object, source snapshot and logs remain.

## Evidence and limits

Evidence root:
`/home/ritz/Documents/Repo/scx_cake_bench/runs/native_scalar_smoke_20261001T201401Z/`.
Files: `identity.json`, `result.json`, `cake.log`, `kernel.log`, `live-functions.txt`.

The new CLZ/MULHI primitive differential/register-preservation tests and actual
loaded native instruction dumps were not run. Kernel pointers remain restricted
at `kptr_restrict=2`; no security setting was changed. Symbol availability and
native-path selection do not independently prove emitted JIT bytes. Other
topologies, long-running stability, paired callback/workload performance and
game outcomes remain untested in this session. Both experiment flags stay off
by default.
