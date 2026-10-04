# Patched-hardware bitops smoke validation — 2026-09-30

**Pass for primitive correctness and actual JIT emission. Performance acceptance
remains pending.** The user reported a noisy OS and requested functional patch
validation only. Timings collected before/during that instruction are diagnostic;
they do not establish a speedup, regression, or Cake/game performance verdict.

## Running artifact

- Host CPU: AMD Ryzen 7 9800X3D.
- Running kernel: `7.2.8-1-cachyos-custom`.
- Live GNU build ID: `486144881b5af8c42558401dea2ad52d0c0fff12`.
- Live BTF SHA256: `3de3ac8bc87673623bea3e3e124b5825367d49f9b99d9fbb2a27515d15636226`.
- Live build ID and BTF match the custom ELF inspected before reboot; installed
  boot-image SHA256 remains
  `b7dc0dda36fec11eddc47c83dad99bf4134314dc743ddc290a8d36ae3852e890`.
- Probe: `scx/target/cake_jit_bitops_20260929/hardware-probe-build/bitops-run`;
  SHA256 `370c112e1c98ae84ec3df450451cf8c48b9e24dee5b270226a142d8d7064bde8`.

## Functional evidence

Three independent program-load transactions each passed 5,780 differential
executions: **17,340 executions, zero mismatches**. The vectors include zero,
all ones, every single set bit and its complement, alternating patterns, and
random inputs. CTZ of zero returns 64; POPCNT stays consistent with the independent
reference. The probe also checks its four live salt values through the checksum.
This does not replace the patch's separate explicit R6–R9 preservation selftest.

Actual loaded native bytes, in all three transactions:

| Program | Operation instruction | Native program size |
|---|---|---|
| `hw_ctz` | `f3 48 0f bc c7` — `tzcnt %rdi,%rax` | 373 bytes |
| `hw_pop` | `f3 48 0f b8 c7` — `popcnt %rdi,%rax` | 373 bytes |
| `sw_ctz` | no TZCNT in the correctness-run dump | 421 bytes |
| `sw_pop` | no POPCNT in the correctness-run dump | 457 bytes |

These are BPF-program JIT bytes, rather than the JIT compiler implementation's
disassembly. All three runners exited successfully with empty stderr. No
BUG/WARNING/Oops/BPF/sched_ext/segfault entries were found in the readable kernel
journal during the test window. This is bounded smoke evidence, not a soak test.

No scheduler or networking hook was attached. sched_ext remained `disabled`.
The patch implements TZCNT/POPCNT; LZCNT is outside this prototype.

## Retained evidence

Under `/home/ritz/Documents/Repo/scx_cake_bench/runs/jit_bitops_20260929/`:

- `hardware-correctness-20260930T152945Z/`: check-only run, translated/native
  bytes, disassembly, and binary/BTF/boot hashes.
- `hardware-native-20260930-session01/`: 12 paired blocks, repeat 10,000, CPU 2.
- `hardware-native-20260930-session02/`: 16 paired blocks, repeat 100,000, CPU 2.
- `hardware-smoke-review-20260930.json`: aggregate functional verdict, exact
  opcode/hash checks, noise classification, and `performance_accepted=false`.

The timing collectors' generated `hardware_performance_evidence` flag identifies
hardware collection; it does not override this review's rejection of performance
acceptance under the user-reported noise condition. No additional performance
runs were started after that instruction.

## Remaining gates and temporary permissions

Native-mode Cake verifier loading, scheduler activation, hardware execution of
the three kernel-patch selftests, unsupported-feature hardware coverage, clean
paired performance runs, and whole-Cake/game measurements remain pending.
Earlier VM native/fallback and kernel-patch selftest evidence remains historical.

The user provisioned the probe with `cap_bpf,cap_net_admin,cap_perfmon,cap_syslog=ep`
and changed `kernel.kptr_restrict` from 2 to 1 for JIT-byte retrieval. Both remain
enabled after these tests; no other security setting was changed. Restore
`kernel.kptr_restrict=2` and remove the probe's file capabilities when testing is
finished. Rebuilding this binary clears its file capabilities.
