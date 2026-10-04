# JIT scalar-bitops experiment: reviewer handoff

Prepared 2026-09-29. This is an experimental implementation and validation
bundle. It has not established a hardware performance gain or been submitted
upstream. Kernel source base: `2709dd5ae32f0828f386327c76bba9f39f63a1c6`.
Cake source base: `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a`.

## Proposal in plain English

Expose trailing-zero count and population count as explicit BPF kernel-function
calls. The x86 JIT recognizes those calls and emits TZCNT or POPCNT when the CPU
supports the instruction. Otherwise, it retains a call to a portable kernel
implementation. Cake can opt into these calls for an A/B experiment.

This does not automatically optimize existing compiler-expanded bit-count
sequences. Call sites must use the new functions. It changes neither LLVM nor
the BPF instruction set, verifier range analysis, or the normal BPF call ABI.
Argument movement, spills, and surrounding operations can remain even though
the recognized call becomes one CPU instruction. LZCNT and a division-replacement
algorithm are outside this first prototype.

## Exact kernel files changed by patch 0001

| File | Change |
|---|---|
| `kernel/bpf/helpers.c` | Adds and registers `bpf_ctz64` and `bpf_popcnt64` as scalar kfuncs with portable implementations. CTZ of zero returns 64; POPCNT returns 0..64. |
| `include/linux/filter.h` | Declares the functions under CONFIG_BPF_SYSCALL so the x86 JIT can identify their addresses. |
| `arch/x86/net/bpf_jit_comp.c` | Recognizes those two kfunc targets during call emission. Uses BMI1/POPCNT feature checks and emits `TZCNT RAX,RDI` / `POPCNT RAX,RDI`; unsupported cases retain ordinary calls. |
| `tools/testing/selftests/bpf/progs/scalar_bitops.c` — new | BPF boundary, randomized comparison, and explicit R6–R9 preservation tests. |
| `tools/testing/selftests/bpf/prog_tests/scalar_bitops.c` — new | Registers the test programs with the kernel BPF selftest harness. |

Apply [0001](0001-bpf-x86-inline-scalar-bitops.patch) to a kernel source tree.
This is the patch to select in CachyOS Kernel Manager. Application to the exact
CachyOS source/configuration selected by the user still needs that build's check.

## Exact Cake files changed by optional patch 0002

| File | Change |
|---|---|
| `scheds/rust/scx_cake/src/bpf/cake.bpf.c` | Adds weak kfunc declarations and a rodata-controlled wrapper for each operation. Replaces two CTZ sites and one POPCNT site with those wrappers. Defaults retain the builtins; native CTZ is masked to 0..63 at its nonzero-input call sites to preserve verifier bounds. |
| `scheds/rust/scx_cake/src/main.rs` | Adds default-off `--native-bitops`, checks x86 BMI1/POPCNT and both kernel symbols, logs the selection and sets the BPF rodata flag. |

Apply [0002](0002-scx-cake-opt-in-native-bitops.patch) to the scx repository,
not the kernel. It requests different implementations of the same operations;
it is not a scheduling-policy redesign. Native mode must still pass the Cake
verifier and live safety gates. Symbol availability alone is not proof of JIT
inlining; inspect the loaded native code.

Both changes were developed in isolated worktrees under
`scx/target/cake_jit_bitops_20260929/{linux,cake}`. The main Cake checkout's
scheduler source was not patched. No host kernel was installed or rebooted,
and no host scheduler was activated for this experiment.

## Every file in this bundle

| Files | Purpose |
|---|---|
| `0001-bpf-x86-inline-scalar-bitops.patch` | Kernel implementation and selftests |
| `0002-scx-cake-opt-in-native-bitops.patch` | Optional Cake integration |
| `bitops.bpf.c` | Software/native CTZ and POPCNT test programs, plus identity control |
| `bitops-run.c` | Correctness checks, native/translated dumps, paired timing capture |
| `selftest-run.c` | Standalone loader executing the three kernel-patch test programs |
| `Makefile` | Builds the BPF object, skeleton and C runners |
| `run.py` | Hardware/VM run orchestration, metadata capture and native-path checking |
| `analyze.py` | Validates paired timing blocks and reports ns/op differences and intervals |
| `test_analyze.py` | Tests arithmetic and rejection of incomplete/invalid comparisons |
| `vm.config` | VM kernel configuration fragment |
| `vm-check.sh` | Reproduces native/fallback TCG runs using the prepared local VM environment |
| `EXPERIMENT.md` | Registered hypothesis, scope, stages and stop conditions |
| `validation.json` | Source identities, checks, evidence paths and SHA256 hashes |
| `checkpatch.txt` | Kernel patch style-check output |
| `README.md` | Build/install/test instructions and validation limitations |
| `HANDOFF.md` | This reviewer-facing change inventory |

The preceding investigation is in [../jit-20260929/](../jit-20260929/README.md):
`bitops.c`, its BPF/x86 objects and disassembly, `installed-jit.asm`,
`counts.json`, `provenance.json`, `sha256.json`, `toolchain.txt`, and `README.md`.
`installed-jit.asm` is the installed JIT compiler's implementation, not code it
generated for Cake. The [cost audit](../../AUDIT_OPERATION_COST_2026-09-15.md)
and [meeting page](../../meeting/index.html) were updated to explain these
distinctions and link the experiment. Later documentation organization changes
are separate from both implementation patches.

## Evidence and remaining gates

Completed: kernel build; BPF_SYSCALL=n JIT object build; clean-base patch checks;
native and unsupported-feature TCG VM runs, each with 5,780 differential checks
and three passing kernel-patch test programs; native bytes confirming TZCNT/
POPCNT, and fallback bytes confirming calls; Cake build/unit/CLI/format checks;
package-only clippy; seven analyzer tests. Full upstream test_progs execution,
all-architecture coverage, and CachyOS LTO/CFI configurations are not established.

Raw VM logs, translated/native dumps, timing records and summaries are in:
`/home/ritz/Documents/Repo/scx_cake_bench/runs/jit_bitops_20260929/`.
Final runs are `vm-native-final` and `vm-fallback-final`. TCG timings validate
the collection pipeline only; they are not 9800X3D performance results.

Next: build/boot the selected patched CachyOS kernel; verifier-load Cake native
mode; confirm emitted instructions in that actual build; collect repeated paired
hardware wall-clock measurements; then run the maintained Cake/game A/B workflow
with safety and tail-latency checks. Report ns deltas, uncertainty and regressions.

Review focus for kernel/BPF maintainers: kfunc semantics and registration,
feature gating, normal call-ABI preservation, JIT instruction emission and
configuration coverage. Review focus for sched_ext/Cake maintainers: verifier
bounds, call-site invariants, unchanged decisions, dynamic call frequency and
whole-workload results. VM correctness does not close the performance gate.
