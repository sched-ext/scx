# CTZ/POPCNT JIT prototype — registered 2026-09-29

Question: can explicit scalar bitops, inlined by the x86 BPF JIT, reduce actual
BPF execution time without changing results or Cake scheduling decisions?

Base: Linux 2709dd5ae32f0828f386327c76bba9f39f63a1c6 (7.2 source reference),
Cake 8fc5ec9b1. The source is not asserted to be the installed CachyOS source.
Kernel worktree: scx/target/cake_jit_bitops_20260929/linux, detached and isolated.

Steps (budget: six implementation/validation stages):
1. Add only portable bpf_ctz64/bpf_popcnt64 and x86 feature-gated JIT inlining.
2. Build affected kernel code and a VM kernel; check BPF_SYSCALL=n linkage.
3. Build real BPF differential tests and an unattached test-run timing harness.
4. VM correctness, register-liveness and native-byte inspection; CPU-feature
   fallback runs. TCG wall times are diagnostic only, never hardware evidence.
5. Export an apply-ready kernel patch, optional Cake patch and reproducible
   runner for the user's CachyOS Kernel Manager build and reboot.
6. On the patched hardware boot, run paired measurements; Cake scoring remains
   on the maintained receipt/native-pair route. This stage needs that boot.

Invariants: no host scheduler activation, kernel installation, reboot, security
setting change or capabilities workaround during construction. Retain normal
BPF call ABI initially: no KF_FASTCALL or verifier-range changes. Zero CTZ = 64,
population count in 0..64. No workload-specific scheduling policy changes.

Stop/repair conditions: any result mismatch, verifier failure, kernel warning,
bad register preservation, unsupported CPU instruction, patch/build failure,
or missing evidence. No performance claim from reduced instruction count.

Measurements: batch wall time around BPF_PROG_TEST_RUN, reported alongside raw
repeat count, iterations, inputs, output checksum and kernel-reported duration;
ABBA paired blocks, independent and dependent inputs, empty/control path.
Do not subtract an assumed call cost from timings or treat TCG as Zen 5.

Proposed first endpoint: validated reviewable patch + runner, not deployment.
Hardware performance acceptance: paired superiority on the affected paths and
no regressions in correctness/liveness or relevant whole-workload guardrails.
