# Cake scalar-bitops JIT prototype

For reviewers: [exact file changes, bundle inventory and validation handoff](HANDOFF.md).

**Current startup default:** [automatic native bitops](AUTO_NATIVE_BITOPS_2026-10-02.md)
selects CTZ/POPCNT when supported and otherwise falls back. `--portable-bitops`
provides a comparison mode. Older reports below describe their original opt-in
settings; division-free and other research modes are still off by default.

Experimental patches and tests, prepared 2026-09-29. During preparation, the host
kernel and running scheduler were not changed. This is a review/test bundle,
not an upstream-ready submission.

**Consolidated results and charts:** [performance summary](PERFORMANCE_SUMMARY_2026-10-02.md)
contains the measured wins, regressions, uncertainty, and code-generation findings,
with a five-page PDF, standalone chart page, CSV data and reproducible analysis.
It separates the installed scalar-path measurements from later VM-only kernel
candidates and does not claim a confirmed real-game speedup.

**2026-10-02 GPU/input handoffs and scheduler signaling.**
The [implementation and validation report](GPU_INPUT_IRQ_SIGNALING_2026-10-02.md)
provides the inclusive kernel patch, optional Cake policy and 20-case VM
contract. New signals default off; native bitops keep their automatic defaults.
Hardware performance and the expanded debug matrix remain unvalidated. The
earlier research reports below describe the investigation before implementation.

The [signal freshness and clock follow-up](SIGNAL_FRESHNESS_CLOCKS_2026-10-02.md)
maps 33 signals to exact source locations, documents update/accuracy contracts,
checks live timing APIs and includes a GPU/CPU clock-offset PNG plus CSV/JSON.
Its 16 clock queries show why one-time clock conversion goes stale; they are
clock observations, not scheduler-performance results.

The [deep signal-path investigation](GAMING_SIGNAL_PIPELINE_2026-10-02.md)
maps direct GPU-to-waiter scheduling, IRQ visibility, fences, thread waits,
KWin frame/input handoffs, mouse and keyboard readiness. It identifies concrete
queue boundaries and proposes task metadata published before CPU selection,
without an extra userspace round trip for the scheduler hint. The host's key
KWin threads are RT, outside Cake's class. Source hashes and live capability
evidence are retained; no new signal patch or latency result is claimed.

**2026-10-02 direct DSQ index.**
The [implementation and simulation report](DSQ_DIRECT_INDEX_2026-10-02.md)
contains a kernel-owned low-ID index with hash fallback, two patch alternatives
and retained test sources. Six ordinary-kernel VM configurations passed 393,216
concurrent lifecycle iterations, and 20/20 five-block simulation slots passed.
Emulated wall-clock time is inconclusive. Debug boots reproduce pre-existing
baseline warnings; that gate remains open. No kernel install, Cake source change
or measured hardware speedup.

**2026-10-02 deep research and typed DSQ comparison.**
The [research report](DEEP_RESEARCH_2026-10-02.md) includes an
[attributed DSQ comparison backport](0004-sched-ext-typed-dsq-compare-cachyos-7.2.8.patch),
accepted upstream for 7.4 and absent from our 7.2.8 baseline. It is an additional
independent patch, not a replacement for the scalar bundle below. Build and
VM checks passed: 26,248 differential executions, 42 Cake inspection loads,
9 activation/restoration checks. A separate verifier mutation test catches two
unsafe state-pruning acceptances when precision tracking is removed. Historical
perf attribution is corrected, and remaining call-register moves are documented.
No hardware latency claim, installation, or release/default change.

**2026-10-02 scalar bounds and native release refactor.**
The [new report](SCALAR_BOUNDS_REFACTOR_2026-10-02.md) adds trusted verifier
return ranges and two isolated release candidates. The specialized candidate
removes 26 static select_cpu instructions and 13 BPF stack accesses on a
16-thread VM. 20,844 differential executions, 56 Cake inspection loads and
8 activation/restoration checks passed across native, old-kernel and actual
CPU-feature-disabled guests. No hardware latency result or default change.
The latest complete research kernel patch is
[scalar fastcall + return bounds](0001-bpf-x86-scalar-fastcall-bounds-cachyos-7.2.8.patch);
apply it to fresh CachyOS 7.2.8 source **instead of** the earlier complete
patch below. An [incremental bounds patch](0003-bpf-scalar-return-bounds-cachyos-7.2.8.patch)
is available for a tree already carrying unary fastcall. The mask-free Cake
variants require the new verifier contract. The host kernel and ordinary
release remain unchanged.

**2026-10-02 further instruction passes and hardware-cost update.**
The [new investigation](INSTRUCTION_PASS_2026-10-02.md) adds selective fastcall,
a wider CTZ scan prototype, BLSR/ANDN compiler probes and measured 9800X3D scalar
chain costs. 36 VM loads, 10 activation checks and 48 host slots passed. Host
timing remains inconclusive under recorded Unreal/Blender interference; no
default changed. The [cost ladder §10](../../AUDIT_OPERATION_COST_2026-09-15.md#10-local-hardware-costs-and-further-instruction-passes-2026-10-02)
separates core instruction measurements from complete callback prices.

**2026-10-01 fastcall simulation: 20/20 slots passed.**
The [five-block VM and instruction-model report](FASTCALL_SIMULATION_2026-10-01.md)
records 60,000 simulated frames and 320 million fixed-work steps. Guest timing
is mixed; no speedup established. LLVM's `znver5` model is a Zen 4 proxy in the
installed version. The host kernel and ordinary release remain unchanged.

**2026-10-01 unary fastcall follow-up: built and VM-verified.**
The [fastcall report](FASTCALL_KERNEL_REVIEW_2026-10-01.md) provides a new
combined-patch alternative, an increment for the existing combined patch,
and an isolated compiler annotation experiment. Native, C-fallback and old-kernel
compatibility tests pass. Release bitops select_cpu loses eight static
instructions, while diagnostic CLZ code grows. Hardware performance remains
unmeasured; the normal release was restored. The report also scopes DSQ lookup,
kick, cpumask and compiler/verifier opportunities. Existing patch instructions
below describe the preceding ordinary-ABI version.

**2026-10-01 combined-patch Cake smoke: passed.** All four kfuncs are present
in the booted custom kernel. The existing Cake release passed verifier loading,
ran for 15 seconds with `--division-free --native-bitops` and kernel CLZ/MULHI
selection, and stopped cleanly. See [current hardware evidence](HARDWARE_SMOKE_2026-10-01.md).
This supersedes the native-mode Cake load/activation pending statements in the
dated preparation records below for this host topology. New-operation primitive
selftests, actual JIT byte inspection and performance validation remain pending.

**2026-09-30 hardware smoke: passed.** The user booted the patched CachyOS custom
kernel. Three loads passed 17,340 differential executions with zero mismatches;
actual JIT bytes contain TZCNT/POPCNT. Timings are diagnostic only because the
user reported OS noise. No hardware performance gain is accepted, and native-mode
Cake loading remains pending. See [hardware smoke evidence](HARDWARE_SMOKE_2026-09-30.md).

**2026-09-30 exact quotient: implemented in normal Cake builds.** `cake build`
and `target/release/scx_cake --division-free` now select the complete exact
reciprocal quotient. `--native-bitops` is also integrated. Both default off.
The kernel at that time used portable CLZ/MULHI. The combined kernel patch below
provides all four native operations in one file. See
[implementation, validation and manual test](QUOTIENT_IMPLEMENTATION.md).

## Files to apply

**Complete current research stack for CachyOS 7.2.8-1:**

[0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch](0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch)

This includes the full prior stack below plus input/fence wake propagation and
IRQ accounting readers. Replace earlier Cake patch entries; apply only one
inclusive bundle. Read the [signal bundle guide](GPU_INPUT_IRQ_SIGNALING_2026-10-02.md)
for defaults, validation and remaining gates. The prior bundle without signals
is retained as an alternative:

[0001-cake-kernel-full-experimental-cachyos-7.2.8.patch](0001-cake-kernel-full-experimental-cachyos-7.2.8.patch)

It includes all four scalar operations, unary fastcall, precise return bounds,
typed DSQ comparison, the direct DSQ index and scalar selftests. Replace earlier
custom Cake patch entries with this single file on freshly extracted matching
sources. All eight affected files reproduce the retained built/VM-tested source.
Debug and hardware-performance gates remain open. Read the
[bundle guide and validation](KERNEL_FULL_BUNDLE_2026-10-02.md) for requirements,
including the separate Cake build needed for full native specialization.

The earlier [scalar-only combined patch](0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch)
is retained as the installed baseline's patch generation. Do not combine it
with the complete research stack. Historical preparation evidence is at
`target/cake_quotient_20260930/kernel/combined/validation.json`; later hardware
smoke reports above supersede its original runtime-pending status.

**Retained earlier patches for reference:**

| Target source | Kernel patch |
|---|---|
| CachyOS **7.2.8-1**, CTZ/POPCNT only | [0001-bpf-x86-inline-scalar-bitops-cachyos-7.2.8.patch](0001-bpf-x86-inline-scalar-bitops-cachyos-7.2.8.patch) |
| Original development base below / upstream 7.3-rc4 application check, CTZ/POPCNT only | [0001-bpf-x86-inline-scalar-bitops.patch](0001-bpf-x86-inline-scalar-bitops.patch) |

These are alternatives: never apply both. Remove the original entry from Kernel
Manager's patch list when selecting the 7.2.8 version. The original patch failed
on 7.2.8 because that JIT lacks the newer kfunc-arena argument block used as its
insertion point. The port inserts the same gated optimization before ordinary
call emission. See [7.2.8 port validation](CACHYOS_7_2_8_PORT.md).

* `0001-bpf-x86-inline-scalar-bitops.patch`: kernel patch, including BPF selftests.
  Base: Linux `2709dd5ae32f0828f386327c76bba9f39f63a1c6` (7.2.0).
* `0002-scx-cake-opt-in-native-bitops.patch`: optional **scx repository** patch.
  Historical base: `8fc5ec9b1`. Already integrated in the current source; do
  not apply again. Do not give this second patch to Kernel Manager.
* `0003-bpf-x86-inline-clz-mulhi-cachyos-7.2.8.patch`: incremental **kernel**
  patch retained for sources already containing the matching 7.2.8 0001 patch.
  Included in the combined patch; do not apply it alongside the combined file.

Both patches passed clean-base `git apply --check`. Application to the exact
CachyOS source selected by Kernel Manager remains to be checked by that build.
Do not force rejected hunks or assume this reference tree matches the installed
7.2.8 CachyOS kernel.

Additional source compatibility check, 2026-09-29: patch 0001 passes
`git apply --check` against upstream `v7.3-rc4` for all five affected paths
(the x86 JIT hunks have a one-line offset). This is application evidence only,
not a 7.3-rc4 build or runtime test, and does not include CachyOS package patches.
The original build base is a development commit after v7.2
(`v7.2-11943-g2709dd5ae32f`), whose Makefile reports 7.2.0; it is not the
installed CachyOS 7.2.8 source. The local compatibility log is
`scx/target/cake_jit_bitops_20260929/compat-v7.3-rc4/apply-check.txt`.

## What changes

Two explicit BPF kfuncs return a 64-bit scalar:

| Operation | Semantics | x86 JIT when supported | Otherwise |
|---|---|---|---|
| `bpf_ctz64(x)` | trailing zeros; zero returns 64 | `TZCNT RAX,RDI` with BMI1 | ordinary kernel call |
| `bpf_popcnt64(x)` | count set bits, 0..64 | `POPCNT RAX,RDI` with POPCNT | ordinary kernel call |

The change lives in `kernel/bpf/helpers.c`, `include/linux/filter.h`, and
`arch/x86/net/bpf_jit_comp.c`. No new BPF opcode, LLVM change, sched_ext ABI
change, fastcall convention, or verifier-range extension is included. The JIT
recognizes these two kfunc targets and replaces the call with five instruction
bytes. Existing BPF builtins continue to compile the same way. Kfunc use requires
JIT support; this is not an interpreter implementation.

**One instruction replaces the call itself, not the whole surrounding code.**
Normal BPF call rules still cause argument moves and potentially spills. The
Cake CTZ wrapper also masks the result to 0..63 to retain verifier bounds; its
two call sites already require nonzero inputs. The optional Cake change touches
two CTZ sites and one POPCNT site. Actual dynamic frequency and end-to-end value
still need measurement. The first experiment excluded LZCNT and division;
the separate [complete quotient implementation](QUOTIENT_IMPLEMENTATION.md)
now adds them as another opt-in experiment.

## CachyOS Kernel Manager

Use Configure and the local patch facility to select the **single combined
7.2.8 patch** above for that source. Give the
kernel a distinct package name, e.g. `linux-cachyos-cake-bitops`, and retain the
current kernel as a boot option. Build with your usual configuration so the
JIT change is the relevant variable. Keep BPF, BPF_SYSCALL, BPF_JIT,
DEBUG_INFO_BTF, and SCHED_CLASS_EXT enabled. `vm.config` is a test fragment,
not a replacement for your hardware kernel configuration.

Build/install through the manager, then boot the new kernel. This patch is
not a livepatch module. A running JIT cannot be replaced just by loading a new
Cake executable; already-loaded BPF programs must also be reloaded to regenerate
their machine code. The supplied VM path allows correctness checks without
rebooting the host, but this machine currently has no `/dev/kvm`, so those runs
use TCG and cannot supply 9800X3D performance evidence.

Kernel Manager documents custom package names and local patch support in its
[official guide](https://wiki.cachyos.org/features/kernel_manager/).

## Standalone hardware measurement after boot

Build prerequisites: clang with BPF target, C compiler, libbpf development
files, bpftool, pkg-config, Python 3, and objdump. From this directory:

```sh
make
python3 -m unittest test_analyze.py
python3 run.py /home/ritz/Documents/Repo/scx_cake_bench/runs/jit-bitops-hardware-001 \
  --environment hardware --expect native --cpu 0 --repeat 10000 --blocks 12
```

Use an available CPU from the current affinity and a fresh output directory.
The execution session needs permission to load/test BPF programs and retrieve
JIT instruction bytes. The runner does not elevate permissions or alter security
settings. A denied load or hidden JIT dump stops the run and retains the error;
it is not recorded as a performance result.

The runner pins its process, validates 5,780 executions, dumps translated BPF
and native bytes, checks the expected native mnemonics, and measures paired
ABBA/BAAB blocks. It records raw wall time, kernel-reported duration, batch and
repeat counts, seeds, checksums, CPU/kernel metadata, BTF/binary hashes, and
before/after frequency, temperature, load and interrupt snapshots where readable.
It attaches no scheduler or networking hook.

There are independent and dependent input sequences at 64/256/1024 operations
per batch. A numeric BPF iterator keeps verification bounded; its overhead and
the input/checksum work are included in both arms. The control is an identity
loop, not a zero-cost calibration. No assumed overhead is subtracted. Software
CTZ here defines zero as 64; Cake's existing nonzero CTZ path is a different
context. Report the measured ns/op differences and uncertainty, not a conversion
from instruction count to nanoseconds. Bootstrap intervals use paired blocks
within one run and do not establish across-boot repeatability.

Run multiple quiet sessions and retain regressions as well as wins. Whole-Cake
testing is a separate gate: use the repository's maintained artifact receipt,
`cakebench native-pair`, and game A/B routes, with identical workload/configuration
and the `--native-bitops` flag as the intended difference. Do not replace those
routes with this primitive benchmark or claim an FPS benefit from it.

## Optional Cake build

The isolated candidate already exists at
`scx/target/cake_jit_bitops_20260929/cake`; the release binary is at
`scx/target/cake_jit_bitops_20260929/cake-build/release/scx_cake`.
For another checkout at the named base, apply 0002 and build `scx_cake` normally.
The option defaults off. `--native-bitops` requires x86 BMI1/POPCNT and both
kernel symbols, otherwise startup fails. JIT inspection is still required to
prove that a particular kernel actually inlines those symbols.

The optional Cake candidate has been built and unit-tested, but **its native
mode has not yet been verifier-loaded or activated as a scheduler**. That remains
a patched-hardware validation gate before any scheduler performance claim.

## Validation completed

* Complete LLVM VM kernel build, with x86 IBT enabled; no LTO/CFI in this test
  configuration. CachyOS LTO/CFI combinations remain a separate build/run gate.
* BPF_SYSCALL=n x86 JIT object compiled; no unresolved references to the new
  kfuncs. This is an object/configuration check, not an all-architecture build.
* Native TCG VM: 5,780 differential executions, zero mismatches; all three
  kernel-patch selftests pass, including explicit R6-R9 preservation.
* Unsupported-feature TCG VM (`qemu64`): same checks pass; both optimized
  program dumps contain ordinary calls instead of TZCNT/POPCNT.
* Native program dumps contain `f3 48 0f bc c7` / `f3 48 0f b8 c7` at the
  operation site. Both full timing matrices complete; **TCG timings are not
  hardware performance evidence**.
* Kernel selftest BPF object compiles with warnings as errors. Its three
  programs were run through the supplied standalone loader; the full upstream
  `test_progs` suite has not been run.
* Cake release build, format check, unit/CLI tests pass (32 unit tests plus
  3 integration tests; one outer test is ignored, with its child test run by
  another test). Package-only clippy passes. Workspace dependency linting hits
  a pre-existing `scx_stats` type-complexity warning with `-D warnings`.
* Analyzer tests cover known ns deltas and rejection of incomplete matrices,
  missing slots, duplicate slots, wrong arm order, mismatched results and failed
  correctness. Kernel checkpatch: zero errors, one new-file MAINTAINERS reminder.

Evidence: `/home/ritz/Documents/Repo/scx_cake_bench/runs/jit_bitops_20260929/`.
Successful runs: `vm-native-final` and `vm-fallback-final`. Earlier failed setup
runs are retained, including a verifier-complexity rejection repaired by the
numeric iterator. A mixed-feature QEMU max model caused userspace SIGILL during
boot; the coherent qemu64 model passed the unsupported-feature test. Successful
VMs emit known QEMU platform/init warnings; they are not represented as clean
production-kernel soak tests.

The VM uses an official Ubuntu noble root filesystem because host CachyOS
userspace is built for unsupported TCG ISA features. Its archive SHA256 is
`820311e238ea34d76a8ca2643d6c01065212e9417109e7397d70472a236df261`.
VM-only C runner copies have `.note.gnu.property` removed: host startup objects
advertise x86-64-v4 although their inspected code and the runners compiled for
baseline x86-64 do not require it. Hardware runner binaries are unmodified.

`vm-check.sh BUILD_ROOT RESULTS_ROOT NEW_NAME native|fallback` reproduces the
VM runs using the existing local build/rootfs/venv. `selftest-run` takes the
compiled `scalar_bitops.bpf.o` from the patch's selftests. Source and binary
provenance is recorded in `validation.json`.
