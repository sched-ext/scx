# Scalar return bounds and native release specialization

Built and tested two linked changes: trusted kernel return bounds for the three
unary scalar kfuncs, and release Cake variants that remove result masks while
preserving the compiler's knowledge of those ranges. A further native-only
variant removes runtime CTZ/POPCNT mode loads from BPF, with explicit userspace
option and hardware checks.

On the 16-thread VM topology, native-bitops `select_cpu` shrinks from 1,444 to
1,418 native instructions, 6,087 to 5,961 bytes, and 80 to 67 BPF stack accesses.
These are **static counts for the loaded program and its subprograms**, not
instructions executed on every wakeup or a measured latency reduction. The
host has not booted this verifier/fastcall kernel. No hardware latency, game,
throughput, or default-promotion result is claimed.

## Engineering question and source trail

Can Cake remove the overhead surrounding CTZ/CLZ/POPCNT without changing CPU
selection, idle claims, queue ordering, fairness, or verifier safety?

Sources checked October 2, 2026:

| Source | What it establishes | Local consequence |
|---|---|---|
| [Linux verifier documentation](https://docs.kernel.org/bpf/verifier.html#register-value-tracking) | Register ranges, known bits and memory bounds are tracked separately from source-language types | A C cast alone does not supply a small kfunc result range |
| [Linux kfunc documentation](https://docs.kernel.org/bpf/kfuncs.html) | Registered kfuncs have verifier-visible BTF contracts | Match trusted vmlinux function IDs; do not trust arbitrary names or user-provided return annotations |
| [Clang `__builtin_assume`](https://clang.llvm.org/docs/LanguageExtensions.html#builtin-assume) | An assumption supplies an optimizer invariant; violating it is undefined behavior | Use the existing nonzero-input scan contract, and keep zero-case rejection tests |
| Retained CachyOS 7.2.8 `kernel/bpf/verifier.c`, `include/linux/bpf_verifier.h`, `helpers.c`, and x86 JIT | Exact local call, precision, circular-range and native/fallback behavior | This patch uses this tree's range setters and preserves argument precision before call clobbering |

The upstream documentation describes mechanisms, not a performance result for
Cake. The build and running VM artifacts establish the results below.

## Kernel implementation

[Incremental bounds patch](0003-bpf-scalar-return-bounds-cachyos-7.2.8.patch)
applies on the previous unary-fastcall tree. The
[complete replacement patch](0001-bpf-x86-scalar-fastcall-bounds-cachyos-7.2.8.patch)
applies to fresh CachyOS 7.2.8 source and includes the original scalar emitters,
safe unary fastcall handling, existing scalar selftests, and these bounds.
Use the complete patch **instead of** the preceding complete scalar patch;
do not stack the two complete patches. Neither patch was installed on the host.

| Operation | Any input | Proven nonzero input |
|---|---|---|
| CTZ64 | 0–64; zero returns 64 | 0–63 |
| CLZ64 | 0–64; zero returns 64 | 0–63 |
| POPCNT64 | 0–64, including 64 for all bits set | Still 0–64 |

Only the three exact function IDs in `btf_vmlinux` receive these facts.
Unrelated helpers and MULHI retain their existing contracts. Before caller
registers are invalidated, the verifier captures whether CTZ/CLZ input is
nonzero. When the smaller bound depends on that input, `mark_chain_precision()`
preserves the dependency through state pruning. The return register receives
an unsigned range and tnum, followed by normal range synchronization.

The full LLVM kernel build and compilation database generation passed.
Both patch forms applied cleanly to isolated base files and reproduced the
tested source bytes. Incremental patch `checkpatch --strict`: zero errors,
warnings or checks. This is a tested research prototype, not a comprehensive
verifier security audit or an upstream-ready patch series.

## Why deleting masks initially increased code

The previous `& 63` had two jobs: constraining the verifier result and giving
LLVM a small result range. Merely deleting it removed both. Although the new
verifier could prove memory safety, LLVM had already generated extra width
handling and changed allocation. Native-bitops select grew from 1,414 to 1,427
instructions versus the selective-fastcall candidate on the two-CPU VM.

[The range-preserving Cake patch](cake-scalar-bounds-assumed.patch) supplies
`__builtin_assume(count < 64)` after native CTZ/CLZ. It emits no runtime test.
The kernel still checks the resulting BPF independently: the old kernel rejects
native-bitops loading with an unbounded pointer-offset error. The new one accepts
it. Keeping the assumption without the required kernel contract is not a
compatibility solution.

The nonzero premise was traced through every current wrapper caller:
SMT expansion has a nonempty `seats` loop; cold selection starts from a nonempty
eligible set and each preference preserves a nonempty fallback; ring iteration
tests `pending`; quotient normalization checks its divisor; histogram input
is ORed with one. The generic kernel kfuncs remain defined at zero; these Cake
scan wrappers retain the narrower contract already required by their portable
compiler builtins. Recheck this premise before adding future callers.

## Further release refactor: native specialization

[The specialized Cake patch](cake-scalar-bounds-specialized.patch) also resolves
the CTZ and POPCNT mode branches at compilation. This removes surviving volatile
mode reads and changes allocation again. The research executable requires
`--native-bitops`; it rejects an omitted flag. Existing CPU-feature and symbol
checks remain. Other flags still have their ordinary meanings; division-free
remains off unless explicitly selected.

This is an isolated research executable. A portable product integration would
need loader selection between retained compatible and specialized BPF objects,
including a real return-bounds feature probe. Kernel version strings and symbol
presence cannot distinguish the new bounds contract from the older scalar patch.
The ordinary release and all scheduler source were restored exactly.

## Actual release JIT results

Same new kernel, QEMU TCG `-cpu max`, two CPUs, probe disabled, native-bitops
enabled in all compared arms:

| Callback | Ordinary release | Prior selective fastcall | Delete masks only | Preserve LLVM range | Also specialize native mode |
|---|---:|---:|---:|---:|---:|
| select_cpu instructions | 1,423 | 1,414 | 1,427 | 1,410 | **1,398** |
| enqueue instructions | 1,952 | 1,953 | 1,966 | 1,952 | **1,946** |
| dispatch instructions | 1,163 | 1,162 | 1,162 | 1,161 | **1,159** |
| stopping instructions | 306 | 306 | 306 | 306 | 306 |
| select_cpu BPF stack accesses | 80 | 71 | 71 | 71 | **67** |
| enqueue BPF stack accesses | 121 | 119 | 122 | 122 | **120** |

Specialized select is 123 bytes smaller than the ordinary release and removes
three CTZ-result masks. Enqueue shows why every callback matters: the
range-preserving variant adds three stack accesses versus prior selective
fastcall, even though its overall instruction count falls by one. Specializing
recovers two of those accesses, but still has one more than prior selective.

With eight cores / sixteen threads, ordinary → specialized native-bitops:

| Callback | Native instructions | Native bytes | BPF stack accesses |
|---|---:|---:|---:|
| select_cpu | 1,444 → **1,418** | 6,087 → **5,961** | 80 → **67** |
| enqueue | 1,963 → **1,956** | 8,229 → **8,188** | 121 → **120** |
| dispatch | 1,177 → **1,173** | 4,834 → **4,813** | 76 → **74** |
| stopping | 306 → 306 | 1,269 → 1,269 | 32 → 32 |

Separately, diagnostic CLZ histograms (`--native-hist --toggle probe=1`) drop
two masks: stopping 493 → **491 instructions**, 2,044 → **2,038 bytes**, unchanged
46 stack accesses. This is a probe path, not the normal gaming release path.
Specialized histogram runs additionally enable bitops and must not be compared
as a histogram-only change in other callbacks.

The earlier native dependency-chain measurements price CTZ/CLZ alone near one
cycle and count-plus-mask near two on this 9800X3D. They motivate removing the
dependency, but do not convert this table into callback nanoseconds. No timing
was taken from these VM validation runs.

## Validation matrix

Final evidence uses `native-v4`, `smt16-v4`, `old-v4`, and `fallback-v8`:

| Guest | Bounds positive / negative programs | Differential executions | Cake inspection loads accepted | Activation/restoration checks |
|---|---:|---:|---:|---:|
| New kernel, 2 CPUs, native instructions | 17 / 13 | 6,562 | 19 | 3 |
| New kernel, 8 cores / 16 threads | 17 / 13 | 6,562 | 19 | 3 |
| Old installed kernel booted in VM | 3 / 27 | 1,158 | 14 | 1 |
| New kernel, baseline CPU without BMI1/POPCNT/ABM | 17 / 13 | 6,562 | 4 | 1 |
| Total | 54 / 66 | **20,844** | **56** | **8** |

Each positive program is exercised with 386 inputs: zero, all bits set, all
single-bit and single-cleared-bit values, and 256 seeded values. The tests use
real 64/65-element map values, including zero and off-by-one failures, unrelated
helper/MULHI results, and merged zero/nonzero paths. `BPF_F_TEST_STATE_FREQ`
forces frequent verifier checkpoints; logs show the input precision propagation.
The 27 old-kernel rejections comprise 13 unsafe programs and 14 safe programs
whose required new return-range contract is absent. All 13 unsafe programs
remain rejected in every guest.

The earlier scalar differential/fastcall suite also passes all 24 positive
program executions and four expected MULHI register-clobber rejections. Actual
native and C-fallback register preservation is exercised. Five Cake loads on
the old kernel are expected to reject the new mask-free contract. The specialized
binary rejects missing `--native-bitops`, and rejects native bitops on the
feature-disabled CPU. No unsupported native candidate is activated.

Development failures remain in the evidence directory. The first run had a JIT
dump metadata-reuse bug in the new userspace test runner; a fresh info structure
fixed it. An old-kernel serial export was interrupted by kernel console text;
the corrected guest suppresses printk during export and checks decoded sizes.
Clearing kernel CPU flags did not clear userspace CPUID, so it could not test
loader CPU rejection. Physically clearing selected features from QEMU `max`
then exposed a GCC runtime POPCNT dependency and an incoherent CPU combination
that trapped in glibc's AVX2/BZHI path. The final oracle uses a portable bit loop;
the final `qemu64,-bmi1,-popcnt,-abm` guest passes both fallback execution and
loader rejection. These failed runs are not counted as successful validation.

## Artifacts and next measurable step

Candidate root: `target/cake_scalar_bounds_20261002T082205Z/`.
Measurements: `../scx_cake_bench/runs/cake_scalar_bounds_20261002T082205Z/`.
`final-validation.json` in both roots records hashes, identities, counts,
restoration and source closure. Per-guest directories contain exact QEMU
commands, verifier logs, BPF/native bytes, assembly and status. Candidate root
also retains build scripts, kernel source/build, initramfs versions, patches,
compile database, build logs and patch-application checks.

- Kernel image SHA256: `87a326ab3ff4cd0279c50957955b5d3a60fcc45b4f581bc5f85c2b95ffcc4064`.
- Specialized release SHA256: `7677f0ebde21bd2812e29a2909977e0ce11320546a4304f7c4f37c882540374b`.
- Embedded BPF SHA256: `4be97d25be6a1d67f69febb08aa80fbcb4e70afb1e87644a7f88a55085b15bbe`.
- Restored ordinary release SHA256: `238869478389fceceb64ffe681eebce1025c9c848ec050aa5b0606d5ed6d3723`.

Standalone bounds tests: [BPF source](scalar-bounds.bpf.c) and
[load/run/rejection harness](bounds-run.c). Force-include
[selective fastcall declarations](fastcall-selective-decls.bpf.h) when building
either Cake patch. These declarations are part of each archived build identity.

The next hardware experiment needs the new kernel booted, with the ordinary and
specialized archived releases running identical native-bitops settings. Use the
maintained harness for at least five paired blocks, record callback ns/call and
wall-clock completion, then probe-off frame tails and wake-to-run latency.
Do not pool in the earlier Blender/Unreal-contaminated campaign. Broader CPU
topologies, sustained liveness/fairness, and independent holdout/game validation
remain required before default integration.

Larger latency opportunities remain avoiding repeated DSQ hash lookups and
redundant CPU/current-task reads within a valid decision interval. Kernel DSQ
handles need ownership/RCU/destroy-recreate correctness; kick changes must
preserve rq lock ordering and idle-race progress. Those require separate designs
and measurements. BLSR cannot replace Cake's preferred-CPU failed-claim removal,
because that chosen bit is not necessarily the lowest set bit. Adding more
kfunc calls without shortening the full path is not an optimization result.
