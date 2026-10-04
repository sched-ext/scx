Register pressure, packed bitfields and SWAR — 2026-10-01
========================================================

**Result:** packing several unrelated values merely to carry them across a call did not produce a robust modeled win. Correct fastcall preservation was the better candidate in that probe. A different experiment, incrementing sixteen independent saturating nibble counters together, compiled to 15 BPF instructions with SWAR and no stack traffic. Both are useful findings; neither is a measured Cake speedup.

**What eBPF supports.** A 64-bit scalar register can hold sixteen 4-bit fields. Masks, shifts, addition and bitwise operations are ordinary BPF operations. SWAR (SIMD Within A Register) uses those scalar operations to process several fields together. Simply storing multiple fields in a word is packed-bitfield storage; manipulating them together is the SWAR part. Hardware SSE/AVX vector-register operations are a separate facility, with no general interface in the standard BPF ISA used here. [BPF ISA](https://docs.kernel.org/bpf/standardization/instruction-set.html), [SWAR technical overview by Hank Dietz](https://aggregate.org/SWAR/over.html).

The appropriate implementation terms are **packed bitfields**, **compile-time-specialized bitfield accessors**, and **SWAR arithmetic**. The layout should normally be known when compiling; storing a runtime description of how to unpack it adds decoding work. Inline accessors are not calls in the final code if actually inlined. Neither C bitfield syntax nor writing a packed expression guarantees register allocation will keep values together.

**Why the eBPF register model can cost performance.** The ABI exposes ten writable scalar registers plus a frame pointer, with four registers normally preserved across calls. In the inspected retained x86 JIT, `reg2hex[]` fixes their hardware mapping. This is not a second LLVM-style global register allocation pass: an ordinary BPF stack spill generally becomes a native memory operation unless a specific transformation removes it. The JIT can introduce additional preservation, such as pushes/pops around DIV's required RAX/RDX operands. [BPF ABI](https://docs.kernel.org/bpf/standardization/abi.html).

Consequently there are several different costs: too many simultaneously live values, the call-preservation convention, native instruction register constraints, expanded operations, and guards/workarounds required by available verifier reasoning. Fastcall addresses call preservation; it does not solve all of them. Most verification is performed while loading, so verifier complexity is not a runtime charge on every scheduler operation. The 9800X3D's internal renamed registers do not automatically remove explicit BPF stores/reloads or enlarge the registers exposed to the compiler.

No single percentage describes this overhead. A noncritical spill can overlap other work; a dependent reload can delay the next decision. Cache state, forwarding, call frequency and path selection matter. EEVDF versus Cake would compare scheduling policies as well, not isolate the cost of the BPF register model.

**Existing Cake object: places to investigate, not executed spill counts.** A read-only census of `target/release/build/scx_cake-d032ab4aa53d1e48/out/bpf.bpf.o`, SHA-256 `3a7fb2162072f0e96f53caaf0b048ab763daa5bed5e750437eb4e66c4c4f2989`, found:

| Function | Stack-store sites | Stack-load sites |
|---|---:|---:|
| `cake_dispatch_search` | 15 | 65 |
| `cake_enqueue` | 12 | 53 |
| `cake_select_cpu` | 10 | 30 |
| `cake_stopping` | 17 | 23 |
| `cake_pick_idle_clean` | 16 | 22 |

This is an existing **unpruned build object**. No exact source/binary receipt was established for it here. Diagnostic and topology branches can disappear during loading, not all stack accesses are register-pressure spills, and a function's alternative paths do not all execute on each invocation. The census is unsuitable for multiplying by a fixed ns/access figure. Its `insns` column also counts relocation lines; the table above uses only its stack-access columns. The simulation's separate instruction parser excludes relocation lines. The inspected live sched_ext state was `disabled`; no scheduler was activated.

**Experiment A: six small values across one native scalar operation.**

Six byte-sized inputs, masked to nibbles, are consumed after a scalar call. The result combines additions, products, XORs and shifts so the values really remain needed after the call. This is an intentionally synthetic pressure case, not a reconstruction of any Cake callback. The native replay substitutes POPCNT for the hypothetical kfunc in every variant, including ordinary-call variants.

| Variant | BPF instructions, including exit | Stack stores + loads |
|---|---:|---:|
| Separate values, ordinary declaration | 41 | 2 + 2 |
| Packed expression, ordinary declaration | 45 | 2 + 2 |
| Force one packed value across the call | 61 | 0 + 0 |
| Separate values, fastcall attribute before removal | 43 | 3 + 3 |
| Separate values, modeled fastcall pair removal | 37 | 0 + 0 |
| Packed expression, modeled fastcall pair removal | 41 | 0 + 0 |

Clang partly scalarized the ordinary packed expression, so it did not remove spills. A zero-byte inline-assembly barrier keeping the packed word opaque did remove them, but added 20 BPF instructions. Such a barrier can impede optimization and verifier range reasoning; it is an experimental control, not a recommendation to add barriers throughout Cake.

The fastcall-removal variants delete exactly the inspected three stores/three reloads immediately around the call. They assume a correct preserving implementation and do not demonstrate kernel verifier acceptance. The lowerer fails on unknown instructions; generated native replay functions passed 70,000 result comparisons against an independent scalar reference.

LLVM MCA 22.1.8, `-mcpu=znver5`, 500 repetitions of the modeled native body:

| Variant | Independent inputs, noalias=true | Independent inputs, noalias=false | Dependent inputs, noalias=true |
|---|---:|---:|---:|
| Separate values, ordinary | 7.026 | 14.032 | 9.020 |
| Ordinary packed expression | 7.746 | 14.044 | 21.020 |
| Forced packed word | 11.034 | 11.034 | 11.038 |
| Separate values, modeled fastcall removal | 6.358 | 6.358 | 9.018 |
| Packed expression, modeled fastcall removal | 7.882 | 7.882 | 21.020 |

Units are **modeled cycles per repeated body**, not measured cycles or nanoseconds. Different alias assumptions change the ranking of forced packing against the baseline. This is a reason not to claim a packing win from the model. MCA does not model store-to-load forwarding or cache misses, and these alias settings are sensitivity scenarios rather than reliable upper/lower bounds. Models omit actual callback/trampoline/frame costs, frontend fetch effects and other threads. Native bodies follow the inspected register mapping and BMI2 shift strategy but are not captured kernel-JIT output. [LLVM MCA limitations](https://llvm.org/docs/CommandGuide/llvm-mca.html#load-store-unit-and-memory-consistency-model).

**Experiment B: a true SWAR operation.**

Increment every one of sixteen nibble counters, saturating each at 15. Instead of extracting/editing/repacking all sixteen, identify full lanes and add one only in the others:

```c
const u64 ones = 0x1111111111111111ULL;
u64 full = word & (word >> 1) & (word >> 2) & (word >> 3) & ones;
return word + (ones ^ full);
```

For each nibble, the lowest bit in `full` is one exactly when all four bits were one. A full lane gets no increment; every other lane gets one, so no carry escapes a nibble. This retains all neighboring fields and handles an all-ones word.

| Implementation | Static BPF instructions | Executed BPF instructions in the model | Stack stores + loads |
|---|---:|---:|---:|
| Extract/update/repack, explicitly unrolled | 167 | 116–167 | 9 + 9 |
| Extract/update/repack, bounded loop | 17 | 164–212 | 0 + 0 |
| SWAR, all sixteen together | 15 | 15 | 0 + 0 |

Counts include exit and count a wide immediate as one instruction, not two encoding slots. The bounded loop demonstrates why code size and executed work must be separated. The branch-aware interpreter checks the emitted BPF subset on 1,016 inputs per variant, including every uniform nibble pattern and random full words. It is a semantic model, not the kernel verifier/interpreter. The C variants also passed 100,016 native differential cases under UBSan. The code uses only existing scalar BPF operations; no SIMD register or new opcode is involved.

This is a strong instruction-count result for a suitable operation. It does **not** establish a current Cake path that needs sixteen simultaneous saturating increments, nor an 11x runtime gain. Arbitrary unrelated fields do not acquire this benefit merely by sharing a word.

**Extraction and edits can already be small.** The standalone fixed-position getter is four BPF instructions including argument/result movement and exit: the field operation itself is a shift and mask. Fixed-position replacement is six; variable-position replacement is eleven. Updating a known field directly avoids fully unpacking the word. Boolean fields need one bit, not a whole nibble. Values must retain their required range; CPU IDs on wider hosts cannot be assumed to fit four bits.

Cake already has packed small state: `cake_run_slot.hint` combines `CAKE_HINT_WOKE` with a saturating confidence field (`CAKE_HINT_CONF_MAX = 3`). That is an existing packed representation, not proof of reduced register pressure. Candidate local flags could potentially be carried together, but timestamps, full CPU masks, arbitrary counters and verifier-tracked pointers cannot simply be truncated or mixed into nibble values. Shared-memory layout changes also have concurrency effects separate from local-register packing.

**Validation and reproduction.**

```sh
python scheds/rust/scx_cake/docs/research/isa-opportunities-20261001/simulate-packing.py
```

Inputs: [register-packing.c](register-packing.c) and [simulate-packing.py](simulate-packing.py). Output: [simulation.json](../../../../../../target/cake_register_pressure_20261001/simulation.json), [BPF assembly](../../../../../../target/cake_register_pressure_20261001/packing.bpf.asm), [native replay assembly](../../../../../../target/cake_register_pressure_20261001/replay.S), [Cake object census](../../../../../../target/cake_register_pressure_20261001/cake-object-stack-census.txt), and per-variant MCA reports in the same directory. The script records exact commands, toolchain versions, hashes and evidence limits. Re-running refreshes that output directory.

All builds passed with warnings treated as errors. Native UBSan tests passed 1,700,000 field cases, 100,000 call-input cases and 100,016 SWAR cases. Native replay passed 70,000 checks; the BPF lane model passed 3,048 checks. No BPF program was loaded and no hardware performance benchmark was run.

The justified next experiment is a source-identified Cake hot path whose loaded spills are attributable to several small scalars with overlapping lifetimes. Compare shorter lifetimes, safe fastcall and selective packing; retain the same policy and input ranges. Measure callback ns, total BPF CPU and latency tails after verifier/JIT inspection. Bulk SWAR deserves a separate experiment only where the existing policy already calls for the same operation on multiple small fields.
