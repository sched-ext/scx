Cake native-operation research — 2026-10-01
==========================================

**Recommendation:** first investigate fastcall for the existing scalar bitops, with a verifier/JIT agreement about when register preservation is guaranteed. The generic compiled-kfunc inlining proposed on the mailing list is a useful longer-term implementation direction. Neither adding a flag nor copying an arbitrary function body is sufficient. Keep quotient fusion experimental; defer wide-host atomic changes for the 9800X3D; treat histogram changes as diagnostic overhead work.

This work changes no Cake scheduling source, installs no kernel, loads no BPF, and activates no scheduler. It adds reproducible standalone compiler probes and offline correctness checks. There are no new timing measurements or FPS results.

Follow-up: [register-pressure, packed-bitfield and SWAR simulation](PACKING_SIMULATION.md) includes compiler spill comparisons, a Zen 5 instruction-scheduling model, and branch-aware BPF execution of a sixteen-nibble update.

**Source and environment identity.** The checkout is dirty at scx commit `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a`; the commit alone does not identify the inspected code. Per-file SHA-256 values and commands are in [summary.json](../../../../../../target/cake_isa_research_20261001/summary.json). Clang is 22.1.8. BPF probes use `-target bpf -mcpu=v3 -O2`; native probes use `-O2 -march=znver5`. The running kernel reports `7.2.8-1-cachyos-custom`, and online CPUs are `0-15`. Kernel ABI conclusions below use the retained CachyOS 7.2.8 source at `target/cake_jit_bitops_20260929/cachyos-7.2.8-port/linux`. That source was not freshly matched to the booted image in this investigation.

| Candidate | Finding in the current source | Priority for this host |
|---|---|---|
| Fastcall around scalar bitops | Compiler and retained kernel already contain the mechanism. Cake's declarations and combined scalar patch do not enable it. MULHI and fallback calls need special care. | First experiment; scheduling decisions can stay identical. |
| Carry and combined shifts | Quotient finish can use a short native sequence. Clang also found `SETB + SHLD`, so `ADC + SHRD` is not the only candidate. | Only with `--division-free`; measure the complete quotient against division. |
| Atomic old-bit operations | Wide-host idle occupancy needs only the old bit, a match for `LOCK BTS/BTR`. Other atomic results are often unused already. | Matching occupancy path is bypassed by this host's one-word mode. |
| Logarithmic histogram buckets | Exact CLZ formulation exists. Ordinary BPF `__builtin_clzll` expands substantially with the tested compiler settings. | Useful with diagnostics enabled; no default-path benefit demonstrated. |

**1. Fastcall: available infrastructure, but a real ABI contract.**

Relevant current source:

- [Cake native declarations and wrappers](../../../src/bpf/cake.bpf.c), at the beginning of the file.
- [Combined CachyOS scalar patch](../jit-bitops-prototype/0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch).
- Retained kernel `include/linux/btf.h`: `KF_FASTCALL`; `kernel/bpf/verifier.c`: `bpf_get_call_summary()` and the fastcall contract; `kernel/bpf/fixups.c`: `bpf_remove_fastcall_spills_fills()`.

The Clang `bpf_fastcall` declaration attribute changes register allocation and adds recognizable compatibility saves/restores. The kernel can remove those pairs when it knows the implementation preserves the relevant registers. This is a compiler, verifier and implementation agreement. The attribute is documented in [Clang's attribute reference](https://clang.llvm.org/docs/AttributeReference.html#bpf-fastcall).

For a non-void function with two scalar arguments, R0 is the result and R1/R2 may be overwritten; R3–R5 must survive. On x86, BPF R3 maps to RDX. The existing MULHI JIT body is:

```asm
mov rax, rdi
mul rsi          ; result in RDX:RAX
mov rax, rdx
```

It is valid for the current ordinary call convention. It would violate the two-argument fastcall contract because RDX is not restored. This is not a newly discovered bug in the current ordinary-call patch; it is a blocker to simply adding `KF_FASTCALL`.

One possible preserving sequence uses the disposable first argument register:

```asm
mov rax, rdi
mov rdi, rdx     ; preserve BPF R3 in the consumed R1
mul rsi
mov rax, rdx
mov rdx, rdi     ; restore BPF R3
```

The offline probe checks this sequence's product and RDX preservation over 200,196 input cases. It costs two additional register moves compared with the original body, which must be included in any benefit calculation. This is a sequence prototype, not a patched or loaded kernel implementation.

Fallback also matters. The retained kernel sets a kfunc call's fastcall summary directly from `KF_FASTCALL`. A CPU-feature fallback to an ordinary compiled C function can clobber more registers. Removing the caller's saves while retaining that fallback can corrupt live values. Either guarantee the actual fallback also preserves the registers, or condition the verifier's fastcall summary on the implementation that will really run. Interpreter behavior must also be included in that agreement.

Leon Hwang's [February 19 v2 generic patch](https://lists.openwall.net/netdev/2026/02/19/109) already proposed querying whether the JIT will inline the kfunc before applying fastcall to those JIT calls. Its [x86 companion](https://lists.openwall.net/netdev/2026/02/19/110) preserves RCX around variable rotates. These are useful design precedents, not evidence that the local scalar patch contains those changes.

Fresh standalone BPF compiler output, including the call and exit:

| Probe | Normal declaration | Fastcall declaration, before kernel rewriting | Explicit save/load instructions in fastcall version | Size if all matching pairs are removed |
|---|---:|---:|---:|---:|
| One argument, four other values live | 11 | 15 | 8 | 7 |
| Two arguments, three other values live | 9 | 12 | 6 | 6 |

The final column is arithmetic based on the inspected pattern, not a verifier/JIT result. Both normal probes use callee-saved BPF registers and have **zero explicit BPF stack accesses**. Therefore the claim should be reduced register movement/pressure, with possible stack savings in larger functions, rather than a claim that every existing call spills. Actual Cake call sites and native prologues must be inspected after loading.

**2. The mailing-list proposal: inspect compiled native code, then inline it.**

The quoted proposal appears in [Alexei Starovoitov's discussion of the bitops series](https://lists.openwall.net/netdev/2026/02/20/124). In a [follow-up](https://lists.openwall.net/linux-kernel/2026/02/21/332), he points to existing x86/arm64 instruction decoding used by kprobes and suggests fastcall as the candidate marker. Leon later [said he would prepare an RFC after a proof of concept](https://lists.openwall.net/netdev/2026/02/23/203). Those messages establish the design discussion; this investigation does not establish a later upstream merge or availability of a generic inliner in the booted kernel.

The proposed flow is: compile a kernel kfunc normally; inspect its actual machine instructions when deciding whether it can be inlined; establish its register and control-flow properties; insert the eligible body into the BPF JIT output without its function return. Decoder work happens during preparation/JIT compilation, not on each scheduler callback.

The attraction is maintenance and reuse: one implementation can supply both normal calls and inlined native code, instead of an opcode encoder for every operation on every architecture. It could also help fused arithmetic that currently has no direct BPF opcode. Architecture-specific decoding and eligibility analysis would still exist.

Our standalone native compiler output illustrates both the opportunity and the limitation:

```asm
body_clz:                    body_popcnt:
    lzcnt rax, rdi               popcnt rax, rdi
    ret                          ret

body_mulhi:
    mov rdx, rsi
    mulx rax, rax, rdi
    ret
```

The two unary bodies touch only their result register. MULHI still overwrites RDX/BPF R3 even though Clang chose BMI2 `MULX`. A checker should not approve that body under the two-argument fastcall promise. These are userspace compiler objects, not kernel objects built with kernel instrumentation and configuration.

My engineering assessment: start with small scalar leaf bodies and reject unsupported cases. A decoder tells us how an instruction is encoded; a safe inliner must additionally establish:

- Explicit and implicit register effects, including MUL's implicit RDX output and variable shifts' use of CL. Save/restore sequences need preservation analysis if accepted.
- Correct function boundaries and exits. Kernel builds can contain return thunks, entry instrumentation, padding or multiple exits; the last byte is not reliably a removable `RET`.
- Copying safety for PC-relative data, external branches, stack references and exception-table entries. Such cases need relocation/metadata handling or rejection. Internal relative branches can sometimes remain valid if their layout is preserved.
- Applicable CPU features and kernel text changes. Copying bytes does not turn generic compiler output into Zen 5-specific code, nor make every CPU instruction legal in kernel/BPF context.
- A consistent fallback before fastcall saves are removed, plus normal BPF kfunc argument/memory checks and module lifetime rules.

The local x86 decoder is real: `arch/x86/include/asm/insn.h` declares `insn_decode()` and `insn_rip_relative()`; `arch/x86/kernel/kprobes/core.c` already handles relative-address issues when copying instructions. Reusing that infrastructure does not eliminate the eligibility analysis above.

If a copied body and the current manual emitter produce identical machine instructions, their arithmetic cost is identical. Speed comes from selecting a better body and removing call/register overhead. Raw machine-code copying also does not give the compiler full cross-boundary constant folding or register allocation as C source inlining would.

**3. Quotient finish: fuse the calculation, including its carry.**

[quotient.bpf.h](../../../src/bpf/quotient.bpf.h) computes a high product, adds it to the numerator, then combines the low sum and its carry:

```c
sum = numerator + hi;
q = (sum >> (64 - shift)) | ((u64)(sum < numerator) << shift);
```

After the current early returns, `shift` is in 1–63. This equals the low 64 bits of the 65-bit sum shifted right by `64 - shift`. A fused operation can capture carry immediately after ADD and use SHRD. The offline prototype uses `XOR; ADD; ADC; SHRD`, with count setup outside that sequence.

However, compiling the original expression directly for Zen 5 produced `XOR; ADD; MOV; SETB; SHLD; RET`. That is another suitable candidate, and the offline test validates the corresponding SHLD arithmetic. Prefer a fused arithmetic API with defined input ranges over exposing a separate carry flag: intervening generated instructions may overwrite x86 flags, and BPF has no general persistent carry-flag register.

This isolated expression is 12 BPF instructions with one conditional branch in the tested BPF object. That is not a native-cycle comparison. A three-argument fastcall still has to preserve R4/RCX, despite variable SHLD/SHRD using CL; count setup and any preservation must be included. No separate compelling SBB hot path was identified in this inspected quotient.

A shorter finish cannot establish that division-free wins. Reciprocal refinement, high multiplies, special cases, final correction, ABI costs and dependencies all remain. Test the full quotient against hardware division with Cake's divisor distribution and both dependent and independent workloads. Keep `--division-free` off by default until that evidence exists.

**4. Atomic test-and-set/clear: an exact match in a bypassed path.**

In `cake_update_idle()`, after the `cake_one_word` early return, Cake tests one bit of the old value returned by fetch-OR/fetch-AND. A bounded native `LOCK BTS/BTR` plus carry-to-boolean operation can express this without a compare-exchange retry loop. The [kernel x86 bitops implementation](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/bitops.h) already uses these instructions for its bit-test operations.

This differs from returning the entire previous word: BTS/BTR returns the old bit in CF, not the old 64-bit value. A generic replacement of BPF fetch-OR/AND would be wrong. Likewise, when the old value is unused, the x86 BPF JIT already has direct locked OR/AND paths; there is no retry loop to remove there. The inspected native compiler probe still emitted CMPXCHG loops for the old-bit C expressions, so source-level spelling alone does not guarantee BTS/BTR.

The bit index must be bounded to 0–63 for a verified single 64-bit word: x86 memory bit-test instructions otherwise can address a different word. Preserve writable-memory validation, alignment, ordering and the idle-count protocol. An explicit kfunc needs its own safe memory contract; a JIT pattern transformation must prove only the tested bit is observable.

The current host is in the one-word topology class, so the matching occupancy code is bypassed. The 65,536 offline cases validate old-bit and new-word values for both instructions; they do not test concurrent updates or scheduler liveness. Larger-host contention measurements would be the relevant performance experiment.

**5. Histogram CLZ: exact buckets, conditional diagnostic benefit.**

`cake_release_band()` uses shift 10 and 8 buckets; `cake_hist_band()` uses shift 8 and 16 buckets. Both are equivalent to:

```c
v = (ns >> SHIFT) | 1;
band = min(63 - clz64(v), BANDS - 1);
```

The `| 1` preserves bucket zero for zero and one and prevents a zero-input CLZ result of 64 from being broken by the existing `& 63` range bound. Apply the clamp to retain saturation behavior.

| Standalone BPF function | Current loop expression | Ordinary builtin CLZ | Native-CLZ kfunc expression |
|---|---:|---:|---:|
| 8-bucket release band | 16 | 44 | 8, including one call |
| 16-bucket general band | 32 | 44 | 8, including one call |

These are static disassembly instruction counts, including exit, before verification/JIT. They are not executed instruction counts, BPF slot counts or cycle estimates, and the kfunc body is excluded. The loop can exit early. A bare builtin change can increase code size on the tested BPF target; use actual native lowering and measure the real value distribution before calling it a win.

The callers are behind `cake_tog_probe`. Improving these buckets can reduce measurement overhead with diagnostics enabled, but should not be advertised as a default scheduling improvement.

**Reproduction and evidence.** Run from the scx root:

```sh
python scheds/rust/scx_cake/docs/research/isa-opportunities-20261001/run_research.py
```

The script snapshots the current quotient header, records hashes, compiles both targets, saves disassemblies, and runs native correctness checks with undefined-behavior sanitization. It writes under `target/cake_isa_research_20261001/`. Re-running refreshes that evidence directory; hashes identify the exact run's inputs.

| Offline check | Cases | Result |
|---|---:|---|
| 65-bit finish: original vs wide reference vs ADC/SHRD and SHLD variants | 642,348 | Zero mismatches |
| Complete original and ADC/SHRD candidate quotient vs unsigned division | 438,596 | Zero mismatches |
| Both histogram layouts, including zero, edges and saturation | 2,497,564 | Zero mismatches |
| Atomic old-bit/new-word semantics, single thread | 65,536 | Zero mismatches |
| MULHI product and RDX preservation | 200,196 | Zero mismatches |

All compilation commands succeeded with `-Wall -Wextra -Werror`; the validation run reported no UBSan errors. These 3,844,240 cases are finite input checks, not formal proof, concurrent correctness, BPF verifier acceptance or performance evidence. [Raw validation](../../../../../../target/cake_isa_research_20261001/validation.json), [BPF disassembly](../../../../../../target/cake_isa_research_20261001/probes.bpf.asm), [native disassembly](../../../../../../target/cake_isa_research_20261001/probes.x86.asm), and [archived mailing-list source manifest](../../../../../../target/cake_isa_research_20261001/references/manifest.json) are retained.

For the next implementation experiment, first add safe fastcall eligibility for unary native bitops. Check live registers across calls, feature-disabled fallbacks and exact loaded JIT output. Handle MULHI separately with its preservation cost visible. Then use the maintained Cake benchmark receipt workflow for callback nanoseconds, total BPF cost, wake-to-run/frame tails and throughput. Record tiny positive deltas as such, with dispersion and regressions. A reduction in static instruction count alone cannot settle scheduler performance.
