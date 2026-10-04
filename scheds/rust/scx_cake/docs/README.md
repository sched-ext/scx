# Cake documentation map

Current source and STATE come first; dated documents describe the builds they
examined. Paths stay stable for existing citations.

## Start here

| Need | Document |
|---|---|
| Build, flags, stock vs custom kernel, limits | [README](../README.md) |
| Current scheduling behaviour | [DESIGN](../DESIGN.md) |
| Current status, pattern ledger, owed work | [STATE](../STATE.md) |
| Rules | Repository-root `CLAUDE.md` (local) |
| Measurement method and limits | [PERFORMANCE](PERFORMANCE.md) |
| Instruction and kernel-call costs | [Cost audit](AUDIT_OPERATION_COST_2026-09-15.md) |
| Kernel patch research | [research index](research/README.md) |
| September 28 nightly game evidence | [KovaaK's A/B](KOVAAKS_KICK_ABBA_2026-09-28.md) |
| Tools | [bench](../bench/README.md), [TOOLING](TOOLING.md) |
| File inventory and layout | [STRUCTURE](STRUCTURE.md) |
| Meeting page | [meeting/index.html](meeting/index.html) |
| History, rejected ideas | [archive](archive/README.md), `archive/STATE_ARCHIVE.md` |

## Folders

| Location | Holds |
|---|---|
| `src/`, `src/bpf/` | Loader and BPF scheduler source |
| `tests/` | CLI tests; unit tests live in the Rust source |
| `bench/` | Offline models and diagnostics |
| `veristat/` | Verifier fixture (`9950x.json`), not a topology certification |
| `docs/` | Standing references and dated evidence |
| `docs/research/<topic>/` | Investigations and patch bundles, each with a README stating its limits |
| `docs/archive/` | Settled reviews, plans and the STATE archive |
| `../../../target/` | Builds and test arms (`cake_receipt_builds/`) |
| `scx_cake_bench/` (sibling repo) | Measurement tools and run outputs (`runs/`) |

## Dated references

| Document | Role |
|---|---|
| [Kernel tool inventory](KERNEL_TOOL_INVENTORY_2026-08-23.md) | Kernel capability survey; verify against the target kernel |
| [RT placement](RT_PLACEMENT_LOGIC_2026-07-24.md) | Placement rationale |
| [Predict/verify audit](AUDIT_PREDICT_VERIFY_2026-08-22.md) | Cost and design reasoning |
| [ADPF/LLF](RESEARCH_ADPF_LLF_2026-08-09.md), [new constructs](RESEARCH_NEW_CONSTRUCTS_2026-08-17.md), [construct theory](THEORY_CONSTRUCTS_ABC_2026-08-17.md) | Candidate mechanisms, not defaults |
| [Signals audit](SIGNALS_AUDIT_2026-08-17.md) | Signal inventory |
| [G21/G23 review](REVIEW_G21_G23_2026-08-02.md), [Diablo analysis](ANALYSIS_DIABLO_CHOP_2026-08-02.md) | Construct review, workload diagnosis |

## Keeping it tidy

- New investigation: `docs/research/<topic>/README.md` with source base, question,
  evidence, result, kernel requirement and open gates.
- Bulk measurement output stays in `scx_cake_bench/runs/`; link it, don't copy it.
- STATE carries conclusions; README and DESIGN change only with behaviour.
- Archive a finished investigation after fixing inbound links.

Older bulk scratch lives in `scx_cake_bench/history/imported_from_scx_repo/`
(restore with `zstd -dc <tarball> | tar -xf -`); deleted docs are in Git history
(`git log --diff-filter=D --name-only -- scheds/rust/scx_cake/docs/`).
