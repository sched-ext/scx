# Cake documentation and folder map

Reviewed 2026-09-29. Start with current source and status; dated documents retain
claims about the exact builds they examined. Paths are kept stable for existing
citations and evidence manifests.

## Start here

See the [structure map and complete file inventory](STRUCTURE.md) for a diagram,
Git/local-file distinctions, and proposed improvements to the physical layout.

| Need | Document |
|---|---|
| Build, supported flags, hardware limits | [User README](../README.md) |
| Current scheduling behavior | [Design](../DESIGN.md) |
| Current status and open validation | [State](../STATE.md), newest entry first |
| Local development rules | Repository-root `CLAUDE.md` and `.agents/AGENTS.md` (local files, not distributed docs) |
| Measurement method and result limits | [Performance](PERFORMANCE.md) |
| September 28 nightly game evidence | [KovaaK's A/B report](KOVAAKS_KICK_ABBA_2026-09-28.md) |
| Instruction costs and JIT proposal | [Cost audit](AUDIT_OPERATION_COST_2026-09-15.md), [research index](research/README.md) |
| Unary fastcall patch and further kernel optimizations | [Release/VM findings and scoped next experiments](research/jit-bitops-prototype/FASTCALL_KERNEL_REVIEW_2026-10-01.md) |
| Kernel DSQ caching prototype and simulation | [Direct index implementation, results and open debug gate](research/jit-bitops-prototype/DSQ_DIRECT_INDEX_2026-10-02.md) |
| Meeting presentation | [Local meeting page](meeting/index.html) |
| Tools and commands | [Bench index](../bench/README.md), [tool inventory](TOOLING.md) |
| Previous decisions and rejected ideas | [Archive index](archive/README.md) |

The old `sched-ext-dev` skill path in historical notes is absent in this checkout.
This session used the installed `sched-ext-development` skill. Consult the skills
available in your environment instead of assuming that old path exists.

## Folder ownership

| Location | Purpose and handling |
|---|---|
| `src/`, `src/bpf/` | Maintained Rust loader and BPF scheduler source; the root README maps individual files |
| `Cargo.toml`, `build.rs` | Package definition and BPF build integration |
| `src/bpf_skel.rs`, `src/bpf_intf.rs` | Source wrappers including generated files from Cargo OUT_DIR; keep the wrappers in source |
| `tests/` | CLI integration tests; additional unit tests are in Rust source |
| [bench/](../bench/README.md) | Offline models and diagnostics, plus explicit retired launcher stubs |
| `veristat/` | Retained verifier fixture (`9950x.json`), not a live topology certification |
| `.cargo/` | Local Cargo configuration; currently sets target-cpu=native when applicable. Build from the workspace root as documented for normal builds |
| `.codegraph/` | Local generated code index, not policy documentation or measurement evidence |
| `docs/` | Standing references and named dated evidence cited by current records |
| [research/](research/README.md) | Self-contained investigations and experimental patch bundles; each declares its validation limits |
| `docs/meeting/` | Presentation derived from the research; technical status belongs in the linked research README |
| [archive/](archive/README.md) | Historical reviews, plans and the old state ledger |
| Repository `target/` | Build outputs and isolated candidate worktrees; preserve candidates referenced by experiments |
| Sibling `scx_cake_bench/` | Maintained measurement tooling, receipts, captures, run outputs and historical vault |

## Standing references and dated research

| Document | Role |
|---|---|
| [Operation cost audit](AUDIT_OPERATION_COST_2026-09-15.md) | Cost ladder and hardware/BPF/JIT evidence distinctions; includes September 29 additions |
| [Kernel tool inventory](KERNEL_TOOL_INVENTORY_2026-08-23.md) | Dated kernel capabilities survey; verify against the target kernel |
| [RT placement](RT_PLACEMENT_LOGIC_2026-07-24.md) | Dated placement rationale |
| [Predict/verify audit](AUDIT_PREDICT_VERIFY_2026-08-22.md) | Historical cost/design reasoning |
| [ADPF/LLF research](RESEARCH_ADPF_LLF_2026-08-09.md) | Candidate mechanisms, not accepted default behavior |
| [New constructs](RESEARCH_NEW_CONSTRUCTS_2026-08-17.md) | Candidate mechanism survey |
| [Construct theory](THEORY_CONSTRUCTS_ABC_2026-08-17.md) | Supporting theory |
| [Signals audit](SIGNALS_AUDIT_2026-08-17.md) | Dated signal inventory |
| [G21/G23 review](REVIEW_G21_G23_2026-08-02.md) | Dated construct review |
| [Diablo analysis](ANALYSIS_DIABLO_CHOP_2026-08-02.md) | Historical workload diagnosis |

## Keeping this organized

Put runnable source in `src/`, reusable diagnostics in `bench/`, and a new
investigation in `docs/research/<topic>/` with a README recording its source base,
question, evidence, result and pending gates. Store bulk measurement output in
`scx_cake_bench/runs/`; link it instead of copying captures into docs. Keep raw
hash-bound research artifacts at their recorded paths.

Update STATE for current conclusions and README/DESIGN only when supported
behavior changes. Archive a completed investigation only after updating inbound
links; retain dates, negative results and raw-evidence references. Do not delete
scratch or candidates merely because their conclusion was summarized.

The package ignore rules now expose research sources, retained evidence, patches
and the meeting page to Git, while excluding research builds and Python caches.
New files are **eligible for tracking, not automatically staged or committed**.
Check `git status --short --untracked-files=all` before sharing; local absolute
paths in provenance identify this machine and are not portable dependencies.

## The vault (bulk data and untracked scratch)

Under `~/Documents/Repo/scx_cake_bench/history/imported_from_scx_repo/`, following
`scx_cake_bench/COMPACTION_2026-08-01.md`.

| archive | contents |
|---|---|
| `scx_cake_docs_2026-09-15/docs_untracked_scratch_2026-05_to_2026-06.tar.zst` (156 KB, 109 entries) | `*_2026-05-23.{tsv,json,jsonl}`, `benchmark_ml_attempts_since_2026-05-22.jsonl`, `active_path_help_hurt_synthesis_2026-05-23/`, `benchmark_help_hurt_deep_dive_2026-05-23/`, `benchmark_perf_correlation_workbook_2026-05-23/`, `research/`, `superpowers/`, `glm-5.2-findings/` |
| `scx_cake_docs_2026-08-06/docs_analysis_2026-05-23.tar.zst`, `docs_session_notes_pre_2026-07.tar.zst` | **not found at the documented path on 2026-09-15** — the 2026-08-06 restructure recorded them here (253 MB → 8.5 MB; 1.04 MB → 228 KB). Locate before relying on them |

Restore:

```bash
mkdir -p /home/ritz/Documents/Repo/scx_cake_bench/history/restored_docs
zstd -dc <tarball> | tar -xf - -C /home/ritz/Documents/Repo/scx_cake_bench/history/restored_docs
```


The earlier September 15 cleanup archived old `research/` scratch. The current
`research/` directory contains new September 29 investigations, not restored old
scratch. Older deleted documents can also be recovered from Git history:

```sh
git log --oneline --diff-filter=D --name-only -- scheds/rust/scx_cake/docs/archive/
```

`APP_SIMULATION.md` references in older notes refer to the companion repository's
`scx_cake_bench/docs/APP_SIMULATION.md`.
