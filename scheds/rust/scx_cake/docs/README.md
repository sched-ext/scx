# scx_cake/docs — what is here, and where the rest went

**2026-09-15 tidy:** root holds live material only (cited from `STATE.md`, source,
or backing an open experiment). Completed dated reviews and analyses moved to
[`archive/`](archive/) and are tracked there. Untracked 2026-05/06 bulk data and
scratch (`*_2026-05-23.*`, `research/`, `superpowers/`, `glm-5.2-findings/`) went to
the vault tarball below and were removed here. Earlier restructures: 2026-08-18
(root pruned to live files) and 2026-08-06 (261 MB / 149 files to the vault).

`docs/*` is gitignored (`.gitignore:2`). `docs/archive/` and an explicit
whitelist of docs-root files are tracked; anything else here exists only on
this machine. **If a doc is worth citing from `STATE.md`,
whitelist and track it** — a citation to an untracked file is a dangling
reference for everyone else.

## Start here, not in a dated file

| Question | Where |
|---|---|
| Current state, scoreboard, open gaps | [`../STATE.md`](../STATE.md) |
| Which experiment to run next | the `§` registry in [`../STATE.md`](../STATE.md) |
| Rules, design laws, invariants | [`../CLAUDE.md`](../CLAUDE.md) |
| How the scheduler behaves | [`../DESIGN.md`](../DESIGN.md) |
| How to build / bench | the `sched-ext-dev` skill |

## Layout

| Location | Holds |
|---|---|
| `docs/` (root) | live material only: standing references (`TOOLING.md`, `KERNEL_TOOL_INVENTORY`, `RT_PLACEMENT_LOGIC`, `PERFORMANCE.md`), the current cost audit (`AUDIT_OPERATION_COST_2026-09-15.md`), registered research, and the dated files `STATE.md` cites |
| [`archive/`](archive/) | completed dated reviews, audits, plans and the EEVDF campaign gate log; tracked, so a `STATE.md` citation into it resolves for everyone |

Conclusions live in `STATE.md` (ledger + `§` registry). Records pruned from
`archive/` on 2026-08-18 are in git history:

```bash
git log --oneline --diff-filter=D --name-only -- "scheds/rust/scx_cake/docs/archive/" | head -40
git show "<deleting-commit>^:scheds/rust/scx_cake/docs/archive/<file>.md"
```

## The vault (bulk data and untracked scratch)

Under `~/Documents/Repo/scx_cake_bench/history/imported_from_scx_repo/`, following
`scx_cake_bench/COMPACTION_2026-08-01.md`.

| archive | contents |
|---|---|
| `scx_cake_docs_2026-09-15/docs_untracked_scratch_2026-05_to_2026-06.tar.zst` (156 KB, 109 entries) | `*_2026-05-23.{tsv,json,jsonl}`, `benchmark_ml_attempts_since_2026-05-22.jsonl`, `active_path_help_hurt_synthesis_2026-05-23/`, `benchmark_help_hurt_deep_dive_2026-05-23/`, `benchmark_perf_correlation_workbook_2026-05-23/`, `research/`, `superpowers/`, `glm-5.2-findings/` |
| `scx_cake_docs_2026-08-06/docs_analysis_2026-05-23.tar.zst`, `docs_session_notes_pre_2026-07.tar.zst` | **not found at the documented path on 2026-09-15** — the 2026-08-06 restructure recorded them here (253 MB → 8.5 MB; 1.04 MB → 228 KB). Locate before relying on them |

Restore:

```bash
zstd -dc <tarball> | tar -xf - -C /tmp
```

## Selection rule

Root keeps a doc only while it is live: cited from a canonical file or source,
or backing an open experiment. A completed campaign's evidence moves to
`archive/`; scratch whose conclusions are registered in `STATE.md`'s `§` registry is
deleted — git history and the vault are the backstop.

Note: `APP_SIMULATION.md` is cited in older material as a local path; the real
file lives in the companion repo at `scx_cake_bench/docs/APP_SIMULATION.md`.
