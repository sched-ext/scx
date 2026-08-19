# scx_cake/docs — what is here, and where the rest went

**2026-08-18 restructure:** docs root now holds only live design and evidence
files; everything from a completed campaign sits in [`archive/`](archive/);
local scratch was deleted (recoverable from the vault or never worth keeping).
Earlier, the 2026-08-06 cleanup moved 261 MB / 149 files to the vault —
nothing from that cleanup was deleted either.

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
| `docs/` (root) | live material only: active investigations, standing references, registered research |
| [`archive/`](archive/) | one file: the EEVDF campaign gate log. Every other dated record lives in git history |
| `research/` | local scratch, never tracked, never cited from canonical files |

The archive was pruned to one file on 2026-08-18. Conclusions live in
`STATE.md` (ledger + `§` registry); the dated records behind them are in
git history. To read a removed record:

```bash
git log --oneline --diff-filter=D --name-only -- "scheds/rust/scx_cake/docs/archive/" | head -40
git show "<deleting-commit>^:scheds/rust/scx_cake/docs/archive/<file>.md"
```

## The vault (bulk data from 2026-08-06)

Both archives are under
`~/Documents/Repo/scx_cake_bench/history/imported_from_scx_repo/scx_cake_docs_2026-08-06/`,
following the precedent in `scx_cake_bench/COMPACTION_2026-08-01.md`.

| archive | was | now | contents |
|---|---|---|---|
| `docs_analysis_2026-05-23.tar.zst` | 253 MB, 122 files | **8.5 MB** (30×) | `ml_analysis_*`, `benchmark_asset_*`, `perf_helps_hurts_atlas`, `code_pattern_matrix`, `full_suite_mesh`, `positive_code_patterns`, `mixed_cache_memcpy_*`, 4× `frames_*.csv` |
| `docs_session_notes_pre_2026-07.tar.zst` | 1.04 MB, 78 files | **228 KB** | dated session notes older than 30 days, none tracked, none cited |

Restore any of it:

```bash
zstd -dc ~/Documents/Repo/scx_cake_bench/history/imported_from_scx_repo/scx_cake_docs_2026-08-06/docs_analysis_2026-05-23.tar.zst | tar -xf - -C /tmp
```

## Selection rule

Root keeps a doc only while it is live: cited from a canonical file or source,
or backing an open experiment. A completed campaign's evidence moves to
`archive/`; scratch whose conclusions are registered in `STATE.md`'s `§` registry is
deleted — git history and the vault are the backstop.

Note: `APP_SIMULATION.md` is cited in older material as a local path; the real
file lives in the companion repo at `scx_cake_bench/docs/APP_SIMULATION.md`.
