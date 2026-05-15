# scx_cake Benchmark History

This repo has a local benchmark-history layer for `scx_cake` work. It is meant
to keep scheduler mutation runs, historical benchmark results, git state, and
score comparisons in one durable place so future AI sessions do not rely on chat
memory for performance claims.

The benchmark artifacts live outside this checkout by default:

```text
/home/ritz/Documents/Repo/scx
  cakebench
  tools/cakebench_history.py
  tools/tests/test_cakebench_history.py

/home/ritz/Documents/Repo/scx_cake_bench_assets
  cakebench
  runs/
  history/
```

Override the asset repo with `SCX_CAKE_BENCH_REPO=/path/to/scx_cake_bench_assets`
when needed.

## What Gets Recorded

Every recorded run points back to the raw benchmark artifact directory. The
history layer does not move or delete raw benchmark folders.

For live runs it records:

- benchmark name, scheduler name, capture mode, command, and artifact paths
- parsed score metrics such as cache ops/s, memcpy ops/s, context switches, CPU
  migrations, task clock, primary matrix metric, and wall time when available
- host-noise summary from `/proc`, including clean/warn/noisy severity, outside
  CPU pressure, PSI pressure, and top background processes
- current git branch/head/subject, dirty status, changed files, and a dirty diff
  patch when the tree has local changes
- latest `cake_constants.rs` baked constants and `cake.bpf.o` hash
- optional mutation id and hypothesis text

For old imported runs it records the same normalized scores where available and
links back to the historical `runs/` artifact paths.

## History Layout

The history root is:

```text
/home/ritz/Documents/Repo/scx_cake_bench_assets/history
```

Important files:

```text
history/
  runs.jsonl       append-only source ledger, one JSON object per run
  latest.json      latest run record
  best.json        global best scores by tracked metric
  catalog.json     counts, schedulers, sources, and per-benchmark bests
  index.html       static GUI/dashboard for browsing scores
  patches/         dirty diff patches captured from live uncommitted runs
```

Each single-run artifact can also contain:

```text
<run-output>/
  noise/
    pre.json/.md       short host snapshot before the run
    timeline.jsonl     per-sample process/load/PSI observations
    summary.json/.md   aggregate clean/low/warn/noisy verdict
    post.json/.md      short host snapshot after the run
```

Generated files can be rebuilt from `runs.jsonl`:

```fish
./cakebench history rebuild
```

## GUI

Open the static dashboard:

```fish
xdg-open /home/ritz/Documents/Repo/scx_cake_bench_assets/history/index.html
```

The dashboard shows:

- total and visible record counts
- filters for benchmark, scheduler, source, and metric
- search across run id, path, git, and hypothesis
- noise severity for each run, with top background processes in the tooltip
- score trend chart
- best score table
- benchmark count table
- full run table with score columns and artifact paths

No server is required. The page embeds the local data and can be opened directly
from disk.

## Common Commands

Show the active history path:

```fish
./cakebench history path
```

Backfill old benchmark artifacts without writing anything:

```fish
./cakebench history import-old --dry-run
```

Backfill old benchmark artifacts into the ledger:

```fish
./cakebench history import-old
```

Rebuild generated JSON and dashboard files:

```fish
./cakebench history rebuild
```

Run the fast cache/mem benchmark and record it automatically:

```fish
./cakebench score attempt-001 --kind policy local shield policy baseline
```

That is the preferred command for mutation work. It expands to the standard
cache/mem benchmark with:

```text
SCX_CAKE_QUEUE_POLICY=local
SCX_CAKE_STORM_GUARD=shield
SCX_CAKE_BUSY_WAKE_KICK=policy
benchmark=stress-ng-cpu-cache-mem
capture=stat
```

The first word after `score` is the mutation id. `--kind` records what type of
work this was, so future comparisons can separate knobs from policy and system
changes. Any remaining words become the hypothesis. If no hypothesis words are
provided, the mutation id is reused as the hypothesis.

If the hypothesis has punctuation or you are pasting a long sentence, quote it
so fish cannot split the command:

```fish
./cakebench score attempt-001 --kind policy "local shield policy baseline"
```

Suggested mutation kinds:

```text
system      cross-path scheduling design or queue topology change
policy      scheduling decision rule or ownership/fairness policy change
mechanism   lower-level implementation mechanism, data structure, or hot-path primitive
knob        threshold, constant, budget, or slice-size tuning
diagnostic  observability-only change
baseline    known baseline or comparison run
revert      rollback or removal of a failed mutation
```

The history parser also derives simultaneous cache/mem score metrics:

```text
stress_cache_mem_dual_score
stress_cache_mem_geomean_score
stress_cache_vs_best_ratio
stress_memcpy_vs_best_ratio
stress_cache_mem_goal_pass
```

`stress_cache_mem_dual_score` is the important frontier score. It is the lower
of the cache ratio and memcpy ratio against the current best targets:

```text
cache target:  5,484,539.37 bogo ops/s
memcpy target: 5,859.61 bogo ops/s
```

A dual score above `1.0` means one run beat both targets at the same time.

The longer explicit form is:

```fish
begin
    set -lx SCX_CAKE_QUEUE_POLICY local
    set -lx SCX_CAKE_STORM_GUARD shield
    set -lx SCX_CAKE_BUSY_WAKE_KICK policy
    ./cakebench one stress-ng-cpu-cache-mem --capture stat --mutation-id attempt-001 --hypothesis "local shield policy baseline"
end
```

Agent-friendly non-interactive run:

```fish
sudo -v
```

Then the AI can run:

```fish
./cakebench score attempt-001 --kind policy local shield policy baseline
```

`ai-one` uses `sudo -n` internally. That means it fails fast if sudo is not
already warmed instead of hanging at a password prompt the agent cannot answer.

Run another scheduler for comparison:

```fish
./cakebench one stress-ng-cpu-cache-mem --scheduler scx_cosmos --capture stat --hypothesis "cosmos comparison"
```

Run debug Cake with final diagnostics:

```fish
./cakebench debug-one stress-ng-cpu-cache-mem --capture stat --queue-policy local
```

## Noise Checks

Single-run commands capture host noise automatically. Disable it only when you
are debugging the benchmark wrapper itself:

```fish
env SCX_CAKE_BENCH_NOISE=0 ./cakebench score attempt-001 --kind diagnostic "no noise sampler"
```

Manual one-shot host check:

```fish
./cakebench noise --sample-secs 2
```

Manual monitor until `Ctrl-C`:

```fish
./cakebench noise --monitor --interval 1 --sample-secs 0.25
```

Severity is intentionally conservative:

```text
clean  no meaningful outside CPU or pressure was sampled
low    small outside CPU or kernel activity was present
warn   enough outside CPU/PSI pressure to treat close scores carefully
noisy  high outside CPU/PSI pressure; rerun before judging scheduler quality
```

The score history should treat `noisy` benchmark results as evidence about the
machine state, not as proof that a scheduler mutation regressed.

### Noise Comparability Rule

Benchmark noise is not a one-way penalty. Background work can lower a score, but
it can also distort the cache/mem balance and make a mutation look better than
it really is. Treat noise as part of the benchmark condition, not just metadata.

For keep/reject decisions:

```text
clean/low vs clean/low  decision-grade comparison
warn vs warn            usable, but close results need a rerun
warn vs clean/low       flag the comparison and prefer a rerun
noisy vs anything       evidence only; rerun before judging scheduler quality
```

A mutation should only count as a true improvement when it beats the prior best
under comparable noise. If the noise class differs, record the result but mark
the conclusion as tentative. Do not chase a policy branch from one noisy win.

The `stream-overflow-throughput-slice-v10` rerun on 2026-05-14 is the reference
example:

```text
noisy v10: cache 4.036M, memcpy 2.604K, dual 0.444, ctx 555k, mig 11.7k, noise noisy
clean v10: cache 4.145M, memcpy 2.283K, dual 0.390, ctx 222k, mig 3.1k, noise low
```

Removing Discord/music/AI/browser noise improved cache and reduced churn, but
memcpy fell enough that the mutation was worse overall. The noisy run was not a
valid signal that v10 improved the dual goal; it showed that outside activity
can manipulate the measured balance.

Future analysis may add normalized views, but raw normalized scores must remain
labelled as estimates. A useful normalization report should include at least:

```text
raw score
noise severity
avg/max external CPU
known noisy processes
benchmark saturated true/false
context switches and migrations
normalized or adjusted score, if computed
confidence/validity label
```

Normalization can help sort old data and find candidates worth rerunning. It
should not replace a clean rerun for deciding whether a scheduler mutation won.

## AI Mutation Workflow

Use the history as the scoreboard before and after every scheduler mutation.

1. Read `catalog.json`, `best.json`, and `latest.json` to establish the current
   best scores, latest run, and noise state.
2. Make one scoped scheduler change.
3. Run `./cakebench ai-one ... --mutation-id ... --mutation-kind policy
   --hypothesis ...` when sudo is warmed, or `./cakebench score ... --kind
   policy ...` when the user is driving the terminal.
4. Let `cakebench` record the run automatically.
5. Check the new record's noise severity before comparing score deltas.
6. Keep, mutate, park, or revert based on measured score deltas and correctness
   evidence.

Useful quick reads:

```fish
python3 -c 'import json,pathlib; c=json.loads(pathlib.Path("../scx_cake_bench_assets/history/catalog.json").read_text()); print(c["best_by_benchmark"]["stress-ng-cpu-cache-mem"])'
```

```fish
python3 -c 'import json,pathlib; r=json.loads(pathlib.Path("../scx_cake_bench_assets/history/latest.json").read_text()); print(r["run_id"]); print(r["metrics"]); print(r["git"])'
```

The important rule: do not use chat memory as the score source. Use the JSON
ledger and raw artifact paths.

## Letting AI Run Benchmarks

The AI-safe benchmark command is:

```fish
./cakebench score attempt-001 --kind policy what changed
```

Before asking the AI to run it, warm sudo in your own shell:

```fish
sudo -v
```

Why this exists:

- `sched_ext`, `perf`, and scheduler startup usually require root
- ordinary `sudo` can block forever waiting for a password prompt
- `ai-one` sets non-interactive mode and uses `sudo -n`
- if credentials are not available, it exits with setup instructions
- when the run completes, history capture happens automatically

The same alias supports debug and sibling-scheduler comparisons:

```fish
./cakebench ai-one stress-ng-cpu-cache-mem --debug --capture stat
./cakebench ai-one stress-ng-cpu-cache-mem --scheduler scx_cosmos --capture stat
```

## Score Keys

The most important normalized keys for the cache/mem lane are:

```text
stress_cache_bogo_ops_per_s
stress_memcpy_bogo_ops_per_s
context_switches
cpu_migrations
task_clock_ms
```

Matrix imports may also include:

```text
primary_metric
primary_value
primary_direction
primary_unit
wall_seconds
output_metric
output_value
```

For higher-is-better throughput, compare the ops/s fields. For lower-is-better
latency, wall time, migrations, or context-switch pressure, check the direction
field or benchmark-specific context.

## Cleanup And Organization

Do not delete or rearrange old raw `runs/` folders unless you are intentionally
archiving evidence. The history ledger stores references back to those folders.

Safe cleanup:

- rebuild generated indexes with `./cakebench history rebuild`
- rerun `./cakebench history import-old --dry-run` to confirm no missing imports
- archive old raw runs only after copying or preserving `history/runs.jsonl`,
  `catalog.json`, and any needed raw artifacts

Risky cleanup:

- deleting `history/runs.jsonl`
- deleting `history/patches/` when uncommitted mutation evidence matters
- moving raw `runs/` folders without updating or rebuilding the ledger

## Verification

After changes to the wrapper or history parser, run:

```fish
bash -n cakebench
PYTHONPYCACHEPREFIX=/tmp/scx_cake_pycache python3 -m py_compile tools/cakebench_history.py tools/tests/test_cakebench_history.py
python3 -m unittest tools.tests.test_cakebench_history
./cakebench history import-old --dry-run
```

For a visual smoke check:

```fish
/usr/bin/chromium --headless --no-sandbox --disable-gpu --window-size=1440,1100 --screenshot=/tmp/scx_cake_history_dashboard.png file:///home/ritz/Documents/Repo/scx_cake_bench_assets/history/index.html
```
