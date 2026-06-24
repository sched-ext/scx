# scx-forge-agent

`scx-forge-agent` is an LLM-driven optimizer for `sched_ext` schedulers. It
operates on the scheduler specified by `[scheduler].package` (any crate under
`scheds/rust/<name>`, with `scx_forge` as the default), modifying the selected
crate in place and automatically closing the edit -> build -> validate loop
through an OpenAI-compatible inference endpoint. The overall workflow remains
deterministic and implemented in code, while optimization strategy, code
generation, and patch creation are delegated to one or more LLM roles.

- **Deterministic controller**: builds the crate, runs the built-in validation
  harness as the reward function, reads the verdict, and decides keep-or-revert
  (stage the working-tree edit vs restore it) based on whether the metric improved
  beyond the run's stddev.
- **LLM, per round**: a planner/reasoner model first chooses one coherent policy
  experiment with read-only tools, then a coding model applies the patch with
  sandboxed target-crate tools. Both roles work within the target crate and can
  inspect host topology with fixed read-only `lscpu -e`, `numactl -H`, and CPU
  cache-size sysfs tools. With `[ai].cross_scheduler_refs` they can also inspect
  other schedulers under `scheds/rust` through read-only reference tools and port
  ideas to the target crate; this is disabled by default to keep the prompt and
  tool surface (and token usage) smaller.
- **Two phases**: the run starts in a **knob-tuning** phase that only retunes the
  scheduler's existing CLI options, then transitions to a **code-change** phase
  that proposes new scheduling mechanisms. See [How it works](#how-it-works).

## Configuration (OpenAI-compatible)

API keys (and, optionally, endpoints) come from the environment; everything else
lives in `tools/scx_forge_agent/spec.toml`. Secrets are never stored in the
spec.

```bash
# Planner role (and the default for the coding role):
export SCX_FORGE_API_KEY=<api-key>        # optional (omit for keyless local backends)

# Coding role only, when it runs on a separate endpoint:
export SCX_FORGE_CODING_API_KEY=<api-key> # optional; falls back to $SCX_FORGE_API_KEY
```

The planner and coding roles are configured independently and can use different
backends (see [Backends](#backends)). Spec values take precedence over the
matching env var; when a coding field is unset it falls back to the planner's.
To use one OpenAI endpoint for both, set just `[ai].backend` (or
`$SCX_FORGE_BACKEND`) and `$SCX_FORGE_API_KEY`.

The rest of the configuration lives in `tools/scx_forge_agent/spec.toml`.
Example:

```toml
[ai]
backend = "http://localhost:11434/v1"
model = "gemma4:31b"
# Optional: run the coding role on a separate backend/model.
coding_backend = "http://localhost:11434/v1"
coding_model = "qwen3-coder:30b"
```

## Backends

Each role's backend is selected by its `backend` value in the spec.
`[ai].backend` and `[ai].coding_backend` accept either an OpenAI-compatible URL
or one of the keywords `claude`, `codex`, `opencode`, `cursor-agent`. The planner
and coder resolve independently, so you can mix backends (e.g. an `openai`
planner with a `claude` coder).

- URL value -> **openai**: the built-in HTTP tool loop talks to that
  OpenAI-compatible endpoint. The planner role uses `[ai].backend` (or
  `$SCX_FORGE_BACKEND`), `$SCX_FORGE_API_KEY`, and `[ai].model`; the coding role
  uses `[ai].coding_backend` / `[ai].coding_model` (each falling back to the
  planner's) and `$SCX_FORGE_CODING_API_KEY` (falling back to
  `$SCX_FORGE_API_KEY`).
- `claude` / `opencode` / `codex` / `cursor-agent` value -> that CLI: the agent
  shells out to it, run with the crate dir as its cwd so its own agent edits the
  files in place. The controller then builds/validates the resulting diff exactly
  as for `openai`, so keep/revert and dedup are unchanged. These CLIs use their
  **own** auth/config (each reads whatever it documents, e.g. `OPENAI_*` for
  codex, `ANTHROPIC_*` for claude, `CURSOR_API_KEY` (or its stored login) for
  cursor-agent, from the inherited environment). `[ai].model` /
  `[ai].coding_model` are still honored and passed to the CLI as its model id
  (e.g. `claude` with `model = "haiku"`, or `cursor-agent` with `model = "Auto"`);
  leave them unset to use the CLI's own default.

When the planner and coder resolve to the **same** subprocess backend and model
(e.g. both `claude`, the default once `coding_backend` inherits `backend`), that
CLI plans and edits in one shot - there is no separate planning turn. When they
**differ** (e.g. a `claude` planner feeding an `openai`/`qwen` coder), the
planner runs a dedicated read-only planning turn and its plan is handed to the
coder: `claude` uses its `plan` permission mode, `codex` a `read-only` sandbox,
and `cursor-agent` its `plan` mode (all genuinely cannot edit), while `opencode`
uses its built-in `plan` agent on a best-effort basis and may still touch files
(those edits are validated/reverted like any other round). This costs two model
round-trips per round instead of one.

## Build

```bash
cargo build --release -p scx_forge_agent
```

The scheduler build honors `$CARGO`, so a specific Cargo binary can be selected
for both the controller build gate and the validation harness:

```bash
CARGO=cargo-1.91 scx-forge-agent --spec /path/to/spec.toml
```

## Usage

The scheduler to optimize is set in the spec, not on the command line: edit
`[scheduler].package` in `tools/scx_forge_agent/spec.toml` (default `scx_forge`;
set it to e.g., `scx_cosmos` for a different scheduler). The crate directory is
derived as `scheds/rust/<package>`, and the cargo `profile` also comes from the
spec, so the build gate and the validation harness always agree.

```bash
# Dry run: print the assembled prompt + planned loop, no API call, no scheduler load.
# Shows the resolved package / crate_dir / profile derived from the spec.
scx-forge-agent --dry-run

# Real run (needs [ai].backend, root for the harness, and a live workload).
# The round budget is [ai].rounds in the spec. To skip the knob-tuning phase,
# set [ai].skip_knobs = true in the spec.
scx-forge-agent

# Point at a different spec.toml (e.g., one targeting another scheduler).
scx-forge-agent --spec-toml /path/to/scx_cosmos.spec.toml

# After the optimization loop completes, rebuild the final accepted scheduler
# and run it in the foreground in the current terminal.
scx-forge-agent --keep-running
```

## Metric extraction

`[workload].command` is the only metric source. It must run the workload and
print exactly one numeric metric value; any parsing or aggregation belongs in the
command itself. `[workload].duration` is the hard cap in seconds for that
workload run, and `[workload].runs` sets the repeated measurement count. The
reported metric name is always `score`; `[goal].prompt` and
`[goal].direction` describe what that value means and which way is better.

## Root / sudo

The validation harness loads the scheduler as root. It authenticates in this
order: already root (no sudo), `$SUDO_ASKPASS`, `$SCX_SUDO_PASSWORD_FILE` (a file
holding the sudo password), then plain `sudo -n` (passwordless / cached creds).

Set `[system].sudo_passwd_file` in the spec to have the agent set
`SCX_SUDO_PASSWORD_FILE` for the harness, so a normal-user run works without
configuring passwordless sudo:

```toml
[system]
sudo_passwd_file = "~/.scx_sudo_pass"
```

An empty string means unset. `~` expands to `$HOME`, relative paths are resolved
relative to the spec file, and wildcard patterns must match exactly one file.
Keep that file readable only by you (e.g. `chmod 600`); the password is fed to
sudo via a generated askpass shim and never appears in argv or the process table.

## How it works

The agent runs in two phases that share the single `[ai].rounds` budget. Phase 1
exhausts the cheap, reversible wins available through existing configuration
before Phase 2 spends rounds on writing new code.

1. **Round 0** validates the current crate (the scheduler named by
   `[scheduler].package`) to seed the objective (fixed metric name `score` plus
   the direction from `[goal].direction`) and the starting value. The
   plain-language `[goal].prompt` is passed to the model to frame what the
   metric means.
2. **Phase 1 - knob tuning.** The agent first explores the scheduler's existing
   tuning knobs without writing any new logic. It builds a knob inventory from
   the scheduler binary's `--help` output (every CLI option, its default, and -
   for enums - its possible values), so this works for any `scheds/rust/<package>`
   crate and never goes stale. Each round the planner picks **one** existing
   option and proposes changing its default to a single untested value it expects
   will improve the metric; the coding model applies just that knob change (Rust
   default / CLI plumbing / `rodata` assignment). The phase ends when the planner
   judges the knob space exhausted (it emits a completion sentinel) or
   immediately if `[ai].skip_knobs` is set; the remaining rounds (up to
   `[ai].rounds`) carry over to Phase 2.
3. **Phase 2 - code changes.** The planner now proposes new scheduling mechanisms
   rather than just retuning options: one coherent policy experiment per round
   (task placement, queue ordering, DSQ selection/topology, dispatch pulling,
   deadline/vtime calculation, preemption/kick behavior, ...), which may include
   multiple related edits. The coding model applies the patch to the target
   crate in place.
4. **Each round** (both phases): the controller builds (with a bounded build-fix
   sub-loop), runs the harness, verifies the scheduler is still `enabled` after
   the workload, gives the coding model a bounded runtime-fix sub-loop if the
   scheduler aborts, exits, or prevents the workload from producing a parseable
   metric, and keeps the change (staged in the working tree) only if `value`
   improves over the best by more than `accept_threshold_stddev * stddev`
   (set in the spec's `[workload]` section).
   Otherwise it reverts the edit (restoring the crate from the last accepted
   state). The next prompt includes the factual round history and validation
   context, but the model is free to choose the next self-contained experiment
   on its own technical merits rather than exploiting kept directions or cooling
   down regressed ones.
   When `trace-cmd` is available, the harness also records a small curated sched
   profile while the workload runs and passes only a compact trace summary in
   the verdict JSON to the planner model.
5. The crate is edited in place on the current branch, no branch is created and
   no commits are made. Accepted edits accumulate in the working tree; the final
   report (markdown or `--json`) shows the per-round history and the winner, and
   the winning variant is left as uncommitted modifications.
6. By default the agent does not read or write an attempt state file. Use
   `--save <path>` to append a compact attempt summary when the run completes,
   and `--resume <path>` to load a previously saved state file into the
   planner/coder prompts as factual context.

## Safety

The agent never measures or decides "better/worse" itself, that is the harness +
controller. The harness owns scheduler attach/teardown (it returns the host to
`sched_ext state=disabled` on every validation run). With `--keep-running`, the
agent restores the final accepted source state, rebuilds the scheduler, prints the
final report, and then execs the scheduler in the foreground in the current
terminal. The agent requires the crate directory to be clean before starting and
edits it in place without committing, so a run can always be undone with `git
checkout -- scheds/rust/<package>` (or `git stash`). Other scheduler crates
under `scheds/rust` are exposed only through read-only reference tools;
`edit_file` remains locked to the target crate.
