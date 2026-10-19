<p align="center">
  <img
    src="https://raw.githubusercontent.com/sched-ext/scx/main/tools/scxtui/assets/scxtui-logo.png"
    alt="scxtui logo"
    width="320"
  >
</p>

# scxtui

**A terminal user interface for managing Linux [`sched_ext`](https://github.com/sched-ext/scx) schedulers through `scx.service`.**

`scxtui` provides an interactive view of the `sched_ext` schedulers installed
on the system. It can start, switch, stop and restart the scheduler run by
the [`scx.service`](../../services/) systemd unit, browse the unit's journal,
and launch `scxtop` without leaving the interface. Alongside the state
derived from the unit, it reads the kernel's own view of `sched_ext` from
sysfs and warns whenever the two disagree: a scheduler started behind the
service's back, or one that crashed without the unit noticing.

`scx.service` is the only backend. The TUI has no daemon of its own and no
D-Bus dependency: it reads the unit's environment file, asks `systemctl`
about the unit and the manager environment, and drives the unit with
`systemctl start/stop/restart`.

## Features

- Lists the `scx_*` scheduler executables installed in `PATH`.
- Starts a scheduler in a profile, or switches the running one, by
  rewriting `SCX_SCHEDULER` and `SCX_FLAGS` in the unit's environment file
  and (re)starting the unit. The file is rewritten atomically through a
  unique temporary file, every other line is preserved, and a file that
  cannot be read or that changed under the editor is never overwritten.
- Profiles (`auto`, `gaming`, `powersave`, `lowlatency`, `server`): named
  flag sets per scheduler, with scx_loader's schema and built-in tables.
  An existing `/etc/scx_loader.toml` is picked up as-is; see
  [`config.toml.example`](config.toml.example). `d` restores the file's
  `default_sched` in its `default_mode`. `a` opens a field for own flags,
  written to `SCX_FLAGS` instead of a profile's. `--export-profiles` dumps
  the resolved table as JSON.
- Shows what runs now and what the next start would run, separately. The
  running scheduler and its flags come from the unit's main process
  (`MainPID`, `/proc/<pid>/cmdline`), never from the file, so a file edited
  under a running unit shows up as a pending change rather than as the
  running state. The next start is resolved from the unit's environment
  assembled the way systemd assembles it (manager environment,
  `Environment=`, every `EnvironmentFile=` in order, `UnsetEnvironment=`),
  so an `SCX_SCHEDULER_OVERRIDE` / `SCX_FLAGS_OVERRIDE` set in any of those
  layers is honoured exactly like the unit's `ExecStart` does. A write is
  refused when a later environment file (or `UnsetEnvironment=`) would
  override it, since `systemctl restart` would then report success while
  running something else.
- Displays the kernel's own `sched_ext` state from sysfs and warns when it
  disagrees with the unit: schedulers attached outside the service's
  control, crashed or watchdog-ejected schedulers, and ops-name mismatches.
- Stops or restarts the unit. Notices report what systemd accepted; what
  actually attached is read back and shown in the State and Kernel lines,
  since under `Type=simple` a successful start says nothing about the
  scheduler attaching.
- Follows changes made by hand (`systemctl`, editing the file) with a
  periodic poll; the kernel view is re-read every tick.
- Browses logs from `scx.service` for the current or previous boot, with
  syslog-priority highlighting and multi-line entries preserved.
- Launches `scxtop` as an external monitor and restores the TUI after it
  exits.

## Requirements

- Linux with `sched_ext` support.
- The `scx.service` systemd unit from this repository (or a distribution
  package of it) with its environment file. The file path is taken from the
  unit's first `EnvironmentFile=` (`/etc/default/scx` upstream,
  `/etc/sysconfig/scx` on some distributions); a unit that declares none
  is read-only in the TUI.
- `systemd` and `journalctl` for the integrated log viewer, and permission
  to read the system journal.
- Root privileges to control the unit and edit its environment file.
  Reading the state works as any user.
- Optional: `scxtop` in `PATH` for integrated monitoring. `scxtop` may
  require root privileges or suitable BPF capabilities.

## Installation

Build from this repository:

```bash
cargo build --release -p scxtui
./target/release/scxtui
```

## Usage

```bash
scxtui
scxtui --export-profiles profiles.json   # or - for stdout
```

The export holds, for every scheduler the TUI would list, the flags each
profile resolves to (file rows merged with the built-in defaults) plus the
configured default, as plain JSON for scripts and other front ends.

`scxtui` checks that `scx.service` exists before switching the terminal into
raw mode. If the unit is missing, it exits with a normal error message
instead of leaving the terminal in a broken state.

### Scheduler view

| Key | Action |
|---|---|
| `↑` / `↓`, `k` / `j` | Select the previous or next scheduler |
| `Tab`, `m` / `Shift+Tab`, `M` | Select the next / previous profile |
| `Enter` | Start the selected scheduler in the selected profile, or switch to it (config edit + restart) when the unit is active |
| `a` | Open the own-flags field; `Enter` starts/switches with the typed flags in `SCX_FLAGS`, `Esc` cancels |
| `s` | Stop the unit |
| `r` | Restart the unit |
| `d` | Start or switch to the profiles file's `default_sched` in its `default_mode` |
| `l` | Open the journal log viewer |
| `t` | Launch `scxtop` |
| `R` | Refresh the scheduler list and state |
| `q`, `Esc` | Quit |

Scheduler-changing actions are debounced to prevent terminal key repeat from
triggering several starts, stops, or restarts in quick succession.

### Log view

| Key | Action |
|---|---|
| `↑` / `↓`, `k` / `j` | Scroll one line |
| `Page Up` / `Page Down` | Scroll one page |
| `g` / `G` | Jump to the oldest or newest entry |
| `b` | Toggle between the current and previous boot |
| `R` | Reload the journal |
| `q`, `Esc`, `l` | Return to the scheduler view |

The log viewer calls `journalctl --output=json` and parses the result
locally. This avoids a build-time dependency on `libsystemd` while retaining
journal priority information for message highlighting.

## How it works

Two sources of truth, kept apart. What runs now comes from `systemctl show`
(`ActiveState`, `MainPID`) and `/proc/<pid>/cmdline`: the unit is
`Type=simple` and its `ExecStart` execs the scheduler, so the main process
is the scheduler and `argv` is its flags. What the next start would run
comes from the unit's environment, assembled per systemd.exec(5): the
manager environment (`systemctl show-environment`) is the base,
`Environment=` from the unit and its drop-ins overrides it, and each
`EnvironmentFile=` overrides both, later files winning, and
`UnsetEnvironment=` is applied last. The result is resolved like
`ExecStart` does: `${SCX_SCHEDULER_OVERRIDE:-$SCX_SCHEDULER}` and
`${SCX_FLAGS_OVERRIDE:-$SCX_FLAGS}`. systemd prints `Environment=` values
in `"…"` quoting and `show-environment` values in ANSI-C `$'…'` quoting;
both are decoded. A layer that cannot be read (a file, or the manager
environment), or a required file that is missing, is reported in the panel
rather than read as empty, and writes are refused while that holds.

Writes go to the unit's first `EnvironmentFile=`, re-read from the live
unit at write time: if a drop-in plus `daemon-reload` moved it since the
TUI started, the write is refused (restart the TUI), and a unit that
declares no file gets no write at all rather than a guessed path. Before
writing, every later file is checked for `SCX_SCHEDULER` / `SCX_FLAGS`,
and `UnsetEnvironment=` for the same names (`NAME=VALUE` only when VALUE is
exactly what would be written): any of them would override the write, so
it is refused with the file named instead of restarting into the wrong
scheduler. Flags are refused if they contain whitespace, quotes,
backslashes or glob characters (`*`, `?`, `[`), since the unit expands
`$SCX_FLAGS` unquoted and bash would split or glob them.

A start or switch is refused when the unit's state cannot be read: unknown
is not inactive, and `systemctl start` on an already running unit would
leave the old scheduler running under a file that names the new one.

A profile is a flag list. Starting or switching writes the selected
scheduler to `SCX_SCHEDULER=` and the profile's flags to `SCX_FLAGS=` (write
to a unique temporary file in the same directory, carry the original
mode and owner over, re-check that the file did not change meanwhile,
rename into place, through a symlink to its target) and starts or restarts
the unit. Nothing records which profile
was started: the running profile is recognised by comparing the process'
arguments with the table, and anything else shows as custom flags. An
active `SCX_SCHEDULER_OVERRIDE` or `SCX_FLAGS_OVERRIDE` still wins over
the file; the notice names it instead of letting the next poll look like a
failed switch or a wrong profile.

Independently of the unit, `scxtui` reads `/sys/kernel/sched_ext/state` and
`/sys/kernel/sched_ext/root/ops` to show what the kernel itself reports, and
flags disagreements between the kernel and the unit.

The UI is built with [`ratatui`](https://ratatui.rs/). The backend sits
behind a small trait so the application logic is tested against an
in-memory stub.

## Current limitations

- Own flags are whitespace-separated tokens; a flag value containing a
  space cannot be expressed, because the unit expands `$SCX_FLAGS`
  unquoted.
- A file edited by hand between scxtui's read and its rename is detected
  and the write refused, but there is no lock: two editors racing inside
  that window can still interleave.
- The rewrite carries the file's mode and owner over, not ACLs or xattrs.
- Environment file parsing covers `KEY=VALUE` lines with simple quoting;
  systemd's line continuations and in-quote escapes are not interpreted.
- The log viewer loads the selected boot into memory rather than following
  new entries continuously.
- `scxtop` integration depends on a separately installed executable.
- Controlling the unit requires running `scxtui` as root.

## License

`scxtui` is distributed under the terms of the
[GNU General Public License v2.0 only](../../LICENSE), matching the rest of
the `scx` project.
