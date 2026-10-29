<p align="center">
  <img
    src="https://raw.githubusercontent.com/sched-ext/scx/main/tools/scxtui/assets/scxtui-logo.png"
    alt="scxtui logo"
    width="320"
  >
</p>

# scxtui

**A terminal user interface for Linux [`sched_ext`](https://github.com/sched-ext/scx) schedulers.**

`scxtui` shows the schedulers scx recommends (Default, Cosmos, LAVD,
EEVDF, Cake), every other scheduler installed, which one is running, and
the kernel's own view of `sched_ext`, and starts one with a key. It is a
client of [`scxcli`](../scxcli/README.md): every read is
`scxcli list --json` and every change is `pkexec scxcli start|stop|run`,
so scxtui runs as a normal user and is never the program that edits the
configuration. There is no daemon and no D-Bus; the backend is
`scx.service` and its environment file.

## Features

- **Recommended view (default):** the catalog's recommended schedulers
  with a line on each, the running one marked, a stopped or failed
  selection marked differently, entries whose scheduler is not installed
  shown disabled. Enter starts the selected one with its own defaults
  (`default` stops the unit and disables it); `s` stops the unit and
  keeps the selection for the next start or boot. With the shipped
  polkit policy none of that asks for a password.
- **All schedulers (`A`):** every `scx_*` scheduler installed in
  systemd's default search path that the catalog does not hide: the
  ones the catalog calls stable first, with the recommended ones
  marked and on top, then the ones it calls experimental, then anything
  installed that the catalog does not name, each group under its own
  divider. Enter starts the selected scheduler with its
  own defaults, without a password; `a` asks for its command-line
  arguments first and goes through `scxcli run`, which asks for an
  administrator's. The view opens with a warning that a scheduler
  unsuited to the workload can perform worse than the kernel's default.
- **Status panel:** the state (the kernel's scheduler, or which one
  runs), what runs now (the unit's process), what is configured and
  whether it is what runs (the file, or an `SCX_SCHEDULER_OVERRIDE` /
  `SCX_FLAGS_OVERRIDE` in effect), why the last start failed, and the
  kernel's `sched_ext` state with a warning whenever it disagrees with
  the unit: a scheduler attached outside the service, a unit that is
  active while nothing is attached, an ops name that does not match.
- **Refresh:** the catalog files and the unit's environment file are
  watched with inotify, so a change made by any other client or by hand
  shows up at once; the unit's and the kernel's state are polled.
- **Logs (`l`):** `scx.service`'s journal for the current or previous
  boot, with priority highlighting.
- **Monitor (`t`):** launches `scxtop` and restores the TUI after it exits.

## Requirements

- Linux with `sched_ext` support and the `scx.service` unit from this
  repository (or a distribution package of it).
- `scxcli` in systemd's default search path, with
  `/usr/share/scx/catalog.json` installed, and `pkexec` with the shipped
  polkit policy for use as a normal user. As root, scxtui calls scxcli
  directly.
- `journalctl` and permission to read the system journal for the log view.
- Optional: `scxtop` for integrated monitoring; it needs root or BPF
  capabilities.

## Installation

```bash
cargo build --release -p scxtui -p scxcli
./target/release/scxtui
```

See [scxcli's README](../scxcli/README.md) for installing scxcli, the
polkit policy and the catalog.

## Command line

scxtui's command line is `--help`, `--version` and `--catalog PATH`,
which lists with the named catalog file instead of the installed one
(`scxtui --catalog ./services/catalog.json` shows a checkout's catalog
before it is installed); starting a scheduler still goes by the
installed catalog, since the polkit policy covers what that one lists.
Scripts use scxcli directly: `scxcli get --json`, `scxcli list --json`,
`pkexec scxcli start SCHED`. The scxctl-style `--cli` and
`--export-profiles` of earlier versions are gone: the catalog is a plain
JSON file and `scxcli list --json` prints it resolved.

Per-scheduler modes (`auto`, `gaming`, `powersave`, `lowlatency`,
`server`) and the scx_loader configuration files scxtui used to read
(`/etc/scx_loader.toml`, `/etc/scxtui/config.toml`) are no longer used.
A scheduler is started with its own defaults, or with the options typed
in the full list.

The contract scxtui reads is
[`services/CATALOG.md`](../../services/CATALOG.md).

`scxtui` checks that `scxcli` is installed before switching the terminal
into raw mode, so a missing tool is a normal error message instead of a
broken terminal.

## Credits and provenance

`scxtui` originated in the [`scx_loader`](https://github.com/sched-ext/scx-loader)
project, alongside [`scxctl`](https://github.com/sched-ext/scx-loader/tree/main/crates/scxctl).
We thank **Vladislav Nepogodin** and all other contributors to `scx_loader` and
`scxctl` for their work. The idea of a curated list a user picks a
scheduler from comes from `scx_loader`'s modes, and the client model
from `scxctl`.

The version of `scxtui` maintained here uses `scxcli` and `scx.service`
directly, without the `scx_loader` D-Bus backend. This change in
architecture does not diminish the contributions of the original projects
and their authors.

## License

`scxtui` is distributed under the terms of the
[GNU General Public License v2.0 only](../../LICENSE), matching the rest of
the scx repository.
