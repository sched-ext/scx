<p align="center">
  <img
    src="https://raw.githubusercontent.com/sched-ext/scx/main/tools/scxtui/assets/scxtui-logo.png"
    alt="scxtui logo"
    width="320"
  >
</p>

# scxtui

**A terminal user interface for Linux [`sched_ext`](https://github.com/sched-ext/scx) scheduling profiles.**

`scxtui` shows the scheduling profiles that scx ships (Default, Desktop,
Gaming, Low latency, Power saver, Server), which one is running, and the
kernel's own view of `sched_ext`, and applies a profile with one key. It
is a client of [`scxcli`](../scxcli/README.md): every read is
`scxcli list --json` and every change is `pkexec scxcli apply|run|profiles`,
so scxtui runs as a normal user and is never the program that edits the
configuration. There is no daemon and no D-Bus; the backend is
`scx.service` and its environment file.

## Features

- **Profiles view (default):** the profile list with descriptions and the
  scheduler and options behind each, the running one marked, profiles
  whose scheduler is not installed shown disabled. Enter applies the
  selected profile; with the shipped polkit policy that asks for no
  password.
- **Editing the list:** `S` saves what runs now as a named profile, `x`
  deletes the selected profile (after a confirmation), `J`/`K` move it,
  `D` restores the shipped list. Each edit is saved through
  `scxcli profiles save` and asks for an administrator's password.
- **Advanced view (`A`):** every `scx_*` scheduler installed in systemd's
  default search path, with free-form options (`a`). Enter starts the
  selected scheduler through `scxcli run`, outside any profile, so every
  client shows Custom. The view opens with a warning that a scheduler
  unsuited to the workload can perform worse than the kernel's default.
- **Status panel:** what runs now (the unit's process), what the next
  start would run (the file plus any `SCX_SCHEDULER_OVERRIDE` /
  `SCX_FLAGS_OVERRIDE` in effect), why the last start failed, and the
  kernel's `sched_ext` state with a warning whenever it disagrees with
  the unit: a scheduler attached outside the service, a unit that is
  active while nothing is attached, an ops name that does not match.
- **Refresh:** the profile files and the unit's environment file are
  watched with inotify, so a change made by any other client or by hand
  shows up at once; the unit's and the kernel's state are polled.
- **Logs (`l`):** `scx.service`'s journal for the current or previous
  boot, with priority highlighting.
- **Monitor (`t`):** launches `scxtop` and restores the TUI after it exits.

## Requirements

- Linux with `sched_ext` support and the `scx.service` unit from this
  repository (or a distribution package of it).
- `scxcli` in systemd's default search path, with `/usr/share/scx/profiles.json`
  installed, and `pkexec` with the shipped polkit policy for use as a
  normal user. As root, scxtui calls scxcli directly.
- `journalctl` and permission to read the system journal for the log view.
- Optional: `scxtop` for integrated monitoring; it needs root or BPF
  capabilities.

## Installation

```bash
cargo build --release -p scxtui -p scxcli
./target/release/scxtui
```

See [scxcli's README](../scxcli/README.md) for installing scxcli, the
polkit policy and the profiles file.

## Command line

scxtui has no command line of its own beyond `--help` and `--version`.
Scripts use scxcli directly: `scxcli get --json`, `scxcli list --json`,
`pkexec scxcli apply ID`. The earlier scxctl-style `--cli` prints the
scxcli command that replaces each of its subcommands and exits; it will
be removed in the next release. `--export-profiles` is gone: the profile
list is a plain JSON file and `scxcli list --json` prints it resolved.

Per-scheduler modes (`auto`, `gaming`, `powersave`, `lowlatency`,
`server`) and the scx_loader configuration files scxtui used to read
(`/etc/scx_loader.toml`, `/etc/scxtui/config.toml`) are no longer used.
The profiles file replaces them; a favourite scheduler and options are
saved as a profile from the advanced view.

The contract scxtui reads is
[`services/PROFILES.md`](../../services/PROFILES.md).

`scxtui` checks that `scxcli` is installed before switching the terminal
into raw mode, so a missing tool is a normal error message instead of a
broken terminal.

## Credits and provenance

`scxtui` originated in the [`scx_loader`](https://github.com/sched-ext/scx-loader)
project, alongside [`scxctl`](https://github.com/sched-ext/scx-loader/tree/main/crates/scxctl).
We thank **Vladislav Nepogodin** and all other contributors to `scx_loader` and
`scxctl` for their work. The idea of named presets that scxtui and the
profiles build on comes from `scx_loader`'s modes, and the client model
from `scxctl`.

The version of `scxtui` maintained here uses `scxcli` and `scx.service`
directly, without the `scx_loader` D-Bus backend. This change in
architecture does not diminish the contributions of the original projects
and their authors.

## License

`scxtui` is distributed under the terms of the
[GNU General Public License v2.0 only](../../LICENSE), matching the rest of
the scx repository.
