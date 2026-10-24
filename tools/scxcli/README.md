# scxcli

**Command-line tool for `sched_ext` scheduling profiles, built on
`scx.service`.**

A profile names what the machine should do well (Desktop, Gaming, Low
latency, Power saver, Server) and maps to a scheduler and its options,
chosen and tested by the scx maintainers. scxcli applies one, reports
which one is running, and edits the list. It is the only program that
changes what `scx.service` runs: scxtui, desktop widgets and scripts all
go through it.

```
scxcli list [--json]           List the profiles and the current state
scxcli get [--json]            Show which profile is running
scxcli apply ID                Apply a profile
scxcli profiles save           Replace the profile list with the JSON on stdin
scxcli profiles reset          Remove the administrator's list
scxcli run SCHED [ARGS...]     Start a scheduler with these options, outside
                               any profile
```

`list` and `get` work for any user. The rest need root, or polkit through
`pkexec scxcli apply ID`; scxcli does not escalate on its own. With the
shipped policy (`org.sched_ext.scxcli.policy`), applying a profile needs
no password for a user at the console, and editing the list or running an
arbitrary scheduler asks for an administrator's.

The contract (file format, applied state, how the running profile is
detected, the JSON output, exit codes) is in
[`services/PROFILES.md`](../../services/PROFILES.md). The rules live in
the [`scx_profiles`](../../rust/scx_profiles) crate; scxcli is a thin
wrapper around it.

## How it works

Applying a profile writes `SCX_PROFILE`, `SCX_SCHEDULER` and `SCX_FLAGS`
to the unit's `EnvironmentFile` (`/etc/default/scx`), clears any
`SCX_*_OVERRIDE` from the systemd manager, and runs `systemctl enable`
and `restart`. `default` disables the unit instead. There is no daemon
and no D-Bus: the file is the configuration and the kernel
(`/sys/kernel/sched_ext`) is the truth about what runs, so the choice
survives reboots and can be managed with `systemctl`, configuration
management and image builds like any other unit.

## Install

```
cargo build --release -p scxcli
install -Dm755 target/release/scxcli /usr/bin/scxcli
install -Dm644 tools/scxcli/org.sched_ext.scxcli.policy \
    /usr/share/polkit-1/actions/org.sched_ext.scxcli.policy
install -Dm644 services/profiles.json /usr/share/scx/profiles.json
```

## Scripting

```sh
scxcli get --json | jq -r .profile
pkexec scxcli apply gaming
scxcli list --json | jq -r '.profiles[] | select(.available) | .id'
```

Clients refresh on inotify events for `/etc/scx/profiles.json`,
`/usr/share/scx/profiles.json` and `/etc/default/scx`, never on a timer.
