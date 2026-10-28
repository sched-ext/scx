# scxcli

Command-line tool for `sched_ext` schedulers, built on `scx.service`.

scxcli starts a scheduler from the catalog the scx maintainers keep:
the recommended ones (Default, Cosmos, LAVD, EEVDF, Cake) first, every
other installed scheduler on request, and a hidden set that needs a
configuration of its own. It reports which scheduler is running. It is
the only program that changes what `scx.service` runs: scxtui, desktop
widgets and scripts all go through it.

```
scxcli list [--json]              The recommended schedulers and the
                                  current state
scxcli list recommended [--json]  The same
scxcli list all [--json]          Every installed scheduler: stable,
                                  experimental, then unlisted
scxcli get [--json]               Show which scheduler is running
scxcli start SCHED                Start a scheduler from `list all` with its
                                  defaults, or `default` for the kernel's own
scxcli start                      Start the selected scheduler again after
                                  `stop`
scxcli stop                       Stop the scheduler, keep the selection for
                                  the next start
scxcli run SCHED [ARGS...]        Start a scheduler with these options
```

`list` and `get` work for any user. The rest need root, or polkit through
`pkexec scxcli start scx_cosmos`; scxcli does not escalate on its own.
With the shipped policy (`org.sched_ext.scxcli.policy`), starting a
scheduler from the list with its defaults and stopping it need no
password for a user at the console, and starting one with options asks
for an administrator's.

The contract (file format, selected state, how the running scheduler is
detected, the JSON output, exit codes) is in
[`services/CATALOG.md`](../../services/CATALOG.md). The rules live in the
[`scx_catalog`](../../rust/scx_catalog) crate; scxcli is a thin wrapper
around it.

## How it works

Starting a scheduler writes `SCX_SCHEDULER` and `SCX_FLAGS` to the unit's
`EnvironmentFile` (`/etc/default/scx`), clears any `SCX_*_OVERRIDE` from
the systemd manager, and runs `systemctl enable` and `restart`. `default`
disables the unit instead. There is no daemon and no D-Bus: the file is
the configuration and the kernel (`/sys/kernel/sched_ext`) is the truth
about what runs, so the choice survives reboots and can be managed with
`systemctl`, configuration management and image builds like any other
unit.

## Install

```
cargo build --release -p scxcli
install -Dm755 target/release/scxcli /usr/bin/scxcli
install -Dm644 tools/scxcli/org.sched_ext.scxcli.policy \
    /usr/share/polkit-1/actions/org.sched_ext.scxcli.policy
install -Dm644 services/catalog.json /usr/share/scx/catalog.json
```

The data files (this policy, the catalog, `scx.service` and
`/etc/default/scx`) can also go in with `xtask install`, which copies
them and nothing else; the binary is still installed as above. See
[`INSTALL.md`](../../INSTALL.md).

## Scripting

```sh
scxcli get --json | jq -r .scheduler
pkexec scxcli start scx_cosmos
scxcli list --json | jq -r '.all[] | .name'
```

Clients refresh on inotify events for `/etc/scx/catalog.json`,
`/usr/share/scx/catalog.json` and `/etc/default/scx`, never on a timer.
