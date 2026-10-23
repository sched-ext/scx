# A Quick Start Guide

This guide provides instructions for running the SCX schedulers as a systemd service and checking its logs.

## Getting Started

At the very beginning, configure the /etc/default/scx file:

- in the SCX_SCHEDULER variable, select the scheduler you are interested in

- in the SCX_FLAGS variable, specify the flags you want to add. To do this, execute and read what flags you can add.

```
scx_SCHEDNAME --help
```

To start the SCX scheduler at boot, you need to run the systemd service as root. Here are the steps:


- Enable the service:

```
systemctl enable scx.service
```

- Start the service:

```
systemctl start scx.service
```

Alternatively, you can use a shortened version of these commands:

```
systemctl enable --now scx.service
```

- To check the status of the service, use the following command:

```
systemctl status scx.service
```

## Override global configuration

It is possible to override the global scx settings using systemd environment
variables `SCX_SCHEDULER_OVERRIDE` and `SCX_FLAGS_OVERRIDE`.

Example:

```
systemctl set-environment SCX_SCHEDULER_OVERRIDE=scx_rustland
systemctl set-environment SCX_FLAGS_OVERRIDE="-s 10000"
systemctl restart scx
```

If you want to restore the default value from the `/etc/default/scx` file execute:

```
systemctl unset-environment SCX_SCHEDULER_OVERRIDE
systemctl unset-environment SCX_FLAGS_OVERRIDE
systemctl restart scx
```

## Checking journald Logs


- To view the logs, use the following command:

```
journalctl -u scx.service
```

- To view the logs of the current session use the command

```
journalctl -u scx.service -b 0
```


## Interactive management

[`scxtui`](../tools/scxtui/README.md) wraps the steps above in a terminal
UI: it rewrites `SCX_SCHEDULER` and `SCX_FLAGS` in the unit's environment
file (`/etc/default/scx` here, `/etc/sysconfig/scx` on distributions that
patch the unit), drives the unit with `systemctl`, shows the running
scheduler next to what the next start would run, including any
`SCX_SCHEDULER_OVERRIDE` in effect, and browses the unit's journal.

```
cargo build --release -p scxtui
sudo ./target/release/scxtui
```

## Profiles

[`scxcli`](../tools/scxcli/README.md) manages the unit through
high-level profiles (Default, Desktop, Gaming, Low latency, Power saver,
Server), each backed by a scheduler and options the scx maintainers
chose. `scxcli apply gaming` writes `SCX_PROFILE`, `SCX_SCHEDULER` and
`SCX_FLAGS` to `/etc/default/scx` and restarts the unit; `scxcli get`
says which profile is running. The list ships as
`/usr/share/scx/profiles.json` (`profiles.json` here) and an
administrator overrides it with `/etc/scx/profiles.json`. The contract is
in [PROFILES.md](PROFILES.md).
