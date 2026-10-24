# scx_profiles

High-level scheduling profiles for `sched_ext`, built on `scx.service`.

A profile names what the machine should do well and maps to a scheduler
and its options. This crate owns the profile file
(`/usr/share/scx/profiles.json`, overridden by `/etc/scx/profiles.json`):
loading and validating it, applying a profile to the unit's
`EnvironmentFile`, detecting which profile is running, and editing the
list. It implements the contract in
[`services/PROFILES.md`](../../services/PROFILES.md) and is tested
against the fixtures under `fixtures/`, which clients can copy.

[`scxcli`](../../tools/scxcli) is the crate's command-line front end and
the interface every other client uses. Clients do not link this crate:
writing needs root anyway, and reading goes through `scxcli list --json`
and `get --json`, whose output is versioned on its own.

There is no daemon and no D-Bus. The configuration is the unit's
environment file and the truth about what runs is the kernel's.
