# scx_catalog

The `sched_ext` scheduler catalog, built on `scx.service`.

The catalog says which schedulers scx recommends and which it keeps out
of the lists. This crate owns the catalog file
(`/usr/share/scx/catalog.json`, overridden by `/etc/scx/catalog.json`):
loading and validating it, starting a scheduler from it by rewriting
the unit's `EnvironmentFile`, and detecting which scheduler is running.
It implements the contract in
[`services/CATALOG.md`](../../services/CATALOG.md) and is tested against
the fixtures under `fixtures/`, which clients can copy.

[`scxcli`](../../tools/scxcli) is the crate's command-line front end and
the interface every other client uses. Clients do not link this crate:
writing needs root anyway, and reading goes through `scxcli list --json`
and `get --json`, whose output is versioned on its own.

There is no daemon and no D-Bus. The configuration is the unit's
environment file and the truth about what runs is the kernel's.
