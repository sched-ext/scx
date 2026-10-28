# The scheduler catalog

The catalog is the scx maintainers' word on which schedulers a user
should pick from. It has two lists: the recommended schedulers, shown
first and started with one command, and the hidden ones, kept out of
every list because they do not start without a configuration of their
own or are test tools. Everything else that is installed is available in
the full list.

This file is the contract between the catalog file, the `scx_catalog`
library that owns it, the `scxcli` tool that every client drives, and the
clients themselves (scxtui, desktop widgets, scripts). The fixtures under
`rust/scx_catalog/fixtures` are the executable form of this contract: the
library's tests run against them, and clients can copy them to test their
parsers against the same inputs and outputs.

All of it is built on `scx.service` and plain systemd. There is no daemon
and no D-Bus. The configuration is the unit's `EnvironmentFile`
(`/etc/default/scx`), and the truth about what runs is the kernel's
(`/sys/kernel/sched_ext`).

## Catalog file

- scx ships `/usr/share/scx/catalog.json` (`services/catalog.json` in the
  repo).
- Administrators override it with `/etc/scx/catalog.json`. When that
  file exists it is used; the shipped one is read only when it does not.
  The two are never merged, so an override
  replaces the whole catalog and does not pick up upstream changes to the
  entries it does not mention. A file that exists but cannot be used
  (unreadable, invalid, untrusted, or a symlink whose target is missing)
  is an error, never a fallback to the shipped catalog: a broken override
  is still the administrator's configuration.
- The format is JSON, version 1:

```json
{
  "version": 1,
  "recommended": [
    { "id": "default", "label": "Default",
      "description": "The kernel's built-in scheduler (no sched_ext scheduler active)." },
    { "id": "scx_cosmos", "label": "Cosmos",
      "description": "Keeps the system responsive under load." }
  ],
  "hidden": ["scx_layered", "scx_mitosis"]
}
```

Rules, checked by `scx_catalog::Catalog::validate` and so by every load:

- `version` is 1.
- `recommended` is a non-empty list. `hidden` is a list, possibly empty
  or absent. Unknown keys are an error.
- A recommended entry's `id` is `default` or a scheduler name: a bare
  `scx_*` name of ASCII letters, digits, `_` and `-`, at most 64
  characters. Never a path: the executable is found in systemd's default
  search path (`systemd-path search-binaries-default`). Ids are unique in
  the list.
- `label` is 1 to 64 characters and `description` 0 to 256 characters,
  both UTF-8 with no control characters.
- `default` is always present and always first. It means the kernel's
  own scheduler: no sched_ext scheduler runs, and the unit is stopped and
  disabled.
- A hidden entry is a scheduler name by the same rule, unique, and not a
  recommended one.
- A recommended entry starts its scheduler with the scheduler's own
  defaults and no options. Options are the administrator's, through
  `run`.

The shipped catalog is a maintainer decision and changes as the
schedulers change. Clients must not hard-code it. Hidden means hidden
from the lists, never forbidden: `run` starts a hidden scheduler with the
configuration it needs, and `get` reports it like any other while it
runs.

## Selected state

Starting a scheduler writes two keys to the unit's `EnvironmentFile`:

```
SCX_SCHEDULER=/usr/bin/scx_cosmos
SCX_FLAGS=""
```

then clears any `SCX_SCHEDULER_OVERRIDE` / `SCX_FLAGS_OVERRIDE` from the
systemd manager environment (`systemctl unset-environment`), and runs
`systemctl enable` and `systemctl restart scx.service`, after
`reset-failed` so that a start limit hit by an earlier scheduler does not
refuse this one. `SCX_SCHEDULER` is the resolved absolute path, so that
what the unit runs is exactly what was checked.

Starting `default` runs `systemctl disable --now` first, then writes
both keys empty (`SCX_SCHEDULER=""`, `SCX_FLAGS=""`) and reads the
unit's environment back. The keys are cleared, not removed: an
`EnvironmentFile=` assignment wins over `Environment=` in the unit file
or a drop-in, so an empty value masks a scheduler set there, where a
missing key would let it through to the next `systemctl start`; empty is
unset to the unit's shell. The read-back composes the environment the
way the unit does and refuses to call the cleanup done while any layer
still supplies any of the four variables: the unit expands
`${SCX_SCHEDULER_OVERRIDE:-$SCX_SCHEDULER} ${SCX_FLAGS_OVERRIDE:-$SCX_FLAGS}`
unquoted, so with no scheduler the first word of the flags would be
what runs.
Stopping does not depend on the cleanup: a configuration that cannot be
rewritten (a later file sets the keys, say) leaves the unit stopped and
reports the cleanup failure. After a successful cleanup nothing of the
previous scheduler is left behind: a later `systemctl start scx.service`
by hand launches no scheduler (the unit's `exec` has nothing to run and
the unit ends at once), rather than silently bringing the old one back.

`scxcli run SCHED [ARGS...]` writes the same two keys with the options
given. There is no marker telling a `run` from a `start`: the file is
the whole truth, and a scheduler with options in `SCX_FLAGS` is a `run`
by definition, since `start` never writes any.

Writing:

- The write goes to the unit's first `EnvironmentFile=`. Every line
  other than the two keys is kept. The file is replaced atomically
  through a scratch file and a rename, with the original's owner, mode
  and POSIX access ACL carried over. A file that cannot be read, or that
  changes while it is being rewritten, is never overwritten.
- The write is refused when it could not take effect: when a later
  `EnvironmentFile=` sets one of the keys; when an `UnsetEnvironment=`
  on the unit would drop a key the write sets to a value (one the write
  clears, as `default` does with both, is no concern, since unset and
  empty are the same to the shell); when a non-empty
  `SCX_SCHEDULER_OVERRIDE` or `SCX_FLAGS_OVERRIDE` would still be set
  after `systemctl unset-environment`, that is, in the unit's
  `Environment=`, a drop-in or any environment file, composed the way
  systemd composes them (a later assignment wins, an empty one unsets,
  `UnsetEnvironment=` applies last); or when the unit's environment
  cannot be assembled (a required file is missing or unreadable). The
  error names the source. The administrator's configuration is never
  edited to make a write go through.
- A missing first file is created 0644, whatever the umask: readable by
  every user, since the two managed keys hold nothing secret and `get`
  and `list` must read them as any user, and writable by root only,
  since what the file holds runs as root. An existing file keeps its
  owner, mode and ACL.
- `/etc/scx/catalog.json` decides what `start` offers without a
  password, so it is used only when nobody but root could have written
  it: the file and `/etc/scx` must be owned by root and not writable by
  group or others (a sticky directory excepted), and neither may be a
  symlink, since a link could lead through a directory someone else
  controls. The file's owner and mode are taken from the handle it is
  then read from, not from a second lookup of the path. Otherwise every
  command that loads the catalog refuses, naming the file or directory.
  A `/etc/scx` that is itself a symlink, dangling or not, is a broken
  configuration and an error, never "no override". Nothing writes that
  file: an administrator edits it by hand, with the modes above.
- Known limitation, kept on purpose: the contract says `get` and `list`
  work for any user, which holds for the files as this tool creates
  them. An administrator who makes the environment file or the catalog
  private (0600) keeps it private; an unprivileged `get` then reports
  `config_error` naming the file, and an unprivileged `list` fails to
  load the catalog. The tool does not work around that, because the
  environment file may hold other variables the administrator did not
  mean to expose, and a separate world-readable copy of the state would
  be a second source of truth. Administrators who want unprivileged
  clients keep the files readable. The unit's own `EnvironmentFile=`
  entries are read the way systemd lists them, several on one line
  included.

## Detecting the running scheduler

The current state is read from three sources: the unit's environment,
assembled the way systemd assembles it (manager environment,
`Environment=`, every `EnvironmentFile=` in order, `UnsetEnvironment=`),
the unit's main process (`MainPID` and `/proc/<pid>/cmdline`), and the
kernel (`/sys/kernel/sched_ext/state` and `root/ops`). The catalog plays
no part: which scheduler runs is a fact about the unit and the kernel,
and whether it is recommended or hidden is the listing's business.

- A scheduler is running when the unit is active, its main process is
  known, and the kernel reports an attached scheduler whose ops name
  matches the process (exact, with or without the `scx_` prefix, or
  followed by `_` and a version suffix).
- `scheduler` is:
  - the running scheduler, by the process's basename;
  - `default`, when nothing is attached and the unit is inactive,
    whatever the file says the next start would run (after `stop`, or
    after a failed start, the kernel's own scheduler is what runs);
  - null otherwise: the unit is active but nothing is attached yet, or
    something is attached that the unit did not start.
- `next` is what the file says, so `scheduler` of `default` with a
  `next` is a stopped or failed selection, and `failure` says why when
  the journal says.

## scxcli

```
scxcli list [recommended|all] [--json]   # any user
scxcli get [--json]                      # any user
scxcli start SCHED            # root, or polkit: allow_active=yes
scxcli start                  # root, or polkit: allow_active=yes
scxcli stop                   # root, or polkit: allow_active=yes
scxcli run SCHED [ARGS...]    # root, or polkit: auth_admin_keep
```

Clients that are not root run the privileged commands as
`pkexec scxcli start SCHED`. scxcli does not escalate on its own.

- `list` and `list recommended` show the recommended entries with the
  current state; `list all` shows every installed scheduler the catalog
  does not hide, the recommended ones marked. `list`, `list recommended`,
  `list all` and `get` take only `--json`.
- `start SCHED` takes exactly one argument: `default`, or a scheduler
  from `list all` by name, started with its own defaults. What `list
  all` would not show is refused by the same two tests the listing
  applies: an `scx_*` executable that is not a scheduler (`scx_loader`,
  `scx_forge_agent` and the other tools) is not a scheduler here either,
  and a hidden scheduler is refused with a pointer to `run`. A path or
  anything that is not a scheduler name is a usage error.
- `start` alone starts the unit again after `stop`. Because the shipped
  policy lets it run without a password, it starts only what `start
  SCHED` could have written: `SCX_SCHEDULER` must resolve, through the
  same rules `start` and `run` use, to an executable in systemd's
  default search path that `list all` would show (a scheduler, not
  hidden); `SCX_FLAGS` must
  be empty; no `SCX_*_OVERRIDE` may be in effect; and the environment
  must have resolved. Anything else is refused, with the command that
  does it with the right authority: `start SCHED`, which rewrites the
  file and clears overrides, or `run` as an administrator for a
  configuration with options. `reset-failed` precedes the start.
- `stop` stops the unit and changes nothing else: the selected scheduler
  stays in the file, `get` reports `default` running with it as `next`,
  and the next boot or `start` brings it back. It is for a baseline
  measurement or a test; "no scheduler at all" is `start default`, which
  also removes the selection.
- `run` validates the scheduler (a name, or an absolute path that is
  plain, under `/usr`, `/bin` or `/sbin`, in systemd's default search
  path and executable) and each option: 1 to 256 characters drawn from
  ASCII letters, digits and `-_=.,:/+`. Nothing else is accepted: the
  values are written into a file that a shell expands unquoted, and the
  allowlist is what survives that round trip. scxcli never runs a shell
  to interpret anything the user supplies; it writes the file and
  drives `systemctl`. The unit itself does run its `ExecStart` through
  bash, which expands `$SCX_SCHEDULER $SCX_FLAGS` unquoted, and the
  allowlist exists so that nothing written survives that expansion as
  anything but the intended words.
- There is no `restart`: `start SCHED` restarts the unit with the
  scheduler, and `systemctl restart scx.service` restarts it with the
  file as it is. A `restart` of its own would have to choose between the
  running process and the file, which differ after a hand edit.

Exit codes: 0 success, 1 failure, 2 usage error (unknown command or
argument, invalid name or option), 3 permission denied (the write or
`systemctl` needs root).

### JSON output

The JSON output has its own version, 2, separate from the file format.
Fields are only added within a version. Clients ignore fields they do
not know.

`scxcli get --json`:

```json
{
  "version": 2,
  "scheduler": "scx_cosmos",
  "unit": { "active": true, "enabled": true },
  "running": { "sched": "scx_cosmos", "args": [] },
  "next": { "sched": "/usr/bin/scx_cosmos", "args": [], "override": false },
  "kernel": { "state": "enabled", "ops": "cosmos" },
  "failure": null
}
```

- `scheduler` is as defined above.
- `unit` is the unit's state: active (its process may be alive) and
  enabled (it starts at boot).
- `running` is the unit's main process, by basename, or null when the
  unit is inactive or the process cannot be read.
- `next` is what the next start would run after the environment is
  resolved like the unit's `ExecStart` does, with `sched` as the file
  holds it (a path when scxcli wrote it) and `override` true when an
  `SCX_SCHEDULER_OVERRIDE` or `SCX_FLAGS_OVERRIDE` decided it. Null when
  nothing is configured.
- `kernel` is `/sys/kernel/sched_ext`: `state` and the attached
  scheduler's `ops` name (null when nothing is attached). The whole
  object is null on a kernel without `sched_ext`.
- `failure` is `{ "message": "...", "status": "exit-code/1" }` when the
  unit is not active and its last run in this boot did not end in
  success; otherwise null. `status` is systemd's `Result` and
  `ExecMainStatus`. `message` is the last lines the scheduler logged,
  when the journal is readable, else systemd's verdict.
- `config_error` is present only when the unit's environment could not
  be fully resolved (a required file missing or unreadable); `next` is
  then incomplete.

`scxcli list --json` (`list recommended --json` and `list all --json`
print the same object):

```json
{
  "version": 2,
  "source": "/usr/share/scx/catalog.json",
  "customized": false,
  "recommended": [
    { "id": "default", "label": "Default",
      "description": "The kernel's built-in scheduler (no sched_ext scheduler active).",
      "available": true },
    { "id": "scx_cosmos", "label": "Cosmos", "description": "...",
      "path": "/usr/bin/scx_cosmos", "available": true },
    { "id": "scx_eevdf", "label": "EEVDF", "description": "...",
      "available": false }
  ],
  "all": [
    { "name": "scx_cosmos", "path": "/usr/bin/scx_cosmos", "recommended": true },
    { "name": "scx_bpfland", "path": "/usr/bin/scx_bpfland", "recommended": false }
  ],
  "config": "/etc/default/scx",
  "current": { ... the same object as get ... }
}
```

- `recommended` is the catalog's list, in its order. `available` is
  whether the entry can be started here: `default` always, a scheduler
  when it is installed in systemd's default search path, and `path` is
  then the resolved executable.
- `all` is every `scx_*` scheduler found in that search path, minus the
  hidden ones, with whether each is recommended: the recommended ones
  first, in the catalog's order, then the rest by name. Clients show
  the list in this order.
- `config` is the unit's environment file, the one starting writes and
  the one clients watch; absent when the unit declares none.

Clients refresh on inotify events for `/etc/scx/catalog.json`,
`/usr/share/scx/catalog.json` and the unit's environment file (`config`
in the listing), not on a timer. The unit's state and the kernel's are
not files that change under inotify, so a client that shows them keeps a
slow poll for those alone.

## polkit

scx ships `org.sched_ext.scxcli.policy` with three actions, told apart
by the `org.freedesktop.policykit.exec.argv1` annotation:

| action                       | argv1   | default           |
|------------------------------|---------|-------------------|
| `org.sched_ext.scxcli.start` | `start` | `allow_active=yes`|
| `org.sched_ext.scxcli.stop`  | `stop`  | `allow_active=yes`|
| `org.sched_ext.scxcli.run`   | `run`   | `auth_admin_keep` |

Starting needs no password because the caller passes only a name, the
scheduler starts with its own defaults, and the executable comes from
systemd's default search path and a catalog that an administrator
controls; the risk in a scheduler is in its options, not in a binary
under `/usr`. Stopping changes nothing about what runs as root. Starting
a scheduler with arbitrary options, or a hidden one with the
configuration it needs, changes what runs as root and needs an
administrator. The policy is a separate file: a distribution that wants
every action to need a password ships a stricter one or none, and scxcli
then works only as root.
