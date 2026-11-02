# The scheduler catalog

The catalog says what a user picks from and what the maintainers think
of what is installed. Its `recommended` list holds the profiles: entries
shown first and started with one command, each a scheduler with its own
defaults or, in an administrator's catalog, a scheduler with options.
Its `featured` list is the maintainers' word on which schedulers are
worth reaching for, shown first in the full list. The hidden ones are
kept out of every list because they do not start without a
configuration of their own or are test tools. Everything else that is
installed is available in the full list.

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
  entries it does not mention; `catalog show --shipped` prints the
  shipped one for a client to compare or start a fresh copy from.
  Clients write the override only through `scxcli catalog save` and
  remove it with `scxcli catalog reset`; an administrator may also edit
  it by hand as root. A file that exists but cannot be used
  (unreadable, invalid, untrusted, or a symlink whose target is missing)
  is an error, never a fallback to the shipped catalog: a broken override
  is still the administrator's configuration.
- The format is JSON, version 2 (version 1 still loads; see below):

```json
{
  "version": 2,
  "recommended": [
    { "id": "default", "label": "Default",
      "description": "The kernel's built-in scheduler (no sched_ext scheduler active)." },
    { "id": "scx_cosmos", "label": "Cosmos",
      "description": "Keeps the system responsive under load." },
    { "id": "latency", "label": "Low latency",
      "description": "EEVDF with a short slice.",
      "sched": "scx_eevdf", "args": ["--slice-us", "1600"] }
  ],
  "featured": ["scx_cosmos", "scx_lavd", "scx_eevdf"],
  "hidden": ["scx_layered", "scx_mitosis"],
  "stable": ["scx_bpfland"],
  "experimental": ["scx_flow", "scx_mlfq"]
}
```

The five lists, and what each holds:

- `recommended` holds profiles: what users pick from. `default`, plain
  profiles (a scheduler with its defaults) and, in the administrator's
  catalog, custom profiles (a scheduler with options).
- `featured` holds scheduler names: the schedulers the maintainers
  recommend. They count as stable and come first in the full list.
- `stable` holds scheduler names: the other schedulers the maintainers
  stand behind.
- `experimental` holds scheduler names: schedulers the maintainers do
  not call stable, and say so.
- `hidden` holds scheduler names: left out of every list.

`recommended` and `featured` are two lists because they have two
authors. `featured` is upstream's: which schedulers are worth reaching
for, whoever installs them. `recommended` is the catalog's author's: in
the shipped file the maintainers' picks, in an override whatever the
administrator of that machine offers, options included. An override
that starts as a copy of the shipped file keeps upstream's `featured`
while its profiles change.

Rules, checked by `scx_catalog::Catalog::validate` and so by every load:

- `version` is 1 or 2. `featured`, `sched` and `args` are what version
  2 adds, and a version 1 file may use none of them, so that an older
  tool reading a newer file reports an unsupported version rather than
  an unknown key.
- `recommended` is a non-empty list. `featured`, `hidden`, `stable` and
  `experimental` are lists, possibly empty or absent. Unknown keys are
  an error.
- A profile is plain when it has no `sched`. Its `id` is `default` or a
  scheduler name: a bare `scx_*` name of ASCII letters, digits, `_` and
  `-`, at most 64 characters. Never a path: the executable is found in
  systemd's default search path (`systemd-path search-binaries-default`).
  A plain profile starts its scheduler with the scheduler's own
  defaults; `args` on it is absent or empty (in a version 2 file).
- A profile is custom when it has `sched`. Its `id` is 1 to 64
  lowercase ASCII letters, digits, `_` and `-`, starting with a letter
  or digit (so it is never taken for an option), not `default` and not
  starting with `scx_`, so that `start ID` can never be read as a
  scheduler's name. `sched` is a scheduler name by the rule above, and
  `args` holds at most 32 options, each 1 to 256 characters of ASCII
  letters, digits and `-_=.,:/+` (the allowlist `run` applies). Several
  custom profiles may share a scheduler.
- Ids are unique in the list, profile ids and scheduler names together.
- `label` is 1 to 64 characters and `description` 0 to 256 characters,
  both UTF-8 with no control characters.
- `default` is always present and always first. It means the kernel's
  own scheduler: no sched_ext scheduler runs, and the unit is stopped and
  disabled. An override may change its label and description.
- Custom profiles are accepted only from `/etc/scx/catalog.json`, under
  the trust rules below: their options run as root on any user's
  say-so, so they come only from the file nobody but root could have
  written. The shipped catalog holds none, and one found there is an
  error. A file named with `list --catalog` is read as is, custom
  profiles included, since nothing starts from it.
- A hidden entry is a scheduler name by the same rule, unique, and not
  the scheduler of a plain profile. A custom profile may use a hidden
  scheduler: that is how a hidden scheduler gets the configuration it
  needs.
- A featured entry is a scheduler name by the same rule, unique, and not
  hidden, stable or experimental: it counts as stable on its own, and
  each scheduler is in one tier list at most. The list's order is the
  order the full list shows them in. A featured scheduler needs no
  profile, and a plain profile's scheduler need not be featured. When
  the key is absent the featured schedulers are those of the plain
  profiles, in their order, and in a version 2 file that derived list
  is held to the same rule (a plain profile's scheduler may not also be
  in `stable`); a version 1 file, where that overlap was the norm, is
  read as it was. The shipped catalog writes the list out.
- A stable entry is a scheduler name by the same rule, unique. It is
  the maintainers' word that they stand behind the scheduler. In the
  shipped catalog every featured and stable entry lives under
  `scheds/rust`, and the crate's tests hold it to that; a place there is
  not stability, so a scheduler under `scheds/rust` that is not stable
  by its own account is not listed here.
- An experimental entry is a scheduler name by the same rule, unique,
  not the scheduler of a plain profile, not featured and not stable. It
  may also be hidden. In the shipped catalog the list holds every
  scheduler under `scheds/experimental`, and the ones under
  `scheds/rust` whose own README says they are not for production
  (`scx_chaos`, built to misbehave; `scx_forge`, a base meant to be
  rewritten); the tests record those extras by name. Every scheduler in
  the tree has a tier on record.
- A scheduler the catalog names nowhere is unknown to it: installed,
  and that is all the list says. Nothing is stable by default, however
  it got installed. The tier is information for the lists, not a
  restriction: an experimental or unknown scheduler starts like any
  other.
- Profiles start with no options, except custom profiles in the
  administrator's catalog. Any other options are the administrator's,
  through `run`.

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

Last, the kernel is asked. A scheduler started outside `scx.service`
(from a shell, say) survives the stop and the cleanup, and `default` has
not happened until the kernel's own scheduler runs, so `start default`
fails, naming the attached `ops`, while one is still attached (the error
describes that state; it cannot tell who started it); the unit
is stopped and disabled all the same, and `get` then reports the state
described below (`scheduler` null with `kernel.ops` set), which clients
show as a scheduler outside the unit's control. A scheduler the unit
did run is given a moment to detach first.

`scxcli run SCHED [ARGS...]` writes the same two keys with the options
given. There is no marker telling a `run` from a `start`: the file is
the whole truth, and a scheduler with options in `SCX_FLAGS` is a `run`
by definition, since `start` never writes any.

Writing:

- The environment files are read line by line, the way systemd reads
  `KEY=VALUE` lines with `#` and `;` comments and single-line quoting.
  Four things systemd also accepts are not parsed: a quoted value that
  continues past the end of its line, a quoted value followed by
  anything but blanks on its line (systemd lets a closed quote reopen,
  and the reopened part may run on), a line continued with a trailing
  backslash, and a bare carriage return as a line end (CRLF is fine). Inside double quotes a backslash escapes the next
  character; inside single quotes it is an ordinary character, as in
  systemd. Reading the inside of a multi-line value line by
  line would take an assignment written in it for a real one, so a file
  that uses either is reported (`config_error` names the file and the
  line) and nothing in it is taken for an assignment; while it is, no
  write goes through. A later file with such syntax blocks the write
  the same way. A parser for the full syntax is a possible follow-up.
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
  configuration and an error, never "no override". `catalog save` is
  what writes that file, with the modes above; an administrator may
  also edit it by hand as root.
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
scxcli start ID               # root, or polkit: allow_active=yes
scxcli start                  # root, or polkit: allow_active=yes
scxcli stop                   # root, or polkit: allow_active=yes
scxcli run SCHED [ARGS...]    # root, or polkit: auth_admin_keep
scxcli catalog show [--shipped]          # any user
scxcli catalog save           # root, or polkit: auth_admin_keep
scxcli catalog reset          # root, or polkit: auth_admin_keep
```

Clients that are not root run the privileged commands as
`pkexec scxcli start ID`. scxcli does not escalate on its own.

- `list` and `list recommended` show the recommended entries with the
  current state; `list all` shows every installed scheduler the catalog
  does not hide, the recommended ones marked. `list` in every form
  takes `--json` and `--catalog PATH`; `get` takes only `--json`.
  `--catalog` lists with the named file instead of the installed
  catalog (a checkout's `services/catalog.json`, say, to see what it
  would show before it is installed): the same scan and the same state,
  classified by that file, which is read as is, without the trust rules,
  since nothing privileged follows from it. `source` is then the file
  and `customized` false. No other command takes a catalog: `start` and
  `resume` consult the installed one, since the policy covers what that
  one lists. A client listing with `--catalog` therefore shows custom
  profiles that `start ID` would not run as shown: the installed
  catalog may have no such id, or another command under it. Such a
  client does not start a custom profile from a listing it got that
  way, and says so; `default` and plain profiles are the same command
  under every catalog, so those it may start. Options never travel
  from a listing to `start`: `start` takes an id and nothing else.
- `start ID` takes exactly one argument: `default`; a scheduler from
  `list all` by name, started with its own defaults; or a custom
  profile by its id, started with the scheduler and options the
  installed catalog gives it. What `list all` would not show is refused
  by the same two tests the listing applies: an `scx_*` executable that
  is not a scheduler (`scx_loader`, `scx_forge_agent` and the other
  tools) is not a scheduler here either, and a hidden scheduler is
  refused with a pointer to `run` and to profiles. A profile may name a
  hidden scheduler, but not a tool. A path, or anything that is neither
  a scheduler name nor a profile id in form, is a usage error; an id in
  form that the catalog does not have is a failure.
- `start` alone starts the unit again after `stop`. Because the shipped
  policy lets it run without a password, it starts only what `start
  ID` could have written: `SCX_SCHEDULER` must resolve, through the
  same rules `start` and `run` use, to an executable in systemd's
  default search path; no `SCX_*_OVERRIDE` may be in effect; the
  environment must have resolved; `SCX_FLAGS` must be in the one form
  `start` and `run` write, options separated by single spaces with
  nothing around them, since the unit's shell splits the value on its
  own rules (a no-break space is a separator to a Unicode reader and
  part of a word to bash) and only that form is read the same way by
  both; and then either `SCX_FLAGS` is empty and the scheduler is one
  `list all` would show (a scheduler, not hidden), or the scheduler and
  `SCX_FLAGS` are exactly the command of a custom profile in the
  installed catalog, the same executable and the same options in the
  same order. Anything else is refused, with the
  command that does it with the right authority: `start ID`, which
  rewrites the file and clears overrides, or `run` as an administrator
  for a configuration with options no profile has. A profile edited
  since the selection no longer matches and is refused the same way,
  rather than started as something else. What was validated is the
  executable the value resolves to; what the unit's shell would run is
  the value as written, and a bare name is looked up in that shell's
  own PATH, which a drop-in or an environment file can point elsewhere.
  So when the file holds anything but the resolved absolute path, that
  path is written into it first, with the options as they were, exactly
  as `start ID` would have, and only then is the unit started.
  `reset-failed` precedes the start.
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
- `catalog show` prints the catalog in use (the override when there is
  one, else the shipped file), rendered the way the crate writes it,
  every list included, for a client to edit and send back whole; with
  `--shipped`, the shipped catalog whatever is in use, so a client can
  offer a fresh copy to start from or show what an override differs
  in. `catalog save` reads a whole catalog on standard input, at most
  64 KiB, takes no argument (any is a usage error, so scxcli never
  opens a path it was handed under this action), validates it with the
  administrator's rules (custom profiles allowed, since this is the
  file they are allowed in) before anything is written, and writes it
  as the crate renders it, not byte for byte as it came. The write
  rules are stricter than the read rules: `/etc/scx` must be root's
  and writable by nobody else, sticky or not, since anyone can add an
  entry to a sticky world-writable directory, a symlink under the name
  about to be written included, between any check and the write; and
  a `/etc/scx` or `/etc/scx/catalog.json` that is a symlink is
  refused, as is an existing file the read rules would refuse
  (writing root's catalog into a place someone else controls would
  hand them the password-free `start`). A missing `/etc/scx` is
  created closed (0700, which the umask cannot widen) and then opened
  to 0755, so there is no moment at which another user could put an
  entry in it. The file goes through a scratch file under a fresh
  name, `fsync`, and a rename over the path, which replaces whatever
  directory entry is there, a link that appeared since the check
  included, rather than writing through it. The file is always
  written 0644, whatever an earlier override's mode: what this
  command installs is read by `list` as any user. scxcli does not
  restart anything: a profile whose command changed is the client's
  to start again with `start ID`, and `get` says what runs meanwhile.
  `catalog reset` removes the override, so
  the shipped catalog is in use again; a missing override is not an
  error, a `/etc/scx` that is a symlink is, and an override that is
  itself a symlink is removed as the link it is. Clients run these as
  `pkexec scxcli catalog save < edited.json`; `show` needs no
  privilege and clients run it as themselves.
- There is no `restart`: `start ID` restarts the unit with the
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
      "available": false },
    { "id": "latency", "label": "Low latency", "description": "...",
      "sched": "scx_eevdf", "args": ["--slice-us", "1600"],
      "available": false }
  ],
  "all": [
    { "name": "scx_cosmos", "path": "/usr/bin/scx_cosmos",
      "recommended": true, "featured": true, "tier": "stable" },
    { "name": "scx_bpfland", "path": "/usr/bin/scx_bpfland",
      "recommended": false, "featured": false, "tier": "stable" },
    { "name": "scx_flow", "path": "/usr/bin/scx_flow",
      "recommended": false, "featured": false, "tier": "experimental" },
    { "name": "scx_rake", "path": "/usr/local/bin/scx_rake",
      "recommended": false, "featured": false, "tier": "unknown" }
  ],
  "config": "/etc/default/scx",
  "current": { ... the same object as get ... }
}
```

- `recommended` is the catalog's list of profiles, in its order.
  `available` is whether the entry can be started here: `default`
  always, a scheduler when it is installed in systemd's default search
  path, and `path` is then the resolved executable. A custom profile
  carries `sched`, its scheduler by name, and `args`, its options;
  both keys are absent on a plain profile (`args` is then empty). The
  command a profile stands for is `path` with `args`. The unit's file
  holds that command and not the id, so a client that marks the
  running or the selected profile compares the command: the scheduler
  the kernel reports, or `next`, with exactly those options; a plain
  profile matches with none. Two profiles with one command are both
  marked, and which one was picked is not on record; an
  administrator who wants them told apart gives them different
  options.
- `all` is every `scx_*` scheduler found in that search path, minus the
  hidden ones, with whether a plain profile names it (`recommended`),
  whether the catalog features it (`featured`; absent in older output
  reads as false) and its `tier`:
  `stable`, `experimental`, or `unknown` when the catalog names the
  scheduler nowhere. The featured ones come first, in `featured`'s
  order, then the other stable ones by name, then the experimental ones
  by name, then the unknown ones by name. Clients show the list in this
  order and mark the tier; a client reading older output without the
  field treats it as unknown, since that output made no statement.
- `config` is the unit's environment file, the one starting writes and
  the one clients watch; absent when the unit declares none.

Clients refresh on inotify events for `/etc/scx/catalog.json`,
`/usr/share/scx/catalog.json` and the unit's environment file (`config`
in the listing), not on a timer. The unit's state and the kernel's are
not files that change under inotify, so a client that shows them keeps a
slow poll for those alone.

## polkit

scx ships `org.sched_ext.scxcli.policy` with four actions, told apart
by the `org.freedesktop.policykit.exec.argv1` annotation:

| action                         | argv1     | default           |
|--------------------------------|-----------|-------------------|
| `org.sched_ext.scxcli.start`   | `start`   | `allow_active=yes`|
| `org.sched_ext.scxcli.stop`    | `stop`    | `allow_active=yes`|
| `org.sched_ext.scxcli.run`     | `run`     | `auth_admin_keep` |
| `org.sched_ext.scxcli.catalog` | `catalog` | `auth_admin_keep` |

Starting needs no password because the caller passes only an id: the
scheduler starts with its own defaults, or with the options an
administrator wrote into the trusted catalog for that id, and the
executable comes from systemd's default search path; the risk in a
scheduler is in its options, and the only options this path runs are
the administrator's. Stopping changes nothing about what runs as root.
Starting a scheduler with options of the caller's choosing, or a hidden
one outside a profile, changes what runs as root and needs an
administrator; so does changing the catalog, which decides what the
password-free `start` offers from then on. `catalog show` falls under
the same action when run through pkexec, but needs none of it and
clients run it as themselves. The policy is a separate file: a
distribution that wants every action to need a password ships a
stricter one or none, and scxcli then works only as root.
