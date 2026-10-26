# Scheduling profiles

A profile is a name for what the machine should do well (Default, Desktop,
Gaming, Low latency, Power saver, Server), backed by a scheduler and its
options. Users pick a profile; scx maintainers decide what backs it.

This file is the contract between the profile file, the `scx_profiles`
library that owns it, the `scxcli` tool that every client drives, and the
clients themselves (scxtui, desktop widgets, scripts). The fixtures under
`rust/scx_profiles/fixtures` are the executable form of this contract:
the library's tests run against them, and clients can copy them to test
their parsers against the same inputs and outputs.

Profiles are built on `scx.service` and plain systemd. There is no daemon
and no D-Bus. The configuration is the unit's `EnvironmentFile`
(`/etc/default/scx`), and the truth about what runs is the kernel's
(`/sys/kernel/sched_ext`).

## Profile file

- scx ships `/usr/share/scx/profiles.json` (`services/profiles.json` in
  the repo).
- Administrators override it with `/etc/scx/profiles.json`. The first
  file found is used, in that order. The two are never merged, so an
  override replaces the whole list and does not pick up upstream changes
  to the profiles it does not mention. `scxcli profiles reset` removes
  the override. A file that exists but cannot be used (unreadable,
  invalid, untrusted, or a symlink whose target is missing) is an error,
  never a fallback to the shipped list: a broken override is still the
  administrator's configuration.
- The format is JSON, version 2:

```json
{
  "version": 2,
  "profiles": [
    { "id": "default", "label": "Default",
      "description": "Use the kernel's default scheduler.",
      "action": "stop" },
    { "id": "gaming", "label": "Gaming",
      "description": "Keep games responsive under background load.",
      "sched": "scx_lavd", "args": ["--performance"] }
  ]
}
```

Rules, checked by `scx_profiles::Profiles::validate` and so by every
load and save:

- `version` is 2.
- `profiles` is a non-empty list. Unknown keys are an error.
- `id` is 1 to 64 characters of lowercase ASCII letters, digits and `-`,
  starting with a letter, and is unique in the list.
- `label` is 1 to 64 characters and `description` 0 to 256 characters,
  both UTF-8 with no control characters.
- A profile has either `action` or `sched`, never both. The only action
  is `stop`, and only `default` may have it: a second profile that
  stops the unit would be indistinguishable from `default` once applied.
- `default` is always present, always first, always `action: "stop"`,
  and cannot be edited or deleted: its whole record is fixed, label
  `Default` and description `Use the kernel's default scheduler.`
  included. It is the kernel's own scheduler and the profile to fall
  back to when a scheduler fails.
- `custom` is reserved and can never be a profile id: it is the marker
  `run` writes (see below).
- `sched` is a bare `scx_*` name (ASCII letters, digits, `_` and `-`,
  at most 64 characters) or an absolute path to one. A path must be
  plain (no `.`, `..`, doubled or trailing `/`) and under `/usr`, `/bin`
  or `/sbin`; when the profile is applied its directory must also be on
  systemd's default search path (`systemd-path
  search-binaries-default`) and the file executable. A bare name is
  resolved to an absolute path when the profile is applied, so a name
  and the path it resolves to match the same profile (profiles compare
  schedulers by basename) and older files keep working.
- `args` is a list, possibly empty, of options. Each is 1 to 256
  characters drawn from ASCII letters, digits and `-_=.,:/+`. Nothing
  else is accepted: the values are written into a file that a shell
  expands unquoted, and the allowlist is what survives that round trip.
  scxcli never runs a shell to interpret anything the user or the
  file supplies; it writes the file and drives `systemctl`. The unit
  itself does run its `ExecStart` through bash, which expands
  `$SCX_SCHEDULER $SCX_FLAGS` unquoted, and the allowlist exists so
  that nothing written survives that expansion as anything but the
  intended words.

The shipped list is a starting point. Which scheduler and options back
each profile is a maintainer decision, made with benchmark data, and it
changes as the schedulers change. Clients must not hard-code it.

## Applied state

Applying a profile writes three keys to the unit's `EnvironmentFile`:

```
SCX_PROFILE=gaming
SCX_SCHEDULER=/usr/bin/scx_lavd
SCX_FLAGS="--performance"
```

then clears any `SCX_SCHEDULER_OVERRIDE` / `SCX_FLAGS_OVERRIDE` from the
systemd manager environment (`systemctl unset-environment`), and runs
`systemctl enable` and `systemctl restart scx.service`, after
`reset-failed` so that a start limit hit by an earlier profile does not
refuse this one.

Applying `default` runs `systemctl disable --now` first, then removes
all three keys. Stopping does not depend on the cleanup: a
configuration that cannot be rewritten (a later file sets the keys,
say) leaves the unit stopped and reports the cleanup failure. After a
successful cleanup nothing of the previous profile is left behind: a
later `systemctl start scx.service` by hand has no scheduler to run and
fails, rather than silently bringing the old one back.

`scxcli run SCHED [ARGS...]` writes `SCX_SCHEDULER` and `SCX_FLAGS` and
sets `SCX_PROFILE=custom`, the reserved marker. A scheduler started this
way reports as Custom in every client even when its scheduler and
options equal a profile's: the marker says the choice was deliberate.
Only a file with no marker at all (one an older tool wrote) is matched
against the list by scheduler and options. A marker that names no
profile in the list (one deleted or renamed since it was applied) is
never a reason to guess either: its scheduler keeps running as Custom.

Writing:

- The write goes to the unit's first `EnvironmentFile=`. Every line
  other than the three keys is kept. The file is replaced atomically
  through a scratch file and a rename, with the original's owner, mode
  and POSIX access ACL carried over. A file that cannot be read, or that
  changes while it is being rewritten, is never overwritten.
- The write is refused when it could not take effect: when a later
  `EnvironmentFile=` sets one of the keys; when an `UnsetEnvironment=`
  on the unit would drop a key the write sets (one the write removes or
  leaves alone, as applying `default` does with all three, is no
  concern); when a non-empty `SCX_SCHEDULER_OVERRIDE` or
  `SCX_FLAGS_OVERRIDE` would still be set after `systemctl
  unset-environment`, that is, in the unit's `Environment=`, a drop-in
  or any environment file, composed the way systemd composes them (a
  later assignment wins, an empty one unsets, `UnsetEnvironment=`
  applies last); or when the unit's environment cannot be assembled (a
  required file is missing or unreadable). The error names the source.
  The administrator's configuration is never edited to make a write go
  through.
- A missing first file is created 0644, whatever the umask: readable by
  every user, since the three managed keys hold nothing secret and `get`
  and `list` must read them as any user, and writable by root only,
  since what the file holds runs as root. `/etc/scx/profiles.json` is
  created the same way by `profiles save`, and `/etc/scx` itself, when
  `profiles save` has to create it, is 0755 whatever the umask. An
  existing file or directory keeps its owner, mode and ACL.
- `/etc/scx/profiles.json` decides what `apply` runs without a
  password, so it is used only when nobody but root could have written
  it: the file and `/etc/scx` must be owned by root and not writable by
  group or others (a sticky directory excepted), and neither may be a
  symlink, since a link could lead through a directory someone else
  controls. The file's owner and mode are taken from the handle it is
  then read from, not from a second lookup of the path. Otherwise every
  command that loads the list refuses, naming the file or directory.
  When `profiles save` has to create `/etc/scx`, the directory is made
  0700 and widened to 0755 only once it exists, so nobody can place
  anything in it first. `profiles save` applies the same rules before
  it writes: it refuses a directory or an existing target that is a
  symlink, not root's, or writable by group or others (here a sticky
  directory is not excepted, since anyone could create a symlink of the
  target's name in it before the file exists), and never follows a
  symlink when writing the list. A `/etc/scx` that is itself a symlink,
  dangling or not, is a broken configuration and an error, never
  "no override".
- Known limitation, kept on purpose: the contract says `get` and `list`
  work for any user, which holds for the files as this tool creates
  them. An administrator who makes the environment file or the profile
  file private (0600) keeps it private; an unprivileged `get` then
  reports `config_error` naming the file, and an unprivileged `list`
  fails to load the list. The tool does not work around that, because
  the environment file may hold other variables the administrator did
  not mean to expose, and a separate world-readable copy of the state
  would be a second source of truth. Administrators who want
  unprivileged clients keep the files readable. The unit's own `EnvironmentFile=`
  entries are read the way systemd lists them, several on one line
  included.

## Detecting the running profile

The current state is read from three sources: the unit's environment,
assembled the way systemd assembles it (manager environment,
`Environment=`, every `EnvironmentFile=` in order, `UnsetEnvironment=`),
the unit's main process (`MainPID` and `/proc/<pid>/cmdline`), and the
kernel (`/sys/kernel/sched_ext/state` and `root/ops`).

- `applied` is the profile named by `SCX_PROFILE` in the assembled
  environment, when it names a profile in the list. Otherwise null,
  which includes the reserved `custom` marker.
- A scheduler is running when the unit is active, its main process is
  known, and the kernel reports an attached scheduler whose ops name
  matches the process (exact, with or without the `scx_` prefix, or
  followed by `_` and a version suffix).
- `profile` is:
  - `applied`, when a scheduler is running and the process's scheduler
    (by basename) and arguments equal the applied profile's `sched` and
    `args`;
  - the first profile in the list with the same scheduler and arguments,
    when a scheduler is running and the file has no marker at all (a
    file written by an older tool); never when there is a marker, be it
    `custom` or the id of a profile no longer in the list;
  - `default`, when no scheduler is attached, the unit is inactive, and
    `applied` is null or `default`;
  - null otherwise.
- `custom` is true when a scheduler is attached and `profile` is null:
  it was started by `run`, or matches no profile, or the applied
  profile's scheduler or arguments no longer match what runs, or the
  applied profile has been deleted, or a scheduler is attached outside
  the unit's control.
- `profile` null and `custom` false together mean that nothing runs and
  something other than `default` was applied: the scheduler failed to
  start or was stopped. `failure` then says why, when the journal says.

## scxcli

```
scxcli list [profiles|scheds] [--json]   # any user
scxcli get [--json]                      # any user
scxcli apply ID               # root, or polkit: allow_active=yes
scxcli stop                   # root, or polkit: allow_active=yes
scxcli start                  # root, or polkit: allow_active=yes
scxcli profiles save          # root, or polkit: auth_admin_keep (list on stdin)
scxcli profiles reset         # root, or polkit: auth_admin_keep
scxcli run SCHED [ARGS...]    # root, or polkit: auth_admin_keep
```

Clients that are not root run the privileged commands as
`pkexec scxcli apply ID`. scxcli does not escalate on its own.

- `apply` takes exactly one argument, a profile id, and rejects anything
  else.
- `profiles` takes exactly `save` or `reset`. `save` reads a complete
  profile file on stdin, validates it, and writes it to
  `/etc/scx/profiles.json`. `reset` removes that file.
- `run` validates the scheduler and each option by the profile rules.
- `list` shows the profiles with the current state and the installed
  schedulers; `list profiles` and `list scheds` show one or the other.
  `list`, `list profiles` and `get` take only `--json`.
- `stop` stops the unit and changes nothing else: the applied profile
  stays in the file, `get` reports it as applied and not running, and
  the next boot or `start` brings it back. It is the counterpart of
  `start`, for a baseline measurement or a test; "no scheduler at all"
  is `apply default`, which also removes the choice.
- `start` starts the unit again after `stop`. Because the shipped
  policy lets it run without a password, it starts only what `apply
  ID` could have started without one: the file must name a profile in
  the list by `SCX_PROFILE` (not `custom`, not `default`, not a profile
  since deleted); `SCX_SCHEDULER` must resolve, through the same rules
  `apply` uses, to the very executable the profile's scheduler resolves
  to (a different file with the same basename, in another directory on
  the search path or off it, is not the profile); `SCX_FLAGS` must be
  the profile's options; no `SCX_*_OVERRIDE` may be in effect; and the
  environment must have resolved. Anything else is refused, with the
  command that does it with the right authority: `apply ID`, which
  rewrites the file and clears overrides, or `run` as an administrator
  for a configuration outside the profiles. A hand-written file with a
  scheduler and no marker is refused for the same reason. `reset-failed`
  precedes the start, as with `apply`.
- There is no `restart`: `apply ID` restarts the unit with the profile,
  and `systemctl restart scx.service` restarts it with the file as it
  is. A `restart` of its own would have to choose between the running
  process and the file, which differ after a hand edit.

Exit codes: 0 success, 1 failure, 2 usage error (unknown command or
argument, invalid id), 3 permission denied (the write or `systemctl`
needs root).

### JSON output

The JSON output has its own version, 1, separate from the file format.
Fields are only added within a version. Clients ignore fields they do
not know.

`scxcli get --json`:

```json
{
  "version": 1,
  "profile": "gaming",
  "applied": "gaming",
  "custom": false,
  "unit": { "active": true, "enabled": true },
  "running": { "sched": "scx_lavd", "args": ["--performance"] },
  "next": { "sched": "/usr/bin/scx_lavd", "args": ["--performance"],
            "override": false },
  "kernel": { "state": "enabled", "ops": "lavd" },
  "failure": null
}
```

- `profile`, `applied` and `custom` are as defined above.
- `unit` is the unit's state: active (its process may be alive) and
  enabled (it starts at boot).
- `running` is the unit's main process, by basename, or null when the
  unit is inactive or the process cannot be read.
- `next` is what the next start would run after the environment is
  resolved like the unit's `ExecStart` does, with `sched` as the file
  holds it (a path when a profile wrote it) and `override` true when an
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

`scxcli list scheds --json`:

```json
{
  "version": 1,
  "schedulers": [
    { "name": "scx_bpfland", "path": "/usr/bin/scx_bpfland" },
    { "name": "scx_lavd", "path": "/usr/bin/scx_lavd" }
  ]
}
```

`scxcli list --json` (and `list profiles --json`, the same object):

```json
{
  "version": 1,
  "source": "/usr/share/scx/profiles.json",
  "customized": false,
  "profiles": [
    { "id": "default", "label": "Default",
      "description": "Use the kernel's default scheduler.",
      "action": "stop", "available": true },
    { "id": "gaming", "label": "Gaming",
      "description": "Keep games responsive under background load.",
      "sched": "scx_lavd", "path": "/usr/bin/scx_lavd",
      "args": ["--performance"], "available": true }
  ],
  "installed": ["scx_bpfland", "scx_cosmos", "scx_lavd"],
  "config": "/etc/default/scx",
  "current": { ... the same object as get ... }
}
```

- `available` is whether the profile's scheduler is installed in
  systemd's default search path. `path` is the resolved executable, or
  absent when it is not.
- `installed` lists every `scx_*` scheduler found in that search path,
  for the advanced path that starts one outside the profiles.
- `config` is the unit's environment file, the one applying writes and
  the one clients watch; absent when the unit declares none.

Clients refresh on inotify events for `/etc/scx/profiles.json`,
`/usr/share/scx/profiles.json` and the unit's environment file (`config`
in the listing), not on a timer. The unit's state and the kernel's are
not files that change under inotify, so a client that shows them keeps a
slow poll for those alone.

## polkit

scx ships `org.sched_ext.scxcli.policy` with three actions, told apart
by the `org.freedesktop.policykit.exec.argv1` annotation:

| action                          | argv1      | default           |
|---------------------------------|------------|-------------------|
| `org.sched_ext.scxcli.apply`    | `apply`    | `allow_active=yes`|
| `org.sched_ext.scxcli.stop`     | `stop`     | `allow_active=yes`|
| `org.sched_ext.scxcli.start`    | `start`    | `allow_active=yes`|
| `org.sched_ext.scxcli.profiles` | `profiles` | `auth_admin_keep` |
| `org.sched_ext.scxcli.run`      | `run`      | `auth_admin_keep` |

Choosing a profile needs no password because the caller passes only an
id from a list that an administrator controls. Stopping changes nothing
about what runs as root. Starting is password-free only because it
starts nothing but a profile from that list, exactly as applied
(above); a file that says anything else is refused. Changing that list, or
starting a scheduler with arbitrary options, changes what runs as root
and needs an administrator. The policy is a separate file: a
distribution that wants every action to need a password ships a stricter
one or none, and scxcli then works only as root.
