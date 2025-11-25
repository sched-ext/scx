This doc explains both how our releases work and the steps the developer performing the release needs to take.

## What's a release?

sched_ext cuts a monthly release of the monorepo. This currently has a semantic
version versioning scheme where we always bump the last number. It may change in
the future, the key here is it's monotonically increasing. These releases are
available at https://github.com/sched-ext/scx/releases which correspond to a git
tag.

### Versioning schemes

There are two versioning schemes involved in the sched_ext releases:
1. The version number included in the tag. This is monotonically increasing, and
   as they have no further metadata, is also the version of the C schedulers.
2. The version number of each Rust crate. Each Rust crate, including the scheduler
   binaries, has its own semantic version. This is also monotonically increasing
   _per crate_, but each crate has no relation to the others or the larger
   sched_ext release version.

When the main scx version is increased every crate version is increased along
with it. However, bumping an independent crate version does not imply bumping
the sched_ext major version. That is, crates may move independently of each other
and the repo, but if the repo cuts a new version every crate will have a new version.

### Guidance for distributions

Distributions are free to choose whether they'd rather package all of the Rust
schedulers together or use a package per crate. However, a per-crate package is
often a better solution, as it both allows sched_ext to bump their versions off
of the monthly cycle for bugfixes, and it allows distributions to hold back a
version of a specific scheduler if bugs are found in the monthly release.

It is not recommended to package from the monorepo for a crate version. That is,
if we bump the version of only `scx_lavd`, that should be packaged with its
dependencies (and preferably source) from crates.io instead of the monorepo.
This allows the scx developer to choose what dependencies you're getting, for
example we might choose to select the same version of scx_utils as the dependency
instead of an intermediate version from the monorepo.

## Cutting a release

This is guidance for sched_ext developers cutting a release. You need a lot of
permissions to do this, which will be explained as we go through.

### The monthly release

There are 3 main steps to the monthly release:
1. Bumping the versions of all crates and cross dependencies in the monorepo.
2. Publishing all of these new crate versions to crates.io.
3. Publishing a tag to GitHub and creating a release.

This roughly looks like:

```
# bump crate versions and all cross dependencies
$ cargo xtask bump-versions --all
# update Cargo.lock
$ cargo build --all-targets
$ git commit -S -s -am 'versions: bump versions for X.Y.Z release'
```

Note we signed this commit. This isn't strictly necessary as we sign the tag below,
but this should be a GPG key that CachyOS is aware of. It's required for their
packaging.

Now it gets a bit tricky. Cargo is still _really_ racy when publishing a
monorepo. We can do our best to make it less painful, but there will always be
opportunities for exciting new failures as-is.

```
$ cargo publish --workspace --dry-run
```

This gets some of the errors involved in publishing. It creates a temporary
crates.io repository locally and checks the interdependencies between crates. It
still misses many reasons for crates.io rejecting a crate, unfortunately.

At this point in the process you can still amend your commit because nothing has
been published to crates.io yet. One the dry run is green, you should push your
commit to the CI and wait for the pull request to be green to. These are all things
you can amend to fix, so it's best to do that first.

Then:
```
$ python3 cargo-publish.py
```

This is a permissions heavy task. You need individual permissions on every crate
published in the repo, and mostly need the `publish_new` permission on your
token too.

This may fail in the middle. That is, it may publish crates that are early in the
ordering then fail to publish a new one later. If this requires source fixes,
push a _new_ commit to the branch - don't rebase/amend! We want all crates.io
publishing to come from a commit that ends in main.

Once all the crates are published you can start the merge into `main`. Don't
rebase because we'll lose the history, a merge commit of possibly several commits
is the best way to maintain history.

```
$ git tag -s -m  'vX.Y.Z' vX.Y.Z
```

This git tag is also important. It should come from the head of the PR you're
merging, _not_ the merge commit into main. This is needed to best replicate the
crates.io versions in the tagged version - you don't want to race with someone
merging and tag from a Git commit that includes other changes that weren't in the
published crate sources.

Same story with the signature as above. If CachyOS aren't aware of your GPG key
it causes them trouble, and often requires force-pushing the tag to sign it later.

Finally, go to https://github.com/sched-ext/scx/releases and draft a new release.
You can select your recently pushed tag and auto-generate a changelog.

### Bumping individual crates

Bumping individual crates outside of the normal monthly release is often necessary
for bugfixes/getting experimental features out into other distributions more quickly.

This is a simpler job. You choose the point in history you want to branch off of.
This may be the last monthly tag, or the last time the crate was updated.

Then run:
```
# increase the version of lavd, layered, and all their dependencies
$ cargo xtask bump-versions -p scx_lavd -p scx_layered
```

This script is a bit excessive at the minute as it bumps every dependency. In
some cases the dependency might be identical to the last version on crates.io and
this might be unnecessary. It is possible to be more precise here.

Now put up the PR and make sure it's green.

Optional: publishing to crates.io. This isn't necessary, but if a distribution
is packaging from crates.io and you want to reach them it can be helpful. There's
no nice script for this at the minute, so it's likely a case of manually attempting
the publish until it succeeds. Sorry!
