# AGENTS.md

Instructions for AI agents working in this repository: the conventions for
commits and pull requests, and the maintenance workflows specific to this
tree.

## Basics

- Rust schedulers live under scheds/rust, experimental ones under
  scheds/experimental, and the shared BPF headers under scheds/include.
  Support crates are under rust/ and tools under tools/. The C example
  schedulers live in the kernel tree, under tools/sched_ext.
  DEVELOPER_GUIDE.md covers development kernels and tooling.
- Build with `cargo build` and test with `cargo test`. CI checks `cargo
  fmt`, runs clang-format on the C sources of tools/scxtop,
  scheds/rust/scx_chaos and scheds/rust/scx_mitosis, runs `make -C
  lib/selftests/compat test`, and runs clippy with -Dwarnings on the crates
  whose Cargo.toml sets `ci.use_clippy = true` under
  `[package.metadata.scx]`.
- cid-form schedulers need clang 22 or newer. scx_cargo refuses to build
  them with an older one.
- Editing a header under scheds/include rebuilds the BPF objects, because
  scx_cargo's build script registers those files with cargo. Replacing
  rust/scx_utils/vmlinux.tar.zst does not, so run `cargo clean` after a
  vmlinux.h update.
- Before each commit, run `cargo fmt` and `cargo build`, and check `git diff
  --cached --stat` so that only the intended files are staged. Before a pull
  request, `cargo build`, `cargo fmt -- --check` and `cargo test` must pass.
- Never commit to main. Work on a topic branch and open a pull request
  against main.

## Patch descriptions

A patch description tells a reviewer why the change exists and what they
need to judge it. The diff already shows what changed, so the description is
not a second copy of it in English.

What goes in:

- The rationale, first. Open with the problem or the use case behind the
  change, before any mechanism.
- The design at a high level, including why the obvious simpler approach
  does not work.
- What the diff does not make evident: invariants, ordering and lifetime
  constraints, the correctness argument a reviewer needs, and any check that
  now accepts or rejects something it did not before.
- For a refactor, the mapping that lets a reviewer confirm the old and new
  code are equivalent. "No functional change" is only for changes that leave
  behavior identical.

What stays out:

- Code restated in English: walks through functions, branches and call
  chains, lists of renamed identifiers or touched hunks, paraphrases of
  comments the diff adds.
- Reassurance about what stays the same, unless a reviewer would otherwise
  wonder.
- Speculation about failures nobody observed, severity commentary, test logs
  and machine details.
- Enumerations where one phrase names the whole class.
- Positioning within a series. Refer to landed commits as `<sha12>
  ("subject")`.

How it reads:

- Plain, direct and concise. Say each thing once. Do not restate a point in
  other words, and do not follow a claim with a weaker version of it.
- Short sentences with one claim each. Plain words over formal register, and
  no invented terms.
- Imperative mood ("Add X", not "This adds X"). The subject is `prefix:
  Description`, capitalized after the prefix, and names the impact. Version
  and dependency bumps use the fixed lowercase subjects given under their
  workflows.
- Length follows complexity. A one-line fix gets two or three sentences, a
  mechanical change one short paragraph, and a real change explains only its
  non-obvious parts.
- Short paragraphs, one topic each. A paragraph past eight lines is a wall
  that is hard to read and parse visually, because the reader cannot see
  where one point ends and the next begins. Split it at every point
  boundary.
- ASCII only, wrapped at 76 columns. No em or en dashes and no chains of
  semicolons. Use a period, a comma or parentheses instead.

## Pull requests

- Keep paragraphs short. List the commits as an itemized list, one item per
  commit.
- Describe testing in two or three sentences: the kind of coverage that ran
  and what the change itself leaves open. No test-plan checkboxes, no
  machine sizes or run counts, no build and format checks, and no failures
  that reproduce without the change.

## Syncing the shared headers with the kernel

The kernel's sched_ext tree
(https://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git) carries
the same headers in tools/sched_ext/include as scheds/include here. Both
sides change, so a sync merges them. scx takes the merged result first, and
one kernel patch then copies it into the kernel tree.

1. Sync against the kernel's development branch, the highest-numbered
   for-X.Y branch without a suffix. Topic branches such as
   for-7.3-arena-args are not it. List the files on both sides. Leave out
   scheds/include/lib, which exists only here, the `*.autogen.*` files, and
   non-header files such as scheds/include/.gitignore. The kernel's
   scx/bpf_arena_common.bpf.h is scheds/include/bpf_arena_common.bpf.h here.
2. A file present on only one side needs the maintainer's decision: copy it,
   keep it one-sided, or upstream it. A file that the synced headers include
   has to go up with them. A shared header must not depend on a definition
   that exists only here, such as one under scheds/include/lib. Move such a
   definition into a small dependency-free header in the shared set and
   include that from both places.
3. Find the base: a kernel commit and an scx commit from the last sync whose
   shared files are byte-identical. The kernel side is usually its last
   "Sync ... from the scx repo" commit, and the scx side is the scx commit
   that patch names. Older sync patches name none. Then the scx side is
   usually scx's last `scheds/include: Sync with kernel` commit or one
   shortly after it. When the files differ, step through neighboring commits
   on either side until a byte-identical pair turns up.
4. Merge each differing file three ways, into the scx copy, as below. `diff
   scx/$f merged/$f` shows what scx gains, and `diff kernel/$f merged/$f`
   shows what the kernel patch carries. Attribute every hunk to its commit
   on either side with `git log --no-merges BASE..TIP -- PATH`. A conflict
   needs a resolution the maintainer confirms.
5. When the merged headers use kernel types or enums the current vmlinux.h
   lacks, update vmlinux.h first (see Updating vmlinux.h). Then copy the
   merged files into scheds/include. rust/scx_cargo/bpf_h is a symlink to
   scheds/include and follows along. Update the callers of kfuncs and compat
   helpers whose names or prototypes changed.
6. Update the enum tables. enum_defs.autogen.h and enums_abi.autogen.h are
   regenerated from vmlinux.h. enums.autogen.h and enums.autogen.bpf.h have
   no generator, whatever the kernel copy's header says. They and
   rust/scx_utils/src/enums.rs, which must match them, are the
   hand-maintained list of enumerators the schedulers can look up. Diff the
   kernel's copy of the two tables against ours and add what it has that
   ours lacks, each entry under the enum type the new vmlinux.h shows it in,
   since a lookup under a type the running kernel lacks yields zero without
   an error. The kernel's copy is where kernel changes add their
   enumerators, but its types can go stale, as its task state lookups did
   after the kernel folded the states into scx_ent_flags. Keep our entries
   for enumerators the kernel removed, which zero-fill at load. Enumerators
   in table-covered types that neither copy lists, such as rq and entity
   internals, stay out unless a scheduler needs them.
7. Build, then run `cargo test` and `make -C lib/selftests/compat test`.
   Commit the sync as `scheds/include: Sync with kernel sched_ext/for-X.Y
   (<sha12>)`, with the vmlinux.h update and the caller fixes in commits of
   their own.
8. Send the kernel one patch that copies the synced files into
   tools/sched_ext/include, titled `sched_ext: Sync common and compat
   headers from the scx repo`. Its body names the scx commit the files come
   from as `<sha12> ("subject")` and lists briefly what scx accumulated. The
   autogen headers go in a patch of their own. With the patches applied,
   build the kernel in that tree first, then tools/sched_ext and
   tools/testing/selftests/sched_ext off the same tree, and fix whatever the
   synced headers break there in the same patch. Both tool builds dump their
   vmlinux.h from the tree's own vmlinux. Without one they fall back to the
   running kernel's BTF, and every type that kernel lacks then looks like a
   header error. Before posting, diff every patched kernel file against
   scheds/include. Each shared file must be identical. Post to
   sched-ext@lists.linux.dev against the development branch, with Cc to the
   reviewers scripts/get_maintainer.pl lists.

```sh
# scratch directories base/ kernel/ scx/ merged/, each with scx/ and
# bpf-compat/gnu/ subdirectories; for each differing file $f, named by its
# kernel path (bpf_arena_common.bpf.h sits one level up on the scx side)
git -C $KERNEL show $KBASE:tools/sched_ext/include/$f > base/$f
git -C $KERNEL show for-X.Y:tools/sched_ext/include/$f > kernel/$f
git show main:scheds/include/$f > scx/$f
cp scx/$f merged/$f
git merge-file -L scx -L base -L kernel merged/$f base/$f kernel/$f
```

Record the direction of every hunk and every decision, for the pull request
description.

## Updating vmlinux.h

scheds/vmlinux/arch/ holds one BTF dump per architecture (arm, arm64, mips,
powerpc, riscv, s390 and x86). A dump is named vmlinux-<version>-g<sha12>.h
after `git describe --tags --abbrev=0 --match='v*'` and the kernel commit,
and vmlinux.h in the same directory is a symlink to it.
scheds/vmlinux/vmlinux.h links to arch/x86/vmlinux.h and never changes.
Builds read rust/scx_utils/vmlinux.tar.zst rather than the directory, so
every update regenerates the tarball and commits it together with the dumps.

The builds need pahole 1.22 or newer, bpftool and zstd, plus the cross
toolchains below. The kernel.org crosstool nolibc toolchains work where the
distribution lacks a prefix. Without a new enough pahole, olddefconfig
silently drops CONFIG_DEBUG_INFO_BTF and, with it, CONFIG_SCHED_CLASS_EXT,
so check .config for both.

1. Build vmlinux from the kernel's development branch one architecture at a
   time, in a kernel tree nobody else is using. Remove vmlinux and .config
   first. Run defconfig, append the options below to .config (the same ones
   scripts/gen_vmlinux_h.sh appends), run olddefconfig, then `make
   KCFLAGS=-Wno-error -j$(nproc) vmlinux`. For every architecture except
   x86, pass `ARCH=<arch> CROSS_COMPILE=<prefix>` to every make invocation,
   defconfig and olddefconfig included. The architecture names in the table
   are the kernel's ARCH values. Build x86 natively: a cross
   x86_64-linux-gnu- toolchain has failed the realmode link, even though
   gen_vmlinux_h.sh uses that prefix.
2. Before starting the next architecture, confirm that make exited 0 and
   that the dump below is non-empty. Otherwise a failed build leaves the
   previous architecture's vmlinux behind to be dumped.
3. Dump the BTF with `bpftool btf dump file vmlinux format c` into the
   architecture's directory and run scripts/fixup_vmlinux_h.py on the
   result, which gives struct cpumask a portable size. Wrap the file in
   `#pragma clang diagnostic push`, `#pragma clang diagnostic ignored
   "-Wmissing-declarations"` and a closing `#pragma clang diagnostic pop`,
   which silences the warnings anonymous struct embeddings raise. Point
   vmlinux.h at the new dump by bare file name, `ln -fsT
   vmlinux-<version>-g<sha12>.h vmlinux.h` inside the architecture
   directory, since the build resolves the link relative to that directory.
   Remove the old dump.
4. Regenerate the enum definitions and ABI tables, which CI checks against
   vmlinux.h, and then the tarball, with the reproducible settings shown
   below.
5. Check that every symlink names the new dump, that the x86 dump has the
   types the update was for, that the dumps really are per architecture
   (pt_regs has r15 on x86 and regs[31] on arm64), and that struct cpumask
   has `long unsigned int bits[128]`.
6. Run `cargo clean`, since cached BPF objects keep the old vmlinux.h, then
   `cargo build`, `cargo test` and `make -C lib/selftests/compat test`. A
   -Wmissing-declarations warning from vmlinux.h means a dump lost its
   pragma wrapping. common.bpf.h defines BPF_NO_KFUNC_PROTOTYPES, so a
   conflicting-type error from a kfunc whose signature changed comes from a
   file that includes vmlinux.h directly. Defining BPF_NO_KFUNC_PROTOTYPES
   before that include fixes it.
7. Commit the new dumps, the removal of the old ones, the regenerated enum
   files and the tarball together in one commit.

Options: CONFIG_DEBUG_INFO_REDUCED=n, CONFIG_DEBUG_INFO_DWARF4,
CONFIG_BPF_SYSCALL, CONFIG_DEBUG_INFO_BTF, CONFIG_GROUP_SCHED_BANDWIDTH,
CONFIG_GROUP_SCHED_WEIGHT, CONFIG_CFS_BANDWIDTH, CONFIG_BPF_JIT,
CONFIG_SCHED_CLASS_EXT, CONFIG_CGROUP_SCHED, CONFIG_FTRACE, CONFIG_NUMA,
CONFIG_NUMA_BALANCING and CONFIG_CPUSETS, all =y except the first.

| Architecture | Cross prefix |
| --- | --- |
| arm | arm-linux-gnueabi- |
| arm64 | aarch64-linux-gnu- |
| mips | mips64-linux-gnu- |
| powerpc | powerpc64le-linux-gnu- |
| riscv | riscv64-linux-gnu- |
| s390 | s390x-linux-gnu- |
| x86 | none, native build |

```sh
./scripts/gen_enum_defs.py scheds/vmlinux/vmlinux.h \
    scheds/include/scx/enum_defs.autogen.h \
    scheds/include/scx/enums_abi.autogen.h \
    rust/scx_utils/src/enums_abi.autogen.rs
tar --use-compress-program 'zstd -19' --owner=0 --group=0 --numeric-owner \
    --format=ustar --mtime='1970-01-01 00:00:00 UTC' \
    -cf rust/scx_utils/vmlinux.tar.zst -C scheds vmlinux
```

scripts/gen_vmlinux_h.sh automates the builds, dumps, fixups, symlinks and
regeneration. Run `./scripts/gen_vmlinux_h.sh <kernel-tree>
"$PWD/scheds/vmlinux/arch"` from the repository root, against a kernel tree
with no .config, since the script appends its options to an existing one. It
installs the cross toolchains through the distribution's package manager
with sudo. Where that does not work, run the steps by hand. The pragma
wrapping and the removal of the old dumps are always done by hand, so rerun
the tar command after them. CI checks the tarball against scheds/vmlinux.

## Releases

RELEASE.md describes the monthly release and individual crate bumps. The
steps, and the details that trip them up:

1. Start from an up-to-date main with every pending pull request merged.
   `git tag --sort=-v:refname | head -1` gives the current version, and `git
   log --oneline vX.Y.Z..main | wc -l` the number of commits since it. The
   new version is the previous tag's with its last number incremented.
2. Run `cargo xtask bump-versions --all`, then `cargo build --all-targets`
   to update Cargo.lock. Stage with `git add Cargo.lock '*Cargo.toml'` and
   check that nothing else is staged. The maintainer signs the commit with a
   GPG key CachyOS recognizes: `git commit -S -s -m 'versions: bump versions
   for X.Y.Z <Month> <YYYY> release'`.
3. Run `cargo publish --workspace --dry-run --exclude scx_rlfifo --exclude
   scx_rustland`. Those two crates are excluded because the rustland-core
   builder writes into the source directory. `--allow-dirty` is needed when
   the dry run precedes the bump commit. Until something is published, fixes
   can be amended.
4. Push the branch, open the pull request and wait for CI to pass.
5. `python3 cargo-publish.py` publishes every crate. It needs owner
   permissions on every crate and a token with the publish-new scope. `cargo
   owner --list scx_utils` succeeds only with a valid token, but it does not
   prove the scope. Publishing is not atomic. After a failure it resumes
   with `--start <crate>`, with `-i` to skip crates already published. Every
   published crate must come from a commit that ends up in main, so a source
   fix after a partial publish goes in a new commit, never an amend or a
   rebase.
6. Merge the pull request with a merge commit, never a rebase. With checks
   passing, `gh pr merge N --merge` queues it, or reports it already queued,
   and the merge queue runs CI again before merging. `--admin` is needed
   only when required checks are failing.
7. The maintainer tags the head of the pull request that was published, not
   the merge commit, with a signed tag whose name matches the version in
   Cargo.toml: `git tag -s -m 'vX.Y.Z' vX.Y.Z`, then pushes it.
8. Draft a GitHub release on the tag with the auto-generated changelog.

The crates.io API rejects requests without an identifying User-Agent, so
check a published version in the sparse index instead: the last line of
`https://index.crates.io/<c1c2>/<c3c4>/<crate>` carries it in its vers
field.

An off-cycle bugfix release bumps the targeted crates and every workspace
crate they depend on, `cargo xtask bump-versions -p scx_lavd -p scx_layered`
for example, and goes through a pull request. Publishing it to crates.io is
optional and manual.

## Dependency updates

version-tool.py prints every crate version and dependency spec as JSON on
stdout, applies an edited copy with `-u FILE`, and adds the newest crates.io
versions with `-q`. It uses crates.io's newest stable version, so
pre-releases stay out. The JSON has four sections: 00-versions,
01-rust-versions (the crate versions), 02-rust-deps (the dependency specs)
and, with `-q`, 03-newer-versions. The dump records the first spec it finds
for each dependency, and `-u` writes that value into every Cargo.toml. Its
warnings on stderr flag dependencies whose specs differ across crates, and
all remaining ones should be benign by the end. vers.json is not ignored by
git, so write it outside the tree or delete it, and never commit it.

```sh
python3 version-tool.py 2>/dev/null > vers.json   # dump, edit 02-rust-deps
python3 version-tool.py -u vers.json               # apply
python3 version-tool.py 2>&1 >/dev/null            # remaining warnings
python3 version-tool.py -q 2>/dev/null             # newer versions
```

1. If version-tool.py misparses a Cargo.toml, fix it first and commit the
   fix on its own.
2. Normalize the specs. A spec names the API-breaking point: the major
   version from 1.0 on ("1"), major and minor for 0.x ("0.30"). Exact pins
   ("=0.26.1") and operator specs (">=0.69") stay as they are. Crate
   versions belong to the release workflow and stay untouched. For each
   mismatch warning, set the highest spec, or delete the entry to leave that
   dependency alone. After applying, run `cargo update` and `cargo build`,
   and commit Cargo.lock separately from the Cargo.toml changes.
3. List the newer versions with `-q`. Minor bumps of 0.x crates can break
   the API. Major bumps break it and happen only on request.
4. Bump one dependency per commit, with the subject `crate: bump dep X.Y ->
   X.Z`, `crate1, crate2: bump ...` for several crates, or `Cargo.toml: bump
   ...` when every crate is affected. Edit each Cargo.toml directly rather
   than with sed, since version strings collide across dependencies, and
   check `git diff -- '*.toml'` for collateral changes. Run `cargo update`,
   which is more reliable than `cargo update -p` when the lockfile holds
   several versions, then build.
5. When a bump breaks the build, read the dependency's changelog, migration
   guide or `cargo doc` output before changing any code. Record for each
   dependency its old and new versions, each API change, the files it
   touched, and the changelog or documentation consulted.
6. Run cargo fmt and `cargo clippy --no-deps -p CRATE -- -Dwarnings` for
   every crate with code changes. CI enforces -Dwarnings only on the crates
   that opt into clippy, where deprecations become errors. Bumping ratatui
   is known to trip this.
7. Before the pull request, `cargo build`, `cargo fmt -- --check`, the
   clippy runs and the version-tool.py warning check must all come out
   clean, and `-q` shows what is still outdated.
8. The pull request description lists the bumps that needed code changes and
   what they affected, the crates that need scrutiny, the bumps that needed
   none, any version-tool.py changes, and the recorded API changes. Watch CI
   with `gh pr checks N --repo sched-ext/scx` and fix failures in new
   commits.
