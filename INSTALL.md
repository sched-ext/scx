# Install Instructions by Distro

## Ubuntu

#### Upgrading to 26.04 (Resolute Raccoon) - recommended

Currently, only release 26.04 and newer are supported. If you're using an
earlier release, upgrade to the latest release (26.04) using the command
below:

```
$ sudo do-release-upgrade
```

#### Setting up Dev Environment

```
$ sudo apt install -y build-essential cmake cargo rustc clang llvm pkg-config libelf-dev protobuf-compiler libseccomp-dev libbpf-dev pahole
```

#### Build the scx schedulers from source

```
$ git clone https://github.com/sched-ext/scx.git
$ cd scx
$ cargo build --release
```

#### Install the scx schedulers from source

```
$ ls -d scheds/rust/scx_* | xargs -I{} cargo install --path {}
```

## Arch Linux

```
sudo pacman -S scx-scheds
```

#### Git Packages (Devario)

[Devario](https://github.com/Seafoam-Labs/devario-custom-packagbuilds) provides
`scx-scheds-git` and `scx-tools-git` built from `main`, in two repositories
(enable **only one**):

- `devario-scx` – upstream `main` without experimental backports.
- `devario-scx-dev` – additionally carries scheduler backports not yet merged
  upstream; may regress, intended for testers.

Import and locally sign the signing key, with `pacman-key`:

```
sudo pacman-key --recv-keys BB62CD2725FD8E25558F900A84F94F672976872C --keyserver hkps://keyserver.ubuntu.com
sudo pacman-key --lsign-key BB62CD2725FD8E25558F900A84F94F672976872C
```

or with [Shelly](https://github.com/Seafoam-Labs/Shelly-ALPM):

```
shelly keyring recv BB62CD2725FD8E25558F900A84F94F672976872C --keyserver hkps://keyserver.ubuntu.com
shelly keyring lsign BB62CD2725FD8E25558F900A84F94F672976872C
```

Add **one** of the repositories to `/etc/pacman.conf`:

```ini
# Upstream-based
[devario-scx]
SigLevel = Required DatabaseOptional
Server = https://mirrors.seafoam-labs.org/devario-scx/$arch
```

```ini
# Experimental backports
[devario-scx-dev]
SigLevel = Required DatabaseOptional
Server = https://mirrors.seafoam-labs.org/devario-scx-dev/$arch
```

Then install:

```
sudo pacman -Syu scx-scheds-git scx-tools-git
```

Note that `main` is a development branch, not a stable release.

#### Setting Up Dev Environment

In addition to the packages from the previous step, install the following.

```
$ sudo pacman -Sy cargo bpf pahole
```

## Gentoo Linux
Make sure you build the kernel with the right configuration, installation
should be easy (pahole is required for BTF):
```
emerge sys-kernel/scx dev-util/pahole
```
The kernel config used for CI can be used as a reference for required configs.
See [kernel.config](kernel.config) for reference.

## Fedora

There are multiple ways to install scx_scheds on Fedora. The simplest way is to use the schedulers [COPR package](https://copr.fedorainfracloud.org/coprs/bieszczaders/kernel-cachyos-addons), which is maintained by the CachyOS community.

```sh
$ sudo dnf copr enable bieszczaders/kernel-cachyos-addons
$ sudo dnf install scx-scheds
```

Alternatively, we also provide a `-git` package that is synced daily to match the upstream repository.

#### Setting up Dev Environment

No additional steps needed here other than what is mentioned in the main README.md.

## Nix

From NixOS 24.11 onwards, `scx` is available on Nixpkgs. Using a kernel of version 6.12+ or later is required.

```nix
{
  services.scx.enable = true;
  services.scx.scheduler = "scx_lavd"; # default is "scx_rustland"
  boot.kernelPackages = pkgs.linuxPackages_latest;
}
```

Then rebuild and reboot your system. You can check if the scheduler is running by:

```shell
  systemctl status scx.service
```

## openSUSE Tumbleweed

The scx package is included in openSUSE Factory and can be installed directly from Tumbleweed.

#### Installing the Schedulers

All schedulers are provided in the scx package

Example:

```sh
$ sudo zypper install scx
$ sudo scx_rusty
```

#### Setting up Dev Environment

No additional steps needed here other than what is mentioned in the main README.md.

## The scheduler catalog (scxcli and scxtui)

A package must deliver these together, since each depends on the others:

- `scxcli` at `/usr/bin/scxcli`, the path the polkit policy names;
- `services/catalog.json` as `/usr/share/scx/catalog.json`;
- `tools/scxcli/org.sched_ext.scxcli.policy` as
  `/usr/share/polkit-1/actions/org.sched_ext.scxcli.policy`;
- `scxtui`, with a runtime dependency on the package that ships `scxcli`
  (it exits at startup when `scxcli` is missing).

By hand:

```
cargo build --release -p scxcli -p scxtui
install -Dm755 target/release/scxcli /usr/bin/scxcli
install -Dm755 target/release/scxtui /usr/bin/scxtui
install -Dm644 services/catalog.json /usr/share/scx/catalog.json
install -Dm644 tools/scxcli/org.sched_ext.scxcli.policy \
    /usr/share/polkit-1/actions/org.sched_ext.scxcli.policy
```

Or, for the data files, `xtask install`. It puts `scx.service`,
`/etc/default/scx`, `/usr/share/scx/catalog.json` and the polkit policy
in place and nothing else: it installs no binaries (the package does
that; note that `cargo install scxcli` on its own lands in
`~/.cargo/bin`, not at the `/usr/bin/scxcli` the policy names), does
not build, does not call `systemctl`,
and on a live system leaves an existing `/etc/default/scx` alone. The
paths are the ones the tools are built with and do not move; only the
unit directory and the polkit actions directory can be set, since those
differ between distributions. The policy is installed as shipped, after
a check that every action in it names `/usr/bin/scxcli`.

Build xtask once, then install from the built binary with
`--source-dir`, so the install step neither compiles nor runs cargo
(`cargo xtask …` is `cargo run`, which would build on demand, and
without `--source-dir` xtask asks `cargo metadata --no-deps` for the
checkout, which `sudo` may not find on its PATH):

```
cargo build --release -p xtask
sudo target/release/xtask install --source-dir .
```

For a package build, stage into `DESTDIR` and let the package manager
own the files:

```
# build()
cargo build --release -p xtask -p scxcli -p scxtui

# package()
target/release/xtask install --source-dir . --destdir "$pkgdir"
install -Dm755 target/release/scxcli "$pkgdir/usr/bin/scxcli"
install -Dm755 target/release/scxtui "$pkgdir/usr/bin/scxtui"
```

`--unitdir` (default `/usr/lib/systemd/system`) and `--polkitdir`
(default `/usr/share/polkit-1/actions`) set the two directories that
vary. Directories the install creates are 0755 whatever the umask;
directories that exist keep their mode.

See [services/CATALOG.md](services/CATALOG.md) for the contract.
