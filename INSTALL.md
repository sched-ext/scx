# Install Instructions by Distro

## Ubuntu

`sched_ext` support for Ubuntu is currently provided by the linux-unstable
kernel, available at
[ppa:canonical-kernel-team/unstable](https://launchpad.net/~canonical-kernel-team/+archive/ubuntu/unstable).

#### Upgrading to 25.04 (Plucky Puffin) - recommended

Currently, only the 25.04 release is supported. You can upgrade to 25.04
using the following command:

```
$ sudo do-release-upgrade -d
```

#### Enable ppa:canonical-kernel-team/unstable

```
$ sudo add-apt-repository -y --enable-source ppa:canonical-kernel-team/unstable
```

If you are **not** on Ubuntu 25.04, make sure to select `plucky` as the release
for the linux-unstable ppa:
```
$ sudo sed -i "s/^Suites: .*/Suites: plucky/" \
  /etc/apt/sources.list.d/canonical-kernel-team-ubuntu-unstable-plucky.sources
```

#### Installing the linux-unstable Kernel

```
$ sudo apt install -y linux-generic-wip
$ sudo reboot
```

#### Setting up Dev Environment

```
$ sudo apt install -y build-essential meson cmake cargo rustc clang llvm pkg-config libelf-dev
```

#### Build the scx schedulers from source

```
$ git clone https://github.com/sched-ext/scx.git
$ cd scx
$ meson setup build
$ meson compile -C build
```

#### Install the scx schedulers from source

```
$ meson install -C build
```

## Arch Linux

```
sudo pacman -S scx-scheds
```

#### Setting Up Dev Environment

In addition to the packages from the previous step, install the following.

```
$ sudo pacman -Sy meson cargo bpf pahole
```

## Gentoo Linux
Make sure you build the kernel with the right configuration, installation
should be easy:
```
echo 'sys-kernel/scx ~amd64' >> /etc/portage/package.accept_keywords
emerge sys-kernel/scx
```

## Fedora

CachyOS provides a [community-maintained copr repository](https://copr.fedorainfracloud.org/coprs/bieszczaders/kernel-cachyos) for
CachyOS kernels which has sched-ext support.

#### Installing the Kernel

```sh
$ sudo dnf copr enable bieszczaders/kernel-cachyos
$ sudo dnf install kernel-cachyos kernel-cachyos-devel-matched
$ sudo setsebool -P domain_kernel_load_modules on # Necessary for loading kernel modules
$ sudo reboot
```

#### Installing the Schedulers

The schedulers package is hosted in [another copr](https://copr.fedorainfracloud.org/coprs/bieszczaders/kernel-cachyos-addons)
also maintained by the CachyOS community.

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
```

$ sudo zypper install scx
$ sudo scx_rusty
```

#### Setting up Dev Environment

No additional steps needed here other than what is mentioned in the main README.md.
