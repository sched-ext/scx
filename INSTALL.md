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
emerge sys-kernel/scx ~amd64
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

[Chaotic Nyx](https://github.com/chaotic-cx/nyx) is maintaining the linux-cachyos kernel and scx-scheds package in a flake.

#### Integrate the repository using flake

<pre lang="nix"><code class="language-nix">
{
  description = "My configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    chaotic.url = "github:chaotic-cx/nyx/nyxpkgs-unstable";
  };

  outputs = { nixpkgs, chaotic, ... }: {
    nixosConfigurations = {
      hostname = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          ./configuration.nix # Your system configuration.
          chaotic.nixosModules.default # OUR DEFAULT MODULE
        ];
      };
    };
  };
}
</code></pre>

#### Add this to your configuration to install the kernel

<pre lang="nix"><code class="language-nix">
{
  boot.kernelPackages = pkgs.linuxPackages_cachyos;
  environment.systemPackages =  [ pkgs.scx ];
}
</code></pre>

Then install the package and reboot your system. After you can use all provided example schedulers.

## openSUSE Tumbleweed

Experimental sched_ext support for openSUSE Tumbleweed is provided by the following
OBS project:

 https://build.opensuse.org/project/show/home:flonnegren:sched-ext

#### Adding the Repository

Add the home:flonnegren:sched-ext repository using:

```
$ sudo zypper addrepo --name sched-ext --refresh --enable https://download.opensuse.org/repositories/home:flonnegren:sched-ext/standard/home:flonnegren:sched-ext.repo
$ sudo zypper refresh
```

#### Installing the Kernel

```
$ sudo zypper install --repo sched-ext --force kernel-default
$ sudo reboot
```

Then the new kernel should be booted by default.

#### Installing the Schedulers

All schedulers are provided in the scx package

Example:
```
$ sudo zypper install scx
$ sudo scx_rusty
```

#### Setting up Dev Environment

No additional steps needed here other than what is mentioned in the main README.md.
