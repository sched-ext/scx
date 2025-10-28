# Install Instructions by Distro

## Ubuntu

#### Upgrading to 25.10 (Questing Quokka) - recommended

Currently, only release 25.04 and newer are supported. If you're using an
earlier release, upgrade to the latest release (25.10) using the command
below:

```
$ sudo do-release-upgrade
```

#### Setting up Dev Environment

```
$ sudo apt install -y build-essential cmake cargo rustc clang llvm pkg-config libelf-dev protobuf-compiler libseccomp-dev libbpf-dev
```

#### Build the scx schedulers from source

```
$ git clone https://github.com/sched-ext/scx.git
$ cd scx
$ make all                    # Build C schedulers
$ cargo build --release       # Build Rust schedulers
```

#### Install the scx schedulers from source

```
$ make install INSTALL_DIR=~/bin                                        # Install C schedulers
$ ls -d scheds/rust/scx_* | xargs -I{} cargo install --path {}          # Install Rust schedulers
```

## Arch Linux

```
sudo pacman -S scx-scheds
```

#### Setting Up Dev Environment

In addition to the packages from the previous step, install the following.

```
$ sudo pacman -Sy cargo bpf pahole
```

## Gentoo Linux
Make sure you build the kernel with the right configuration, installation
should be easy:
```
echo 'sys-kernel/scx ~amd64' >> /etc/portage/package.accept_keywords
emerge sys-kernel/scx sys-libs/libseccomp dev-libs/protobuf
```
The kernel config used for CI can be used as a reference for required configs.
See [kernel.config](kernel.config) for reference.

## Fedora

CachyOS provides a [community-maintained copr repository](https://copr.fedorainfracloud.org/coprs/bieszczaders/kernel-cachyos) for
CachyOS kernels which has sched-ext support.

#### Installing the Kernel

```sh
$ sudo dnf copr enable bieszczaders/kernel-cachyos
$ sudo dnf install kernel-cachyos kernel-cachyos-devel-matched
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

#### Debugging/Security Note

In past documentation it was reccomended to set the SELinux boolean domain_kernel_load_modules on in order to facilitate loading kernel modules by confined domains (e.g. scx_rusty). However recently, this has proven unnecessary in most cases in which the CachyOS kernel is present on the machine. If you expirience issues running your desired scheduler on a Fedora system, you may try running the following command:

```sh
$ sudo setsebool -P domain_kernel_load_modules on
```

NOTE: Running the above command inherently decreases the effectiveness of SELinux in containing malware IF it is present on the machine, by way of allowing a confined domain to load kernel modules, which in theory could allow an attacker to insert malicious code into the kernel.

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
