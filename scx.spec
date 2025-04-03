%global debug_package %{nil}

Name: 		scx
Version:	1%{?dist}
Release:        %autorelease
Summary:	sched-ext/scx scheds


License:	GPLv2
URL:		https://github.com/likewhatevs/scx
Source0:	${nil}

BuildRequires: cargo, rust, elfutils-devel, clang

%description
scx schedulers packaged to simplify perf testing

%prep
%setup -q

%build
export RUSTFLAGS="%build_rustflags"
cargo build --release -p scx_layered -p scx_p2dq -p scx_tickless -p scx_lavd -p scx_bpfland -p scx_flash -p scx_mitosis

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 target/release/scx_layered %{buildroot}/usr/bin/scx_layered
install -m 0755 target/release/scx_p2dq %{buildroot}/usr/bin/scx_p2dq
install -m 0755 target/release/scx_tickless %{buildroot}/usr/bin/scx_tickless
install -m 0755 target/release/scx_lavd %{buildroot}/usr/bin/scx_lavd
install -m 0755 target/release/scx_bpfland %{buildroot}/usr/bin/scx_bpfland
install -m 0755 target/release/scx_flash %{buildroot}/usr/bin/scx_flash
install -m 0755 target/release/scx_mitosis %{buildroot}/usr/bin/scx_mitosis

%files
/usr/bin/scx_layered
/usr/bin/scx_p2dq
/usr/bin/scx_tickless
/usr/bin/scx_lavd
/usr/bin/scx_bpfland
/usr/bin/scx_flash
/usr/bin/scx_mitosis

%changelog
* Thu Apr 03 2025 Pat Somaru <patso@likewhatevs.io> 1.0.11-1
- new package built with tito

%autochangelog

