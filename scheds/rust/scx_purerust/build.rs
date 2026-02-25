fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "scx_purerust-ebpf",
            root_dir: "scx_purerust-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("Failed to build scx_purerust-ebpf eBPF program");
}
