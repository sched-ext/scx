fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "scx_simple-ebpf",
            root_dir: "scx_simple-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("Failed to build scx_simple-ebpf eBPF program");
}
