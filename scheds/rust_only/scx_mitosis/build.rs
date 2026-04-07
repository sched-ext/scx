fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "scx_mitosis-ebpf",
            root_dir: "scx_mitosis-ebpf",
            features: &[],
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("Failed to build scx_mitosis-ebpf eBPF program");
}
