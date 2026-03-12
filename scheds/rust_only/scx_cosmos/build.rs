fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "scx_cosmos-ebpf",
            root_dir: "scx_cosmos-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("Failed to build scx_cosmos-ebpf eBPF program");
}
