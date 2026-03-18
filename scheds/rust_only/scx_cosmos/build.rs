fn main() {
    // Propagate the kernel_6_16 feature to the eBPF sub-build so that
    // select_cpu_and() code is only compiled when targeting >= 6.16.
    let mut features: Vec<&str> = Vec::new();
    if cfg!(feature = "kernel_6_16") {
        features.push("kernel_6_16");
    }

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "scx_cosmos-ebpf",
            root_dir: "scx_cosmos-ebpf",
            features: &features,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("Failed to build scx_cosmos-ebpf eBPF program");
}
