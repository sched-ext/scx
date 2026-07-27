fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
