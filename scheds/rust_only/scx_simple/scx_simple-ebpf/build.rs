fn main() {
    scx_vmlinux::generate(&[
        "task_struct",
        "sched_ext_entity",
        "scx_exit_info",
    ])
    .expect("failed to generate vmlinux bindings");
}
