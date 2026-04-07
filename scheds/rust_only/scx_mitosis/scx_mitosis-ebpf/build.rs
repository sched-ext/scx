fn main() {
    scx_vmlinux::generate(&[
        "task_struct",
        "sched_ext_entity",
        "scx_exit_info",
        "scx_init_task_args",
        "scx_exit_task_args",
        "cpumask",
        "cgroup",
    ])
    .expect("failed to generate vmlinux bindings");
}
