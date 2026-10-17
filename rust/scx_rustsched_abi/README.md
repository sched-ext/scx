# scx_rustsched_abi

What a Rust BPF sched_ext scheduler and its loader agree on: the layout of
the configuration table the loader fills in and the BPF side reads by
index. The crate compiles for the BPF target and the host, so both sides
take the indexes from the same list.
