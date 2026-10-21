// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

// The kfuncs the program calls, declared once for both sides: src/kfuncs.rs
// includes this file to declare them to Rust, and the build includes it to
// add their prototypes to the object's BTF and to export them to the
// linker. Parameter types are the names both sides define, see each
// kfuncs! macro. A #[weak] kfunc may be missing from the kernel, which
// libbpf then resolves to zero. A #[sized] kfunc takes a trailing size
// parameter on kernels that pass the structure's size. A #[safe] kfunc
// takes no pointer, so no argument can make it touch memory it should
// not, and Rust code calls it without `unsafe`.
kfuncs! {
    #[safe] fn scx_bpf_cid_to_cpu(cid: I32) -> I32;
    fn scx_bpf_dsq_insert(task: TaskPtr, dsq_id: U64, slice: U64, enq_flags: U64);
    fn bpf_arena_alloc_pages(map: VoidPtr, address: VoidPtr, count: U32, node: I32, flags: U64) -> VoidPtr;
    fn bpf_cpumask_test_cpu(cpu: U32, mask: CpumaskPtr) -> Bool;
    #[safe] fn scx_bpf_nr_online_cids() -> U32;
    #[safe] fn scx_bpf_cid_curr(cid: I32) -> TaskPtr;
    #[sized] fn scx_bpf_cid_topo(cid: I32, out: TopoPtr);
    fn scx_bpf_task_cid(task: TaskPtr) -> I32;
    #[safe] fn scx_bpf_dsq_nr_queued(dsq_id: U64) -> I32;
    #[safe] fn scx_bpf_now() -> U64;
    fn scx_bpf_task_set_slice(task: TaskPtr, slice: U64) -> Bool;
    fn scx_bpf_task_running(task: TaskPtr) -> Bool;
    #[safe] fn scx_bpf_kick_cid(cid: I32, flags: U64);
    #[safe] fn scx_bpf_nr_cpu_ids() -> U32;
    #[safe] fn scx_bpf_tid_to_task(tid: U64) -> TaskPtr;
    fn bpf_task_acquire(task: TaskPtr) -> TaskPtr;
    fn bpf_task_release(task: TaskPtr);
    #[safe] fn scx_bpf_cidperf_set(cid: I32, perf: U32) -> I32;
    #[safe] fn scx_bpf_this_cid() -> I32;
    #[safe] fn scx_bpf_cpu_to_cid(cpu: I32) -> I32;
    fn scx_bpf_task_set_dsq_vtime(task: TaskPtr, vtime: U64) -> Bool;
    fn scx_bpf_task_cgroup(task: TaskPtr) -> CgroupPtr;
    fn bpf_cgroup_ancestor(cgroup: CgroupPtr, level: I32) -> CgroupPtr;
    fn bpf_cgroup_release(cgroup: CgroupPtr);
    fn bpf_cgroup_from_id(id: U64) -> CgroupPtr;
    fn bpf_arena_free_pages(map: VoidPtr, address: VoidPtr, count: U32);
    fn scx_bpf_dump_bstr(fmt: BytePtr, data: U64Ptr, data__sz: U32);
    #[weak] #[safe] fn scx_bpf_cid_node(cid: I32) -> I32;
    #[weak] fn scx_bpf_cgroup_nr_cpus(cgroup: CgroupPtr) -> U32;
}
