#![cfg(feature = "ktstr-tests")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use ktstr::prelude::*;

declare_scheduler!(MITOSIS, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 2, 4, 2),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--cpu-controller-disabled",
        "--cell-parent-cgroup", "/ktstr",
    ],
});

/// Mount a per-worker cgroupv1 named hierarchy and mkdir level-2
/// cgroups in it. Named v1 (`none,name=...`) requires no subsystem
/// support so works on any kernel with CONFIG_CGROUPS=y.
///
/// The v1 hierarchy lives in its own `kernfs_root` with its own
/// kn id idr. The v1 root cgroup gets `kn->id = 1` (first allocated
/// in the fresh idr). That collides with the hardcoded BPF
/// `root_cgid = 1` default in mitosis.bpf.c — but
/// `bpf_cgroup_from_id(root_cgid=1)` at mitosis_init time searches
/// only `cgrp_dfl_root.kf_root` (the cgroupv2 root) and initializes
/// THAT cgroup's storage, NOT the v1 root's.
///
/// Subsequent `tp_cgroup_mkdir` fires for a level-2 cgroup in the v1
/// hierarchy. `init_cgrp_ctx_with_ancestors` walks the chain. The
/// level-1 ancestor (a v1 cgroup) has no cgrp_ctx, so the walker
/// calls `init_cgrp_ctx` on it, which then calls
/// `lookup_cgrp_ctx(parent_cg)` at mitosis.bpf.c:1510 with parent_cg
/// = v1 root. v1 root's storage was never initialized (different
/// cgroup struct than v2 root), so the non-fallible
/// `lookup_cgrp_ctx` wrapper bails at mitosis.bpf.c:148 with
/// `"cgrp_ctx lookup failed for cgid 1"`.
fn mkdir_v1_level2(stop: &AtomicBool) -> WorkerReport {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;

    let mount_point = PathBuf::from(format!("/tmp/cgv1-{}", tid));
    let _ = std::fs::create_dir(&mount_point);
    let mp_c = std::ffi::CString::new(mount_point.to_str().unwrap().to_string()).unwrap();
    let opts_c = std::ffi::CString::new(format!("none,name=repro{}", tid)).unwrap();
    let src_c = std::ffi::CString::new("cgroup").unwrap();
    let fs_c = std::ffi::CString::new("cgroup").unwrap();
    let mount_rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            mp_c.as_ptr(),
            fs_c.as_ptr(),
            0,
            opts_c.as_ptr() as *const libc::c_void,
        )
    };
    if mount_rc != 0 {
        return WorkerReport {
            tid,
            work_units: 0,
            ..WorkerReport::default()
        };
    }

    // Level-1 ancestor that holds the level-2 leaf we'll churn.
    let level1 = mount_point.join("lvl1");
    let _ = std::fs::create_dir(&level1);

    let mut work_units: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let leaf = level1.join(format!("leaf-{}", work_units));
        if std::fs::create_dir(&leaf).is_ok() {
            let _ = std::fs::remove_dir(&leaf);
        }
        work_units = work_units.wrapping_add(1);
    }

    let _ = std::fs::remove_dir(&level1);
    let _ = unsafe { libc::umount(mp_c.as_ptr()) };
    let _ = std::fs::remove_dir(&mount_point);

    WorkerReport {
        tid,
        work_units,
        ..WorkerReport::default()
    }
}

/// Reproduces mitosis.bpf.c's "cgrp_ctx lookup failed for cgid 1"
/// scx_bpf_error at line 148. With `--cpu-controller-disabled` set,
/// `tp_cgroup_mkdir` fires for every cgroup created system-wide,
/// not just those under `--cell-parent-cgroup`.
/// `init_cgrp_ctx_with_ancestors` walks the new cgroup's ancestor
/// chain and calls `init_cgrp_ctx` on each. For any cgroup whose
/// parent does not have a cgrp_ctx, the
/// `lookup_cgrp_ctx(parent_cg)` call at mitosis.bpf.c:1510 returns
/// NULL and the non-fallible wrapper bails the scheduler:
///
///   EXIT: scx_bpf_error (src/bpf/mitosis.bpf.c:148: cgrp_ctx
///   lookup failed for cgid 1)
///
/// Trigger is reliable when a cgroup is created in a cgroupv1 named
/// hierarchy: mitosis_init only initializes the cgroupv2 default
/// root cgrp_ctx via `bpf_cgroup_from_id(root_cgid=1)` (which
/// searches `cgrp_dfl_root.kf_root`), leaving the v1 root cgroup
/// (also with `kn->id = 1` in its own kernfs idr) with no storage.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 15,
    memory_mib = 1024,
    cleanup_budget_ms = 5000,
)]
fn mitosis_cgrp_ctx_lookup_v1_root(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![Step::with_defs(
        vec![CgroupDef::named("churners")
            .workers(4)
            .work_type(WorkType::custom("mkdir_v1_level2", mkdir_v1_level2))],
        HoldSpec::FULL,
    )];
    execute_steps(ctx, steps)
}
