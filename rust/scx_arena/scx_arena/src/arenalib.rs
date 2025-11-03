// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Meta Platforms
// Author: Emil Tsalapatis <etsal@meta.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub use crate::bpf_skel::types;

use scx_utils::Topology;
use scx_utils::{Core, Llc};

use std::ffi::CString;
use std::os::raw::c_ulong;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Result;

use libbpf_rs::libbpf_sys;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Object;
use libbpf_rs::ProgramInput;
use libbpf_rs::ProgramMut;

// MAX_CPU_ARRSZ has to be big enough to accomodate all present CPUs.
// Even if it's larger than the size of cpumask_t, we truncate any
// invalid data when passing it to the kernel's topology init functions.
/// Maximum length of CPU mask supported by the library in bits.
const MAX_CPU_SUPPORTED: usize = 640;

/// Holds state related to BPF arenas in the program.
#[derive(Debug)]
pub struct ArenaLib<'a> {
    task_size: usize,
    obj: &'a mut Object,
}

impl<'a> ArenaLib<'a> {
    /// Maximum CPU mask size, derived from MAX_CPU_SUPPORTED.
    const MAX_CPU_ARRSZ: usize = (MAX_CPU_SUPPORTED + 63) / 64;

    /// Amount of pages allocated at once form the BPF map. by the static stack allocator.
    const STATIC_ALLOC_PAGES_GRANULARITY: c_ulong = 8;

    fn run_prog_by_name(&self, name: &str, input: ProgramInput) -> Result<i32> {
        let c_name = CString::new(name)?;
        let ptr = unsafe {
            libbpf_sys::bpf_object__find_program_by_name(
                self.obj.as_libbpf_object().as_ptr(),
                c_name.as_ptr(),
            )
        };
        if ptr as u64 == 0 as u64 {
            bail!("No program with name {} found in object", name);
        }

        let bpfprog = unsafe { &mut *ptr };
        let prog = ProgramMut::new_mut(bpfprog);

        let output = prog.test_run(input)?;

        // Reach into the object and get the fd of the program
        // Get the fd of the test program to run

        return Ok(output.return_value as i32);
    }

    /// Set up basic library state.
    fn setup_arena(&self) -> Result<()> {
        // Allocate the arena memory from the BPF side so userspace initializes it before starting
        // the scheduler. Despite the function call's name this is neither a test nor a test run,
        // it's the recommended way of executing SEC("syscall") probes.
        let mut args = types::arena_init_args {
            static_pages: Self::STATIC_ALLOC_PAGES_GRANULARITY as c_ulong,
            task_ctx_size: self.task_size as c_ulong,
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let ret = self.run_prog_by_name("arena_init", input)?;
        if ret != 0 {
            bail!("Could not initialize arenas, setup_arenas returned {}", ret);
        }

        Ok(())
    }

    fn setup_topology_node(&self, mask: &[u64], id: usize) -> Result<()> {
        let mut args = types::arena_alloc_mask_args {
            bitmap: 0 as c_ulong,
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let ret = self.run_prog_by_name("arena_alloc_mask", input)?;

        if ret != 0 {
            bail!(
                "Could not initialize arenas, setup_topology_node returned {}",
                ret
            );
        }

        let ptr = unsafe {
            &mut *std::ptr::with_exposed_provenance_mut::<[u64; 640]>(
                args.bitmap.try_into().unwrap(),
            )
        };

        let (valid_mask, _) = ptr.split_at_mut(mask.len());
        valid_mask.clone_from_slice(mask);

        let mut args = types::arena_topology_node_init_args {
            bitmap: args.bitmap as c_ulong,
            data_size: 0 as c_ulong,
            id: id as c_ulong,
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let ret = self.run_prog_by_name("arena_topology_node_init", input)?;
        if ret != 0 {
            bail!("arena_topology_node_init returned {}", ret);
        }

        Ok(())
    }

    fn setup_topology(&self) -> Result<()> {
        let topo = Topology::new().expect("Failed to build host topology");

        // Top level - ID 0 is fine as there's only one top-level node
        self.setup_topology_node(topo.span.as_raw_slice(), 0)?;

        for (node_id, node) in topo.nodes {
            self.setup_topology_node(node.span.as_raw_slice(), node_id)?;
        }

        // LLCs need to use their actual LLC ID for proper indexing in topo_nodes
        for (llc_id, llc) in topo.all_llcs {
            self.setup_topology_node(
                Arc::<Llc>::into_inner(llc)
                    .expect("missing llc")
                    .span
                    .as_raw_slice(),
                llc_id,
            )?;
        }

        for (core_id, core) in topo.all_cores {
            self.setup_topology_node(
                Arc::<Core>::into_inner(core)
                    .expect("missing core")
                    .span
                    .as_raw_slice(),
                core_id,
            )?;
        }
        for (_, cpu) in topo.all_cpus {
            let mut mask = [0; Self::MAX_CPU_ARRSZ - 1];
            mask[cpu.id / 64] |= 1 << (cpu.id % 64);
            self.setup_topology_node(&mask, cpu.id)?;
        }

        Ok(())
    }

    /// Create an Arenalib object This call only initializes the Rust side of Arenalib.
    pub fn init(obj: &'a mut Object, task_size: usize, nr_cpus: usize) -> Result<Self> {
        if nr_cpus >= MAX_CPU_SUPPORTED {
            bail!("Scheduler specifies too many CPUs");
        }

        Ok(Self { task_size, obj })
    }

    /// Set up the BPF arena library state.
    pub fn setup(&self) -> Result<()> {
        self.setup_arena()?;
        self.setup_topology()?;

        Ok(())
    }
}
