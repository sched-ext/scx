// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Meta Platforms
// Author: Emil Tsalapatis <etsal@meta.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_utils::Topology;
use scx_utils::{Core, Llc};

use std::ffi::CString;
use std::os::raw::c_ulong;
use std::sync::Arc;

use anyhow::Result;
use anyhow::bail;

use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Object;
use libbpf_rs::ProgramInput;
use libbpf_rs::ProgramMut;
use libbpf_rs::libbpf_sys;

mod types {
    use std::os::raw::c_ulong;

    #[repr(C)]
    pub(super) struct ArenaInitArgs {
        pub task_ctx_size: c_ulong,
        pub task_ctx_align: c_ulong,
    }

    #[repr(C)]
    pub(super) struct ArenaAllocMaskArgs {
        pub bitmap: c_ulong,
    }

    #[repr(C)]
    pub(super) struct ArenaTopologyNodeInitArgs {
        pub bitmap: c_ulong,
        pub data_size: c_ulong,
        pub id: c_ulong,
    }

    #[repr(C)]
    pub(super) struct ArenaTopologyInitArgs {
        pub max_children: [u32; 5],
    }
}

/// Live BPF arena library state. Returned by setup() and must be kept alive
/// for as long as the scheduler instance uses the arena: dropping it stops
/// and joins the library's background threads.
#[must_use]
#[derive(Debug)]
pub struct ScxLibArena {
    _watcher: crate::Daemon,
    _urcu: Option<crate::Daemon>,
}

impl ScxLibArena {
    /// Number of u64 words needed to hold a mask of @nr_cpus bits.
    fn nr_cpumask_words(nr_cpus: usize) -> usize {
        nr_cpus.div_ceil(64)
    }

    fn run_prog_by_name(obj: &Object, name: &str, input: ProgramInput) -> Result<i32> {
        let c_name = CString::new(name)?;
        let ptr = unsafe {
            libbpf_sys::bpf_object__find_program_by_name(
                obj.as_libbpf_object().as_ptr(),
                c_name.as_ptr(),
            )
        };
        if ptr as u64 == 0_u64 {
            bail!("No program with name {} found in object", name);
        }

        let bpfprog = unsafe { &mut *ptr };
        let prog = ProgramMut::new_mut(bpfprog);

        let output = prog.test_run(input)?;

        // Reach into the object and get the fd of the program
        // Get the fd of the test program to run

        Ok(output.return_value as i32)
    }

    /// Initialize the buddy allocator before allocating any arena objects.
    /// Pass the address of the loaded skeleton's arena globals.
    pub fn init_buddy(obj: &Object, arena_globals: usize) -> Result<()> {
        const CHUNK_BYTES: usize = 1 << 20;

        // SAFETY: The object owns the map, and sysconf takes no pointers.
        let (map, page_size) = unsafe {
            (
                libbpf_sys::bpf_object__find_map_by_name(
                    obj.as_libbpf_object().as_ptr(),
                    c"arena".as_ptr(),
                ),
                usize::try_from(libc::sysconf(libc::_SC_PAGESIZE))?,
            )
        };
        if map.is_null() || page_size == 0 || !CHUNK_BYTES.is_multiple_of(page_size) {
            bail!("Missing libarena map or unsupported page size: {page_size}");
        }
        let mut globals_size = 0;
        // SAFETY: The map belongs to obj and globals_size is writable.
        let (base, map_pages) = unsafe {
            (
                libbpf_sys::bpf_map__initial_value(map, &mut globals_size).cast::<u8>(),
                libbpf_sys::bpf_map__max_entries(map) as usize,
            )
        };
        if base.is_null() {
            bail!("Missing libarena mapping");
        }
        let globals_pages = usize::try_from(globals_size)?.div_ceil(page_size);
        let chunk_pages = CHUNK_BYTES / page_size;
        if globals_pages > map_pages || chunk_pages > map_pages - globals_pages {
            bail!("Libarena globals and reserved prefix exceed the arena");
        }
        // libbpf places globals at the end when the kernel supports it.
        // On older kernels pad the globals to the next chunk boundary.
        let (first_page, prefix_pages) = if arena_globals == base.addr() {
            (globals_pages, globals_pages.next_multiple_of(chunk_pages))
        } else if arena_globals == base.addr() + (map_pages - globals_pages) * page_size {
            (0, chunk_pages)
        } else {
            bail!("Unexpected placement of libarena globals");
        };
        let nr_pages = prefix_pages - first_page;
        if nr_pages != 0 {
            let mut args = [0_u8; 16];
            args[..8].copy_from_slice(&(first_page as u64).to_ne_bytes());
            args[8..].copy_from_slice(&(nr_pages as u64).to_ne_bytes());
            let ret = Self::run_prog_by_name(
                obj,
                "arena_alloc_reserve",
                ProgramInput {
                    context_in: Some(&mut args),
                    ..Default::default()
                },
            )?;
            if ret == -libc::EOPNOTSUPP {
                // SAFETY: The prefix is inside the arena mapping and excludes
                // all globals. No allocation can be live before buddy init.
                unsafe {
                    base.add(first_page * page_size)
                        .write_bytes(0, nr_pages * page_size)
                };
            } else if ret != 0 {
                bail!("Could not reserve libarena prefix: {ret}");
            }
        }

        let ret = Self::run_prog_by_name(obj, "arena_buddy_reset", ProgramInput::default())?;
        if ret != 0 {
            bail!("Could not initialize libarena buddy allocator: {}", ret);
        }
        Ok(())
    }

    /// Set up basic library state after initializing the buddy allocator.
    fn setup_arena(obj: &Object, task_size: usize, task_align: usize) -> Result<()> {
        // Allocate the arena memory from the BPF side so userspace initializes it before starting
        // the scheduler. Despite the function call's name this is neither a test nor a test run,
        // it's the recommended way of executing SEC("syscall") probes.
        let mut args = types::ArenaInitArgs {
            task_ctx_size: task_size as c_ulong,
            task_ctx_align: task_align as c_ulong,
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

        let ret = Self::run_prog_by_name(obj, "arena_init", input)?;
        if ret != 0 {
            bail!("Could not initialize arenas, setup_arenas returned {}", ret);
        }

        Ok(())
    }

    fn setup_topology_node(obj: &Object, nr_cpus: usize, mask: &[u64], id: usize) -> Result<()> {
        let nr_words = Self::nr_cpumask_words(nr_cpus);
        if mask.len() < nr_words {
            bail!(
                "CPU mask has {} words, expected at least {}",
                mask.len(),
                nr_words
            );
        }
        let mask = &mask[..nr_words];

        let mut args = types::ArenaAllocMaskArgs {
            bitmap: 0 as c_ulong,
        };

        // Exclude memory-only NUMA nodes
        if mask.iter().all(|&b| b == 0) {
            return Ok(());
        }

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let ret = Self::run_prog_by_name(obj, "arena_alloc_mask", input)?;

        if ret != 0 {
            bail!(
                "Could not initialize arenas, setup_topology_node returned {}",
                ret
            );
        }

        let valid_mask = unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u64>(args.bitmap.try_into().unwrap()),
                nr_words,
            )
        };
        valid_mask.copy_from_slice(mask);

        let mut args = types::ArenaTopologyNodeInitArgs {
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

        let ret = Self::run_prog_by_name(obj, "arena_topology_node_init", input)?;
        if ret != 0 {
            bail!("arena_topology_node_init returned {}", ret);
        }

        Ok(())
    }

    /// Set the per-level maximum number of children before registering topology
    /// nodes. Each topology node at level L is allocated with
    /// topo_max_children[L] child pointer slots, so these values must be set
    /// before any arena_topology_node_init() calls. The sizes are derived from
    /// the actual host topology to keep per-node allocation as small as
    /// possible.
    fn setup_topology_max_children(obj: &Object, topo: &Topology) -> Result<()> {
        // Compute the maximum number of children at each topology level.
        // TOPO_TOP  (0): children are NUMA nodes
        // TOPO_NODE (1): children are LLCs
        // TOPO_LLC  (2): children are cores
        // TOPO_CORE (3): children are CPUs (SMT threads)
        // TOPO_CPU  (4): leaf nodes, no children
        let max_children: [u32; 5] = [
            topo.nodes.len() as u32,
            topo.nodes.values().map(|n| n.llcs.len()).max().unwrap_or(0) as u32,
            topo.all_llcs
                .values()
                .map(|l| l.cores.len())
                .max()
                .unwrap_or(0) as u32,
            topo.all_cores
                .values()
                .map(|c| c.cpus.len())
                .max()
                .unwrap_or(0) as u32,
            0,
        ];

        let mut args = types::ArenaTopologyInitArgs { max_children };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let ret = Self::run_prog_by_name(obj, "arena_topology_init", input)?;
        if ret != 0 {
            bail!("arena_topology_init returned {}", ret);
        }

        Ok(())
    }

    fn setup_topology(obj: &Object, nr_cpus: usize) -> Result<()> {
        let topo = Topology::new().expect("Failed to build host topology");

        Self::setup_topology_max_children(obj, &topo)?;

        // Top level - ID 0 is fine as there's only one top-level node
        Self::setup_topology_node(obj, nr_cpus, topo.span.as_raw_slice(), 0)?;

        for (node_id, node) in topo.nodes {
            Self::setup_topology_node(obj, nr_cpus, node.span.as_raw_slice(), node_id)?;
        }

        // LLCs need to use their actual LLC ID for proper indexing in topo_nodes
        for (llc_id, llc) in topo.all_llcs {
            Self::setup_topology_node(
                obj,
                nr_cpus,
                Arc::<Llc>::into_inner(llc)
                    .expect("missing llc")
                    .span
                    .as_raw_slice(),
                llc_id,
            )?;
        }

        for (core_id, core) in topo.all_cores {
            Self::setup_topology_node(
                obj,
                nr_cpus,
                Arc::<Core>::into_inner(core)
                    .expect("missing core")
                    .span
                    .as_raw_slice(),
                core_id,
            )?;
        }
        for (_, cpu) in topo.all_cpus {
            let mut mask = vec![0; Self::nr_cpumask_words(nr_cpus)];
            mask[cpu.id / 64] |= 1 << (cpu.id % 64);
            Self::setup_topology_node(obj, nr_cpus, &mask, cpu.id)?;
        }

        Ok(())
    }

    /// Set up the BPF arena library state and, when the object carries the
    /// scx_urcu doorbell, spawn the reclaim daemon. The returned ScxLibArena
    /// owns the library's background threads.
    /// @task_align: task ctx element alignment, 0 for word alignment.
    pub fn setup(
        obj: &Object,
        arena_globals: usize,
        task_size: usize,
        task_align: usize,
        nr_cpus: usize,
    ) -> Result<ScxLibArena> {
        Self::init_buddy(obj, arena_globals)?;
        Self::setup_arena(obj, task_size, task_align)?;
        Self::setup_topology(obj, nr_cpus)?;

        Self::start(obj)
    }

    /// Start the userspace services for BPF arena state initialized by the
    /// caller. The returned ScxLibArena must be kept alive for as long as the BPF
    /// object uses the arena.
    ///
    /// Use this instead of setup() when a scheduler has its own BPF-side arena
    /// initialization and does not use the generic arena topology.
    pub fn start(obj: &Object) -> Result<ScxLibArena> {
        Ok(ScxLibArena {
            _watcher: crate::stream_watcher_spawn(obj)?,
            _urcu: crate::urcu_spawn(obj)?,
        })
    }
}
