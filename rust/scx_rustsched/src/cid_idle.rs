// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The idle CIDs: which ones are idle, and the scans that pick one by
//! topology.
//!
//! The lifecycle is that of lib/cid_idle.h: seed the idle CIDs at init,
//! mirror transitions from ops.update_idle(), claim atomically at
//! selection, and rearm from ops.dispatch(). A reverse walk of the CIDs at
//! init stores each one's core, cluster, shard, LLC and node ranges in the
//! arena, as lib/cid_topology.h does. A CID without topology has ranges of
//! its own, and a kernel whose topology has no clusters gets the LLC as
//! the cluster.
//!
//! The idle state is one mask per shard, the kernel's segment of an LLC
//! cut on core boundaries, each on cache lines of its own, so that idle
//! transitions in one shard do not contend with those in another. A shard
//! that does not start on a core boundary fails init. Each node keeps its
//! shards in a pool of its own, allocated on that node where the kernel
//! has scx_bpf_cid_node(), after a summary with a bit per shard that may
//! have an idle CID: a claim that empties a shard clears the bit and looks
//! again, and a transition that finds it clear sets it. A scan that covers
//! a whole shard skips one whose bit is clear, and the summaries alone say
//! when nothing is idle anywhere, which ends a search at once under load.
//! A table gives each CID's mask word and bit in one line.
//!
//! Each LLC's idle-core hint, fair.c's has_idle_cores, is a bit in its
//! node's hint mask, which follows the summary in the node's pool, so that
//! whether any LLC has an idle core is one word test per node. A full-core
//! check reads the candidate's core in its shard's mask, one word unless
//! the core crosses a word boundary, before one CID is claimed; another
//! selector can still claim a sibling concurrently. Machines without
//! multi-CID cores skip that pass.
//!
//! Claims and transitions are bounded compare and exchange loops, since
//! the kernel rejects fetching bitwise atomics on arena memory. A loop
//! that runs out of retries is counted, and the loader fails the run on
//! it.
//!
//! A scheduler looks for an idle CID with pick(), scx_cid_idle_pick(): an
//! anchor CID, a Scope around it (its core, cluster, LLC, node or the
//! machine) and a Kind (a whole idle core or any idle CID). The scheduler
//! chooses the scopes and their order, and scope_same() tells it when a
//! wider one would repeat the last:
//!
//! ```text
//! let mut cid = pick(task, prev, Scope::Core, Kind::AnyCpu);
//! if cid < 0 && !scope_same(prev, Scope::Core, Scope::Llc) {
//!     cid = pick(task, prev, Scope::Llc, Kind::AnyCpu);
//! }
//! if cid < 0 && !scope_same(prev, Scope::Llc, Scope::Anywhere) {
//!     cid = pick(task, prev, Scope::Anywhere, Kind::AnyCpu);
//! }
//! ```
//!
//! select_idle_cpu() is pick() of the LLC as fair.c walks it, within the
//! SIS_UTIL budget the scheduler sets with set_llc_budget().
//!
//! The scans that run for every CID of a domain are global BPF functions,
//! which the verifier checks once rather than in every caller's state.

use core::{
    ffi::c_void,
    hint::black_box,
    ptr::{null_mut, read_volatile, write_volatile},
};

use crate::kfuncs::{
    bpf_arena_alloc_pages, bpf_cpumask_test_cpu, scx_bpf_cid_curr, scx_bpf_cid_node,
    scx_bpf_cid_to_cpu, scx_bpf_cid_topo, scx_bpf_nr_online_cids,
};
use crate::ops::scx_cid_topo;
use crate::{
    cid_ranges::{RangeBuilder, RangeEnds, SegmentBuilder, word_mask},
    cids, config,
    config::runtime::{DISABLE_NUMA, DISABLE_SMT, SMT_ASYM_PACKING, SMT_WHOLE_CORE},
    cpumask,
    helpers::{self, read_kernel},
    mem,
    pool::arena,
    task_struct,
};

// Per-CPU kernel variables, read as ksyms, see build.rs.
unsafe extern "C" {
    static sd_llc: u64;
    static sd_llc_id: i32;
    static sd_share_id: i32;
}

const BITS_PER_PAGE: u32 = 4096 * 8;
const RANGE_BYTES: u32 = core::mem::size_of::<RangeEnds>() as u32;
const PF_IDLE: u32 = 2;
const CAS_TRIES: u32 = 64;

#[inline(always)]
unsafe fn initialize_topology(out: *mut scx_cid_topo) {
    for index in 0..core::mem::size_of::<scx_cid_topo>() / 4 {
        unsafe { write_volatile(out.cast::<i32>().add(index), -1) };
    }
}

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.idle")]
static mut IDLE: [u64; 8] = [0; 8];

/// Did the kernel give any CID a cluster? A sized scx_bpf_cid_topo() on a
/// kernel without the cluster fields leaves them at -1.
#[inline(always)]
fn has_clusters() -> bool {
    unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(7)) != 0 }
}

#[inline(always)]
unsafe fn cid_topology(cid: i32, out: *mut scx_cid_topo) {
    #[cfg(feature = "topo_size")]
    unsafe {
        scx_bpf_cid_topo(cid, out, core::mem::size_of::<scx_cid_topo>() as u64);
    }
    #[cfg(not(feature = "topo_size"))]
    unsafe {
        scx_bpf_cid_topo(cid, out);
    }
}

/// The idle masks are kept per node, after lib/cid: each node has a pool,
/// NUMA-local where the kernel says which node a CPU is on, that starts
/// with the node's summary, one bit per shard of the node that may have an
/// idle CID, at the shard's first CID. Each shard of the node follows, on
/// cache lines of its own: a header line, then its mask words.
const LINE_BYTES: u64 = 64;
/// A shard header's words: the address of the summary word that holds the
/// shard's bit, that bit, and how many mask words the shard has.
const HEADER_SUMMARY: u64 = 0;
const HEADER_BIT: u64 = 1;
const HEADER_WORDS: u64 = 2;
/// A slot, one per CID: the address of the mask word that holds the CID's
/// idle bit, and the bit's position with the word's index in its shard
/// above it, from bit 6. One line, where the range entry the shard is
/// described in takes a volatile read per field.
const SLOT_BYTES: u64 = 16;

/// The NUMA node of `cid` for allocations, __COMPAT_scx_bpf_cid_node(): the
/// kfunc is weak, and a kernel without it gets NUMA_NO_NODE.
#[inline(always)]
fn cid_node(cid: i32) -> i32 {
    let kfunc = core::hint::black_box(scx_bpf_cid_node as *const c_void);
    if kfunc.is_null() {
        return -1;
    }
    unsafe { scx_bpf_cid_node(cid) }.max(-1)
}

/// Bytes a shard of `nr` CIDs takes in its node's pool: a header line and
/// its mask words, on whole lines.
#[inline(always)]
fn shard_bytes(nr: u32) -> u64 {
    LINE_BYTES + (u64::from(nr.div_ceil(64)) * 8).next_multiple_of(LINE_BYTES)
}

/// Bytes the summary of a node of `nr` CIDs takes, on whole lines.
#[inline(always)]
fn summary_bytes(nr: u32) -> u64 {
    (u64::from(nr.div_ceil(64)) * 8).next_multiple_of(LINE_BYTES)
}

/// `cid`'s slot entry.
#[inline(always)]
unsafe fn slot_entry(cid: u32) -> u64 {
    let base = unsafe { read_volatile((&raw const IDLE).cast::<u64>()) };
    base + u64::from(cid) * SLOT_BYTES
}

/// The address of `cid`'s mask word, and the position word.
#[inline(always)]
unsafe fn slot(cid: u32) -> (u64, u64) {
    let entry = unsafe { slot_entry(cid) };
    unsafe { (mem::load(entry, 0), mem::load(entry, 8)) }
}

/// The address of the word holding `cid`'s idle bit, and the bit.
#[inline(always)]
unsafe fn word(cid: u32) -> (u64, u64) {
    let (address, position) = unsafe { slot(cid) };
    (address, 1_u64 << (position & 63))
}

/// The address of the header of `cid`'s shard.
#[inline(always)]
unsafe fn header(cid: u32) -> u64 {
    let (address, position) = unsafe { slot(cid) };
    address - (position >> 6) * 8 - LINE_BYTES
}

/// The node table entry of `node`, a node's first CID: its pool, whose
/// summary words come first.
#[inline(always)]
unsafe fn node_entry(node: u32) -> u64 {
    let base = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(4)) };
    base + u64::from(node) * 8
}

/// Is every mask word of the shard whose header is at `header` clear?
#[inline(always)]
unsafe fn shard_empty(header: u64) -> bool {
    let words = unsafe { mem::load(header + HEADER_WORDS * 8, 0) }.min(64) as u32;
    let mut empty = true;
    unsafe {
        for value in crate::loops::range(0, words) {
            if mem::load(header + LINE_BYTES + u64::from(value) * 8, 0) != 0 {
                empty = false;
                break;
            }
        }
    }
    empty
}

/// Set or clear the summary bit of the shard whose header is at `header`.
#[inline(always)]
unsafe fn summary_update(header: u64, set: bool) {
    unsafe {
        let summary = mem::load(header + HEADER_SUMMARY * 8, 0);
        let bit = mem::load(header + HEADER_BIT * 8, 0);
        cas_update(summary, bit, set);
    }
}

/// Is the summary bit of the shard whose header is at `header` set?
#[inline(always)]
unsafe fn summary_test(header: u64) -> bool {
    unsafe {
        let summary = mem::load(header + HEADER_SUMMARY * 8, 0);
        mem::load(summary, 0) & mem::load(header + HEADER_BIT * 8, 0) != 0
    }
}

/// Is no CID idle anywhere, scx_cid_idle_empty()? One look at each node's
/// summary: nearly always the answer under load, without a scan.
#[inline(always)]
pub fn idle_empty() -> bool {
    !node_masks_any(false)
}

/// Is a bit set in any node's summary, or with `hints` in any node's
/// idle-core hints? Out of line: the wakeup paths ask it in several places.
#[inline(never)]
fn node_masks_any(hints: bool) -> bool {
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    let mut node = 0;
    let mut found = false;
    unsafe {
        for _ in crate::loops::range(0, count) {
            if node >= count {
                break;
            }
            let end = range_field(node, 6).min(count);
            if end <= node {
                break;
            }
            let mut mask = mem::load(node_entry(node), 0);
            if hints {
                mask += summary_bytes(end - node);
            }
            let words = (end - node).div_ceil(64);
            let mut word_index = 0;
            while word_index < words.min(64) {
                if mem::load(mask + u64::from(word_index) * 8, 0) != 0 {
                    found = true;
                    break;
                }
                word_index += 1;
            }
            if found {
                break;
            }
            node = end;
        }
    }
    found
}

/// The address of `cid`'s range entry.
#[inline(always)]
unsafe fn range(cid: u32) -> u64 {
    let base = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(2)) };
    base + u64::from(cid) * u64::from(RANGE_BYTES)
}

/// The idle-core hint of the LLC whose first CID is `llc`: fair.c's
/// sd_llc_shared->has_idle_cores, a bit in its node's mask of them, after
/// the node's summary, as lib/cid keeps node_core_llcs. Set by
/// an idle transition that leaves a whole core idle, cleared by a
/// whole-core scan that finds none, so that a scan under load does not look
/// for idle cores that are not there.
#[inline(always)]
unsafe fn hint_bit(llc: u32) -> (u64, u64) {
    unsafe {
        let node = (mem::load(base_word(llc), 0) >> 32) as u32;
        let end = range_field(node, 6);
        let hints = mem::load(node_entry(node), 0) + summary_bytes(end.saturating_sub(node));
        let offset = llc.saturating_sub(node);
        (hints + u64::from(offset / 64) * 8, 1_u64 << (offset % 64))
    }
}

/// Set or clear the idle-core hint of the LLC whose first CID is `llc`.
/// The LLCs of a node share words, so the update is a CAS.
#[inline(always)]
unsafe fn hint_set(llc: u32, set: bool) {
    let (pointer, bit) = unsafe { hint_bit(llc) };
    unsafe { cas_update(pointer, bit, set) };
}

/// Set or clear `bit` in the arena word at `pointer`, by bounded CAS.
#[inline(always)]
unsafe fn cas_update(pointer: u64, bit: u64, set: bool) {
    for _ in crate::loops::range(0, CAS_TRIES) {
        let previous = unsafe { mem::load(pointer, 0) };
        let next = if set { previous | bit } else { previous & !bit };
        if previous == next || unsafe { mem::cas(pointer, previous, next) } == previous {
            return;
        }
    }
    crate::pool::count_cas_failure();
}

/// The first CID of `cid`'s LLC.
#[inline(always)]
fn llc_of(cid: i32) -> u32 {
    unsafe { mem::load(base_word(cid as u32), 0) as u32 }
}

/// Does `cid`'s LLC have a whole idle core, by the hint?
#[inline(always)]
fn has_idle_core(cid: i32) -> bool {
    valid(cid) && {
        let (pointer, bit) = unsafe { hint_bit(llc_of(cid)) };
        (unsafe { mem::load(pointer, 0) } & bit) != 0
    }
}

/// The runtime's options, see scx_rustsched_abi.
#[inline(always)]
fn options() -> u64 {
    config::get(config::RUNTIME_OPTIONS)
}

/// SMT_WHOLE_CORE: a whole idle core anywhere wins over a busy core's
/// sibling.
#[inline(always)]
pub fn smt_whole_core() -> bool {
    (options() & SMT_WHOLE_CORE) != 0
}

/// Does any LLC have a whole idle core, by the hints? Out of line, to keep
/// its loop out of the caller's frame.
#[inline(never)]
pub fn any_idle_core() -> bool {
    node_masks_any(true)
}

/// test_idle_cores(): does `cid`'s LLC have a whole idle core, by its hint?
#[inline(always)]
pub fn test_idle_cores(cid: i32) -> bool {
    has_idle_core(cid)
}

/// set_idle_cores(cpu, false): a scan of `cid`'s LLC for a whole idle core
/// found none, so clear its hint until a core goes idle there.
#[inline(always)]
pub unsafe fn clear_idle_cores(cid: i32) {
    unsafe { hint_set(llc_of(cid), false) }
}

/// The walk select_idle_cpu() makes of `target`'s LLC: the cluster of
/// `target` from the CID after it, wrapping, then the CIDs after the
/// cluster and the CIDs before it. Without `cluster_first` the cluster is
/// the whole LLC. llc_walk_cid() gives the CID at a position of the walk
/// and llc_walk_pos() the position of a CID of that LLC.
#[inline(always)]
pub fn llc_walk_cid(target: i32, cluster_first: bool, position: u32) -> i32 {
    if !valid(target) {
        return -1;
    }
    let ends = unsafe { read_range(target as u32) };
    let llc_base = llc_of(target);
    let (base, end) = if cluster_first {
        (ends.cluster_base, ends.cluster)
    } else {
        (llc_base, ends.llc)
    };
    let nr = end.saturating_sub(base);
    let start = if (target as u32) + 1 < end {
        target as u32 + 1
    } else {
        base
    };
    let rest = ends.llc.saturating_sub(base);
    let cid = if position < nr {
        if start + position < end {
            start + position
        } else {
            start + position - nr
        }
    } else if position < rest {
        base + position
    } else {
        llc_base + position - rest
    };
    cid as i32
}

#[inline(always)]
pub fn llc_walk_pos(target: i32, cluster_first: bool, cid: i32) -> u32 {
    if !valid(target) {
        return u32::MAX;
    }
    let ends = unsafe { read_range(target as u32) };
    let llc_base = llc_of(target);
    let (base, end) = if cluster_first {
        (ends.cluster_base, ends.cluster)
    } else {
        (llc_base, ends.llc)
    };
    let nr = end.saturating_sub(base);
    let start = if (target as u32) + 1 < end {
        target as u32 + 1
    } else {
        base
    };
    let cid = cid as u32;
    if cid >= end {
        cid - base
    } else if cid >= base {
        if cid >= start {
            cid - start
        } else {
            cid + nr - start
        }
    } else {
        ends.llc.saturating_sub(base) + cid - llc_base
    }
}

/// test_idle_cores() for select_idle_capacity(): the hint of `cid`'s LLC,
/// or with a `shared` asymmetric domain, `range`, whether any of the
/// domain's LLCs has one.
#[inline(always)]
pub fn asym_has_idle_core(cid: i32, range: u64, shared: bool) -> bool {
    if !shared {
        return has_idle_core(cid);
    }
    let mut found = false;
    unsafe {
        for_each_llc(range, |llc| {
            let (pointer, bit) = hint_bit(llc);
            found = mem::load(pointer, 0) & bit != 0;
            found
        })
    };
    found
}

/// set_idle_cores(cpu, false) for select_idle_capacity(), over every LLC
/// of a `shared` asymmetric domain, `range`.
#[inline(always)]
pub unsafe fn asym_clear_idle_cores(cid: i32, range: u64, shared: bool) {
    if !shared {
        if valid(cid) {
            unsafe { hint_set(llc_of(cid), false) };
        }
        return;
    }
    unsafe {
        for_each_llc(range, |llc| {
            hint_set(llc, false);
            false
        })
    };
}

/// Run `body` on the first CID of each LLC in `range`, nr:base, until it
/// returns true.
#[inline(always)]
unsafe fn for_each_llc(range: u64, mut body: impl FnMut(u32) -> bool) {
    let (base, nr) = (range as u32, (range >> 32) as u32);
    let mut llc = base;
    unsafe {
        for _ in crate::loops::range(0, nr) {
            if llc >= base + nr || !valid(llc as i32) || body(llc) {
                break;
            }
            llc = range_field(llc, 5);
        }
    }
}

/// An idle transition of `cid`: if its whole core is idle now, say so in
/// its LLC's hint, written only when it was clear.
#[inline(always)]
unsafe fn note_idle_core(cid: i32) {
    if !smt() || has_idle_core(cid) {
        return;
    }
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    if unsafe { core_idle(cid as u32, count) } {
        unsafe { hint_set(llc_of(cid), true) };
    }
}

/// The address of the word of `cid`'s CPU.
#[inline(always)]
unsafe fn cpu_word(cid: u32) -> u64 {
    let base = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(6)) };
    base + u64::from(cid) * 4
}

/// The CPU of `cid`, cached at init as scx_eevdf caches it: the kfunc
/// looks the scheduler up on every call. -1 for an invalid CID.
#[inline(always)]
pub fn cpu(cid: i32) -> i32 {
    if !valid(cid) {
        return -1;
    }
    unsafe { mem::load32(cpu_word(cid as u32), 0) as i32 }
}

/// The address of the word of `cid`'s LLC and node bases, `node << 32 |
/// llc`.
#[inline(always)]
unsafe fn base_word(cid: u32) -> u64 {
    let base = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(5)) };
    base + u64::from(cid) * 8
}

#[inline(always)]
unsafe fn write_range(cid: u32, ends: RangeEnds) {
    let pointer = unsafe { range(cid) };
    unsafe {
        mem::store32(pointer, 0, ends.core_base);
        mem::store32(pointer, 4, ends.core);
        mem::store32(pointer, 8, ends.cluster);
        mem::store32(pointer, 12, ends.shard_base);
        mem::store32(pointer, 16, ends.shard);
        mem::store32(pointer, 20, ends.llc);
        mem::store32(pointer, 24, ends.node);
        mem::store32(pointer, 28, ends.segment_word);
        mem::store32(pointer, 32, ends.cluster_base);
    }
}

/// One field of `cid`'s range entry, by its index in write_range(). An
/// arena read is never dropped, so read_range() loads all nine fields
/// even for a caller that wants one.
#[inline(always)]
unsafe fn range_field(cid: u32, index: usize) -> u32 {
    unsafe { mem::load32(range(cid), index as u64 * 4) }
}

#[inline(always)]
unsafe fn read_range(cid: u32) -> RangeEnds {
    let pointer = unsafe { range(cid) };
    unsafe {
        RangeEnds {
            core_base: mem::load32(pointer, 0),
            core: mem::load32(pointer, 4),
            cluster: mem::load32(pointer, 8),
            shard_base: mem::load32(pointer, 12),
            shard: mem::load32(pointer, 16),
            llc: mem::load32(pointer, 20),
            node: mem::load32(pointer, 24),
            segment_word: mem::load32(pointer, 28),
            cluster_base: mem::load32(pointer, 32),
        }
    }
}

unsafe fn initialize_ranges(count: u32) -> i32 {
    let pages = (count * RANGE_BYTES).div_ceil(4096);
    let table = unsafe { bpf_arena_alloc_pages((&raw mut arena).cast(), null_mut(), pages, -1, 0) };
    let bases = unsafe {
        bpf_arena_alloc_pages(
            (&raw mut arena).cast(),
            null_mut(),
            (count * 8).div_ceil(4096),
            -1,
            0,
        )
    };
    let cpus = unsafe {
        bpf_arena_alloc_pages(
            (&raw mut arena).cast(),
            null_mut(),
            (count * 4).div_ceil(4096),
            -1,
            0,
        )
    };
    if table.is_null() || bases.is_null() || cpus.is_null() {
        return -12;
    }
    unsafe { IDLE[6] = cpus as u64 };
    unsafe {
        IDLE[2] = table as u64;
        IDLE[5] = bases as u64;
    }
    let mut builder = RangeBuilder::new();
    for value in crate::loops::range(0, count) {
        let cid = count - 1 - value;
        let mut topology = core::mem::MaybeUninit::<scx_cid_topo>::uninit();
        unsafe { initialize_topology(topology.as_mut_ptr()) };
        unsafe { cid_topology(cid as i32, topology.as_mut_ptr()) };
        let topology = unsafe { topology.assume_init() };
        // A kernel without the cluster fields leaves them at -1.
        #[cfg(feature = "topo_size")]
        let cluster = if topology.cluster_cid >= 0 {
            unsafe { IDLE[7] = 1 };
            topology.cluster_cid
        } else {
            topology.llc_cid
        };
        #[cfg(not(feature = "topo_size"))]
        let cluster = topology.llc_cid;
        let shard = if topology.shard_cid >= 0 {
            topology.shard_cid
        } else {
            topology.llc_cid
        };
        // DISABLE_SMT makes every CID a core of its own, and DISABLE_NUMA
        // the machine one node.
        let options = options();
        let core = if options & DISABLE_SMT != 0 {
            cid as i32
        } else {
            topology.core_cid
        };
        let node = if options & DISABLE_NUMA != 0 {
            0
        } else {
            topology.node_cid
        };
        let ends = builder.add(cid, core, cluster, shard, topology.llc_cid, node);
        if ends.core > ends.core_base + 1 {
            unsafe { IDLE[3] = 1 };
        }
        unsafe { write_range(cid, ends) };
        // The LLC's and the node's first CIDs, which wakeups and balance
        // ask for without a kfunc call each.
        let llc = if topology.llc_cid >= 0 {
            topology.llc_cid as u32
        } else {
            cid
        };
        let node = if node >= 0 { node as u32 } else { cid };
        unsafe { mem::store(base_word(cid), 0, u64::from(llc) | u64::from(node) << 32) };
        unsafe { mem::store32(cpu_word(cid), 0, scx_bpf_cid_to_cpu(cid as i32) as u32) };
    }
    let nodes = unsafe {
        bpf_arena_alloc_pages(
            (&raw mut arena).cast(),
            null_mut(),
            (count * 8).div_ceil(4096),
            -1,
            0,
        )
    };
    if nodes.is_null() {
        return -12;
    }
    unsafe { IDLE[4] = nodes as u64 };
    // Check the shards, and add up what each node's shards take, in its
    // node table entry for now.
    let mut segments = SegmentBuilder::new();
    for value in crate::loops::range(0, count) {
        let cid = value;
        let ends = unsafe { read_range(cid) };
        let node = unsafe { mem::load(base_word(cid), 0) >> 32 } as u32;
        // A shard starts on a core boundary and lies within one node.
        if (cid == ends.shard_base && ends.core_base != cid)
            || ends.shard_base < node
            || ends.shard > ends.node
            || segments.add(cid, ends.shard_base, ends.shard).is_none()
        {
            return -22;
        }
        if cid == ends.shard_base {
            let bytes = shard_bytes(ends.shard - ends.shard_base);
            unsafe { mem::store(node_entry(node), 0, mem::load(node_entry(node), 0) + bytes) };
        }
    }
    // Allocate each node's pool, on its node, and lay its summary and its
    // shards out in it.
    let (mut summary, mut cursor) = (0_u64, 0_u64);
    for value in crate::loops::range(0, count) {
        let cid = value;
        let ends = unsafe { read_range(cid) };
        let node = unsafe { mem::load(base_word(cid), 0) >> 32 } as u32;
        if cid == node {
            // The summary, then the LLCs' idle-core hints, the same size.
            let summary_bytes = summary_bytes(ends.node - node);
            let bytes = 2 * summary_bytes + unsafe { mem::load(node_entry(node), 0) };
            let numa = cid_node(cid as i32);
            let pool = unsafe {
                bpf_arena_alloc_pages(
                    (&raw mut arena).cast(),
                    null_mut(),
                    bytes.div_ceil(4096) as u32,
                    numa,
                    0,
                )
            };
            if pool.is_null() {
                return -12;
            }
            summary = pool as u64;
            cursor = summary + 2 * summary_bytes;
            unsafe { mem::store(node_entry(node), 0, summary) };
        }
        if cid == ends.shard_base {
            let offset = cid - node;
            let header = cursor;
            let shard_words = u64::from((ends.shard - cid).div_ceil(64));
            unsafe {
                mem::store(
                    header + HEADER_SUMMARY * 8,
                    0,
                    summary + u64::from(offset / 64) * 8,
                );
                mem::store(header + HEADER_BIT * 8, 0, 1_u64 << (offset % 64));
                mem::store(header + HEADER_WORDS * 8, 0, shard_words);
            }
            cursor += shard_bytes(ends.shard - cid);
        }
        let position = u64::from(cid - ends.shard_base);
        let first_word = cursor - shard_bytes(ends.shard - ends.shard_base) + LINE_BYTES;
        unsafe {
            let entry = slot_entry(cid);
            mem::store(entry, 0, first_word + position / 64 * 8);
            mem::store(entry, 8, (position / 64) << 6 | position % 64);
        }
    }
    // Every CID starts idle; a claim or an idle exit clears a busy one.
    for value in crate::loops::range(0, count) {
        unsafe { set(value as i32) };
    }
    0
}

/// The SIS_UTIL budgets, sis_idle_scan_nr(): how many CIDs a wakeup's scan
/// of an LLC may look at, kept at the LLC's base CID, and the budget of an
/// asymmetric capacity domain, at its base, zero while unset, two u32 in
/// one per-CID word. The policy's periodic balance measures and sets them;
/// they are zero until then, and read whole when the scan is unbounded.
#[inline(always)]
unsafe fn budget(cid: i32, asym: bool) -> u32 {
    let offset = cids::BUDGETS * 8 + if asym { 4 } else { 0 };
    unsafe { mem::load32(cids::entry(cid), offset) }
}

#[inline(always)]
unsafe fn set_budget(cid: i32, asym: bool, budget: u32) {
    let offset = cids::BUDGETS * 8 + if asym { 4 } else { 0 };
    unsafe { mem::store32(cids::entry(cid), offset, budget) }
}

/// Is the scan bounded at all, SIS_UTIL? Set once by the policy.
#[inline(always)]
pub fn scan_bounded() -> bool {
    cids::flag(cids::SCAN_BOUNDED)
}

pub unsafe fn set_scan_bounded(bounded: bool) {
    unsafe { cids::set_flag(cids::SCAN_BOUNDED, bounded) }
}

/// How many CIDs a wakeup may scan in `cid`'s LLC, u32::MAX for no bound.
#[inline(always)]
pub fn scan_budget(cid: i32) -> u32 {
    if !scan_bounded() || !valid(cid) {
        return u32::MAX;
    }
    unsafe { budget(llc_of(cid) as i32, false) }
}

#[inline(always)]
pub unsafe fn set_llc_budget(base: i32, budget: u32) {
    unsafe { set_budget(base, false, budget) }
}

/// The asymmetric domain's budget kept at `base`, raw: zero while unset.
#[inline(always)]
pub fn asym_budget(base: i32) -> u32 {
    unsafe { budget(base, true) }
}

#[inline(always)]
pub unsafe fn set_asym_budget(base: i32, budget: u32) {
    unsafe { set_budget(base, true, budget) }
}

pub unsafe fn init() -> i32 {
    let count = unsafe { scx_bpf_nr_online_cids() };
    if count == 0 || count > BITS_PER_PAGE {
        return -22;
    }
    let slots = unsafe {
        bpf_arena_alloc_pages(
            (&raw mut arena).cast(),
            null_mut(),
            (u64::from(count) * SLOT_BYTES).div_ceil(4096) as u32,
            -1,
            0,
        )
    };
    if slots.is_null() {
        return -12;
    }
    unsafe {
        IDLE[0] = slots as u64;
        IDLE[1] = u64::from(count);
        let result = cids::init(count);
        if result != 0 {
            return result;
        }
    }
    unsafe { initialize_ranges(count) }
}

#[inline(always)]
fn valid(cid: i32) -> bool {
    cid >= 0 && (cid as u64) < unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) }
}

#[inline(never)]
pub unsafe fn claim(cid: i32) -> bool {
    if !valid(cid) {
        return false;
    }
    let (pointer, bit) = unsafe { word(cid as u32) };
    // Bounded by may_goto rather than a plain counted loop: the verifier
    // would walk every retry at every call site.
    let mut result = None;
    for _ in crate::loops::range(0, CAS_TRIES) {
        let previous = unsafe { mem::load(pointer, 0) };
        if previous & bit == 0 {
            result = Some(false);
            break;
        }
        let observed = unsafe { mem::cas(pointer, previous, previous & !bit) };
        if observed == previous {
            result = Some(true);
            break;
        }
    }
    match result {
        Some(true) => {
            // Clear the summary bit of a shard this claim emptied, then
            // look again: a concurrent set() may have added a CID after the
            // first look and skipped the summary because its bit was still
            // set. Either that set() sees the bit cleared and sets it
            // again, or the second look here sees its CID. Each side does
            // an RMW on one word and then loads the other, the
            // store-buffering pattern, which the fully ordered CAS covers.
            // In between, a shard that just gained an idle CID looks empty
            // to the summary-driven scans for a few instructions, which
            // costs a less ideal placement at most.
            let header = unsafe { header(cid as u32) };
            if unsafe { shard_empty(header) } {
                unsafe { summary_update(header, false) };
                if !unsafe { shard_empty(header) } {
                    unsafe { summary_update(header, true) };
                }
            }
            true
        }
        Some(false) => false,
        None => {
            crate::pool::count_cas_failure();
            false
        }
    }
}

#[inline(always)]
unsafe fn allowed(task: *mut task_struct, cid: i32) -> bool {
    let cpu = cpu(cid);
    if cpu < 0 {
        return false;
    }
    let mask_offset = config::get(config::CPUS_PTR) as usize;
    let mask =
        unsafe { read_volatile(task.cast::<u8>().add(mask_offset).cast::<*const cpumask>()) };
    unsafe { bpf_cpumask_test_cpu(cpu as u32, mask) }
}

#[inline(always)]
unsafe fn core_idle(cid: u32, count: u32) -> bool {
    let ends = unsafe { read_range(cid) };
    if ends.core_base > cid || ends.core <= cid || ends.core > count {
        return false;
    }
    // A core is contiguous in its segment, so its bits are one word's
    // unless it crosses a word boundary.
    let (address, position) = unsafe { slot(ends.core_base) };
    let nr = u64::from(ends.core - ends.core_base);
    let shift = position & 63;
    if nr < 64 && shift + nr <= 64 {
        let mask = ((1_u64 << nr) - 1) << shift;
        return unsafe { mem::load(address, 0) } & mask == mask;
    }
    let mut idle = true;
    for sibling in crate::loops::range(ends.core_base, ends.core) {
        if !idle_test(sibling as i32) {
            idle = false;
            break;
        }
    }
    idle
}

/// A scan's filter: whole idle cores only, and a capacity tier plus one
/// from bit 1, 0 for any. Packed, since an out-of-line scan takes at most
/// five arguments.
const WHOLE_CORE: u32 = 1;
pub const ANY_TIER: u32 = u32::MAX;

/// A scan that only looks: the candidate is returned without a claim.
const NO_CLAIM: u32 = 1 << 31;

/// A scan for an idle peer of `previous` rather than a place for a wakee,
/// idle_peer_cid()'s flags: `previous` is not taken first, and the LLC is
/// walked whole, from the CID after `previous`, without SIS_UTIL's bound or
/// the cluster first.
const PEER: u32 = 1 << 30;

/// Is `cid` in the capacity tier `filter` asks for, if any?
#[inline(always)]
fn in_tier(cid: i32, filter: u32) -> bool {
    let tier = (filter & !(NO_CLAIM | PEER)) >> 1;
    tier == 0 || crate::tiers::capacity_tier(cid) == tier - 1
}

#[inline(always)]
unsafe fn scan_segment(
    task: *mut task_struct,
    start: u32,
    end: u32,
    previous: i32,
    filter: u32,
) -> i32 {
    if start >= end {
        return -1;
    }
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    let mut cursor = start;
    let mut found = -1;
    for _ in crate::loops::range(0, end - start) {
        if cursor >= end {
            break;
        }
        let ends = unsafe { read_range(cursor) };
        if ends.shard_base > cursor || ends.shard <= cursor || ends.shard > count {
            break;
        }
        // A scan that covers a whole shard and goes on past it asks the
        // node's summary first, and skips a shard that has nothing idle.
        // One that starts or ends inside a shard reads the shard itself,
        // so a narrow scope never touches a summary.
        if cursor == ends.shard_base && end > ends.shard && !unsafe { summary_test(header(cursor)) }
        {
            cursor = ends.shard;
            continue;
        }
        let word_base = ends.shard_base + (cursor - ends.shard_base) / 64 * 64;
        let chunk_end = (word_base + 64).min(ends.shard).min(end);
        let mut bits =
            unsafe { mem::load(word(cursor).0, 0) } & word_mask(cursor, chunk_end, word_base);
        if previous >= word_base as i32 && previous < (word_base + 64) as i32 {
            bits &= !(1_u64 << (previous as u32 - word_base));
        }
        if bits != 0 {
            for _ in crate::loops::range(0, 64) {
                if bits == 0 {
                    break;
                }
                let cid = (word_base + bits.trailing_zeros()) as i32;
                bits &= bits - 1;
                if unsafe {
                    allowed(task, cid)
                        && (filter & WHOLE_CORE == 0 || core_idle(cid as u32, count))
                        && in_tier(cid, filter)
                        && (filter & NO_CLAIM != 0 || claim(cid))
                } {
                    found = cid;
                    break;
                }
            }
            if found >= 0 {
                break;
            }
        }
        cursor = chunk_end;
    }
    found
}

/// Scan the scope `base..end` for an idle CID, in CID order from its base,
/// skipping `previous`.
#[inline(always)]
unsafe fn scan_scope(
    task: *mut task_struct,
    base: i32,
    end: u32,
    previous: i32,
    filter: u32,
) -> i32 {
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    if base < 0 || base as u32 >= end || end > count {
        return -1;
    }
    unsafe { scan_segment(task, base as u32, end, previous, filter) }
}

/// Scan the window of `nr` CIDs of the domain `span` from `base`, counted
/// from `start` and wrapping at the end of the domain, the walk of
/// for_each_cpu_wrap(cpu, cpus, target + 1) in select_idle_cpu(). The two
/// ranges are scanned in turn rather than as one, which would hand back
/// the lowest CID of both where they share a bitmap word. `range` packs
/// span:base and `window` nr:start, as scan_idle_window() does. A global
/// function, verified once rather than at each scan of each pass; `task` is
/// tagged trusted by build.rs.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rust_scan_window(
    task: *mut task_struct,
    range: u64,
    window: u64,
    previous: i32,
    filter: u32,
) -> i32 {
    let (base, span) = (range as u32, (range >> 32) as u32);
    let (mut start, nr) = (window as u32, ((window >> 32) as u32).min(span));
    if task.is_null() || nr == 0 || span == 0 {
        return -1;
    }
    if start < base || start >= base + span {
        start = base;
    }
    let head = nr.min(base + span - start);
    // One scan in a loop rather than two inlined, for the stack frame.
    let mut found = -1;
    unsafe {
        for value in crate::loops::range(0, 2) {
            let (from, to) = if value as i32 == 0 {
                (start, start + head)
            } else {
                (base, base + nr - head)
            };
            found = scan_scope(task, from as i32, to, previous, filter);
            if found >= 0 {
                break;
            }
        }
    }
    found
}

/// The window from `start` in the domain `range`, span:base, that holds
/// the next `budget` CIDs `task` may run on, allowed_window():
/// select_idle_cpu() walks sched_domain_span() & p->cpus_ptr, so a CPU
/// outside the task's affinity does not use up its SIS_UTIL budget.
/// Returns the budget used in the upper 32 bits and the window's length in
/// the lower. A global function, so the loop is verified once; `task` is
/// tagged trusted by build.rs.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rust_allowed_window(
    task: *mut task_struct,
    range: u64,
    start: u32,
    budget: u32,
) -> u64 {
    let (base, span) = (range as u32, (range >> 32) as u32);
    if task.is_null() || span == 0 {
        return 0;
    }
    let start = if start < base || start >= base + span {
        base
    } else {
        start
    };
    let (mut nr, mut used) = (0_u32, 0_u32);
    unsafe {
        for value in crate::loops::range(0, span) {
            let mut cid = start + value;
            if cid >= base + span {
                cid -= span;
            }
            if allowed(task, cid as i32) {
                if used == budget {
                    break;
                }
                used += 1;
            }
            nr += 1;
        }
    }
    u64::from(used) << 32 | u64::from(nr)
}

/// Bits of each count rust_llc_windows() packs: a window is at most an LLC.
pub const WINDOW_BITS: u32 = 20;
pub const WINDOW_MASK: u64 = (1 << WINDOW_BITS) - 1;

/// The next window of a budgeted walk, `span` CIDs from `base` scanned
/// from `start`, taken out of `budget`. Without `count_allowed` every CID
/// counts.
#[inline(always)]
unsafe fn budget_window(
    task: *mut task_struct,
    base: u32,
    span: u32,
    start: u32,
    budget: &mut u32,
    count_allowed: bool,
) -> u32 {
    if span == 0 || *budget == 0 {
        return 0;
    }
    if !count_allowed {
        let nr = span.min(*budget);
        *budget -= nr;
        return nr;
    }
    let window = unsafe {
        rust_allowed_window(
            task,
            u64::from(span) << 32 | u64::from(base),
            start,
            *budget,
        )
    };
    *budget = budget.saturating_sub((window >> 32) as u32);
    window as u32
}

/// Share `budget` out over the walk of `cid`'s LLC, budgeted_llc_scan_counts():
/// its cluster from the CID after `cid`, or the whole LLC without
/// `cluster_first`, then the CIDs after the cluster and the CIDs before it.
/// A restricted task spends the budget only on CIDs it may run on, and one
/// no smaller than its affinity cannot run out at all. Returns the three
/// counts, WINDOW_BITS each, the first lowest. A global function, so that
/// the budget accounting stays out of the scan's stack frame; `task` is
/// tagged trusted by build.rs.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rust_llc_windows(
    task: *mut task_struct,
    cid: i32,
    budget: u32,
    cluster_first: u32,
) -> u64 {
    if task.is_null() || !valid(cid) {
        return 0;
    }
    let ends = unsafe { read_range(cid as u32) };
    let llc_base = llc_of(cid);
    let llc_end = ends.llc.max(llc_base);
    let (base, end) = if cluster_first != 0 {
        (
            ends.cluster_base.clamp(llc_base, llc_end),
            ends.cluster.clamp(llc_base, llc_end),
        )
    } else {
        (llc_base, llc_end)
    };
    let end = end.max(base);
    let offset = config::get(config::NR_CPUS_ALLOWED) as usize;
    let allowed = unsafe { read_volatile(task.cast::<u8>().add(offset).cast::<u32>()) };
    let restricted = allowed < cids::nr_cpu_ids();
    let mut budget = if restricted && budget >= allowed {
        u32::MAX
    } else {
        budget
    };
    let count_allowed = restricted && budget < llc_end - llc_base;
    let first = unsafe {
        budget_window(
            task,
            base,
            end - base,
            cid as u32 + 1,
            &mut budget,
            count_allowed,
        )
    };
    let after = unsafe { budget_window(task, end, llc_end - end, end, &mut budget, count_allowed) };
    let before = unsafe {
        budget_window(
            task,
            llc_base,
            base - llc_base,
            llc_base,
            &mut budget,
            count_allowed,
        )
    };
    u64::from(first) | u64::from(after) << WINDOW_BITS | u64::from(before) << (2 * WINDOW_BITS)
}

/// pick_idle_cid_topology(): `previous` itself if idle, then the first idle
/// CID of its LLC, and unless `llc_only` of its node and the machine. The
/// LLC is walked as select_idle_cpu() walks it: the cluster of `previous`
/// from the CID after it when the kernel searches clusters first, then the
/// rest of the LLC wrapping from the end of the cluster. Without a cluster,
/// the whole LLC from the CID after `previous`. The walk of a pass that is
/// not after whole cores is bounded by SIS_UTIL, and a bounded one that
/// finds nothing ends the search, where select_idle_cpu() returns -1 and
/// leaves the task on its target: every wider scan would cover the LLC
/// again unbounded.
///
/// A global function, called from one site in a loop, so that its frame is
/// not that loop's; `task` is tagged trusted by build.rs.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rust_pick_pass(
    task: *mut task_struct,
    previous: i32,
    filter: u32,
    llc_only: u32,
) -> i32 {
    if task.is_null() {
        return -1;
    }
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    let llc_only = llc_only != 0;
    let peer = filter & PEER != 0;
    if valid(previous)
        && !peer
        && (filter & WHOLE_CORE == 0 || unsafe { core_idle(previous as u32, count) })
        && in_tier(previous, filter)
    {
        if filter & NO_CLAIM != 0 || unsafe { claim(previous) } {
            return previous;
        }
    }
    if valid(previous) {
        let budget = if filter & WHOLE_CORE == 0 && !peer {
            scan_budget(previous)
        } else {
            u32::MAX
        };
        let cluster_first = !peer && cluster_active(previous);
        let windows = unsafe { rust_llc_windows(task, previous, budget, u32::from(cluster_first)) };
        // Read again rather than kept across the calls, to keep them off
        // the stack.
        let ends = unsafe { read_range(previous as u32) };
        let llc_base = llc_of(previous);
        let (base, end) = if cluster_first {
            (ends.cluster_base, ends.cluster)
        } else {
            (llc_base, ends.llc)
        };
        let mut found = unsafe {
            rust_scan_window(
                task,
                u64::from(end.saturating_sub(base)) << 32 | u64::from(base),
                (windows & WINDOW_MASK) << 32 | u64::from(previous as u32 + 1),
                previous,
                filter,
            )
        };
        let after = (windows >> WINDOW_BITS) & WINDOW_MASK;
        if found < 0 && after != 0 {
            let ends = unsafe { read_range(previous as u32) };
            let end = if cluster_first {
                ends.cluster
            } else {
                ends.llc
            };
            found = unsafe {
                rust_scan_window(
                    task,
                    u64::from(ends.llc.saturating_sub(end)) << 32 | u64::from(end),
                    after << 32 | u64::from(end),
                    previous,
                    filter,
                )
            };
        }
        let before = windows >> (2 * WINDOW_BITS);
        if found < 0 && before != 0 {
            let ends = unsafe { read_range(previous as u32) };
            let llc_base = llc_of(previous);
            let base = if cluster_first {
                ends.cluster_base
            } else {
                llc_base
            };
            found = unsafe {
                rust_scan_window(
                    task,
                    u64::from(base.saturating_sub(llc_base)) << 32 | u64::from(llc_base),
                    before << 32 | u64::from(llc_base),
                    previous,
                    filter,
                )
            };
        }
        let ends = unsafe { read_range(previous as u32) };
        let llc_base = llc_of(previous);
        if found >= 0 || llc_only || budget < ends.llc.saturating_sub(llc_base) {
            return found;
        }
        let node_base = (unsafe { mem::load(base_word(previous as u32), 0) } >> 32) as u32 as i32;
        let llc_base = llc_base as i32;
        if node_base != llc_base || ends.node != ends.llc {
            let span = u64::from(ends.node.saturating_sub(node_base as u32));
            let range = span << 32 | u64::from(node_base as u32);
            let found = unsafe { rust_scan_window(task, range, range, previous, filter) };
            if found >= 0 {
                return found;
            }
        }
    }
    let range = u64::from(count) << 32;
    unsafe { rust_scan_window(task, range, range, previous, filter) }
}

/// Where pick() looks for an idle CID around its anchor, lib/cid_idle.h's
/// scx_cid_idle_scope. Each scope holds the ones before it, so a wider pick
/// looks at the narrower scope's CIDs again.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Scope {
    /// The anchor first, then its SMT siblings.
    Core = 0,
    /// The anchor's cluster, its LLC on a kernel without cluster topology.
    Cluster = 1,
    Llc = 2,
    Node = 3,
    Anywhere = 4,
}

/// What pick() accepts, lib/cid_idle.h's scx_cid_idle_kind.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A CID whose SMT siblings are all idle too. The claim reserves the
    /// one CID, not the core.
    FullCore,
    /// Any idle CID.
    AnyCpu,
}

/// A scan's filter for `kind` and capacity tier `tier`, ANY_TIER for all.
#[inline(always)]
fn scan_filter(kind: Kind, tier: u32) -> u32 {
    let tier = if tier == ANY_TIER { 0 } else { (tier + 1) << 1 };
    match kind {
        Kind::FullCore => tier | WHOLE_CORE,
        Kind::AnyCpu => tier,
    }
}

/// The CIDs of `scope` around `anchor`, nr:base, or 0 for an anchor that is
/// not a CID. Anywhere needs no anchor.
#[inline(always)]
unsafe fn scope_range(anchor: i32, scope: u32) -> u64 {
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    if scope == Scope::Anywhere as u32 {
        return u64::from(count) << 32;
    }
    if !valid(anchor) {
        return 0;
    }
    let ends = unsafe { read_range(anchor as u32) };
    let (base, end) = if scope == Scope::Core as u32 {
        (ends.core_base, ends.core)
    } else if scope == Scope::Cluster as u32 {
        (ends.cluster_base, ends.cluster)
    } else if scope == Scope::Llc as u32 {
        (llc_of(anchor), ends.llc)
    } else {
        (
            (unsafe { mem::load(base_word(anchor as u32), 0) } >> 32) as u32,
            ends.node,
        )
    };
    if end <= base || end > count {
        return 0;
    }
    u64::from(end - base) << 32 | u64::from(base)
}

/// The CIDs of `scope` around `anchor`, as the first and how many: none
/// for an anchor that is not a CID.
#[inline(always)]
pub fn scope_cids(anchor: i32, scope: Scope) -> (u32, u32) {
    let range = unsafe { scope_range(anchor, scope as u32) };
    (range as u32, (range >> 32) as u32)
}

/// scx_cid_idle_scope_same(): do scopes `a` and `b` hold the same CIDs
/// around `anchor`? A cluster of one core, an LLC that is its node and a
/// node that is the machine do, and a search that widens can skip the
/// second, which would only repeat the first.
#[inline(always)]
pub fn scope_same(anchor: i32, a: Scope, b: Scope) -> bool {
    let (a, b) = unsafe { (scope_range(anchor, a as u32), scope_range(anchor, b as u32)) };
    a != 0 && a == b
}

/// scx_cid_idle_pick(): claim an idle CID of `kind` for `task` in `scope`
/// around `anchor`, among the CIDs the task may run on. Scope::Core tries
/// the anchor first and then its siblings. A wider scope starts at the CID
/// after the anchor and wraps, so that wakeups around one CID do not all
/// take the lowest idle CID of the scope. Returns the CID, or -1.
///
/// Winning the claim keeps other picks off the CID. It does not keep the
/// CPU idle until the task arrives.
#[inline(always)]
pub unsafe fn pick(task: *mut task_struct, anchor: i32, scope: Scope, kind: Kind) -> i32 {
    unsafe { rust_idle_pick(task, anchor, scope as u32, scan_filter(kind, ANY_TIER)) }
}

/// pick() among the CIDs of capacity tier `tier`, ANY_TIER for all.
#[inline(always)]
pub unsafe fn pick_in_tier(
    task: *mut task_struct,
    anchor: i32,
    scope: Scope,
    kind: Kind,
    tier: u32,
) -> i32 {
    unsafe { rust_idle_pick(task, anchor, scope as u32, scan_filter(kind, tier)) }
}

/// pick(), as a global function, verified once however many scopes a
/// caller widens through; `task` is tagged trusted by build.rs.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rust_idle_pick(
    task: *mut task_struct,
    anchor: i32,
    scope: u32,
    filter: u32,
) -> i32 {
    if task.is_null() {
        return -1;
    }
    let range = unsafe { scope_range(anchor, scope) };
    let (base, nr) = (range as u32, (range >> 32) as u32);
    if nr == 0 {
        return -1;
    }
    let count = unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(1)) } as u32;
    let (mut start, mut skip) = (base, -1);
    if anchor >= base as i32 && (anchor as u32) < base + nr {
        if scope == Scope::Core as u32 {
            if idle_test(anchor)
                && unsafe { allowed(task, anchor) }
                && (filter & WHOLE_CORE == 0 || unsafe { core_idle(anchor as u32, count) })
                && in_tier(anchor, filter)
                && unsafe { claim(anchor) }
            {
                return anchor;
            }
            skip = anchor;
        }
        start = anchor as u32 + 1;
    }
    unsafe {
        rust_scan_window(
            task,
            range,
            u64::from(nr) << 32 | u64::from(start),
            skip,
            filter,
        )
    }
}

/// select_idle_cpu(): pick() in `target`'s LLC as fair.c walks it. `target`
/// itself is taken if it qualifies, then its cluster from the CID after it
/// where the kernel searches clusters first, then the rest of the LLC. For
/// Kind::AnyCpu the walk looks at no more CIDs the task may run on than
/// the LLC's SIS_UTIL budget, scan_budget(). For Kind::FullCore it is not
/// bounded, as select_idle_core() is not. `tier` restricts it to one
/// capacity tier, ANY_TIER for none. Returns the CID claimed, or -1.
#[inline(always)]
pub unsafe fn select_idle_cpu(task: *mut task_struct, target: i32, kind: Kind, tier: u32) -> i32 {
    unsafe { rust_pick_pass(task, target, scan_filter(kind, tier), 1) }
}

/// A scan claimed `found`. Where the threads of a core rank, take the
/// sibling placement prefers in its place and give `found` back. Returns
/// the CID that is claimed now.
#[inline(always)]
pub unsafe fn claim_preferred(task: *mut task_struct, found: i32) -> i32 {
    if found >= 0 && smt_asym_possible() {
        let preferred = unsafe { rust_smt_preferred(task, found) };
        if preferred != found && unsafe { claim(preferred) } {
            unsafe { set(found) };
            return preferred;
        }
    }
    found
}

/// An idle CID that `task` may run on, for `cid` to kick so that it comes
/// and looks at a queue it would otherwise never read, scx_eevdf's
/// idle_peer_cid(); -1 if none. Not claimed. Whole idle cores first, then
/// any idle CID, in the order a wakeup scans, capacity tiers outermost.
/// Packing priority plays no part: the peer only supplies an idle balancer
/// for queued work, and packing applies when it pulls.
pub unsafe fn idle_peer(task: *mut task_struct, cid: i32) -> i32 {
    if !valid(cid) || unsafe { crate::task::pinned(task) } || idle_empty() {
        return -1;
    }
    let tiers = if crate::tiers::asym_capacity() {
        crate::tiers::nr_capacity_tiers()
    } else {
        1
    };
    let mut found = -1;
    for whole in [true, false] {
        if found >= 0 || (whole && !smt()) {
            continue;
        }
        unsafe {
            for value in crate::loops::range(0, tiers) {
                let tier = if crate::tiers::asym_capacity() {
                    (value + 1) << 1
                } else {
                    0
                };
                let filter = tier | NO_CLAIM | PEER | if whole { WHOLE_CORE } else { 0 };
                found = rust_pick_pass(task, cid, filter, 0);
                if found >= 0 {
                    break;
                }
            }
        }
    }
    if found >= 0 {
        unsafe { rust_smt_preferred(task, found) }
    } else {
        -1
    }
}

/// select_idle_smt(): an idle sibling of `prev`, the CPU the task last ran
/// on, if it shares `target`'s LLC, claimed or -1.
#[inline(never)]
pub unsafe fn select_idle_smt(task: *mut task_struct, prev: i32, target: i32) -> i32 {
    if !smt() || !valid(prev) || !valid(target) || !same_idle_llc(prev, target) {
        return -1;
    }
    let ends = ends(prev);
    let mut found = -1;
    unsafe {
        for value in crate::loops::range(ends.core_base, ends.core) {
            let sibling = value as i32;
            if sibling == prev || !idle_test(sibling) || !allowed(task, sibling) {
                continue;
            }
            let sibling = smt_preferred(task, sibling);
            if claim(sibling) {
                found = sibling;
                break;
            }
        }
    }
    found
}

/// The first idle CID the walk of the LLC around `target` would take,
/// in_llc() without the claim, or -1.
#[inline(always)]
pub unsafe fn probe(task: *mut task_struct, target: i32) -> i32 {
    if idle_empty() {
        return -1;
    }
    let found = unsafe { rust_pick_pass(task, target, NO_CLAIM, 1) };
    if found >= 0 {
        unsafe { rust_smt_preferred(task, found) }
    } else {
        -1
    }
}

/// Do the threads of `cid`'s core rank, so that placement prefers one?
/// When the kernel's SMT domain packs, or with --smt-asym-packing.
#[inline(always)]
pub fn smt_asym_active(cid: i32) -> bool {
    smt()
        && valid(cid)
        && (options() & SMT_ASYM_PACKING != 0 || crate::tiers::smt_asym_packing(cid))
}

/// Is the thread `a` preferred over `b`: the lower CPU number with
/// --smt-asym-packing, the better packing tier otherwise.
#[inline(always)]
pub fn smt_prefer(a: i32, b: i32) -> bool {
    if !valid(a) || !valid(b) {
        return false;
    }
    if options() & SMT_ASYM_PACKING != 0 {
        return cpu(a) < cpu(b);
    }
    crate::tiers::place_tier(a) < crate::tiers::place_tier(b)
}

/// Can the threads of any core rank? The cheap test that keeps placement
/// on its old path, without a call, on machines where none do.
#[inline(always)]
pub fn smt_asym_possible() -> bool {
    options() & SMT_ASYM_PACKING != 0 || crate::tiers::any_smt_asym_packing()
}

/// The sibling of `cid` a claim takes instead, see rust_smt_preferred().
#[inline(always)]
pub unsafe fn smt_preferred(task: *mut task_struct, cid: i32) -> i32 {
    if smt_asym_possible() {
        unsafe { rust_smt_preferred(task, cid) }
    } else {
        cid
    }
}

/// select_idle_smt_cpu(): the most preferred idle sibling of `cid` that
/// `task` may run on, or `cid`, which a claim then takes instead. A global
/// function; `task` is tagged trusted by build.rs.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rust_smt_preferred(task: *mut task_struct, cid: i32) -> i32 {
    if task.is_null() || !smt_asym_active(cid) {
        return cid;
    }
    let ends = ends(cid);
    let mut best = cid;
    unsafe {
        for value in crate::loops::range(ends.core_base, ends.core) {
            let sibling = value as i32;
            if sibling != best
                && idle_test(sibling)
                && allowed_by_mask(task, sibling)
                && smt_prefer(sibling, best)
            {
                best = sibling;
            }
        }
    }
    best
}

/// Is every CID of `cid`'s core idle?
#[inline(always)]
pub fn core_is_idle(cid: i32) -> bool {
    valid(cid)
        && unsafe {
            core_idle(
                cid as u32,
                read_volatile((&raw const IDLE).cast::<u64>().add(1)) as u32,
            )
        }
}

/// Is every other CID of `cid`'s core idle?
#[inline(always)]
pub fn siblings_idle(cid: i32) -> bool {
    if !valid(cid) {
        return false;
    }
    let ends = unsafe { read_range(cid as u32) };
    let mut idle = true;
    let mut sibling = ends.core_base;
    // A core has few CIDs; a plain loop walks them.
    for _ in 0..8 {
        if sibling >= ends.core {
            break;
        }
        if sibling != cid as u32 && !idle_test(sibling as i32) {
            idle = false;
        }
        sibling += 1;
    }
    idle
}

/// Is `cid` idle, as far as the bitmap knows?
#[inline(always)]
pub fn idle_test(cid: i32) -> bool {
    valid(cid) && {
        let (pointer, bit) = unsafe { word(cid as u32) };
        (unsafe { mem::load(pointer, 0) } & bit) != 0
    }
}

/// Can `task` run on `cid` by its affinity?
#[inline(always)]
pub unsafe fn allowed_by_mask(task: *mut task_struct, cid: i32) -> bool {
    valid(cid) && unsafe { allowed(task, cid) }
}

/// Do `a` and `b` share an LLC? Topology ranges are contiguous, so equal
/// range ends mean the same LLC.
#[inline(always)]
pub fn same_llc(a: i32, b: i32) -> bool {
    valid(a) && valid(b) && unsafe { range_field(a as u32, 5) == range_field(b as u32, 5) }
}

/// The value of the per-CPU int `variable`, a weak ksym, on `cid`'s CPU.
#[inline(always)]
unsafe fn per_cpu_int(variable: *const c_void, cid: i32) -> Option<i32> {
    let cpu = cpu(cid);
    if variable.is_null() || cpu < 0 {
        return None;
    }
    let value: *const i32 = unsafe { helpers::per_cpu_ptr(variable, cpu as u32) };
    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

/// cpus_share_cache(): are `a` and `b` in one LLC? Compares the kernel's
/// per_cpu(sd_llc_id) where it can be read, as scx_eevdf's
/// same_idle_llc() does: the CID ranges are fixed at init, while a sched
/// domain rebuild, such as a cpuset partition change, can split an LLC
/// without restarting the scheduler.
#[inline(always)]
pub fn same_idle_llc(a: i32, b: i32) -> bool {
    if a == b {
        return true;
    }
    let id = black_box(&raw const sd_llc_id).cast::<c_void>();
    if let (Some(a), Some(b)) = unsafe { (per_cpu_int(id, a), per_cpu_int(id, b)) } {
        return a == b;
    }
    same_llc(a, b)
}

/// cpus_share_resources(): are `a` and `b` in the same lowest cache-sharing
/// domain, by the kernel's per_cpu(sd_share_id)? A kernel without it has no
/// cluster scheduling, and one without CID clusters has no cluster-first
/// scan to make room for, so for both every CID of an LLC shares.
#[inline(always)]
pub fn same_share_domain(a: i32, b: i32) -> bool {
    // Referenced either way: build.rs declares the ksym for both builds.
    let id = black_box(&raw const sd_share_id).cast::<c_void>();
    if !cfg!(feature = "topo_size") || !has_clusters() {
        return true;
    }
    match unsafe { (per_cpu_int(id, a), per_cpu_int(id, b)) } {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// Does select_idle_cpu() search `cid`'s cluster before the rest of its
/// LLC? It does when the groups of the CPU's sd_llc carry SD_CLUSTER, read
/// from the live domain for the reason above. The scan walks the CID
/// cluster, so that has to be one the kernel keeps too: wider than the core
/// and narrower than the LLC.
#[inline(always)]
pub fn cluster_active(cid: i32) -> bool {
    if !valid(cid) {
        return false;
    }
    unsafe {
        let ends = read_range(cid as u32);
        let llc_base = llc_of(cid);
        let cluster_nr = ends.cluster.saturating_sub(ends.cluster_base);
        if cluster_nr <= ends.core.saturating_sub(ends.core_base)
            || cluster_nr >= ends.llc.saturating_sub(llc_base)
        {
            return false;
        }
        let groups = config::get(config::SD_GROUPS);
        let domains = black_box(&raw const sd_llc).cast::<c_void>();
        let cpu = cpu(cid);
        if groups == 0 || domains.is_null() || cpu < 0 {
            return false;
        }
        let domain = helpers::per_cpu_ptr::<u8>(domains, cpu as u32) as u64;
        if domain == 0 {
            return false;
        }
        let domain: u64 = read_kernel(domain);
        if domain == 0 {
            return false;
        }
        let group: u64 = read_kernel(domain + groups - 1);
        if group == 0 {
            return false;
        }
        let flags: u32 = read_kernel(group + config::get(config::SG_FLAGS));
        u64::from(flags) & config::get(config::SD_CLUSTER) != 0
    }
}

/// Do `a` and `b` share a node?
#[inline(always)]
pub fn same_node(a: i32, b: i32) -> bool {
    valid(a) && valid(b) && unsafe { range_field(a as u32, 6) == range_field(b as u32, 6) }
}

/// Do `a` and `b` share a core?
#[inline(always)]
pub fn same_core(a: i32, b: i32) -> bool {
    valid(a) && valid(b) && unsafe { range_field(a as u32, 0) == range_field(b as u32, 0) }
}

/// Does the machine have cores of more than one CID?
#[inline(always)]
pub fn smt() -> bool {
    unsafe { read_volatile((&raw const IDLE).cast::<u64>().add(3)) != 0 }
}

/// The topology range ends of `cid`.
#[inline(always)]
pub fn ends(cid: i32) -> RangeEnds {
    if valid(cid) {
        unsafe { read_range(cid as u32) }
    } else {
        RangeEnds::default()
    }
}

/// The number of CIDs in `cid`'s node, and its first.
#[inline(always)]
pub unsafe fn node_span(cid: i32) -> (u32, u32) {
    if !valid(cid) {
        return (1, 0);
    }
    unsafe {
        let base = (mem::load(base_word(cid as u32), 0) >> 32) as u32;
        let end = mem::load32(range(cid as u32), 24);
        (end.saturating_sub(base).max(1), base)
    }
}

/// The number of CIDs in `cid`'s LLC, and its first.
#[inline(always)]
pub unsafe fn llc_span(cid: i32) -> (u32, u32) {
    if !valid(cid) {
        return (1, 0);
    }
    unsafe {
        let base = mem::load(base_word(cid as u32), 0) as u32;
        let end = mem::load32(range(cid as u32), 20);
        (end.saturating_sub(base).max(1), base)
    }
}

/// Set the summary bit of `cid`'s shard after setting `cid`'s, see claim()
/// for the other half. Testing first keeps CPUs going idle from writing
/// the node's shared summary line when the bit is already set.
#[inline(always)]
unsafe fn summary_set(cid: u32) {
    let header = unsafe { header(cid) };
    if !unsafe { summary_test(header) } {
        unsafe { summary_update(header, true) };
    }
}

unsafe fn set(cid: i32) {
    if valid(cid) {
        let (pointer, bit) = unsafe { word(cid as u32) };
        for _ in 0..CAS_TRIES {
            let previous = unsafe { mem::load(pointer, 0) };
            if previous & bit != 0 {
                unsafe { summary_set(cid as u32) };
                unsafe { note_idle_core(cid) };
                return;
            }
            let observed = unsafe { mem::cas(pointer, previous, previous | bit) };
            if observed == previous {
                unsafe { summary_set(cid as u32) };
                unsafe { note_idle_core(cid) };
                return;
            }
        }
        crate::pool::count_cas_failure();
    }
}

pub unsafe fn update(cid: i32, idle: bool) {
    if idle {
        unsafe { set(cid) };
    } else {
        unsafe { claim(cid) };
    }
}

pub unsafe fn rearm(cid: i32, flags_offset: usize) {
    if !valid(cid) {
        return;
    }
    let task = unsafe { scx_bpf_cid_curr(cid) };
    if !task.is_null() {
        let flags = unsafe { read_volatile(task.cast::<u8>().add(flags_offset).cast::<u32>()) };
        if flags & PF_IDLE != 0 {
            unsafe { set(cid) };
        }
    }
}
