//! Newtype wrappers and type aliases for domain concepts.
//!
//! Newtypes for identifiers (DSQ IDs, PIDs, CPU IDs) and virtual time
//! prevent silent type confusion. Type aliases for plain quantities
//! (timestamps) provide self-documenting code without the boilerplate
//! of implementing arithmetic traits.

use std::fmt;

/// Dispatch queue identifier. Wraps u64 with kernel bit-flag conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DsqId(pub u64);

/// Process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Pid(pub i32);

/// CPU identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CpuId(pub u32);

impl DsqId {
    pub const FLAG_BUILTIN: u64 = 1u64 << 63;
    pub const GLOBAL: DsqId = DsqId(Self::FLAG_BUILTIN | 1);
    pub const LOCAL: DsqId = DsqId(Self::FLAG_BUILTIN | 2);
    pub const LOCAL_ON_MASK: u64 = 0xC000000000000000;
    pub const LOCAL_CPU_MASK: u64 = 0x00000000FFFFFFFF;

    pub fn is_local(self) -> bool {
        self == Self::LOCAL
    }

    pub fn is_local_on(self) -> bool {
        self.0 & Self::LOCAL_ON_MASK == Self::LOCAL_ON_MASK
    }

    /// Whether this is a built-in DSQ (LOCAL, GLOBAL, or LOCAL_ON).
    /// The kernel rejects vtime ordering for built-in DSQs.
    pub fn is_builtin(self) -> bool {
        self.0 & Self::FLAG_BUILTIN != 0
    }

    pub fn local_on_cpu(self) -> CpuId {
        CpuId((self.0 & Self::LOCAL_CPU_MASK) as u32)
    }
}

/// Address-space (mm_struct) group identifier.
///
/// Tasks with the same `MmId` share an address space (threads in the same
/// process). Used by COSMOS's `is_wake_affine()` to co-locate related tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MmId(pub u32);

/// Bitflags for `scx_bpf_kick_cpu` matching kernel `scx_kick_flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KickFlags(u64);

impl KickFlags {
    pub const NONE: KickFlags = KickFlags(0);
    pub const IDLE: KickFlags = KickFlags(1);
    pub const PREEMPT: KickFlags = KickFlags(2);

    pub fn from_raw(raw: u64) -> Self {
        KickFlags(raw)
    }

    pub fn contains(self, other: KickFlags) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: KickFlags) {
        self.0 |= other.0;
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

/// Simulated time in nanoseconds.
pub type TimeNs = u64;

/// Virtual time for fair scheduling (opaque u64, not nanoseconds).
///
/// Ordering uses wrapping comparison (like the kernel's `time_before64`),
/// so `Vtime(u64::MAX)` compares as less than `Vtime(0)` when they are
/// within half the u64 range of each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vtime(pub u64);

impl PartialOrd for Vtime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Vtime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Matches kernel time_before64: (s64)(a - b) < 0 means a < b.
        // Wrapping subtraction cast to i64 handles overflow correctly.
        (self.0.wrapping_sub(other.0) as i64).cmp(&0)
    }
}

impl fmt::Display for Vtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::fmt::fmt_grouped(self.0))
    }
}
