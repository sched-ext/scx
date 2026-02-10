//! Newtype wrappers and type aliases for domain concepts.
//!
//! Newtypes for identifiers (DSQ IDs, PIDs, CPU IDs) prevent silent type
//! confusion. Type aliases for quantities (timestamps, vtimes, weights)
//! provide self-documenting code without the boilerplate of implementing
//! arithmetic traits.

/// Dispatch queue identifier. Wraps u64 with kernel bit-flag conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DsqId(pub u64);

/// Process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pid(pub i32);

/// CPU identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

    pub fn local_on_cpu(self) -> CpuId {
        CpuId((self.0 & Self::LOCAL_CPU_MASK) as u32)
    }
}

/// Simulated time in nanoseconds.
pub type TimeNs = u64;

/// Virtual time for fair scheduling (opaque u64, not nanoseconds).
pub type Vtime = u64;

/// Scheduler weight (higher = more CPU share).
pub type Weight = u32;
