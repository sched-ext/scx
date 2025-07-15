/// Definitions related to task completion.
pub(in crate::reactor::task) mod completion;
/// Definitions related to the task context.
pub(in crate::reactor::task) mod context;
/// Definitions related to the task iterator.
pub(in crate::reactor::task) mod iterator;

pub(in crate::reactor) use self::{
    completion::TaskCompletion,
    context::{TaskContext, TaskContextSplit},
    iterator::TaskIter,
};
use crate::reactor::buffer::BufferRingToken;

/// Task Opcodes for the [`EventReactor`].
///
/// These tasks are pinned to the [`EventReactor`]'s task arena and submitted to
/// the `io_uring` submission queue as sqe user data.
///
/// On task completion, `io_uring` returns cqes with user data corresponding to
/// the completed task.
///
/// [`EventReactor`]: crate::EventReactor
pub enum Task {
    #[allow(dead_code, reason = "wip")]
    /// Close an AMD P-State Preferred Core Ranking file for a given CPU.
    AmdPstatePrefcoreRankingClose {
        /// The given CPU's ID number.
        cpu: u32,
    },
    /// Update the AMD P-State Preferred Core Ranking files for the given CPUs.
    #[allow(dead_code, reason = "wip")]
    AmdPstatePrefcoreRankingFilesUpdate {
        /// The given CPU ID numbers.
        cpus: Box<[u32]>,
    },
    /// Open an AMD P-State Preferred Core Ranking file for a given CPU.
    #[allow(dead_code, reason = "wip")]
    AmdPstatePrefcoreRankingOpen {
        /// The given CPU's ID number.
        cpu: u32,
    },
    /// Read an AMD P-State Preferred Core Ranking file for a given CPU.
    #[allow(dead_code, reason = "wip")]
    AmdPstatePrefcoreRankingRead {
        /// The token for retrieving the buffer from associated the buffer ring.
        token: BufferRingToken,
        /// The given CPU's ID number.
        cpu: u32,
    },
    /// Receive bytes on a socket configured for Generic Netlink ACPI messages.
    NetlinkAcpiEventSocketReceive {
        /// The token for retrieving the buffer from the associated buffer ring.
        token: BufferRingToken,
    },
    /// Receive bytes on a socket configured for Kobject Uevent Netlink messages.
    NetlinkKobjectUeventSocketReceive {
        /// The token for retrieving the buffer from the associated buffer ring.
        token: BufferRingToken,
    },
    /// Process a wake (from futex wait) event for the Reactor.
    ReactorFutexWake,
    /// Process a transition to the `handling` phase for the Reactor.
    ReactorPhaseHandling,
    /// Process a transition to the `shutdown` phase for the Reactor.
    ReactorPhaseShutdown,
}
