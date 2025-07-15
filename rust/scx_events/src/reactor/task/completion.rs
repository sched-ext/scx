use ::core::ops::Deref;
use ::rustix_uring::cqueue;

use crate::{
    arena::{ArenaDrop, ArenaPin},
    reactor::task::Task,
};

/// A task completion for the [`EventReactor`]
///
/// [`EventReactor`]: crate::EventReactor
pub struct TaskCompletion<'bump> {
    /// An `io_uring` completion queue entry.
    cqe: cqueue::Entry,
    /// A task opcode.
    pub op: ArenaPin<'bump, Task>,
}

impl<'bump> TaskCompletion<'bump> {
    /// Creates a new [`TaskCompletion`].
    pub const fn new(cqe: cqueue::Entry, op: ArenaPin<'bump, Task>) -> Self {
        Self { cqe, op }
    }

    /// Returns a shared reference to the underlying CQE.
    pub const fn cqe(&self) -> &cqueue::Entry {
        &self.cqe
    }
}

impl<'bump> Deref for TaskCompletion<'bump> {
    type Target = <ArenaDrop<'bump, Task> as Deref>::Target;

    fn deref(&self) -> &Self::Target {
        &self.op
    }
}
