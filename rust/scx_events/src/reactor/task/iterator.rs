use ::core::marker::PhantomData;
use ::rustix_uring::{CompletionQueue, cqueue};

use crate::{
    arena::ArenaPin,
    reactor::task::{Task, TaskCompletion},
};

/// The task iterator structure.
pub struct TaskIter<'cqueue, 'bump> {
    /// The `io_uring` completion queue as the underlying iterator.
    iter: &'cqueue mut CompletionQueue<'bump, cqueue::Entry>,
    /// Phantom data for the allocator lifetime.
    phantom: PhantomData<ArenaPin<'bump, Task>>,
}

impl Drop for TaskIter<'_, '_> {
    fn drop(&mut self) {
        self.iter.sync();
    }
}

impl<'cqueue, 'bump> TaskIter<'cqueue, 'bump> {
    /// Creates a new [`TaskIter`].
    pub const fn new(iter: &'cqueue mut CompletionQueue<'bump, cqueue::Entry>) -> Self {
        let phantom = PhantomData;
        Self { iter, phantom }
    }
}

impl<'cqueue> Iterator for TaskIter<'cqueue, '_> {
    type Item = TaskCompletion<'cqueue>;

    fn next(&mut self) -> Option<Self::Item> {
        let cqe = self.iter.next()?;
        // SAFETY: interface ensures `user_data` is always pinned in arena.
        let pin = unsafe { ArenaPin::try_from_user_data(cqe.user_data()) }.ok()?;
        Some(TaskCompletion::new(cqe, pin))
    }
}
