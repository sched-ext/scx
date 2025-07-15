use ::alloc::sync::Arc;
use ::anyhow::bail;
use ::core::{
    ops::{Deref, DerefMut},
    sync::atomic::Ordering,
};
use ::linux_raw_sys::general::FUTEX_BITSET_MATCH_ANY;
use ::neli::{consts::socket::NlFamily, router::synchronous::NlRouter, socket::NlSocket, utils::Groups as NlGroups};
use ::rustix::{fd::AsRawFd as _, io_uring::FutexWaitFlags};
use ::rustix_uring::{CompletionQueue, IoUring, SubmissionQueue, Submitter, opcode, squeue};
use ::winnow::BStr;

use crate::{
    arena::{ArenaBump, ArenaPin, ArenaSlab},
    events::netlink::{genl::acpi::AcpiProcessorNotifyHighestPerfChanged, kobject_uevent::KobjectUevent},
    reactor::{
        buffer::BufferRingToken,
        phase::{ReactorPhase, ReactorPhaseKind},
        state::ReactorState,
        store::ReactorStore,
        task::{Task, TaskCompletion, TaskIter},
    },
};

/// A wrapper for [`Submitter`] preventing multiple borrows.
pub struct TaskContextSubmitter<'ring> {
    /// The `io_uring` [`Submitter`].
    inner: Submitter<'ring>,
    /// The atomic guard preventing multiple borrows.
    #[allow(unused, reason = "used for reference count")]
    split_guard: Arc<()>,
}
impl<'ring> Deref for TaskContextSubmitter<'ring> {
    type Target = Submitter<'ring>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for TaskContextSubmitter<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A wrapper for [`SubmissionQueue`] preventing multiple borrows.
pub struct TaskContextSubmissionQueue<'ring> {
    /// The `io_uring` [`SubmissionQueue`].
    inner: SubmissionQueue<'ring>,
    /// The atomic guard preventing multiple borrows.
    #[allow(unused, reason = "used for reference count")]
    split_guard: Arc<()>,
}
impl<'ring> Deref for TaskContextSubmissionQueue<'ring> {
    type Target = SubmissionQueue<'ring>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for TaskContextSubmissionQueue<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A wrapper for [`CompletionQueue`] preventing multiple borrows.
pub struct TaskContextCompletionQueue<'ring> {
    /// The `io_uring` [`CompletionQueue`].
    inner: CompletionQueue<'ring>,
    /// The atomic guard preventing multiple borrows.
    #[allow(unused, reason = "used for reference count")]
    split_guard: Arc<()>,
}
impl<'ring> Deref for TaskContextCompletionQueue<'ring> {
    type Target = CompletionQueue<'ring>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for TaskContextCompletionQueue<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A structure for splitting the submitter and queues from an `io_uring` while
/// disallowing multiple borrows.
pub struct TaskContextSplit<'ring> {
    /// The uniquely borrowed [`Submitter`].
    pub submitter: TaskContextSubmitter<'ring>,
    /// The uniquely borrowed [`SubmissionQueue`].
    pub squeue: TaskContextSubmissionQueue<'ring>,
    /// The uniquely borrowed [`CompletionQueue`].
    pub cqueue: TaskContextCompletionQueue<'ring>,
}

/// The task context which manages and pins reactor task data in stable memory.
///
/// This structure and its behavior are necessary to enable the approach we use
/// for interfacing with `io_uring`.
///
/// Rather than storing slab indices as user data in `io_uring` entries, we
/// store the address of the stable memory backing each task. This avoids an
/// extra table lookup and improves latency when processing completions.
///
/// It also supports a memory model with minimal allocation churn, as allocated
/// chunks can be reused when old tasks are dropped and new ones are installed.
///
/// Achieving this requires careful memory management and guarantees that task
/// memory cannot be invalidated while referenced by `io_uring`.
pub struct TaskContext<'bump> {
    /// The underlying [`ArenaSlab`] which manages the pinned tasks.
    slab: ArenaSlab<'bump, Task>,
    /// The atomic guard preventing multiple borrows of `io_uring` data.
    split_guard: Arc<()>,
}

impl<'bump> TaskContext<'bump> {
    /// Creates a new [`TaskContext`].
    pub fn new(bump: &'bump ArenaBump) -> Self {
        let slab = ArenaSlab::new(bump);
        let split_guard = Arc::new(());
        Self { slab, split_guard }
    }

    /// Detaches a [`TaskCompletion`] from the context. This marks it ready for
    /// removal from the arena on drop.
    fn detach(&self, task: TaskCompletion<'_>) {
        drop(self.slab.detach(task.op));
    }

    /// Creates an iterator for task completions.
    pub fn iter<'cqueue>(cqueue: &'cqueue mut CompletionQueue<'bump>) -> impl Iterator<Item = TaskCompletion<'cqueue>> {
        TaskIter::new(cqueue)
    }

    /// Splits the [`TaskContext`] into the `io_uring` submitter and queues.
    pub fn split<'ring>(&self, ring: &'ring IoUring) -> crate::Result<TaskContextSplit<'ring>> {
        if Arc::strong_count(&self.split_guard) > 1 {
            bail!("queues already shared");
        }
        let submitter = TaskContextSubmitter {
            inner: ring.submitter(),
            split_guard: Arc::clone(&self.split_guard),
        };
        let squeue = TaskContextSubmissionQueue {
            // SAFETY: `split_guard` ensures unique borrow.
            inner: unsafe { ring.submission_shared() },
            split_guard: Arc::clone(&self.split_guard),
        };
        let cqueue = TaskContextCompletionQueue {
            // SAFETY: `split_guard` ensures unique borrow.
            inner: unsafe { ring.completion_shared() },
            split_guard: Arc::clone(&self.split_guard),
        };
        Ok(TaskContextSplit {
            submitter,
            squeue,
            cqueue,
        })
    }
}

impl<'bump> TaskContext<'bump> {
    /// Installs the `task` into the context and submits the associated `sqe` to
    /// the `io_uring` queue.
    fn install(
        squeue: &mut SubmissionQueue<'bump>,
        sqe: squeue::Entry,
        task: ArenaPin<'bump, Task>,
    ) -> crate::Result<()> {
        let sqe = sqe.user_data(task);
        // SAFETY: `sqe` data is guaranteed to live long enough due via arena.
        unsafe { squeue.push(&sqe) }?;
        Ok(())
    }

    /// Performs the task for closing a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::missing_const_for_fn, reason = "wip")]
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(clippy::unused_self, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub fn install_amd_pstate_prefcore_ranking_close(&self) -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for updating a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::missing_const_for_fn, reason = "wip")]
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(clippy::unused_self, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub fn install_amd_pstate_prefcore_ranking_files_update(&self) -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for opening a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::missing_const_for_fn, reason = "wip")]
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(clippy::unused_self, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub fn install_amd_pstate_prefcore_ranking_open(&self) -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for reading a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::missing_const_for_fn, reason = "wip")]
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(clippy::unused_self, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub fn install_amd_pstate_prefcore_ranking_read(&self) -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for waking the reactor from a futex.
    pub fn install_reactor_futex_wake(
        &self,
        squeue: &mut SubmissionQueue<'bump>,
        state: &ReactorState,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[install]: futex_woke");
        let sqe = {
            let futex = state.wake.as_ptr().cast();
            let val = u64::from(state.wake.load(Ordering::Relaxed));
            let mask = u64::from(FUTEX_BITSET_MATCH_ANY);
            let futex_flags = FutexWaitFlags::PRIVATE | FutexWaitFlags::SIZE_U32;
            opcode::FutexWait::new(futex, val, mask, futex_flags).build()
        };
        let task = self.slab.try_attach(Task::ReactorFutexWake)?;
        Self::install(squeue, sqe, task)?;
        Ok(())
    }

    /// Performs the task for transitioning the reactor to the handling phase.
    pub fn install_reactor_step_handling(&self, squeue: &mut SubmissionQueue<'bump>) -> crate::Result<()> {
        ::log::debug!("reactor[install]: step_handling");
        // Install a no-op to immediately wake the reactor on first iteration.
        let task = self.slab.try_attach(Task::ReactorPhaseHandling)?;
        let sqe = opcode::Nop::new().build();
        Self::install(squeue, sqe, task)
    }

    /// Performs the task for transitioning the reactor to the shutdown phase.
    pub fn install_reactor_step_shutdown(
        &self,
        squeue: &mut SubmissionQueue<'bump>,
        state: &ReactorState,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[install]: step_shutdown");
        if let ReactorPhaseKind::Handling = state.step.load(Ordering::Relaxed) {
            let sqe = {
                let futex = state.step.as_ptr();
                let val = u64::from(ReactorPhase::kind_into(ReactorPhaseKind::Handling));
                let mask = u64::from(FUTEX_BITSET_MATCH_ANY);
                let futex_flags = FutexWaitFlags::PRIVATE | FutexWaitFlags::SIZE_U32;
                opcode::FutexWait::new(futex, val, mask, futex_flags).build()
            };
            let task = self.slab.try_attach(Task::ReactorPhaseShutdown)?;
            return Self::install(squeue, sqe, task);
        }
        let msg = format!("reactor[loop]: expected state: {:?}", ReactorPhaseKind::Handling);
        Err(crate::Error::msg(msg))
    }

    /// Performs the task for receiving data from the Generic Netlink ACPI
    /// socket.
    pub fn install_netlink_acpi_event_socket_receive(
        &self,
        squeue: &mut SubmissionQueue<'bump>,
        store: &mut ReactorStore,
    ) -> crate::Result<()> {
        use crate::events::netlink::genl::acpi;

        ::log::debug!("reactor[install]: netlink_acpi_event_socket_receive");

        // Create the router so we can lookup the Netlink ACPI mcast id.
        let proto = NlFamily::Generic;
        let pid = None;
        let groups = NlGroups::empty();
        let (router, handle) = NlRouter::connect(proto, pid, groups)?;
        drop(handle);

        // Lookup the Netlink ACPI mcast id.
        let family_name = acpi::ACPI_GENL_FAMILY_NAME;
        let mcast_name = acpi::ACPI_GENL_MCAST_GROUP_NAME;
        let acpi_mc_group = router.resolve_nl_mcast_group(family_name, mcast_name)?;
        drop(router);

        // Create the Netlink socket and configure for ACPI mcast.
        let sock = NlSocket::connect(proto, pid, NlGroups::new_groups(&[acpi_mc_group]))?;
        let fd = ::rustix_uring::types::Fd(sock.as_raw_fd());
        store.netlink_genl_acpi.sock = Some(sock);

        // Install the multi-shot receive task.
        let token = store.netlink_genl_acpi.ring.token();
        let task = self.slab.try_attach(Task::NetlinkAcpiEventSocketReceive { token })?;
        let sqe = opcode::RecvMulti::new(fd, store.netlink_genl_acpi.ring.group()).build();
        Self::install(squeue, sqe, task)?;

        Ok(())
    }

    /// Performs the task for receiving data from the Kobject Uevent Netlink
    /// socket.
    pub fn install_netlink_kobject_uevent_socket_receive(
        &self,
        squeue: &mut SubmissionQueue<'bump>,
        store: &mut ReactorStore,
    ) -> crate::Result<()> {
        use crate::events::netlink::kobject_uevent;

        ::log::debug!("reactor[install]: netlink_kobject_uevent_socket_receive");

        // Prepare the Netlink Kobject Uevent mcast id.
        let proto = NlFamily::KobjectUevent;
        let pid = None;
        let groups = NlGroups::new_groups(&[kobject_uevent::KOBJECT_UEVENT_MCAST_GROUP]);

        // Create the Netlink socket and configure for KObject Uevent mcast.
        let sock = NlSocket::connect(proto, pid, groups)?;
        let fd = ::rustix_uring::types::Fd(sock.as_raw_fd());
        store.netlink_kobject_uevent.sock = Some(sock);

        // Install the multi-shot receive task.
        let token = store.netlink_kobject_uevent.ring.token();
        let task = self
            .slab
            .try_attach(Task::NetlinkKobjectUeventSocketReceive { token })?;
        let sqe = opcode::RecvMulti::new(fd, store.netlink_kobject_uevent.ring.group()).build();
        Self::install(squeue, sqe, task)?;

        Ok(())
    }
}

impl<'bump> TaskContext<'bump> {
    /// Performs the task for closing a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub const fn perform_amd_pstate_prefcore_ranking_close() -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for updating a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub const fn perform_amd_pstate_prefcore_ranking_files_update() -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for opening a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub const fn perform_amd_pstate_prefcore_ranking_open() -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for reading a AMD P-State Preferred Core Ranking file.
    #[allow(clippy::unnecessary_wraps, reason = "wip")]
    #[allow(dead_code, reason = "wip")]
    pub const fn perform_amd_pstate_prefcore_ranking_read() -> crate::Result<()> {
        Ok(())
    }

    /// Performs the task for waking the reactor from a futex.
    pub fn perform_reactor_futex_woke(
        &self,
        squeue: &mut SubmissionQueue<'bump>,
        state: &ReactorState,
        task: TaskCompletion,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[perform]: futex_woke");

        task.cqe().result()?;

        // Remove the one-shot task from the arena.
        self.detach(task);

        // Re-arm the wake futex.
        self.install_reactor_futex_wake(squeue, state)?;

        Ok(())
    }

    /// Performs the task for transitioning the reactor to the handling phase.
    pub fn perform_reactor_phase_handling(
        &self,
        squeue: &mut SubmissionQueue<'bump>,
        state: &ReactorState,
        store: &mut ReactorStore,
        task: TaskCompletion,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[perform]: step_handling");

        // Remove the one-shot task from the arena.
        self.detach(task);

        // Step to the `handling` state.
        state.step.store(ReactorPhaseKind::Handling, Ordering::Release);

        // Prepare to wake the reactor if requested.
        self.install_reactor_futex_wake(squeue, state)?;
        // Prepare to shutdown the reactor if requested.
        self.install_reactor_step_shutdown(squeue, state)?;

        // Open the AMD P-State Preferred Core sysfs files.
        self.install_amd_pstate_prefcore_ranking_open()?;

        // Listen for Netlink ACPI events.
        self.install_netlink_acpi_event_socket_receive(squeue, store)?;
        // Listen for Netlink Kobject Uevent events.
        self.install_netlink_kobject_uevent_socket_receive(squeue, store)?;

        // Unpark the parent thread to resume main.
        state.parent.unpark();

        Ok(())
    }

    /// Performs the task for transitioning the reactor to the shutdown phase.
    pub fn perform_reactor_phase_shutdown(
        &self,
        state: &mut ReactorState,
        store: &mut ReactorStore,
        task: TaskCompletion,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[perform]: step_shutdown");

        // Handle errors from handling the futex.
        if let Err(err) = task.cqe().result() {
            #[cfg(not(miri))]
            const EAGAIN: u32 = ::linux_raw_sys::errno::EAGAIN;
            #[cfg(miri)]
            const EAGAIN: u32 = 11;
            // Ignore EAGAIN, otherwise forward the error.
            if err.raw_os_error().cast_unsigned() != EAGAIN {
                return Err(crate::Error::from(::std::io::Error::from(err)));
            }
            ::log::debug!("reactor[loop]: already shutting down");
        }

        // Remove the one-shot task from the arena.
        self.detach(task);

        // Drop the Netlink ACPI socket.
        store.netlink_genl_acpi.sock = None;
        // Drop the Netlink Kobject Uevent socket.
        store.netlink_kobject_uevent.sock = None;

        // Toggle the stop var to terminate the event loop.
        state.stop = true;

        Ok(())
    }

    /// Performs the task for receiving data from the Generic Netlink ACPI
    /// socket.
    #[allow(clippy::print_stdout, reason = "wip")]
    #[allow(clippy::use_debug, reason = "wip")]
    pub fn perform_netlink_acpi_event_socket_receive(
        store: &ReactorStore,
        task: &TaskCompletion,
        token: BufferRingToken,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[perform]: netlink_acpi_event_socket_receive");
        if let Some(buf) = store.netlink_genl_acpi.ring.get_buf(task.cqe(), token)? {
            let res = AcpiProcessorNotifyHighestPerfChanged::try_from(&*buf)?;
            println!("res: {res:#?}");
        }
        Ok(())
    }

    /// Performs the task for receiving data from the Kobject Uevent Netlink
    /// socket.
    #[allow(clippy::print_stdout, reason = "wip")]
    #[allow(clippy::use_debug, reason = "wip")]
    pub fn perform_netlink_kobject_uevent_socket_receive(
        store: &ReactorStore,
        task: &TaskCompletion,
        token: BufferRingToken,
    ) -> crate::Result<()> {
        ::log::debug!("reactor[perform]: netlink_kobject_uevent_socket_receive");
        // TODO: process CPU hotplug events
        if let Some(buf) = store.netlink_kobject_uevent.ring.get_buf(task.cqe(), token)? {
            let stream = &mut BStr::new(&*buf);
            let _header = KobjectUevent::header(stream)?;
            let body = KobjectUevent::parse(stream)?;
            println!("{body:#?}");
        }
        Ok(())
    }
}
