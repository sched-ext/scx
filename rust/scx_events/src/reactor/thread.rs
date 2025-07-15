use ::rustix_uring::{IoUring, cqueue, squeue};

use crate::{
    arena::ArenaBump,
    reactor::{
        // buffer::CqeExt as _,
        state::ReactorState,
        store::ReactorStore,
        task::{Task, TaskContext, TaskContextSplit},
    },
};

/// The [`EventReactorThread`] owns the various components of the
/// [`EventReactor`] which are used in the run-loop.
///
/// [`EventReactor`]: crate::EventReactor
pub struct EventReactorThread<'bump> {
    /// The underlying `io_uring` which the reactor drives.
    uring: IoUring<squeue::Entry, cqueue::Entry>,
    /// The bump allocator backing the arena for reactor tasks.
    arena: &'bump ArenaBump,
    /// The reactor state (internal API).
    state: ReactorState,
    /// The reactor store (buffers and storage for event data).
    store: ReactorStore,
}

impl<'bump> EventReactorThread<'bump> {
    /// Create a new [`EventReactorThread`].
    pub fn new(arena: &'bump ArenaBump, state: ReactorState) -> crate::Result<Self> {
        let uring = IoUring::new(256)?;
        let store = ReactorStore::new(&uring)?;
        Ok(Self {
            uring,
            arena,
            state,
            store,
        })
    }

    /// Run the event reactor run-loop.
    pub fn run(self) -> crate::Result<()> {
        let EventReactorThread {
            uring,
            arena,
            mut state,
            mut store,
        } = self;
        ::log::debug!("reactor[loop]: step: starting");

        let tasks = TaskContext::new(arena);

        let TaskContextSplit { mut squeue, .. } = tasks.split(&uring)?;
        tasks.install_reactor_step_handling(&mut squeue)?;
        drop(squeue);

        while !state.stop {
            let TaskContextSplit {
                submitter,
                mut squeue,
                mut cqueue,
            } = tasks.split(&uring)?;
            submitter.submit_and_wait(1)?;
            for task in TaskContext::iter(&mut cqueue) {
                match *task {
                    #[allow(clippy::match_same_arms, reason = "wip")]
                    Task::AmdPstatePrefcoreRankingClose { .. } => {},
                    #[allow(clippy::match_same_arms, reason = "wip")]
                    Task::AmdPstatePrefcoreRankingFilesUpdate { .. } => {},
                    #[allow(clippy::match_same_arms, reason = "wip")]
                    Task::AmdPstatePrefcoreRankingOpen { .. } => {},
                    #[allow(clippy::match_same_arms, reason = "wip")]
                    Task::AmdPstatePrefcoreRankingRead { .. } => {},
                    Task::ReactorFutexWake => {
                        tasks.perform_reactor_futex_woke(&mut squeue, &state, task)?;
                    },
                    Task::ReactorPhaseHandling => {
                        tasks.perform_reactor_phase_handling(&mut squeue, &state, &mut store, task)?;
                    },
                    Task::ReactorPhaseShutdown => {
                        tasks.perform_reactor_phase_shutdown(&mut state, &mut store, task)?;
                    },
                    Task::NetlinkAcpiEventSocketReceive { token } => {
                        TaskContext::perform_netlink_acpi_event_socket_receive(&store, &task, token)?;
                    },
                    Task::NetlinkKobjectUeventSocketReceive { token } => {
                        TaskContext::perform_netlink_kobject_uevent_socket_receive(&store, &task, token)?;
                    },
                }
            }
        }

        ::log::debug!("reactor[loop]: exiting");
        Ok(())
    }
}
