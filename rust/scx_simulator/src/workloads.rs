//! Workload builder helpers for common task patterns.
//!
//! Each function returns a [`TaskBehavior`] representing a well-known
//! workload archetype. These are composed into scenarios for testing
//! scheduler classification (e.g., LAVD latency criticality).
//!
//! **LAVD wake_freq note**: Ping-pong and wake-chain tasks must share
//! the same `mm_id` (address space) for LAVD's `lavd_waking` to update
//! `wake_freq`. Without matching `mm_id`, `wake_freq` stays 0 and
//! latency criticality classification fails.

use crate::task::{Phase, RepeatMode, TaskBehavior};
use crate::types::Pid;

/// Pure CPU-bound task: runs continuously with no sleep or wake.
///
/// Expected LAVD classification: low `lat_cri` (low `wait_freq`, zero `wake_freq`).
pub fn cpu_bound(run_ns: u64) -> TaskBehavior {
    TaskBehavior {
        phases: vec![Phase::Run(run_ns)],
        repeat: RepeatMode::Forever,
    }
}

/// Periodic task: runs for `run_ns`, sleeps for the remainder of `period_ns`.
///
/// Expected LAVD classification: moderate `lat_cri` (non-zero `wait_freq`).
///
/// # Panics
/// Panics if `run_ns >= period_ns`.
pub fn periodic(run_ns: u64, period_ns: u64) -> TaskBehavior {
    assert!(
        run_ns < period_ns,
        "run_ns ({run_ns}) must be less than period_ns ({period_ns})"
    );
    TaskBehavior {
        phases: vec![Phase::Run(run_ns), Phase::Sleep(period_ns - run_ns)],
        repeat: RepeatMode::Forever,
    }
}

/// I/O-bound task: short run bursts with long sleeps.
///
/// Expected LAVD classification: high `lat_cri` (high `wait_freq`).
pub fn io_bound(run_ns: u64, sleep_ns: u64) -> TaskBehavior {
    TaskBehavior {
        phases: vec![Phase::Run(run_ns), Phase::Sleep(sleep_ns)],
        repeat: RepeatMode::Forever,
    }
}

/// Ping-pong pair: two tasks that alternate waking each other.
///
/// Task A: `Run(work_ns) → Wake(B) → Suspend`
/// Task B: `Suspend → Run(work_ns) → Wake(A)`
///
/// Both tasks must share the same `mm_id` for LAVD wake_freq tracking.
///
/// Expected LAVD classification: very high `lat_cri` for both tasks.
///
/// Returns `(behavior_a, behavior_b)`.
pub fn ping_pong(pid_a: Pid, pid_b: Pid, work_ns: u64) -> (TaskBehavior, TaskBehavior) {
    let a = TaskBehavior {
        phases: vec![
            Phase::Run(work_ns),
            Phase::Wake(pid_b),
            Phase::Sleep(u64::MAX), // suspend until woken
        ],
        repeat: RepeatMode::Forever,
    };
    let b = TaskBehavior {
        phases: vec![
            Phase::Sleep(u64::MAX), // suspend until woken
            Phase::Run(work_ns),
            Phase::Wake(pid_a),
        ],
        repeat: RepeatMode::Forever,
    };
    (a, b)
}

/// Wake chain: a pipeline of tasks where each wakes the next.
///
/// - Head:   `Run(work_ns) → Wake(next) → Sleep(head_sleep_ns)`
/// - Middle: `Suspend → Run(work_ns) → Wake(next)`
/// - Tail:   `Suspend → Run(work_ns)`
///
/// All tasks must share the same `mm_id` for LAVD wake_freq tracking.
///
/// Expected LAVD classification: high `lat_cri` for middle/tail tasks.
///
/// Returns a `Vec<TaskBehavior>` in pid order.
///
/// # Panics
/// Panics if `pids` has fewer than 2 elements.
pub fn wake_chain(pids: &[Pid], work_ns: u64, head_sleep_ns: u64) -> Vec<TaskBehavior> {
    assert!(
        pids.len() >= 2,
        "wake_chain requires at least 2 tasks, got {}",
        pids.len()
    );

    let mut behaviors = Vec::with_capacity(pids.len());

    for (i, _pid) in pids.iter().enumerate() {
        let is_head = i == 0;
        let is_tail = i == pids.len() - 1;

        let behavior = if is_head {
            TaskBehavior {
                phases: vec![
                    Phase::Run(work_ns),
                    Phase::Wake(pids[1]),
                    Phase::Sleep(head_sleep_ns),
                ],
                repeat: RepeatMode::Forever,
            }
        } else if is_tail {
            TaskBehavior {
                phases: vec![
                    Phase::Sleep(u64::MAX), // suspend until woken
                    Phase::Run(work_ns),
                ],
                repeat: RepeatMode::Forever,
            }
        } else {
            // Middle: Suspend → Run → Wake(next)
            TaskBehavior {
                phases: vec![
                    Phase::Sleep(u64::MAX), // suspend until woken
                    Phase::Run(work_ns),
                    Phase::Wake(pids[i + 1]),
                ],
                repeat: RepeatMode::Forever,
            }
        };

        behaviors.push(behavior);
    }

    behaviors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_bound_phases() {
        let b = cpu_bound(10_000_000);
        assert_eq!(b.phases.len(), 1);
        assert!(matches!(b.phases[0], Phase::Run(10_000_000)));
        assert_eq!(b.repeat, RepeatMode::Forever);
    }

    #[test]
    fn test_periodic_phases() {
        let b = periodic(5_000_000, 20_000_000);
        assert_eq!(b.phases.len(), 2);
        assert!(matches!(b.phases[0], Phase::Run(5_000_000)));
        assert!(matches!(b.phases[1], Phase::Sleep(15_000_000)));
    }

    #[test]
    #[should_panic(expected = "run_ns")]
    fn test_periodic_panics_on_invalid() {
        periodic(20_000_000, 10_000_000);
    }

    #[test]
    fn test_io_bound_phases() {
        let b = io_bound(200_000, 5_000_000);
        assert_eq!(b.phases.len(), 2);
        assert!(matches!(b.phases[0], Phase::Run(200_000)));
        assert!(matches!(b.phases[1], Phase::Sleep(5_000_000)));
    }

    #[test]
    fn test_ping_pong_phases() {
        let (a, b) = ping_pong(Pid(1), Pid(2), 500_000);

        assert_eq!(a.phases.len(), 3);
        assert!(matches!(a.phases[0], Phase::Run(500_000)));
        assert!(matches!(a.phases[1], Phase::Wake(Pid(2))));
        assert!(matches!(a.phases[2], Phase::Sleep(u64::MAX)));

        assert_eq!(b.phases.len(), 3);
        assert!(matches!(b.phases[0], Phase::Sleep(u64::MAX)));
        assert!(matches!(b.phases[1], Phase::Run(500_000)));
        assert!(matches!(b.phases[2], Phase::Wake(Pid(1))));
    }

    #[test]
    fn test_wake_chain_three_tasks() {
        let pids = [Pid(1), Pid(2), Pid(3)];
        let behaviors = wake_chain(&pids, 100_000, 10_000_000);
        assert_eq!(behaviors.len(), 3);

        // Head: Run, Wake(2), Sleep
        assert_eq!(behaviors[0].phases.len(), 3);
        assert!(matches!(behaviors[0].phases[0], Phase::Run(100_000)));
        assert!(matches!(behaviors[0].phases[1], Phase::Wake(Pid(2))));
        assert!(matches!(behaviors[0].phases[2], Phase::Sleep(10_000_000)));

        // Middle: Suspend, Run, Wake(3)
        assert_eq!(behaviors[1].phases.len(), 3);
        assert!(matches!(behaviors[1].phases[0], Phase::Sleep(u64::MAX)));
        assert!(matches!(behaviors[1].phases[1], Phase::Run(100_000)));
        assert!(matches!(behaviors[1].phases[2], Phase::Wake(Pid(3))));

        // Tail: Suspend, Run
        assert_eq!(behaviors[2].phases.len(), 2);
        assert!(matches!(behaviors[2].phases[0], Phase::Sleep(u64::MAX)));
        assert!(matches!(behaviors[2].phases[1], Phase::Run(100_000)));
    }

    #[test]
    #[should_panic(expected = "at least 2")]
    fn test_wake_chain_panics_on_single() {
        wake_chain(&[Pid(1)], 100_000, 10_000_000);
    }
}
