use std::process::Child;
use std::time::{Duration, Instant};

/// RAII guard for a spawned child process. Tracks its process group ID.
/// On drop, executes three-phase shutdown (muEmacs pattern):
///   1. SIGINT to process group (graceful -- scheduler has ctrlc handler)
///   2. Poll try_wait() for 500ms
///   3. SIGKILL to process group (force)
pub struct ChildGuard {
    child: Option<Child>,
    pgid: i32,
}

impl ChildGuard {
    /// Wrap a child process. PGID is assumed to equal child PID
    /// (requires the child to have been spawned with `.process_group(0)`).
    pub fn new(child: Child) -> Self {
        let pgid = child.id() as i32;
        Self {
            child: Some(child),
            pgid,
        }
    }

    pub fn id(&self) -> u32 {
        self.child.as_ref().map(|c| c.id()).unwrap_or(0)
    }

    /// Three-phase shutdown: SIGINT → wait 500ms → SIGKILL.
    /// Targets the entire process group via killpg.
    pub fn stop(&mut self) {
        let child = match self.child.as_mut() {
            Some(c) => c,
            None => return,
        };

        // CHECK IF ALREADY EXITED
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }

        // PHASE 1: SIGINT TO PROCESS GROUP
        unsafe {
            libc::killpg(self.pgid, libc::SIGINT);
        }

        // PHASE 2: WAIT UP TO 500MS
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }

        // PHASE 3: SIGKILL TO PROCESS GROUP
        unsafe {
            libc::killpg(self.pgid, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    /// Consume the guard and return the inner Child without triggering
    /// the Drop cleanup. Caller becomes responsible for the process.
    /// Use this when you need wait_with_output() for stdout capture.
    pub fn into_child(mut self) -> Child {
        self.child
            .take()
            .expect("ChildGuard: child already consumed")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.stop();
        }
    }
}
