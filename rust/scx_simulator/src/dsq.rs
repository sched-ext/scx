//! Dispatch queue (DSQ) simulation.
//!
//! Provides both FIFO and vtime-ordered dispatch queues that mirror
//! the kernel's DSQ semantics. Like the kernel, a DSQ must be used
//! exclusively as either FIFO or vtime-ordered — mixing is an error.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::cpu::SimCpu;
use crate::types::{DsqId, Pid, Vtime};

/// The ordering mode of a DSQ. The kernel enforces that a DSQ is either
/// purely FIFO or purely PRIQ (vtime-ordered); mixing triggers scx_error().
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DsqMode {
    /// No tasks have been inserted yet — mode is undetermined.
    Empty,
    /// Tasks are ordered FIFO (inserted via scx_bpf_dsq_insert).
    Fifo,
    /// Tasks are ordered by vtime (inserted via scx_bpf_dsq_insert_vtime).
    Priq,
}

/// A single dispatch queue, supporting either FIFO or vtime ordering.
#[derive(Debug)]
pub struct Dsq {
    /// Vtime-ordered entries: (vtime, insertion_order) -> pid.
    /// The insertion_order provides a tiebreaker for equal vtimes.
    vtime_entries: BTreeMap<(Vtime, u64), Pid>,
    /// FIFO entries (used when tasks are inserted without vtime).
    fifo_entries: VecDeque<Pid>,
    /// Monotonic counter for insertion ordering.
    insertion_counter: u64,
    /// Current mode — enforced to prevent mixing FIFO and vtime tasks.
    mode: DsqMode,
}

impl Dsq {
    pub fn new() -> Self {
        Dsq {
            vtime_entries: BTreeMap::new(),
            fifo_entries: VecDeque::new(),
            insertion_counter: 0,
            mode: DsqMode::Empty,
        }
    }

    /// Insert a task in FIFO order.
    ///
    /// # Panics
    /// Panics if the DSQ already contains vtime-ordered tasks (mixing is
    /// not allowed, matching the kernel's `dispatch_enqueue` check).
    pub fn insert_fifo(&mut self, pid: Pid) {
        assert!(
            self.mode != DsqMode::Priq,
            "cannot insert FIFO task into a vtime-ordered DSQ"
        );
        self.mode = DsqMode::Fifo;
        self.fifo_entries.push_back(pid);
    }

    /// Insert a task ordered by vtime.
    ///
    /// # Panics
    /// Panics if the DSQ already contains FIFO tasks (mixing is not
    /// allowed, matching the kernel's `dispatch_enqueue` check).
    pub fn insert_vtime(&mut self, pid: Pid, vtime: Vtime) {
        assert!(
            self.mode != DsqMode::Fifo,
            "cannot insert vtime task into a FIFO DSQ"
        );
        self.mode = DsqMode::Priq;
        let order = self.insertion_counter;
        self.insertion_counter += 1;
        self.vtime_entries.insert((vtime, order), pid);
    }

    /// Pop the highest-priority task.
    ///
    /// For PRIQ DSQs, returns the lowest-vtime task.
    /// For FIFO DSQs, returns the head of the queue.
    /// Resets mode to Empty when the last task is removed.
    pub fn pop(&mut self) -> Option<Pid> {
        let result = match self.mode {
            DsqMode::Priq => {
                let (&key, &pid) = self.vtime_entries.iter().next()?;
                self.vtime_entries.remove(&key);
                Some(pid)
            }
            DsqMode::Fifo => self.fifo_entries.pop_front(),
            DsqMode::Empty => None,
        };
        if self.is_empty() {
            self.mode = DsqMode::Empty;
        }
        result
    }

    /// Number of queued tasks.
    pub fn len(&self) -> usize {
        self.vtime_entries.len() + self.fifo_entries.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.vtime_entries.is_empty() && self.fifo_entries.is_empty()
    }

    /// Return all PIDs in priority order without consuming.
    pub fn ordered_pids(&self) -> Vec<Pid> {
        match self.mode {
            DsqMode::Priq => self.vtime_entries.values().copied().collect(),
            DsqMode::Fifo => self.fifo_entries.iter().copied().collect(),
            DsqMode::Empty => Vec::new(),
        }
    }

    /// Remove a specific PID from the queue. Returns true if found.
    /// Resets mode to Empty when the last task is removed.
    pub fn remove_pid(&mut self, pid: Pid) -> bool {
        let found = match self.mode {
            DsqMode::Priq => {
                if let Some(key) = self
                    .vtime_entries
                    .iter()
                    .find_map(|(k, &v)| if v == pid { Some(*k) } else { None })
                {
                    self.vtime_entries.remove(&key);
                    true
                } else {
                    false
                }
            }
            DsqMode::Fifo => {
                if let Some(pos) = self.fifo_entries.iter().position(|&p| p == pid) {
                    self.fifo_entries.remove(pos);
                    true
                } else {
                    false
                }
            }
            DsqMode::Empty => false,
        };
        if found && self.is_empty() {
            self.mode = DsqMode::Empty;
        }
        found
    }
}

impl Default for Dsq {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages all dispatch queues in the simulation.
#[derive(Debug)]
pub struct DsqManager {
    dsqs: HashMap<DsqId, Dsq>,
}

impl DsqManager {
    pub fn new() -> Self {
        // Pre-create the global DSQ
        let mut dsqs = HashMap::new();
        dsqs.insert(DsqId::GLOBAL, Dsq::new());
        DsqManager { dsqs }
    }

    /// Create a new DSQ. Returns true if created, false if it already exists.
    pub fn create(&mut self, dsq_id: DsqId) -> bool {
        if self.dsqs.contains_key(&dsq_id) {
            return false;
        }
        self.dsqs.insert(dsq_id, Dsq::new());
        true
    }

    /// Insert a task in FIFO order into the specified DSQ.
    pub fn insert_fifo(&mut self, dsq_id: DsqId, pid: Pid) {
        if let Some(dsq) = self.dsqs.get_mut(&dsq_id) {
            dsq.insert_fifo(pid);
        }
    }

    /// Insert a task with vtime ordering into the specified DSQ.
    pub fn insert_vtime(&mut self, dsq_id: DsqId, pid: Pid, vtime: Vtime) {
        if let Some(dsq) = self.dsqs.get_mut(&dsq_id) {
            dsq.insert_vtime(pid, vtime);
        }
    }

    /// Move the head task from a DSQ to a CPU's local DSQ.
    /// Returns true if a task was moved.
    pub fn move_to_local(&mut self, dsq_id: DsqId, cpu: &mut SimCpu) -> bool {
        if let Some(dsq) = self.dsqs.get_mut(&dsq_id) {
            if let Some(pid) = dsq.pop() {
                cpu.local_dsq.push_back(pid);
                return true;
            }
        }
        false
    }

    /// Get the number of queued tasks in a DSQ.
    pub fn nr_queued(&self, dsq_id: DsqId) -> usize {
        self.dsqs.get(&dsq_id).map_or(0, |dsq| dsq.len())
    }

    /// Get ordered PIDs in a DSQ without consuming.
    pub fn ordered_pids(&self, dsq_id: DsqId) -> Vec<Pid> {
        self.dsqs
            .get(&dsq_id)
            .map_or_else(Vec::new, |dsq| dsq.ordered_pids())
    }

    /// Remove a specific PID from a DSQ. Returns true if found.
    pub fn remove_pid(&mut self, dsq_id: DsqId, pid: Pid) -> bool {
        self.dsqs
            .get_mut(&dsq_id)
            .map_or(false, |dsq| dsq.remove_pid(pid))
    }
}

impl Default for DsqManager {
    fn default() -> Self {
        Self::new()
    }
}
