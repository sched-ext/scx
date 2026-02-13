//! Dispatch queue (DSQ) simulation.
//!
//! Provides both FIFO and vtime-ordered dispatch queues that mirror
//! the kernel's DSQ semantics.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::cpu::SimCpu;
use crate::types::{DsqId, Pid, Vtime};

/// A single dispatch queue, supporting both FIFO and vtime ordering.
#[derive(Debug)]
pub struct Dsq {
    /// Vtime-ordered entries: (vtime, insertion_order) -> pid.
    /// The insertion_order provides a tiebreaker for equal vtimes.
    vtime_entries: BTreeMap<(Vtime, u64), Pid>,
    /// FIFO entries (used when tasks are inserted without vtime).
    fifo_entries: VecDeque<Pid>,
    /// Monotonic counter for insertion ordering.
    insertion_counter: u64,
}

impl Dsq {
    pub fn new() -> Self {
        Dsq {
            vtime_entries: BTreeMap::new(),
            fifo_entries: VecDeque::new(),
            insertion_counter: 0,
        }
    }

    /// Insert a task in FIFO order.
    pub fn insert_fifo(&mut self, pid: Pid) {
        self.fifo_entries.push_back(pid);
    }

    /// Insert a task ordered by vtime.
    pub fn insert_vtime(&mut self, pid: Pid, vtime: Vtime) {
        let order = self.insertion_counter;
        self.insertion_counter += 1;
        self.vtime_entries.insert((vtime, order), pid);
    }

    /// Pop the highest-priority task (lowest vtime, or FIFO head).
    /// Vtime entries take priority over FIFO entries.
    pub fn pop(&mut self) -> Option<Pid> {
        // Try vtime entries first
        if let Some((&key, &pid)) = self.vtime_entries.iter().next() {
            self.vtime_entries.remove(&key);
            return Some(pid);
        }
        // Fall back to FIFO
        self.fifo_entries.pop_front()
    }

    /// Number of queued tasks.
    pub fn len(&self) -> usize {
        self.vtime_entries.len() + self.fifo_entries.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.vtime_entries.is_empty() && self.fifo_entries.is_empty()
    }

    /// Return all PIDs in priority order (vtime first, then FIFO) without consuming.
    pub fn ordered_pids(&self) -> Vec<Pid> {
        let mut pids = Vec::with_capacity(self.len());
        for &pid in self.vtime_entries.values() {
            pids.push(pid);
        }
        for &pid in &self.fifo_entries {
            pids.push(pid);
        }
        pids
    }

    /// Remove a specific PID from the queue. Returns true if found.
    pub fn remove_pid(&mut self, pid: Pid) -> bool {
        if let Some(key) = self
            .vtime_entries
            .iter()
            .find_map(|(k, &v)| if v == pid { Some(*k) } else { None })
        {
            self.vtime_entries.remove(&key);
            return true;
        }
        if let Some(pos) = self.fifo_entries.iter().position(|&p| p == pid) {
            self.fifo_entries.remove(pos);
            return true;
        }
        false
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
