//! Scenario definition and builder API.

use crate::task::{TaskBehavior, TaskDef};

/// A complete simulation scenario: CPUs, tasks, and duration.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub nr_cpus: u32,
    pub tasks: Vec<TaskDef>,
    pub duration_ns: u64,
}

/// Builder for constructing scenarios.
pub struct ScenarioBuilder {
    nr_cpus: u32,
    tasks: Vec<TaskDef>,
    duration_ns: u64,
    next_pid: i32,
}

impl Scenario {
    pub fn builder() -> ScenarioBuilder {
        ScenarioBuilder {
            nr_cpus: 1,
            tasks: Vec::new(),
            duration_ns: 100_000_000, // 100ms default
            next_pid: 1,
        }
    }
}

impl ScenarioBuilder {
    /// Set the number of simulated CPUs.
    pub fn cpus(mut self, n: u32) -> Self {
        self.nr_cpus = n;
        self
    }

    /// Add a task with a full TaskDef.
    pub fn task(mut self, def: TaskDef) -> Self {
        self.tasks.push(def);
        self
    }

    /// Convenience: add a task with auto-assigned PID.
    pub fn add_task(
        mut self,
        name: &str,
        weight: u32,
        behavior: TaskBehavior,
    ) -> Self {
        let pid = self.next_pid;
        self.next_pid += 1;
        self.tasks.push(TaskDef {
            name: name.to_string(),
            pid,
            weight,
            behavior,
            start_time_ns: 0,
        });
        self
    }

    /// Set the simulation duration in nanoseconds.
    pub fn duration_ns(mut self, ns: u64) -> Self {
        self.duration_ns = ns;
        self
    }

    /// Set the simulation duration in milliseconds.
    pub fn duration_ms(mut self, ms: u64) -> Self {
        self.duration_ns = ms * 1_000_000;
        self
    }

    /// Build the scenario.
    pub fn build(self) -> Scenario {
        assert!(!self.tasks.is_empty(), "scenario must have at least one task");
        assert!(self.nr_cpus > 0, "scenario must have at least one CPU");
        Scenario {
            nr_cpus: self.nr_cpus,
            tasks: self.tasks,
            duration_ns: self.duration_ns,
        }
    }
}
