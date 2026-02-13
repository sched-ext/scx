use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_lavd
scheduler_tests!(|nr_cpus| DynamicScheduler::lavd(nr_cpus));
