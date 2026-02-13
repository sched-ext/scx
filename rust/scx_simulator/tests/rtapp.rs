use scx_simulator::*;

mod common;

/// Parse simple_wake.json and verify the generated Scenario structure.
#[test]
fn test_rtapp_parse_simple_wake() {
    let _lock = common::setup_test();
    let json = include_str!("../workloads/simple_wake.json");
    let scenario = load_rtapp(json, 2).unwrap();

    assert_eq!(scenario.nr_cpus, 2);
    assert_eq!(scenario.duration_ns, 1_000_000_000); // 1 second

    assert_eq!(scenario.tasks.len(), 2);

    // Producer: run 5ms, wake consumer, run 5ms, sleep 10ms (repeat)
    let producer = &scenario.tasks[0];
    assert_eq!(producer.name, "producer");
    assert_eq!(producer.nice, -5);
    assert!(producer.behavior.repeat);
    assert_eq!(producer.behavior.phases.len(), 4);
    assert!(matches!(producer.behavior.phases[0], Phase::Run(5_000_000)));
    assert!(matches!(producer.behavior.phases[1], Phase::Wake(_))); // consumer
    assert!(matches!(producer.behavior.phases[2], Phase::Run(5_000_000)));
    assert!(matches!(
        producer.behavior.phases[3],
        Phase::Sleep(10_000_000)
    ));

    // Consumer: suspend (sleep MAX), run 10ms (repeat)
    let consumer = &scenario.tasks[1];
    assert_eq!(consumer.name, "consumer");
    assert_eq!(consumer.nice, 0);
    assert!(consumer.behavior.repeat);
    assert_eq!(consumer.behavior.phases.len(), 2);
    assert!(matches!(
        consumer.behavior.phases[0],
        Phase::Sleep(u64::MAX)
    ));
    assert!(matches!(
        consumer.behavior.phases[1],
        Phase::Run(10_000_000)
    ));
}

/// Parse simple_wake.json, run it through scx_simple, and verify both tasks run.
#[test]
fn test_rtapp_simulate_simple_wake() {
    let _lock = common::setup_test();
    let json = include_str!("../workloads/simple_wake.json");
    let scenario = load_rtapp(json, 2).unwrap();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let producer_pid = Pid(1);
    let consumer_pid = Pid(2);

    // Both tasks should have been scheduled
    assert!(
        trace.schedule_count(producer_pid) > 0,
        "producer was never scheduled"
    );
    assert!(
        trace.schedule_count(consumer_pid) > 0,
        "consumer was never scheduled"
    );

    // Both tasks should accumulate some runtime
    let producer_rt = trace.total_runtime(producer_pid);
    let consumer_rt = trace.total_runtime(consumer_pid);

    eprintln!("producer runtime: {producer_rt}ns, consumer runtime: {consumer_rt}ns");

    assert!(
        producer_rt > 0,
        "expected producer to have nonzero runtime, got {producer_rt}ns"
    );
    assert!(
        consumer_rt > 0,
        "expected consumer to have nonzero runtime, got {consumer_rt}ns"
    );
}

/// Inline JSON with a single CPU-bound looping task — basic sanity check.
#[test]
fn test_rtapp_single_runner() {
    let _lock = common::setup_test();
    let json = r#"{
        "global": { "duration": 1 },
        "tasks": {
            "runner": {
                "loop": -1,
                "run": 20000
            }
        }
    }"#;

    let scenario = load_rtapp(json, 1).unwrap();
    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let runtime = trace.total_runtime(Pid(1));
    // With 1s duration and a repeating 20ms run phase, should fill most of the time
    assert!(
        runtime > 500_000_000,
        "expected >500ms runtime for CPU-bound task in 1s, got {runtime}ns"
    );
}

/// Parse two_runners.json and simulate: two tasks with run+sleep cycles and
/// different priorities, using only the fully-supported rt-app feature subset.
#[test]
fn test_rtapp_two_runners() {
    let _lock = common::setup_test();
    let json = include_str!("../workloads/two_runners.json");
    let scenario = load_rtapp(json, 2).unwrap();

    assert_eq!(scenario.nr_cpus, 2);
    assert_eq!(scenario.duration_ns, 1_000_000_000);
    assert_eq!(scenario.tasks.len(), 2);

    // heavy: nice=-5, run 10ms / sleep 10ms (50% duty, 20ms cycle → ~50 cycles/s)
    let heavy = &scenario.tasks[0];
    assert_eq!(heavy.name, "heavy");
    assert_eq!(heavy.nice, -5);
    assert!(heavy.behavior.repeat);
    assert_eq!(heavy.behavior.phases.len(), 2);
    assert!(matches!(heavy.behavior.phases[0], Phase::Run(10_000_000)));
    assert!(matches!(heavy.behavior.phases[1], Phase::Sleep(10_000_000)));

    // light: nice=0, run 5ms / sleep 15ms (25% duty, 20ms cycle → ~50 cycles/s)
    let light = &scenario.tasks[1];
    assert_eq!(light.name, "light");
    assert_eq!(light.nice, 0);
    assert!(light.behavior.repeat);
    assert_eq!(light.behavior.phases.len(), 2);
    assert!(matches!(light.behavior.phases[0], Phase::Run(5_000_000)));
    assert!(matches!(light.behavior.phases[1], Phase::Sleep(15_000_000)));

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let heavy_rt = trace.total_runtime(Pid(1));
    let light_rt = trace.total_runtime(Pid(2));
    eprintln!("heavy(nice=-5) runtime: {heavy_rt}ns, light(nice=0) runtime: {light_rt}ns");

    // heavy: 50 cycles × 10ms = ~500ms expected
    assert!(
        heavy_rt > 400_000_000,
        "expected heavy >400ms runtime, got {heavy_rt}ns"
    );
    // light: 50 cycles × 5ms = ~250ms expected
    assert!(
        light_rt > 200_000_000,
        "expected light >200ms runtime, got {light_rt}ns"
    );
}

/// Test that rt-app workloads with nice priorities produce weighted-fair results.
#[test]
fn test_rtapp_weighted_tasks() {
    let _lock = common::setup_test();
    let json = r#"{
        "global": { "duration": 1 },
        "tasks": {
            "heavy": {
                "priority": -5,
                "loop": -1,
                "run": 50000
            },
            "light": {
                "priority": 0,
                "loop": -1,
                "run": 50000
            }
        }
    }"#;

    let scenario = load_rtapp(json, 1).unwrap();
    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    let heavy_rt = trace.total_runtime(Pid(1));
    let light_rt = trace.total_runtime(Pid(2));

    eprintln!("heavy(nice=-5) runtime: {heavy_rt}ns, light(nice=0) runtime: {light_rt}ns");

    // nice -5 has weight ~3.05x of nice 0; heavy should get more
    assert!(
        heavy_rt > light_rt,
        "expected heavy task to get more runtime: heavy={heavy_rt}, light={light_rt}"
    );
}
