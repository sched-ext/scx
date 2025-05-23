use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use scxtop::available_perf_events;
use scxtop::Search;

fn get_search() -> Search {
    let available_perf_events_list: Vec<String> = available_perf_events()
        .unwrap()
        .iter()
        .flat_map(|(subsystem, events)| {
            events
                .iter()
                .map(|event| format!("{}:{}", subsystem.clone(), event.clone()))
        })
        .collect();
    Search::new(available_perf_events_list)
}

fn bench_empty(c: &mut Criterion) {
    let search = get_search();
    let i = "";

    let mut group = c.benchmark_group("Empty String Search");

    group.bench_with_input(BenchmarkId::new("Fuzzy Empty", i), i, |b, i| {
        b.iter(|| search.fuzzy_search(i))
    });
    group.bench_with_input(BenchmarkId::new("Substring Empty", i), i, |b, i| {
        b.iter(|| search.substring_search(i))
    });
    group.finish();
}

fn bench_easy_string(c: &mut Criterion) {
    let search = get_search();
    let i = "alarm";

    let mut group = c.benchmark_group("Easy String Search");

    group.bench_with_input(BenchmarkId::new("Fuzzy Easy String", i), i, |b, i| {
        b.iter(|| search.fuzzy_search(i))
    });
    group.bench_with_input(BenchmarkId::new("Substring Easy String", i), i, |b, i| {
        b.iter(|| search.substring_search(i))
    });
    group.finish();
}

fn bench_complex_string(c: &mut Criterion) {
    let search = get_search();
    let i = "alrMcacEL";

    let mut group = c.benchmark_group("Complex String Search");

    group.bench_with_input(BenchmarkId::new("Fuzzy Complex String", i), i, |b, i| {
        b.iter(|| search.fuzzy_search(i))
    });
    group.bench_with_input(BenchmarkId::new("Substring Complex", i), i, |b, i| {
        b.iter(|| search.substring_search(i))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_empty,
    bench_easy_string,
    bench_complex_string
);
criterion_main!(benches);
