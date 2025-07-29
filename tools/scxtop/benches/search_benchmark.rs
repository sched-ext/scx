// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use scxtop::available_perf_events;
use scxtop::search;

fn get_search() -> Vec<String> {
    let mut available_perf_events_list: Vec<String> = available_perf_events()
        .unwrap()
        .into_iter()
        .flat_map(|(subsystem, events)| {
            events
                .into_iter()
                .map(move |event| format!("{}:{}", &subsystem, &event))
        })
        .collect();
    available_perf_events_list.sort();
    available_perf_events_list
}

fn bench_empty(c: &mut Criterion) {
    let search = get_search();
    let i = "";

    let mut group = c.benchmark_group("Empty String Search");

    group.bench_with_input(BenchmarkId::new("Fuzzy Empty", i), i, |b, i| {
        b.iter(|| search::fuzzy_search(&search, i))
    });
    group.bench_with_input(BenchmarkId::new("Substring Empty", i), i, |b, i| {
        b.iter(|| search::substring_search(&search, i))
    });
    group.finish();
}

fn bench_easy_string(c: &mut Criterion) {
    let search = get_search();
    let i = "alarm";

    let mut group = c.benchmark_group("Easy String Search");

    group.bench_with_input(BenchmarkId::new("Fuzzy Easy String", i), i, |b, i| {
        b.iter(|| search::fuzzy_search(&search, i))
    });
    group.bench_with_input(BenchmarkId::new("Substring Easy String", i), i, |b, i| {
        b.iter(|| search::substring_search(&search, i))
    });
    group.finish();
}

fn bench_complex_string(c: &mut Criterion) {
    let search = get_search();
    let i = "alrMcacEL";

    let mut group = c.benchmark_group("Complex String Search");

    group.bench_with_input(BenchmarkId::new("Fuzzy Complex String", i), i, |b, i| {
        b.iter(|| search::fuzzy_search(&search, i))
    });
    group.bench_with_input(
        BenchmarkId::new("Substring Complex String", i),
        i,
        |b, i| b.iter(|| search::substring_search(&search, i)),
    );
    group.finish();
}

fn bench_long_complex_string(c: &mut Criterion) {
    let search = get_search();
    let i = "alrMtIImeralarmmer_cacEL";

    let mut group = c.benchmark_group("Long Complex String Search");

    group.bench_with_input(
        BenchmarkId::new("Fuzzy Long Complex String", i),
        i,
        |b, i| b.iter(|| search::fuzzy_search(&search, i)),
    );
    group.bench_with_input(
        BenchmarkId::new("Substring Long Complex String", i),
        i,
        |b, i| b.iter(|| search::substring_search(&search, i)),
    );
    group.finish();
}

fn configure_criterion() -> Criterion {
    Criterion::default().measurement_time(std::time::Duration::new(10, 0))
}

criterion_group!(
    name = benches;
    config = configure_criterion();
    targets = bench_empty, bench_easy_string, bench_complex_string, bench_long_complex_string
);
criterion_main!(benches);
