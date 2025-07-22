use ::core::time::Duration;
use ::criterion::{Criterion, criterion_group, criterion_main};
use ::std::hint::black_box;

mod data {
    pub const ALLOCATIONS: usize = 10_000;

    #[derive(Default)]
    pub struct Small(#[allow(unused)] u8);

    #[derive(Default)]
    pub struct Large(#[allow(unused)] [usize; 32]);
}

mod arena {
    use ::scx_event_reactor::bench::arena::*;

    use super::*;
    use crate::data::*;

    fn try_alloc_mut<T: Default>(n: usize) {
        let bump = ArenaBump::try_with_capacity(n * ::core::mem::size_of::<T>()).unwrap();
        let mut slab = ArenaSlab::new(&bump);
        for _ in 0..n {
            let slab = black_box(&mut slab);
            let val = slab.try_alloc(black_box(T::default()));
            let _ = black_box(val);
        }
    }

    fn detach<T: Default>(iters: u64, n: usize) -> Duration {
        let mut total_time = Duration::default();
        for _ in 0..iters {
            let bump = ArenaBump::try_with_capacity(n * ::core::mem::size_of::<T>()).unwrap();
            let mut slab = ArenaSlab::new(&bump);
            let mut vals = black_box(Vec::with_capacity(n));
            for _ in 0..n {
                let slab = black_box(&mut slab);
                let val = slab.try_alloc(black_box(T::default())).unwrap();
                vals.push(black_box(val));
            }
            let start = ::std::time::Instant::now();
            for val in vals {
                let det = black_box(slab.detach(val));
                drop(det);
            }
            total_time += start.elapsed();
        }
        total_time
    }

    pub fn bench(c: &mut Criterion) {
        // {
        //     let mut group = c.benchmark_group("arena::try_alloc_mut");
        //     group.throughput(::criterion::Throughput::Elements(ALLOCATIONS as u64));
        //     group.bench_function("small", |b| b.iter(|| self::try_alloc_mut::<Small>(ALLOCATIONS)));
        //     group.bench_function("large", |b| b.iter(|| self::try_alloc_mut::<Large>(ALLOCATIONS)));
        // }
        {
            let mut group = c.benchmark_group("arena::detach");
            group.throughput(::criterion::Throughput::Elements(ALLOCATIONS as u64));
            group.bench_function("small", |b| {
                b.iter_custom(|iters| self::detach::<Small>(iters, ALLOCATIONS))
            });
            group.bench_function("large", |b| {
                b.iter_custom(|iters| self::detach::<Large>(iters, ALLOCATIONS))
            });
        }
    }
}

criterion_group!(benches, arena::bench);
criterion_main!(benches);
