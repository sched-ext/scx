use crate::bpf_skel::*;
use crate::MetricsSnapshot;
use anyhow::{ensure, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{ProgramInput, RingBuffer, RingBufferBuilder};
use std::cell::RefCell;
use std::mem::{self, MaybeUninit};
use std::rc::Rc;

#[derive(Default)]
struct Totals {
    busy: u64,
    needed: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CpuSnapshot {
    runnable_tasks: u32,
    online_cpus: u32,
    busy_cpus: u32,
}

pub struct Collector {
    _skel: BpfSkel<'static>,
    ringbuf: RingBuffer<'static>,
    totals: Rc<RefCell<Totals>>,
}

impl Collector {
    pub fn start() -> Result<Self> {
        let storage = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open = BpfSkelBuilder::default().open(storage)?;
        open.maps.rodata_data.as_mut().unwrap().nr_cpu_ids = libbpf_rs::num_possible_cpus()? as u32;
        let skel = open.load()?;
        let totals = Rc::new(RefCell::new(Totals::default()));
        let callback_totals = Rc::clone(&totals);
        let mut builder = RingBufferBuilder::new();
        builder.add(&skel.maps.samples, move |data| {
            if data.len() != mem::size_of::<CpuSnapshot>() {
                return 0;
            }
            let sample = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const CpuSnapshot) };
            let needed = sample.runnable_tasks.min(sample.online_cpus) as u64;
            let busy = sample.busy_cpus.min(sample.runnable_tasks) as u64;
            let mut totals = callback_totals.borrow_mut();
            totals.busy = totals.busy.saturating_add(busy.min(needed));
            totals.needed = totals.needed.saturating_add(needed);
            0
        })?;
        let ringbuf = builder.build()?;

        let output = skel
            .progs
            .start_sampling
            .test_run(ProgramInput::default())?;
        ensure!(
            output.return_value == 0,
            "failed to start BPF sampling timer"
        );

        Ok(Self {
            _skel: skel,
            ringbuf,
            totals,
        })
    }

    pub fn collect(&mut self) -> Result<()> {
        self.ringbuf.consume()?;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<MetricsSnapshot> {
        let totals = self.totals.borrow();
        Ok(MetricsSnapshot {
            work_conservation: (totals.needed > 0)
                .then(|| totals.busy as f64 / totals.needed as f64),
            busy_cpu_samples_total: totals.busy,
            needed_cpu_samples_total: totals.needed,
        })
    }
}
