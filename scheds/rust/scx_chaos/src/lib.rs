// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_intf;
mod bpf_skel;

use bpf_skel::BpfSkel;

use scx_p2dq::SchedulerOpts as P2dqOpts;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use anyhow::Result;
use libbpf_rs::OpenObject;
use log::debug;
use nix::unistd::Pid;

use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug)]
pub enum Trait {
    RandomDelays {
        frequency: f64,
        min_us: u64,
        max_us: u64,
    },
}

#[derive(Debug)]
pub enum RequiresPpid {
    ExcludeParent(Pid),
    IncludeParent(Pid),
}

#[derive(Debug)]
/// State required to build a Scheduler configuration.
pub struct Builder<'a> {
    pub traits: Vec<Trait>,
    pub verbose: u8,
    pub p2dq_opts: &'a P2dqOpts,
    pub requires_ppid: Option<RequiresPpid>,
}

pub struct Scheduler {
    open_object: MaybeUninit<OpenObject>,
    skel: BpfSkel<'static>,
    struct_ops: libbpf_rs::Link,

    // Skel holds a reference to the OpenObject, so the address must not change.
    _pin: PhantomPinned,
}

impl Scheduler {
    pub fn observe(
        &self,
        shutdown: &(Mutex<bool>, Condvar),
        timeout: Option<Duration>,
    ) -> Result<()> {
        let (lock, cvar) = shutdown;

        let start_time = Instant::now();

        let mut guard = lock.lock().unwrap();
        while !*guard {
            if uei_exited!(&self.skel, uei) {
                return uei_report!(&self.skel, uei)
                    .and_then(|_| Err(anyhow::anyhow!("scheduler exited unexpectedly")));
            }

            if timeout.is_some_and(|x| Instant::now().duration_since(start_time) >= x) {
                break;
            }

            guard = cvar
                .wait_timeout(guard, Duration::from_millis(500))
                .unwrap()
                .0;
        }

        Ok(())
    }
}

impl<'a> TryFrom<Builder<'a>> for Pin<Box<Scheduler>> {
    type Error = anyhow::Error;

    fn try_from(b: Builder<'a>) -> Result<Pin<Box<Scheduler>>> {
        let mut out = Box::<Scheduler>::new_uninit();

        let open_object = &mut unsafe {
            // SAFETY: We're extracting a MaybeUninit field from a MaybeUninit which is always
            // safe.
            let ptr = out.as_mut_ptr();
            (&raw mut (*ptr).open_object).as_mut().unwrap()
        };

        let open_object = unsafe {
            // SAFETY: Scheduler is pinned so this reference will not be invalidated for the
            // lifetime of Scheduler. Dropping MaybeUninit is a no-op, so it doesn't matter who
            // gets first. The use site (BpfSkel) is also in Scheduler and has the same lifetime.
            // Therefore it is safe to treat this reference as 'static from BpfSkel's perspective.
            std::mem::transmute::<&mut MaybeUninit<OpenObject>, &'static mut MaybeUninit<OpenObject>>(
                open_object,
            )
        };

        let mut skel_builder = bpf_skel::BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(b.verbose > 1);
        init_libbpf_logging(None);

        let mut open_skel = scx_ops_open!(skel_builder, open_object, chaos)?;
        scx_p2dq::init_open_skel!(&mut open_skel, b.p2dq_opts, b.verbose)?;

        // TODO: figure out how to abstract waking a CPU in enqueue properly, but for now disable
        // this codepath
        open_skel.maps.rodata_data.select_idle_in_enqueue = false;

        match b.requires_ppid {
            None => {
                open_skel.maps.rodata_data.ppid_targeting_ppid = -1;
            }
            Some(RequiresPpid::ExcludeParent(p)) => {
                open_skel.maps.rodata_data.ppid_targeting_inclusive = false;
                open_skel.maps.rodata_data.ppid_targeting_ppid = p.as_raw();
            }
            Some(RequiresPpid::IncludeParent(p)) => {
                open_skel.maps.rodata_data.ppid_targeting_inclusive = true;
                open_skel.maps.rodata_data.ppid_targeting_ppid = p.as_raw();
            }
        };

        for tr in b.traits {
            match tr {
                Trait::RandomDelays {
                    frequency,
                    min_us,
                    max_us,
                } => {
                    open_skel.maps.rodata_data.random_delays_freq_frac32 =
                        (frequency * 2_f64.powf(32_f64)) as u32;
                    open_skel.maps.rodata_data.random_delays_min_ns = min_us * 1000;
                    open_skel.maps.rodata_data.random_delays_max_ns = max_us * 1000;
                }
            }
        }

        let mut skel = scx_ops_load!(open_skel, chaos, uei)?;
        scx_p2dq::init_skel!(&mut skel);

        let struct_ops = scx_ops_attach!(skel, chaos)?;

        let out = unsafe {
            // SAFETY: initialising field by field. open_object is already "initialised" (it's
            // permanently MaybeUninit so any state is fine), hence the structure will be
            // initialised after initialising `skel` and `struct_ops`.
            let ptr = out.as_mut_ptr();

            (&raw mut (*ptr).skel).write(skel);
            (&raw mut (*ptr).struct_ops).write(struct_ops);

            out.assume_init()
        };

        debug!("scx_chaos scheduler started");
        Ok(Box::into_pin(out))
    }
}
