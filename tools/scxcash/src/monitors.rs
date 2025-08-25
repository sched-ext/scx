// Cache monitor trait definitions and implementations.

use anyhow::{Context, Result};
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use log::trace;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

/// Enum for cache monitor produced values.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CacheMonitorValue {
    /// A soft-dirty page fault event (tid and faulting address).
    SoftDirtyFault { tid: u32, address: u64 },
}

/// Trait representing a cache monitor instance.
pub trait CacheMonitor<'a> {
    fn poll(&mut self) -> Result<()>;
    fn consume(&mut self, cb: &mut dyn FnMut(CacheMonitorValue)) -> Result<()>;
}

/// Soft-dirty page reset monitor.
pub struct SoftDirtyCacheMonitor<'a> {
    pid: Option<u32>,
    _skel: crate::bpf::BpfSkel<'a>,
    _ringbuf: RingBuffer<'a>,
    _link: libbpf_rs::Link,
    events: Rc<RefCell<VecDeque<CacheMonitorValue>>>,
}

impl<'a> SoftDirtyCacheMonitor<'a> {
    pub fn new(
        open_storage: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        pid: Option<u32>,
        ring_size: u64,
    ) -> Result<Self> {
        let mut open_skel = crate::bpf::BpfSkelBuilder::default().open(open_storage)?;
        let mut ring_capacity = ring_size.max(4096);
        if !ring_capacity.is_power_of_two() {
            ring_capacity = ring_capacity.next_power_of_two();
        }
        let max_entries = ring_capacity.min(u32::MAX as u64) as u32;
        unsafe {
            libbpf_sys::bpf_map__set_max_entries(
                open_skel.maps.soft_dirty_events.as_libbpf_object().as_ptr(),
                max_entries,
            );
        }
        if let Some(pid) = pid {
            open_skel.maps.rodata_data.as_mut().unwrap().filter_tgid = pid as i32;
        }
        let skel = open_skel.load()?;
        let link = skel.progs.handle_do_fault.attach()?;
        let mut builder = RingBufferBuilder::new();
        let events: Rc<RefCell<VecDeque<CacheMonitorValue>>> =
            Rc::new(RefCell::new(VecDeque::new()));
        let events_cb = Rc::clone(&events);
        let events_map = &skel.maps.soft_dirty_events;
        builder.add(events_map, move |data: &[u8]| {
            if data.len() == std::mem::size_of::<crate::bpf_intf::soft_dirty_fault_event>() {
                let ev: &crate::bpf_intf::soft_dirty_fault_event =
                    unsafe { &*(data.as_ptr() as *const _) };
                trace!("soft-dirty fault tid={} addr=0x{:x}", ev.tid, ev.address);
                events_cb
                    .borrow_mut()
                    .push_back(CacheMonitorValue::SoftDirtyFault {
                        tid: ev.tid,
                        address: ev.address,
                    });
            }
            0
        })?;
        let ringbuf = builder.build()?;
        Ok(Self {
            pid,
            _skel: skel,
            _ringbuf: ringbuf,
            _link: link,
            events,
        })
    }

    fn write_clear_refs(pid: u32) -> Result<()> {
        let mut path = PathBuf::from("/proc");
        path.push(pid.to_string());
        path.push("clear_refs");
        let mut f = OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("Opening {:?}", path))?;
        f.write_all(b"4\n")
            .with_context(|| format!("Writing to {:?}", path))?;
        Ok(())
    }

    fn walk_all_pids() -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if let Some(fname) = entry.file_name().to_str() {
                if let Ok(pid) = fname.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
        Ok(pids)
    }
}

impl<'a> CacheMonitor<'a> for SoftDirtyCacheMonitor<'a> {
    fn poll(&mut self) -> Result<()> {
        // TODO(kkd): Switch to epoll later?
        let _ = self._ringbuf.poll(Duration::from_millis(0));
        match self.pid {
            Some(pid) => {
                // TODO(kkd): Handle failures
                let _ = Self::write_clear_refs(pid);
            }
            None => {
                // TODO(kkd): Make this less expensive
                for pid in Self::walk_all_pids()? {
                    let _ = Self::write_clear_refs(pid);
                }
            }
        }
        Ok(())
    }

    fn consume(&mut self, cb: &mut dyn FnMut(CacheMonitorValue)) -> Result<()> {
        {
            let mut q = self.events.borrow_mut();
            while let Some(ev) = q.pop_front() {
                cb(ev);
            }
        }
        Ok(())
    }
}
