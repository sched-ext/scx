// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use prost::Message;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use scx_utils::scx_enums;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::edm::ActionHandler;
use crate::protos_gen::perfetto_scx;
use crate::{
    Action, CpuhpEnterAction, CpuhpExitAction, ExecAction, ExitAction, ForkAction, GpuMemAction,
    IPIAction, SchedSwitchAction, SchedWakeupAction, SchedWakingAction, SoftIRQAction,
};

use crate::protos_gen::perfetto_scx::clock_snapshot::Clock;
use crate::protos_gen::perfetto_scx::counter_descriptor::Unit::Count as UNIT_COUNT;
use crate::protos_gen::perfetto_scx::trace_packet;
use crate::protos_gen::perfetto_scx::{
    BuiltinClock, ClockSnapshot, CounterDescriptor, CpuhpEnterFtraceEvent, CpuhpExitFtraceEvent,
    FtraceEvent, FtraceEventBundle, GpuMemTotalFtraceEvent, IpiRaiseFtraceEvent, ProcessDescriptor,
    SchedProcessExecFtraceEvent, SchedProcessExitFtraceEvent, SchedProcessForkFtraceEvent,
    SchedSwitchFtraceEvent, SchedWakeupFtraceEvent, SchedWakingFtraceEvent,
    SoftirqEntryFtraceEvent, SoftirqExitFtraceEvent, ThreadDescriptor, Trace, TracePacket,
    TrackDescriptor, TrackEvent,
};

/// Handler for perfetto traces. For details on data flow in perfetto see:
/// https://perfetto.dev/docs/concepts/buffers and
/// https://perfetto.dev/docs/reference/trace-packet-proto
pub struct PerfettoTraceManager {
    // proto fields
    trace: Trace,

    trace_id: u32,
    trusted_pid: i32,
    rng: StdRng,
    output_file_prefix: String,

    // per cpu ftrace events
    ftrace_events: BTreeMap<u32, Vec<FtraceEvent>>,
    dsq_lat_events: BTreeMap<u64, Vec<TrackEvent>>,
    dsq_lat_trusted_packet_seq_uuid: u32,
    dsq_nr_queued_events: BTreeMap<u64, Vec<TrackEvent>>,
    dsq_nr_queued_trusted_packet_seq_uuid: u32,
    dsq_uuids: BTreeMap<u64, u64>,
    processes: HashMap<u64, ProcessDescriptor>,
    threads: HashMap<u64, ThreadDescriptor>,
    process_uuids: HashMap<i32, u64>,
}

impl PerfettoTraceManager {
    /// Returns a PerfettoTraceManager that is ready to start tracing.
    pub fn new(output_file_prefix: String, seed: Option<u64>) -> Self {
        let trace_uuid = seed.unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        );
        let mut rng = StdRng::seed_from_u64(trace_uuid);
        let trace = Trace::default();
        let dsq_lat_trusted_packet_seq_uuid = rng.next_u32();
        let dsq_nr_queued_trusted_packet_seq_uuid = rng.next_u32();

        Self {
            trace,
            trace_id: 0,
            trusted_pid: std::process::id() as i32,
            rng,
            output_file_prefix,
            ftrace_events: BTreeMap::new(),
            dsq_uuids: BTreeMap::new(),
            dsq_lat_events: BTreeMap::new(),
            dsq_lat_trusted_packet_seq_uuid,
            dsq_nr_queued_events: BTreeMap::new(),
            dsq_nr_queued_trusted_packet_seq_uuid,
            processes: HashMap::new(),
            threads: HashMap::new(),
            process_uuids: HashMap::new(),
        }
    }

    /// Starts a new perfetto trace.
    pub fn start(&mut self) -> Result<()> {
        self.clear();
        self.trace = Trace::default();
        self.snapshot_clocks();
        Ok(())
    }

    /// Clears all events.
    fn clear(&mut self) {
        self.ftrace_events.clear();
        self.dsq_lat_events.clear();
        self.dsq_uuids.clear();
    }

    /// Returns the trace file.
    pub fn trace_file(&self) -> String {
        format!("{}_{}.proto", self.output_file_prefix, self.trace_id)
    }

    /// Creates the TrackDescriptors for the trace.
    fn track_descriptors(&self) -> BTreeMap<u64, Vec<TrackDescriptor>> {
        let mut desc_map = BTreeMap::new();

        // First add DSQ descriptor tracks
        for (&dsq, &dsq_uuid) in &self.dsq_uuids {
            let mut descs = vec![];

            // DSQ latency
            descs.push(TrackDescriptor {
                uuid: Some(dsq_uuid),
                counter: Some(CounterDescriptor {
                    unit: Some(UNIT_COUNT as i32),
                    unit_name: Some(format!("DSQ {dsq} latency ns")),
                    is_incremental: Some(false),
                    ..CounterDescriptor::default()
                }),
                static_or_dynamic_name: Some(
                    perfetto_scx::track_descriptor::StaticOrDynamicName::StaticName(format!(
                        "DSQ {dsq} latency ns"
                    )),
                ),
                ..TrackDescriptor::default()
            });

            // DSQ nr_queued
            descs.push(TrackDescriptor {
                uuid: Some(dsq_uuid + 1),
                counter: Some(CounterDescriptor {
                    unit: Some(UNIT_COUNT as i32),
                    unit_name: Some(format!("DSQ {dsq} nr_queued")),
                    is_incremental: Some(false),
                    ..CounterDescriptor::default()
                }),
                static_or_dynamic_name: Some(
                    perfetto_scx::track_descriptor::StaticOrDynamicName::StaticName(format!(
                        "DSQ {dsq} nr_queued"
                    )),
                ),
                ..TrackDescriptor::default()
            });

            desc_map.insert(dsq_uuid, descs);
        }

        desc_map
    }

    fn get_clock_value(&mut self, clock_id: libc::c_int) -> u64 {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
            return 0;
        }
        (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
    }

    fn snapshot_clocks(&mut self) {
        let clock_snapshot = ClockSnapshot {
            clocks: vec![
                Clock {
                    clock_id: Some(BuiltinClock::Monotonic as u32),
                    timestamp: Some(self.get_clock_value(libc::CLOCK_MONOTONIC)),
                    ..Clock::default()
                },
                Clock {
                    clock_id: Some(BuiltinClock::Boottime as u32),
                    timestamp: Some(self.get_clock_value(libc::CLOCK_BOOTTIME)),
                    ..Clock::default()
                },
                Clock {
                    clock_id: Some(BuiltinClock::Realtime as u32),
                    timestamp: Some(self.get_clock_value(libc::CLOCK_REALTIME)),
                    ..Clock::default()
                },
                Clock {
                    clock_id: Some(BuiltinClock::RealtimeCoarse as u32),
                    timestamp: Some(self.get_clock_value(libc::CLOCK_REALTIME_COARSE)),
                    ..Clock::default()
                },
                Clock {
                    clock_id: Some(BuiltinClock::MonotonicCoarse as u32),
                    timestamp: Some(self.get_clock_value(libc::CLOCK_MONOTONIC_COARSE)),
                    ..Clock::default()
                },
                Clock {
                    clock_id: Some(BuiltinClock::MonotonicRaw as u32),
                    timestamp: Some(self.get_clock_value(libc::CLOCK_MONOTONIC_RAW)),
                    ..Clock::default()
                },
            ],
            primary_trace_clock: None,
        };

        self.trace.packet.push(TracePacket {
            data: Some(perfetto_scx::trace_packet::Data::ClockSnapshot(
                clock_snapshot,
            )),
            ..TracePacket::default()
        });
    }

    fn generate_key(&mut self, v1: u32, v2: u32) -> u64 {
        let v1_u32 = v1 as u64;
        let v2_u32 = v2 as u64;
        (v1_u32 << 32) | v2_u32
    }

    fn record_process_thread(&mut self, pid: u32, tid: u32, comm: String) {
        let key = self.generate_key(pid, tid);

        if pid == tid {
            let process = self
                .processes
                .entry(key)
                .or_insert_with(|| ProcessDescriptor {
                    pid: Some(pid as i32),
                    ..ProcessDescriptor::default()
                });
            process.process_name.get_or_insert(comm);
        } else {
            self.threads.entry(key).or_insert_with(|| ThreadDescriptor {
                tid: Some(tid as i32),
                pid: Some(pid as i32),
                thread_name: Some(comm),
                ..ThreadDescriptor::default()
            });
            // Create a ProcessDescriptor with an empty comm if one doesn't
            // exist - if we ever see the main thread we populate the process
            // name field there (see above).
            let pkey = self.generate_key(pid, pid);
            self.processes
                .entry(pkey)
                .or_insert_with(|| ProcessDescriptor {
                    pid: Some(pid as i32),
                    ..ProcessDescriptor::default()
                });
        }
    }

    fn get_comm(pid: i32) -> Result<String> {
        let path = format!("/proc/{}/comm", pid);
        let content = fs::read_to_string(path)?;
        Ok(content.trim_end().to_string())
    }

    /// Stops the trace and writes to configured output file.
    pub fn stop(
        &mut self,
        output_file: Option<String>,
        last_relevent_timestamp_ns: Option<u64>,
    ) -> Result<()> {
        // TracePacket is the root object of a Perfetto trace. A Perfetto trace is a linear
        // sequence of TracePacket(s). The tracing service guarantees that all TracePacket(s)
        // written by a given TraceWriter are seen in-order, without gaps or duplicates.
        // https://perfetto.dev/docs/reference/trace-packet-proto

        let trace_cpus: Vec<u32> = self.ftrace_events.keys().cloned().collect();
        let trace_dsqs: Vec<u64> = self.dsq_nr_queued_events.keys().cloned().collect();

        fn timestamp_absolute_us(e: &TrackEvent) -> i64 {
            use crate::protos::protos_gen::perfetto_scx::track_event::Timestamp;
            match e.timestamp {
                Some(Timestamp::TimestampAbsoluteUs(t)) => t,
                None | Some(Timestamp::TimestampDeltaUs(_)) => 0,
            }
        }

        // remove any events >last_relevent_timestamp_ns
        if let Some(ns) = last_relevent_timestamp_ns {
            let signed_ns = ns as i64;
            self.dsq_lat_events
                .iter_mut()
                .for_each(|(_, v)| v.retain(|e| timestamp_absolute_us(e) * 1000 < signed_ns));
            self.dsq_nr_queued_events
                .iter_mut()
                .for_each(|(_, v)| v.retain(|e| timestamp_absolute_us(e) * 1000 < signed_ns));
            self.ftrace_events
                .iter_mut()
                .for_each(|(_, v)| v.retain(|e| e.timestamp.unwrap_or(0) < ns));
        };

        for (_, mut process) in self.processes.drain() {
            let uuid = self.rng.next_u64();
            self.process_uuids.insert(process.pid(), uuid);

            if process.process_name().is_empty() {
                process.process_name = Self::get_comm(process.pid()).ok();
            }

            let desc = TrackDescriptor {
                uuid: Some(uuid),
                process: Some(process),
                ..TrackDescriptor::default()
            };

            let packet = TracePacket {
                data: Some(trace_packet::Data::TrackDescriptor(desc)),
                ..TracePacket::default()
            };
            self.trace.packet.push(packet);
        }

        for (_, thread) in self.threads.drain() {
            let uuid = self.rng.next_u64();

            let pid = thread.pid();
            let desc = TrackDescriptor {
                parent_uuid: self.process_uuids.get(&pid).copied(),
                thread: Some(thread),
                uuid: Some(uuid),
                ..TrackDescriptor::default()
            };

            let packet = TracePacket {
                data: Some(trace_packet::Data::TrackDescriptor(desc)),
                ..TracePacket::default()
            };
            self.trace.packet.push(packet);
        }

        for trace_descs in self.track_descriptors().values() {
            for trace_desc in trace_descs {
                self.trace.packet.push(TracePacket {
                    data: Some(perfetto_scx::trace_packet::Data::TrackDescriptor(
                        trace_desc.clone(),
                    )),
                    ..TracePacket::default()
                });
            }
        }

        // dsq latency tracks
        for dsq in &trace_dsqs {
            if let Some(events) = self.dsq_lat_events.remove(dsq) {
                for dsq_lat_event in events {
                    let ts: u64 = timestamp_absolute_us(&dsq_lat_event) as u64 / 1_000;
                    self.trace.packet.push(TracePacket {
                        data: Some(
                            perfetto_scx::trace_packet::Data::TrackEvent(
                                dsq_lat_event,
                            ),
                        ),
                        timestamp: Some(ts),
                        optional_trusted_packet_sequence_id: Some(
                            perfetto_scx::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                            self.dsq_lat_trusted_packet_seq_uuid,
                        )), ..TracePacket::default()
                    });
                }
            }
        }

        // dsq nr_queued tracks
        for dsq in &trace_dsqs {
            if let Some(events) = self.dsq_nr_queued_events.remove(dsq) {
                for dsq_lat_event in events {
                    let ts: u64 = timestamp_absolute_us(&dsq_lat_event) as u64 / 1_000;
                    self.trace.packet.push(TracePacket {
                        data: Some(
                            perfetto_scx::trace_packet::Data::TrackEvent(
                                dsq_lat_event,
                            ),
                        ),
                        timestamp: Some(ts),
                        optional_trusted_packet_sequence_id: Some(
                            perfetto_scx::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                            self.dsq_nr_queued_trusted_packet_seq_uuid,
                        )),
                        ..TracePacket::default()
                    });
                }
            }
        }

        // ftrace events
        for cpu in &trace_cpus {
            self.trace.packet.push(TracePacket {
                trusted_pid: Some(self.trusted_pid),
                data: Some(perfetto_scx::trace_packet::Data::FtraceEvents(
                    FtraceEventBundle {
                        cpu: Some(*cpu),
                        event: self
                            .ftrace_events
                            .remove(cpu)
                            .map(|mut events| {
                                // sort by timestamp just to make sure.
                                events.sort_by_key(|event| event.timestamp.unwrap_or(0));
                                events
                            })
                            .unwrap_or_default(),
                        ..FtraceEventBundle::default()
                    },
                )),
                ..TracePacket::default()
            });
        }

        let out_bytes: Vec<u8> = self.trace.encode_to_vec();
        match output_file {
            Some(trace_file) => {
                fs::write(trace_file, out_bytes)?;
            }
            None => {
                fs::write(self.trace_file(), out_bytes)?;
            }
        }

        self.clear();
        self.trace_id += 1;
        Ok(())
    }

    pub fn on_exit(&mut self, action: &ExitAction) {
        let ExitAction {
            ts,
            cpu,
            pid,
            tgid,
            prio,
            comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::SchedProcessExit(
                    SchedProcessExitFtraceEvent {
                        comm: Some(comm.as_str().to_string()),
                        pid: Some((*pid).try_into().unwrap()),
                        tgid: Some((*tgid).try_into().unwrap()),
                        prio: Some((*prio).try_into().unwrap()),
                    },
                )),
                ..FtraceEvent::default()
            }
        });
        self.record_process_thread(*tgid, *pid, comm.to_string());
    }

    pub fn on_fork(&mut self, action: &ForkAction) {
        let ForkAction {
            ts,
            cpu,
            parent_pid,
            child_pid,
            parent_comm,
            child_comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*parent_pid),
                event: Some(perfetto_scx::ftrace_event::Event::SchedProcessFork(
                    SchedProcessForkFtraceEvent {
                        parent_comm: Some(parent_comm.as_str().to_string()),
                        parent_pid: Some((*parent_pid).try_into().unwrap()),
                        child_comm: Some(child_comm.as_str().to_string()),
                        child_pid: Some((*child_pid).try_into().unwrap()),
                    },
                )),
                ..FtraceEvent::default()
            }
        });
    }

    pub fn on_exec(&mut self, action: &ExecAction) {
        let ExecAction {
            ts,
            cpu,
            old_pid,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*old_pid),
                event: Some(perfetto_scx::ftrace_event::Event::SchedProcessExec(
                    SchedProcessExecFtraceEvent {
                        pid: Some((*pid).try_into().unwrap()),
                        old_pid: Some((*old_pid).try_into().unwrap()),
                        ..SchedProcessExecFtraceEvent::default()
                    },
                )),
                ..FtraceEvent::default()
            }
        });
    }
    /// Adds events for on sched_wakeup.
    pub fn on_sched_wakeup(&mut self, action: &SchedWakeupAction) {
        let SchedWakeupAction {
            ts,
            cpu,
            pid,
            tgid,
            prio,
            comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::SchedWakeup(
                    SchedWakeupFtraceEvent {
                        comm: Some(comm.as_str().to_string()),
                        pid: Some((*pid).try_into().unwrap()),
                        prio: Some(*prio),
                        target_cpu: Some((*cpu).try_into().unwrap()),
                        ..SchedWakeupFtraceEvent::default()
                    },
                )),
                ..FtraceEvent::default()
            }
        });
        self.record_process_thread(*tgid, *pid, comm.to_string());
    }

    /// Adds events for on sched_wakeup_new.
    pub fn on_sched_wakeup_new(&mut self, _action: &Action) {
        // TODO
    }

    /// Adds events for on sched_waking.
    pub fn on_sched_waking(&mut self, action: &SchedWakingAction) {
        let SchedWakingAction {
            ts,
            cpu,
            pid,
            tgid,
            prio,
            comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::SchedWaking(
                    SchedWakingFtraceEvent {
                        comm: Some(comm.as_str().to_string()),
                        pid: Some((*pid).try_into().unwrap()),
                        prio: Some(*prio),
                        target_cpu: Some((*cpu).try_into().unwrap()),
                        ..SchedWakingFtraceEvent::default()
                    },
                )),
                ..FtraceEvent::default()
            }
        });
        self.record_process_thread(*tgid, *pid, comm.to_string());
    }

    /// Adds events for the softirq entry/exit events.
    pub fn on_softirq(&mut self, action: &SoftIRQAction) {
        self.ftrace_events.entry(action.cpu).or_default().extend({
            [
                // Entry event
                (FtraceEvent {
                    timestamp: Some(action.entry_ts),
                    pid: Some(action.pid),
                    event: Some(perfetto_scx::ftrace_event::Event::SoftirqEntry(
                        SoftirqEntryFtraceEvent {
                            vec: Some(action.softirq_nr as u32),
                        },
                    )),
                    ..FtraceEvent::default()
                }),
                // Exit event
                (FtraceEvent {
                    timestamp: Some(action.exit_ts),
                    pid: Some(action.pid),
                    event: Some(perfetto_scx::ftrace_event::Event::SoftirqExit(
                        SoftirqExitFtraceEvent {
                            vec: Some(action.softirq_nr as u32),
                        },
                    )),
                    ..FtraceEvent::default()
                }),
            ]
        });
    }

    /// Adds events for the IPI entry/exit events.
    pub fn on_ipi(&mut self, action: &IPIAction) {
        let IPIAction {
            ts,
            cpu,
            target_cpu,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::IpiRaise(
                    IpiRaiseFtraceEvent {
                        reason: Some("IPI raise".to_string()),
                        target_cpus: Some(*target_cpu),
                    },
                )),
                ..FtraceEvent::default()
            }
        });
    }

    pub fn on_gpu_mem(&mut self, action: &GpuMemAction) {
        let GpuMemAction {
            ts,
            size,
            cpu,
            gpu,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::GpuMemTotal(
                    GpuMemTotalFtraceEvent {
                        gpu_id: Some(*gpu),
                        pid: Some(*pid),
                        size: Some(*size),
                    },
                )),
                ..FtraceEvent::default()
            }
        });
    }

    pub fn on_cpu_hp_enter(&mut self, action: &CpuhpEnterAction) {
        let CpuhpEnterAction {
            ts,
            cpu,
            target,
            state,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::CpuhpEnter(
                    CpuhpEnterFtraceEvent {
                        cpu: Some(*cpu),
                        target: Some(*target),
                        idx: Some(*state),
                        ..CpuhpEnterFtraceEvent::default()
                    },
                )),
                ..FtraceEvent::default()
            }
        });
    }

    pub fn on_cpu_hp_exit(&mut self, action: &CpuhpExitAction) {
        let CpuhpExitAction {
            ts,
            cpu,
            state,
            idx,
            ret,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*pid),
                event: Some(perfetto_scx::ftrace_event::Event::CpuhpExit(
                    CpuhpExitFtraceEvent {
                        cpu: Some(*cpu),
                        state: Some(*state),
                        idx: Some(*idx),
                        ret: Some(*ret),
                    },
                )),
                ..FtraceEvent::default()
            }
        });
    }
    /// Adds events for the sched_switch event.
    pub fn on_sched_switch(&mut self, action: &SchedSwitchAction) {
        let SchedSwitchAction {
            ts,
            cpu,
            next_dsq_id,
            next_dsq_nr_queued,
            next_dsq_lat_us,
            next_pid,
            next_tgid,
            next_prio,
            next_comm,
            prev_pid,
            prev_tgid,
            prev_prio,
            prev_comm,
            prev_state,
            ..
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            FtraceEvent {
                timestamp: Some(*ts),
                pid: Some(*prev_pid),
                // XXX: On the BPF side the prev/next pid gets set to an invalid pid (0) if the
                // prev/next task is invalid.
                event: Some(perfetto_scx::ftrace_event::Event::SchedSwitch(
                    SchedSwitchFtraceEvent {
                        next_pid: (*next_pid > 0).then_some((*next_pid).try_into().unwrap()),
                        next_prio: (*next_pid > 0).then_some(*next_prio),
                        next_comm: (*next_pid > 0).then(|| next_comm.as_str().to_string()),
                        prev_pid: (*prev_pid > 0).then_some((*prev_pid).try_into().unwrap()),
                        prev_prio: (*prev_pid > 0).then_some(*prev_prio),
                        prev_comm: (*prev_pid > 0).then(|| prev_comm.as_str().to_string()),
                        prev_state: (*prev_pid > 0).then(|| (*prev_state).try_into().unwrap()),
                    },
                )),
                ..FtraceEvent::default()
            }
        });

        if *next_pid > 0 {
            self.record_process_thread(*next_tgid, *next_pid, next_comm.to_string());
        }
        if *prev_pid > 0 {
            self.record_process_thread(*prev_tgid, *prev_pid, prev_comm.to_string());
        }

        // Skip handling DSQ data if the sched_switch event didn't have
        // any DSQ data.
        if *next_dsq_id == scx_enums.SCX_DSQ_INVALID {
            return;
        }

        let next_dsq_uuid = self
            .dsq_uuids
            .entry(*next_dsq_id)
            .or_insert_with(|| self.rng.next_u64());
        self.dsq_lat_events.entry(*next_dsq_id).or_default().push({
            TrackEvent {
                r#type: Some(perfetto_scx::track_event::Type::Counter as i32),
                track_uuid: Some(*next_dsq_uuid),
                counter_value_field: Some(
                    perfetto_scx::track_event::CounterValueField::CounterValue(
                        (*next_dsq_lat_us).try_into().unwrap(),
                    ),
                ),
                timestamp: Some(perfetto_scx::track_event::Timestamp::TimestampAbsoluteUs(
                    (*ts) as i64 / 1000,
                )),
                ..TrackEvent::default()
            }
        });
        self.dsq_nr_queued_events
            .entry(*next_dsq_id)
            .or_default()
            .push({
                TrackEvent {
                    r#type: Some(perfetto_scx::track_event::Type::Counter as i32),
                    track_uuid: Some(*next_dsq_uuid),
                    // Each track needs a separate unique UUID, so we'll add one to the dsq for
                    // the nr_queued events.
                    counter_value_field: Some(
                        perfetto_scx::track_event::CounterValueField::CounterValue(
                            *next_dsq_nr_queued as i64,
                        ),
                    ),
                    timestamp: Some(perfetto_scx::track_event::Timestamp::TimestampAbsoluteUs(
                        (*ts) as i64 / 1000,
                    )),
                    ..TrackEvent::default()
                }
            });
    }
}

impl ActionHandler for PerfettoTraceManager {
    fn on_action(&mut self, action: &Action) -> Result<()> {
        match action {
            Action::SchedSwitch(a) => {
                self.on_sched_switch(a);
            }
            Action::SchedWakeup(a) => {
                self.on_sched_wakeup(a);
            }
            Action::SchedWaking(a) => {
                self.on_sched_waking(a);
            }
            Action::SoftIRQ(a) => {
                self.on_softirq(a);
            }
            Action::IPI(a) => {
                self.on_ipi(a);
            }
            Action::Exec(a) => {
                self.on_exec(a);
            }
            Action::Fork(a) => {
                self.on_fork(a);
            }
            Action::GpuMem(a) => {
                self.on_gpu_mem(a);
            }
            Action::Exit(a) => {
                self.on_exit(a);
            }
            Action::CpuhpEnter(a) => {
                self.on_cpu_hp_enter(a);
            }
            Action::CpuhpExit(a) => {
                self.on_cpu_hp_exit(a);
            }
            _ => {}
        }

        Ok(())
    }
}
