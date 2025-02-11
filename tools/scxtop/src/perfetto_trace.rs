// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use protobuf::Message;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use scx_utils::scx_enums;

use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Action, SchedSwitchAction, SchedWakeupAction, SchedWakingAction};

use crate::protos_gen::perfetto_scx::counter_descriptor::Unit::UNIT_COUNT;
use crate::protos_gen::perfetto_scx::trace_packet::Data::TrackDescriptor as DataTrackDescriptor;
use crate::protos_gen::perfetto_scx::track_event::Type as TrackEventType;
use crate::protos_gen::perfetto_scx::{
    CounterDescriptor, FtraceEvent, FtraceEventBundle, SchedSwitchFtraceEvent,
    SchedWakeupFtraceEvent, SchedWakingFtraceEvent, Trace, TracePacket, TrackDescriptor,
    TrackEvent,
};

/// Handler for perfetto traces. For details on data flow in perfetto see:
/// https://perfetto.dev/docs/concepts/buffers and
/// https://perfetto.dev/docs/reference/trace-packet-proto
pub struct PerfettoTraceManager<'a> {
    // proto fields
    trace: Trace,

    trace_id: u32,
    trusted_pid: i32,
    rng: StdRng,
    output_file_prefix: &'a str,

    // per cpu ftrace events
    ftrace_events: BTreeMap<u32, Vec<FtraceEvent>>,
    dsq_lat_events: BTreeMap<u64, Vec<TrackEvent>>,
    dsq_lat_trusted_packet_seq_uuid: u32,
    dsq_nr_queued_events: BTreeMap<u64, Vec<TrackEvent>>,
    dsq_nr_queued_trusted_packet_seq_uuid: u32,
    dsq_uuids: BTreeMap<u64, u64>,
}

impl<'a> PerfettoTraceManager<'a> {
    /// Returns a PerfettoTraceManager that is ready to start tracing.
    pub fn new(output_file_prefix: &'a str, seed: Option<u64>) -> Self {
        let trace_uuid = seed.unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        );
        let mut rng = StdRng::seed_from_u64(trace_uuid);
        let trace = Trace::new();
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
        }
    }

    /// Starts a new perfetto trace.
    pub fn start(&mut self) -> Result<()> {
        self.trace = Trace::new();
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
        for (dsq, dsq_uuid) in &self.dsq_uuids {
            let mut descs = vec![];

            // DSQ latency
            let mut desc = TrackDescriptor::new();
            desc.set_uuid(*dsq_uuid);
            desc.set_name(format!("DSQ {} latency ns", *dsq));
            desc.set_static_name(format!("DSQ {} latency ns", *dsq));

            let mut counter_desc = CounterDescriptor::new();
            counter_desc.set_unit_name(format!("DSQ {} latency ns", *dsq));
            counter_desc.set_unit(UNIT_COUNT);
            counter_desc.set_is_incremental(false);
            desc.counter = Some(counter_desc).into();
            descs.push(desc);

            // DSQ nr_queued
            let mut desc = TrackDescriptor::new();
            desc.set_uuid(*dsq_uuid + 1);
            desc.set_name(format!("DSQ {} nr_queued", *dsq));
            desc.set_static_name(format!("DSQ {} nr_queued", *dsq));

            let mut counter_desc = CounterDescriptor::new();
            counter_desc.set_unit_name(format!("DSQ {} nr_queued", *dsq));
            counter_desc.set_unit(UNIT_COUNT);
            counter_desc.set_is_incremental(false);
            desc.counter = Some(counter_desc).into();
            descs.push(desc);

            desc_map.insert(*dsq_uuid, descs);
        }

        desc_map
    }

    /// Stops the trace and writes to configured output file.
    pub fn stop(&mut self) -> Result<()> {
        // TracePacket is the root object of a Perfetto trace. A Perfetto trace is a linear
        // sequence of TracePacket(s). The tracing service guarantees that all TracePacket(s)
        // written by a given TraceWriter are seen in-order, without gaps or duplicates.
        // https://perfetto.dev/docs/reference/trace-packet-proto

        let trace_cpus: Vec<u32> = self.ftrace_events.keys().cloned().collect();
        let trace_dsqs: Vec<u64> = self.dsq_nr_queued_events.keys().cloned().collect();

        for trace_descs in self.track_descriptors().values() {
            for trace_desc in trace_descs {
                let mut packet = TracePacket::new();
                packet.data = Some(DataTrackDescriptor(trace_desc.clone()));
                self.trace.packet.push(packet);
            }
        }

        // dsq latency tracks
        for dsq in &trace_dsqs {
            self.dsq_lat_events.remove(&dsq).map(|events| {
                for dsq_lat_event in events {
                    let ts: u64 = dsq_lat_event.timestamp_absolute_us() as u64 / 1_000;
                    let mut packet = TracePacket::new();
                    packet.set_track_event(dsq_lat_event);
                    packet.set_trusted_packet_sequence_id(self.dsq_lat_trusted_packet_seq_uuid);
                    packet.set_timestamp(ts);
                    self.trace.packet.push(packet);
                }
            });
        }

        // dsq nr_queued tracks
        for dsq in &trace_dsqs {
            self.dsq_nr_queued_events.remove(&dsq).map(|events| {
                for dsq_lat_event in events {
                    let ts: u64 = dsq_lat_event.timestamp_absolute_us() as u64 / 1_000;
                    let mut packet = TracePacket::new();
                    packet.set_track_event(dsq_lat_event);
                    packet
                        .set_trusted_packet_sequence_id(self.dsq_nr_queued_trusted_packet_seq_uuid);
                    packet.set_timestamp(ts);
                    self.trace.packet.push(packet);
                }
            });
        }

        // ftrace events
        for cpu in &trace_cpus {
            let mut packet = TracePacket::new();
            let mut bundle = FtraceEventBundle::new();

            self.ftrace_events.remove(&cpu).map(|mut events| {
                // sort by timestamp just to make sure.
                events.sort_by_key(|event| event.timestamp());
                bundle.event = events;
            });
            bundle.set_cpu(*cpu);
            packet.set_ftrace_events(bundle);
            packet.trusted_pid = Some(self.trusted_pid);
            self.trace.packet.push(packet);
        }

        let out_bytes: Vec<u8> = self.trace.write_to_bytes()?;
        fs::write(self.trace_file(), out_bytes)?;

        self.clear();
        self.trace_id += 1;
        Ok(())
    }

    /// Adds events for on sched_wakeup.
    pub fn on_sched_wakeup(&mut self, action: &SchedWakeupAction) {
        let SchedWakeupAction {
            ts,
            cpu,
            pid,
            prio,
            comm,
        } = action;

        let _ = self
            .ftrace_events
            .entry(*cpu)
            .or_insert_with(Vec::new)
            .push({
                let mut ftrace_event = FtraceEvent::new();
                let mut wakeup_event = SchedWakeupFtraceEvent::new();
                let pid = *pid as u32;
                let cpu = *cpu as i32;

                wakeup_event.set_pid(pid.try_into().unwrap());
                wakeup_event.set_prio(*prio);
                wakeup_event.set_comm(comm.clone());
                wakeup_event.set_target_cpu(cpu);

                ftrace_event.set_timestamp(*ts);
                ftrace_event.set_sched_wakeup(wakeup_event);
                ftrace_event.set_pid(pid);

                ftrace_event
            });
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
            prio,
            comm,
        } = action;

        let _ = self
            .ftrace_events
            .entry(*cpu)
            .or_insert_with(Vec::new)
            .push({
                let mut ftrace_event = FtraceEvent::new();
                let mut waking_event = SchedWakingFtraceEvent::new();
                let pid = *pid as u32;
                let cpu = *cpu as i32;

                waking_event.set_pid(pid.try_into().unwrap());
                waking_event.set_prio(*prio);
                waking_event.set_comm(comm.clone());
                waking_event.set_target_cpu(cpu);

                ftrace_event.set_timestamp(*ts);
                ftrace_event.set_sched_waking(waking_event);
                ftrace_event.set_pid(pid);

                ftrace_event
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
            next_prio,
            next_comm,
            prev_pid,
            prev_prio,
            prev_comm,
            prev_state,
            ..
        } = action;

        let _ = self
            .ftrace_events
            .entry(*cpu)
            .or_insert_with(Vec::new)
            .push({
                let mut ftrace_event = FtraceEvent::new();
                let mut switch_event = SchedSwitchFtraceEvent::new();
                let prev_pid: i32 = *prev_pid as i32;
                let next_pid: i32 = *next_pid as i32;

                switch_event.set_next_pid(next_pid);
                switch_event.set_next_comm(next_comm.clone());
                switch_event.set_next_prio(*next_prio);
                switch_event.set_prev_pid(prev_pid);
                switch_event.set_prev_prio(*prev_prio);
                switch_event.set_prev_comm(prev_comm.clone());
                switch_event.set_prev_state(*prev_state as i64);
                ftrace_event.set_timestamp(*ts);
                ftrace_event.set_sched_switch(switch_event);
                ftrace_event.set_pid(prev_pid.try_into().unwrap());

                ftrace_event
            });

        // Skip handling DSQ data if the sched_switch event didn't have
        // any DSQ data.
        if *next_dsq_id == scx_enums.SCX_DSQ_INVALID {
            return;
        }

        let next_dsq_uuid = self
            .dsq_uuids
            .entry(*next_dsq_id)
            .or_insert_with(|| self.rng.next_u64());
        let _ = self
            .dsq_lat_events
            .entry(*next_dsq_id)
            .or_insert_with(Vec::new)
            .push({
                let mut event = TrackEvent::new();
                let ts: i64 = (*ts).try_into().unwrap();
                event.set_type(TrackEventType::TYPE_COUNTER);
                event.set_track_uuid(*next_dsq_uuid);
                event.set_counter_value((*next_dsq_lat_us).try_into().unwrap());
                event.set_timestamp_absolute_us(ts / 1000);

                event
            });
        let _ = self
            .dsq_nr_queued_events
            .entry(*next_dsq_id)
            .or_insert_with(Vec::new)
            .push({
                let mut event = TrackEvent::new();
                let ts: i64 = (*ts).try_into().unwrap();
                event.set_type(TrackEventType::TYPE_COUNTER);
                // Each track needs a separate unique UUID, so we'll add one to the dsq for
                // the nr_queued events.
                event.set_track_uuid(*next_dsq_uuid + 1);
                event.set_counter_value(*next_dsq_nr_queued as i64);
                event.set_timestamp_absolute_us(ts / 1000);

                event
            });
    }
}
