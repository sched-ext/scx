// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::Action;
use serde_json::{json, Value};

/// Convert scxtop Actions to MCP events
/// Returns None for internal actions that shouldn't be streamed as events
pub fn action_to_mcp_event(action: &Action) -> Option<Value> {
    match action {
        Action::SchedSwitch(a) => Some(json!({
            "type": "sched_switch",
            "ts": a.ts,
            "cpu": a.cpu,
            "prev_pid": a.prev_pid,
            "prev_tgid": a.prev_tgid,
            "prev_prio": a.prev_prio,
            "prev_comm": a.prev_comm.to_string(),
            "prev_layer_id": a.prev_layer_id,
            "prev_state": a.prev_state,
            "prev_dsq_id": a.prev_dsq_id,
            "prev_used_slice_ns": a.prev_used_slice_ns,
            "prev_slice_ns": a.prev_slice_ns,
            "next_pid": a.next_pid,
            "next_tgid": a.next_tgid,
            "next_prio": a.next_prio,
            "next_comm": a.next_comm.to_string(),
            "next_layer_id": a.next_layer_id,
            "next_dsq_id": a.next_dsq_id,
            "next_dsq_lat_us": a.next_dsq_lat_us,
            "next_dsq_nr_queued": a.next_dsq_nr_queued,
            "next_dsq_vtime": a.next_dsq_vtime,
            "next_slice_ns": a.next_slice_ns,
            "preempt": a.preempt,
        })),

        Action::SchedWakeup(a) => Some(json!({
            "type": "sched_wakeup",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "tgid": a.tgid,
            "prio": a.prio,
            "comm": a.comm.to_string(),
            "waker_pid": a.waker_pid,
            "waker_comm": a.waker_comm.to_string(),
        })),

        Action::SchedWaking(a) => Some(json!({
            "type": "sched_waking",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "tgid": a.tgid,
            "prio": a.prio,
            "comm": a.comm.to_string(),
            "waker_pid": a.waker_pid,
            "waker_comm": a.waker_comm.to_string(),
        })),

        Action::SchedWakeupNew(a) => Some(json!({
            "type": "sched_wakeup_new",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "tgid": a.tgid,
            "prio": a.prio,
            "comm": a.comm.to_string(),
            "waker_pid": a.waker_pid,
            "waker_comm": a.waker_comm.to_string(),
        })),

        Action::SchedMigrateTask(a) => Some(json!({
            "type": "sched_migrate_task",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "prio": a.prio,
            "comm": a.comm.to_string(),
            "dest_cpu": a.dest_cpu,
        })),

        Action::Fork(a) => Some(json!({
            "type": "fork",
            "ts": a.ts,
            "cpu": a.cpu,
            "parent_pid": a.parent_pid,
            "parent_tgid": a.parent_tgid,
            "parent_comm": a.parent_comm.to_string(),
            "parent_layer_id": a.parent_layer_id,
            "child_pid": a.child_pid,
            "child_tgid": a.child_tgid,
            "child_comm": a.child_comm.to_string(),
            "child_layer_id": a.child_layer_id,
        })),

        Action::Exec(a) => Some(json!({
            "type": "exec",
            "ts": a.ts,
            "cpu": a.cpu,
            "old_pid": a.old_pid,
            "pid": a.pid,
            "layer_id": a.layer_id,
        })),

        Action::Exit(a) => Some(json!({
            "type": "exit",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "tgid": a.tgid,
            "comm": a.comm.to_string(),
        })),

        Action::Wait(a) => Some(json!({
            "type": "wait",
            "ts": a.ts,
            "cpu": a.cpu,
            "comm": a.comm.to_string(),
            "pid": a.pid,
            "prio": a.prio,
        })),

        Action::SoftIRQ(a) => Some(json!({
            "type": "softirq",
            "cpu": a.cpu,
            "pid": a.pid,
            "entry_ts": a.entry_ts,
            "exit_ts": a.exit_ts,
        })),

        Action::IPI(a) => Some(json!({
            "type": "ipi",
            "ts": a.ts,
            "cpu": a.cpu,
            "target_cpu": a.target_cpu,
            "pid": a.pid,
        })),

        Action::GpuMem(a) => Some(json!({
            "type": "gpu_mem",
            "ts": a.ts,
            "size": a.size,
            "cpu": a.cpu,
            "gpu": a.gpu,
            "pid": a.pid,
        })),

        Action::CpuhpEnter(a) => Some(json!({
            "type": "cpuhp_enter",
            "ts": a.ts,
            "cpu": a.cpu,
            "target": a.target,
            "state": a.state,
            "pid": a.pid,
        })),

        Action::CpuhpExit(a) => Some(json!({
            "type": "cpuhp_exit",
            "ts": a.ts,
            "cpu": a.cpu,
            "state": a.state,
            "idx": a.idx,
            "ret": a.ret,
        })),

        Action::HwPressure(a) => Some(json!({
            "type": "hw_pressure",
            "hw_pressure": a.hw_pressure,
            "cpu": a.cpu,
        })),

        Action::Kprobe(a) => Some(json!({
            "type": "kprobe",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "instruction_pointer": a.instruction_pointer,
        })),

        Action::PerfSample(a) => Some(json!({
            "type": "perf_sample",
            "ts": a.ts,
            "cpu": a.cpu,
            "pid": a.pid,
            "instruction_pointer": a.instruction_pointer,
            "cpu_id": a.cpu_id,
            "is_kernel": a.is_kernel,
            "kernel_stack": a.kernel_stack.clone(),
            "user_stack": a.user_stack.clone(),
            "layer_id": a.layer_id,
        })),

        Action::SchedHang(a) => Some(json!({
            "type": "sched_hang",
            "ts": a.ts,
            "cpu": a.cpu,
            "comm": a.comm.to_string(),
            "pid": a.pid,
        })),

        Action::SchedCpuPerfSet(a) => Some(json!({
            "type": "sched_cpu_perf_set",
            "cpu": a.cpu,
            "perf": a.perf,
        })),

        Action::MangoApp(a) => Some(json!({
            "type": "mango_app",
            "pid": a.pid,
            "vis_frametime": a.vis_frametime,
            "app_frametime": a.app_frametime,
            "fsr_upscale": a.fsr_upscale,
            "fsr_sharpness": a.fsr_sharpness,
            "latency_ns": a.latency_ns,
            "output_width": a.output_width,
            "output_height": a.output_height,
            "display_refresh": a.display_refresh,
        })),

        Action::TraceStarted(a) => Some(json!({
            "type": "trace_started",
            "start_immediately": a.start_immediately,
            "ts": a.ts,
            "stop_scheduled": a.stop_scheduled,
        })),

        Action::TraceStopped(a) => Some(json!({
            "type": "trace_stopped",
            "ts": a.ts,
        })),

        Action::SystemStat(a) => Some(json!({
            "type": "system_stat",
            "ts": a.ts,
            // Note: cpu_data and mem_info are complex structs that can't be directly serialized
            // These would need separate serialization logic if needed
        })),

        Action::SchedStats(s) => Some(json!({
            "type": "sched_stats",
            "data": s,
        })),

        // Ignore internal actions that aren't actual events
        Action::Tick
        | Action::Quit
        | Action::None
        | Action::UpdateColVisibility(_)
        | Action::Backspace
        | Action::ChangeTheme
        | Action::ClearEvent
        | Action::DecBpfSampleRate
        | Action::DecTickRate
        | Action::Down
        | Action::Enter
        | Action::Event
        | Action::Esc
        | Action::Filter
        | Action::Help
        | Action::IncBpfSampleRate
        | Action::IncTickRate
        | Action::InputEntry(_)
        | Action::NextEvent
        | Action::NextViewState
        | Action::PageDown
        | Action::PageUp
        | Action::PerfSampleRateIncrease
        | Action::PerfSampleRateDecrease
        | Action::PrevEvent
        | Action::RequestTrace
        | Action::ReloadStatsClient
        | Action::SaveConfig
        | Action::SchedReg
        | Action::SchedUnreg
        | Action::SetState(_)
        | Action::TickRateChange(_)
        | Action::ToggleBpfPerfSampling
        | Action::ToggleCpuFreq
        | Action::ToggleLocalization
        | Action::ToggleHwPressure
        | Action::ToggleUncoreFreq
        | Action::Up => None,
    }
}
