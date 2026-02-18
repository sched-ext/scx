//! Chrome Trace Event Format (JSON) export for Perfetto.
//!
//! Writes the simulation trace as a JSON file loadable in
//! [ui.perfetto.dev](https://ui.perfetto.dev). Each CPU is a Perfetto
//! process (pid = cpu index) with a single "running" thread showing task
//! execution as colored duration blocks.

use std::io::Write;

use serde_json::json;

use crate::trace::{Trace, TraceKind};
use crate::types::DsqId;

/// Write the trace as Chrome Trace Event Format JSON.
///
/// Stream-writes events one at a time (no intermediate `Vec<Value>`) to
/// avoid unnecessary allocation per coding conventions.
pub(crate) fn write_json(trace: &Trace, writer: &mut impl Write) -> std::io::Result<()> {
    writer.write_all(b"{\"traceEvents\":[")?;

    let mut need_comma = false;

    // Emit process metadata: one "process" per CPU
    for cpu in 0..trace.nr_cpus {
        write_comma(writer, &mut need_comma)?;
        serde_json::to_writer(
            &mut *writer,
            &json!({
                "ph": "M",
                "pid": cpu,
                "tid": 0,
                "name": "process_name",
                "args": { "name": format!("CPU {cpu}") }
            }),
        )?;

        write_comma(writer, &mut need_comma)?;
        serde_json::to_writer(
            &mut *writer,
            &json!({
                "ph": "M",
                "pid": cpu,
                "tid": 0,
                "name": "thread_name",
                "args": { "name": "running" }
            }),
        )?;
    }

    // Emit trace events
    for event in trace.events() {
        let cpu = event.cpu.0;
        let ts = event.time_ns / 1000; // ns → μs

        write_comma(writer, &mut need_comma)?;
        let value = match &event.kind {
            TraceKind::TaskScheduled { pid } => {
                let name = trace.task_name(*pid);
                json!({
                    "ph": "B",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": name,
                    "cat": "sched",
                    "args": { "pid": pid.0 }
                })
            }

            TraceKind::TaskPreempted { pid } => {
                json!({
                    "ph": "E",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "cat": "sched",
                    "args": { "reason": "preempted", "pid": pid.0 }
                })
            }

            TraceKind::TaskYielded { pid } => {
                json!({
                    "ph": "E",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "cat": "sched",
                    "args": { "reason": "yielded", "pid": pid.0 }
                })
            }

            TraceKind::TaskSlept { pid } => {
                json!({
                    "ph": "E",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "cat": "sched",
                    "args": { "reason": "slept", "pid": pid.0 }
                })
            }

            TraceKind::TaskCompleted { pid } => {
                json!({
                    "ph": "E",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "cat": "sched",
                    "args": { "reason": "completed", "pid": pid.0 }
                })
            }

            TraceKind::SimulationEnd { pid } => {
                json!({
                    "ph": "E",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "cat": "sched",
                    "args": { "reason": "sim_end", "pid": pid.0 }
                })
            }

            TraceKind::CpuIdle => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "idle",
                    "s": "t"
                })
            }

            TraceKind::TaskWoke { pid } => {
                let name = trace.task_name(*pid);
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "wake",
                    "s": "t",
                    "args": { "task": name, "pid": pid.0 }
                })
            }

            // Ops events
            TraceKind::PutPrevTask {
                pid,
                still_runnable,
            } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "put_prev_task",
                    "cat": "ops",
                    "s": "t",
                    "args": { "pid": pid.0, "still_runnable": still_runnable }
                })
            }

            TraceKind::SelectTaskRq {
                pid,
                prev_cpu,
                selected_cpu,
            } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "select_task_rq",
                    "cat": "ops",
                    "s": "t",
                    "args": {
                        "pid": pid.0,
                        "prev_cpu": prev_cpu.0,
                        "selected_cpu": selected_cpu.0
                    }
                })
            }

            TraceKind::EnqueueTask { pid, enq_flags } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "enqueue",
                    "cat": "ops",
                    "s": "t",
                    "args": { "pid": pid.0, "enq_flags": format!("{enq_flags:#x}") }
                })
            }

            TraceKind::Balance { prev_pid } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "balance",
                    "cat": "ops",
                    "s": "t",
                    "args": { "prev_pid": prev_pid.map(|p| p.0) }
                })
            }

            TraceKind::PickTask { pid } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "pick_task",
                    "cat": "ops",
                    "s": "t",
                    "args": { "pid": pid.0 }
                })
            }

            TraceKind::SetNextTask { pid } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "set_next_task",
                    "cat": "ops",
                    "s": "t",
                    "args": { "pid": pid.0 }
                })
            }

            // Kfunc events
            TraceKind::DsqInsert { pid, dsq_id, slice } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "dsq_insert",
                    "cat": "kfunc",
                    "s": "t",
                    "args": {
                        "pid": pid.0,
                        "dsq_id": format_dsq_id(*dsq_id),
                        "slice_ns": slice
                    }
                })
            }

            TraceKind::DsqInsertVtime {
                pid,
                dsq_id,
                slice,
                vtime,
            } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "dsq_insert_vtime",
                    "cat": "kfunc",
                    "s": "t",
                    "args": {
                        "pid": pid.0,
                        "dsq_id": format_dsq_id(*dsq_id),
                        "slice_ns": slice,
                        "vtime": vtime.0
                    }
                })
            }

            TraceKind::DsqMoveToLocal { dsq_id, success } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "dsq_move_to_local",
                    "cat": "kfunc",
                    "s": "t",
                    "args": {
                        "dsq_id": format_dsq_id(*dsq_id),
                        "success": success
                    }
                })
            }

            TraceKind::KickCpu { target_cpu } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "kick_cpu",
                    "cat": "kfunc",
                    "s": "t",
                    "args": { "target_cpu": target_cpu.0 }
                })
            }

            TraceKind::Tick { pid } => {
                json!({
                    "ph": "i",
                    "pid": cpu,
                    "tid": 0,
                    "ts": ts,
                    "name": "tick",
                    "cat": "kfunc",
                    "s": "t",
                    "args": { "pid": pid.0 }
                })
            }
        };
        serde_json::to_writer(&mut *writer, &value)?;
    }

    writer.write_all(b"]}")?;
    Ok(())
}

/// Write a comma separator if this is not the first entry.
fn write_comma(writer: &mut impl Write, need_comma: &mut bool) -> std::io::Result<()> {
    if *need_comma {
        writer.write_all(b",")?;
    }
    *need_comma = true;
    Ok(())
}

/// Format a DSQ ID for display in trace args.
fn format_dsq_id(dsq_id: DsqId) -> String {
    if dsq_id == DsqId::GLOBAL {
        "GLOBAL".to_string()
    } else if dsq_id.is_local() {
        "LOCAL".to_string()
    } else if dsq_id.is_local_on() {
        format!("LOCAL_ON({})", dsq_id.local_on_cpu().0)
    } else {
        format!("{:#x}", dsq_id.0)
    }
}
