#!/usr/bin/env python3
"""Rebuild the dated source-location catalog; does not attach or change policy."""
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[7]
OUT = Path(__file__).resolve().parent
K = ROOT / "target/cake_dsq_index_20261002T201929Z/linux"
R = ROOT / "target/cake_signal_research_20261002T213213Z/sources"
A = ROOT / "target/cake_signal_atlas_20261002T220459Z"
SOURCES = {
    "cake": ROOT / "scheds/rust/scx_cake/src/bpf/cake.bpf.c",
    "loader": ROOT / "scheds/rust/scx_cake/src/main.rs",
    "ext": K / "kernel/sched/ext/ext.c",
    "ops": K / "kernel/sched/ext/internal.h",
    "core": K / "kernel/sched/core.c",
    "rq": K / "kernel/sched/sched.h",
    "irqtime": K / "kernel/sched/cputime.c",
    "irq": K / "kernel/irq/handle.c",
    "softirq": K / "kernel/softirq.c",
    "apic": K / "arch/x86/kernel/apic/apic.c",
    "schedclock": K / "kernel/sched/clock.c",
    "bpfclock": K / "kernel/bpf/helpers.c",
    "traceclock": K / "kernel/trace/trace_clock.c",
    "perf": K / "arch/x86/kernel/cpu/aperfmperf.c",
    "fence": K / "drivers/dma-buf/dma-fence.c",
    "syncfile": K / "drivers/dma-buf/sync_file.c",
    "syncobj": K / "drivers/gpu/drm/drm_syncobj.c",
    "futex": K / "kernel/futex/waitwake.c",
    "ntsync": K / "drivers/misc/ntsync.c",
    "epoll": K / "fs/eventpoll.c",
    "input": K / "drivers/input/input.c",
    "evdev": K / "drivers/input/evdev.c",
    "hid": K / "drivers/hid/usbhid/hid-core.c",
    "nvidia": R / "nvidia-drm-fence.c",
    "nvcrtc": R / "nvidia-drm-crtc.c",
    "nvkapi": R / "nvidia-src_nvidia-modeset_kapi_src_nvkms-kapi-sync.c",
    "kwininput": R / "kwin-src_backends_libinput_connection.cpp",
    "kwinbackend": R / "kwin-src_backends_libinput_libinputbackend.cpp",
    "kwinevents": R / "kwin-src_backends_libinput_events.cpp",
    "kwinrender": R / "kwin-renderloop.cpp",
    "kwintransaction": A / "sources/kwin-src_wayland_transaction.cpp",
    "kwinsync": A / "sources/kwin-src_core_syncobjtimeline.cpp",
    "presentation": Path("/usr/share/wayland-protocols/stable/presentation-time/presentation-time.xml"),
    "protocolsync": Path("/usr/share/wayland-protocols/staging/linux-drm-syncobj/linux-drm-syncobj-v1.xml"),
    "inputstamp": Path("/usr/share/wayland-protocols/unstable/input-timestamps/input-timestamps-unstable-v1.xml"),
}

rows = []


def add(id, name, refs, update, clock, accuracy, access, use, invalidate):
    locations = []
    for key, needle in refs:
        p = SOURCES[key]
        matches = [i for i, line in enumerate(p.read_text().splitlines(), 1) if needle in line]
        if not matches:
            raise ValueError((key, needle))
        locations.append({"source": key, "symbol": needle, "path": str(p), "lines": matches})
    rows.append(dict(id=id, signal=name, locations=locations, update_rule=update,
                     clock_or_units=clock, accuracy_and_staleness=accuracy,
                     access_and_cost=access, cake_use=use, invalidation=invalidate,
                     hardware_update_latency_ns=None, hotpath_read_cost_ns=None))


add("irq_depth", "Cake live handler depth", [("cake", "cake_irq_edge"), ("irq", "trace_irq_handler_entry"), ("softirq", "trace_softirq_entry")],
    "Increment/decrement at attached generic hardirq-action and softirq handler boundaries; event driven.", "Counter; observer timestamps only if added.",
    "Own CPU writes; remote load can race. Generic IRQ actions do not cover all APIC/NMI/firmware work. Missing attachment is not quiet.",
    "Already in Cake: BPF entry/exit execution plus one padded-slot read; cache coherence cost unmeasured.",
    "Refine candidate choice; compare broader kernel snapshot against current writer cost.", "Attach/detach, nesting, CPU lifecycle, coverage change.")
add("irq_vectors", "Architecture timer/IPI interference", [("apic", "trace_local_timer_entry")],
    "At architecture vector entry/exit; no fixed publication period.", "Trace clock or BPF observation clock.",
    "Earlier boundary than a generic device action, different coverage. Avoid double-counting nested intervals.",
    "Trace events available; extra observers cost per vector. Production summary would need kernel ownership.",
    "Identify missing interference; fold into a bounded candidate hint only if beneficial.", "Architecture/config, nested IRQ, detach/hotplug.")
add("irq_total", "Accounted IRQ duration", [("irqtime", "void irqtime_account_irq("), ("rq", "static inline u64 irq_time_read(")],
    "Accumulates at IRQ accounting boundaries, including entry/exit; running interval may not yet be charged.", "Duration ns derived from sched_clock_cpu; not a MONOTONIC epoch timestamp.",
    "Fine units; excludes ksoftirqd task execution. Requires enabled accounting and coherent reads; no hard maximum publication lag.",
    "Existing internal counter; proposed bounded kfunc, no text parse. No measured reader/writer ns cost.",
    "Short-window CPU interference estimate without adding a new time source to every event.", "Availability, CPU online generation, baseline for counter differences.")
add("irq_proc", "Cake chronic IRQ mask", [("loader", "fn read_irq_ticks("), ("loader", "struct SinkMonitor")],
    "One-second loop; sampling adapts to 1–4 seconds; mark/unmark requires 2/3 confirming windows.", "USER_HZ ticks; host CLK_TCK=100, 10 ms units.",
    "Slow aggregate intentionally hysteretic; interval is not a guaranteed freshness bound if loader is delayed.",
    "Text parsing/cold userspace update; BPF reads cached mask.",
    "Chronic interference only; keep distinct from immediate handler depth.", "CPU topology, unknown samples, process stalls, attachment generation.")
add("cpu_current", "Current task on a CPU", [("ext", "struct task_struct *scx_bpf_cpu_curr("), ("cake", "struct task_struct *cake_cpu_curr(")],
    "Core changes rq->curr on scheduling transition; query reads current pointer.", "Identity/state, not a timestamp.",
    "RCU protects lifetime, not a stable occupant or a reserved CPU. IRQ can execute while the interrupted task remains curr.",
    "Existing kfunc/compat wrapper; candidate-local remote read. No need to poll through userspace.",
    "Observe occupant/RT interference while keeping authoritative idle claims.", "Context switch, migration, task exit, CPU hotplug.")
add("rq_clock", "Cake cached scheduler time", [("ext", "__bpf_kfunc u64 scx_bpf_now("), ("rq", "static inline void scx_rq_clock_update("), ("cake", "u64 cake_now_rq(")],
    "Cached after rq clock update until rq unpin/unlock invalidates; otherwise fresh sched_clock_cpu read.", "ns; scheduler clock family, same-CPU ordering only.",
    "Repeated calls can return identical values; cross-CPU deltas may be negative. Not interchangeable with MONOTONIC.",
    "Existing fast kfunc. Cache savings trade timestamp freshness; no cost measured here.",
    "Existing internal accounting; exclude from external GPU/input timestamp joins.", "CPU provenance, cache validity, clocksource/suspend events.")
add("mono_clock", "Cake cross-component observation clock", [("cake", "u64 cake_now("), ("bpfclock", "BPF_CALL_0(bpf_ktime_get_ns)")],
    "Read on call; kernel timekeeping supplies current clock conversion.", "CLOCK_MONOTONIC ns; implementation uses mono_fast accessor.",
    "Host reports 1 ns resolution, not accuracy. Frequency discipline applies; suspend excluded; fast accessor has exceptional timekeeping caveats.",
    "Existing BPF helper; reuse event timestamp rather than repeat reads. No measured BPF read latency here.",
    "Common domain for readiness/publication/consumption timestamps.", "Boot/session generation; reject impossible negative/outlier deltas rather than silently counting zero.")
add("jiffies_age", "Cake approximate task age", [("cake", "u64 cake_task_age("), ("loader", "fn coarse_tick_ns(")],
    "jiffies-based approximation with offset measured at Cake attach; host coarse resolution is 1 ms.", "jiffies * nominal tick + one-time MONOTONIC offset.",
    "Lifetime approximation only; tick quantization, NO_HZ batching and calibration mean it is not an exact cross-component clock.",
    "Existing cheap cached conversion; fallback precise read when tick rejected.",
    "Keep for its documented age use; never repurpose for device/deadline measurements.", "Attach, suspend/clock changes; long-duration error has not been characterized.")
add("task_runtime", "Task CPU service consumed", [("core", "static void update_rq_clock_task("), ("cake", "p->se.sum_exec_runtime")],
    "Updated by scheduler execution accounting; current running segment may be pending until accounting runs.", "Accumulated service ns, not wall-clock epoch.",
    "IRQ/steal subtraction belongs to kernel accounting. Runtime does not reveal frame completion or wall-clock waiting.",
    "Existing task field read; lifetime and concurrent updates matter.",
    "Keep service budgets separate from readiness age and wall time.", "Task lifetime, last accounting update; never subtract IRQ twice.")
add("wake", "Task accepted wake/placement", [("core", "trace_sched_waking(p)"), ("core", "trace_sched_wakeup(p)"), ("ops", "s32 (*select_cpu)")],
    "Event-driven during successful wake path; waking precedes normal CPU choice, wakeup occurs later.", "No intrinsic timestamp in state; use the chosen observer clock.",
    "Reason absent; some paths skip select_cpu and already-runnable events need no wake. Current PID in IRQ is not cause ownership.",
    "Existing callback receives actual task; new typed metadata can ride existing wake with no daemon round trip.",
    "Read cause before first placement, and handle enqueue/next service where selection is skipped.", "Task/dependency generation, duplicate/failed wakes, concurrent causes.")
add("run_stop", "Task selected, running, preempted or blocked", [("ext", "static void set_next_task_scx("), ("core", "trace_sched_switch("), ("ops", "void (*stopping)")],
    "At scheduling transitions; Cake receives its class callbacks. All-class sched_switch covers RT as well.", "Timestamp at callback/switch boundary; execution-accounting clock is distinct.",
    "running/sched_switch precede actual application resume. stopping can mean preempted, not blocked or done.",
    "Reuse Cake notifications; trace observer only for other classes/research.",
    "Maintain scheduling state without an extra cross-process state query.", "Migration, class change, CPU hotplug, task exit; record transition generation.")
add("cpuperf", "CPU performance estimate", [("ext", "__bpf_kfunc u32 scx_bpf_cpuperf_cur("), ("perf", "void arch_scale_freq_tick(")],
    "Kfunc reads arch_scale_freq_capacity; x86 reference updates scale from APERF/MPERF intervals on tick path.", "Normalized capacity, not instantaneous GHz or a timestamp.",
    "Host HZ=1000 is nominal active tick cadence; NO_HZ/idle/disabled invariance can leave older/default scale. No general 1 ms freshness guarantee.",
    "Existing kfunc; recomputing ratios or polling cpufreq in BPF would duplicate work.",
    "Optional candidate service-capacity hint, only if it improves choices.", "Architecture path, active sampling, CPU topology/power state.")
add("clockevent", "Next programmed CPU timer", [("cake", "bool cake_cpu_tick_soon(")],
    "clock_event_device next_event changes when timer programming changes.", "ktime/MONOTONIC deadline.",
    "Advisory remote snapshot; not all future interrupts, not necessarily a periodic scheduler tick, and hardware may fire late.",
    "Cake already uses weak tick_cpu_device symbol and one search clock read.",
    "Predict a nearby programmed event without broad timer polling.", "Reprogramming, tick stop, device replacement, suspend/hotplug.")
add("gpu_semaphore", "NVIDIA timeline progress", [("nvidia", "__nv_drm_get_semsurf_ctx_seqno("), ("nvkapi", "static void SemaphoreSurfaceKapiCallback(")],
    "GPU semaphore advances with submitted work; RM/KAPI notification invokes registered callback; DRM then reads sequence.", "Timeline sequence, not calibrated CPU timestamp.",
    "Source code does not bound GPU completion-to-RM callback latency. Context/timeline scope matters; one device-wide bit loses attribution.",
    "Driver-owned mapping and callbacks; not an arbitrary BPF-loadable GPU pointer.",
    "Publish known dependency progress on existing callback; avoid MMIO/RM polling in Cake.", "Sequence/context lifetime, 32/64-bit expansion, reset/error, submission generation.")
add("fence_signal", "Generic fence signaled and timestamp", [("fence", "void dma_fence_signal_timestamp_locked("), ("fence", "void dma_fence_signal(struct")],
    "One successful signal per fence; flag, tracepoint, timestamp publication, then callbacks in source order.", "Supplied timestamp must be CLOCK_MONOTONIC; ordinary signal samples ktime_get.",
    "Signaled tracepoint precedes timestamp-union publication. Ordinary NVIDIA signal timestamp is software delivery time, not exact hardware finish.",
    "Existing trace/function argument; add typed metadata only under correct lifetime/atomic-context rules.",
    "Carry completion/error cause to actual waiter before CPU placement.", "Fence context+seqno+generation; errors, chains/arrays, timeout/reuse.")
add("fence_cpu_wait", "Direct fence CPU waiter", [("fence", "dma_fence_default_wait_cb("), ("syncobj", "static void syncobj_wait_fence_func(")],
    "Registered callback runs when dependency signals, then calls existing task wake.", "Timestamp at satisfied wait; common MONOTONIC observation recommended.",
    "Actual waiter known, but only these wait implementations are covered. Wake acceptance and first service are later distinct events.",
    "Direct kernel path; proposed cause handoff need not add userspace or a workqueue.",
    "High-priority candidate for precise ready-to-CPU attribution.", "Timeout/cancel, callback removal, task lifetime, merged waits.")
add("syncobj_available", "Syncobj point materialized versus complete", [("syncobj", "static void syncobj_wait_syncobj_func("), ("syncobj", "DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE"), ("kwinsync", "bool SyncTimeline::isMaterialized(")],
    "Availability updates when fence for a point is installed; completion updates only when it signals.", "Sequence/flags; these are different logical events.",
    "WAIT_AVAILABLE can wake while GPU work is unfinished. One generic GPU-ready label is incorrect.",
    "Existing wait flag/point registration; timestamp and type must travel together.",
    "Learn future dependency early, but mark runnable-for-dependent-work only at the required stage.", "Timeline point and flags, replacement, context reset, chained fences.")
add("syncobj_eventfd", "Fence completion through eventfd/epoll", [("syncobj", "static void syncobj_eventfd_entry_fence_func("), ("syncobj", "if (entry->flags & DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE)"), ("epoll", "static int ep_poll_callback(")],
    "Completion callback signals eventfd; availability-only mode can signal earlier; epoll queues readiness and wakes waiters.", "Observer timestamps; object has no universal frame clock.",
    "Fan-in/coalescing/already-readable eventfd break one-event/one-wake assumptions; mode must be preserved.",
    "Existing kernel notification, then consumer service. Metadata propagation needs a valid identity across aggregation.",
    "Measure queue boundary and preserve cause into actual consumer.", "FD/object lifetime, point/mode, readiness consumption, epoll fan-out.")
add("syncfile", "Fence poll via sync_file", [("syncfile", "static __poll_t sync_file_poll("), ("syncfile", "static void fence_check_cb_func(")],
    "Poll installs callback if needed; signaled fence wakes waitqueue and yields EPOLLIN.", "Fence state plus observation clock.",
    "Observer registration may enable software signaling. Actual consumer can be epoll, not direct CPU fence waiter.",
    "Callback+waitqueue; avoid assuming poll wake implies a new task transition.",
    "Cover alternative GPU-to-compositor route without misattributing by submitting PID.", "File/fence lifetime, callback registration, shared waiters.")
add("nvidia_worker", "NVIDIA deferred dependency worker", [("nvidia", "__nv_drm_semsurf_wait_fence_cb"), ("nvidia", "__nv_drm_semsurf_wait_fence_work_cb")],
    "Fence callback queues worker when RM operation cannot run in interrupt context; already-signaled ioctl has immediate path.", "Record enqueue/start/end in one CPU clock domain.",
    "Queue latency is workload-dependent; source gives no maximum. Must identify actual required worker and class.",
    "Existing workqueue boundary; no gain from boosting an unrelated game thread.",
    "Measure and prioritize real runnable dependency, or redesign safe deferral if justified.", "Worker/context teardown, retry/error, dependency generation.")
add("futex_wait", "Futex release-to-task wake", [("futex", "void futex_wake_mark("), ("futex", "wake_up_q(")],
    "Successful wake-mark adds actual task to wake_q; wake follows lock release.", "Logical wake plus chosen clock; ordinary futex has no general owner contract.",
    "Timeout/racing wakes and PI semantics matter; user word is not a trusted task pointer.",
    "Existing wake path; cause must survive wake_q and deduplication.",
    "Shorten proven dependency handoffs, not all short-sleeping threads.", "Wait-key reuse, requeue, cancel, duplicate wake and task lifetime.")
add("ntsync_wait", "NTSYNC ANY/ALL readiness", [("ntsync", "static void try_wake_all("), ("ntsync", "static void try_wake_any_event(")],
    "Object updates evaluate wait conditions and atomically satisfy a wait before waking q->task.", "Logical readiness; annotate monotonic time if needed.",
    "Owner field is opaque userspace ID; all-wait readiness is not each individual object being signaled at some earlier time.",
    "Driver knows waiter; typed wake must preserve its existing lock/context ordering.",
    "Potential Proton path after verifying title usage; precise readiness beats ioctl-name heuristics.", "Object/instance/task lifetime, owner mismatch, alert/timeout/cancel.")
add("input_origin", "Kernel input timestamp", [("input", "void input_set_timestamp("), ("input", "ktime_t *input_get_timestamp(")],
    "Driver supplies event time, or input core samples ktime_get when no valid timestamp exists; reset on flush.", "MONOTONIC internally; REALTIME/BOOTTIME conversions also stored.",
    "May be receipt timestamp; no guaranteed physical sensor timestamp. Delayed conversion across suspend can be inaccurate.",
    "Existing event time; observe producer field, not a later clock read mislabeled as hardware time.",
    "Input age with source-quality flag and consumer identity.", "Device/report generation, suspend, synthetic events and clock choice.")
add("hid_ready", "USB HID report arrival", [("hid", "static void hid_irq_in(")],
    "Successful USB URB completion processes report; cadence depends on device/USB configuration and generated reports.", "Receipt observation time, not physical scan time.",
    "1/8 kHz imply 1 ms/125 us nominal intervals only as examples; this device cadence is not measured.",
    "Existing driver function; tracing every event has cost. BPF cannot eliminate pre-arrival firmware/USB time.",
    "Locate upstream delay; do not wake an unrouted consumer before packet readiness.", "Disconnect/reset, report parsing errors, HID quirks, transport.")
add("evdev_ready", "Mouse/key packet ready for client", [("evdev", "static void evdev_pass_values("), ("evdev", "static int evdev_set_clk_type(")],
    "Nonempty SYN_REPORT packet publication, then poll wake after client buffer lock is released.", "Selected evdev clock; serialized timeval truncates ns to microseconds.",
    "Up to <1 us serialization truncation, plus earlier timestamp uncertainty and later queue delay. Clock changes can flush pending data/SYN_DROPPED.",
    "Actual evdev client context known; trace or typed notification at readiness, no raw key/coordinate payload needed.",
    "Good generic input cause origin before downstream epoll/task selection.", "Client grab/revoke, SYN_DROPPED, clock switch, device/task lifetimes.")
add("libinput", "Libinput delivery to KWin", [("kwinevents", "libinput_event_pointer_get_time_usec"), ("kwinevents", "libinput_event_keyboard_get_time_usec"), ("kwininput", "void Connection::handleEvent(")],
    "KWin dispatches and queues libinput events when its event-loop service runs; empty-to-nonempty emits notification.", "libinput MONOTONIC microseconds; arrival order need not match event timestamp order.",
    "Timestamp can retain event age despite delayed delivery; synthesized events can have older timestamps.",
    "Userspace event queue; kernel cannot infer route through Qt without cooperation or measured association.",
    "Separate event age, queue age and freshest sample age.", "Seat/device/focus and process generation; synthesized-event semantics.")
add("kwin_input_queue", "KWin input thread-to-main handoff", [("kwinbackend", "Qt::QueuedConnection"), ("kwininput", "void Connection::processEvents("), ("kwininput", "latestTime = p->time()")],
    "Queued Qt notification, processed on main-thread service; consecutive motion events coalesced with latest event time.", "Event time in MONOTONIC us; add enqueue/dequeue stamps separately.",
    "Unbounded under stalls; latest-only timestamp hides oldest backlog. Both involved host threads are RR priority 1.",
    "Existing userspace handoff; preserve dependency metadata rather than add another polling broker.",
    "Measure this queue separately from Cake-owned game CPU queue.", "Consumer acknowledgment, focus, suspend and process lifetime.")
add("keyboard_edges", "Keyboard press/release/repeat delivery", [("kwininput", "case LIBINPUT_EVENT_KEYBOARD_KEY:"), ("input", "static void input_repeat_key(")],
    "Per accepted input edge/report; kernel or higher layers may generate repeat.", "Event MONOTONIC us in KWin; event class determines meaning.",
    "Press/release ordering and seat counts matter. Repeat is not a new hardware scan; release lag needs its own measurement.",
    "Reuse packet readiness with discrete-input class; no keycode required for scheduler.",
    "Bound urgency until real consumer handles edge; do not renew forever on repeat.", "Focus loss, dropped synchronization, held-key state, disconnect, acknowledgment.")
add("kwin_fence_queue", "KWin acquire fence to transaction readiness", [("kwintransaction", "void Transaction::watchSyncObj("), ("kwinsync", "FileDescriptor SyncTimeline::eventFd(")],
    "KWin requests eventfd with flags=0 for acquire point; unreadable fd becomes a transaction fence and event-loop dependency.", "Timeline point is completion state; event-loop notification time is later.",
    "Source path waits for completion, distinct from isMaterialized WAIT_AVAILABLE. Whether game uses this path is not traced yet.",
    "GPU fence -> kernel eventfd -> KWin event loop; per-point setup exists already.",
    "Concrete compositor consumer route worth measuring; main thread remains RT.", "Surface/transaction/point generation, fence error/discard, client exit.")
add("frame_target", "KWin planned frame and render start", [("kwinrender", "void RenderLoopPrivate::scheduleRepaint("), ("kwinrender", "void RenderLoopPrivate::notifyFrameCompleted(")],
    "Recomputed when scheduling/revising repaint; render estimate updated after frame feedback.", "steady_clock ns; current Linux presentation clock verified MONOTONIC; timer duration is cast to ms.",
    "Prediction, not measured future time. 1 ms extra safety allowance and sub-ms timer conversion affect planning; VRR/queue state change it.",
    "Userspace already owns frame target; proposed bounded phase/target publication.",
    "Advisory latest-start/slack for actual dependency; no permanent process priority.", "Frame/output generation, refresh/VRR/mode change, estimate age, suspend.")
add("vblank", "NVIDIA last-vblank timestamp", [("nvcrtc", "static bool nv_drm_crtc_get_vblank_timestamp("), ("nvcrtc", "static void nv_drm_crtc_vblank_callback(")],
    "Optional callback stores supplied timestamp per vblank; read uses cache to avoid sleeping KAPI call under DRM locks.", "Driver-supplied ns timestamp; end-to-end hardware origin not established here.",
    "Host nvidia_drm.vblank=N: this optional path is disabled. Available symbols alone do not make it live; separate pageflip feedback can still work.",
    "Existing kernel cache if enabled; do not enable as part of observation or infer absent feedback from this flag alone.",
    "Output phase evidence only after coverage/clock validation; vblank is not per-game completion.", "Enablement, output/mode lifecycle, last-event age, fallback quality.")
add("presentation", "Actual presentation/discard feedback", [("presentation", '<event name="clock_id">'), ("presentation", '<event name="presented"'), ("protocolsync", '<request name="set_release_point">')],
    "Feedback per requested surface content update after presentation or discard; delivery may lag embedded event timestamp.", "Advertised presentation clock: host CLOCK_MONOTONIC; seconds+ns plus quality flags.",
    "HW_CLOCK/HW_COMPLETION/ZERO_COPY flags have distinct meanings. Buffer release can occur without display; protocol availability does not prove a game's coverage.",
    "Existing Wayland protocol; CPU scheduler needs cooperative frame association, not direct protocol parsing in BPF.",
    "Outcome validation and prediction calibration, not a future-ready fact.", "Connection clock, output, frame ID, discard, mode/VRR and buffer generation.")
add("input_protocol", "High-resolution input timestamp protocol", [("inputstamp", '<event name="timestamp">')],
    "If supported and subscribed, accompanies next matching timestamped input event.", "seconds+ns in same domain as corresponding input timestamp.",
    "Higher representation precision does not recover precision already lost upstream. Not advertised in this host registry snapshot.",
    "Userspace protocol; availability must be negotiated, not inferred from installed XML.",
    "Optional measurement/phase publisher input, not a required Cake dependency.", "Seat subscription, device/client lifetime, clock mapping and event matching.")


def main():
    assert (ROOT / "scheds/rust/scx_cake").is_dir(), ROOT
    sources = {k: {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
               for k, p in SOURCES.items()}
    data = {"schema": 1, "date": "2026-10-02", "basis": "Source semantics plus separately retained host capability/clock query evidence; no game latency measurement", "sources": sources, "signals": rows}
    (OUT / "catalog.json").write_text(json.dumps(data, indent=2) + "\n")
    fields = ["id", "signal", "source_locations", "update_rule", "clock_or_units", "accuracy_and_staleness", "access_and_cost", "cake_use", "invalidation", "hardware_update_latency_ns", "hotpath_read_cost_ns"]
    with (OUT / "catalog.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            flat = {k: v for k, v in row.items() if k != "locations"}
            flat["source_locations"] = "; ".join(f"{loc['path']}:{loc['lines'][0]} ({loc['symbol']})" for loc in row["locations"])
            w.writerow(flat)
    text = ["# Signal location catalog", "", "Generated by `build_catalog.py`. Source hashes and all matching lines are in [catalog.json](catalog.json); [CSV](catalog.csv) supports sorting/review. Null timing fields mean unmeasured, never zero cost.", ""]
    for row in rows:
        text += [f"## {row['id']}: {row['signal']}", ""]
        text.append("**Locations:** " + "; ".join(f"[{loc['source']}: {loc['symbol']}]({loc['path']}:{loc['lines'][0]})" for loc in row["locations"]) + ".")
        for label, key in [("Update", "update_rule"), ("Clock/units", "clock_or_units"), ("Accuracy/freshness", "accuracy_and_staleness"), ("Access/cost", "access_and_cost"), ("Cake opportunity", "cake_use"), ("Invalidate/recheck", "invalidation")]:
            text += ["", f"**{label}:** {row[key]}"]
        text.append("")
    (OUT / "CATALOG.md").write_text("\n".join(text))
    print(f"Generated {len(rows)} signals with {len(sources)} hashed source files")


if __name__ == "__main__":
    main()
