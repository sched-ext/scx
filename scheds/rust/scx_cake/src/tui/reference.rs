// SPDX-License-Identifier: GPL-2.0

use super::*;

pub(super) fn draw_reference_tab(frame: &mut Frame, area: Rect) {
    // 2-column layout: left = matrix columns, right = dump/profile/keys
    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);

    // Helper: styled section header
    fn section(text: &str) -> Line<'_> {
        Line::from(Span::styled(
            text,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))
    }
    // Helper: styled subsection header
    fn subsection(text: &str) -> Line<'_> {
        Line::from(Span::styled(
            text,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
    }
    // Helper: column definition entry
    fn col(name: &str, desc: &str) -> Line<'static> {
        Line::from(vec![
            Span::styled(
                format!("{:<8}", name),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(desc.to_string()),
        ])
    }
    // Helper: indented sub-entry
    fn sub(prefix: &str, desc: &str, color: Color) -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("          {}", prefix), Style::default().fg(color)),
            Span::raw(format!(" {}", desc)),
        ])
    }

    // ═══ LEFT PANEL: Matrix Columns ═══
    let left_text = vec![
        section("═══ LIVE MATRIX COLUMNS ═══"),
        Line::from(""),
        subsection("── Identity & Current Slot ──"),
        col("PPID", "Parent PID — groups threads by launcher"),
        col("PID", "Thread ID (per-thread, not process)"),
        col("ST", "Task status:"),
        sub(
            "●LIVE",
            "Alive — actively scheduled, has telemetry",
            Color::Green,
        ),
        sub(
            "○IDLE",
            "Idle — in sysinfo but no BPF telemetry",
            Color::DarkGray,
        ),
        sub("✗DEAD", "Dead — exited since last refresh", Color::DarkGray),
        col("COMM", "Thread name (first 15 chars, from /proc)"),
        col("CLS", "Current cake role:"),
        sub("KCR", "Kernel-critical helper thread", Color::LightRed),
        sub("N-", "Raised weight / negative nice task", Color::Yellow),
        sub("N0", "Default nice-0 task", Color::Blue),
        sub("N+", "Reduced weight / positive nice task", Color::DarkGray),
        Line::from(""),
        subsection("── Activity & Latency ──"),
        col(
            "PELT",
            "Kernel PELT util_avg (0-1024), not a cake-private metric",
        ),
        col(
            "MAXµs",
            "Largest runtime seen for the task in this interval",
        ),
        col(
            "GAPµs",
            "Time since previous run start ('sleep' = long sleeper)",
        ),
        col("JITµs", "Average inter-run jitter in this interval"),
        col("WAITµs", "Last enqueue→run wait before the current run"),
        col(
            "LIFE",
            "Per-task lifecycle: init→enqueue / select / run, plus live age",
        ),
        col("RUNS/s", "Runs per second — scheduling frequency"),
        Line::from(""),
        subsection("── Placement ──"),
        col("CPU", "Last CPU this task ran on"),
        col(
            "SPRD",
            "Sampled logical CPU / physical-core spread (e.g. 6/3)",
        ),
        col(
            "RES%",
            "Sampled residency on top logical CPU / top physical core",
        ),
        col("SMT%", "Sampled share of runs on non-primary SMT threads"),
        col(
            "COMM color",
            "Heuristic role: GAME / RENDER / UI / AUDIO / BUILD / KCRIT",
        ),
        Line::from(""),
        subsection("── Callback Overhead (ns) ──"),
        col("SELns", "select_cpu callback wall time"),
        col("ENQns", "enqueue callback wall time"),
        col("STOPns", "stopping callback wall time"),
        col("RUNns", "running callback wall time"),
        Line::from(""),
        subsection("── Wake / Placement Shape (%) ──"),
        col("G1%", "Fast local/idle gate hit rate"),
        col("G3%", "Kernel select fallback gate hit rate"),
        col("DSQ%", "Shared DSQ / tunnel fallback rate"),
        col("MIGR/s", "CPU migrations per second"),
        Line::from(""),
        subsection("── Color Semantics ──"),
        col("Green", "Healthy / low latency / good locality"),
        col("Yellow", "Watch value / moderate cost"),
        col("Red", "Poor latency / churn / high callback cost"),
    ];

    let left_paragraph = Paragraph::new(left_text)
        .block(
            Block::default()
                .title(" Matrix Columns ")
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false });

    // ═══ RIGHT PANEL: Dump Fields + Units + Keys ═══
    let right_text = vec![
        section("═══ DUMP / COPY FIELDS ═══"),
        Line::from(""),
        subsection("── Unit Conventions ──"),
        col("PELT", "Kernel util_avg raw scale 0-1024"),
        col("...µs", "Task latency/runtime/jitter values"),
        col("...ns", "Callback stopwatch values"),
        col(
            "SPRD",
            "Sampled logical CPU / physical-core spread in the interval",
        ),
        col(
            "RES%",
            "Sampled top logical/top physical residency percentages",
        ),
        col("SMT%", "Sampled residency on SMT secondary threads"),
        col("scope", "Lifetime totals plus rolling 30s/60s windows"),
        col(
            "cap",
            "Current hard-latency vs soft UI vs build overlap snapshot",
        ),
        col(
            "queue.shared",
            "Shared DSQ depth plus cumulative enqueue/consume net flow",
        ),
        col("roles", "Current live role counts from heuristics"),
        Line::from(""),
        subsection("── Per-Callback Stopwatch (ns) ──"),
        col("gate_cas", "select_cpu: full gate cascade duration"),
        col("life_init", "BPF monotonic task-init timestamp for lifecycle math"),
        col("vtime_cm", "enqueue: vtime adjustment overhead"),
        col("mbox", "running: per-CPU mailbox CL0 write burst"),
        col("classify", "reserved legacy timing slot"),
        col("life_live", "Live task age at the iterator snapshot"),
        col("warm", "stopping: warm CPU ring shift (migration)"),
        Line::from(""),
        subsection("── Extended Detail Fields ──"),
        col("ROLE", "Heuristic workload role plus capacity band"),
        col("STEER", "Per-thread home/primary steering hit counters"),
        col("path/place", "Last select path and home-locality outcome"),
        col("waker", "Last waker locality vs chosen CPU"),
        col("deps", "Wake source counts: same TGID / cross TGID"),
        col("DIRECT", "Direct dispatch count (bypassed DSQ)"),
        col(
            "Q[f/b/p]",
            "Per-task stop outcomes: full slice / blocked-slept with slice left / preempted runnable",
        ),
        col("SYLD", "Explicit sched_yield callbacks for this task"),
        col("PRMPT", "Explicit enqueue-preempt callbacks for this task"),
        col(
            "LIFE",
            "init→first enqueue/select/run in µs; x is live task age until exit; AVGRTus is run→stop average",
        ),
        col("CLS", "Current cake role: KCR / N- / N0 / N+"),
        col(
            "SLICEOCC%",
            "Approx slice occupancy percent from the 128-scale sample; >100 means runtime exceeded slice",
        ),
        col("LLC", "Last LLC (L3 cache) node"),
        col("STREAK", "Consecutive same-CPU runs (locality)"),
        col("WHIST", "Wait histogram: <10µ/<100µ/<1m/≥1ms"),
        col("hwait<=5ms", "Per-task wait by home locality: avg/max/count"),
        Line::from(""),
        section("═══ DASHBOARD PANELS ═══"),
        Line::from(""),
        subsection("── Summary Cards ──"),
        col(
            "Runtime",
            "Topology, uptime, tracked tasks, queue depth, PELT band counts",
        ),
        col(
            "Dispatch",
            "Dispatch volume, local/steal/miss counts, shared queue flow, wake routing, and path share",
        ),
        col(
            "Timing",
            "Average callback cost, wake wait<=5ms, and lifecycle init→enqueue/select/run, run→stop, init→exit",
        ),
        col(
            "Lifecycle",
            "Quantum stop mix (full / blocked / preempt), literal sched_yield count, kick-to-run latency, and post-wake target/follow-up outcomes",
        ),
        Line::from(""),
        subsection("── Analysis Panels ──"),
        col(
            "PELT band",
            "Task counts and averages grouped by idle/light/busy/hot util bands",
        ),
        col(
            "Last60s",
            "Rolling 1-second samples: runs/s, 1% low, callback avg, path share, quantum f/b/p, sched_yield/s, coverage, and retained history span",
        ),
        col(
            "Signals",
            "Balance diagnosis, wake waits<=5ms, post-wake target accuracy, kick latency, placement mix, latest anomaly event",
        ),
        Line::from(""),
        subsection("── Apps Tab ──"),
        col(
            "Apps",
            "TGID-level health view for games, launchers, browser workers, helper daemons, and other process groups",
        ),
        col(
            "Health",
            "Runtime share, ms/s, run/s, wait avg/max, quantum blocked share, SMT contention, and wakegraph coverage",
        ),
        col(
            "Top Threads",
            "Selected app's hottest threads with role, PELT, runtime rate, wait, placement spread, and quantum mix",
        ),
        col(
            "Wake Chain",
            "Selected app inbound/internal/outbound wake edges, wait cost, target hit/miss, and follow-up locality",
        ),
        col(
            "Focus",
            "Enter or p pins selected app; Dashboard/Topology/Dump add focused-app health and placement",
        ),
        col(
            "healthy",
            "Focused app has low wait, low preempt pressure, and no sticky hot threads",
        ),
        col(
            "warm",
            "Focused app has moderate wait or preempt pressure worth watching",
        ),
        col(
            "watch",
            "Focused app has high wait/preempt pressure or a sticky hot thread",
        ),
        Line::from(""),
        subsection("── Topology Tab ──"),
        col(
            "Topology",
            "Per-CPU cells read as Ck runtime share, Ld system load, and temperature over the latest 60s window",
        ),
        col(
            "CPU work",
            "Per-CPU scheduler distribution: Cake runtime share, runs/s, avg run time, SMT contention/overlap, quantum mix, system load",
        ),
        col(
            "Core work",
            "Per-core balance: combined Cake share, hottest thread share, SMT sibling share, overlap/primary contention, average system load",
        ),
        Line::from(""),
        subsection("── Graphs Tab ──"),
        col(
            "Coverage",
            "Fail-loud source status for exact, sampled, bounded, derived, dropped, or missing telemetry",
        ),
        col(
            "Wake edges",
            "Userspace wake graph: top edges, latency-heavy edges, target hit/miss, and wait buckets",
        ),
        col(
            "App graph",
            "TGID wake neighborhoods showing internal and outbound wake pressure",
        ),
        col(
            "Events",
            "Recent ringbuf debug events when available; missing event streams are reported as coverage gaps",
        ),
        Line::from(""),
        section("═══ KEY BINDINGS ═══"),
        Line::from(""),
        col("←/→ Tab", "Switch tabs"),
        col("↑/↓ j/k", "Scroll task, app, or benchmark rows"),
        col("s / S", "Cycle sort column / reverse direction"),
        col("+ / -", "Adjust refresh rate"),
        col("f", "Cycle filters: BPF-tracked -> live-only -> all"),
        col("T", "Jump to first task row"),
        col("Enter", "Fold PPID on Dashboard; pin selected app on Apps"),
        col("Space", "Fold / unfold process thread group"),
        col("p", "Pin / unpin selected app on Apps"),
        col("x", "Clear folds on Dashboard; clear app focus on Apps"),
        col(
            "c",
            "Copy current tab (includes lifetime + 30s/60s windows)",
        ),
        col(
            "d",
            "Dump dashboard to tui_dump_*.txt plus tui_dump_*.json coverage sidecar",
        ),
        col("b", "Run BenchLab benchmark iteration"),
        col("r", "Reset state"),
        col("q / Esc", "Quit scx_cake"),
        Line::from(""),
        subsection("── Scheduler State ──"),
        sub(
            "IDLE",
            "General low-latency mode; detector removed",
            Color::DarkGray,
        ),
    ];

    let right_paragraph = Paragraph::new(right_text)
        .block(
            Block::default()
                .title(" Fields & Keybindings ")
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(left_paragraph, cols[0]);
    frame.render_widget(right_paragraph, cols[1]);
}
