// SPDX-License-Identifier: GPL-2.0

use super::*;

pub(super) fn draw_reference_tab(frame: &mut Frame, area: Rect) {
    let layout = Layout::vertical([
        Constraint::Length(8),
        Constraint::Min(18),
        Constraint::Length(7),
    ])
    .split(area);

    let body = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    let hero = vec![
        guide_title("scx_cake in one screen"),
        guide_text(
            "scx_cake is a sched_ext scheduler tuned for low wake-to-run latency, stable game/input threads, and fast recovery when prediction is wrong.",
        ),
        guide_text(
            "The policy tries the cheapest trustworthy answer first: scoreboard and confidence, then direct/local placement, then the safe native/kernel fallback.",
        ),
        guide_rule(
            "How to read this TUI",
            "use Overview for the instrument cluster, Monitors for health codes, Apps for process groups, Trends for history, and dumps for reproducible research.",
            Color::LightCyan,
        ),
        guide_rule(
            "Research rule",
            "compare counters only within the same scope: latest, rate, lifetime, 30s, or 60s. Mixed scopes create fake conclusions.",
            Color::Yellow,
        ),
        guide_text(
            "Tabs: Overview=now | Live Data=plain read | Monitors=scorecard | Codes=evidence | Apps=processes | Topology=CPUs | Trends=time.",
        ),
    ];

    let matrix = vec![
        guide_section("Live Matrix"),
        guide_text(
            "Each row is a task/thread. The matrix is built for triage: find hot threads, slow waits, placement churn, and fallback-heavy paths quickly.",
        ),
        guide_subsection("Identity"),
        guide_item("PPID / PID", "parent process and thread ID"),
        guide_item("ST / COMM", "task state and thread name from /proc"),
        guide_item("CLS", "Cake class: KCR, N-, N0, or N+"),
        guide_subsection("Activity And Latency"),
        guide_item("UTIL% / RUNS/s", "PELT util percent and scheduling frequency"),
        guide_item("MAXR / LGAP", "largest run and last run-start gap in µs"),
        guide_item("RJIT / LASTW", "run-duration deviation and last wake wait in µs"),
        guide_item("LIFE", "startup e/s/r timings plus live age"),
        guide_subsection("Placement"),
        guide_item("CPU / MIGR/s", "last CPU and migration rate"),
        guide_item("SPRD / RES%", "CPU/core spread and top CPU/core residency"),
        guide_item("SMT2%", "share of runs on secondary SMT siblings"),
        guide_subsection("Cost And Path Shape"),
        guide_item("SEL / ENQ", "last select_cpu and enqueue cost in ns"),
        guide_item("STOP / RUN", "last stopping and running cost in ns"),
        guide_item("FAST/NAT/TUN", "fast Cake, native fallback, and tunnel shares"),
        guide_subsection("Color Reading"),
        guide_item("Green", "healthy, low cost, or good locality"),
        guide_item("Yellow", "watch this value; it may explain feel"),
        guide_item("Red", "expensive, slow-path, or churn-heavy signal"),
    ];

    let guide = vec![
        guide_section("How Cake Thinks"),
        guide_rule(
            "1. Predict",
            "confidence lanes and the scoreboard try to reuse known-good CPU choices before broader work is needed.",
            Color::Green,
        ),
        guide_rule(
            "2. Place",
            "direct dispatch and local DSQs keep wakeups close to their target when the CPU can run them immediately.",
            Color::LightCyan,
        ),
        guide_rule(
            "3. Fall Back",
            "native/kernel fallback is always safe. It is only bad when it becomes the common path for latency-sensitive work.",
            Color::Yellow,
        ),
        guide_rule(
            "4. Learn",
            "running/stopping telemetry feeds placement history, quantum outcomes, wake waits, and confidence health.",
            Color::LightMagenta,
        ),
        Line::from(""),
        guide_section("Who This Helps"),
        guide_item("Users", "watch LASTW, FAST%, NAT%, wake latency, and app focus health"),
        guide_item("Students", "map select/enqueue/running/stopping to sched_ext callbacks"),
        guide_item("Researchers", "use dumps, scopes, and monitors to explain regressions"),
        Line::from(""),
        guide_section("Monitors And Data"),
        guide_item("pass/warn/action", "100, 60, or 20 point monitor state"),
        guide_item("not_ready", "warmup or too few samples; do not tune from it yet"),
        guide_item("floor_ready", "CPUs ready for the fastest confidence floor path"),
        guide_item("route_ready", "route predictor has enough signal to be trusted"),
        guide_item("scoreboard", "claim success/failure for predicted CPU slots"),
        guide_item("fallback", "native fallback rate; safe but expensive"),
        guide_item("scope", "latest, rate, life, 30s, and 60s mean different things"),
        guide_item("source", "exact, bounded, sampled, or derived tells data quality"),
    ];

    let footer = vec![
        guide_section("Keys"),
        guide_key(
            "Tabs",
            "←/→ switch tabs; T jumps to first task row; f cycles filters",
        ),
        guide_key(
            "Rows",
            "↑/↓/j/k move; Enter folds or pins; Space folds process groups",
        ),
        guide_key("Sort", "s cycles sort; S reverses; + / - changes refresh"),
        guide_key("Output", "c copies current view; d writes text/json dumps"),
        guide_key(
            "Control",
            "b measures topology latency; r resets; q/Q or Esc quits",
        ),
    ];

    frame.render_widget(
        guide_paragraph(" Field Guide ", Color::LightCyan, hero),
        layout[0],
    );
    frame.render_widget(
        guide_paragraph(" Live Matrix Legend ", Color::Blue, matrix),
        body[0],
    );
    frame.render_widget(
        guide_paragraph(" Scheduler Research Notes ", Color::LightMagenta, guide),
        body[1],
    );
    frame.render_widget(
        guide_paragraph(" Key Bindings ", Color::Green, footer),
        layout[2],
    );
}

fn guide_paragraph(
    title: &'static str,
    border_color: Color,
    lines: Vec<Line<'static>>,
) -> Paragraph<'static> {
    Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .border_type(BorderType::Rounded)
                .padding(Padding::horizontal(1)),
        )
        .wrap(Wrap { trim: false })
}

fn guide_title(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn guide_section(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("═══ {} ═══", text),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
}

fn guide_subsection(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("── {} ──", text),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn guide_text(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default().fg(Color::Gray),
    ))
}

fn guide_item(name: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<12}", name),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc.to_string(), Style::default().fg(Color::Gray)),
    ])
}

fn guide_key(name: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<11}", name),
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc.to_string(), Style::default().fg(Color::Gray)),
    ])
}

fn guide_rule(name: &str, desc: &str, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<14}", name),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc.to_string(), Style::default().fg(Color::Gray)),
    ])
}
