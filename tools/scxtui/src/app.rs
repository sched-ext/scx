// SPDX-License-Identifier: GPL-2.0

//! Application state and event loop.

use std::io::ErrorKind;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::backend::service::validate_value;
use crate::backend::{SchedulerBackend, Status};
use crate::kernel::{self, KernelState};
use crate::logs::{self, LogLine};
use crate::profiles::{MODES, Mode, Profiles};
use crate::ui;

/// How often the input poll wakes up to redraw / refresh.
const TICK: Duration = Duration::from_millis(250);
/// Status poll cadence. systemd has no cheap push channel for unit state
/// that is worth a D-Bus dependency here, so the view is polled; the
/// kernel sysfs read rides every tick regardless.
const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// Minimum spacing between two scheduler-affecting actions. Linux terminals
/// deliver key autorepeat as plain `Press` events (no kitty protocol), so
/// without this, holding `r` would fire one restart per repeat.
const ACTION_DEBOUNCE: Duration = Duration::from_millis(500);
/// How long informational messages stay in the message bar. Without a
/// TTL, a stale "refreshed" from minutes ago reads as fresh feedback.
/// Errors are exempt: they are actionable and stay until replaced.
const MESSAGE_TTL: Duration = Duration::from_secs(8);

/// Deferred user actions: queued by key handlers, executed by the event
/// loop right after the frame announcing them has been drawn. Backend
/// calls block (a `systemctl restart` waits for the unit to come up), so
/// the UI must show feedback *before* making them.
#[derive(Clone, Debug, PartialEq)]
enum PendingAction {
    StartOrSwitch,
    /// Validated field content; see [`App::submit_args`].
    StartOrSwitchWithArgs(Vec<String>),
    Stop,
    Restart,
    RestoreDefault,
    Monitor,
}

/// State of the own-arguments field. The cursor is counted in
/// characters, not bytes, so editing multi-byte input stays sound; the UI
/// derives its cursor block from the same count.
#[derive(Default)]
pub struct ArgsInput {
    pub buffer: String,
    pub cursor: usize,
}

impl ArgsInput {
    /// Byte offset of the character cursor, for `String` edits.
    fn byte_cursor(&self) -> usize {
        self.buffer
            .char_indices()
            .nth(self.cursor)
            .map_or(self.buffer.len(), |(idx, _)| idx)
    }

    fn len_chars(&self) -> usize {
        self.buffer.chars().count()
    }

    fn insert(&mut self, c: char) {
        let at = self.byte_cursor();
        self.buffer.insert(at, c);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            let at = self.byte_cursor();
            self.buffer.remove(at);
        }
    }

    fn delete(&mut self) {
        let at = self.byte_cursor();
        if at < self.buffer.len() {
            self.buffer.remove(at);
        }
    }
}

/// Which screen is currently shown.
#[derive(Clone, Copy, PartialEq)]
pub enum View {
    Schedulers,
    Logs,
}

pub struct Message {
    pub text: String,
    pub is_error: bool,
    /// When the message was posted; drives [`MESSAGE_TTL`] expiry.
    shown_at: Instant,
}

pub struct App {
    backend: Box<dyn SchedulerBackend>,
    pub profiles: Profiles,
    pub schedulers: Vec<String>,
    pub selected: usize,
    pub mode_idx: usize,
    /// Last successful status read. Stays `None` after a failed read,
    /// with the failure in `status_error`, so the panel shows "unknown"
    /// plus the reason instead of a stale snapshot.
    pub status: Option<Status>,
    pub status_error: Option<String>,
    /// The kernel's own view of `sched_ext`, refreshed alongside `status`.
    /// `None` = kernel without `sched_ext` support.
    pub kernel: Option<KernelState>,
    /// Previous tick's dispute bit; makes the tripwire edge-triggered.
    kernel_disputed: bool,
    /// Own-arguments field; `Some` while the user is typing. While open
    /// it owns every key press.
    pub args_input: Option<ArgsInput>,
    pub message: Option<Message>,
    /// Timestamp of the last scheduler-affecting action, for debouncing.
    last_action: Option<Instant>,
    pub view: View,
    /// `false` = current boot, `true` = previous boot (`journalctl -b -1`).
    pub log_previous_boot: bool,
    /// Flattened journal lines, oldest first.
    pub log_lines: Vec<LogLine>,
    /// Scroll offset counted from the bottom; 0 sticks to the newest line.
    pub log_scroll: usize,
    /// Last known height of the log viewport, written back by the UI so
    /// `PgUp`/`PgDn` can page by exactly one screen.
    pub log_page: usize,
    /// Queued by key handlers, executed by the event loop after the next
    /// draw; see [`PendingAction`].
    pending_action: Option<PendingAction>,
    should_quit: bool,
}

impl App {
    pub fn new(backend: Box<dyn SchedulerBackend>, profiles: Profiles) -> Result<Self> {
        let schedulers = backend.supported_schedulers()?;
        // No initial status fetch here: `run` draws the first frame with
        // the scheduler list alone and fetches right after, so the UI
        // appears immediately instead of waiting on systemctl round-trips.
        Ok(Self {
            backend,
            profiles,
            schedulers,
            selected: 0,
            mode_idx: 0,
            status: None,
            status_error: None,
            kernel: None,
            kernel_disputed: false,
            args_input: None,
            message: None,
            last_action: None,
            view: View::Schedulers,
            log_previous_boot: false,
            log_lines: Vec::new(),
            log_scroll: 0,
            log_page: 20,
            pending_action: None,
            should_quit: false,
        })
    }

    pub fn backend_label(&self) -> String {
        self.backend.label()
    }

    pub fn selected_scheduler(&self) -> Option<&str> {
        self.schedulers.get(self.selected).map(String::as_str)
    }

    pub fn selected_mode(&self) -> Mode {
        MODES[self.mode_idx]
    }

    /// Flags the selected scheduler would be started with in the selected
    /// mode: what `Enter` writes to `SCX_FLAGS`.
    pub fn selected_flags(&self) -> Vec<String> {
        self.selected_scheduler()
            .map(|sched| self.profiles.flags(sched, self.selected_mode()))
            .unwrap_or_default()
    }

    /// The mode the running process' arguments correspond to, if they
    /// match a row of the table for that scheduler.
    pub fn running_mode(&self) -> Option<Mode> {
        let status = self.status.as_ref()?;
        let process = status.process.as_ref().filter(|_| status.active)?;
        self.profiles.mode_for(&process.sched, &process.args)
    }

    pub fn run(&mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut last_refresh = Instant::now();
        let mut primed = false;
        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, self))?;

            // First frame is a skeleton: scheduler list only, status panel
            // in its "unknown" placeholder. The initial fetch happens right
            // after it is on screen and the immediate redraw fills it in.
            if !primed {
                primed = true;
                self.refresh_status();
                self.sync_selection_to_running();
                last_refresh = Instant::now();
                continue;
            }

            // Informational messages expire so stale feedback never reads
            // as fresh; errors stay until replaced (see MESSAGE_TTL).
            if self
                .message
                .as_ref()
                .is_some_and(|m| !m.is_error && m.shown_at.elapsed() >= MESSAGE_TTL)
            {
                self.message = None;
            }

            // Execute a queued action only after the frame announcing it
            // ("working…") has been drawn, then redraw immediately so the
            // result replaces the notice.
            if let Some(action) = self.pending_action.take() {
                self.run_action(action, &mut terminal)?;
                last_refresh = Instant::now();
                continue;
            }

            if event::poll(TICK)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key);
            }

            // Sysfs can change with no service involved; rides every tick.
            self.kernel = kernel::read();

            if self.reconcile_kernel_dispute() {
                last_refresh = Instant::now();
            }
            if last_refresh.elapsed() >= REFRESH_EVERY {
                self.refresh_status();
                last_refresh = Instant::now();
            }
        }
        Ok(())
    }

    /// Hands the terminal over to `scxtop` and takes it back afterwards —
    /// the lazygit-spawns-an-editor pattern. Restoring the terminal to
    /// cooked mode first lets scxtop own the alternate screen and raw mode
    /// itself; a fresh `ratatui::init()` afterwards re-enters ours, and the
    /// explicit clear forces a full repaint of a screen scxtop scribbled
    /// over. Keeping scxtop out-of-process also keeps its heavyweight BPF
    /// dependency chain out of this binary.
    fn run_monitor(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        ratatui::restore();
        let result = Command::new("scxtop").status();
        *terminal = ratatui::init();
        terminal.clear()?;

        match result {
            Ok(status) if status.success() => self.info("scxtop exited"),
            Ok(status) => self.error(&format!(
                "scxtop exited with {status} — it needs root/CAP_BPF; \
try running scxtui as root or granting scxtop capabilities"
            )),
            Err(err) if err.kind() == ErrorKind::NotFound => self.error(
                "scxtop not found in PATH — install it (cargo install scxtop, \
or your distro's scx tools package)",
            ),
            Err(err) => self.error(&format!("failed to launch scxtop: {err}")),
        }
        Ok(())
    }

    /// Queues a scheduler-affecting action behind a "working…" notice, so
    /// the notice renders before the blocking backend call starts.
    fn queue(&mut self, action: PendingAction) {
        self.info("working…");
        self.pending_action = Some(action);
    }

    fn run_action(&mut self, action: PendingAction, terminal: &mut DefaultTerminal) -> Result<()> {
        match action {
            PendingAction::StartOrSwitch => self.start_or_switch(),
            PendingAction::StartOrSwitchWithArgs(args) => self.start_or_switch_with_args(&args),
            PendingAction::Stop => self.act("stop accepted", |b| b.stop()),
            PendingAction::Restart => self.act("restart accepted", |b| b.restart()),
            PendingAction::RestoreDefault => self.restore_default(),
            PendingAction::Monitor => self.run_monitor(terminal)?,
        }
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent) {
        if self.view == View::Schedulers && self.args_input.is_some() {
            self.on_key_args(key);
            return;
        }
        match self.view {
            View::Schedulers => self.on_key_schedulers(key),
            View::Logs => self.on_key_logs(key),
        }
    }

    /// Key handling while the own-arguments field is open. The field owns
    /// every key press: global shortcuts must not fire while the user is
    /// typing text that may well contain their letters, which also means
    /// `Esc` closes the field here instead of quitting.
    fn on_key_args(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.args_input = None,
            KeyCode::Enter => self.submit_args(),
            code => {
                let Some(input) = self.args_input.as_mut() else {
                    return;
                };
                match code {
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        input.insert(c);
                    }
                    KeyCode::Backspace => input.backspace(),
                    KeyCode::Delete => input.delete(),
                    KeyCode::Left => input.cursor = input.cursor.saturating_sub(1),
                    KeyCode::Right => input.cursor = (input.cursor + 1).min(input.len_chars()),
                    KeyCode::Home => input.cursor = 0,
                    KeyCode::End => input.cursor = input.len_chars(),
                    _ => {}
                }
            }
        }
    }

    /// `Enter` in the field: split on whitespace, exactly as the unit's
    /// unquoted `$SCX_FLAGS` expansion will, and refuse any token the
    /// file or the shell would reinterpret (quotes, globs). Errors keep
    /// the field open with the message bar explaining what to fix; only
    /// a successfully queued action closes it.
    fn submit_args(&mut self) {
        let Some(buffer) = self.args_input.as_ref().map(|input| input.buffer.clone()) else {
            return;
        };
        let args: Vec<String> = buffer.split_whitespace().map(str::to_owned).collect();
        if args.is_empty() {
            self.error(
                "no arguments typed — to run with scheduler defaults, press Esc and use the \
auto profile instead",
            );
            return;
        }
        if let Some(err) = args
            .iter()
            .find_map(|arg| validate_value("flag", arg).err())
        {
            self.error(&format!("{err:#}"));
            return;
        }
        if self.action_allowed() {
            self.args_input = None;
            self.queue(PendingAction::StartOrSwitchWithArgs(args));
        }
    }

    fn on_key_schedulers(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('t') => {
                if self.action_allowed() {
                    self.pending_action = Some(PendingAction::Monitor);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_prev(),
            KeyCode::Char('a') => {
                if self.selected_scheduler().is_some() {
                    self.args_input = Some(ArgsInput::default());
                }
            }
            KeyCode::Tab | KeyCode::Char('m') => self.cycle_mode(true),
            KeyCode::BackTab | KeyCode::Char('M') => self.cycle_mode(false),
            KeyCode::Enter => {
                if self.action_allowed() {
                    self.queue(PendingAction::StartOrSwitch);
                }
            }
            KeyCode::Char('s') => {
                if self.action_allowed() {
                    self.queue(PendingAction::Stop);
                }
            }
            KeyCode::Char('r') => {
                if self.action_allowed() {
                    self.queue(PendingAction::Restart);
                }
            }
            KeyCode::Char('d') => {
                if self.action_allowed() {
                    self.queue(PendingAction::RestoreDefault);
                }
            }
            KeyCode::Char('R') => {
                // The success notice must not clobber a list-refresh error,
                // same rule as refresh_status not touching the message bar.
                let list_ok = self.refresh_schedulers();
                self.refresh_status();
                if list_ok {
                    self.info("refreshed");
                }
            }
            _ => {}
        }
    }

    fn on_key_logs(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q' | 'l') | KeyCode::Esc => {
                self.view = View::Schedulers;
            }
            KeyCode::Up | KeyCode::Char('k') => self.log_scroll_up(1),
            KeyCode::Down | KeyCode::Char('j') => self.log_scroll_down(1),
            KeyCode::PageUp => self.log_scroll_up(self.log_page),
            KeyCode::PageDown => self.log_scroll_down(self.log_page),
            KeyCode::Char('g') => self.log_scroll = usize::MAX, // clamped by the UI
            KeyCode::Char('G') => self.log_scroll = 0,
            KeyCode::Char('b') => {
                self.log_previous_boot = !self.log_previous_boot;
                self.reload_logs();
            }
            KeyCode::Char('R') => self.reload_logs(),
            _ => {}
        }
    }

    fn open_logs(&mut self) {
        self.view = View::Logs;
        self.reload_logs();
    }

    fn reload_logs(&mut self) {
        match logs::fetch(logs::UNIT, self.log_previous_boot) {
            Ok(fetch) => {
                let boot = if self.log_previous_boot { "-1" } else { "0" };
                let tail_note = if fetch.truncated {
                    " — older entries omitted, see journalctl for the full log"
                } else {
                    ""
                };
                self.info(&format!(
                    "loaded {} lines from {} (boot {boot}){tail_note}",
                    fetch.lines.len(),
                    logs::UNIT
                ));
                self.log_lines = fetch.lines;
                self.log_scroll = 0;
            }
            Err(err) => {
                self.log_lines = Vec::new();
                self.error(&format!("{err:#}"));
            }
        }
    }

    /// The upper bound is clamped against the viewport in the UI, which
    /// knows the current height; only the zero bound is handled here.
    fn log_scroll_up(&mut self, lines: usize) {
        self.log_scroll = self.log_scroll.saturating_add(lines);
    }

    fn log_scroll_down(&mut self, lines: usize) {
        self.log_scroll = self.log_scroll.saturating_sub(lines);
    }

    fn select_next(&mut self) {
        if !self.schedulers.is_empty() {
            self.selected = (self.selected + 1) % self.schedulers.len();
        }
    }

    fn select_prev(&mut self) {
        if !self.schedulers.is_empty() {
            self.selected = (self.selected + self.schedulers.len() - 1) % self.schedulers.len();
        }
    }

    fn cycle_mode(&mut self, forward: bool) {
        let len = MODES.len();
        self.mode_idx = if forward {
            (self.mode_idx + 1) % len
        } else {
            (self.mode_idx + len - 1) % len
        };
    }

    /// Aligns the selection and the mode selector with what is actually
    /// running, so the first `Enter` after startup acts on what the user
    /// sees instead of on `schedulers[0]` + `auto`. Only called on
    /// startup — never on the periodic refresh, which must not fight the
    /// user's own selection.
    ///
    /// A running scheduler outside the list (hand-launched, or an override
    /// naming a binary PATH does not have) leaves both selectors alone,
    /// and flags matching no profile row leave the mode alone: no
    /// selector position represents "custom".
    fn sync_selection_to_running(&mut self) {
        let Some(idx) = self
            .status
            .as_ref()
            .and_then(Status::running)
            .and_then(|current| self.schedulers.iter().position(|s| s == current))
        else {
            return;
        };
        self.selected = idx;
        if let Some(idx) = self
            .running_mode()
            .and_then(|mode| MODES.iter().position(|m| *m == mode))
        {
            self.mode_idx = idx;
        }
    }

    /// Debounce gate for scheduler-affecting actions (Enter/s/r/d/t).
    /// Returns `true` and arms the timer when enough time has passed since
    /// the last action; swallows the event otherwise. See
    /// [`ACTION_DEBOUNCE`].
    fn action_allowed(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last_action
            .is_some_and(|last| now.duration_since(last) < ACTION_DEBOUNCE)
        {
            return false;
        }
        self.last_action = Some(now);
        true
    }

    /// `Enter`: start the selected scheduler in the selected mode, or
    /// switch to it when the unit is active (config rewrite plus
    /// restart). Pressing it on the running scheduler is a restart that
    /// also pins the configuration, which is how a mode change applies.
    fn start_or_switch(&mut self) {
        let Some(sched) = self.selected_scheduler().map(str::to_owned) else {
            return;
        };
        let mode = self.selected_mode();
        let flags = self.profiles.flags(&sched, mode);
        self.launch(&sched, &format!("{} profile", mode.label()), &flags);
    }

    /// The own-arguments sibling of [`Self::start_or_switch`]: the typed
    /// flags go to `SCX_FLAGS` instead of a profile's. They persist in
    /// the file like any other write; the panel will show them as custom
    /// flags since they match no profile row.
    fn start_or_switch_with_args(&mut self, args: &[String]) {
        let Some(sched) = self.selected_scheduler().map(str::to_owned) else {
            return;
        };
        self.launch(&sched, "custom flags", args);
    }

    /// `d`: start or switch to the profile file's `default_sched` in its
    /// `default_mode`.
    fn restore_default(&mut self) {
        let Some((sched, mode)) = self
            .profiles
            .default_launch()
            .map(|(sched, mode)| (sched.to_owned(), mode))
        else {
            self.error("no default_sched in the profiles file — nothing to restore");
            return;
        };
        let flags = self.profiles.flags(&sched, mode);
        self.launch(&sched, &format!("{} profile", mode.label()), &flags);
    }

    /// Writes `sched`/`flags` and starts or restarts the unit. The notice
    /// reports what systemd *accepted*; what actually attached is read
    /// back right after and shown in the State and Kernel lines, since
    /// under `Type=simple` a successful start says nothing about the
    /// scheduler attaching.
    fn launch(&mut self, sched: &str, how: &str, flags: &[String]) {
        // Re-read the unit state right before deciding start vs switch:
        // the cached status can be up to REFRESH_EVERY old, and someone
        // may have started the unit by hand in that window.
        self.refresh_status();
        // Unknown is not inactive. Treating a failed read as "nothing
        // running" would pick `start`, which leaves an already running
        // unit untouched: the file would name the new scheduler while the
        // old one keeps running.
        let Some(status) = self.status.as_ref() else {
            let why = self.status_error.clone().unwrap_or_default();
            self.error(&format!(
                "not touching {sched}: the unit's state could not be read ({why})"
            ));
            return;
        };
        let active = status.active;
        let overrides: Vec<&str> = [
            status
                .override_sched
                .as_ref()
                .map(|_| "SCX_SCHEDULER_OVERRIDE"),
            status.override_flags.as_ref().map(|_| "SCX_FLAGS_OVERRIDE"),
        ]
        .into_iter()
        .flatten()
        .collect();

        let result = if active {
            self.backend.switch(sched, flags)
        } else {
            self.backend.start(sched, flags)
        };

        match result {
            Ok(()) => {
                let verb = if active { "restart" } else { "start" };
                let mut text = format!(
                    "{verb} accepted: {sched} with {how} — see State and Kernel for what attached"
                );
                // The file now names `sched` and the profile's flags, but
                // an override still wins in the unit's ExecStart: say so
                // instead of letting the next poll look like a failed
                // switch or a wrong profile.
                if !overrides.is_empty() {
                    text.push_str(&format!(
                        "; {} in effect and takes precedence (systemctl unset-environment, \
or the file that sets it)",
                        overrides.join(" and ")
                    ));
                }
                self.info(&text);
            }
            Err(err) => {
                let verb = if active { "switch to" } else { "start" };
                self.error(&format!("{verb} {sched} failed: {err:#}"));
            }
        }
        self.refresh_status();
    }

    fn act(&mut self, ok_text: &str, op: impl FnOnce(&dyn SchedulerBackend) -> Result<()>) {
        match op(self.backend.as_ref()) {
            Ok(()) => self.info(ok_text),
            Err(err) => self.error(&format!("{err:#}")),
        }
        self.refresh_status();
    }

    /// A failed read clears the snapshot and records why: the panel must
    /// not keep showing a state the backend can no longer vouch for.
    fn refresh_status(&mut self) {
        match self.backend.status() {
            Ok(status) => {
                self.status = Some(status);
                self.status_error = None;
            }
            Err(err) => {
                self.status = None;
                self.status_error = Some(format!("{err:#}"));
            }
        }
        self.kernel = kernel::read();
    }

    /// The panel's warning; the event loop reuses it as a tripwire.
    pub fn kernel_warning(&self) -> Option<String> {
        let kernel = self.kernel.as_ref()?;
        let status = self.status.as_ref()?;
        match (status.active, status.running(), kernel.enabled()) {
            // Unit inactive, kernel disagrees: started behind its back.
            (false, _, true) => {
                Some("a scheduler is attached outside of scx.service's control".to_owned())
            }
            // Unit active, kernel disagrees: still loading, crashed, or
            // ejected and not yet restarted (or Restart= gave up).
            (true, running, false) => Some(format!(
                "scx.service is active ({}), but the kernel shows no attached scheduler",
                running.unwrap_or("process unknown")
            )),
            // Both agree something runs — but is it the same something?
            (true, Some(sched), true) if !kernel.matches(sched) => {
                let ops = kernel.ops.as_deref().unwrap_or("?");
                Some(format!(
                    "scx.service runs {sched}, but the kernel ops name is \"{ops}\""
                ))
            }
            _ => None,
        }
    }

    /// Edge-triggered: re-asks once per new dispute; returns whether it refreshed.
    fn reconcile_kernel_dispute(&mut self) -> bool {
        let disputed = self.kernel_warning().is_some();
        let fire = disputed && !self.kernel_disputed;
        if fire {
            self.refresh_status();
        }
        // Post-refresh truth: unresolved disputes stand without re-triggering.
        self.kernel_disputed = self.kernel_warning().is_some();
        fire
    }

    /// Re-enumerates the scheduler list. The list is otherwise fetched
    /// once at startup, so without this a scheduler package installed
    /// later would stay invisible until scxtui itself restarts. The
    /// selection survives by name where possible; on a failed query the
    /// old list stays — a stale list beats an empty one.
    fn refresh_schedulers(&mut self) -> bool {
        match self.backend.supported_schedulers() {
            Ok(schedulers) => {
                let previous = self.selected_scheduler().map(str::to_owned);
                self.selected = previous
                    .and_then(|name| schedulers.iter().position(|s| *s == name))
                    .unwrap_or(0);
                self.schedulers = schedulers;
                true
            }
            Err(err) => {
                self.error(&format!("scheduler list refresh failed: {err:#}"));
                false
            }
        }
    }

    fn info(&mut self, text: &str) {
        self.message = Some(Message {
            text: text.to_owned(),
            is_error: false,
            shown_at: Instant::now(),
        });
    }

    fn error(&mut self, text: &str) {
        self.message = Some(Message {
            text: text.to_owned(),
            is_error: true,
            shown_at: Instant::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use anyhow::anyhow;

    use super::*;
    use crate::backend::Process;

    /// What the stub was asked to do, in order.
    #[derive(Debug, PartialEq)]
    enum Call {
        Start(String, Vec<String>),
        Switch(String, Vec<String>),
        Stop,
        Restart,
    }

    /// Minimal in-memory backend: enough for exercising selection and
    /// refresh logic without systemd.
    struct StubBackend {
        schedulers: Rc<RefCell<Vec<String>>>,
        /// The authoritative answer `status` returns.
        truth: Rc<RefCell<Status>>,
        /// When set, `status` errors after counting the attempt.
        status_broken: Rc<RefCell<bool>>,
        /// How many times `status` reached the backend.
        status_queries: Rc<RefCell<usize>>,
        calls: Rc<RefCell<Vec<Call>>>,
    }

    impl StubBackend {
        fn new() -> Self {
            Self {
                schedulers: Rc::new(RefCell::new(vec![
                    "scx_bpfland".into(),
                    "scx_lavd".into(),
                    "scx_cake".into(),
                ])),
                truth: Rc::new(RefCell::new(Status::default())),
                status_broken: Rc::new(RefCell::new(false)),
                status_queries: Rc::new(RefCell::new(0)),
                calls: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl SchedulerBackend for StubBackend {
        fn label(&self) -> String {
            "stub".into()
        }
        fn status(&self) -> Result<Status> {
            *self.status_queries.borrow_mut() += 1;
            if *self.status_broken.borrow() {
                return Err(anyhow!("status broken"));
            }
            Ok(self.truth.borrow().clone())
        }
        fn supported_schedulers(&self) -> Result<Vec<String>> {
            let scheds = self.schedulers.borrow().clone();
            if scheds.is_empty() {
                return Err(anyhow!("no schedulers"));
            }
            Ok(scheds)
        }
        fn start(&self, sched: &str, flags: &[String]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(Call::Start(sched.into(), flags.to_vec()));
            Ok(())
        }
        fn switch(&self, sched: &str, flags: &[String]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(Call::Switch(sched.into(), flags.to_vec()));
            Ok(())
        }
        fn stop(&self) -> Result<()> {
            self.calls.borrow_mut().push(Call::Stop);
            Ok(())
        }
        fn restart(&self) -> Result<()> {
            self.calls.borrow_mut().push(Call::Restart);
            Ok(())
        }
    }

    fn app_with_backend(backend: StubBackend) -> App {
        App::new(Box::new(backend), Profiles::default()).unwrap()
    }

    fn strs(flags: &[&str]) -> Vec<String> {
        flags.iter().map(|s| (*s).to_owned()).collect()
    }

    /// An active unit whose process is `sched` with `args`, and whose
    /// file says `configured` (which may differ: edited under the unit).
    fn running(sched: &str, args: &[&str], configured: &str) -> Status {
        Status {
            active: true,
            process: Some(Process {
                sched: sched.into(),
                args: strs(args),
            }),
            next_sched: Some(configured.into()),
            configured: Some(configured.into()),
            ..Status::default()
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    #[test]
    fn sync_aligns_selection_and_mode_with_the_process_not_the_file() {
        // The file was edited to scx_cake under a running scx_lavd: the
        // selection must follow the process. Its arguments match the
        // built-in gaming row, so the mode selector follows too.
        let mut app = app_with_backend(StubBackend::new());
        app.status = Some(running(
            "scx_lavd",
            &["--performance", "--pinned-slice-us", "500"],
            "scx_cake",
        ));
        app.sync_selection_to_running();
        assert_eq!(app.selected_scheduler(), Some("scx_lavd"));
        assert_eq!(app.selected_mode(), Mode::Gaming);
        assert_eq!(app.running_mode(), Some(Mode::Gaming));
    }

    #[test]
    fn sync_with_custom_flags_or_unknown_scheduler_leaves_selectors_alone() {
        let mut app = app_with_backend(StubBackend::new());
        app.selected = 2;
        app.mode_idx = 3;

        app.status = Some(running("scx_homebrew", &[], "scx_homebrew"));
        app.sync_selection_to_running();
        assert_eq!(app.selected_scheduler(), Some("scx_cake"));
        assert_eq!(app.selected_mode(), Mode::LowLatency);

        // Known scheduler, flags matching no row: selection follows,
        // mode stays (no selector position means "custom").
        app.status = Some(running("scx_bpfland", &["-k"], "scx_bpfland"));
        app.sync_selection_to_running();
        assert_eq!(app.selected_scheduler(), Some("scx_bpfland"));
        assert_eq!(app.selected_mode(), Mode::LowLatency);
        assert_eq!(app.running_mode(), None);

        // Inactive unit: nothing to follow.
        app.selected = 2;
        app.status = Some(Status::default());
        app.sync_selection_to_running();
        assert_eq!(app.selected_scheduler(), Some("scx_cake"));
    }

    #[test]
    fn enter_starts_when_inactive_and_switches_when_active_with_mode_flags() {
        let backend = StubBackend::new();
        let truth = Rc::clone(&backend.truth);
        let calls = Rc::clone(&backend.calls);
        let mut app = app_with_backend(backend);
        app.selected = 0; // scx_bpfland
        app.mode_idx = MODES.iter().position(|m| *m == Mode::Gaming).unwrap();

        app.start_or_switch();
        assert_eq!(
            *calls.borrow(),
            [Call::Start("scx_bpfland".into(), strs(&["-m", "all"]))]
        );
        let message = app.message.as_ref().unwrap();
        assert!(!message.is_error);
        assert!(message.text.starts_with("start accepted"));

        // The decision is made against freshly polled truth, not the
        // cached panel state; the mode comes from the selector.
        *truth.borrow_mut() = running("scx_cake", &[], "scx_cake");
        app.selected = 1; // scx_lavd
        app.mode_idx = MODES.iter().position(|m| *m == Mode::PowerSave).unwrap();
        app.start_or_switch();
        assert_eq!(
            calls.borrow().last(),
            Some(&Call::Switch(
                "scx_lavd".into(),
                strs(&["--powersave", "--pinned-slice-us", "500"])
            ))
        );
    }

    #[test]
    fn switch_under_an_override_warns_in_the_notice() {
        let backend = StubBackend::new();
        let truth = Rc::clone(&backend.truth);
        let mut app = app_with_backend(backend);
        *truth.borrow_mut() = Status {
            override_sched: Some("scx_rustland".into()),
            ..running("scx_rustland", &[], "scx_lavd")
        };

        app.start_or_switch();
        let message = app.message.as_ref().unwrap();
        assert!(!message.is_error);
        assert!(message.text.contains("SCX_SCHEDULER_OVERRIDE"));
    }

    #[test]
    fn unknown_unit_state_aborts_the_action() {
        // scx_lavd runs, `systemctl show` fails for a moment, the user
        // presses Enter on another scheduler: nothing may reach systemd,
        // since `start` would leave the running unit on the old scheduler
        // with the file already naming the new one.
        let backend = StubBackend::new();
        let broken = Rc::clone(&backend.status_broken);
        let calls = Rc::clone(&backend.calls);
        let mut app = app_with_backend(backend);
        *broken.borrow_mut() = true;
        app.selected = 1;

        app.start_or_switch();
        assert!(calls.borrow().is_empty(), "no start or switch issued");
        let message = app.message.as_ref().unwrap();
        assert!(message.is_error);
        assert!(message.text.contains("could not be read"));

        app.restore_default();
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn flags_override_is_named_in_the_notice_too() {
        let backend = StubBackend::new();
        let truth = Rc::clone(&backend.truth);
        let mut app = app_with_backend(backend);
        *truth.borrow_mut() = Status {
            override_flags: Some(strs(&["-s", "1"])),
            ..running("scx_lavd", &[], "scx_lavd")
        };

        app.start_or_switch();
        let message = app.message.as_ref().unwrap();
        assert!(!message.is_error);
        assert!(message.text.contains("SCX_FLAGS_OVERRIDE"));
        assert!(!message.text.contains("SCX_SCHEDULER_OVERRIDE"));
    }

    fn type_str(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn args_field_owns_keys_and_queues_validated_flags() {
        let backend = StubBackend::new();
        let calls = Rc::clone(&backend.calls);
        let mut app = app_with_backend(backend);
        app.on_key(key(KeyCode::Char('a')));
        assert!(app.args_input.is_some());

        // 'q' quits globally, but inside the field it is just a letter;
        // Esc closes the field instead of quitting the app.
        app.on_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.on_key(key(KeyCode::Esc));
        assert!(app.args_input.is_none() && !app.should_quit);

        // A glob is refused and the field stays open to be fixed.
        app.on_key(key(KeyCode::Char('a')));
        type_str(&mut app, "--path=*");
        app.on_key(key(KeyCode::Enter));
        assert!(app.args_input.is_some());
        assert!(app.message.as_ref().unwrap().is_error);
        assert_eq!(app.pending_action, None);

        // Valid input: whitespace-split, queued, field closed, and the
        // queued action reaches the backend as custom flags.
        app.args_input = Some(ArgsInput::default());
        type_str(&mut app, "  -s 20000   --verbose ");
        app.last_action = None;
        app.on_key(key(KeyCode::Enter));
        assert!(app.args_input.is_none());
        let Some(PendingAction::StartOrSwitchWithArgs(args)) = app.pending_action.take() else {
            panic!("expected a queued with-args action");
        };
        assert_eq!(args, strs(&["-s", "20000", "--verbose"]));
        app.start_or_switch_with_args(&args);
        assert_eq!(
            calls.borrow().last(),
            Some(&Call::Start(
                "scx_bpfland".into(),
                strs(&["-s", "20000", "--verbose"])
            ))
        );
        assert!(app.message.as_ref().unwrap().text.contains("custom flags"));
    }

    #[test]
    fn restore_default_needs_a_configured_default() {
        let backend = StubBackend::new();
        let calls = Rc::clone(&backend.calls);
        let mut app = app_with_backend(backend);

        app.restore_default();
        assert!(app.message.as_ref().unwrap().is_error);
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn status_read_failure_is_surfaced_not_swallowed() {
        let backend = StubBackend::new();
        let truth = Rc::clone(&backend.truth);
        let broken = Rc::clone(&backend.status_broken);
        let mut app = app_with_backend(backend);

        *truth.borrow_mut() = running("scx_lavd", &[], "scx_lavd");
        app.refresh_status();
        assert!(app.status.is_some());
        assert_eq!(app.status_error, None);

        *broken.borrow_mut() = true;
        app.refresh_status();
        assert_eq!(app.status, None, "a stale snapshot must not survive");
        assert!(
            app.status_error
                .as_deref()
                .unwrap()
                .contains("status broken")
        );
    }

    #[test]
    fn actions_are_debounced() {
        let mut app = app_with_backend(StubBackend::new());
        app.on_key(key(KeyCode::Char('s')));
        assert_eq!(app.pending_action, Some(PendingAction::Stop));
        app.pending_action = None;
        // A second press inside the debounce window is swallowed.
        app.on_key(key(KeyCode::Char('r')));
        assert_eq!(app.pending_action, None);
    }

    #[test]
    fn refresh_keeps_the_selection_by_name() {
        let backend = StubBackend::new();
        let schedulers = Rc::clone(&backend.schedulers);
        let mut app = app_with_backend(backend);
        app.selected = 2; // scx_cake

        *schedulers.borrow_mut() = vec!["scx_cake".into(), "scx_flash".into()];
        app.on_key(key(KeyCode::Char('R')));
        assert_eq!(app.selected_scheduler(), Some("scx_cake"));
        assert!(!app.message.as_ref().unwrap().is_error);

        // A failed query keeps the old list and reports the error.
        schedulers.borrow_mut().clear();
        app.on_key(key(KeyCode::Char('R')));
        assert_eq!(app.schedulers.len(), 2);
        assert!(app.message.as_ref().unwrap().is_error);
    }

    fn disabled_kernel() -> KernelState {
        KernelState {
            state: "disabled".into(),
            ops: None,
        }
    }

    fn enabled_kernel(ops: &str) -> KernelState {
        KernelState {
            state: "enabled".into(),
            ops: Some(ops.into()),
        }
    }

    #[test]
    fn kernel_dispute_is_edge_triggered_and_rearms_after_refresh() {
        let backend = StubBackend::new();
        let truth = Rc::clone(&backend.truth);
        let queries = Rc::clone(&backend.status_queries);
        let mut app = app_with_backend(backend);
        *truth.borrow_mut() = running("scx_cake", &[], "scx_cake");

        // A standing dispute is not an edge; no hammering every tick.
        app.status = Some(running("scx_cake", &[], "scx_cake"));
        app.kernel = Some(disabled_kernel());
        app.kernel_disputed = true;
        assert!(!app.reconcile_kernel_dispute());
        assert_eq!(*queries.borrow(), 0);

        // Arm the edge; the stored bit is recomputed post-refresh.
        app.kernel_disputed = false;
        assert!(app.reconcile_kernel_dispute());
        assert_eq!(*queries.borrow(), 1);
        assert!(!app.kernel_disputed);

        // A new disagreement is a new edge with its own immediate refresh.
        app.status = Some(running("scx_cake", &[], "scx_cake"));
        app.kernel = Some(disabled_kernel());
        assert!(app.reconcile_kernel_dispute());
        assert_eq!(*queries.borrow(), 2);
    }

    #[test]
    fn kernel_warning_judges_the_process_not_the_file() {
        let mut app = app_with_backend(StubBackend::new());

        app.status = Some(Status::default());
        app.kernel = Some(enabled_kernel("lavd"));
        assert!(app.kernel_warning().unwrap().contains("outside"));

        app.status = Some(running("scx_lavd", &[], "scx_lavd"));
        app.kernel = Some(disabled_kernel());
        assert!(app.kernel_warning().unwrap().contains("no attached"));

        // File edited to scx_cake under a running scx_lavd: the kernel
        // runs lavd, which agrees with the process, so no warning.
        app.status = Some(running("scx_lavd", &[], "scx_cake"));
        app.kernel = Some(enabled_kernel("lavd"));
        assert_eq!(app.kernel_warning(), None);

        app.kernel = Some(enabled_kernel("bpfland_1.1.4"));
        assert!(app.kernel_warning().unwrap().contains("ops name"));

        // Active unit with an unreadable process: nothing to compare the
        // ops name against, so no mismatch is claimed.
        app.status = Some(Status {
            active: true,
            ..Status::default()
        });
        assert_eq!(app.kernel_warning(), None);
        app.kernel = Some(disabled_kernel());
        assert!(app.kernel_warning().unwrap().contains("process unknown"));
    }
}
