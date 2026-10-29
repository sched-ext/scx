// SPDX-License-Identifier: GPL-2.0

//! Application state and event loop.
//!
//! Everything that reads or changes `scx.service` goes through the
//! backend, which is `scxcli`. The app holds the last listing it got
//! back, the kernel's own view read every tick, and the selections of
//! the three views.

use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::backend::Backend;
use crate::kernel::{self, KernelState};
use crate::logs::{self, LogLine};
use crate::model::{DEFAULT_ID, Installed, Listing, Pick, validate_arg};
use crate::system::system_command;
use crate::ui;
use crate::watch::Watcher;

/// How often the input poll wakes up to redraw / refresh.
const TICK: Duration = Duration::from_millis(250);
/// Slow poll for what inotify cannot see: the unit's state and the
/// process behind it. The catalog and environment files are refreshed
/// on inotify events instead.
const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// Minimum spacing between two scheduler-affecting actions. Linux
/// terminals deliver key autorepeat as plain `Press` events, so without
/// this, holding Enter would fire one start per repeat.
const ACTION_DEBOUNCE: Duration = Duration::from_millis(500);
/// How long informational messages stay in the message bar. Errors are
/// exempt: they are actionable and stay until replaced.
const MESSAGE_TTL: Duration = Duration::from_secs(8);

/// Deferred user actions: queued by key handlers, executed by the event
/// loop right after the frame announcing them has been drawn. scxcli
/// blocks (a restart waits for the unit to come up, pkexec may prompt),
/// so the UI must show feedback before the call starts.
#[derive(Clone, Debug, PartialEq)]
enum PendingAction {
    Start(String),
    Run(String, Vec<String>),
    Stop,
    Monitor,
}

/// A single-line text field. The cursor is counted in characters, so
/// editing multi-byte input stays sound; the UI derives its cursor
/// block from the same count.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Input {
    pub buffer: String,
    pub cursor: usize,
}

impl Input {
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

    fn edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.len_chars()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.len_chars(),
            _ => {}
        }
    }
}

/// Which screen is shown.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum View {
    Recommended,
    All,
    Logs,
}

pub struct Message {
    pub text: String,
    pub is_error: bool,
    shown_at: Instant,
}

pub struct App {
    backend: Box<dyn Backend>,
    /// Listing with a catalog file of the caller's (`--catalog`): the
    /// lists are that file's, and a custom profile in them is not what
    /// the installed catalog would start under that id.
    pub preview_catalog: bool,
    /// Last successful listing. Stays `None` after a failed read, with
    /// the failure in `listing_error`, so the panel shows "unknown" plus
    /// the reason instead of a stale snapshot.
    pub listing: Option<Listing>,
    pub listing_error: Option<String>,
    /// The kernel's own view, re-read every tick.
    pub kernel: Option<KernelState>,
    read_kernel: Box<dyn Fn() -> Option<KernelState>>,
    kernel_disputed: bool,
    watcher: Option<Watcher>,
    pub selected: usize,
    pub sched_selected: usize,
    /// The options field of the full list, when open. While it is open
    /// it owns every key press, so global shortcuts cannot fire from
    /// typed text.
    pub args: Option<Input>,
    /// The full list's warning is shown once per session.
    pub all_warned: bool,
    pub message: Option<Message>,
    last_action: Option<Instant>,
    pub view: View,
    pub log_previous_boot: bool,
    pub log_lines: Vec<LogLine>,
    pub log_scroll: usize,
    pub log_page: usize,
    pending_action: Option<PendingAction>,
    should_quit: bool,
}

impl App {
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Self {
            backend,
            preview_catalog: false,
            listing: None,
            listing_error: None,
            kernel: None,
            read_kernel: Box::new(|| kernel::read().unwrap_or(None)),
            kernel_disputed: false,
            watcher: None,
            selected: 0,
            sched_selected: 0,
            args: None,
            all_warned: false,
            message: None,
            last_action: None,
            view: View::Recommended,
            log_previous_boot: false,
            log_lines: Vec::new(),
            log_scroll: 0,
            log_page: 20,
            pending_action: None,
            should_quit: false,
        }
    }

    pub fn backend_label(&self) -> String {
        self.backend.label()
    }

    pub fn recommended(&self) -> &[Pick] {
        self.listing
            .as_ref()
            .map_or(&[], |l| l.recommended.as_slice())
    }

    pub fn all(&self) -> &[Installed] {
        self.listing.as_ref().map_or(&[], |l| l.all.as_slice())
    }

    pub fn selected_pick(&self) -> Option<&Pick> {
        self.recommended().get(self.selected)
    }

    pub fn selected_scheduler(&self) -> Option<&Installed> {
        self.all().get(self.sched_selected)
    }

    pub fn run(&mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut last_refresh = Instant::now();
        let mut primed = false;
        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, self))?;

            // First frame is a skeleton; the initial fetch happens right
            // after it is on screen and the immediate redraw fills it in.
            if !primed {
                primed = true;
                self.refresh();
                self.sync_selection_to_running();
                self.start_watching();
                last_refresh = Instant::now();
                continue;
            }

            if self
                .message
                .as_ref()
                .is_some_and(|m| !m.is_error && m.shown_at.elapsed() >= MESSAGE_TTL)
            {
                self.message = None;
            }

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

            self.kernel = (self.read_kernel)();

            let files_changed = self.watcher.as_mut().is_some_and(Watcher::changed);
            if files_changed
                || self.reconcile_kernel_dispute()
                || last_refresh.elapsed() >= REFRESH_EVERY
            {
                self.refresh();
                last_refresh = Instant::now();
            }
        }
        Ok(())
    }

    fn start_watching(&mut self) {
        let config = self.listing.as_ref().and_then(|l| l.config.clone());
        let mut files = Watcher::files_for(config.as_deref());
        // A catalog given on the command line is a file like the
        // others: a change to it refreshes the lists.
        if let Some(source) = self.listing.as_ref().map(|l| l.source.clone())
            && !files.contains(&source)
        {
            files.push(source);
        }
        match Watcher::new(&files) {
            Ok(watcher) => self.watcher = Some(watcher),
            Err(err) => self.error(&format!("file watching unavailable ({err:#}); polling")),
        }
    }

    /// Hands the terminal over to `scxtop` and takes it back afterwards.
    fn run_monitor(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        let Ok(mut command) = system_command("scxtop") else {
            self.error(
                "scxtop not found in systemd's default search path; install it (cargo install \
scxtop, or your distro's scx tools package)",
            );
            return Ok(());
        };
        ratatui::restore();
        let result = command.status();
        *terminal = ratatui::init();
        terminal.clear()?;
        match result {
            Ok(status) if status.success() => self.info("scxtop exited"),
            Ok(status) => self.error(&format!(
                "scxtop exited with {status}; it needs root/CAP_BPF"
            )),
            Err(err) => self.error(&format!("failed to launch scxtop: {err}")),
        }
        Ok(())
    }

    fn queue(&mut self, action: PendingAction) {
        self.info("working...");
        self.pending_action = Some(action);
    }

    /// Runs a privileged scxcli command. When it goes through pkexec
    /// the terminal is handed over for the duration, because pkexec may
    /// prompt for a password on it (a text agent when the session has
    /// no graphical one); with the shipped policy starting a scheduler
    /// from the list prompts for nothing and the hand-over is a flicker.
    fn privileged(
        &mut self,
        terminal: &mut DefaultTerminal,
        call: impl FnOnce(&dyn Backend) -> Result<String>,
    ) -> Result<Result<String>> {
        if !self.backend.escalates() {
            return Ok(call(self.backend.as_ref()));
        }
        ratatui::restore();
        let result = call(self.backend.as_ref());
        *terminal = ratatui::init();
        terminal.clear()?;
        Ok(result)
    }

    fn run_action(&mut self, action: PendingAction, terminal: &mut DefaultTerminal) -> Result<()> {
        let outcome = match action {
            PendingAction::Start(id) => self
                .privileged(terminal, |b| b.start(&id))?
                .map(|report| format!("{report}; see State and Kernel for what attached")),
            PendingAction::Run(sched, args) => {
                self.privileged(terminal, |b| b.run(&sched, &args))?
            }
            PendingAction::Stop => self.privileged(terminal, |b| b.stop())?,
            PendingAction::Monitor => return self.run_monitor(terminal),
        };
        match outcome {
            Ok(text) => self.info(&text),
            Err(err) => self.error(&format!("{err:#}")),
        }
        self.refresh();
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent) {
        if self.args.is_some() {
            self.on_key_args(key);
            return;
        }
        match self.view {
            View::Recommended => self.on_key_recommended(key),
            View::All => self.on_key_all(key),
            View::Logs => self.on_key_logs(key),
        }
    }

    fn on_key_args(&mut self, key: KeyEvent) {
        let Some(input) = self.args.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.args = None,
            KeyCode::Enter => self.submit_args(),
            _ => input.edit(key),
        }
    }

    fn submit_args(&mut self) {
        let Some(input) = self.args.clone() else {
            return;
        };
        let args: Vec<String> = input.buffer.split_whitespace().map(str::to_owned).collect();
        if let Some(err) = args.iter().find_map(|arg| validate_arg(arg).err()) {
            self.error(&format!("{err:#}"));
            return;
        }
        let Some(sched) = self.selected_scheduler().map(|s| s.name.clone()) else {
            return;
        };
        if self.action_allowed() {
            self.args = None;
            self.queue(PendingAction::Run(sched, args));
        }
    }

    fn on_key_recommended(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('A') => self.open_all(),
            KeyCode::Char('t') => {
                if self.action_allowed() {
                    self.pending_action = Some(PendingAction::Monitor);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, self.recommended().len(), true);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, self.recommended().len(), false);
            }
            KeyCode::Enter => self.start_selected_pick(),
            KeyCode::Char('s') => self.stop_running(),
            KeyCode::Char('R') => {
                self.refresh();
                if self.listing.is_some() {
                    self.info("refreshed");
                }
            }
            _ => {}
        }
    }

    fn on_key_all(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('A') => {
                self.view = View::Recommended;
            }
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('t') => {
                if self.action_allowed() {
                    self.pending_action = Some(PendingAction::Monitor);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.sched_selected = step(self.sched_selected, self.all().len(), true);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.sched_selected = step(self.sched_selected, self.all().len(), false);
            }
            KeyCode::Char('a') => {
                if self.selected_scheduler().is_some() {
                    self.args = Some(Input::default());
                }
            }
            KeyCode::Enter => {
                if let Some(sched) = self.selected_scheduler().map(|s| s.name.clone())
                    && self.action_allowed()
                {
                    self.queue(PendingAction::Start(sched));
                }
            }
            KeyCode::Char('s') => self.stop_running(),
            KeyCode::Char('R') => {
                self.refresh();
                if self.listing.is_some() {
                    self.info("refreshed");
                }
            }
            _ => {}
        }
    }

    fn on_key_logs(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q' | 'l') | KeyCode::Esc => self.view = View::Recommended,
            KeyCode::Up | KeyCode::Char('k') => self.log_scroll = self.log_scroll.saturating_add(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_scroll = self.log_scroll.saturating_sub(1);
            }
            KeyCode::PageUp => self.log_scroll = self.log_scroll.saturating_add(self.log_page),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(self.log_page),
            KeyCode::Char('g') => self.log_scroll = usize::MAX,
            KeyCode::Char('G') => self.log_scroll = 0,
            KeyCode::Char('b') => {
                self.log_previous_boot = !self.log_previous_boot;
                self.reload_logs();
            }
            KeyCode::Char('R') => self.reload_logs(),
            _ => {}
        }
    }

    fn open_all(&mut self) {
        self.view = View::All;
        if !self.all_warned {
            self.all_warned = true;
            self.info(
                "all schedulers: one unsuited to the workload can perform worse than the \
kernel's default; the recommended ones are marked",
            );
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
                    "; older entries omitted, see journalctl for the full log"
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

    /// Aligns the selections with what runs, so the first Enter acts
    /// on what the user sees. Only on startup, never on a refresh,
    /// which must not fight the user's own selection.
    fn sync_selection_to_running(&mut self) {
        let Some(listing) = &self.listing else {
            return;
        };
        let Some(name) = listing.current.scheduler.as_deref() else {
            return;
        };
        // The profile whose command runs, by the command: a running
        // `latency` lands on `latency`, not on the plain `scx_eevdf`
        // above it. With no such profile (a `run`), the plain one.
        let by_command = listing
            .recommended
            .iter()
            .position(|p| is_running_pick(listing, p));
        let by_name = listing.recommended.iter().position(|p| p.id == name);
        if let Some(idx) = by_command.or(by_name) {
            self.selected = idx;
        }
        if let Some(idx) = listing.all.iter().position(|s| s.name == name) {
            self.sched_selected = idx;
        }
    }

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

    /// Enter in the recommended list: `scxcli start ID`. The same call
    /// whether the entry is stopped, failed or running something else;
    /// scxcli rewrites the file and restarts the unit either way.
    fn start_selected_pick(&mut self) {
        let Some(pick) = self.selected_pick() else {
            return;
        };
        if !pick.available {
            self.error(&format!("{} is not installed", pick.id));
            return;
        }
        // The command on screen is this file's; what `start ID` runs
        // is the installed catalog's, which may have no such id or
        // another command under it. `default` and a plain profile are
        // the same command under every catalog, so those start; a
        // custom profile is only looked at here.
        if self.preview_catalog && pick.is_custom() {
            self.error(&format!(
                "{} is a profile of the catalog file being previewed; the installed catalog \
decides what `start {}` runs, so start it from scxtui without --catalog",
                pick.id, pick.id
            ));
            return;
        }
        let id = pick.id.clone();
        if self.action_allowed() {
            self.queue(PendingAction::Start(id));
        }
    }

    /// `s`: stop the unit and keep the selection, so it comes back on
    /// the next start or boot. Not `start default`, which forgets it.
    fn stop_running(&mut self) {
        let active = self.listing.as_ref().is_some_and(|l| l.current.unit.active);
        if !active {
            self.info("nothing is running");
            return;
        }
        if self.action_allowed() {
            self.queue(PendingAction::Stop);
        }
    }

    /// A failed read clears the snapshot and records why.
    fn refresh(&mut self) {
        match self.backend.list() {
            Ok(listing) => {
                // The cursor follows the entry, not its position: a
                // catalog change (or an installation) that moves the
                // focused scheduler leaves it focused. Only an entry
                // that is gone falls back to the clamped position.
                let pick = self.selected_pick().map(|p| p.id.clone());
                let sched = self.selected_scheduler().map(|s| s.name.clone());
                self.selected = pick
                    .and_then(|id| listing.recommended.iter().position(|p| p.id == id))
                    .unwrap_or(
                        self.selected
                            .min(listing.recommended.len().saturating_sub(1)),
                    );
                self.sched_selected = sched
                    .and_then(|name| listing.all.iter().position(|s| s.name == name))
                    .unwrap_or(self.sched_selected.min(listing.all.len().saturating_sub(1)));
                self.listing = Some(listing);
                self.listing_error = None;
            }
            Err(err) => {
                self.listing = None;
                self.listing_error = Some(format!("{err:#}"));
            }
        }
        self.kernel = (self.read_kernel)();
    }

    /// The panel's warning; the event loop reuses it as a tripwire.
    pub fn kernel_warning(&self) -> Option<String> {
        let kernel = self.kernel.as_ref()?;
        let current = &self.listing.as_ref()?.current;
        let running = current.running.as_ref().map(|r| r.sched.as_str());
        match (current.unit.active, running, kernel.enabled()) {
            (false, _, true) => {
                Some("a scheduler is attached outside of scx.service's control".to_owned())
            }
            (true, running, false) => Some(format!(
                "scx.service is active ({}), but the kernel shows no attached scheduler",
                running.unwrap_or("process unknown")
            )),
            (true, Some(sched), true) if !kernel.matches(sched) => {
                let ops = kernel.ops.as_deref().unwrap_or("?");
                Some(format!(
                    "scx.service runs {sched}, but the kernel ops name is \"{ops}\""
                ))
            }
            _ => None,
        }
    }

    /// Edge-triggered: re-asks once per new dispute.
    fn reconcile_kernel_dispute(&mut self) -> bool {
        let disputed = self.kernel_warning().is_some();
        let fire = disputed && !self.kernel_disputed;
        self.kernel_disputed = disputed;
        fire
    }

    /// An error-styled message that stays until replaced, for a
    /// condition found before the loop starts.
    pub fn warn(&mut self, text: &str) {
        self.error(text);
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

fn step(idx: usize, len: usize, forward: bool) -> usize {
    if len == 0 {
        0
    } else if forward {
        (idx + 1) % len
    } else {
        (idx + len - 1) % len
    }
}

/// Whether `id` is the entry that runs, for the lists' marker: the
/// running scheduler's name, or `default` while the kernel's own runs.
pub fn is_running(listing: &Listing, id: &str) -> bool {
    listing.current.scheduler.as_deref() == Some(id)
}

/// Whether the profile's command is what runs: its scheduler, by the
/// kernel's word, with exactly its options. Not every profile on that
/// scheduler: `latency` running is not `scx_eevdf` with its defaults
/// running, and the lists say which.
pub fn is_running_pick(listing: &Listing, pick: &Pick) -> bool {
    let current = &listing.current;
    match pick.sched_name() {
        None => current.scheduler.as_deref() == Some(DEFAULT_ID),
        Some(sched) => {
            current.scheduler.as_deref() == Some(sched)
                && current
                    .running
                    .as_ref()
                    .is_some_and(|r| pick.is_command(&r.sched, &r.args))
        }
    }
}

/// Whether the profile's command is what the next start would run,
/// for the lists' second marker: a selection that is stopped or
/// failed. Options that are no profile's are a `run`, and a `run` is
/// not a selection.
pub fn is_selected_pick(listing: &Listing, pick: &Pick) -> bool {
    match (&listing.current.next, pick.sched_name()) {
        (Some(next), Some(sched)) => {
            !next.overridden && pick.is_command(sched, &next.args) && next.name() == sched
        }
        (Some(_), None) => false,
        (None, sched) => sched.is_none(),
    }
}

/// Whether `name` is what the next start would run, for the full
/// list: with no options, or with a profile's. A `run` is not a
/// selection.
pub fn is_selected(listing: &Listing, name: &str) -> bool {
    match &listing.current.next {
        Some(next) => {
            !next.overridden
                && next.name() == name
                && (next.args.is_empty()
                    || listing
                        .recommended
                        .iter()
                        .any(|p| p.is_command(name, &next.args)))
        }
        None => name == DEFAULT_ID,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::model::{Current, Running, Unit};
    use anyhow::anyhow;

    use super::*;

    #[derive(Debug, PartialEq)]
    enum Call {
        Start(String),
        Run(String, Vec<String>),
        Stop,
    }

    struct Stub {
        listing: Rc<RefCell<Listing>>,
        broken: Rc<RefCell<bool>>,
        calls: Rc<RefCell<Vec<Call>>>,
    }

    fn pick(id: &str, available: bool) -> Pick {
        Pick {
            id: id.into(),
            label: id.into(),
            description: String::new(),
            sched: None,
            args: Vec::new(),
            path: (id != DEFAULT_ID && available).then(|| format!("/usr/bin/{id}")),
            available,
        }
    }

    fn profile(id: &str, sched: &str, args: &[&str]) -> Pick {
        Pick {
            sched: Some(sched.into()),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            path: Some(format!("/usr/bin/{sched}")),
            ..pick(id, true)
        }
    }

    fn installed(name: &str, recommended: bool) -> Installed {
        Installed {
            name: name.into(),
            path: format!("/usr/bin/{name}"),
            recommended,
            featured: recommended,
            tier: crate::model::Tier::Stable,
        }
    }

    fn listing() -> Listing {
        Listing {
            version: crate::model::OUTPUT_VERSION,
            source: "/usr/share/scx/catalog.json".into(),
            customized: false,
            recommended: vec![
                pick("default", true),
                pick("scx_cosmos", true),
                pick("scx_eevdf", false),
                profile("latency", "scx_cosmos", &["--slice-us", "1600"]),
            ],
            all: vec![
                installed("scx_bpfland", false),
                installed("scx_cosmos", true),
            ],
            config: Some("/etc/default/scx".into()),
            current: Current {
                version: crate::model::OUTPUT_VERSION,
                scheduler: Some("scx_cosmos".into()),
                unit: Unit {
                    active: true,
                    enabled: true,
                },
                running: Some(Running {
                    sched: "scx_cosmos".into(),
                    args: Vec::new(),
                }),
                next: Some(crate::model::Next {
                    sched: "/usr/bin/scx_cosmos".into(),
                    args: Vec::new(),
                    overridden: false,
                }),
                kernel: None,
                failure: None,
                config_error: None,
            },
        }
    }

    impl Backend for Stub {
        fn label(&self) -> String {
            "stub".into()
        }
        fn list(&self) -> Result<Listing> {
            if *self.broken.borrow() {
                return Err(anyhow!("list broken"));
            }
            Ok(self.listing.borrow().clone())
        }
        fn start(&self, id: &str) -> Result<String> {
            self.calls.borrow_mut().push(Call::Start(id.into()));
            let mut l = self.listing.borrow_mut();
            l.current.unit.active = id != DEFAULT_ID;
            l.current.scheduler = Some(id.into());
            Ok(format!("started {id}"))
        }
        fn run(&self, sched: &str, args: &[String]) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(Call::Run(sched.into(), args.to_vec()));
            Ok("running".into())
        }
        fn stop(&self) -> Result<String> {
            self.calls.borrow_mut().push(Call::Stop);
            let mut l = self.listing.borrow_mut();
            l.current.unit.active = false;
            l.current.running = None;
            l.current.scheduler = Some(DEFAULT_ID.into());
            Ok("stopped".into())
        }
        fn escalates(&self) -> bool {
            false
        }
    }

    struct Harness {
        app: App,
        calls: Rc<RefCell<Vec<Call>>>,
        listing: Rc<RefCell<Listing>>,
        broken: Rc<RefCell<bool>>,
    }

    fn app() -> Harness {
        let listing = Rc::new(RefCell::new(listing()));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let broken = Rc::new(RefCell::new(false));
        let stub = Stub {
            listing: listing.clone(),
            broken: broken.clone(),
            calls: calls.clone(),
        };
        let mut app = App::new(Box::new(stub));
        app.read_kernel = Box::new(|| None);
        app.refresh();
        app.sync_selection_to_running();
        Harness {
            app,
            calls,
            listing,
            broken,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn drain(app: &mut App) {
        // The event loop would run it after a draw; tests run the
        // backend call directly.
        if let Some(action) = app.pending_action.take() {
            let outcome = match action {
                PendingAction::Start(id) => app.backend.start(&id),
                PendingAction::Run(s, a) => app.backend.run(&s, &a),
                PendingAction::Stop => app.backend.stop(),
                PendingAction::Monitor => Ok(String::new()),
            };
            assert!(outcome.is_ok());
            app.refresh();
        }
    }

    #[test]
    fn startup_selects_the_running_scheduler_in_both_lists() {
        let Harness { app, .. } = app();
        assert_eq!(app.selected_pick().unwrap().id, "scx_cosmos");
        assert_eq!(app.selected_scheduler().unwrap().name, "scx_cosmos");
    }

    #[test]
    fn a_refresh_keeps_the_focused_scheduler_when_the_lists_reorder() {
        let Harness {
            mut app, listing, ..
        } = app();
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected_pick().unwrap().id, "scx_eevdf");
        app.on_key(key(KeyCode::Char('A')));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.selected_scheduler().unwrap().name, "scx_bpfland");

        // Another catalog: eevdf moves to the top of the recommended
        // list, a new scheduler lands before bpfland in the full one.
        {
            let mut l = listing.borrow_mut();
            l.recommended = vec![
                pick("scx_eevdf", true),
                pick("default", true),
                pick("scx_cosmos", true),
            ];
            l.all.insert(0, installed("scx_aaa", false));
        }
        app.refresh();
        assert_eq!(app.selected_pick().unwrap().id, "scx_eevdf");
        assert_eq!(app.selected_scheduler().unwrap().name, "scx_bpfland");

        // An entry that is gone: the cursor stays where it was, clamped.
        {
            let mut l = listing.borrow_mut();
            l.recommended.retain(|p| p.id != "scx_eevdf");
            l.all.retain(|s| s.name != "scx_bpfland");
        }
        app.refresh();
        assert_eq!(app.selected_pick().unwrap().id, "default");
        assert_eq!(app.selected_scheduler().unwrap().name, "scx_cosmos");
    }

    #[test]
    fn enter_starts_the_selected_entry_but_not_an_unavailable_one() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Start("scx_cosmos".into())]);

        app.last_action = None;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected_pick().unwrap().id, "scx_eevdf");
        app.on_key(key(KeyCode::Enter));
        assert!(app.pending_action.is_none());
        assert!(app.message.as_ref().unwrap().is_error);
        assert_eq!(calls.borrow().len(), 1);

        // A custom profile starts by its id, like any entry.
        app.last_action = None;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected_pick().unwrap().id, "latency");
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(calls.borrow().last(), Some(&Call::Start("latency".into())));

        // Default is an entry like any other: `start default`.
        app.last_action = None;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected_pick().unwrap().id, "default");
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(calls.borrow().last(), Some(&Call::Start("default".into())));
    }

    #[test]
    fn start_is_debounced() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        app.on_key(key(KeyCode::Enter));
        assert!(
            app.pending_action.is_none(),
            "second press within the window is swallowed"
        );
        assert_eq!(calls.borrow().len(), 1);
    }

    #[test]
    fn stop_keeps_the_selection_and_marks_it() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('s')));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Stop]);
        let listing = app.listing.as_ref().unwrap();
        assert!(!listing.current.unit.active);
        assert!(is_running(listing, "default"));
        assert!(is_running_pick(listing, &pick("default", true)));
        assert!(is_selected(listing, "scx_cosmos"));
        assert!(is_selected_pick(listing, &pick("scx_cosmos", true)));
        assert!(!is_selected(listing, "default"));

        // Stopping with nothing running is a message, not a call.
        app.last_action = None;
        app.on_key(key(KeyCode::Char('s')));
        assert!(app.pending_action.is_none());
        assert!(!app.message.as_ref().unwrap().is_error);
        assert_eq!(calls.borrow().len(), 1);
    }

    #[test]
    fn the_selection_marker_ignores_runs_and_overrides() {
        let Harness { listing, .. } = app();
        let mut l = listing.borrow().clone();
        assert!(is_selected(&l, "scx_cosmos"));
        l.current.next.as_mut().unwrap().args = vec!["-v".into()];
        assert!(!is_selected(&l, "scx_cosmos"), "a run is not a selection");
        // A profile's options are a selection: of the profile in the
        // recommended list, and of its scheduler in the full one.
        l.current.next.as_mut().unwrap().args = vec!["--slice-us".into(), "1600".into()];
        assert!(is_selected(&l, "scx_cosmos"));
        assert!(is_selected_pick(&l, &l.recommended[3]));
        assert!(
            !is_selected_pick(&l, &l.recommended[1]),
            "not the plain profile"
        );
        l.current.next.as_mut().unwrap().args.clear();
        l.current.next.as_mut().unwrap().overridden = true;
        assert!(!is_selected(&l, "scx_cosmos"));
        l.current.next = None;
        assert!(is_selected(&l, "default"));
    }

    /// The running mark lands on the profile whose command runs and on
    /// no other profile of that scheduler, and startup focuses it.
    #[test]
    fn a_running_profile_is_marked_and_focused_by_its_command() {
        let Harness {
            mut app, listing, ..
        } = app();
        {
            let mut l = listing.borrow_mut();
            let args = vec!["--slice-us".to_owned(), "1600".to_owned()];
            l.current.running.as_mut().unwrap().args = args.clone();
            l.current.next.as_mut().unwrap().args = args;
        }
        app.refresh();
        app.sync_selection_to_running();
        assert_eq!(app.selected_pick().unwrap().id, "latency");
        let l = app.listing.as_ref().unwrap();
        assert!(is_running_pick(l, &l.recommended[3]));
        assert!(
            !is_running_pick(l, &l.recommended[1]),
            "cosmos with defaults is not running"
        );
        assert!(
            is_running(l, "scx_cosmos"),
            "the full list marks the scheduler"
        );
        // A `run` with options no profile has marks no profile; the
        // focus falls back to the plain one.
        {
            let mut l = listing.borrow_mut();
            l.current.running.as_mut().unwrap().args = vec!["-v".into()];
        }
        app.refresh();
        app.sync_selection_to_running();
        assert_eq!(app.selected_pick().unwrap().id, "scx_cosmos");
        let l = app.listing.as_ref().unwrap();
        assert!(l.recommended.iter().all(|p| !is_running_pick(l, p)));
    }

    /// With `--catalog`, Enter on a custom profile is refused, since
    /// the installed catalog decides what `start ID` runs; a plain
    /// profile and `default` are the same command under every catalog.
    #[test]
    fn a_previewed_catalogs_custom_profile_does_not_start() {
        let Harness { mut app, calls, .. } = app();
        app.preview_catalog = true;
        app.selected = 3;
        assert_eq!(app.selected_pick().unwrap().id, "latency");
        app.on_key(key(KeyCode::Enter));
        assert!(app.pending_action.is_none());
        let message = app.message.as_ref().unwrap();
        assert!(
            message.is_error && message.text.contains("previewed"),
            "{}",
            message.text
        );
        assert!(calls.borrow().is_empty());

        app.selected = 1;
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Start("scx_cosmos".into())]);
        app.last_action = None;
        app.selected = 0;
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(calls.borrow().last(), Some(&Call::Start("default".into())));
    }

    #[test]
    fn the_full_list_starts_with_defaults_or_runs_with_typed_options() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('A')));
        assert_eq!(app.view, View::All);
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.selected_scheduler().unwrap().name, "scx_bpfland");
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Start("scx_bpfland".into())]);

        app.last_action = None;
        app.on_key(key(KeyCode::Char('a')));
        for c in "-m performance".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(
            calls.borrow().last(),
            Some(&Call::Run(
                "scx_bpfland".into(),
                vec!["-m".into(), "performance".into()]
            ))
        );
        assert!(app.args.is_none());
    }

    #[test]
    fn typed_options_are_validated_before_anything_runs() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('A')));
        app.on_key(key(KeyCode::Char('a')));
        for c in "$(id)".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert!(app.args.is_some(), "the field stays open to fix");
        assert!(app.message.as_ref().unwrap().is_error);
        assert!(calls.borrow().is_empty());
        // Global shortcuts do not fire from inside the field.
        app.on_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.on_key(key(KeyCode::Esc));
        assert!(app.args.is_none());
    }

    #[test]
    fn a_failed_listing_clears_the_snapshot_and_keeps_selection_sane() {
        let Harness {
            mut app,
            listing,
            broken,
            ..
        } = app();
        *broken.borrow_mut() = true;
        app.refresh();
        assert!(app.listing.is_none());
        assert!(app.listing_error.is_some());
        assert!(app.selected_pick().is_none());
        app.on_key(key(KeyCode::Enter));
        assert!(app.pending_action.is_none());

        *broken.borrow_mut() = false;
        listing.borrow_mut().recommended.truncate(1);
        app.selected = 2;
        app.refresh();
        assert_eq!(app.selected, 0);
    }

    /// Every view draws on a small terminal, with the panel's lines
    /// wrapping rather than the frame failing, and the words the panel
    /// is built on are the ones on screen.
    #[test]
    fn every_view_draws_at_80x24() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let Harness { mut app, .. } = app();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for view in [View::Recommended, View::All, View::Logs] {
            app.view = view;
            terminal.draw(|frame| ui::draw(frame, &mut app)).unwrap();
        }
        app.view = View::All;
        app.on_key(key(KeyCode::Char('a')));
        terminal.draw(|frame| ui::draw(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("State:"));
        assert!(text.contains("Configured:"));
        assert!(text.contains("Focused:"));
        assert!(!text.contains("Selected:"));
    }

    /// The cursor lands on the scheduler, never on the header above
    /// the first scheduler of a group: the headers are items of their
    /// own and the selection is mapped past them.
    #[test]
    fn the_cursor_marks_the_first_scheduler_of_each_group_not_its_header() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let Harness {
            mut app, listing, ..
        } = app();
        {
            let mut l = listing.borrow_mut();
            let tiered = |name: &str, tier| Installed {
                name: name.into(),
                path: format!("/usr/bin/{name}"),
                recommended: false,
                featured: false,
                tier,
            };
            l.all = vec![
                installed("scx_cosmos", true),
                installed("scx_rusty", false),
                tiered("scx_flow", crate::model::Tier::Experimental),
                tiered("scx_mlfq", crate::model::Tier::Experimental),
                tiered("scx_rake", crate::model::Tier::Unknown),
            ];
        }
        app.refresh();
        app.view = View::All;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for (idx, name) in [(0, "cosmos"), (2, "flow"), (4, "rake")] {
            app.sched_selected = idx;
            terminal.draw(|frame| ui::draw(frame, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            let width = usize::from(buffer.area.width);
            let rows: Vec<String> = buffer
                .content()
                .chunks(width)
                .map(|cells| cells.iter().map(|c| c.symbol()).collect())
                .collect();
            let marked: Vec<&String> = rows.iter().filter(|r| r.contains('\u{25b6}')).collect();
            assert_eq!(marked.len(), 1, "one cursor on screen for {name}");
            let row = marked[0];
            assert!(row.contains(name), "cursor row for {name}: {row:?}");
            for header in ["stable", "experimental", "not in the catalog", "\u{2500}"] {
                assert!(
                    !row.contains(header),
                    "cursor on a header for {name}: {row:?}"
                );
            }
        }
    }

    #[test]
    fn kernel_warnings_follow_the_unit_and_the_kernel() {
        let Harness { mut app, .. } = app();
        app.kernel = Some(KernelState {
            state: "enabled".into(),
            ops: Some("rusty".into()),
        });
        assert!(app.kernel_warning().unwrap().contains("ops name"));
        app.kernel = Some(KernelState {
            state: "disabled".into(),
            ops: None,
        });
        assert!(
            app.kernel_warning()
                .unwrap()
                .contains("no attached scheduler")
        );
        assert!(app.reconcile_kernel_dispute());
        assert!(!app.reconcile_kernel_dispute(), "edge-triggered");
    }
}
