// SPDX-License-Identifier: GPL-2.0

//! Application state and event loop.
//!
//! Everything that reads or changes the profiles and `scx.service` goes
//! through the backend, which is `scxcli`. The app holds the last
//! listing it got back, the kernel's own view read every tick, and the
//! selections and fields of the three views.

use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::backend::ProfileBackend;
use crate::kernel::{self, KernelState};
use crate::logs::{self, LogLine};
use crate::model::{
    DEFAULT_ID, Entry, FORMAT_VERSION, Listing, Profile, ProfilesFile, validate_arg, validate_id,
};
use crate::system::system_command;
use crate::ui;
use crate::watch::Watcher;

/// How often the input poll wakes up to redraw / refresh.
const TICK: Duration = Duration::from_millis(250);
/// Slow poll for what inotify cannot see: the unit's state and the
/// process behind it. The profile and environment files are refreshed
/// on inotify events instead.
const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// Minimum spacing between two scheduler-affecting actions. Linux
/// terminals deliver key autorepeat as plain `Press` events, so without
/// this, holding Enter would fire one apply per repeat.
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
    Apply(String),
    Run(String, Vec<String>),
    SaveList(ProfilesFile, String),
    Reset,
    Stop,
    Start,
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

/// What an open text field is for. While one is open it owns every key
/// press, so global shortcuts cannot fire from typed text.
#[derive(Clone, Debug, PartialEq)]
pub enum Field {
    /// Advanced view: options for the selected scheduler, run on Enter.
    Args,
    /// Profiles view: the id of a new profile made from what runs now.
    SaveAs { sched: String, args: Vec<String> },
    /// Profiles view: `y` deletes the named profile.
    ConfirmDelete(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenField {
    pub field: Field,
    pub input: Input,
}

/// Which screen is shown.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum View {
    Profiles,
    Advanced,
    Logs,
}

pub struct Message {
    pub text: String,
    pub is_error: bool,
    shown_at: Instant,
}

pub struct App {
    backend: Box<dyn ProfileBackend>,
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
    pub field: Option<OpenField>,
    /// The advanced view's warning is shown once per session.
    pub advanced_warned: bool,
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
    pub fn new(backend: Box<dyn ProfileBackend>) -> Self {
        Self {
            backend,
            listing: None,
            listing_error: None,
            kernel: None,
            read_kernel: Box::new(|| kernel::read().unwrap_or(None)),
            kernel_disputed: false,
            watcher: None,
            selected: 0,
            sched_selected: 0,
            field: None,
            advanced_warned: false,
            message: None,
            last_action: None,
            view: View::Profiles,
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

    pub fn profiles(&self) -> &[Entry] {
        self.listing.as_ref().map_or(&[], |l| l.profiles.as_slice())
    }

    pub fn installed(&self) -> &[String] {
        self.listing
            .as_ref()
            .map_or(&[], |l| l.installed.as_slice())
    }

    pub fn selected_profile(&self) -> Option<&Entry> {
        self.profiles().get(self.selected)
    }

    pub fn selected_scheduler(&self) -> Option<&str> {
        self.installed()
            .get(self.sched_selected)
            .map(String::as_str)
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
        match Watcher::new(&Watcher::files_for(config.as_deref())) {
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
    /// no graphical one); with the shipped policy applying a profile
    /// prompts for nothing and the hand-over is a flicker.
    fn privileged(
        &mut self,
        terminal: &mut DefaultTerminal,
        call: impl FnOnce(&dyn ProfileBackend) -> Result<String>,
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
            PendingAction::Apply(id) => self
                .privileged(terminal, |b| b.apply(&id))?
                .map(|report| format!("{report}; see State and Kernel for what attached")),
            PendingAction::Run(sched, args) => {
                self.privileged(terminal, |b| b.run(&sched, &args))?
            }
            PendingAction::SaveList(profiles, what) => self
                .privileged(terminal, |b| b.save(&profiles))?
                .map(|report| format!("{what}: {report}")),
            PendingAction::Reset => self.privileged(terminal, |b| b.reset())?,
            PendingAction::Stop => self.privileged(terminal, |b| b.stop())?,
            PendingAction::Start => self.privileged(terminal, |b| b.start())?,
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
        if self.field.is_some() {
            self.on_key_field(key);
            return;
        }
        match self.view {
            View::Profiles => self.on_key_profiles(key),
            View::Advanced => self.on_key_advanced(key),
            View::Logs => self.on_key_logs(key),
        }
    }

    fn on_key_field(&mut self, key: KeyEvent) {
        let Some(open) = self.field.as_mut() else {
            return;
        };
        match (&open.field, key.code) {
            (_, KeyCode::Esc) => self.field = None,
            (Field::ConfirmDelete(id), KeyCode::Char('y' | 'Y')) => {
                let id = id.clone();
                self.field = None;
                self.delete_profile(&id);
            }
            (Field::ConfirmDelete(_), _) => self.field = None,
            (_, KeyCode::Enter) => self.submit_field(),
            _ => open.input.edit(key),
        }
    }

    fn submit_field(&mut self) {
        let Some(open) = self.field.clone() else {
            return;
        };
        match open.field {
            Field::Args => {
                let args: Vec<String> = open
                    .input
                    .buffer
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
                if let Some(err) = args.iter().find_map(|arg| validate_arg(arg).err()) {
                    self.error(&format!("{err:#}"));
                    return;
                }
                let Some(sched) = self.selected_scheduler().map(str::to_owned) else {
                    return;
                };
                if self.action_allowed() {
                    self.field = None;
                    self.queue(PendingAction::Run(sched, args));
                }
            }
            Field::SaveAs { sched, args } => {
                let id = open.input.buffer.trim().to_owned();
                if let Err(err) = validate_id(&id) {
                    self.error(&format!("{err:#}"));
                    return;
                }
                if self.profiles().iter().any(|p| p.id == id) {
                    self.error(&format!("a profile {id:?} already exists"));
                    return;
                }
                let mut profiles = self.current_profiles();
                profiles.profiles.push(Profile {
                    id: id.clone(),
                    label: label_from_id(&id),
                    // The scheduler and options are shown under every
                    // profile anyway; a generated description from them
                    // could run past the contract's 256 characters.
                    description: SAVED_DESCRIPTION.to_owned(),
                    action: None,
                    sched: Some(sched),
                    args,
                });
                if self.action_allowed() {
                    self.field = None;
                    self.queue(PendingAction::SaveList(profiles, format!("saved {id}")));
                }
            }
            Field::ConfirmDelete(_) => self.field = None,
        }
    }

    fn on_key_profiles(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('A') => self.open_advanced(),
            KeyCode::Char('t') => {
                if self.action_allowed() {
                    self.pending_action = Some(PendingAction::Monitor);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = step(self.selected, self.profiles().len(), true);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = step(self.selected, self.profiles().len(), false);
            }
            KeyCode::Enter => self.apply_selected(),
            KeyCode::Char('s') => self.stop_running(),
            KeyCode::Char('J') => self.move_selected(true),
            KeyCode::Char('K') => self.move_selected(false),
            KeyCode::Char('x') => {
                if let Some(p) = self.selected_profile() {
                    if p.id == DEFAULT_ID {
                        self.error("the default profile cannot be deleted");
                    } else {
                        self.field = Some(OpenField {
                            field: Field::ConfirmDelete(p.id.clone()),
                            input: Input::default(),
                        });
                    }
                }
            }
            KeyCode::Char('w') => self.save_running_as_profile(),
            KeyCode::Char('D') => {
                if self.listing.as_ref().is_some_and(|l| l.customized) {
                    if self.action_allowed() {
                        self.queue(PendingAction::Reset);
                    }
                } else {
                    self.info("the shipped list is already in use");
                }
            }
            KeyCode::Char('R') => {
                self.refresh();
                if self.listing.is_some() {
                    self.info("refreshed");
                }
            }
            _ => {}
        }
    }

    fn on_key_advanced(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('A') => self.view = View::Profiles,
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('t') => {
                if self.action_allowed() {
                    self.pending_action = Some(PendingAction::Monitor);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.sched_selected = step(self.sched_selected, self.installed().len(), true);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.sched_selected = step(self.sched_selected, self.installed().len(), false);
            }
            KeyCode::Char('a') => {
                if self.selected_scheduler().is_some() {
                    self.field = Some(OpenField {
                        field: Field::Args,
                        input: Input::default(),
                    });
                }
            }
            KeyCode::Enter => {
                if let Some(sched) = self.selected_scheduler().map(str::to_owned)
                    && self.action_allowed()
                {
                    self.queue(PendingAction::Run(sched, Vec::new()));
                }
            }
            KeyCode::Char('s') => self.stop_running(),
            KeyCode::Char('w') => self.save_running_as_profile(),
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
            KeyCode::Char('q' | 'l') | KeyCode::Esc => self.view = View::Profiles,
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

    fn open_advanced(&mut self) {
        self.view = View::Advanced;
        if !self.advanced_warned {
            self.advanced_warned = true;
            self.info(
                "advanced: a scheduler unsuited to the workload can perform worse than the \
kernel's default; what you start here shows as Custom everywhere",
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

    /// Aligns the profile selection with what runs, so the first Enter
    /// acts on what the user sees. Only on startup, never on a refresh,
    /// which must not fight the user's own selection.
    fn sync_selection_to_running(&mut self) {
        let Some(listing) = &self.listing else {
            return;
        };
        if let Some(id) = &listing.current.profile
            && let Some(idx) = listing.profiles.iter().position(|p| p.id == *id)
        {
            self.selected = idx;
        }
        if let Some(running) = &listing.current.running
            && let Some(idx) = listing.installed.iter().position(|s| *s == running.sched)
        {
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

    fn apply_selected(&mut self) {
        let Some(profile) = self.selected_profile() else {
            return;
        };
        if !profile.available {
            self.error(&format!(
                "{} is not installed; the profile cannot be applied here",
                profile.sched.as_deref().unwrap_or("its scheduler")
            ));
            return;
        }
        let id = profile.id.clone();
        // Enter on the profile that is applied but stopped resumes it
        // with `start` rather than re-applying, when what the next start
        // would run is exactly this profile: the file names it, the
        // scheduler and options match, no override is in effect and the
        // environment resolved. That mirrors scxcli's own rule for a
        // password-free start; anything less goes through `apply`,
        // which rewrites the file and so cannot run anything else.
        let resume = self.listing.as_ref().is_some_and(|l| {
            let c = &l.current;
            c.applied.as_deref() == Some(id.as_str())
                && !c.unit.active
                && id != DEFAULT_ID
                && c.config_error.is_none()
                && c.next.as_ref().is_some_and(|next| {
                    // `path` is the profile's scheduler as scxcli
                    // resolved it, and apply writes exactly that into
                    // the file, so the two are equal when the file is
                    // the profile's; a name or another path is not.
                    !next.overridden
                        && profile.path.as_deref() == Some(next.sched.as_str())
                        && next.args == profile.args
                })
        });
        if self.action_allowed() {
            self.queue(if resume {
                PendingAction::Start
            } else {
                PendingAction::Apply(id)
            });
        }
    }

    /// `s`: stop the unit and keep the applied profile, so it comes back
    /// on the next start or boot. Not `apply default`, which forgets it.
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

    /// The listing's profiles as a file, for an edit.
    fn current_profiles(&self) -> ProfilesFile {
        ProfilesFile {
            version: FORMAT_VERSION,
            profiles: self.profiles().iter().map(Entry::to_profile).collect(),
        }
    }

    fn move_selected(&mut self, down: bool) {
        let len = self.profiles().len();
        let from = self.selected;
        let to = if down { from + 1 } else { from.wrapping_sub(1) };
        // `default` stays first: neither it nor the one below it moves up.
        if from == 0 || to == 0 || to >= len {
            return;
        }
        let mut profiles = self.current_profiles();
        profiles.profiles.swap(from, to);
        let id = profiles.profiles[to].id.clone();
        if self.action_allowed() {
            self.selected = to;
            self.queue(PendingAction::SaveList(profiles, format!("moved {id}")));
        }
    }

    fn delete_profile(&mut self, id: &str) {
        let mut profiles = self.current_profiles();
        profiles.profiles.retain(|p| p.id != id);
        if self.action_allowed() {
            self.selected = self.selected.min(profiles.profiles.len().saturating_sub(1));
            self.queue(PendingAction::SaveList(profiles, format!("deleted {id}")));
        }
    }

    /// `S`: the running scheduler and its options become a named
    /// profile, after a prompt for the id.
    fn save_running_as_profile(&mut self) {
        let Some(running) = self
            .listing
            .as_ref()
            .and_then(|l| l.current.running.clone())
        else {
            self.error("nothing is running; start a scheduler first");
            return;
        };
        if let Some(err) = running.args.iter().find_map(|a| validate_arg(a).err()) {
            self.error(&format!("the running options cannot be a profile: {err:#}"));
            return;
        }
        self.field = Some(OpenField {
            field: Field::SaveAs {
                sched: running.sched,
                args: running.args,
            },
            input: Input::default(),
        });
    }

    /// A failed read clears the snapshot and records why.
    fn refresh(&mut self) {
        match self.backend.list() {
            Ok(listing) => {
                self.selected = self.selected.min(listing.profiles.len().saturating_sub(1));
                self.sched_selected = self
                    .sched_selected
                    .min(listing.installed.len().saturating_sub(1));
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

/// The description a profile saved from what runs gets; short and fixed,
/// since the backing is shown under it and the user can edit it later.
const SAVED_DESCRIPTION: &str = "Saved from the running scheduler.";

/// `low-latency2` -> `Low latency2`.
fn label_from_id(id: &str) -> String {
    let mut label = id.replace('-', " ");
    if let Some(first) = label.get(..1) {
        let upper = first.to_ascii_uppercase();
        label.replace_range(..1, &upper);
    }
    label
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::model::{Action, Current, Running, Unit};
    use anyhow::anyhow;

    use super::*;

    #[derive(Debug, PartialEq)]
    enum Call {
        Apply(String),
        Run(String, Vec<String>),
        Save(Vec<String>),
        Reset,
        Stop,
        Start,
    }

    struct Stub {
        listing: Rc<RefCell<Listing>>,
        broken: Rc<RefCell<bool>>,
        calls: Rc<RefCell<Vec<Call>>>,
    }

    fn entry(id: &str, sched: Option<&str>, args: &[&str], available: bool) -> Entry {
        Entry {
            id: id.into(),
            label: id.into(),
            description: String::new(),
            action: sched.is_none().then_some(Action::Stop),
            sched: sched.map(str::to_owned),
            path: sched.filter(|_| available).map(|s| format!("/usr/bin/{s}")),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            available,
        }
    }

    fn listing() -> Listing {
        Listing {
            version: crate::model::OUTPUT_VERSION,
            source: "/usr/share/scx/profiles.json".into(),
            customized: false,
            profiles: vec![
                entry("default", None, &[], true),
                entry("gaming", Some("scx_lavd"), &["--performance"], true),
                entry("server", Some("scx_rusty"), &[], false),
            ],
            installed: vec!["scx_bpfland".into(), "scx_lavd".into()],
            config: Some("/etc/default/scx".into()),
            current: Current {
                version: crate::model::OUTPUT_VERSION,
                profile: Some("gaming".into()),
                applied: Some("gaming".into()),
                custom: false,
                unit: Unit {
                    active: true,
                    enabled: true,
                },
                running: Some(Running {
                    sched: "scx_lavd".into(),
                    args: vec!["--performance".into()],
                }),
                next: Some(crate::model::Next {
                    sched: "/usr/bin/scx_lavd".into(),
                    args: vec!["--performance".into()],
                    overridden: false,
                }),
                kernel: None,
                failure: None,
                config_error: None,
            },
        }
    }

    impl ProfileBackend for Stub {
        fn label(&self) -> String {
            "stub".into()
        }
        fn list(&self) -> Result<Listing> {
            if *self.broken.borrow() {
                return Err(anyhow!("list broken"));
            }
            Ok(self.listing.borrow().clone())
        }
        fn apply(&self, id: &str) -> Result<String> {
            self.calls.borrow_mut().push(Call::Apply(id.into()));
            Ok(format!("applied {id}"))
        }
        fn run(&self, sched: &str, args: &[String]) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(Call::Run(sched.into(), args.to_vec()));
            Ok("running".into())
        }
        fn save(&self, profiles: &ProfilesFile) -> Result<String> {
            self.calls.borrow_mut().push(Call::Save(
                profiles.profiles.iter().map(|p| p.id.clone()).collect(),
            ));
            Ok("saved".into())
        }
        fn reset(&self) -> Result<String> {
            self.calls.borrow_mut().push(Call::Reset);
            Ok("reset".into())
        }
        fn stop(&self) -> Result<String> {
            self.calls.borrow_mut().push(Call::Stop);
            self.listing.borrow_mut().current.unit.active = false;
            self.listing.borrow_mut().current.running = None;
            self.listing.borrow_mut().current.profile = None;
            Ok("stopped".into())
        }
        fn start(&self) -> Result<String> {
            self.calls.borrow_mut().push(Call::Start);
            self.listing.borrow_mut().current.unit.active = true;
            Ok("started".into())
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
                PendingAction::Apply(id) => app.backend.apply(&id),
                PendingAction::Run(s, a) => app.backend.run(&s, &a),
                PendingAction::SaveList(p, _) => app.backend.save(&p),
                PendingAction::Reset => app.backend.reset(),
                PendingAction::Stop => app.backend.stop(),
                PendingAction::Start => app.backend.start(),
                PendingAction::Monitor => Ok(String::new()),
            };
            assert!(outcome.is_ok());
            app.refresh();
        }
    }

    #[test]
    fn startup_selects_the_running_profile_and_scheduler() {
        let Harness { app, .. } = app();
        assert_eq!(app.selected_profile().unwrap().id, "gaming");
        assert_eq!(app.selected_scheduler(), Some("scx_lavd"));
    }

    #[test]
    fn enter_applies_the_selected_profile_but_not_an_unavailable_one() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Apply("gaming".into())]);

        app.last_action = None;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected_profile().unwrap().id, "server");
        app.on_key(key(KeyCode::Enter));
        assert!(app.pending_action.is_none());
        assert!(app.message.as_ref().unwrap().is_error);
        assert_eq!(calls.borrow().len(), 1);
    }

    #[test]
    fn apply_is_debounced() {
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
    fn stop_keeps_the_profile_and_enter_on_it_resumes_instead_of_reapplying() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('s')));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Stop]);
        let current = &app.listing.as_ref().unwrap().current;
        assert_eq!(current.applied.as_deref(), Some("gaming"));
        assert!(!current.unit.active);

        // The selection is still on gaming, which is applied but stopped.
        app.last_action = None;
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Stop, Call::Start]);

        // Stopping with nothing running is a message, not a call.
        app.last_action = None;
        app.listing.as_mut().unwrap().current.unit.active = false;
        app.on_key(key(KeyCode::Char('s')));
        assert!(app.pending_action.is_none());
        assert!(!app.message.as_ref().unwrap().is_error);
        assert_eq!(calls.borrow().len(), 2);
    }

    /// The marker still says gaming, but the file was edited under it:
    /// Enter must apply, never start what the file now holds.
    #[test]
    fn enter_on_an_edited_applied_profile_applies_instead_of_resuming() {
        let Harness {
            mut app,
            calls,
            listing,
            ..
        } = app();
        {
            let mut l = listing.borrow_mut();
            l.current.unit.active = false;
            l.current.running = None;
            l.current.profile = None;
            l.current.next = Some(crate::model::Next {
                sched: "/usr/bin/scx_bpfland".into(),
                args: vec!["--performance".into()],
                overridden: false,
            });
        }
        app.refresh();
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Apply("gaming".into())]);

        // Same with the right scheduler but an override in effect, and
        // with an environment that did not resolve.
        for (overridden, error) in [(true, None), (false, Some("x is unreadable"))] {
            {
                let mut l = listing.borrow_mut();
                l.current.next = Some(crate::model::Next {
                    sched: "/usr/bin/scx_lavd".into(),
                    args: vec!["--performance".into()],
                    overridden,
                });
                l.current.config_error = error.map(str::to_owned);
            }
            app.refresh();
            app.last_action = None;
            app.on_key(key(KeyCode::Enter));
            drain(&mut app);
        }
        assert_eq!(
            *calls.borrow(),
            vec![
                Call::Apply("gaming".into()),
                Call::Apply("gaming".into()),
                Call::Apply("gaming".into())
            ]
        );
        assert!(!calls.borrow().contains(&Call::Start));
    }

    #[test]
    fn advanced_view_runs_the_selected_scheduler_with_typed_options() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('A')));
        assert_eq!(app.view, View::Advanced);
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.selected_scheduler(), Some("scx_bpfland"));
        app.on_key(key(KeyCode::Char('a')));
        for c in "-m performance".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(
            *calls.borrow(),
            vec![Call::Run(
                "scx_bpfland".into(),
                vec!["-m".into(), "performance".into()]
            )]
        );
        assert!(app.field.is_none());
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
        assert!(app.field.is_some(), "the field stays open to fix");
        assert!(app.message.as_ref().unwrap().is_error);
        assert!(calls.borrow().is_empty());
        // Global shortcuts do not fire from inside the field.
        app.on_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.on_key(key(KeyCode::Esc));
        assert!(app.field.is_none());
    }

    #[test]
    fn save_as_profile_appends_a_validated_id() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('w')));
        for c in "Mine".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert!(
            app.message.as_ref().unwrap().is_error,
            "uppercase id refused"
        );
        app.field.as_mut().unwrap().input = Input::default();
        for c in "gaming".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert!(
            app.message
                .as_ref()
                .unwrap()
                .text
                .contains("already exists")
        );
        app.field.as_mut().unwrap().input = Input::default();
        for c in "my-lavd".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        drain(&mut app);
        assert_eq!(
            *calls.borrow(),
            vec![Call::Save(vec![
                "default".into(),
                "gaming".into(),
                "server".into(),
                "my-lavd".into()
            ])]
        );
        assert_eq!(label_from_id("low-latency2"), "Low latency2");
    }

    #[test]
    fn delete_asks_first_and_never_touches_default() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('x')));
        assert!(matches!(
            app.field.as_ref().unwrap().field,
            Field::ConfirmDelete(ref id) if id == "gaming"
        ));
        app.on_key(key(KeyCode::Char('n')));
        assert!(app.field.is_none());
        assert!(calls.borrow().is_empty());

        app.on_key(key(KeyCode::Char('x')));
        app.on_key(key(KeyCode::Char('y')));
        drain(&mut app);
        assert_eq!(
            *calls.borrow(),
            vec![Call::Save(vec!["default".into(), "server".into()])]
        );

        app.selected = 0;
        app.on_key(key(KeyCode::Char('x')));
        assert!(app.field.is_none());
        assert!(app.message.as_ref().unwrap().is_error);
    }

    #[test]
    fn reorder_keeps_default_first() {
        let Harness { mut app, calls, .. } = app();
        app.on_key(key(KeyCode::Char('K')));
        assert!(calls.borrow().is_empty(), "nothing moves above default");
        app.on_key(key(KeyCode::Char('J')));
        drain(&mut app);
        assert_eq!(
            *calls.borrow(),
            vec![Call::Save(vec![
                "default".into(),
                "server".into(),
                "gaming".into()
            ])]
        );
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn reset_only_when_a_custom_list_is_in_use() {
        let Harness {
            mut app,
            calls,
            listing,
            ..
        } = app();
        app.on_key(key(KeyCode::Char('D')));
        assert!(app.pending_action.is_none());
        listing.borrow_mut().customized = true;
        app.refresh();
        app.on_key(key(KeyCode::Char('D')));
        drain(&mut app);
        assert_eq!(*calls.borrow(), vec![Call::Reset]);
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
        assert!(app.selected_profile().is_none());
        app.on_key(key(KeyCode::Enter));
        assert!(app.pending_action.is_none());

        *broken.borrow_mut() = false;
        listing.borrow_mut().profiles.truncate(1);
        app.selected = 2;
        app.refresh();
        assert_eq!(app.selected, 0);
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
