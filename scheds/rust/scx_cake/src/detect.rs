// SPDX-License-Identifier: GPL-2.0
// Game + compiler detection for scx_cake (headless and TUI modes).
//
// Extracted from tui.rs to enable game detection in --release/headless mode.
// Without this, sched_state stays IDLE and the 4-class system (GAME/NORMAL/BG/HOG),
// class-aware kick guard, SYNC strip, and quantum differentiation are all inactive.
//
// Detection pipeline (runs every ~1s headless, ~500ms TUI):
//   Phase 1: Steam env — SteamGameId= in /proc/{pid}/environ (conf 100, instant lock)
//            Detects ALL Steam games: native Linux (CS2, Dota 2) AND Proton (.exe).
//   Phase 2: Wine .exe — .exe in /proc/{pid}/cmdline (conf 90, 5s holdoff)
//            Catches non-Steam Wine launchers (Heroic, Lutris, manual Wine).
//   Compiler: /proc scan for known compiler comms in 'R' state (≥2 = COMPILATION)
//
// Data flow: poll() → DetectResult → caller writes to BPF BSS →
//   BPF reclassifier reads sched_state → enables GAMING classification path.

use std::time::Instant;

use log::{debug, info};

// ═══ State Constants (match intf.h) ═══
const CAKE_STATE_IDLE: u8 = 0;
const CAKE_STATE_COMPILATION: u8 = 1;
const CAKE_STATE_GAMING: u8 = 2;

// ═══ Game Detection Constants ═══
/// Minimum child processes under a PPID to qualify as a game family.
/// Prevents idle browsers (1-3 procs) from triggering.
/// Proton games easily exceed: game.exe + wineserver + winedevice + services + etc.
/// Native Linux games also pass: main + audio + IO + render.
const GAME_MIN_CHILDREN: usize = 5;

/// After this many consecutive stable polls with the same PPID winning,
/// 20 × 1s = 20s stable before entering fast-path (headless polls at 1s).
const GAME_CONFIDENCE_THRESHOLD: u32 = 20;

/// Steam infrastructure processes — never game processes.
/// Filtered when checking if a PPID group has non-infra threads.
const STEAM_INFRA: &[&str] = &[
    "steam",
    "steamwebhelper",
    "pressure-vessel",
    "pv-bwrap",
    "reaper",
];

/// Known compiler binary names for COMPILATION state detection.
/// Require ≥2 actively running to avoid false positives from
/// transient ld/as invocations or idle IDE processes.
const COMPILE_COMMS: &[&str] = &[
    "cc1", "rustc", "clang", "clang++", "ld", "ld.lld", "lld", "ninja", "cmake", "as", "gcc",
    "g++", "link",
];

// ═══ Public Types ═══

/// BSS write payload returned by poll(). Caller writes these to BPF BSS.
#[allow(dead_code)]
pub struct DetectResult {
    pub game_tgid: u32,
    pub game_ppid: u32,
    pub game_confidence: u8,
    pub sched_state: u8,
    pub quantum_ceiling_ns: u64,
}

/// Shared game + compiler detector. Self-contained — does its own /proc scanning.
/// No TUI or BPF iterator dependencies.
pub struct GameDetector {
    // ─── Public state (read by TUI for display) ───
    pub tracked_game_tgid: u32,
    pub tracked_game_ppid: u32,
    pub game_name: String,
    pub game_thread_count: usize,
    pub game_confidence: u8,
    pub sched_state: u8,
    pub compile_task_count: usize,
    // ─── Hysteresis internals (pub for TUI display) ───
    pub challenger_ppid: u32,
    pub challenger_since: Option<Instant>,
    pub stable_polls: u32,
    /// Reusable buffer for PPID aggregation — avoids per-poll heap allocation.
    /// Sorted in-place each poll; run-counting replaces HashMap<u32, usize>.
    ppid_buf: Vec<u32>,
    /// Cached UID — set once at init, used to skip non-user /proc entries.
    uid: u32,
    /// TUI mode: resolve game name + thread count for display.
    /// Headless: skip resolve — game_tgid = game_ppid, zero extra reads.
    verbose: bool,
}

// ═══ Internal: Lightweight /proc Entry ═══

/// Minimal task data from /proc/{pid}/stat. One file read per PID.
struct ProcEntry {
    pid: u32,
    ppid: u32,
    comm: String,
    state: char, // 'R'=running, 'S'=sleeping, etc.
}

/// Parse /proc/{pid}/stat into a ProcEntry.
/// Format: `pid (comm) state ppid pgrp session ...`
/// Handles comms with spaces/parens by finding the last ')'.
fn parse_proc_stat(content: &str) -> Option<ProcEntry> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    let pid: u32 = content[..open].trim().parse().ok()?;
    let comm = content[open + 1..close].to_string();
    let rest = content.get(close + 2..)?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid: u32 = fields.next()?.parse().ok()?;
    Some(ProcEntry {
        pid,
        ppid,
        comm,
        state,
    })
}

/// Detect the real user UID, even when running as root via sudo.
/// scx_cake runs with root privileges, but games run as the unprivileged user.
/// Resolution order (cheapest first):
///   1. SUDO_UID env var — set by sudo, always correct
///   2. /proc/self/loginuid — set by PAM at login
///   3. getuid() — fallback (will be 0 if running as root)
/// Called once at GameDetector init — zero hot-path cost.
fn detect_real_uid() -> u32 {
    // SUDO_UID is the most reliable: set by sudo for every escalated session
    if let Ok(val) = std::env::var("SUDO_UID") {
        if let Ok(uid) = val.parse::<u32>() {
            debug!("UID filter: using SUDO_UID={}", uid);
            return uid;
        }
    }
    // loginuid: set by PAM at session login, survives su/sudo
    if let Ok(val) = std::fs::read_to_string("/proc/self/loginuid") {
        if let Ok(uid) = val.trim().parse::<u32>() {
            // 4294967295 (0xFFFFFFFF) means "not set"
            if uid != 0xFFFF_FFFF && uid != 0 {
                debug!("UID filter: using loginuid={}", uid);
                return uid;
            }
        }
    }
    // Fallback — will be 0 if running as root, which disables UID filtering
    // (all /proc entries are checked, equivalent to old behavior)
    let uid = unsafe { libc::getuid() };
    debug!("UID filter: using getuid()={}", uid);
    uid
}

/// Scan /proc for user-owned thread-group leaders.
/// Filters:
///   1. UID: stat() on /proc/{pid} dir — skips kernel, system, and other users (~80% reduction)
///   2. kthreadd: skip PPID 2 children (kernel workers)
/// Cost after filters: ~50-100 stat reads for a typical gaming desktop.
fn scan_proc(uid: u32) -> Vec<ProcEntry> {
    let mut entries = Vec::with_capacity(128);
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return entries,
    };
    for dir_entry in proc_dir.flatten() {
        let name = dir_entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // UID filter: /proc/{pid} dir ownership == process real UID.
        // stat() is metadata-only — no file content read.
        if let Ok(meta) = dir_entry.metadata() {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                continue;
            }
        } else {
            continue;
        }
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
            if let Some(entry) = parse_proc_stat(&stat) {
                // Skip kthreadd children (PPID 2) — kernel workers, never games.
                if entry.ppid == 2 {
                    continue;
                }
                entries.push(entry);
            }
        }
    }
    entries
}

/// Read actual thread count from /proc/{pid}/status.
/// The kernel reports "Threads:\tN" which is the authoritative count.
/// Returns 1 on any read failure (safe fallback — doesn't inflate rank).
fn read_thread_count(pid: u32) -> u32 {
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Threads:\t") {
                return val.trim().parse().unwrap_or(1);
            }
        }
    }
    1
}

/// Check and retrieve the Steam App ID from process environment variables.
/// Reads /proc/{pid}/environ — definitive signal for ALL Steam games
fn get_steam_appid_and_lib(pid: u32) -> (Option<u32>, Option<String>) {
    let mut appid = None;
    let mut lib_path = None;
    if let Ok(env) = std::fs::read(format!("/proc/{}/environ", pid)) {
        for kv in env.split(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(kv) {
                if let Some(appid_str) = s.strip_prefix("SteamAppId=") {
                    appid = appid_str.parse().ok();
                } else if let Some(appid_str) = s.strip_prefix("SteamGameId=") {
                    appid = appid.or_else(|| appid_str.parse().ok());
                } else if let Some(appid_str) = s.strip_prefix("STEAM_GAME=") {
                    appid = appid.or_else(|| appid_str.parse().ok());
                } else if let Some(val) = s.strip_prefix("STEAM_COMPAT_DATA_PATH=") {
                    // Extract library path, e.g. "/mnt/games/SteamLibrary/steamapps/compatdata/1234"
                    // -> "/mnt/games/SteamLibrary/steamapps"
                    if let Some(idx) = val.rfind("/compatdata") {
                        lib_path = Some(val[..idx].to_string());
                    }
                }
            }
        }
    }
    (appid, lib_path)
}

/// Parse the official game name from the Steam appmanifest_{appid}.acf file.
fn read_acf_name(appid: u32, extra_lib: Option<String>) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let mut paths = vec![
        format!("{}/.steam/steam/steamapps/appmanifest_{}.acf", home, appid),
        format!(
            "{}/.local/share/Steam/steamapps/appmanifest_{}.acf",
            home, appid
        ),
        format!(
            "{}/.steam/debian-installation/steamapps/appmanifest_{}.acf",
            home, appid
        ),
        format!(
            "{}/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/appmanifest_{}.acf",
            home, appid
        ),
    ];
    if let Some(lib) = extra_lib {
        paths.insert(0, format!("{}/appmanifest_{}.acf", lib, appid));
    }

    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("\"name\"") {
                    let parts: Vec<&str> = trimmed.split('"').collect();
                    if parts.len() >= 4 {
                        return Some(parts[3].to_string());
                    }
                }
            }
        }
    }
    None
}

/// Check if a process has a .exe in its cmdline (Wine/Proton game).
fn has_exe_cmdline(pid: u32) -> bool {
    if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
        cmdline
            .split(|&b| b == 0)
            .filter_map(|arg| std::str::from_utf8(arg).ok())
            .any(|s| s.to_lowercase().ends_with(".exe"))
    } else {
        false
    }
}

/// Count children for a PPID in a sorted PPID buffer using binary search.
/// O(log n) lookup + O(run_length) count. Cache-friendly: sequential scan
/// on contiguous memory, no hash computation or pointer chasing.
fn count_children(sorted_ppids: &[u32], ppid: u32) -> usize {
    // Binary search for any occurrence of ppid
    let idx = match sorted_ppids.binary_search(&ppid) {
        Ok(i) => i,
        Err(_) => return 0,
    };
    // Walk backward to run start
    let mut start = idx;
    while start > 0 && sorted_ppids[start - 1] == ppid {
        start -= 1;
    }
    // Walk forward to run end
    let mut end = idx + 1;
    while end < sorted_ppids.len() && sorted_ppids[end] == ppid {
        end += 1;
    }
    end - start
}

/// Resolve the best TGID + display name for a game family PPID.
/// Picks the process with the most threads — game processes always dominate
/// (100+ threads for UE5/Unity vs single-digits for infra like tabtip, wine).
/// No blocklist needed: thread count is the definitive signal.
/// For Proton, extracts .exe basename; for native, uses /proc/{tgid}/comm.
fn resolve_game(ppid: u32, entries: &[ProcEntry]) -> (u32, String) {
    // Collect ALL descendants of this PPID to find the real game engine.
    // Steam launches games via scripts (hl2.sh) or wrappers (wineserver),
    // making the 50+ thread game engine a grandchild or great-grandchild.
    // This is 100% userspace (Rust) and costs 0 BPF cycles.
    let mut descendants = Vec::with_capacity(32);
    descendants.push(ppid);
    let mut added = true;
    while added {
        added = false;
        for e in entries {
            if descendants.contains(&e.ppid) && !descendants.contains(&e.pid) {
                descendants.push(e.pid);
                added = true;
            }
        }
    }

    let mut best_pid: u32 = ppid;
    let mut best_threads: u32 = 0;
    for e in entries {
        if descendants.contains(&e.pid) {
            let threads = read_thread_count(e.pid);
            if threads > best_threads {
                best_threads = threads;
                best_pid = e.pid;
            }
        }
    }

    let game_tgid = best_pid;

    // Read display name: try ACF manifest, then .exe basename (Proton), then comm (native).
    let name = {
        let mut n = String::from("unknown");

        // 1. Precise Steam Manifest Parser
        let (appid_opt, lib_opt) = get_steam_appid_and_lib(game_tgid);
        let (appid, lib) = if appid_opt.is_some() {
            (appid_opt, lib_opt)
        } else {
            get_steam_appid_and_lib(ppid)
        };

        if let Some(id) = appid {
            if let Some(acf_name) = read_acf_name(id, lib) {
                n = acf_name;
            }
        }

        if n == "unknown" {
            if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", game_tgid)) {
                for arg in cmdline.split(|&b| b == 0) {
                    if let Ok(s) = std::str::from_utf8(arg) {
                        if s.to_lowercase().ends_with(".exe") {
                            let basename = s.rsplit(['\\', '/']).next().unwrap_or(s);
                            n = basename
                                .trim_end_matches(".exe")
                                .trim_end_matches(".EXE")
                                .to_string();
                            break;
                        }
                    }
                }
            }
        }
        // Native game fallback: use comm (e.g., "cs2", "dota2").
        if n == "unknown" {
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", game_tgid)) {
                n = comm.trim().to_string();
            }
        }
        n
    };
    (game_tgid, name)
}

// ═══ GameDetector Implementation ═══

impl GameDetector {
    /// Create detector for TUI mode (resolves game name + thread count).
    pub fn new() -> Self {
        Self::with_verbose(true)
    }

    /// Create detector for headless/release mode (skips name resolution).
    pub fn new_headless() -> Self {
        Self::with_verbose(false)
    }

    fn with_verbose(verbose: bool) -> Self {
        Self {
            tracked_game_tgid: 0,
            tracked_game_ppid: 0,
            game_name: String::new(),
            game_thread_count: 0,
            game_confidence: 0,
            sched_state: CAKE_STATE_IDLE,
            compile_task_count: 0,
            challenger_ppid: 0,
            challenger_since: None,
            stable_polls: 0,
            ppid_buf: Vec::with_capacity(512),
            uid: detect_real_uid(),
            verbose,
        }
    }

    /// Main detection entry point. Call every ~1s (headless) or ~500ms (TUI).
    /// Returns BSS values to write. Caller is responsible for BSS propagation.
    pub fn poll(&mut self) -> DetectResult {
        // ─── Game exit detection (fires before throttle) ───
        // Dead game always clears on the very next poll, regardless of confidence.
        if self.tracked_game_tgid > 0 {
            let proc_path = format!("/proc/{}", self.tracked_game_tgid);
            if !std::path::Path::new(&proc_path).exists() {
                // Only announce exit if the game was alive long enough to be announced.
                if !self.verbose && self.stable_polls >= 10 {
                    info!(
                        "Game exited: {} (PID {})",
                        self.game_name, self.tracked_game_tgid
                    );
                }
                self.tracked_game_tgid = 0;
                self.tracked_game_ppid = 0;
                self.game_thread_count = 0;
                self.game_name.clear();
                self.challenger_ppid = 0;
                self.challenger_since = None;
                self.stable_polls = 0;

                self.game_confidence = 0;
            }
        }

        // ─── Stable game fast-path: skip /proc entirely ───
        // When game is stable (≥20 polls = ~20s), BPF init_task handles
        // all new task classification at creation time. No /proc scan needed.
        // Cost: 1 stat() on /proc/{game_tgid} (~1µs) vs ~700µs full scan.
        // Full scan resumes immediately when game exits (stable_polls reset to 0).
        if self.tracked_game_tgid > 0 && self.stable_polls >= GAME_CONFIDENCE_THRESHOLD {
            self.sched_state = CAKE_STATE_GAMING;
            self.compile_task_count = 0;
            return DetectResult {
                game_tgid: self.tracked_game_tgid,
                game_ppid: self.tracked_game_ppid,
                game_confidence: self.game_confidence,
                sched_state: CAKE_STATE_GAMING,
                quantum_ceiling_ns: 2_000_000,
            };
        }

        // ─── /proc scan (UID-filtered — skips kernel, system, other users) ───
        // Only runs when: no game detected, or game not yet stable (<20 polls).
        let entries = scan_proc(self.uid);

        // ─── Game detection sweep ───
        self.run_game_detection(&entries);

        // ─── Compiler detection (only when not in stable gaming) ───
        self.detect_compilers(&entries);

        // ─── Re-resolve game_tgid during startup stabilization (ALL modes) ───
        // Steam launches wrappers (wineserver) before the real 50+ thread game.
        // Update the tracked name/TGID once the real engine assumes thread dominance.
        if self.tracked_game_tgid > 0
            && self.stable_polls >= 3
            && self.stable_polls < GAME_CONFIDENCE_THRESHOLD
        {
            let (new_tgid, new_name) = resolve_game(self.tracked_game_ppid, &entries);
            if new_tgid != self.tracked_game_tgid || new_name != self.game_name {
                self.tracked_game_tgid = new_tgid;
                self.game_name = new_name;
            }
        }

        // ─── Deferred Terminal Logging (Headless) ───
        // Wait exactly 10 seconds (10 polls) for wrappers (Wine) to settle
        // into the true game engine before printing to the terminal.
        if !self.verbose && self.tracked_game_tgid > 0 && self.stable_polls == 10 {
            info!(
                "Game detected: {} (PID {}, PPID {}, conf {})",
                self.game_name,
                self.tracked_game_tgid,
                self.tracked_game_ppid,
                self.game_confidence
            );
        }

        // ─── State machine: GAMING > COMPILATION > IDLE ───
        self.sched_state = if self.tracked_game_tgid > 0 {
            CAKE_STATE_GAMING
        } else if self.compile_task_count >= 2 {
            CAKE_STATE_COMPILATION
        } else {
            CAKE_STATE_IDLE
        };

        DetectResult {
            game_tgid: self.tracked_game_tgid,
            game_ppid: self.tracked_game_ppid,
            game_confidence: self.game_confidence,
            sched_state: self.sched_state,
            quantum_ceiling_ns: if self.sched_state == CAKE_STATE_COMPILATION {
                8_000_000 // AQ_BULK_CEILING_COMPILE_NS
            } else {
                2_000_000 // AQ_BULK_CEILING_NS
            },
        }
    }

    /// Three-phase game detection + hysteresis state machine.
    fn run_game_detection(&mut self, entries: &[ProcEntry]) {
        // ─── PPID aggregation via sorted Vec (replaces HashMap) ───
        // Collect all PPIDs, sort, then count consecutive runs.
        // Cache-friendly sequential scan, zero heap alloc (reuses self.ppid_buf),
        // deterministic iteration order (sorted ascending).
        self.ppid_buf.clear();
        for e in entries {
            if e.ppid > 0 {
                self.ppid_buf.push(e.ppid);
            }
        }
        self.ppid_buf.sort_unstable();

        // ─── Phase 1: Steam scan (highest priority, no holdoff) ───
        // Covers: Proton games, native Linux Steam games (CS2, Dota 2),
        // Battle.net/Epic via Steam. SteamGameId= is the definitive signal.
        let mut steam_ppid: u32 = 0;
        {
            let mut i = 0;
            while i < self.ppid_buf.len() {
                let ppid = self.ppid_buf[i];
                // Count run length = number of children under this PPID
                let run_start = i;
                while i < self.ppid_buf.len() && self.ppid_buf[i] == ppid {
                    i += 1;
                }
                let child_count = i - run_start;
                // native Linux games (CS2) are just ONE process with 100+ threads, so child_count == 1.
                // Because SteamAppId= is cryptographically foolproof, we don't need a child threshold here!
                if child_count >= 1 && get_steam_appid_and_lib(ppid).0.is_some() {
                    // Skip if ALL children under this PPID are Steam infra.
                    let has_non_infra = entries.iter().any(|e| {
                        e.ppid == ppid
                            && !STEAM_INFRA
                                .iter()
                                .any(|&infra| e.comm.to_lowercase().contains(infra))
                    });
                    if has_non_infra {
                        steam_ppid = ppid;
                        break;
                    }
                }
            }
        }

        // ─── Phase 2: .exe scan (Wine without Steam — Heroic, Lutris, etc.) ───
        let mut exe_ppid: u32 = 0;
        if steam_ppid == 0 {
            let mut i = 0;
            while i < self.ppid_buf.len() {
                let ppid = self.ppid_buf[i];
                let run_start = i;
                while i < self.ppid_buf.len() && self.ppid_buf[i] == ppid {
                    i += 1;
                }
                let child_count = i - run_start;
                if child_count >= GAME_MIN_CHILDREN && has_exe_cmdline(ppid) {
                    exe_ppid = ppid;
                    break;
                }
            }
        }

        // ─── Resolve winning PPID: Steam wins → .exe wins → no game ───
        let new_game_ppid = if steam_ppid > 0 {
            steam_ppid
        } else if exe_ppid > 0 {
            exe_ppid
        } else {
            0
        };

        // Phase 1 (Steam) → 100, Phase 2 (.exe) → 90, no game → 0.
        let new_game_confidence: u8 = if new_game_ppid == 0 {
            0
        } else if new_game_ppid == steam_ppid {
            100
        } else {
            90 // exe match
        };

        // Holdoff by confidence tier:
        //   100 (Steam) → instant lock
        //    90 (.exe)  → 5s holdoff (Wine apps nearly always games, but brief wait)
        let holdoff_for_conf = |conf: u8| -> u64 {
            if conf >= 100 {
                0
            } else {
                5
            }
        };

        // ─── Hysteresis State Machine ───
        // Challenger can only displace a locked game if challenger_confidence >=
        // locked_game_confidence. Steam (100) always beats .exe (90).
        if self.tracked_game_tgid == 0 {
            // No game locked — try to lock now.
            if new_game_confidence > 0 {
                let holdoff = holdoff_for_conf(new_game_confidence);
                if holdoff == 0 || self.challenger_ppid == new_game_ppid {
                    let accept = holdoff == 0
                        || self.challenger_since.is_some_and(|s| {
                            s.elapsed() >= std::time::Duration::from_secs(holdoff)
                        });
                    if accept {
                        // Verbose: resolve game name for TUI display.
                        // Headless: game_tgid = game_ppid, skip name resolution.
                        // Always resolve true engine TGID and name for logging accuracy
                        let (tgid, name) = resolve_game(new_game_ppid, entries);
                        self.tracked_game_tgid = tgid;
                        self.game_name = name.clone();
                        self.game_thread_count = count_children(&self.ppid_buf, new_game_ppid);

                        // Silence initial prints to prevent 'winedevice' spam.
                        // Wait for self.stable_polls == 10 to announce.
                        self.tracked_game_ppid = new_game_ppid;
                        self.game_confidence = new_game_confidence;
                        self.challenger_ppid = 0;
                        self.challenger_since = None;
                        self.stable_polls = 1;
                    }
                } else {
                    // Start or continue holdoff timer.
                    if self.challenger_ppid != new_game_ppid {
                        self.challenger_ppid = new_game_ppid;
                        self.challenger_since = Some(Instant::now());
                    }
                }
            }
        } else if new_game_ppid == self.tracked_game_ppid {
            // Same game family still winning — update child count.
            self.game_thread_count = count_children(&self.ppid_buf, new_game_ppid);
            // Preserve active challenger timer (GAME SWAP FIX C from TUI).
            if self.challenger_ppid == 0 {
                self.stable_polls = self.stable_polls.saturating_add(1);
            }
        } else if new_game_confidence > 0 && new_game_confidence >= self.game_confidence {
            // GAME SWAP: equal-or-higher confidence can contest (GAME SWAP FIX B).
            // Handles: close Game A → launch Game B (both Steam = 100%).
            self.stable_polls = 0;
            if self.challenger_ppid != new_game_ppid {
                self.challenger_ppid = new_game_ppid;
                self.challenger_since = Some(Instant::now());
            } else if let Some(since) = self.challenger_since {
                let holdoff = if new_game_confidence > self.game_confidence {
                    holdoff_for_conf(new_game_confidence)
                } else {
                    5 // Equal confidence: 5s holdoff prevents iteration flicker
                };
                if since.elapsed() >= std::time::Duration::from_secs(holdoff) {
                    // Always resolve on swap for accurate Headless logging
                    let (tgid, name) = resolve_game(new_game_ppid, entries);
                    self.tracked_game_tgid = tgid;
                    self.game_name = name.clone();
                    self.game_thread_count = count_children(&self.ppid_buf, new_game_ppid);

                    // Silence swap prints to prevent 'winedevice' spam.
                    // Wait for self.stable_polls == 10 to announce.
                    self.tracked_game_ppid = new_game_ppid;
                    self.game_confidence = new_game_confidence;
                    self.challenger_ppid = 0;
                    self.challenger_since = None;
                    self.stable_polls = 1;
                }
            }
        } else {
            // No qualifying candidate or lower-confidence challenger — hold current.
            self.challenger_ppid = 0;
            self.challenger_since = None;
            self.stable_polls = 0;
        }
    }

    /// Compiler detection: count known compiler comms in 'R' (running) state.
    /// Simpler than TUI's PELT-based check but avoids false positives from
    /// idle/sleeping compiler processes. ≥2 running compilers = COMPILATION.
    fn detect_compilers(&mut self, entries: &[ProcEntry]) {
        self.compile_task_count = entries
            .iter()
            .filter(|e| {
                e.state == 'R'
                    && COMPILE_COMMS
                        .iter()
                        .any(|&c| e.comm.to_lowercase().contains(c))
            })
            .count();
    }
}
