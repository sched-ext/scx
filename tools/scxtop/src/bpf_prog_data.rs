// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use libbpf_rs::{btf, query::ProgInfoIter, ProgramType};
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Scheduler operation types for sched_ext programs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchedExtOpType {
    Enqueue,
    Dequeue,
    Dispatch,
    Running,
    Stopping,
    Quiescent,
    Yield,
    CoreSched,
    SetWeight,
    SetCpumask,
    CpuAcquire,
    CpuRelease,
    CpuOnline,
    CpuOffline,
    InitTask,
    ExitTask,
    Enable,
    Cancel,
    Unknown,
}

impl SchedExtOpType {
    /// Parse operation type from program name
    pub fn from_program_name(name: &str) -> Self {
        let name_lower = name.to_lowercase();

        if name_lower.contains("enqueue") {
            SchedExtOpType::Enqueue
        } else if name_lower.contains("dequeue") {
            SchedExtOpType::Dequeue
        } else if name_lower.contains("dispatch") {
            SchedExtOpType::Dispatch
        } else if name_lower.contains("running") {
            SchedExtOpType::Running
        } else if name_lower.contains("stopping") {
            SchedExtOpType::Stopping
        } else if name_lower.contains("quiescent") {
            SchedExtOpType::Quiescent
        } else if name_lower.contains("yield") {
            SchedExtOpType::Yield
        } else if name_lower.contains("coresched") {
            SchedExtOpType::CoreSched
        } else if name_lower.contains("set_weight") {
            SchedExtOpType::SetWeight
        } else if name_lower.contains("set_cpumask") {
            SchedExtOpType::SetCpumask
        } else if name_lower.contains("cpu_acquire") {
            SchedExtOpType::CpuAcquire
        } else if name_lower.contains("cpu_release") {
            SchedExtOpType::CpuRelease
        } else if name_lower.contains("cpu_online") {
            SchedExtOpType::CpuOnline
        } else if name_lower.contains("cpu_offline") {
            SchedExtOpType::CpuOffline
        } else if name_lower.contains("init_task") || name_lower.contains("init") {
            SchedExtOpType::InitTask
        } else if name_lower.contains("exit_task") || name_lower.contains("exit") {
            SchedExtOpType::ExitTask
        } else if name_lower.contains("enable") {
            SchedExtOpType::Enable
        } else if name_lower.contains("cancel") {
            SchedExtOpType::Cancel
        } else {
            SchedExtOpType::Unknown
        }
    }

    /// Get display name for this operation type
    pub fn display_name(&self) -> &'static str {
        match self {
            SchedExtOpType::Enqueue => "Enqueue",
            SchedExtOpType::Dequeue => "Dequeue",
            SchedExtOpType::Dispatch => "Dispatch",
            SchedExtOpType::Running => "Running",
            SchedExtOpType::Stopping => "Stopping",
            SchedExtOpType::Quiescent => "Quiescent",
            SchedExtOpType::Yield => "Yield",
            SchedExtOpType::CoreSched => "CoreSched",
            SchedExtOpType::SetWeight => "SetWeight",
            SchedExtOpType::SetCpumask => "SetCpumask",
            SchedExtOpType::CpuAcquire => "CPU Acquire",
            SchedExtOpType::CpuRelease => "CPU Release",
            SchedExtOpType::CpuOnline => "CPU Online",
            SchedExtOpType::CpuOffline => "CPU Offline",
            SchedExtOpType::InitTask => "Init Task",
            SchedExtOpType::ExitTask => "Exit Task",
            SchedExtOpType::Enable => "Enable",
            SchedExtOpType::Cancel => "Cancel",
            SchedExtOpType::Unknown => "Unknown",
        }
    }
}

/// BPF line information for symbolization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfLineInfo {
    pub file_name_off: u32,
    pub line_col: u32,
    pub instruction_offset: u32,
}

impl BpfLineInfo {
    /// Extract line number from line_col field
    #[allow(dead_code)]
    pub fn line_number(&self) -> u32 {
        self.line_col >> 10
    }

    /// Extract column number from line_col field
    #[allow(dead_code)]
    pub fn column_number(&self) -> u32 {
        self.line_col & 0x3ff
    }
}

/// BPF program symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfSymbolInfo {
    pub tag: String,
    pub jited_line_info: Vec<u64>,
    pub line_info: Vec<BpfLineInfo>,
    pub btf_info: Option<Vec<u8>>,
    pub jited_ksyms: Vec<u64>, // Start addresses of JIT-compiled functions
    pub jited_func_lens: Vec<u32>, // Lengths of JIT-compiled functions
}

impl BpfSymbolInfo {
    /// Extract filename from BTF data using file_name_off
    #[allow(dead_code)]
    pub fn get_filename(&self, file_name_off: u32) -> Option<String> {
        // This would need actual BTF parsing implementation
        // For now, return a placeholder
        Some(format!("bpf_program_{}.c", file_name_off))
    }

    /// Get source location for a BPF instruction address
    /// Returns (line_number, column_number) if available
    pub fn get_source_location(&self, ip: u64) -> Option<(u32, u32)> {
        if self.jited_line_info.is_empty() || self.line_info.is_empty() {
            return None;
        }

        // Binary search to find the index in jited_line_info
        match self.jited_line_info.binary_search(&ip) {
            Ok(idx) => {
                // Exact match
                if idx < self.line_info.len() {
                    let line_info = &self.line_info[idx];
                    Some((line_info.line_number(), line_info.column_number()))
                } else {
                    None
                }
            }
            Err(idx) => {
                // Not exact match - check if we're between this and previous address
                if idx > 0 && idx <= self.jited_line_info.len() {
                    let prev_idx = idx - 1;
                    let prev_addr = self.jited_line_info[prev_idx];

                    // If IP is close to previous address, use that line info
                    // (multiple instructions can map to one line)
                    if ip >= prev_addr && ip < prev_addr + 100 && prev_idx < self.line_info.len() {
                        let line_info = &self.line_info[prev_idx];
                        return Some((line_info.line_number(), line_info.column_number()));
                    }
                }
                None
            }
        }
    }

    /// Check if an instruction pointer falls within any of the JIT-compiled functions
    pub fn contains_address(&self, ip: u64) -> bool {
        // If we have jited_ksyms (function start addresses) and jited_func_lens (function lengths)
        // we can check if the IP is within any function's address range
        if !self.jited_ksyms.is_empty() && self.jited_ksyms.len() == self.jited_func_lens.len() {
            for (i, &start_addr) in self.jited_ksyms.iter().enumerate() {
                let end_addr = start_addr + self.jited_func_lens[i] as u64;
                if ip >= start_addr && ip < end_addr {
                    return true;
                }
            }
            false
        } else if !self.jited_line_info.is_empty() {
            // Fallback: use jited_line_info with tolerance
            // The jited_line_info is sorted, so use binary search for efficiency
            match self.jited_line_info.binary_search(&ip) {
                Ok(_) => true, // Exact match
                Err(pos) => {
                    // Check if IP is close to a nearby address
                    // Check previous address if it exists
                    if pos > 0 {
                        let prev_addr = self.jited_line_info[pos - 1];
                        if ip >= prev_addr && ip < prev_addr + 1000 {
                            return true;
                        }
                    }
                    // Check next address if it exists
                    if pos < self.jited_line_info.len() {
                        let next_addr = self.jited_line_info[pos];
                        if ip >= next_addr && ip < next_addr + 1000 {
                            return true;
                        }
                    }
                    false
                }
            }
        } else {
            // No address information available
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfProgData {
    pub id: u32,
    pub prog_type: String,
    pub name: String,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub min_runtime_ns: u64,
    pub max_runtime_ns: u64,
    pub recursion_misses: u64,
    pub verified_insns: u32,
    pub loaded_at: u64,
    pub uid: u32,
    pub gpl_compatible: bool,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_map_ids: u32,
    pub map_ids: Vec<u32>,
    pub btf_id: u32,

    // Latency distribution tracking
    #[serde(skip)]
    pub runtime_history: VecDeque<u64>,
    #[serde(skip)]
    pub calls_history: VecDeque<u64>,
    #[serde(skip)]
    pub timestamp_history: VecDeque<u64>,

    // Latency percentiles (computed from runtime distribution)
    pub p50_runtime_ns: u64,
    pub p90_runtime_ns: u64,
    pub p99_runtime_ns: u64,

    // Scheduler identification
    pub is_sched_ext: bool,
    pub sched_ext_ops_name: Option<String>,
    pub sched_ext_op_type: Option<SchedExtOpType>,
}

impl BpfProgData {
    /// Calculate average runtime per call in nanoseconds
    pub fn avg_runtime_ns(&self) -> f64 {
        if self.run_cnt == 0 {
            0.0
        } else {
            self.run_time_ns as f64 / self.run_cnt as f64
        }
    }

    /// Calculate runtime percentage relative to total system runtime
    pub fn runtime_percentage(&self, total_runtime_ns: u64) -> f64 {
        if total_runtime_ns == 0 {
            0.0
        } else {
            (self.run_time_ns as f64 / total_runtime_ns as f64) * 100.0
        }
    }

    /// Helper function to interpolate percentile values from sorted data
    fn interpolate_percentile(sorted_data: &[u64], rank: f64) -> u64 {
        let rank_floor = rank.floor();
        let rank_ceil = rank.ceil();

        if rank_floor == rank_ceil {
            // Exact index, no interpolation needed
            sorted_data[rank as usize]
        } else {
            // Interpolate between two values
            let idx_floor = rank_floor as usize;
            let idx_ceil = rank_ceil as usize;
            let d0 = sorted_data[idx_floor];
            let d1 = sorted_data[idx_ceil];
            d0 + ((rank - rank_floor) * (d1 - d0) as f64) as u64
        }
    }

    /// Update latency histogram from new samples
    pub fn update_histogram(&mut self, max_samples: usize) {
        // Keep only last N samples
        while self.runtime_history.len() > max_samples {
            self.runtime_history.pop_front();
        }
        while self.calls_history.len() > max_samples {
            self.calls_history.pop_front();
        }
        while self.timestamp_history.len() > max_samples {
            self.timestamp_history.pop_front();
        }

        // Calculate percentiles if we have enough samples
        if self.run_cnt > 0 && !self.runtime_history.is_empty() {
            let mut sorted_runtimes: Vec<u64> = self.runtime_history.iter().copied().collect();
            sorted_runtimes.sort_unstable();

            let len = sorted_runtimes.len();
            if len > 0 {
                // Use proper percentile calculation: rank = (percentile/100) * (n-1)
                // This matches the implementation in stats.rs
                let n = len as f64;

                // P50
                let rank_p50 = 0.50 * (n - 1.0);
                self.p50_runtime_ns = Self::interpolate_percentile(&sorted_runtimes, rank_p50);

                // P90
                let rank_p90 = 0.90 * (n - 1.0);
                self.p90_runtime_ns = Self::interpolate_percentile(&sorted_runtimes, rank_p90);

                // P99
                let rank_p99 = 0.99 * (n - 1.0);
                self.p99_runtime_ns = Self::interpolate_percentile(&sorted_runtimes, rank_p99);
            }
        }
    }

    /// Calculate calls per second based on recent history
    pub fn calls_per_second(&self) -> f64 {
        if self.calls_history.len() < 2 || self.timestamp_history.len() < 2 {
            return 0.0;
        }

        let call_delta = self.calls_history.back().unwrap() - self.calls_history.front().unwrap();
        let time_delta_ns =
            self.timestamp_history.back().unwrap() - self.timestamp_history.front().unwrap();

        if time_delta_ns == 0 {
            return 0.0;
        }

        (call_delta as f64 / time_delta_ns as f64) * 1_000_000_000.0
    }
}

/// Per-operation aggregate statistics
#[derive(Debug, Clone)]
pub struct OperationStats {
    pub total_runtime_ns: u64,
    pub total_calls: u64,
    pub program_count: usize,
}

#[derive(Debug, Clone)]
pub struct BpfProgStats {
    pub programs: HashMap<u32, BpfProgData>,
    pub total_runtime_ns: u64,

    // Per-operation aggregate statistics
    pub operation_stats: HashMap<SchedExtOpType, OperationStats>,
}

// BPF program info structure definition for syscalls
#[repr(C)]
#[derive(Default)]
struct BpfProgInfo {
    type_: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    verified_insns: u32,
}

/// Type alias for the complex return type from extract_line_info
type LineInfoResult = (Vec<BpfLineInfo>, Vec<u64>, Vec<u64>, Vec<u32>);

impl BpfProgStats {
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            total_runtime_ns: 0,
            operation_stats: HashMap::new(),
        }
    }

    /// Calculate aggregate statistics per operation type
    pub fn calculate_operation_stats(&mut self) {
        self.operation_stats.clear();

        for prog_data in self.programs.values() {
            if let Some(op_type) = prog_data.sched_ext_op_type {
                let stats = self
                    .operation_stats
                    .entry(op_type)
                    .or_insert(OperationStats {
                        total_runtime_ns: 0,
                        total_calls: 0,
                        program_count: 0,
                    });

                stats.total_runtime_ns += prog_data.run_time_ns;
                stats.total_calls += prog_data.run_cnt;
                stats.program_count += 1;
            }
        }
    }

    /// Detect if a BPF program is part of sched_ext
    fn detect_sched_ext_program(info: &libbpf_rs::query::ProgramInfo) -> (bool, Option<String>) {
        // Method 1: Check if program type is STRUCT_OPS (sched_ext uses struct_ops)
        if matches!(info.ty, ProgramType::StructOps) {
            // Try to extract the scheduler name from the program name
            let name = info.name.to_string_lossy().to_string();

            // Sched_ext struct_ops programs typically have names like:
            // "scx_<scheduler_name>_ops", "<scheduler_name>_ops", etc.
            if name.contains("_ops") {
                let scheduler_name = name
                    .strip_prefix("scx_")
                    .or(Some(name.as_str()))
                    .and_then(|n| n.strip_suffix("_ops"))
                    .map(|n| n.to_string());

                return (true, scheduler_name);
            }
        }

        // Method 2: Check if the name contains common sched_ext keywords
        let name = info.name.to_string_lossy().to_string();
        let sched_ext_keywords = [
            "enqueue",
            "dequeue",
            "dispatch",
            "running",
            "stopping",
            "quiescent",
            "yield",
            "set_weight",
            "set_cpumask",
            "cpu_acquire",
            "cpu_release",
            "cpu_online",
            "cpu_offline",
            "init_task",
            "exit_task",
        ];

        for keyword in &sched_ext_keywords {
            if name.contains(keyword) {
                // This is likely a sched_ext callback
                // Try to extract scheduler name from prefix
                let parts: Vec<&str> = name.split('_').collect();
                if parts.len() > 1 && parts[0] == "scx" {
                    return (true, Some(parts[1].to_string()));
                }
                return (true, Some("sched_ext".to_string()));
            }
        }

        (false, None)
    }

    /// Convert ProgramType to string representation
    fn program_type_to_string(prog_type: &ProgramType) -> String {
        match prog_type {
            ProgramType::SocketFilter => "socket_filter",
            ProgramType::Kprobe => "kprobe",
            ProgramType::SchedCls => "sched_cls",
            ProgramType::SchedAct => "sched_act",
            ProgramType::Tracepoint => "tracepoint",
            ProgramType::Xdp => "xdp",
            ProgramType::PerfEvent => "perf_event",
            ProgramType::CgroupSkb => "cgroup_skb",
            ProgramType::CgroupSock => "cgroup_sock",
            ProgramType::LwtIn => "lwt_in",
            ProgramType::LwtOut => "lwt_out",
            ProgramType::LwtXmit => "lwt_xmit",
            ProgramType::SockOps => "sock_ops",
            ProgramType::SkSkb => "sk_skb",
            ProgramType::CgroupDevice => "cgroup_device",
            ProgramType::SkMsg => "sk_msg",
            ProgramType::RawTracepoint => "raw_tracepoint",
            ProgramType::CgroupSockAddr => "cgroup_sock_addr",
            ProgramType::LwtSeg6local => "lwt_seg6local",
            ProgramType::LircMode2 => "lirc_mode2",
            ProgramType::SkReuseport => "sk_reuseport",
            ProgramType::FlowDissector => "flow_dissector",
            ProgramType::CgroupSysctl => "cgroup_sysctl",
            ProgramType::RawTracepointWritable => "raw_tracepoint_writable",
            ProgramType::CgroupSockopt => "cgroup_sockopt",
            ProgramType::Tracing => "tracing",
            ProgramType::StructOps => "struct_ops",
            ProgramType::Ext => "ext",
            ProgramType::SkLookup => "sk_lookup",
            ProgramType::Syscall => "syscall",
            _ => "unknown",
        }
        .to_string()
    }

    /// Update existing statistics with new collection, maintaining history
    pub fn collect_and_update(&mut self) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Create a new temporary map to collect current data
        let mut new_programs = HashMap::new();
        let mut new_total_runtime_ns = 0u64;

        // Try to collect BPF programs with runtime statistics using proper BPF calls
        if let Err(e) =
            Self::collect_via_bpf_calls_temp(&mut new_programs, &mut new_total_runtime_ns)
        {
            log::debug!("BPF syscalls failed: {}, falling back to procfs", e);
            // Fallback to procfs scanning (though this won't have runtime stats)
            Self::collect_via_procfs_temp(&mut new_programs, &mut new_total_runtime_ns)?;
        }

        // Now update history for each program
        for (prog_id, mut new_prog_data) in new_programs {
            if let Some(prev_data) = self.programs.get(&prog_id) {
                // Calculate deltas
                let runtime_delta = new_prog_data
                    .run_time_ns
                    .saturating_sub(prev_data.run_time_ns);
                let calls_delta = new_prog_data.run_cnt.saturating_sub(prev_data.run_cnt);

                // Calculate per-call runtime from delta
                let avg_runtime = if calls_delta > 0 {
                    let avg = runtime_delta / calls_delta;

                    // Update min/max
                    if new_prog_data.min_runtime_ns == 0 || avg < new_prog_data.min_runtime_ns {
                        new_prog_data.min_runtime_ns = avg;
                    } else {
                        new_prog_data.min_runtime_ns = prev_data.min_runtime_ns;
                    }

                    if avg > new_prog_data.max_runtime_ns {
                        new_prog_data.max_runtime_ns = avg;
                    } else {
                        new_prog_data.max_runtime_ns = prev_data.max_runtime_ns;
                    }

                    avg
                } else {
                    0
                };

                // Copy history from previous sample
                new_prog_data.runtime_history = prev_data.runtime_history.clone();
                new_prog_data.calls_history = prev_data.calls_history.clone();
                new_prog_data.timestamp_history = prev_data.timestamp_history.clone();
                new_prog_data.p50_runtime_ns = prev_data.p50_runtime_ns;
                new_prog_data.p90_runtime_ns = prev_data.p90_runtime_ns;
                new_prog_data.p99_runtime_ns = prev_data.p99_runtime_ns;

                // Add per-call runtime sample to history (not cumulative total!)
                // Only add if we had actual calls (calls_delta > 0), otherwise skip this sample
                if calls_delta > 0 {
                    new_prog_data.runtime_history.push_back(avg_runtime);
                }
            } else {
                // First time seeing this program, can't calculate delta yet
                // Don't add any sample to runtime_history on first observation
            }

            // Add new samples for calls and timestamp tracking
            // (These are used for calls_per_second calculation)
            new_prog_data.calls_history.push_back(new_prog_data.run_cnt);
            new_prog_data.timestamp_history.push_back(current_time);

            // Update histogram with max 300 samples (5 minutes of history at 1Hz, or ~300 chars wide for large monitors)
            new_prog_data.update_histogram(300);

            self.programs.insert(prog_id, new_prog_data);
        }

        self.total_runtime_ns = new_total_runtime_ns;

        // Calculate per-operation aggregates
        self.calculate_operation_stats();

        Ok(())
    }

    /// Get real BPF symbol information for a program using syscalls and libbpf-rs
    pub fn get_real_symbol_info(prog_id: u32) -> Result<Option<BpfSymbolInfo>> {
        // First, try to get the program file descriptor
        let prog_fd = Self::get_prog_fd_by_id(prog_id)?;
        if prog_fd < 0 {
            return Ok(None);
        }

        // Get detailed program info using bpf_obj_get_info_by_fd
        let prog_info = Self::get_detailed_prog_info(prog_fd)?;

        // Extract line info, JIT info, and function address ranges
        let (line_info, jited_line_info, jited_ksyms, jited_func_lens) =
            Self::extract_line_info(prog_fd, &prog_info)?;

        // Close the file descriptor since we're done with it
        unsafe {
            libc::close(prog_fd);
        }

        // Get BTF information
        let btf_info = Self::get_btf_info_raw(prog_id);

        // Create the tag from program info
        let tag = format!("{:016x}", u64::from_ne_bytes(prog_info.tag));

        Ok(Some(BpfSymbolInfo {
            tag,
            jited_line_info,
            line_info,
            btf_info,
            jited_ksyms,
            jited_func_lens,
        }))
    }

    /// Get the instruction count for a specific BPF program using raw syscalls
    fn get_program_instruction_count(prog_id: u32) -> Result<u32> {
        // Get the program file descriptor first
        let prog_fd = Self::get_prog_fd_by_id(prog_id)?;
        if prog_fd < 0 {
            return Ok(0);
        }

        // Get detailed program info to extract verified_insns
        let prog_info = Self::get_detailed_prog_info(prog_fd)?;

        // Close the file descriptor since we only needed it for the query
        unsafe {
            libc::close(prog_fd);
        }

        Ok(prog_info.verified_insns)
    }

    /// Get program file descriptor by program ID
    fn get_prog_fd_by_id(prog_id: u32) -> Result<i32> {
        use std::mem;

        const BPF_PROG_GET_FD_BY_ID: u32 = 13;

        #[repr(C)]
        #[derive(Default)]
        struct BpfAttr {
            prog_get_fd_by_id: BpfProgGetFdById,
        }

        #[repr(C)]
        #[derive(Default)]
        struct BpfProgGetFdById {
            prog_id: u32,
            next_id: u32,
            open_flags: u32,
        }

        let mut attr = BpfAttr {
            prog_get_fd_by_id: BpfProgGetFdById {
                prog_id,
                next_id: 0,
                open_flags: 0,
            },
        };

        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_GET_FD_BY_ID as libc::c_long,
                &mut attr as *mut _ as libc::c_long,
                mem::size_of::<BpfAttr>() as libc::c_long,
            )
        };

        if fd < 0 {
            return Err(anyhow!(
                "Failed to get prog fd by ID {}: {}",
                prog_id,
                std::io::Error::last_os_error()
            ));
        }

        Ok(fd as i32)
    }

    /// Get detailed BPF program information
    fn get_detailed_prog_info(prog_fd: i32) -> Result<BpfProgInfo> {
        use std::mem;

        const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

        #[repr(C)]
        #[derive(Default)]
        struct BpfAttr {
            info: BpfObjGetInfo,
        }

        #[repr(C)]
        #[derive(Default)]
        struct BpfObjGetInfo {
            bpf_fd: u32,
            info_len: u32,
            info: u64,
        }

        let mut prog_info = BpfProgInfo::default();
        let mut attr = BpfAttr {
            info: BpfObjGetInfo {
                bpf_fd: prog_fd as u32,
                info_len: mem::size_of::<BpfProgInfo>() as u32,
                info: &mut prog_info as *mut _ as u64,
            },
        };

        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
                &mut attr as *mut _ as libc::c_long,
                mem::size_of::<BpfAttr>() as libc::c_long,
            )
        };

        if result < 0 {
            return Err(anyhow!(
                "Failed to get program info: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(prog_info)
    }

    /// Extract line info, JIT line info, and JIT function addresses from BPF program info
    fn extract_line_info(prog_fd: i32, prog_info: &BpfProgInfo) -> Result<LineInfoResult> {
        use std::mem;

        const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

        #[repr(C)]
        #[derive(Default)]
        struct BpfAttr {
            info: BpfObjGetInfo,
        }

        #[repr(C)]
        #[derive(Default)]
        struct BpfObjGetInfo {
            bpf_fd: u32,
            info_len: u32,
            info: u64,
        }

        let mut line_info = Vec::new();
        let mut jited_line_info = Vec::new();
        let mut jited_ksyms = Vec::new();
        let mut jited_func_lens = Vec::new();

        // If the program has line info, extract it
        if prog_info.nr_line_info > 0 {
            // Allocate buffers for line info
            let line_info_size =
                prog_info.nr_line_info as usize * prog_info.line_info_rec_size as usize;
            let mut line_info_buf = vec![0u8; line_info_size];

            // Create a new prog_info structure with the buffer pointers set
            let mut new_prog_info = BpfProgInfo {
                line_info: line_info_buf.as_mut_ptr() as u64,
                nr_line_info: prog_info.nr_line_info,
                line_info_rec_size: prog_info.line_info_rec_size,
                ..Default::default()
            };

            // Make syscall to get line info
            let mut attr = BpfAttr {
                info: BpfObjGetInfo {
                    bpf_fd: prog_fd as u32,
                    info_len: mem::size_of::<BpfProgInfo>() as u32,
                    info: &mut new_prog_info as *mut _ as u64,
                },
            };

            let result = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
                    &mut attr as *mut _ as libc::c_long,
                    mem::size_of::<BpfAttr>() as libc::c_long,
                )
            };

            if result >= 0 {
                // Extract BpfLineInfo entries from the buffer
                let line_info_rec_size = prog_info.line_info_rec_size as usize;
                for i in 0..prog_info.nr_line_info as usize {
                    let offset = i * line_info_rec_size;
                    if offset + 12 <= line_info_buf.len() {
                        let instruction_offset = u32::from_ne_bytes([
                            line_info_buf[offset],
                            line_info_buf[offset + 1],
                            line_info_buf[offset + 2],
                            line_info_buf[offset + 3],
                        ]);
                        let file_name_off = u32::from_ne_bytes([
                            line_info_buf[offset + 4],
                            line_info_buf[offset + 5],
                            line_info_buf[offset + 6],
                            line_info_buf[offset + 7],
                        ]);
                        let line_col = u32::from_ne_bytes([
                            line_info_buf[offset + 8],
                            line_info_buf[offset + 9],
                            line_info_buf[offset + 10],
                            line_info_buf[offset + 11],
                        ]);

                        line_info.push(BpfLineInfo {
                            file_name_off,
                            line_col,
                            instruction_offset,
                        });
                    }
                }
            } else {
                log::warn!(
                    "Failed to extract line info: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // If the program has JIT line info, extract it
        if prog_info.nr_jited_line_info > 0 {
            let jited_line_info_size =
                prog_info.nr_jited_line_info as usize * prog_info.jited_line_info_rec_size as usize;
            let mut jited_line_info_buf = vec![0u8; jited_line_info_size];

            // Create a new prog_info structure with the buffer pointers set
            let mut new_prog_info = BpfProgInfo {
                jited_line_info: jited_line_info_buf.as_mut_ptr() as u64,
                nr_jited_line_info: prog_info.nr_jited_line_info,
                jited_line_info_rec_size: prog_info.jited_line_info_rec_size,
                ..Default::default()
            };

            // Make syscall to get jited line info
            let mut attr = BpfAttr {
                info: BpfObjGetInfo {
                    bpf_fd: prog_fd as u32,
                    info_len: mem::size_of::<BpfProgInfo>() as u32,
                    info: &mut new_prog_info as *mut _ as u64,
                },
            };

            let result = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
                    &mut attr as *mut _ as libc::c_long,
                    mem::size_of::<BpfAttr>() as libc::c_long,
                )
            };

            if result >= 0 {
                // Extract JIT addresses
                let jited_line_info_rec_size = prog_info.jited_line_info_rec_size as usize;
                for i in 0..prog_info.nr_jited_line_info as usize {
                    let offset = i * jited_line_info_rec_size;
                    if offset + 8 <= jited_line_info_buf.len() {
                        let addr = u64::from_ne_bytes([
                            jited_line_info_buf[offset],
                            jited_line_info_buf[offset + 1],
                            jited_line_info_buf[offset + 2],
                            jited_line_info_buf[offset + 3],
                            jited_line_info_buf[offset + 4],
                            jited_line_info_buf[offset + 5],
                            jited_line_info_buf[offset + 6],
                            jited_line_info_buf[offset + 7],
                        ]);
                        jited_line_info.push(addr);
                    }
                }
            } else {
                log::warn!(
                    "Failed to extract JIT line info: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Extract JIT kernel symbols (function start addresses) and function lengths
        if prog_info.nr_jited_ksyms > 0 {
            let ksyms_size = prog_info.nr_jited_ksyms as usize * 8; // u64 addresses
            let mut ksyms_buf = vec![0u8; ksyms_size];

            let func_lens_size = prog_info.nr_jited_func_lens as usize * 4; // u32 lengths
            let mut func_lens_buf = vec![0u8; func_lens_size];

            // Create a new prog_info structure with both buffer pointers set
            let mut new_prog_info = BpfProgInfo {
                jited_ksyms: ksyms_buf.as_mut_ptr() as u64,
                nr_jited_ksyms: prog_info.nr_jited_ksyms,
                jited_func_lens: func_lens_buf.as_mut_ptr() as u64,
                nr_jited_func_lens: prog_info.nr_jited_func_lens,
                ..Default::default()
            };

            // Make syscall to get jited ksyms and func lens
            let mut attr = BpfAttr {
                info: BpfObjGetInfo {
                    bpf_fd: prog_fd as u32,
                    info_len: mem::size_of::<BpfProgInfo>() as u32,
                    info: &mut new_prog_info as *mut _ as u64,
                },
            };

            let result = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
                    &mut attr as *mut _ as libc::c_long,
                    mem::size_of::<BpfAttr>() as libc::c_long,
                )
            };

            if result >= 0 {
                // Extract kernel symbol addresses (function start addresses)
                for i in 0..prog_info.nr_jited_ksyms as usize {
                    let offset = i * 8;
                    if offset + 8 <= ksyms_buf.len() {
                        let addr = u64::from_ne_bytes([
                            ksyms_buf[offset],
                            ksyms_buf[offset + 1],
                            ksyms_buf[offset + 2],
                            ksyms_buf[offset + 3],
                            ksyms_buf[offset + 4],
                            ksyms_buf[offset + 5],
                            ksyms_buf[offset + 6],
                            ksyms_buf[offset + 7],
                        ]);
                        jited_ksyms.push(addr);
                    }
                }

                // Extract function lengths
                for i in 0..prog_info.nr_jited_func_lens as usize {
                    let offset = i * 4;
                    if offset + 4 <= func_lens_buf.len() {
                        let len = u32::from_ne_bytes([
                            func_lens_buf[offset],
                            func_lens_buf[offset + 1],
                            func_lens_buf[offset + 2],
                            func_lens_buf[offset + 3],
                        ]);
                        jited_func_lens.push(len);
                    }
                }
            } else {
                log::warn!(
                    "Failed to extract JIT ksyms/func_lens: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        Ok((line_info, jited_line_info, jited_ksyms, jited_func_lens))
    }

    /// Get BTF information for a program using libbpf-rs btf module
    fn get_btf_info_raw(prog_id: u32) -> Option<Vec<u8>> {
        if prog_id == 0 {
            return None;
        }

        // Use libbpf-rs btf module to get BTF data from program ID
        match btf::Btf::from_prog_id(prog_id) {
            Ok(_btf_obj) => {
                // The BTF object could be used for type information in the future
                None // For now, return None since raw data extraction isn't available
            }
            Err(e) => {
                log::warn!("Failed to get BTF data for program ID {}: {}", prog_id, e);
                None
            }
        }
    }

    /// Collect BPF program stats using libbpf-rs query module (temporary collection)
    /// Note: Assumes BPF stats are already enabled by the caller
    fn collect_via_bpf_calls_temp(
        programs: &mut HashMap<u32, BpfProgData>,
        total_runtime_ns: &mut u64,
    ) -> Result<()> {
        // Use libbpf-rs query module to iterate over loaded BPF programs
        for prog_info in ProgInfoIter::default() {
            if let Some(prog_data) = Self::convert_libbpf_prog_info(&prog_info) {
                *total_runtime_ns += prog_data.run_time_ns;
                programs.insert(prog_data.id, prog_data);
            }
        }

        Ok(())
    }

    /// Convert libbpf-rs ProgramInfo to our BpfProgData structure
    fn convert_libbpf_prog_info(info: &libbpf_rs::query::ProgramInfo) -> Option<BpfProgData> {
        // Extract basic program information (access as fields, not methods)
        let id = info.id;
        let name = info.name.to_string_lossy().to_string();
        let prog_type = Self::program_type_to_string(&info.ty);

        // Extract runtime statistics (access as fields, not methods)
        let run_time_ns = info.run_time_ns;
        let run_cnt = info.run_cnt;
        let recursion_misses = info.recursion_misses;

        // Extract other program metadata (access as fields, not methods)
        // Note: Some fields may not exist on ProgramInfo, use defaults
        // Get instruction count using raw BPF syscalls since xlated_prog_insns might be empty
        let verified_insns = Self::get_program_instruction_count(id).unwrap_or(0);
        let loaded_at = info.load_time.as_nanos() as u64; // Convert Duration to nanoseconds
        let uid = info.created_by_uid;
        let gpl_compatible = info.gpl_compatible;
        let netns_dev = info.netns_dev;
        let netns_ino = info.netns_ino;
        let btf_id = info.btf_id;

        // Extract map IDs if available (access as field, not method)
        let map_ids = info.map_ids.clone();
        let nr_map_ids = map_ids.len() as u32;

        // Detect if this is a sched_ext program
        let (is_sched_ext, sched_ext_ops_name) = Self::detect_sched_ext_program(info);

        // Determine operation type if this is a sched_ext program
        let sched_ext_op_type = if is_sched_ext {
            Some(SchedExtOpType::from_program_name(&name))
        } else {
            None
        };

        Some(BpfProgData {
            id,
            prog_type,
            name,
            run_time_ns,
            run_cnt,
            min_runtime_ns: 0, // Will be calculated from deltas
            max_runtime_ns: 0, // Will be calculated from deltas
            recursion_misses,
            verified_insns,
            loaded_at,
            uid,
            gpl_compatible,
            netns_dev,
            netns_ino,
            nr_map_ids,
            map_ids,
            btf_id,
            // Initialize empty history
            runtime_history: VecDeque::new(),
            calls_history: VecDeque::new(),
            timestamp_history: VecDeque::new(),
            p50_runtime_ns: 0,
            p90_runtime_ns: 0,
            p99_runtime_ns: 0,
            is_sched_ext,
            sched_ext_ops_name,
            sched_ext_op_type,
        })
    }

    /// Fallback method using procfs to find BPF programs (temporary collection)
    fn collect_via_procfs_temp(
        programs: &mut HashMap<u32, BpfProgData>,
        total_runtime_ns: &mut u64,
    ) -> Result<()> {
        // Scan /proc for processes that might have BPF programs
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();

            if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if Self::scan_process_for_bpf_temp(pid, programs, total_runtime_ns).is_err() {
                        // Ignore individual process scan failures
                        continue;
                    }
                }
            }
        }

        Ok(())
    }

    /// Scan a specific process for BPF file descriptors (temporary collection)
    fn scan_process_for_bpf_temp(
        pid: u32,
        programs: &mut HashMap<u32, BpfProgData>,
        total_runtime_ns: &mut u64,
    ) -> Result<()> {
        let fd_dir = format!("/proc/{}/fd", pid);

        if !Path::new(&fd_dir).exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&fd_dir)? {
            let entry = entry?;
            let fd_path = entry.path();

            if let Some(fd_str) = fd_path.file_name().and_then(|n| n.to_str()) {
                if let Ok(fd) = fd_str.parse::<u32>() {
                    if Self::check_fd_for_bpf_temp(pid, fd, programs, total_runtime_ns).is_err() {
                        // Ignore individual FD check failures
                        continue;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a file descriptor is a BPF program and collect its info (temporary collection)
    fn check_fd_for_bpf_temp(
        pid: u32,
        fd: u32,
        programs: &mut HashMap<u32, BpfProgData>,
        total_runtime_ns: &mut u64,
    ) -> Result<()> {
        let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd);

        if let Ok(content) = fs::read_to_string(&fdinfo_path) {
            if content.contains("prog_type") {
                // This looks like a BPF program, try to parse it
                if let Ok(prog_data) = Self::parse_bpf_fdinfo(&content, fd) {
                    *total_runtime_ns += prog_data.run_time_ns;
                    programs.insert(prog_data.id, prog_data);
                }
            }
        }

        Ok(())
    }

    /// Parse BPF program information from fdinfo content
    fn parse_bpf_fdinfo(content: &str, fd: u32) -> Result<BpfProgData> {
        let mut prog_data = BpfProgData {
            id: fd, // Use FD as fallback ID
            prog_type: String::new(),
            name: String::new(),
            run_time_ns: 0,
            run_cnt: 0,
            min_runtime_ns: 0,
            max_runtime_ns: 0,
            recursion_misses: 0,
            verified_insns: 0,
            loaded_at: 0,
            uid: 0,
            gpl_compatible: false,
            netns_dev: 0,
            netns_ino: 0,
            nr_map_ids: 0,
            map_ids: Vec::new(),
            btf_id: 0,
            // Initialize empty history
            runtime_history: VecDeque::new(),
            calls_history: VecDeque::new(),
            timestamp_history: VecDeque::new(),
            p50_runtime_ns: 0,
            p90_runtime_ns: 0,
            p99_runtime_ns: 0,
            is_sched_ext: false,
            sched_ext_ops_name: None,
            sched_ext_op_type: None,
        };

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "prog_type:" => prog_data.prog_type = parts[1].to_string(),
                    "prog_name:" => prog_data.name = parts[1].to_string(),
                    "run_time_ns:" => prog_data.run_time_ns = parts[1].parse().unwrap_or(0),
                    "run_cnt:" => prog_data.run_cnt = parts[1].parse().unwrap_or(0),
                    "recursion_misses:" => {
                        prog_data.recursion_misses = parts[1].parse().unwrap_or(0)
                    }
                    "verified_insns:" => prog_data.verified_insns = parts[1].parse().unwrap_or(0),
                    "load_time:" => prog_data.loaded_at = parts[1].parse().unwrap_or(0),
                    "uid:" => prog_data.uid = parts[1].parse().unwrap_or(0),
                    "gpl_compatible:" => prog_data.gpl_compatible = parts[1] == "1",
                    "netns_dev:" => prog_data.netns_dev = parts[1].parse().unwrap_or(0),
                    "netns_ino:" => prog_data.netns_ino = parts[1].parse().unwrap_or(0),
                    "btf_id:" => prog_data.btf_id = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(prog_data)
    }
}

impl Default for BpfProgStats {
    fn default() -> Self {
        Self::new()
    }
}
