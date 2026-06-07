// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::record::{
    perf_binary, perf_script_output_exists, report_perf_script_stderr, PERF_MEM_DATA_FILE,
    PERF_MEM_JSONL_FILE, PERF_MEM_SCRIPT_FIELDS, PERF_MEM_SCRIPT_FILE, PERF_SCHED_DATA_FILE,
    PERF_SCHED_JSONL_FILE, PERF_SCHED_SCRIPT_FIELDS, PERF_SCHED_SCRIPT_FILE,
};
use anyhow::{bail, Context as _, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

#[derive(Debug, Parser)]
pub struct ProcessOpts {
    /// Path to profile file (tar.gz) or directory
    #[clap(short = 'f', long)]
    pub file: PathBuf,

    /// Print extra information during processing
    #[clap(short, long)]
    pub verbose: bool,
}

/// Represents a single perf mem sample record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfMemRecord {
    pub comm: String,
    pub tid: u32,
    pub pid: u32,
    pub time: String,
    pub addr: String,
    pub cgroup: String,
    pub ip: String,
    pub sym: String,
    pub dso: String,
    pub phys_addr: String,
    pub data_page_size: u64,
    #[serde(default)]
    pub hint: u64,
    #[serde(skip, default)]
    sample_time_ns: Option<u64>,
}

/// Represents a single sched trace record from perf sched script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfSchedScriptRecord {
    pub comm: String,
    pub pid: i32,
    pub tid: i32,
    pub cpu: u32,
    pub time: f64,
    pub event: String,
    pub trace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Map<String, Value>>,
    #[serde(default)]
    pub hint: u64,
    #[serde(skip, default)]
    sample_time_ns: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct HintRecord {
    pid: i32,
    #[allow(dead_code)]
    tgid: i32,
    hints: u64,
    timestamp: u64,
}

#[derive(Debug, Clone)]
struct ThreadHintTimeline {
    records: Vec<HintRecord>,
}

#[derive(Debug, Clone)]
struct OrderingIssues {
    label: &'static str,
    violations: u64,
    affected_tids: HashSet<u32>,
    example_tids: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
struct TraceArtifacts<'a> {
    data_file: &'a str,
    script_file: &'a str,
    jsonl_file: &'a str,
    script_fields: &'a str,
    script_kind: &'a str,
    jsonl_kind: &'a str,
}

#[derive(Debug, Clone, Default)]
struct HintIndex {
    timelines: HashMap<u32, ThreadHintTimeline>,
    ordering_issues: Option<OrderingIssues>,
}

#[derive(Debug)]
struct HintAnnotator<'a> {
    hint_index: &'a HintIndex,
    cursors: HashMap<u32, usize>,
    last_sample_time_ns: HashMap<u32, u64>,
    ordering_issues: OrderingIssues,
}

trait HintAssignable {
    fn hint_tid(&self) -> Option<u32>;
    fn hint_time_ns(&self) -> Option<u64>;
    fn set_hint(&mut self, hint: u64);
}

impl HintIndex {
    fn load_if_exists(profile_dir: &Path) -> Result<Option<Self>> {
        let hints_path = profile_dir.join("hints.jsonl");
        if !hints_path.exists() {
            return Ok(None);
        }

        let file = File::open(&hints_path).context("failed to open hints.jsonl")?;
        let reader = BufReader::new(file);
        let mut timelines: HashMap<u32, Vec<HintRecord>> = HashMap::new();
        let mut last_timestamp_by_tid: HashMap<u32, u64> = HashMap::new();
        let mut ordering_issues = OrderingIssues::new("hint timeline");

        for line in reader.lines() {
            let line = line.context("failed to read hints.jsonl line")?;
            if line.trim().is_empty() {
                continue;
            }
            let record: HintRecord =
                serde_json::from_str(&line).context("failed to parse hints.jsonl record")?;
            if let Ok(pid) = u32::try_from(record.pid) {
                if let Some(last_timestamp) = last_timestamp_by_tid.insert(pid, record.timestamp) {
                    ordering_issues.observe(pid, last_timestamp, record.timestamp);
                }
                timelines.entry(pid).or_default().push(record);
            }
        }

        let timelines = timelines
            .into_iter()
            .map(|(tid, mut records)| {
                records.sort_by_key(|record| record.timestamp);
                (tid, ThreadHintTimeline { records })
            })
            .collect();

        Ok(Some(Self {
            timelines,
            ordering_issues: ordering_issues.into_option(),
        }))
    }
}

impl<'a> HintAnnotator<'a> {
    fn new(hint_index: &'a HintIndex) -> Self {
        Self {
            hint_index,
            cursors: HashMap::new(),
            last_sample_time_ns: HashMap::new(),
            ordering_issues: OrderingIssues::new("sample timeline"),
        }
    }

    fn annotate<R: HintAssignable>(&mut self, record: &mut R) {
        let hint = record
            .hint_tid()
            .zip(record.hint_time_ns())
            .and_then(|(tid, time_ns)| self.resolve_hint(tid, time_ns))
            .unwrap_or(0);
        record.set_hint(hint);
    }

    fn annotate_sched_record(&mut self, record: &mut PerfSchedScriptRecord) {
        self.annotate(record);

        if record.event != "sched:sched_switch" {
            return;
        }

        let Some(time_ns) = record.hint_time_ns() else {
            return;
        };
        let Some(fields) = record.fields.as_mut() else {
            return;
        };

        fields.insert(
            "prev_hint".to_string(),
            Value::Number(Number::from(record.hint)),
        );

        let next_hint = fields
            .get("next_pid")
            .and_then(Value::as_i64)
            .and_then(|tid| u32::try_from(tid).ok())
            .and_then(|tid| self.resolve_hint(tid, time_ns))
            .unwrap_or(0);
        fields.insert(
            "next_hint".to_string(),
            Value::Number(Number::from(next_hint)),
        );
    }

    fn resolve_hint(&mut self, tid: u32, time_ns: u64) -> Option<u64> {
        if let Some(last_time_ns) = self.last_sample_time_ns.insert(tid, time_ns) {
            self.ordering_issues.observe(tid, last_time_ns, time_ns);
        }
        let timeline = self.hint_index.timelines.get(&tid)?;
        let cursor = self.cursors.entry(tid).or_insert(0);
        timeline.resolve_hint(time_ns, cursor)
    }

    fn finish(self) -> Option<OrderingIssues> {
        self.ordering_issues.into_option()
    }
}

impl ThreadHintTimeline {
    fn resolve_hint(&self, time_ns: u64, cursor: &mut usize) -> Option<u64> {
        if self.records.is_empty() {
            return None;
        }

        if *cursor >= self.records.len() {
            *cursor = self.records.len() - 1;
        }

        if self.records[*cursor].timestamp > time_ns {
            let idx = self
                .records
                .partition_point(|record| record.timestamp <= time_ns);
            if idx == 0 {
                *cursor = 0;
                return None;
            }
            *cursor = idx - 1;
            return Some(self.records[*cursor].hints);
        }

        while *cursor + 1 < self.records.len() && self.records[*cursor + 1].timestamp <= time_ns {
            *cursor += 1;
        }

        Some(self.records[*cursor].hints)
    }
}

impl HintAssignable for PerfMemRecord {
    fn hint_tid(&self) -> Option<u32> {
        Some(self.tid)
    }

    fn hint_time_ns(&self) -> Option<u64> {
        self.sample_time_ns
    }

    fn set_hint(&mut self, hint: u64) {
        self.hint = hint;
    }
}

impl HintAssignable for PerfSchedScriptRecord {
    fn hint_tid(&self) -> Option<u32> {
        u32::try_from(self.tid).ok()
    }

    fn hint_time_ns(&self) -> Option<u64> {
        self.sample_time_ns
    }

    fn set_hint(&mut self, hint: u64) {
        self.hint = hint;
    }
}

impl OrderingIssues {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            violations: 0,
            affected_tids: HashSet::new(),
            example_tids: Vec::new(),
        }
    }

    fn observe(&mut self, tid: u32, last_timestamp: u64, current_timestamp: u64) {
        if current_timestamp < last_timestamp {
            self.violations += 1;
            if self.affected_tids.insert(tid) && self.example_tids.len() < 8 {
                self.example_tids.push(tid);
            }
        }
    }

    fn into_option(self) -> Option<Self> {
        (self.violations > 0).then_some(self)
    }

    fn warn(&self, context: &str, conservative_action: &str) {
        let examples = if self.example_tids.is_empty() {
            String::new()
        } else {
            format!(
                " Example tids: {}.",
                self.example_tids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        eprintln!(
            "WARNING: detected {} out-of-order {} violation(s) across {} tid(s) while processing {}. {}{} Please fix the input ordering if possible.",
            self.violations,
            self.label,
            self.affected_tids.len(),
            context,
            conservative_action,
            examples
        );
    }
}

pub fn cmd_process(opts: ProcessOpts) -> Result<()> {
    let profile_dir = prepare_profile_dir(&opts.file)?;

    let output_dir = create_output_dir(&profile_dir)?;
    println!("Output directory: {}", output_dir.display());

    match run_processing(&profile_dir, &output_dir, opts.verbose) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_dir_all(&output_dir);
            Err(e)
        }
    }
}

fn run_processing(profile_dir: &Path, output_dir: &Path, verbose: bool) -> Result<()> {
    let mem_trace = TraceArtifacts {
        data_file: PERF_MEM_DATA_FILE,
        script_file: PERF_MEM_SCRIPT_FILE,
        jsonl_file: PERF_MEM_JSONL_FILE,
        script_fields: PERF_MEM_SCRIPT_FIELDS,
        script_kind: "perf.mem.script",
        jsonl_kind: "perf.mem.jsonl",
    };
    let sched_trace = TraceArtifacts {
        data_file: PERF_SCHED_DATA_FILE,
        script_file: PERF_SCHED_SCRIPT_FILE,
        jsonl_file: PERF_SCHED_JSONL_FILE,
        script_fields: PERF_SCHED_SCRIPT_FIELDS,
        script_kind: "perf.sched.script",
        jsonl_kind: "perf.sched.jsonl",
    };
    let hint_index = HintIndex::load_if_exists(profile_dir)?;
    if let Some(hint_index) = hint_index.as_ref() {
        if let Some(ordering_issues) = hint_index.ordering_issues.as_ref() {
            ordering_issues.warn(
                "hints.jsonl",
                "Hint events will be sorted conservatively before annotation.",
            );
        }
    }
    copy_hints_if_present(profile_dir, output_dir)?;
    if let Some(mem_perf_script_dst) =
        prepare_trace_script_if_present(profile_dir, output_dir, mem_trace)?
    {
        parse_perf_mem_script_to_jsonl(
            &mem_perf_script_dst,
            &output_dir.join(mem_trace.jsonl_file),
            hint_index.as_ref(),
            mem_trace,
            verbose,
        )?;
    }

    if let Some(sched_perf_script_dst) =
        prepare_trace_script_if_present(profile_dir, output_dir, sched_trace)?
    {
        parse_sched_perf_script_to_jsonl(
            &sched_perf_script_dst,
            &output_dir.join(sched_trace.jsonl_file),
            hint_index.as_ref(),
            sched_trace,
            verbose,
        )?;
    }

    print_profile_contents(output_dir)?;
    Ok(())
}

fn copy_hints_if_present(profile_dir: &Path, output_dir: &Path) -> Result<()> {
    let hints_src = profile_dir.join("hints.jsonl");
    if !hints_src.exists() {
        return Ok(());
    }

    let hints_dst = output_dir.join("hints.jsonl");
    fs::copy(&hints_src, &hints_dst).with_context(|| {
        format!(
            "failed to copy hints.jsonl from '{}' to '{}'",
            hints_src.display(),
            hints_dst.display()
        )
    })?;
    Ok(())
}

fn prepare_trace_script_if_present(
    profile_dir: &Path,
    output_dir: &Path,
    artifacts: TraceArtifacts<'_>,
) -> Result<Option<PathBuf>> {
    let perf_data_src = profile_dir.join(artifacts.data_file);
    let perf_script_src = profile_dir.join(artifacts.script_file);
    let perf_script_dst = output_dir.join(artifacts.script_file);

    if !perf_script_src.exists() && !perf_data_src.exists() {
        println!(
            "Skipping {}: neither {} nor {} is present",
            artifacts.jsonl_kind, artifacts.script_file, artifacts.data_file
        );
        return Ok(None);
    }

    if !perf_script_src.exists() {
        println!(
            "Generating {} from {}...",
            artifacts.script_kind, artifacts.data_file
        );
        generate_perf_script(&perf_data_src, &perf_script_src, artifacts.script_fields)?;
    }

    println!("Copying {}...", artifacts.script_kind);
    fs::copy(&perf_script_src, &perf_script_dst)
        .with_context(|| format!("failed to copy {}", artifacts.script_kind))?;

    Ok(Some(perf_script_dst))
}

fn prepare_profile_dir(path: &Path) -> Result<PathBuf> {
    if path.is_dir() {
        return Ok(path.to_path_buf());
    }

    let path_str = path.to_string_lossy();
    if !path_str.ends_with(".tar.gz") {
        bail!("'{}' is not a directory or tar.gz archive", path.display());
    }

    let desired_dir = PathBuf::from(path_str.trim_end_matches(".tar.gz"));
    if desired_dir.exists() {
        return Ok(desired_dir);
    }

    validate_archive_layout(path)?;
    fs::create_dir_all(&desired_dir).with_context(|| {
        format!(
            "failed to create extraction directory '{}'",
            desired_dir.display()
        )
    })?;

    let status = Command::new("tar")
        .args([
            "-xzf",
            &path_str,
            "--strip-components=1",
            "-C",
            desired_dir
                .to_str()
                .context("invalid extraction directory path")?,
        ])
        .status()
        .context("failed to run tar")?;

    if !status.success() {
        let _ = fs::remove_dir_all(&desired_dir);
        bail!("tar extraction failed with status: {}", status);
    }

    if !desired_dir.is_dir() {
        bail!(
            "expected extracted directory '{}' not found after extraction",
            desired_dir.display()
        );
    }

    Ok(desired_dir)
}

fn create_output_dir(profile_dir: &Path) -> Result<PathBuf> {
    let output_dir = PathBuf::from(format!("{}.post", profile_dir.display()));

    if output_dir.exists() {
        bail!("output directory '{}' already exists", output_dir.display());
    }

    fs::create_dir_all(&output_dir).context("failed to create output directory")?;

    Ok(output_dir)
}

fn validate_archive_layout(archive_path: &Path) -> Result<()> {
    let archive_name = archive_path
        .file_name()
        .context("invalid archive path")?
        .to_string_lossy()
        .to_string();

    let output = Command::new("tar")
        .args([
            "-tzf",
            archive_path.to_str().context("invalid archive path")?,
        ])
        .output()
        .context("failed to inspect tar archive")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to inspect tar archive: {}", stderr.trim());
    }

    let listing = String::from_utf8(output.stdout).context("tar listing was not valid UTF-8")?;
    let mut top_levels = HashSet::new();

    for line in listing.lines() {
        let line = line.trim();
        if line.is_empty() || line == "." {
            continue;
        }

        let top = line.split('/').next().unwrap_or_default();
        if top.is_empty() || top == "." {
            continue;
        }

        top_levels.insert(top.to_string());
    }

    match top_levels.len() {
        1 => Ok(()),
        0 => bail!("archive '{}' appears to be empty", archive_name),
        _ => bail!(
            "archive '{}' contains multiple top-level entries; unable to extract into a single profile directory",
            archive_name
        ),
    }
}

fn generate_perf_script(
    perf_data_path: &Path,
    perf_script_path: &Path,
    fields: &str,
) -> Result<()> {
    if !perf_data_path.exists() {
        bail!("perf data file '{}' not found", perf_data_path.display());
    }

    let output_file = File::create(perf_script_path)
        .with_context(|| format!("failed to create {}", perf_script_path.display()))?;

    let output = Command::new(perf_binary())
        .args([
            "script",
            "-F",
            fields,
            "-i",
            perf_data_path.to_str().context("invalid perf.data path")?,
        ])
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run perf script")?
        .wait_with_output()
        .context("failed to run perf script")?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_len = fs::metadata(perf_script_path)
        .map(|meta| meta.len())
        .unwrap_or(0);

    if !output.status.success() {
        if perf_script_output_exists(output_len) {
            eprintln!(
                "warning: perf script exited with status {} after writing {} bytes to {}. Continuing with the generated output because the output file is non-empty.",
                output.status,
                output_len,
                perf_script_path.display()
            );
            report_perf_script_stderr(&perf_script_path.display().to_string(), &stderr);
            return Ok(());
        }
        let _ = fs::remove_file(perf_script_path);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("perf script failed with status: {}", output.status);
        }
        bail!(
            "perf script failed with status: {}: {}",
            output.status,
            stderr
        );
    }

    report_perf_script_stderr(&perf_script_path.display().to_string(), &stderr);

    Ok(())
}

fn sched_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?P<comm>.*?)\s+(?P<pid>-?\d+)/(?P<tid>-?\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<time>\d+\.\d+):\s+(?P<event>[^:]+:[^:]+):\s*(?P<trace>.*)$",
        )
        .unwrap()
    })
}

fn sched_switch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<prev_comm>.+?):(?P<prev_pid>-?\d+)\s+\[(?P<prev_prio>-?\d+)\]\s+(?P<prev_state>.+?)\s+==>\s+(?P<next_comm>.+?):(?P<next_pid>-?\d+)\s+\[(?P<next_prio>-?\d+)\]$",
        )
        .unwrap()
    })
}

fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\w+)=([^\s\]]+)").unwrap())
}

fn action_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[action=([^\]]+)\]").unwrap())
}

fn parse_page_size(s: &str) -> u64 {
    let s = s.trim();
    if s == "N/A" || s.is_empty() {
        return 0;
    }
    let s_upper = s.to_uppercase();
    if let Some(num_str) = s_upper.strip_suffix('K') {
        num_str.parse::<u64>().unwrap_or(0) * 1024
    } else if let Some(num_str) = s_upper.strip_suffix('M') {
        num_str.parse::<u64>().unwrap_or(0) * 1024 * 1024
    } else if let Some(num_str) = s_upper.strip_suffix('G') {
        num_str.parse::<u64>().unwrap_or(0) * 1024 * 1024 * 1024
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

fn parse_u32_pair(part: &str) -> Option<(u32, u32)> {
    let (first, second) = part.split_once('/')?;
    Some((first.parse().ok()?, second.parse().ok()?))
}

fn parse_perf_time_ns(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (secs_str, frac_str) = match s.split_once('.') {
        Some((secs, frac)) => (secs, frac),
        None => (s, ""),
    };

    let secs = secs_str.parse::<u64>().ok()?;
    let mut frac_ns = 0u64;
    let mut scale = 100_000_000u64;

    for ch in frac_str.chars().take(9) {
        let digit = ch.to_digit(10)? as u64;
        frac_ns += digit * scale;
        scale /= 10;
    }

    secs.checked_mul(1_000_000_000)?.checked_add(frac_ns)
}

fn perf_time_f64_to_ns(time: f64) -> Option<u64> {
    if !time.is_finite() || time < 0.0 {
        return None;
    }
    let ns = time * 1_000_000_000.0;
    if ns < 0.0 || ns > u64::MAX as f64 {
        return None;
    }
    Some(ns as u64)
}

fn parse_perf_mem_script_line(line: &str) -> Option<PerfMemRecord> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut iter = line.split_whitespace();
    let mut comm_parts = Vec::new();
    let mut pid = None;
    let mut tid = None;
    for token in iter.by_ref() {
        if let Some((parsed_pid, parsed_tid)) = parse_u32_pair(token) {
            pid = Some(parsed_pid);
            tid = Some(parsed_tid);
            break;
        }
        comm_parts.push(token);
    }

    let pid = pid?;
    let tid = tid?;
    let time = iter.next()?.trim_end_matches(':').to_string();
    let sample_time_ns = parse_perf_time_ns(&time);
    let addr = iter.next()?.to_string();
    let cgroup = iter.next()?.to_string();
    let ip = iter.next()?.to_string();
    let remainder = iter.collect::<Vec<_>>().join(" ");

    let (sym, dso, phys_addr, data_page_size) = if let Some(paren_end) = remainder.rfind(')') {
        if let Some(paren_start) = remainder[..paren_end].rfind('(') {
            let sym = remainder[..paren_start].trim().to_string();
            let dso = remainder[paren_start + 1..paren_end].to_string();
            let after_dso: Vec<&str> = remainder[paren_end + 1..].split_whitespace().collect();
            let phys_addr = after_dso.first().map(|s| s.to_string()).unwrap_or_default();
            let data_page_size = parse_page_size(after_dso.get(1).unwrap_or(&"0"));
            (sym, dso, phys_addr, data_page_size)
        } else {
            (remainder, String::new(), String::new(), 0)
        }
    } else {
        (String::new(), String::new(), String::new(), 0)
    };

    Some(PerfMemRecord {
        comm: comm_parts.join(" "),
        tid,
        pid,
        time,
        addr,
        cgroup,
        ip,
        sym,
        dso,
        phys_addr,
        data_page_size,
        hint: 0,
        sample_time_ns,
    })
}

fn maybe_int_value(value: &str) -> Value {
    match value.parse::<i64>() {
        Ok(num) => Value::Number(Number::from(num)),
        Err(_) => Value::String(value.to_string()),
    }
}

fn parse_sched_fields(event: &str, trace: &str) -> Option<Map<String, Value>> {
    let mut fields = Map::new();

    if event == "sched:sched_switch" {
        let captures = sched_switch_re().captures(trace)?;
        let prev_comm = captures.name("prev_comm")?.as_str();
        let prev_pid = captures.name("prev_pid")?.as_str().parse::<i64>().ok()?;
        let prev_prio = captures.name("prev_prio")?.as_str().parse::<i64>().ok()?;
        let prev_state = captures.name("prev_state")?.as_str();
        let next_comm = captures.name("next_comm")?.as_str();
        let next_pid = captures.name("next_pid")?.as_str().parse::<i64>().ok()?;
        let next_prio = captures.name("next_prio")?.as_str().parse::<i64>().ok()?;

        fields.insert(
            "prev_comm".to_string(),
            Value::String(prev_comm.to_string()),
        );
        fields.insert(
            "prev_pid".to_string(),
            Value::Number(Number::from(prev_pid)),
        );
        fields.insert(
            "prev_prio".to_string(),
            Value::Number(Number::from(prev_prio)),
        );
        fields.insert(
            "prev_state".to_string(),
            Value::String(prev_state.to_string()),
        );
        fields.insert(
            "next_comm".to_string(),
            Value::String(next_comm.to_string()),
        );
        fields.insert(
            "next_pid".to_string(),
            Value::Number(Number::from(next_pid)),
        );
        fields.insert(
            "next_prio".to_string(),
            Value::Number(Number::from(next_prio)),
        );
        fields.insert(
            "cpu_idle".to_string(),
            Value::Bool(next_pid == 0 || next_comm.starts_with("swapper")),
        );
        fields.insert(
            "prev_idle".to_string(),
            Value::Bool(prev_pid == 0 || prev_comm.starts_with("swapper")),
        );
        return Some(fields);
    }

    for captures in kv_re().captures_iter(trace) {
        fields.insert(
            captures[1].to_string(),
            maybe_int_value(captures.get(2).unwrap().as_str()),
        );
    }

    if let Some(captures) = action_re().captures(trace) {
        fields.insert("action".to_string(), Value::String(captures[1].to_string()));
    }

    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

fn parse_sched_perf_script_line(line: &str) -> Option<PerfSchedScriptRecord> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let captures = sched_line_re().captures(line)?;
    let comm = captures.name("comm")?.as_str().trim().to_string();
    let pid = captures.name("pid")?.as_str().parse::<i32>().ok()?;
    let tid = captures.name("tid")?.as_str().parse::<i32>().ok()?;
    let cpu = captures.name("cpu")?.as_str().parse::<u32>().ok()?;
    let time = captures.name("time")?.as_str().parse::<f64>().ok()?;
    let sample_time_ns = perf_time_f64_to_ns(time);
    let event = captures.name("event")?.as_str().trim().to_string();
    let trace = captures.name("trace")?.as_str().trim().to_string();
    let fields = parse_sched_fields(&event, &trace);

    Some(PerfSchedScriptRecord {
        comm,
        pid,
        tid,
        cpu,
        time,
        event,
        trace,
        fields,
        hint: 0,
        sample_time_ns,
    })
}

fn parse_perf_mem_script_to_jsonl(
    perf_script_path: &Path,
    output_path: &Path,
    hint_index: Option<&HintIndex>,
    artifacts: TraceArtifacts<'_>,
    verbose: bool,
) -> Result<()> {
    let file = File::open(perf_script_path)
        .with_context(|| format!("failed to open {}", artifacts.script_kind))?;
    let mut reader = BufReader::new(file);

    let output_file = File::create(output_path)
        .with_context(|| format!("failed to create {}", artifacts.jsonl_kind))?;
    let mut writer = BufWriter::new(output_file);

    let mut count = 0;
    let mut skipped = 0;
    let mut errors = 0;
    let mut hint_annotator = hint_index.map(HintAnnotator::new);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).context("failed to read line")? == 0 {
            break;
        }
        let raw_line = line.trim_end_matches(['\n', '\r']);
        match parse_perf_mem_script_line(raw_line) {
            Some(mut record) => {
                if record.phys_addr == "0" || record.phys_addr.is_empty() {
                    skipped += 1;
                    if verbose {
                        eprintln!("skipped (no phys_addr): {}", raw_line);
                    }
                    continue;
                }
                if record.comm == "perf" || record.comm == "swapper" {
                    skipped += 1;
                    if verbose {
                        eprintln!("skipped (filtered comm): {}", raw_line);
                    }
                    continue;
                }
                if let Some(hint_annotator) = hint_annotator.as_mut() {
                    hint_annotator.annotate(&mut record);
                }
                let json = serde_json::to_string(&record).context("failed to serialize record")?;
                writeln!(writer, "{}", json)?;
                count += 1;
            }
            None => {
                if !raw_line.trim().is_empty() {
                    errors += 1;
                    if verbose {
                        eprintln!("unparseable: {}", raw_line);
                    }
                }
            }
        }
    }

    writer.flush()?;

    if let Some(ordering_issues) = hint_annotator.and_then(HintAnnotator::finish) {
        ordering_issues.warn(
            &perf_script_path.display().to_string(),
            "Hint lookup fell back conservatively for out-of-order samples.",
        );
    }

    let total = count + skipped + errors;
    println!(
        "Parsed {} of {} records ({} skipped, {} unparseable)",
        count, total, skipped, errors
    );

    Ok(())
}

fn parse_sched_perf_script_to_jsonl(
    perf_script_path: &Path,
    output_path: &Path,
    hint_index: Option<&HintIndex>,
    artifacts: TraceArtifacts<'_>,
    verbose: bool,
) -> Result<()> {
    let file = File::open(perf_script_path)
        .with_context(|| format!("failed to open {}", artifacts.script_kind))?;
    let mut reader = BufReader::new(file);

    let output_file = File::create(output_path)
        .with_context(|| format!("failed to create {}", artifacts.jsonl_kind))?;
    let mut writer = BufWriter::new(output_file);

    let mut count = 0;
    let mut errors = 0;
    let mut hint_annotator = hint_index.map(HintAnnotator::new);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).context("failed to read line")? == 0 {
            break;
        }
        let raw_line = line.trim_end_matches(['\n', '\r']);
        match parse_sched_perf_script_line(raw_line) {
            Some(mut record) => {
                if let Some(hint_annotator) = hint_annotator.as_mut() {
                    hint_annotator.annotate_sched_record(&mut record);
                }
                let json = serde_json::to_string(&record).context("failed to serialize record")?;
                writeln!(writer, "{}", json)?;
                count += 1;
            }
            None => {
                if !raw_line.trim().is_empty() {
                    errors += 1;
                    if verbose {
                        eprintln!("unparseable sched line: {}", raw_line);
                    }
                }
            }
        }
    }

    writer.flush()?;

    if let Some(ordering_issues) = hint_annotator.and_then(HintAnnotator::finish) {
        ordering_issues.warn(
            &perf_script_path.display().to_string(),
            "Hint lookup fell back conservatively for out-of-order samples.",
        );
    }

    let total = count + errors;
    println!(
        "Parsed {} of {} sched trace records ({} unparseable)",
        count, total, errors
    );

    Ok(())
}

fn print_profile_contents(profile_dir: &Path) -> Result<()> {
    println!("Output contents:");

    let entries: Vec<_> = std::fs::read_dir(profile_dir)
        .context("failed to read profile directory")?
        .filter_map(|e| e.ok())
        .collect();

    if entries.is_empty() {
        println!("  (empty)");
        return Ok(());
    }

    for entry in entries {
        let metadata = entry.metadata().ok();
        let size = metadata.map(|m| m.len()).unwrap_or(0);
        println!("  {} ({} bytes)", entry.file_name().to_string_lossy(), size);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use tempfile::TempDir;

    fn test_data_dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    fn materialize_test_profile(name: &str) -> Result<(TempDir, PathBuf)> {
        let tempdir = TempDir::new()?;
        let profile_dir = tempdir.path().join(name);
        copy_dir_recursive(&test_data_dir(name), &profile_dir)?;
        Ok((tempdir, profile_dir))
    }

    fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        reader
            .lines()
            .map(|line| {
                let line = line?;
                serde_json::from_str(&line).context("failed to parse jsonl line")
            })
            .collect()
    }

    #[test]
    fn parse_perf_mem_line_interprets_first_id_as_pid_and_second_as_tid() {
        let record = parse_perf_mem_script_line(
            "alpha worker 1000/2001 0.000000050: 1 /cg 2 foo (bar.so) 3 4K",
        )
        .expect("expected mem record to parse");

        assert_eq!(record.comm, "alpha worker");
        assert_eq!(record.pid, 1000);
        assert_eq!(record.tid, 2001);
        assert_eq!(record.sample_time_ns, Some(50));
    }

    #[test]
    fn process_annotates_mem_and_sched_records_with_thread_hints() -> Result<()> {
        let (_tempdir, profile_dir) = materialize_test_profile("profile_basic")?;
        let output_dir = profile_dir.with_extension("post");
        fs::create_dir_all(&output_dir)?;

        run_processing(&profile_dir, &output_dir, false)?;

        let mem_records: Vec<PerfMemRecord> = read_jsonl(&output_dir.join(PERF_MEM_JSONL_FILE))?;
        let sched_records: Vec<PerfSchedScriptRecord> =
            read_jsonl(&output_dir.join(PERF_SCHED_JSONL_FILE))?;

        assert!(output_dir.join("hints.jsonl").exists());

        let mem_hints: Vec<u64> = mem_records.iter().map(|record| record.hint).collect();
        let sched_hints: Vec<u64> = sched_records.iter().map(|record| record.hint).collect();
        assert_eq!(mem_records[0].pid, 1000);
        assert_eq!(mem_records[0].tid, 2001);
        assert_eq!(mem_hints, vec![0, 7, 7, 9, 0, 5, 5, 0]);
        assert_eq!(sched_hints, vec![0, 7, 0, 9, 0, 5, 0]);
        assert_eq!(
            sched_records[2]
                .fields
                .as_ref()
                .and_then(|fields| fields.get("next_hint"))
                .and_then(Value::as_u64),
            Some(7)
        );
        assert_eq!(
            sched_records[2]
                .fields
                .as_ref()
                .and_then(|fields| fields.get("prev_hint"))
                .and_then(Value::as_u64),
            Some(0)
        );

        Ok(())
    }

    #[test]
    fn process_annotates_sched_switch_prev_and_next_hints_independently() -> Result<()> {
        let mut timelines = HashMap::new();
        timelines.insert(
            10,
            ThreadHintTimeline {
                records: vec![HintRecord {
                    pid: 10,
                    tgid: 1000,
                    hints: 256,
                    timestamp: 500,
                }],
            },
        );
        timelines.insert(
            20,
            ThreadHintTimeline {
                records: vec![HintRecord {
                    pid: 20,
                    tgid: 1000,
                    hints: 640,
                    timestamp: 500,
                }],
            },
        );
        let hint_index = HintIndex {
            timelines,
            ordering_issues: None,
        };
        let mut annotator = HintAnnotator::new(&hint_index);
        let mut record = parse_sched_perf_script_line(
            "worker-a 1000/10 [000] 0.000000500: sched:sched_switch: worker-a:10 [120] R ==> worker-b:20 [120]",
        )
        .expect("expected sched record");

        annotator.annotate_sched_record(&mut record);

        assert_eq!(record.hint, 256);
        assert_eq!(
            record
                .fields
                .as_ref()
                .and_then(|fields| fields.get("prev_hint"))
                .and_then(Value::as_u64),
            Some(256)
        );
        assert_eq!(
            record
                .fields
                .as_ref()
                .and_then(|fields| fields.get("next_hint"))
                .and_then(Value::as_u64),
            Some(640)
        );

        Ok(())
    }

    #[test]
    fn hint_annotation_handles_out_of_order_hints_and_samples_conservatively() -> Result<()> {
        let (_tempdir, profile_dir) = materialize_test_profile("profile_out_of_order")?;
        let hint_index =
            HintIndex::load_if_exists(&profile_dir)?.expect("expected hints index to be loaded");

        assert!(hint_index.ordering_issues.is_some());

        let perf_script_path = profile_dir.join(PERF_MEM_SCRIPT_FILE);
        let output_path = profile_dir.join(PERF_MEM_JSONL_FILE);
        let artifacts = TraceArtifacts {
            data_file: PERF_MEM_DATA_FILE,
            script_file: PERF_MEM_SCRIPT_FILE,
            jsonl_file: PERF_MEM_JSONL_FILE,
            script_fields: PERF_MEM_SCRIPT_FIELDS,
            script_kind: "perf.mem.script",
            jsonl_kind: "perf.mem.jsonl",
        };

        parse_perf_mem_script_to_jsonl(
            &perf_script_path,
            &output_path,
            Some(&hint_index),
            artifacts,
            false,
        )?;

        let records: Vec<PerfMemRecord> = read_jsonl(&output_path)?;
        let hints: Vec<u64> = records.iter().map(|record| record.hint).collect();

        assert_eq!(hints, vec![9, 7]);

        let mut annotator = HintAnnotator::new(&hint_index);
        for line in fs::read_to_string(&perf_script_path)?.lines() {
            let mut record = parse_perf_mem_script_line(line).expect("expected mem record");
            annotator.annotate(&mut record);
        }
        assert!(annotator.finish().is_some());

        Ok(())
    }
}
