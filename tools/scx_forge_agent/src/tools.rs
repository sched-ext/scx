// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Sandboxed tools exposed to the model as OpenAI function calls. Target-crate
//! tools (`read_file`, `list_dir`, `grep`, optional `rg`, `web_fetch`, and gated
//! `edit_file`) resolve paths relative to the scheduler crate or public URLs;
//! comparison tools read other schedulers under `scheds/rust` but never write
//! them. Host-topology tools run fixed read-only commands or read fixed sysfs
//! CPU cache metadata paths.
//! Absolute paths and `..` are rejected, and canonicalized targets must stay
//! inside their configured roots.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::CONTENT_TYPE;
use serde_json::{json, Value};

const MAX_READ_BYTES: usize = 200_000;
const MAX_SCHED_READ_BYTES: usize = 50_000;
const MAX_GREP_MATCHES: usize = 200;
const MAX_RG_OUTPUT_BYTES: usize = 200_000;
const MAX_TOPOLOGY_OUTPUT_BYTES: usize = 100_000;
const DEFAULT_WEB_FETCH_BYTES: usize = 50_000;
const MAX_WEB_FETCH_BYTES: usize = 100_000;
const LOCAL_TOOL_TIMEOUT: Duration = Duration::from_secs(60);

/// The function-calling tool schema advertised to the model.
pub fn openai_tools_json(allow_edit: bool, allow_scheduler_refs: bool) -> Value {
    let mut tools = vec![json!({
        "type": "function",
        "function": {
            "name": "grep",
            "description": "Search the scheduler crate with a regex and return file:line matches. Use this FIRST to locate a symbol before reading a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Rust regex to search for."},
                    "glob": {"type": "string", "description": "Optional path substring filter, e.g. 'main.bpf.c'."}
                },
                "required": ["pattern"]
            }
        }
    })];

    if rg_available() {
        tools.push(json!({
            "type": "function",
            "function": {
                "name": "rg",
                "description": "Fast ripgrep search inside the scheduler crate. Use this for broad searches when available; paths are crate-relative and output is file:line:match.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Ripgrep regex to search for."},
                        "path": {"type": "string", "description": "Optional crate-relative file or directory to search, default '.'."},
                        "glob": {"type": "string", "description": "Optional ripgrep glob filter, e.g. '*.rs' or 'src/bpf/**'."}
                    },
                    "required": ["pattern"]
                }
            }
        }));
    }

    tools.extend([
        json!({
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file inside the scheduler crate. Paths are relative to the crate root. Prefer tight start_line/end_line bounds. Output is prefixed with line numbers and a tab ('   123\\tcode') for navigation only - those prefixes are NOT part of the file; never include them in edit_file's old_string/new_string.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Crate-relative path. Absolute paths and '..' are rejected."},
                        "start_line": {"type": "integer", "description": "1-based first line (optional)."},
                        "end_line": {"type": "integer", "description": "1-based last line (optional)."}
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List files and subdirectories of a crate-relative directory ('' or '.' for the crate root).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Crate-relative directory (optional, defaults to crate root)."}
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "lscpu_e",
                "description": "Run the fixed read-only host-topology command `lscpu -e` and return its output. Use this to inspect CPU, core, socket, node, cache, online, and maxmhz topology columns exposed by lscpu on this host.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "numactl_hardware",
                "description": "Run the fixed read-only host-topology command `numactl -H` and return its output. Use this to inspect NUMA nodes, node CPU lists, memory sizes, and distance matrix for host-specific scheduling policy choices.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "cpu_cache_sizes",
                "description": "Read fixed sysfs cache metadata from `/sys/devices/system/cpu/cpu*/cache/index*/size` and related read-only files. Output is tab-separated as cpu, cache index, level, type, size, and shared_cpu_list.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "web_fetch",
                "description": "Fetch a public http(s) URL for scheduler theory, kernel scheduling papers, documentation, or algorithm ideas. This is not a search engine: pass a direct URL. Public text/HTML/JSON/XML content only; localhost, private networks, and binary content are rejected. Output is truncated.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Direct public http(s) URL to fetch."},
                        "max_bytes": {"type": "integer", "description": "Optional output byte cap, default 50000, maximum 100000."}
                    },
                    "required": ["url"]
                }
            }
        }),
    ]);

    if allow_scheduler_refs {
        tools.extend([
            json!({
                "type": "function",
                "function": {
                    "name": "list_schedulers",
                    "description": "List scheduler crate directories available for read-only comparison under scheds/rust. Note: scx_simple is not available in this repo.",
                    "parameters": {
                        "type": "object",
                        "properties": {}
                    }
                }
            }),
            json!({
                "type": "function",
                "function": {
                    "name": "grep_schedulers",
                    "description": "Read-only search across scheduler crates under scheds/rust. Use this to find policy ideas in other schedulers before adapting them to the target crate. Note: scx_simple is not available in this repo.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Rust regex to search for."},
                            "scheduler": {"type": "string", "description": "Optional scheduler directory name under scheds/rust, e.g. scx_rusty. Omit to search all schedulers. Do not use scx_simple; it is not available in this repo."},
                            "glob": {"type": "string", "description": "Optional path substring filter, e.g. 'src/bpf/main.bpf.c'."}
                        },
                        "required": ["pattern"]
                    }
                }
            }),
            json!({
                "type": "function",
                "function": {
                    "name": "read_scheduler_file",
                    "description": "Read a bounded file range from another scheduler crate under scheds/rust for comparison. This is read-only; use edit_file only on the target crate. For large files, call grep_schedulers first and then pass tight start_line/end_line bounds; unbounded large reads are refused to avoid context overflow. Note: scx_simple is not available in this repo.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "scheduler": {"type": "string", "description": "Scheduler directory name under scheds/rust, e.g. scx_rusty. Do not use scx_simple; it is not available in this repo."},
                            "path": {"type": "string", "description": "Path relative to that scheduler crate, e.g. src/bpf/main.bpf.c. Absolute paths and '..' are rejected."},
                            "start_line": {"type": "integer", "description": "1-based first line (optional)."},
                            "end_line": {"type": "integer", "description": "1-based last line (optional)."}
                        },
                        "required": ["scheduler", "path"]
                    }
                }
            }),
        ]);
    }

    if allow_edit {
        tools.push(json!({
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": "Replace an exact substring in a crate file. old_string must be the verbatim file text (NO read_file line-number/tab prefixes), occur exactly once unless replace_all=true, and differ from new_string.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Crate-relative path. Absolute paths and '..' are rejected."},
                        "old_string": {"type": "string", "description": "Exact file text to replace, copied verbatim WITHOUT read_file's line-number+tab prefixes. Include surrounding context to make it unique."},
                        "new_string": {"type": "string", "description": "Replacement text (also without any line-number prefixes)."},
                        "replace_all": {"type": "boolean", "description": "Replace every occurrence (default false)."}
                    },
                    "required": ["path", "old_string", "new_string"]
                }
            }
        }));
    }

    Value::Array(tools)
}

/// Resolve a crate-relative path inside `sandbox`, rejecting `..`/absolute and escapes.
fn resolve(sandbox: &Path, relative: &str) -> Result<PathBuf> {
    let relative = relative.trim();
    if relative.contains("..") || relative.starts_with('/') {
        anyhow::bail!("path must be crate-relative without '..': {relative:?}");
    }
    let rel = relative.trim_start_matches("./");
    let full = if rel.is_empty() || rel == "." {
        sandbox.to_path_buf()
    } else {
        sandbox.join(rel)
    };
    let canon_sandbox = sandbox
        .canonicalize()
        .with_context(|| format!("canonicalize sandbox {}", sandbox.display()))?;
    // The target may not exist yet (it always does for our tools), so canonicalize
    // the existing parent and re-append the final component when needed.
    let canon_full = match full.canonicalize() {
        Ok(p) => p,
        Err(_) => full.clone(),
    };
    if !canon_full.starts_with(&canon_sandbox) {
        anyhow::bail!("path escapes the crate sandbox: {relative:?}");
    }
    Ok(full)
}

fn rg_available() -> bool {
    Command::new("rg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn normalized_crate_relative_path(path: &str) -> String {
    let rel = path.trim().trim_start_matches("./");
    if rel.is_empty() {
        ".".to_string()
    } else {
        rel.to_string()
    }
}

fn rg_glob_arg(args: &Value) -> Result<Option<String>> {
    let Some(glob) = args.get("glob").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let glob = glob.trim();
    if glob.is_empty() {
        return Ok(None);
    }
    let body = glob.trim_start_matches('!');
    if body.starts_with('/') || body.contains("..") {
        anyhow::bail!("rg: glob must not be absolute or contain '..': {glob:?}");
    }
    Ok(Some(glob.to_string()))
}

fn truncate_lossy(bytes: &[u8], max_bytes: usize, marker: &str) -> String {
    let mut out = String::from_utf8_lossy(&bytes[..bytes.len().min(max_bytes)]).to_string();
    if bytes.len() > max_bytes {
        out.push_str(marker);
    }
    out
}

fn run_fixed_topology_command(label: &str, program: &str, args: &[&str]) -> Result<String> {
    let output = match Command::new(program).args(args).output() {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("{label}: command not found: {program}");
        }
        Err(e) => return Err(e).with_context(|| format!("{label}: execute {program}")),
    };

    let cmdline = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    if !output.status.success() {
        let stderr = truncate_lossy(&output.stderr, 4000, "\n[... truncated ...]\n");
        let stdout = truncate_lossy(&output.stdout, 4000, "\n[... truncated ...]\n");
        anyhow::bail!(
            "{label}: `{cmdline}` failed with status {}{}\n{}",
            output.status,
            if stderr.trim().is_empty() {
                ""
            } else {
                "\nstderr:"
            },
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        );
    }

    let mut out = format!("command: {cmdline}\n\n");
    let stdout = truncate_lossy(
        &output.stdout,
        MAX_TOPOLOGY_OUTPUT_BYTES,
        "\n[... truncated by scx-forge-agent topology tool ...]\n",
    );
    if stdout.trim().is_empty() {
        out.push_str("(no output)\n");
    } else {
        out.push_str(&stdout);
    }
    Ok(out)
}

fn lscpu_e() -> Result<String> {
    run_fixed_topology_command("lscpu_e", "lscpu", &["-e"])
}

fn numactl_hardware() -> Result<String> {
    run_fixed_topology_command("numactl_hardware", "numactl", &["-H"])
}

fn parse_prefixed_u32(name: &str, prefix: &str) -> Option<u32> {
    name.strip_prefix(prefix)?.parse::<u32>().ok()
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn cpu_cache_sizes_from_root(cpu_root: &Path) -> Result<String> {
    let mut entries = Vec::new();

    for cpu_ent in std::fs::read_dir(cpu_root)
        .with_context(|| format!("cpu_cache_sizes: read {}", cpu_root.display()))?
    {
        let cpu_ent = cpu_ent?;
        let cpu_name = cpu_ent.file_name().to_string_lossy().to_string();
        let Some(cpu) = parse_prefixed_u32(&cpu_name, "cpu") else {
            continue;
        };

        let cache_dir = cpu_ent.path().join("cache");
        let Ok(cache_entries) = std::fs::read_dir(&cache_dir) else {
            continue;
        };

        for index_ent in cache_entries.flatten() {
            let index_name = index_ent.file_name().to_string_lossy().to_string();
            let Some(index) = parse_prefixed_u32(&index_name, "index") else {
                continue;
            };

            let index_dir = index_ent.path();
            let Some(size) = read_trimmed(&index_dir.join("size")) else {
                continue;
            };
            let level = read_trimmed(&index_dir.join("level")).unwrap_or_else(|| "?".to_string());
            let ty = read_trimmed(&index_dir.join("type")).unwrap_or_else(|| "?".to_string());
            let shared =
                read_trimmed(&index_dir.join("shared_cpu_list")).unwrap_or_else(|| "?".to_string());

            entries.push((cpu, index, level, ty, size, shared));
        }
    }

    entries.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    if entries.is_empty() {
        return Ok(format!(
            "path: {}\n(no CPU cache size files found)\n",
            cpu_root.display()
        ));
    }

    let mut out = format!(
        "path: {}\ncolumns: cpu\tindex\tlevel\ttype\tsize\tshared_cpu_list\n",
        cpu_root.display()
    );
    for (cpu, index, level, ty, size, shared) in entries {
        out.push_str(&format!(
            "cpu{cpu}\tindex{index}\t{level}\t{ty}\t{size}\t{shared}\n"
        ));
        if out.len() > MAX_TOPOLOGY_OUTPUT_BYTES {
            out.push_str("\n[... truncated by scx-forge-agent topology tool ...]\n");
            break;
        }
    }
    Ok(out)
}

fn cpu_cache_sizes() -> Result<String> {
    cpu_cache_sizes_from_root(Path::new("/sys/devices/system/cpu"))
}

fn rg(sandbox: &Path, args: &Value) -> Result<String> {
    let pattern = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("rg: missing pattern"))?;
    let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let _ = resolve(sandbox, path_str)?;
    let path_arg = normalized_crate_relative_path(path_str);
    let glob = rg_glob_arg(args)?;

    let mut cmd = Command::new("rg");
    cmd.current_dir(sandbox)
        .arg("--line-number")
        .arg("--color=never")
        .arg("--no-heading")
        .arg("--hidden")
        .arg("--no-ignore")
        .arg("--max-columns")
        .arg("500")
        .arg("--max-columns-preview")
        .arg("--max-count")
        .arg(MAX_GREP_MATCHES.to_string())
        .arg("--max-filesize")
        .arg("1M")
        .arg("--glob")
        .arg("!.git/**")
        .arg("--glob")
        .arg("!target/**");
    if let Some(glob) = glob {
        cmd.arg("--glob").arg(glob);
    }
    cmd.arg("--").arg(pattern).arg(path_arg);

    let output = match cmd.output() {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("rg: ripgrep is not available on PATH");
        }
        Err(e) => return Err(e).context("rg: execute rg"),
    };

    match output.status.code() {
        Some(0) => {
            let out = truncate_lossy(
                &output.stdout,
                MAX_RG_OUTPUT_BYTES,
                "\n[... truncated by scx-forge-agent rg ...]\n",
            );
            if out.trim().is_empty() {
                Ok("(no matches)".to_string())
            } else {
                Ok(out)
            }
        }
        Some(1) => Ok("(no matches)".to_string()),
        _ => {
            let err = truncate_lossy(&output.stderr, 4000, "\n[... truncated ...]\n");
            let stdout = truncate_lossy(&output.stdout, 4000, "\n[... truncated ...]\n");
            let detail = if err.trim().is_empty() { stdout } else { err };
            anyhow::bail!("rg: {}", detail.trim());
        }
    }
}

fn read_file(sandbox: &Path, args: &Value) -> Result<String> {
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("read_file: missing path"))?;
    let path = resolve(sandbox, path_str)?;
    read_path(&path, args, "read_file", MAX_READ_BYTES, false)
}

fn read_path(
    path: &Path,
    args: &Value,
    label: &str,
    max_bytes: usize,
    refuse_large_unbounded: bool,
) -> Result<String> {
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("{label}: read {}", path.display()))?;
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();

    let start = args.get("start_line").and_then(|v| v.as_u64());
    let end = args.get("end_line").and_then(|v| v.as_u64());
    if refuse_large_unbounded && start.is_none() && end.is_none() && content.len() > max_bytes {
        return Ok(format!(
            "[{} is large: {} bytes, {} lines; full unbounded read suppressed by scx-forge-agent to avoid overflowing the model context. Use grep_schedulers to locate relevant symbols, then call read_scheduler_file with tight start_line/end_line bounds.]\n",
            path.display(),
            content.len(),
            total
        ));
    }
    let line_start_idx = |line: u64| {
        usize::try_from(line.saturating_sub(1))
            .unwrap_or(usize::MAX)
            .min(total)
    };
    let line_end_idx = |line: u64| usize::try_from(line).unwrap_or(usize::MAX).min(total);
    let (mut s, mut e) = match (start, end) {
        (Some(s), Some(e)) if s >= 1 && e >= s => (line_start_idx(s), line_end_idx(e)),
        (Some(s), None) if s >= 1 => (line_start_idx(s), total),
        (None, Some(e)) if e >= 1 => (0, line_end_idx(e)),
        _ => (0, total),
    };
    s = s.min(total);
    e = e.min(total);
    if e < s {
        e = s;
    }
    let mut out = String::new();
    if let Some(start) = start.filter(|line| usize::try_from(*line).map_or(true, |n| n > total)) {
        out.push_str(&format!(
            "[requested start_line {} is past EOF; file has {} lines]\n",
            start, total
        ));
    }
    for (i, line) in lines[s..e].iter().enumerate() {
        out.push_str(&format!("{:>6}\t{}\n", s + i + 1, line));
        if out.len() > max_bytes {
            out.push_str("\n[... truncated by scx-forge-agent ...]\n");
            break;
        }
    }
    Ok(out)
}

fn scheduler_dir(scheds_root: &Path, scheduler: &str) -> Result<PathBuf> {
    let scheduler = scheduler.trim();
    if scheduler.is_empty()
        || scheduler.contains('/')
        || scheduler.contains('\\')
        || scheduler.contains("..")
        || scheduler.starts_with('.')
    {
        anyhow::bail!("scheduler must be a directory name under scheds/rust: {scheduler:?}");
    }
    if scheduler == "scx_simple" {
        anyhow::bail!(
            "scx_simple is not available in this repo; call list_schedulers and choose one of the reported scheduler crates"
        );
    }

    let canon_root = scheds_root
        .canonicalize()
        .with_context(|| format!("canonicalize scheds root {}", scheds_root.display()))?;
    let dir = scheds_root.join(scheduler);
    let canon_dir = dir
        .canonicalize()
        .with_context(|| format!("scheduler not found under scheds/rust: {scheduler}"))?;
    if !canon_dir.starts_with(&canon_root) || !canon_dir.is_dir() {
        anyhow::bail!("scheduler path escapes scheds/rust: {scheduler:?}");
    }
    Ok(canon_dir)
}

fn resolve_scheduler_path(scheds_root: &Path, scheduler: &str, relative: &str) -> Result<PathBuf> {
    let dir = scheduler_dir(scheds_root, scheduler)?;
    resolve(&dir, relative)
}

fn list_schedulers(scheds_root: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for ent in std::fs::read_dir(scheds_root)
        .with_context(|| format!("list_schedulers: {}", scheds_root.display()))?
    {
        let ent = ent?;
        if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            entries.push(ent.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    Ok(entries.join("\n"))
}

fn read_scheduler_file(scheds_root: &Path, args: &Value) -> Result<String> {
    let scheduler = args
        .get("scheduler")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("read_scheduler_file: missing scheduler"))?;
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("read_scheduler_file: missing path"))?;
    let path = resolve_scheduler_path(scheds_root, scheduler, path_str)?;
    let content = read_path(
        &path,
        args,
        "read_scheduler_file",
        MAX_SCHED_READ_BYTES,
        true,
    )?;
    Ok(format!(
        "scheduler: {}\nfile: {}\n{}",
        scheduler.trim(),
        path_str.trim(),
        content
    ))
}

fn list_dir(sandbox: &Path, args: &Value) -> Result<String> {
    let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let dir = resolve(sandbox, path_str)?;
    let mut entries: Vec<String> = Vec::new();
    for ent in std::fs::read_dir(&dir).with_context(|| format!("list_dir: {}", dir.display()))? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().to_string();
        if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            entries.push(format!("{name}/"));
        } else {
            entries.push(name);
        }
    }
    entries.sort();
    Ok(entries.join("\n"))
}

fn grep(sandbox: &Path, args: &Value) -> Result<String> {
    let pattern = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("grep: missing pattern"))?;
    let glob = args.get("glob").and_then(|v| v.as_str());
    let re =
        regex::Regex::new(pattern).with_context(|| format!("grep: invalid regex {pattern:?}"))?;

    let mut matches: Vec<String> = Vec::new();
    grep_dir(sandbox, None, glob, &re, &mut matches);
    if matches.is_empty() {
        Ok("(no matches)".to_string())
    } else {
        Ok(matches.join("\n"))
    }
}

fn grep_dir(
    root: &Path,
    prefix: Option<&str>,
    glob: Option<&str>,
    re: &regex::Regex,
    matches: &mut Vec<String>,
) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let ft = match ent.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                let name = ent.file_name().to_string_lossy().to_string();
                if name == "target" || name == ".git" {
                    continue;
                }
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .to_string();
            if let Some(g) = glob {
                if !rel.contains(g) {
                    continue;
                }
            }
            let shown = match prefix {
                Some(prefix) => format!("{prefix}/{rel}"),
                None => rel,
            };
            let content = match std::fs::read_to_string(&p) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    matches.push(format!("{}:{}:{}", shown, i + 1, line.trim_end()));
                    if matches.len() >= MAX_GREP_MATCHES {
                        matches.push("[... more matches truncated ...]".to_string());
                        return;
                    }
                }
            }
        }
    }
}

fn grep_schedulers(scheds_root: &Path, args: &Value) -> Result<String> {
    let pattern = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("grep_schedulers: missing pattern"))?;
    let glob = args.get("glob").and_then(|v| v.as_str());
    let re = regex::Regex::new(pattern)
        .with_context(|| format!("grep_schedulers: invalid regex {pattern:?}"))?;

    let mut matches = Vec::new();
    if let Some(scheduler) = args.get("scheduler").and_then(|v| v.as_str()) {
        let dir = scheduler_dir(scheds_root, scheduler)?;
        grep_dir(&dir, Some(scheduler.trim()), glob, &re, &mut matches);
    } else {
        let mut schedulers: Vec<String> = std::fs::read_dir(scheds_root)
            .with_context(|| format!("grep_schedulers: {}", scheds_root.display()))?
            .flatten()
            .filter_map(|ent| {
                ent.file_type()
                    .ok()
                    .filter(|t| t.is_dir())
                    .map(|_| ent.file_name().to_string_lossy().to_string())
            })
            .collect();
        schedulers.sort();
        for scheduler in schedulers {
            let dir = match scheduler_dir(scheds_root, &scheduler) {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            grep_dir(&dir, Some(&scheduler), glob, &re, &mut matches);
            if matches.len() >= MAX_GREP_MATCHES {
                break;
            }
        }
    }

    if matches.is_empty() {
        Ok("(no matches)".to_string())
    } else {
        Ok(matches.join("\n"))
    }
}

fn web_fetch_max_bytes(args: &Value) -> usize {
    args.get("max_bytes")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_WEB_FETCH_BYTES)
        .min(MAX_WEB_FETCH_BYTES)
}

fn is_disallowed_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 198 && (18..=19).contains(&o[1]))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

async fn validate_public_url(url: &reqwest::Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => anyhow::bail!("web_fetch: unsupported URL scheme {scheme:?}; use http(s)"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("web_fetch: credentials in URLs are not allowed");
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("web_fetch: URL is missing host"))?;
    if is_disallowed_host(host) {
        anyhow::bail!("web_fetch: refusing localhost/private host {host:?}");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_disallowed_ip(ip) {
            anyhow::bail!("web_fetch: refusing private or local IP address {ip}");
        }
        return Ok(());
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("web_fetch: URL has no known port"))?;
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("web_fetch: DNS lookup failed for {host}"))?;
    for addr in addrs {
        let ip = addr.ip();
        if is_disallowed_ip(ip) {
            anyhow::bail!(
                "web_fetch: refusing host {host:?}; DNS resolved to private or local IP {ip}"
            );
        }
    }

    Ok(())
}

fn web_fetch_content_type_allowed(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return true;
    };
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    ct.starts_with("text/")
        || matches!(
            ct.as_str(),
            "application/json"
                | "application/ld+json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "application/x-bibtex"
        )
}

fn decode_basic_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

fn collapse_text(s: &str) -> String {
    let mut out = String::new();
    let mut blank_lines = 0usize;
    for line in s.lines() {
        let trimmed = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if trimmed.is_empty() {
            blank_lines += 1;
            if blank_lines <= 1 && !out.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }
        blank_lines = 0;
        out.push_str(&trimmed);
        out.push('\n');
    }
    out.trim().to_string()
}

fn html_to_text(html: &str) -> String {
    let mut s = html.to_string();
    for pat in [
        r"(?is)<script\b[^>]*>.*?</script>",
        r"(?is)<style\b[^>]*>.*?</style>",
        r"(?is)<noscript\b[^>]*>.*?</noscript>",
        r"(?is)<!--.*?-->",
    ] {
        if let Ok(re) = regex::Regex::new(pat) {
            s = re.replace_all(&s, " ").to_string();
        }
    }
    if let Ok(re) = regex::Regex::new(r"(?is)<\s*(br|/p|/div|/li|/h[1-6]|/tr)\b[^>]*>") {
        s = re.replace_all(&s, "\n").to_string();
    }
    if let Ok(re) = regex::Regex::new(r"(?is)<[^>]+>") {
        s = re.replace_all(&s, " ").to_string();
    }
    collapse_text(&decode_basic_entities(&s))
}

async fn web_fetch(args: &Value) -> Result<String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("web_fetch: missing url"))?;
    let url = reqwest::Url::parse(url_str).with_context(|| "web_fetch: invalid URL")?;
    validate_public_url(&url).await?;

    let max_bytes = web_fetch_max_bytes(args);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!(
            "scx-forge-agent-web-fetch/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("web_fetch: build HTTP client")?;

    let mut resp = client
        .get(url)
        .send()
        .await
        .context("web_fetch: request failed")?;
    let status = resp.status();
    let final_url = resp.url().clone();
    if !status.is_success() {
        anyhow::bail!("web_fetch: HTTP status {status} for {final_url}");
    }

    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if !web_fetch_content_type_allowed(content_type.as_deref()) {
        anyhow::bail!(
            "web_fetch: unsupported content-type {:?}; fetch public text/html/json/xml pages",
            content_type
        );
    }

    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("web_fetch: read response body")?
    {
        if body.len() + chunk.len() > max_bytes {
            let take = max_bytes.saturating_sub(body.len());
            body.extend_from_slice(&chunk[..take]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    let raw = String::from_utf8_lossy(&body);
    let ct = content_type.as_deref().unwrap_or("");
    let text = if ct.to_ascii_lowercase().contains("html") || raw.contains("<html") {
        html_to_text(&raw)
    } else {
        collapse_text(&decode_basic_entities(&raw))
    };
    let mut out = format!(
        "url: {final_url}\nstatus: {status}\ncontent-type: {}\nbytes-read: {}{}\n\n",
        content_type.as_deref().unwrap_or("(not provided)"),
        body.len(),
        if truncated { " (truncated)" } else { "" }
    );
    out.push_str(&text);
    if truncated {
        out.push_str("\n\n[... truncated by scx-forge-agent web_fetch ...]");
    }
    Ok(out)
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut idx = 0;
    let mut n = 0;
    while let Some(pos) = haystack[idx..].find(needle) {
        n += 1;
        idx += pos + needle.len();
    }
    n
}

fn edit_file(sandbox: &Path, args: &Value) -> Result<String> {
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("edit_file: missing path"))?;
    let old = args
        .get("old_string")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("edit_file: missing old_string"))?;
    let new = args
        .get("new_string")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("edit_file: missing new_string"))?;
    let replace_all = args
        .get("replace_all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if old.is_empty() {
        anyhow::bail!("edit_file: old_string must not be empty");
    }
    if old == new {
        anyhow::bail!("edit_file: new_string must differ from old_string");
    }
    let path = resolve(sandbox, path_str)?;
    if !path.is_file() {
        anyhow::bail!("edit_file: {path_str} is not a regular file");
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("edit_file: read {}", path.display()))?;

    // 1. Exact match, then 2. with read_file's line-number+tab prefixes stripped
    // ("   123\t..."): models frequently copy old_string straight from read_file
    // output, prefixes and all, which never matches the raw file bytes.
    for (i, cand) in [old.to_string(), strip_line_number_prefixes(old)]
        .iter()
        .enumerate()
    {
        let occ = count_occurrences(&content, cand);
        if occ == 0 {
            continue;
        }
        if occ > 1 && !replace_all {
            anyhow::bail!(
                "edit_file: old_string occurs {occ} times in {path_str}; pass replace_all=true or extend old_string with more context to make it unique"
            );
        }
        let repl = if i == 0 {
            new.to_string()
        } else {
            strip_line_number_prefixes(new)
        };
        let updated = if replace_all {
            content.replace(cand, &repl)
        } else {
            content.replacen(cand, &repl, 1)
        };
        std::fs::write(&path, updated)
            .with_context(|| format!("edit_file: write {}", path.display()))?;
        return Ok(format!("edited {path_str} ({occ} occurrence(s) replaced)"));
    }

    // 3. Whitespace-tolerant fallback: match a unique block of lines ignoring
    // per-line indentation and surrounding blank lines (the usual reason a weak
    // model's old_string fails to match), then replace that real region.
    let stripped_old = strip_line_number_prefixes(old);
    if let Some((bs, be)) = fuzzy_line_match(&content, &stripped_old) {
        let mut repl = strip_line_number_prefixes(new);
        if content[bs..be].ends_with('\n') && !repl.ends_with('\n') {
            repl.push('\n');
        }
        let updated = format!("{}{}{}", &content[..bs], repl, &content[be..]);
        std::fs::write(&path, updated)
            .with_context(|| format!("edit_file: write {}", path.display()))?;
        return Ok(format!(
            "edited {path_str} (whitespace-tolerant match; indentation taken from new_string)"
        ));
    }

    // 4. Give up, but point the model at the closest real lines so it can fix
    // old_string on the next attempt.
    let anchor = stripped_old
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let hint = nearest_lines(&content, anchor);
    let hint_msg = if hint.is_empty() {
        String::new()
    } else {
        format!("\nClosest lines currently in the file:\n{hint}")
    };
    anyhow::bail!(
        "edit_file: old_string not found in {path_str}. Provide the exact file text verbatim \
         (no line-number prefixes); indentation may differ but the lines must otherwise match.{hint_msg}"
    );
}

/// Find a unique block of lines in `content` whose whitespace-trimmed text
/// equals the trimmed lines of `needle` (ignoring indentation and blank lines
/// around the block). Returns the byte range [start, end) of that block, or
/// None if there is not exactly one match.
fn fuzzy_line_match(content: &str, needle: &str) -> Option<(usize, usize)> {
    let needle_trim: Vec<&str> = needle.lines().map(str::trim).collect();
    let first = needle_trim.iter().position(|l| !l.is_empty())?;
    let last = needle_trim.iter().rposition(|l| !l.is_empty())?;
    let core = &needle_trim[first..=last];
    let w = core.len();

    let file_lines: Vec<&str> = content.split_inclusive('\n').collect();
    if file_lines.len() < w {
        return None;
    }
    let file_trim: Vec<&str> = file_lines.iter().map(|l| l.trim()).collect();
    let mut offsets = Vec::with_capacity(file_lines.len() + 1);
    let mut acc = 0usize;
    for l in &file_lines {
        offsets.push(acc);
        acc += l.len();
    }
    offsets.push(acc);

    let mut found: Option<usize> = None;
    for s in 0..=(file_trim.len() - w) {
        if file_trim[s..s + w] == core[..] {
            if found.is_some() {
                return None; // ambiguous - refuse rather than edit the wrong block
            }
            found = Some(s);
        }
    }
    let s = found?;
    Some((offsets[s], offsets[s + w]))
}

/// Up to 5 file lines (with 1-based line numbers) that contain `anchor`, for
/// error feedback when old_string doesn't match.
fn nearest_lines(content: &str, anchor: &str) -> String {
    let anchor = anchor.trim();
    if anchor.is_empty() {
        return String::new();
    }
    content
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(anchor))
        .take(5)
        .map(|(i, l)| format!("{}\t{}", i + 1, l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip a leading line-number+tab prefix (as emitted by read_file's
/// `"{:>6}\t"` format) from each line. Preserves a trailing newline.
fn strip_line_number_prefixes(s: &str) -> String {
    fn strip(line: &str) -> &str {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let digit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        // Require at least one digit followed by a tab to treat it as a prefix.
        if i > digit_start && i < bytes.len() && bytes[i] == b'\t' {
            &line[i + 1..]
        } else {
            line
        }
    }
    let joined = s.lines().map(strip).collect::<Vec<_>>().join("\n");
    if s.ends_with('\n') {
        format!("{joined}\n")
    } else {
        joined
    }
}

/// True for write-capable tools (used by the controller to count edits per round).
pub fn is_write_tool(name: &str) -> bool {
    name == "edit_file"
}

/// Dispatch a tool call. `allow_edit` gates `edit_file`.
pub fn execute_tool(
    sandbox: &Path,
    scheds_root: Option<&Path>,
    name: &str,
    args_json: &str,
    allow_edit: bool,
) -> Result<String> {
    let args: Value = serde_json::from_str(args_json)
        .with_context(|| format!("tool {name}: arguments are not valid JSON: {args_json}"))?;
    match name {
        "grep" => grep(sandbox, &args),
        "rg" => rg(sandbox, &args),
        "read_file" => read_file(sandbox, &args),
        "list_dir" => list_dir(sandbox, &args),
        "lscpu_e" => lscpu_e(),
        "numactl_hardware" => numactl_hardware(),
        "cpu_cache_sizes" => cpu_cache_sizes(),
        "list_schedulers" => list_schedulers(
            scheds_root.ok_or_else(|| anyhow!("list_schedulers is not configured"))?,
        ),
        "grep_schedulers" => grep_schedulers(
            scheds_root.ok_or_else(|| anyhow!("grep_schedulers is not configured"))?,
            &args,
        ),
        "read_scheduler_file" => read_scheduler_file(
            scheds_root.ok_or_else(|| anyhow!("read_scheduler_file is not configured"))?,
            &args,
        ),
        "edit_file" => {
            if !allow_edit {
                anyhow::bail!("edit_file is disabled in this run");
            }
            edit_file(sandbox, &args)
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}

/// Async dispatch for tools that may perform network I/O.
pub async fn execute_tool_async(
    sandbox: &Path,
    scheds_root: Option<&Path>,
    name: &str,
    args_json: &str,
    allow_edit: bool,
) -> Result<String> {
    if name == "web_fetch" {
        let args: Value = serde_json::from_str(args_json)
            .with_context(|| format!("tool {name}: arguments are not valid JSON: {args_json}"))?;
        web_fetch(&args).await
    } else {
        let sandbox = sandbox.to_path_buf();
        let scheds_root = scheds_root.map(Path::to_path_buf);
        let name = name.to_string();
        let args_json = args_json.to_string();
        let timeout_name = name.clone();
        let handle = tokio::task::spawn_blocking(move || {
            execute_tool(
                &sandbox,
                scheds_root.as_deref(),
                &name,
                &args_json,
                allow_edit,
            )
        });
        match tokio::time::timeout(LOCAL_TOOL_TIMEOUT, handle).await {
            Ok(joined) => joined.context("local tool worker panicked")?,
            Err(_) => anyhow::bail!(
                "tool {timeout_name} timed out after {}s",
                LOCAL_TOOL_TIMEOUT.as_secs()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_names(tools: Value) -> Vec<String> {
        tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| {
                tool.get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|name| name.as_str())
                    .map(str::to_string)
            })
            .collect()
    }

    #[test]
    fn strips_read_file_prefixes() {
        // Mirrors read_file's "{:>6}\t" formatting.
        let prefixed = "   123\tlet x = 1;\n   124\tlet y = 2;";
        assert_eq!(
            strip_line_number_prefixes(prefixed),
            "let x = 1;\nlet y = 2;"
        );
    }

    #[test]
    fn preserves_lines_without_prefix_and_trailing_newline() {
        assert_eq!(strip_line_number_prefixes("plain code\n"), "plain code\n");
        // A leading number that is NOT followed by a tab is left intact.
        assert_eq!(
            strip_line_number_prefixes("42 is the answer"),
            "42 is the answer"
        );
    }

    #[test]
    fn read_file_past_eof_returns_note_instead_of_panicking() {
        let dir = std::env::temp_dir().join(format!("scx_read_eof_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");
        std::fs::write(&file, "one\ntwo\n").unwrap();

        let args = json!({
            "path": "f.txt",
            "start_line": 10,
            "end_line": 12,
        });
        let out = read_file(&dir, &args).unwrap();
        assert!(
            out.contains("requested start_line 10 is past EOF"),
            "got: {out}"
        );
        assert!(out.contains("file has 2 lines"), "got: {out}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_file_recovers_from_copied_prefixes() {
        let dir = std::env::temp_dir().join(format!("scx_edit_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");
        std::fs::write(&file, "alpha\nbeta\ngamma\n").unwrap();
        // old_string carries read_file-style prefixes; new_string too.
        let args = json!({
            "path": "f.txt",
            "old_string": "     2\tbeta",
            "new_string": "     2\tBETA",
        });
        let out = edit_file(&dir, &args).unwrap();
        assert!(out.contains("edited"));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "alpha\nBETA\ngamma\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fuzzy_line_match_ignores_indentation() {
        let content = "a\n    b\n    c\nd\n";
        let (s, e) = fuzzy_line_match(content, "b\nc").unwrap();
        assert_eq!(&content[s..e], "    b\n    c\n");
    }

    #[test]
    fn fuzzy_line_match_refuses_ambiguous() {
        let content = "x\n    foo\nx\n    foo\n";
        assert!(fuzzy_line_match(content, "foo").is_none());
    }

    #[test]
    fn edit_file_whitespace_tolerant() {
        let dir = std::env::temp_dir().join(format!("scx_fuzzy_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("g.txt");
        std::fs::write(&file, "fn main() {\n    let x = 1;\n    let y = 2;\n}\n").unwrap();
        // old_string has the right lines but the wrong (missing) indentation.
        let args = json!({
            "path": "g.txt",
            "old_string": "let x = 1;\nlet y = 2;",
            "new_string": "let z = 3;",
        });
        let out = edit_file(&dir, &args).unwrap();
        assert!(out.contains("whitespace-tolerant"), "got: {out}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "fn main() {\nlet z = 3;\n}\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nearest_lines_points_at_match() {
        let content = "one\n    target_symbol = 5;\nthree\n";
        let hint = nearest_lines(content, "target_symbol = 5;");
        assert!(hint.contains("2\t"), "got: {hint}");
        assert!(hint.contains("target_symbol"));
    }

    #[test]
    fn rg_schema_tracks_binary_availability() {
        let names = tool_names(openai_tools_json(false, true));
        assert_eq!(names.iter().any(|name| name == "rg"), rg_available());
    }

    #[test]
    fn topology_tools_are_exposed() {
        let names = tool_names(openai_tools_json(false, true));
        assert!(names.iter().any(|name| name == "lscpu_e"));
        assert!(names.iter().any(|name| name == "numactl_hardware"));
        assert!(names.iter().any(|name| name == "cpu_cache_sizes"));
    }

    #[test]
    fn cpu_cache_sizes_reads_fixed_sysfs_shape() {
        let base = std::env::temp_dir().join(format!("scx_cpu_cache_test_{}", std::process::id()));
        let index0 = base.join("cpu0/cache/index0");
        let index1 = base.join("cpu0/cache/index1");
        let index2 = base.join("cpu1/cache/index2");
        std::fs::create_dir_all(&index0).unwrap();
        std::fs::create_dir_all(&index1).unwrap();
        std::fs::create_dir_all(&index2).unwrap();
        std::fs::write(index0.join("size"), "32K\n").unwrap();
        std::fs::write(index0.join("level"), "1\n").unwrap();
        std::fs::write(index0.join("type"), "Data\n").unwrap();
        std::fs::write(index0.join("shared_cpu_list"), "0\n").unwrap();
        std::fs::write(index1.join("level"), "1\n").unwrap(); // no size: skipped
        std::fs::write(index2.join("size"), "1024K\n").unwrap();
        std::fs::write(index2.join("level"), "2\n").unwrap();
        std::fs::write(index2.join("type"), "Unified\n").unwrap();
        std::fs::write(index2.join("shared_cpu_list"), "0-1\n").unwrap();

        let out = cpu_cache_sizes_from_root(&base).unwrap();

        assert!(out.contains("columns: cpu\tindex\tlevel\ttype\tsize\tshared_cpu_list"));
        assert!(out.contains("cpu0\tindex0\t1\tData\t32K\t0"));
        assert!(out.contains("cpu1\tindex2\t2\tUnified\t1024K\t0-1"));
        assert!(!out.contains("index1"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rg_rejects_path_escape() {
        let dir = std::env::temp_dir().join(format!("scx_rg_escape_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let args = json!({
            "pattern": "anything",
            "path": "../outside",
        });

        let err = execute_tool(&dir, None, "rg", &args.to_string(), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("path must be crate-relative"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rg_searches_target_crate_when_available() {
        if !rg_available() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("scx_rg_test_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src/bpf")).unwrap();
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(
            dir.join("src/bpf/main.bpf.c"),
            "void target_symbol(void) {}\n",
        )
        .unwrap();
        std::fs::write(dir.join("target/generated.c"), "target_symbol();\n").unwrap();

        let args = json!({
            "pattern": "target_symbol",
            "path": "src",
            "glob": "*.bpf.c",
        });
        let out = execute_tool(&dir, None, "rg", &args.to_string(), false).unwrap();

        assert!(
            out.contains("src/bpf/main.bpf.c:1:void target_symbol"),
            "got: {out}"
        );
        assert!(!out.contains("target/generated.c"), "got: {out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scheduler_reference_tools_are_read_only() {
        let base = std::env::temp_dir().join(format!("scx_sched_ref_test_{}", std::process::id()));
        let scheds = base.join("scheds/rust");
        let target = scheds.join("scx_target");
        let other = scheds.join("scx_other");
        std::fs::create_dir_all(target.join("src/bpf")).unwrap();
        std::fs::create_dir_all(other.join("src/bpf")).unwrap();
        std::fs::write(target.join("src/bpf/main.bpf.c"), "target_policy();\n").unwrap();
        std::fs::write(
            other.join("src/bpf/main.bpf.c"),
            "void pick_remote(void) {}\n",
        )
        .unwrap();

        let listed = execute_tool(&target, Some(&scheds), "list_schedulers", "{}", false).unwrap();
        assert!(listed.contains("scx_other"), "got: {listed}");
        assert!(listed.contains("scx_target"), "got: {listed}");

        let grep_args = json!({
            "pattern": "pick_remote",
            "scheduler": "scx_other",
            "glob": "main.bpf.c",
        });
        let matches = execute_tool(
            &target,
            Some(&scheds),
            "grep_schedulers",
            &grep_args.to_string(),
            false,
        )
        .unwrap();
        assert!(
            matches.contains("scx_other/src/bpf/main.bpf.c:1:void pick_remote"),
            "got: {matches}"
        );

        let read_args = json!({
            "scheduler": "scx_other",
            "path": "src/bpf/main.bpf.c",
        });
        let read = execute_tool(
            &target,
            Some(&scheds),
            "read_scheduler_file",
            &read_args.to_string(),
            false,
        )
        .unwrap();
        assert!(read.contains("scheduler: scx_other"), "got: {read}");
        assert!(read.contains("file: src/bpf/main.bpf.c"), "got: {read}");
        assert!(read.contains("pick_remote"), "got: {read}");

        let read_past_eof_args = json!({
            "scheduler": "scx_other",
            "path": "src/bpf/main.bpf.c",
            "start_line": 10,
        });
        let read_past_eof = execute_tool(
            &target,
            Some(&scheds),
            "read_scheduler_file",
            &read_past_eof_args.to_string(),
            false,
        )
        .unwrap();
        assert!(
            read_past_eof.contains("scheduler: scx_other"),
            "got: {read_past_eof}"
        );
        assert!(
            read_past_eof.contains("requested start_line 10 is past EOF"),
            "got: {read_past_eof}"
        );

        let simple_args = json!({
            "scheduler": "scx_simple",
            "path": "src/bpf/main.bpf.c",
        });
        let err = execute_tool(
            &target,
            Some(&scheds),
            "read_scheduler_file",
            &simple_args.to_string(),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("scx_simple is not available"), "got: {err}");
        assert!(err.contains("call list_schedulers"), "got: {err}");

        let edit_args = json!({
            "path": "../scx_other/src/bpf/main.bpf.c",
            "old_string": "pick_remote",
            "new_string": "stolen_policy",
        });
        let err = execute_tool(
            &target,
            Some(&scheds),
            "edit_file",
            &edit_args.to_string(),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("path must be crate-relative"), "got: {err}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn async_dispatch_runs_local_tool() {
        let base = std::env::temp_dir().join(format!("scx_tools_async_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("README.md"), "hello\n").unwrap();

        let out = execute_tool_async(&base, None, "read_file", r#"{"path":"README.md"}"#, false)
            .await
            .unwrap();

        assert!(out.contains("hello"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn web_fetch_is_exposed_and_rejects_private_targets() {
        let tools = openai_tools_json(false, true);
        let names: Vec<String> = tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| {
                tool.get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|name| name.as_str())
                    .map(str::to_string)
            })
            .collect();

        assert!(names.iter().any(|name| name == "web_fetch"));
        assert!(is_disallowed_host("localhost"));
        assert!(is_disallowed_host("docs.local"));
        assert!(is_disallowed_ip("127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("10.1.2.3".parse().unwrap()));
        assert!(is_disallowed_ip("::1".parse().unwrap()));
        assert!(!is_disallowed_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn web_fetch_extracts_basic_html_text() {
        let html = r#"
            <html><head><style>.x{}</style><script>bad()</script></head>
            <body><h1>EEVDF scheduling</h1><p>Virtual deadline &amp; lag.</p></body></html>
        "#;
        let text = html_to_text(html);

        assert!(text.contains("EEVDF scheduling"));
        assert!(text.contains("Virtual deadline & lag."));
        assert!(!text.contains("bad()"));
    }

    #[test]
    fn large_scheduler_reference_file_requires_bounds() {
        let base =
            std::env::temp_dir().join(format!("scx_sched_ref_large_test_{}", std::process::id()));
        let scheds = base.join("scheds/rust");
        let target = scheds.join("scx_target");
        let other = scheds.join("scx_other");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(other.join("src/bpf")).unwrap();
        let large = (0..3000)
            .map(|i| format!("void helper_{i}(void) {{ pick_remote(); }}\n"))
            .collect::<String>();
        std::fs::write(other.join("src/bpf/main.bpf.c"), large).unwrap();

        let unbounded_args = json!({
            "scheduler": "scx_other",
            "path": "src/bpf/main.bpf.c",
        });
        let unbounded = execute_tool(
            &target,
            Some(&scheds),
            "read_scheduler_file",
            &unbounded_args.to_string(),
            false,
        )
        .unwrap();
        assert!(
            unbounded.contains("full unbounded read suppressed"),
            "got: {unbounded}"
        );
        assert!(unbounded.contains("grep_schedulers"), "got: {unbounded}");

        let bounded_args = json!({
            "scheduler": "scx_other",
            "path": "src/bpf/main.bpf.c",
            "start_line": 10,
            "end_line": 12,
        });
        let bounded = execute_tool(
            &target,
            Some(&scheds),
            "read_scheduler_file",
            &bounded_args.to_string(),
            false,
        )
        .unwrap();
        assert!(bounded.contains("helper_9"), "got: {bounded}");
        assert!(bounded.contains("helper_11"), "got: {bounded}");

        let _ = std::fs::remove_dir_all(&base);
    }
}
