// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{Input, Sym, Symbolizer};
use blazesym::Pid;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SymbolInfo {
    pub symbol_name: String,
    pub module_name: String,
    pub file_name: Option<String>,
    pub line_number: Option<u32>,
    pub address: u64,
}

#[derive(Clone, Debug)]
pub struct RawStackTrace {
    pub kernel_stack: Vec<u64>,
    pub user_stack: Vec<u64>,
    pub count: u64,
    pub pid: u32,
}

#[derive(Clone, Debug)]
pub struct SymbolizedStackTrace {
    pub kernel_stack: Vec<SymbolInfo>,
    pub user_stack: Vec<SymbolInfo>,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct SymbolSample {
    pub symbol_info: SymbolInfo,
    pub count: u64,
    pub percentage: f64,
    pub pid: u32,
    pub cpu_id: u32,
    pub is_kernel: bool,
    pub stack_traces: Vec<RawStackTrace>,
    pub insertion_order: u64,
    pub layer_id: Option<i32>,
}

const MAX_SYMBOLS: usize = 5000;

#[derive(Debug)]
pub struct SymbolData {
    /// Map from address to symbol information
    symbol_cache: HashMap<u64, SymbolInfo>,
    /// Map from symbol name to aggregated sample count
    symbol_samples: BTreeMap<String, SymbolSample>,
    /// Total sample count for percentage calculation
    total_samples: u64,
    /// Symbolizer instance
    symbolizer: Symbolizer,
    /// Counter for insertion order (FIFO)
    insertion_counter: u64,
}

impl Default for SymbolData {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolData {
    pub fn new() -> Self {
        Self {
            symbol_cache: HashMap::new(),
            symbol_samples: BTreeMap::new(),
            total_samples: 0,
            symbolizer: Symbolizer::new(),
            insertion_counter: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_sample_with_stacks_and_layer(
        &mut self,
        address: u64,
        pid: u32,
        cpu_id: u32,
        is_kernel: bool,
        kernel_stack: &[u64],
        user_stack: &[u64],
        layer_id: Option<i32>,
    ) {
        self.total_samples += 1;

        // Try to get symbol info from cache first
        let symbol_info = if let Some(cached_info) = self.symbol_cache.get(&address) {
            cached_info.clone()
        } else {
            // Symbolize the address
            let symbol_info = self.symbolize_address(address, pid, is_kernel);
            self.symbol_cache.insert(address, symbol_info.clone());
            symbol_info
        };

        // Create raw stack trace if we have stack data (don't symbolize yet)
        let stack_trace = if !kernel_stack.is_empty() || !user_stack.is_empty() {
            Some(RawStackTrace {
                kernel_stack: kernel_stack
                    .iter()
                    .filter(|&&addr| addr != 0)
                    .copied()
                    .collect(),
                user_stack: user_stack
                    .iter()
                    .filter(|&&addr| addr != 0)
                    .copied()
                    .collect(),
                count: 1,
                pid,
            })
        } else {
            None
        };

        // Update the sample count for this symbol
        let symbol_name = symbol_info.symbol_name.clone();

        // Check if we need to enforce the limit
        let is_new_symbol = !self.symbol_samples.contains_key(&symbol_name);
        if is_new_symbol && self.symbol_samples.len() >= MAX_SYMBOLS {
            // Find and remove the oldest symbol (FIFO - First In, First Out)
            if let Some((oldest_symbol_name, _)) = self
                .symbol_samples
                .iter()
                .min_by_key(|(_, sample)| sample.insertion_order)
                .map(|(name, sample)| (name.clone(), sample.insertion_order))
            {
                self.symbol_samples.remove(&oldest_symbol_name);
            }
        }

        self.symbol_samples
            .entry(symbol_name.clone())
            .and_modify(|sample| {
                sample.count += 1;
                sample.percentage = (sample.count as f64 / self.total_samples as f64) * 100.0;

                // Update to the latest CPU ID and PID for this symbol
                sample.cpu_id = cpu_id;
                sample.pid = pid;

                // Update layer_id if provided
                if layer_id.is_some() {
                    sample.layer_id = layer_id;
                }

                // Add stack trace if we have one
                if let Some(new_trace) = stack_trace.clone() {
                    // Check if we already have this exact stack trace (compare addresses)
                    let mut found_existing = false;
                    for existing_trace in &mut sample.stack_traces {
                        if existing_trace.kernel_stack.len() == new_trace.kernel_stack.len()
                            && existing_trace.user_stack.len() == new_trace.user_stack.len()
                            && existing_trace
                                .kernel_stack
                                .iter()
                                .zip(&new_trace.kernel_stack)
                                .all(|(a, b)| a == b)
                            && existing_trace
                                .user_stack
                                .iter()
                                .zip(&new_trace.user_stack)
                                .all(|(a, b)| a == b)
                        {
                            existing_trace.count += 1;
                            found_existing = true;
                            break;
                        }
                    }
                    if !found_existing {
                        sample.stack_traces.push(new_trace);
                    }
                }
            })
            .or_insert_with(|| {
                self.insertion_counter += 1;
                SymbolSample {
                    symbol_info,
                    count: 1,
                    percentage: (1.0 / self.total_samples as f64) * 100.0,
                    pid,
                    cpu_id,
                    is_kernel,
                    stack_traces: if let Some(trace) = stack_trace {
                        vec![trace]
                    } else {
                        Vec::new()
                    },
                    insertion_order: self.insertion_counter,
                    layer_id,
                }
            });

        // Recalculate all percentages
        for sample in self.symbol_samples.values_mut() {
            sample.percentage = (sample.count as f64 / self.total_samples as f64) * 100.0;
        }
    }

    fn symbolize_address(&self, address: u64, pid: u32, is_kernel: bool) -> SymbolInfo {
        let addrs: &[u64] = &[address];

        let src = if is_kernel || pid == 0 {
            // Use kernel source for kernel addresses with kallsyms enabled
            let kernel = Kernel::default();
            // The default Kernel configuration already enables kallsyms
            Source::Kernel(kernel)
        } else {
            // Use process source for user space addresses
            let process = Process::new(Pid::from(pid));
            Source::Process(process)
        };

        let input = Input::AbsAddr(addrs);

        match self.symbolizer.symbolize(&src, input) {
            Ok(symbolized) => {
                // Get the first result (corresponding to our single address)
                if let Some(sym_result) = symbolized.first() {
                    // Extract symbols from the symbolized result
                    match sym_result {
                        blazesym::symbolize::Symbolized::Sym(sym) => {
                            self.extract_symbol_info(sym, address, is_kernel)
                        }
                        blazesym::symbolize::Symbolized::Unknown(_) => {
                            self.unknown_symbol_info(address, is_kernel)
                        }
                    }
                } else {
                    self.unknown_symbol_info(address, is_kernel)
                }
            }
            Err(_) => self.unknown_symbol_info(address, is_kernel),
        }
    }

    fn extract_symbol_info(&self, sym: &Sym, address: u64, is_kernel: bool) -> SymbolInfo {
        let symbol_name = sym.name.to_string();
        let module_name = if let Some(module) = &sym.module {
            PathBuf::from(module)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else if is_kernel {
            // Check if this is a BPF program by looking at the symbol name
            if symbol_name.starts_with("bpf_prog_") {
                "bpf".to_string()
            } else {
                "kernel".to_string()
            }
        } else {
            "unknown".to_string()
        };

        let (file_name, line_number) = if let Some(code_info) = &sym.code_info {
            let file: Option<String> = Some(code_info.file.to_string_lossy().to_string());
            let line = code_info.line;
            (file, line)
        } else {
            (None, None)
        };

        SymbolInfo {
            symbol_name,
            module_name,
            file_name,
            line_number,
            address,
        }
    }

    fn unknown_symbol_info(&self, address: u64, is_kernel: bool) -> SymbolInfo {
        SymbolInfo {
            symbol_name: format!("0x{address:x}"),
            module_name: if is_kernel { "kernel" } else { "unknown" }.to_string(),
            file_name: None,
            line_number: None,
            address,
        }
    }

    pub fn get_top_symbols(&self, limit: usize) -> Vec<&SymbolSample> {
        let mut samples: Vec<&SymbolSample> = self.symbol_samples.values().collect();
        samples.sort_by(|a, b| b.count.cmp(&a.count));
        samples.into_iter().take(limit).collect()
    }

    pub fn clear(&mut self) {
        self.symbol_cache.clear();
        self.symbol_samples.clear();
        self.total_samples = 0;
    }

    pub fn total_samples(&self) -> u64 {
        self.total_samples
    }

    /// Update selected symbol with the latest stack trace details
    pub fn update_selected_symbol_details(
        &mut self,
        address: u64,
        kernel_stack: &[u64],
        user_stack: &[u64],
        pid: u32,
    ) {
        // Find the symbol by address and update its latest stack trace
        for sample in self.symbol_samples.values_mut() {
            if sample.symbol_info.address == address {
                // Remove old stack traces and add the latest one
                let new_trace = RawStackTrace {
                    kernel_stack: kernel_stack
                        .iter()
                        .filter(|&&addr| addr != 0)
                        .copied()
                        .collect(),
                    user_stack: user_stack
                        .iter()
                        .filter(|&&addr| addr != 0)
                        .copied()
                        .collect(),
                    count: 1,
                    pid,
                };

                // Keep only the latest stack trace for the selected symbol
                sample.stack_traces.clear();
                if !new_trace.kernel_stack.is_empty() || !new_trace.user_stack.is_empty() {
                    sample.stack_traces.push(new_trace);
                }
                break;
            }
        }
    }

    /// Symbolize a raw stack trace on demand
    pub fn symbolize_stack_trace(&self, raw_trace: &RawStackTrace) -> SymbolizedStackTrace {
        let kernel_symbols: Vec<SymbolInfo> = raw_trace
            .kernel_stack
            .iter()
            .map(|&addr| {
                if let Some(cached_info) = self.symbol_cache.get(&addr) {
                    cached_info.clone()
                } else {
                    self.symbolize_address(addr, raw_trace.pid, true)
                }
            })
            .collect();

        let user_symbols: Vec<SymbolInfo> = raw_trace
            .user_stack
            .iter()
            .map(|&addr| {
                if let Some(cached_info) = self.symbol_cache.get(&addr) {
                    cached_info.clone()
                } else {
                    self.symbolize_address(addr, raw_trace.pid, false)
                }
            })
            .collect();

        SymbolizedStackTrace {
            kernel_stack: kernel_symbols,
            user_stack: user_symbols,
            count: raw_trace.count,
        }
    }
}
