// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{Input, Sym, Symbolizer};
use blazesym::Pid;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

const MAX_SYMBOLS: usize = 5000;
const MAX_STACK_TRACES_PER_SYMBOL: usize = 10; // Limit stack traces per symbol
const MAX_STACK_DEPTH: usize = 255;

/// Request for symbolization sent to the worker thread
#[derive(Debug, Clone)]
pub struct SymbolizationRequest {
    pub address: u64,
    pub pid: u32,
    pub is_kernel: bool,
    pub request_id: u64,
}

/// Response from symbolization worker thread
#[derive(Debug, Clone)]
pub struct SymbolizationResponse {
    pub request_id: u64,
    pub address: u64,
    pub symbol_info: SymbolInfo,
}

/// Handle for the async symbolization worker
pub struct AsyncSymbolizer {
    request_sender: mpsc::Sender<SymbolizationRequest>,
    response_receiver: mpsc::Receiver<SymbolizationResponse>,
    next_request_id: u64,
}

impl std::fmt::Debug for AsyncSymbolizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncSymbolizer")
            .field("next_request_id", &self.next_request_id)
            .finish()
    }
}

impl AsyncSymbolizer {
    pub fn new() -> Self {
        let (req_tx, req_rx) = mpsc::channel::<SymbolizationRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<SymbolizationResponse>();

        // Spawn the worker thread
        thread::spawn(move || {
            let symbolizer = Symbolizer::new();
            let mut symbol_cache: HashMap<u64, SymbolInfo> = HashMap::new();

            while let Ok(request) = req_rx.recv() {
                let symbol_info = if let Some(cached_info) = symbol_cache.get(&request.address) {
                    cached_info.clone()
                } else {
                    let info = Self::symbolize_address_sync(
                        &symbolizer,
                        request.address,
                        request.pid,
                        request.is_kernel,
                    );
                    symbol_cache.insert(request.address, info.clone());
                    info
                };

                let response = SymbolizationResponse {
                    request_id: request.request_id,
                    address: request.address,
                    symbol_info,
                };

                if resp_tx.send(response).is_err() {
                    // Receiver is closed, exit the thread
                    break;
                }
            }
        });

        Self {
            request_sender: req_tx,
            response_receiver: resp_rx,
            next_request_id: 1,
        }
    }

    pub fn request_symbolization(&mut self, address: u64, pid: u32, is_kernel: bool) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let request = SymbolizationRequest {
            address,
            pid,
            is_kernel,
            request_id,
        };

        // Send request (ignore errors if receiver is closed)
        let _ = self.request_sender.send(request);
        request_id
    }

    pub fn try_recv_responses(&self) -> Vec<SymbolizationResponse> {
        let mut responses = Vec::new();
        while let Ok(response) = self.response_receiver.try_recv() {
            responses.push(response);
        }
        responses
    }

    fn symbolize_address_sync(
        symbolizer: &Symbolizer,
        address: u64,
        pid: u32,
        is_kernel: bool,
    ) -> SymbolInfo {
        let addrs: &[u64] = &[address];

        let src = if is_kernel || pid == 0 {
            let kernel = Kernel::default();
            Source::Kernel(kernel)
        } else {
            let process = Process::new(Pid::from(pid));
            Source::Process(process)
        };

        let input = Input::AbsAddr(addrs);

        match symbolizer.symbolize(&src, input) {
            Ok(symbolized) => {
                if let Some(sym_result) = symbolized.first() {
                    match sym_result {
                        blazesym::symbolize::Symbolized::Sym(sym) => {
                            Self::extract_symbol_info_sync(sym, address, is_kernel)
                        }
                        blazesym::symbolize::Symbolized::Unknown(_) => {
                            Self::unknown_symbol_info_sync(address, is_kernel)
                        }
                    }
                } else {
                    Self::unknown_symbol_info_sync(address, is_kernel)
                }
            }
            Err(_) => Self::unknown_symbol_info_sync(address, is_kernel),
        }
    }

    fn extract_symbol_info_sync(sym: &Sym, address: u64, is_kernel: bool) -> SymbolInfo {
        let symbol_name = sym.name.to_string();
        let module_name = if let Some(module) = &sym.module {
            PathBuf::from(module)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else if is_kernel {
            "kernel".to_string()
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

    fn unknown_symbol_info_sync(address: u64, is_kernel: bool) -> SymbolInfo {
        SymbolInfo {
            symbol_name: format!("0x{address:x}"),
            module_name: if is_kernel { "kernel" } else { "unknown" }.to_string(),
            file_name: None,
            line_number: None,
            address,
        }
    }
}

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

#[derive(Debug)]
pub struct SymbolData {
    /// Map from address to symbol information
    symbol_cache: HashMap<u64, SymbolInfo>,
    /// Map from symbol name to aggregated sample count
    symbol_samples: BTreeMap<String, SymbolSample>,
    /// Total sample count for percentage calculation
    total_samples: u64,
    /// Async symbolizer for background symbolization
    async_symbolizer: AsyncSymbolizer,
    /// Symbolizer instance for immediate symbolization when needed
    symbolizer: Symbolizer,
    /// Counter for insertion order (FIFO)
    insertion_counter: u64,
    /// Pending symbolization requests
    pending_requests: HashMap<u64, (u64, u32, bool)>, // request_id -> (address, pid, is_kernel)
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
            async_symbolizer: AsyncSymbolizer::new(),
            symbolizer: Symbolizer::new(),
            insertion_counter: 0,
            pending_requests: HashMap::new(),
        }
    }

    /// Process any pending async symbolization responses
    pub fn process_async_responses(&mut self) {
        let responses = self.async_symbolizer.try_recv_responses();
        for response in responses {
            // Update the symbol cache with the symbolized result
            self.symbol_cache
                .insert(response.address, response.symbol_info);

            // Remove from pending requests
            self.pending_requests.remove(&response.request_id);
        }
    }

    /// Request async symbolization for an address
    fn request_async_symbolization(&mut self, address: u64, pid: u32, is_kernel: bool) {
        // Don't request if already cached or already pending
        if self.symbol_cache.contains_key(&address) {
            return;
        }

        // Check if we already have a pending request for this address
        let already_pending = self
            .pending_requests
            .values()
            .any(|(pending_addr, _, _)| *pending_addr == address);

        if !already_pending {
            let request_id = self
                .async_symbolizer
                .request_symbolization(address, pid, is_kernel);
            self.pending_requests
                .insert(request_id, (address, pid, is_kernel));
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

        // Process any pending async symbolization responses first
        self.process_async_responses();

        // Try to get symbol info from cache first
        let symbol_info = if let Some(cached_info) = self.symbol_cache.get(&address) {
            cached_info.clone()
        } else {
            // Request async symbolization for this address
            self.request_async_symbolization(address, pid, is_kernel);

            // For immediate display, create a temporary symbol info with the address
            // The real symbolized name will be updated when the async response arrives
            SymbolInfo {
                symbol_name: format!("0x{address:x}"),
                module_name: if is_kernel { "kernel" } else { "unknown" }.to_string(),
                file_name: None,
                line_number: None,
                address,
            }
        };

        // Also request async symbolization for stack addresses (limited depth to prevent overload)
        for &stack_addr in kernel_stack.iter().take(MAX_STACK_DEPTH) {
            if stack_addr != 0 {
                self.request_async_symbolization(stack_addr, pid, true);
            }
        }
        for &stack_addr in user_stack.iter().take(MAX_STACK_DEPTH) {
            if stack_addr != 0 {
                self.request_async_symbolization(stack_addr, pid, false);
            }
        }

        // Truncate stacks to prevent excessive memory usage
        let kernel_stack_filtered: Vec<u64> = kernel_stack
            .iter()
            .take(MAX_STACK_DEPTH)
            .filter(|&&addr| addr != 0)
            .copied()
            .collect();
        let user_stack_filtered: Vec<u64> = user_stack
            .iter()
            .take(MAX_STACK_DEPTH)
            .filter(|&&addr| addr != 0)
            .copied()
            .collect();

        // Create raw stack trace if we have stack data (don't symbolize yet)
        let stack_trace = if !kernel_stack_filtered.is_empty() || !user_stack_filtered.is_empty() {
            Some(RawStackTrace {
                kernel_stack: kernel_stack_filtered,
                user_stack: user_stack_filtered,
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
                        // Limit the number of stack traces per symbol to prevent OOMs
                        if sample.stack_traces.len() >= MAX_STACK_TRACES_PER_SYMBOL {
                            // Remove the least common stack trace (lowest count)
                            if let Some((min_idx, _)) = sample
                                .stack_traces
                                .iter()
                                .enumerate()
                                .min_by_key(|(_, trace)| trace.count)
                            {
                                sample.stack_traces.remove(min_idx);
                            }
                        }
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
            "kernel".to_string()
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
