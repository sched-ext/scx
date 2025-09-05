// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

// MSR-based RAPL (Running Average Power Limit) constants
// Intel RAPL MSR registers - Complete Coverage
const MSR_RAPL_POWER_UNIT: u32 = 0x606; // Power unit definitions

// Energy Status Registers
const MSR_PKG_ENERGY_STATUS: u32 = 0x611; // Package energy consumed
const MSR_DRAM_ENERGY_STATUS: u32 = 0x619; // DRAM energy consumed
const MSR_PP0_ENERGY_STATUS: u32 = 0x639; // Cores energy consumed
const MSR_PP1_ENERGY_STATUS: u32 = 0x641; // GPU/uncore energy consumed
const MSR_PSYS_ENERGY_STATUS: u32 = 0x64D; // Platform energy (Skylake+)

// Power Limit Registers
const MSR_PKG_POWER_LIMIT: u32 = 0x610; // Package power limits
const MSR_DRAM_POWER_LIMIT: u32 = 0x618; // DRAM power limits
const MSR_PP0_POWER_LIMIT: u32 = 0x638; // Cores power limits
const MSR_PP1_POWER_LIMIT: u32 = 0x640; // GPU/uncore power limits
const MSR_PSYS_POWER_LIMIT: u32 = 0x64C; // Platform power limits (Skylake+)

// Power Info Registers
const MSR_PKG_POWER_INFO: u32 = 0x614; // Package power info (TDP, etc.)
const MSR_DRAM_POWER_INFO: u32 = 0x61C; // DRAM power info
const MSR_PP0_POWER_INFO: u32 = 0x63C; // Cores power info
const MSR_PP1_POWER_INFO: u32 = 0x644; // GPU/uncore power info
const MSR_PSYS_POWER_INFO: u32 = 0x650; // Platform power info (Skylake+)

// Performance Status Registers
const MSR_PKG_PERF_STATUS: u32 = 0x613; // Package performance status
const MSR_DRAM_PERF_STATUS: u32 = 0x61B; // DRAM performance status
const MSR_PP0_PERF_STATUS: u32 = 0x63B; // Cores performance status
const MSR_PP1_PERF_STATUS: u32 = 0x643; // GPU/uncore performance status

// Additional Intel MSRs for newer processors
#[allow(dead_code)]
const MSR_PLATFORM_POWER_LIMIT: u32 = 0x65C; // Platform power limit (Ice Lake+)

// AMD RAPL MSR registers - Complete Coverage
const MSR_AMD_RAPL_POWER_UNIT: u32 = 0xC0010299; // Power unit definitions

// Energy Status Registers
const MSR_AMD_CORE_ENERGY_STAT: u32 = 0xC001029A; // Core energy consumed
const MSR_AMD_PKG_ENERGY_STAT: u32 = 0xC001029B; // Package energy consumed
const MSR_AMD_L3_ENERGY_STAT: u32 = 0xC001029C; // L3 cache energy (Zen 3+)

// Power Limit Registers
const MSR_AMD_CORE_POWER_LIMIT: u32 = 0xC0010290; // Core power limits
const MSR_AMD_PKG_POWER_LIMIT: u32 = 0xC0010291; // Package power limits

// Power Info Registers
const MSR_AMD_CORE_POWER_INFO: u32 = 0xC0010292; // Core power info
const MSR_AMD_PKG_POWER_INFO: u32 = 0xC0010293; // Package power info

// Additional AMD MSRs for comprehensive monitoring
#[allow(dead_code)]
const MSR_AMD_RAPL_PWR_UNIT: u32 = 0xC0010299; // Alternative power unit
#[allow(dead_code)]
const MSR_AMD_PWR_REPORTING: u32 = 0xC001007A; // Power reporting enable

// CPU vendor detection
#[derive(Debug, Clone, PartialEq)]
enum CpuVendor {
    Intel,
    Amd,
    Unknown,
}

// RAPL Energy Units (for converting raw energy values)
#[derive(Debug, Clone)]
struct RaplUnits {
    energy_unit: f64, // Joules per unit
    power_unit: f64,  // Watts per unit
    #[allow(dead_code)]
    time_unit: f64, // Seconds per unit
}

impl Default for RaplUnits {
    fn default() -> Self {
        Self {
            energy_unit: 1.0 / 65536.0, // Default: 1/2^16 joules
            power_unit: 1.0 / 8.0,      // Default: 1/8 watts
            time_unit: 1.0 / 1024.0,    // Default: 1/1024 seconds
        }
    }
}

// RAPL energy readings with comprehensive power information
#[derive(Debug, Clone, Default)]
struct RaplReading {
    timestamp: u64,

    // Energy counters (in microjoules)
    package_energy_uj: u64, // Package energy consumed
    core_energy_uj: u64,    // Core energy consumed
    dram_energy_uj: u64,    // DRAM energy consumed
    gpu_energy_uj: u64,     // GPU/uncore energy consumed (Intel)
    psys_energy_uj: u64,    // Platform/system energy consumed (Intel Skylake+)
    l3_energy_uj: u64,      // L3 cache energy consumed (AMD Zen 3+)

    // Power limits (in watts)
    package_power_limit: f64, // Package power limit
    dram_power_limit: f64,    // DRAM power limit
    core_power_limit: f64,    // Core power limit
    gpu_power_limit: f64,     // GPU/uncore power limit
    psys_power_limit: f64,    // Platform power limit (Intel Skylake+)

    // Power info (in watts)
    package_tdp: f64, // Package TDP (Thermal Design Power)
    dram_tdp: f64,    // DRAM TDP
    core_tdp: f64,    // Core TDP
    gpu_tdp: f64,     // GPU/uncore TDP
    psys_tdp: f64,    // Platform TDP

    // Performance status (percentage throttled)
    package_throttled_pct: f64, // Package throttling percentage
    dram_throttled_pct: f64,    // DRAM throttling percentage
    core_throttled_pct: f64,    // Core throttling percentage
    gpu_throttled_pct: f64,     // GPU/uncore throttling percentage
}

// MSR reader with caching for performance
struct MsrReader {
    msr_files: Mutex<HashMap<u32, File>>, // CPU ID -> MSR file handle
    cpu_vendor: CpuVendor,
    rapl_units: HashMap<u32, RaplUnits>, // Per-package RAPL units
}

impl MsrReader {
    pub fn new() -> Result<Self> {
        let cpu_vendor = Self::detect_cpu_vendor()?;

        let mut reader = Self {
            msr_files: Mutex::new(HashMap::new()),
            cpu_vendor,
            rapl_units: HashMap::new(),
        };

        // Initialize RAPL units for available packages
        reader.init_rapl_units()?;

        Ok(reader)
    }

    fn detect_cpu_vendor() -> Result<CpuVendor> {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("vendor_id") {
                    if line.contains("GenuineIntel") {
                        return Ok(CpuVendor::Intel);
                    } else if line.contains("AuthenticAMD") {
                        return Ok(CpuVendor::Amd);
                    }
                    break;
                }
            }
        }
        Ok(CpuVendor::Unknown)
    }

    fn init_rapl_units(&mut self) -> Result<()> {
        // Get package count from topology
        let package_count = self.get_package_count()?;

        for package_id in 0..package_count {
            // Find the first CPU in this package
            if let Some(cpu_id) = self.find_first_cpu_in_package(package_id)? {
                if let Ok(units) = self.read_rapl_units(cpu_id) {
                    self.rapl_units.insert(package_id, units);
                }
            }
        }

        Ok(())
    }

    fn get_package_count(&self) -> Result<u32> {
        let mut max_package = 0;

        // Scan all CPUs to find the maximum package ID
        for cpu_id in 0..256 {
            // Reasonable upper limit
            let topology_path =
                format!("/sys/devices/system/cpu/cpu{cpu_id}/topology/physical_package_id");
            if let Ok(package_str) = fs::read_to_string(&topology_path) {
                if let Ok(package_id) = package_str.trim().parse::<u32>() {
                    max_package = max_package.max(package_id);
                }
            } else {
                break; // No more CPUs
            }
        }

        Ok(max_package + 1)
    }

    fn find_first_cpu_in_package(&self, package_id: u32) -> Result<Option<u32>> {
        for cpu_id in 0..256 {
            // Reasonable upper limit
            let topology_path =
                format!("/sys/devices/system/cpu/cpu{cpu_id}/topology/physical_package_id");
            if let Ok(package_str) = fs::read_to_string(&topology_path) {
                if let Ok(cpu_package_id) = package_str.trim().parse::<u32>() {
                    if cpu_package_id == package_id {
                        return Ok(Some(cpu_id));
                    }
                }
            } else {
                break;
            }
        }
        Ok(None)
    }

    fn read_rapl_units(&self, cpu_id: u32) -> Result<RaplUnits> {
        let power_unit_msr = match self.cpu_vendor {
            CpuVendor::Intel => MSR_RAPL_POWER_UNIT,
            CpuVendor::Amd => MSR_AMD_RAPL_POWER_UNIT,
            CpuVendor::Unknown => return Ok(RaplUnits::default()),
        };

        if let Ok(raw_value) = self.read_msr(cpu_id, power_unit_msr) {
            let energy_unit = 1.0 / (1u64 << ((raw_value >> 8) & 0x1F)) as f64;
            let power_unit = 1.0 / (1u64 << (raw_value & 0xF)) as f64;
            let time_unit = 1.0 / (1u64 << ((raw_value >> 16) & 0xF)) as f64;

            Ok(RaplUnits {
                energy_unit,
                power_unit,
                time_unit,
            })
        } else {
            Ok(RaplUnits::default())
        }
    }

    fn read_msr(&self, cpu_id: u32, msr: u32) -> Result<u64> {
        let mut files = self.msr_files.lock().unwrap();

        // Check if we already have a file handle for this CPU
        if let std::collections::hash_map::Entry::Vacant(e) = files.entry(cpu_id) {
            // Try to open MSR device with graceful error handling
            let file = match File::open(format!("/dev/cpu/{cpu_id}/msr")) {
                Ok(file) => file,
                Err(_) => {
                    // Second attempt: try to load msr module and open again
                    let _ = std::process::Command::new("modprobe").arg("msr").output();

                    match File::open(format!("/dev/cpu/{cpu_id}/msr")) {
                        Ok(file) => file,
                        Err(e) => {
                            return Err(anyhow!("Cannot access MSR device /dev/cpu/{cpu_id}/msr: {e}. MSR access requires elevated privileges or proper kernel module configuration."));
                        }
                    }
                }
            };
            e.insert(file);
        }

        let file = files.get_mut(&cpu_id).unwrap();

        // Seek to MSR address
        file.seek(SeekFrom::Start(msr as u64))?;

        // Read 8 bytes (64-bit value)
        let mut buffer = [0u8; 8];
        file.read_exact(&mut buffer)?;

        Ok(u64::from_le_bytes(buffer))
    }

    pub fn read_rapl_energy(&self, package_id: u32) -> Result<RaplReading> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        // Find the first CPU in this package
        let cpu_id = self
            .find_first_cpu_in_package(package_id)?
            .ok_or_else(|| anyhow!("No CPU found in package {}", package_id))?;

        let mut reading = RaplReading {
            timestamp,
            ..Default::default()
        };

        // Get RAPL units for this package
        let default_units = RaplUnits::default();
        let units = self.rapl_units.get(&package_id).unwrap_or(&default_units);

        match self.cpu_vendor {
            CpuVendor::Intel => {
                // Read Intel RAPL Energy Status MSRs
                if let Ok(pkg_energy) = self.read_msr(cpu_id, MSR_PKG_ENERGY_STATUS) {
                    reading.package_energy_uj =
                        ((pkg_energy & 0xFFFFFFFF) as f64 * units.energy_unit * 1_000_000.0) as u64;
                }

                if let Ok(core_energy) = self.read_msr(cpu_id, MSR_PP0_ENERGY_STATUS) {
                    reading.core_energy_uj = ((core_energy & 0xFFFFFFFF) as f64
                        * units.energy_unit
                        * 1_000_000.0) as u64;
                }

                if let Ok(dram_energy) = self.read_msr(cpu_id, MSR_DRAM_ENERGY_STATUS) {
                    reading.dram_energy_uj = ((dram_energy & 0xFFFFFFFF) as f64
                        * units.energy_unit
                        * 1_000_000.0) as u64;
                }

                if let Ok(gpu_energy) = self.read_msr(cpu_id, MSR_PP1_ENERGY_STATUS) {
                    reading.gpu_energy_uj =
                        ((gpu_energy & 0xFFFFFFFF) as f64 * units.energy_unit * 1_000_000.0) as u64;
                }

                // Read Platform/System energy (Skylake+)
                if let Ok(psys_energy) = self.read_msr(cpu_id, MSR_PSYS_ENERGY_STATUS) {
                    reading.psys_energy_uj = ((psys_energy & 0xFFFFFFFF) as f64
                        * units.energy_unit
                        * 1_000_000.0) as u64;
                }

                // Read Intel Power Limit MSRs
                if let Ok(pkg_power_limit) = self.read_msr(cpu_id, MSR_PKG_POWER_LIMIT) {
                    // Power limit 1 is in bits 14:0, power limit 2 is in bits 46:32
                    let pl1 = (pkg_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.package_power_limit = pl1;
                }

                if let Ok(dram_power_limit) = self.read_msr(cpu_id, MSR_DRAM_POWER_LIMIT) {
                    let dram_limit = (dram_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.dram_power_limit = dram_limit;
                }

                if let Ok(pp0_power_limit) = self.read_msr(cpu_id, MSR_PP0_POWER_LIMIT) {
                    let pp0_limit = (pp0_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.core_power_limit = pp0_limit;
                }

                if let Ok(pp1_power_limit) = self.read_msr(cpu_id, MSR_PP1_POWER_LIMIT) {
                    let pp1_limit = (pp1_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.gpu_power_limit = pp1_limit;
                }

                if let Ok(psys_power_limit) = self.read_msr(cpu_id, MSR_PSYS_POWER_LIMIT) {
                    let psys_limit = (psys_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.psys_power_limit = psys_limit;
                }

                // Read Intel Power Info MSRs (TDP values)
                if let Ok(pkg_power_info) = self.read_msr(cpu_id, MSR_PKG_POWER_INFO) {
                    // TDP is in bits 14:0
                    let tdp = (pkg_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.package_tdp = tdp;
                }

                if let Ok(dram_power_info) = self.read_msr(cpu_id, MSR_DRAM_POWER_INFO) {
                    let dram_tdp = (dram_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.dram_tdp = dram_tdp;
                }

                if let Ok(pp0_power_info) = self.read_msr(cpu_id, MSR_PP0_POWER_INFO) {
                    let pp0_tdp = (pp0_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.core_tdp = pp0_tdp;
                }

                if let Ok(pp1_power_info) = self.read_msr(cpu_id, MSR_PP1_POWER_INFO) {
                    let pp1_tdp = (pp1_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.gpu_tdp = pp1_tdp;
                }

                if let Ok(psys_power_info) = self.read_msr(cpu_id, MSR_PSYS_POWER_INFO) {
                    let psys_tdp = (psys_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.psys_tdp = psys_tdp;
                }

                // Read Intel Performance Status MSRs (throttling info)
                if let Ok(pkg_perf_status) = self.read_msr(cpu_id, MSR_PKG_PERF_STATUS) {
                    // Throttling info is typically in higher bits, calculate percentage
                    let throttle_cycles = (pkg_perf_status >> 32) & 0xFFFFFFFF;
                    let total_cycles = pkg_perf_status & 0xFFFFFFFF;
                    if total_cycles > 0 {
                        reading.package_throttled_pct =
                            (throttle_cycles as f64 / total_cycles as f64) * 100.0;
                    }
                }

                if let Ok(dram_perf_status) = self.read_msr(cpu_id, MSR_DRAM_PERF_STATUS) {
                    let throttle_cycles = (dram_perf_status >> 32) & 0xFFFFFFFF;
                    let total_cycles = dram_perf_status & 0xFFFFFFFF;
                    if total_cycles > 0 {
                        reading.dram_throttled_pct =
                            (throttle_cycles as f64 / total_cycles as f64) * 100.0;
                    }
                }

                if let Ok(pp0_perf_status) = self.read_msr(cpu_id, MSR_PP0_PERF_STATUS) {
                    let throttle_cycles = (pp0_perf_status >> 32) & 0xFFFFFFFF;
                    let total_cycles = pp0_perf_status & 0xFFFFFFFF;
                    if total_cycles > 0 {
                        reading.core_throttled_pct =
                            (throttle_cycles as f64 / total_cycles as f64) * 100.0;
                    }
                }

                if let Ok(pp1_perf_status) = self.read_msr(cpu_id, MSR_PP1_PERF_STATUS) {
                    let throttle_cycles = (pp1_perf_status >> 32) & 0xFFFFFFFF;
                    let total_cycles = pp1_perf_status & 0xFFFFFFFF;
                    if total_cycles > 0 {
                        reading.gpu_throttled_pct =
                            (throttle_cycles as f64 / total_cycles as f64) * 100.0;
                    }
                }
            }
            CpuVendor::Amd => {
                // Read AMD RAPL Energy Status MSRs
                if let Ok(pkg_energy) = self.read_msr(cpu_id, MSR_AMD_PKG_ENERGY_STAT) {
                    reading.package_energy_uj =
                        ((pkg_energy & 0xFFFFFFFF) as f64 * units.energy_unit * 1_000_000.0) as u64;
                }

                if let Ok(core_energy) = self.read_msr(cpu_id, MSR_AMD_CORE_ENERGY_STAT) {
                    reading.core_energy_uj = ((core_energy & 0xFFFFFFFF) as f64
                        * units.energy_unit
                        * 1_000_000.0) as u64;
                }

                // Read L3 cache energy (Zen 3+)
                if let Ok(l3_energy) = self.read_msr(cpu_id, MSR_AMD_L3_ENERGY_STAT) {
                    reading.l3_energy_uj =
                        ((l3_energy & 0xFFFFFFFF) as f64 * units.energy_unit * 1_000_000.0) as u64;
                }

                // Read AMD Power Limit MSRs
                if let Ok(core_power_limit) = self.read_msr(cpu_id, MSR_AMD_CORE_POWER_LIMIT) {
                    let core_limit = (core_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.core_power_limit = core_limit;
                }

                if let Ok(pkg_power_limit) = self.read_msr(cpu_id, MSR_AMD_PKG_POWER_LIMIT) {
                    let pkg_limit = (pkg_power_limit & 0x7FFF) as f64 * units.power_unit;
                    reading.package_power_limit = pkg_limit;
                }

                // Read AMD Power Info MSRs (TDP values)
                if let Ok(core_power_info) = self.read_msr(cpu_id, MSR_AMD_CORE_POWER_INFO) {
                    let core_tdp = (core_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.core_tdp = core_tdp;
                }

                if let Ok(pkg_power_info) = self.read_msr(cpu_id, MSR_AMD_PKG_POWER_INFO) {
                    let pkg_tdp = (pkg_power_info & 0x7FFF) as f64 * units.power_unit;
                    reading.package_tdp = pkg_tdp;
                }
            }
            CpuVendor::Unknown => {
                return Err(anyhow!("Unknown CPU vendor - cannot read RAPL MSRs"));
            }
        }

        Ok(reading)
    }

    pub fn get_cpu_vendor(&self) -> &CpuVendor {
        &self.cpu_vendor
    }
}

// RAPL-based power monitor
struct RaplPowerMonitor {
    msr_reader: MsrReader,
    previous_readings: HashMap<u32, RaplReading>, // Package ID -> Previous reading
    package_count: u32,
}

impl RaplPowerMonitor {
    pub fn new() -> Result<Self> {
        let msr_reader = MsrReader::new()?;
        let package_count = msr_reader.get_package_count()?;

        Ok(Self {
            msr_reader,
            previous_readings: HashMap::new(),
            package_count,
        })
    }

    pub fn collect_power_data(&mut self) -> Result<HashMap<u32, f64>> {
        let mut package_power = HashMap::new();

        for package_id in 0..self.package_count {
            if let Ok(current_reading) = self.msr_reader.read_rapl_energy(package_id) {
                // Calculate power based on energy difference
                if let Some(previous_reading) = self.previous_readings.get(&package_id) {
                    let time_delta_seconds =
                        (current_reading.timestamp - previous_reading.timestamp) as f64
                            / 1_000_000.0;

                    if time_delta_seconds > 0.0 {
                        let energy_delta_joules = (current_reading.package_energy_uj
                            - previous_reading.package_energy_uj)
                            as f64
                            / 1_000_000.0;
                        let power_watts = energy_delta_joules / time_delta_seconds;

                        // Sanity check - ignore unrealistic power values
                        if (0.0..=1000.0).contains(&power_watts) {
                            package_power.insert(package_id, power_watts);
                        }
                    }
                }

                // Store current reading for next iteration
                self.previous_readings.insert(package_id, current_reading);
            }
        }

        Ok(package_power)
    }

    pub fn get_cpu_vendor(&self) -> &CpuVendor {
        self.msr_reader.get_cpu_vendor()
    }

    pub fn is_available(&self) -> bool {
        // Check if we can read at least one package
        for package_id in 0..self.package_count {
            if self.msr_reader.read_rapl_energy(package_id).is_ok() {
                return true;
            }
        }
        false
    }
}

/// C-state information for a CPU core
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CStateInfo {
    pub name: String,
    pub latency: u64,   // Exit latency in microseconds
    pub residency: u64, // Time spent in this C-state (microseconds)
    pub usage: u64,     // Number of times this C-state was entered
}

/// Power monitoring data for a single CPU core
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CorePowerData {
    pub core_id: u32,
    pub frequency_mhz: f64,
    pub temperature_celsius: f64,
    pub power_watts: f64,
    pub c_states: HashMap<String, CStateInfo>,
    pub package_id: u32,

    // Enhanced RAPL data from comprehensive MSR readings
    pub tdp: f64,              // Thermal Design Power (watts)
    pub power_limit: f64,      // Current power limit (watts)
    pub throttle_percent: f64, // Throttling percentage (0-100)
    pub dram_energy_uj: u64,   // DRAM energy consumed (microjoules)
    pub gpu_energy_uj: u64,    // GPU/uncore energy consumed (microjoules)
    pub psys_energy_uj: u64,   // Platform/system energy (Intel Skylake+)
    pub l3_energy_uj: u64,     // L3 cache energy (AMD Zen 3+)
}

/// System-wide power monitoring data
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemPowerData {
    pub timestamp: u64,
    pub cores: HashMap<u32, CorePowerData>,
    pub total_power_watts: f64,
    pub battery_level_percent: Option<f64>,
    pub battery_charging: Option<bool>,
    pub battery_remaining_time_minutes: Option<u32>,
    pub package_power: HashMap<u32, f64>, // Package ID -> Power in watts
}

/// Historical data point for charting
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PowerHistoryPoint {
    pub timestamp: u64,
    pub total_power_watts: f64,
    pub avg_power_per_core: f64,
}

/// Power monitoring snapshot for tracking changes over time
#[derive(Clone, Debug, Default)]
pub struct PowerSnapshot {
    pub current: SystemPowerData,
    pub previous: Option<SystemPowerData>,
    pub history: Vec<PowerHistoryPoint>,
    max_history_points: usize,
    pub cstate_deltas: HashMap<u32, HashMap<String, CStateInfo>>,

    // Min/Max tracking for dynamic thresholds
    power_min: f64,
    power_max: f64,
    temperature_min: f64,
    temperature_max: f64,
    frequency_min: f64,
    frequency_max: f64,

    // Track if we have observed any data yet
    has_data: bool,
}

impl PowerSnapshot {
    pub fn new() -> Self {
        Self {
            max_history_points: 120,
            cstate_deltas: HashMap::new(),
            ..Default::default()
        }
    }

    /// Update the power snapshot with new data
    pub fn update(&mut self, new_data: SystemPowerData) {
        // Calculate C-state deltas if we have previous data
        self.calculate_cstate_deltas(&new_data);

        self.previous = Some(self.current.clone());

        // Track min/max values for dynamic thresholds
        self.update_min_max_values(&new_data);

        // Calculate average power per core
        let avg_power_per_core = if !new_data.cores.is_empty() {
            new_data.total_power_watts / new_data.cores.len() as f64
        } else {
            0.0
        };

        // Add to history
        let history_point = PowerHistoryPoint {
            timestamp: new_data.timestamp,
            total_power_watts: new_data.total_power_watts,
            avg_power_per_core,
        };

        self.history.push(history_point);

        // Keep only the last N points
        if self.history.len() > self.max_history_points {
            self.history.remove(0);
        }

        self.current = new_data;
    }

    /// Update the maximum history points based on chart constraints
    pub fn set_max_history_points(&mut self, max_points: usize) {
        self.max_history_points = max_points;

        // Trim existing history if needed
        while self.history.len() > self.max_history_points {
            self.history.remove(0);
        }
    }

    /// Get time-bounded data for charts based on tick interval and chart constraints
    pub fn get_time_bounded_data(
        &self,
        tick_interval_ms: u64,
        chart_width: u16,
    ) -> &[PowerHistoryPoint] {
        if self.history.is_empty() {
            return &self.history;
        }

        // For higher density charts, allow more data points per pixel
        // Use 1.2 pixels per data point instead of 3.0 for much higher density
        let optimal_points = ((chart_width as f64) / 1.2).floor() as usize;
        let max_points = optimal_points.min(self.max_history_points).max(30); // Increased minimum from 10 to 30

        // Calculate time window based on tick interval
        let time_window_seconds = (max_points as u64 * tick_interval_ms) / 1000;
        let current_time = self.history.last().unwrap().timestamp;
        let start_time = current_time.saturating_sub(time_window_seconds);

        // Find the starting index for our time window
        let start_idx = self
            .history
            .iter()
            .position(|point| point.timestamp >= start_time)
            .unwrap_or(0);

        &self.history[start_idx..]
    }

    /// Get adaptive sampling of data points for optimal chart rendering
    pub fn get_adaptive_chart_data(
        &self,
        tick_interval_ms: u64,
        chart_width: u16,
    ) -> Vec<&PowerHistoryPoint> {
        let bounded_data = self.get_time_bounded_data(tick_interval_ms, chart_width);

        if bounded_data.is_empty() {
            return Vec::new();
        }

        // High density: 1.2 pixels per data point for much more detailed charts
        let target_points = ((chart_width as f64) / 1.2).floor() as usize;

        // If we have fewer points than target, return all available data
        if bounded_data.len() <= target_points {
            return bounded_data.iter().collect();
        }

        // For high-density charts with lots of data, use intelligent sampling
        // that preserves trends while fitting within the target point count
        let mut sampled_points = Vec::new();

        // Always include the first point
        sampled_points.push(&bounded_data[0]);

        if target_points > 2 {
            // Sample middle points with adaptive step size
            let step = bounded_data.len() as f64 / target_points as f64;

            for i in 1..(target_points - 1) {
                let idx = (i as f64 * step).floor() as usize;
                if idx < bounded_data.len() && idx > 0 {
                    sampled_points.push(&bounded_data[idx]);
                }
            }
        }

        // Always include the last point for current data
        if let Some(last_point) = bounded_data.last() {
            if sampled_points.last() != Some(&last_point) {
                sampled_points.push(last_point);
            }
        }

        sampled_points
    }

    /// Get high-density chart data for detailed power visualization
    pub fn get_high_density_chart_data(&self, chart_width: u16) -> Vec<&PowerHistoryPoint> {
        if self.history.is_empty() {
            return Vec::new();
        }

        // For maximum density, show as much recent data as possible
        // Use 0.8 pixels per data point for very high density
        let max_points = ((chart_width as f64) / 0.8).floor() as usize;
        let points_to_show = max_points.min(self.history.len());

        // Take the most recent data points
        let start_idx = self.history.len().saturating_sub(points_to_show);
        self.history[start_idx..].iter().collect()
    }

    /// Calculate C-state deltas between current and new data
    fn calculate_cstate_deltas(&mut self, new_data: &SystemPowerData) {
        if let Some(prev_data) = &self.previous {
            self.cstate_deltas.clear();

            for (core_id, new_core) in &new_data.cores {
                if let Some(prev_core) = prev_data.cores.get(core_id) {
                    let mut core_deltas = HashMap::new();

                    for (cstate_name, new_cstate) in &new_core.c_states {
                        if let Some(prev_cstate) = prev_core.c_states.get(cstate_name) {
                            // Calculate delta for this C-state
                            let delta_residency =
                                new_cstate.residency.saturating_sub(prev_cstate.residency);
                            let delta_usage = new_cstate.usage.saturating_sub(prev_cstate.usage);

                            core_deltas.insert(
                                cstate_name.clone(),
                                CStateInfo {
                                    name: cstate_name.clone(),
                                    latency: new_cstate.latency,
                                    residency: delta_residency,
                                    usage: delta_usage,
                                },
                            );
                        }
                    }

                    self.cstate_deltas.insert(*core_id, core_deltas);
                }
            }
        }
    }

    /// Get C-state delta percentage for a specific core and C-state
    pub fn get_cstate_percentage(&self, core_id: u32, cstate_name: &str) -> f64 {
        if let Some(core_deltas) = self.cstate_deltas.get(&core_id) {
            if let Some(cstate_delta) = core_deltas.get(cstate_name) {
                // Calculate total residency delta for this core
                let total_residency_delta: u64 = core_deltas.values().map(|cs| cs.residency).sum();

                if total_residency_delta > 0 {
                    return (cstate_delta.residency as f64 / total_residency_delta as f64) * 100.0;
                }
            }
        }

        // Fallback to static calculation if no deltas available
        if let Some(core_data) = self.current.cores.get(&core_id) {
            if let Some(cstate_info) = core_data.c_states.get(cstate_name) {
                let total_residency: u64 = core_data.c_states.values().map(|cs| cs.residency).sum();

                if total_residency > 0 {
                    return (cstate_info.residency as f64 / total_residency as f64) * 100.0;
                }
            }
        }

        0.0
    }

    /// Get power usage delta per core since last update
    pub fn get_power_delta(&self) -> HashMap<u32, f64> {
        let mut deltas = HashMap::new();

        if let Some(prev) = &self.previous {
            for (core_id, current_core) in &self.current.cores {
                if let Some(prev_core) = prev.cores.get(core_id) {
                    let delta = current_core.power_watts - prev_core.power_watts;
                    deltas.insert(*core_id, delta);
                }
            }
        }

        deltas
    }

    /// Get historical data points for charting
    pub fn get_chart_data(&self) -> &[PowerHistoryPoint] {
        &self.history
    }

    /// Get time range for chart x-axis
    pub fn get_time_range(&self) -> (f64, f64) {
        if self.history.is_empty() {
            return (0.0, 1.0);
        }

        let min_time = self.history.first().unwrap().timestamp as f64;
        let max_time = self.history.last().unwrap().timestamp as f64;

        // Return range with a small buffer
        let range = max_time - min_time;
        let buffer = range * 0.1;
        (min_time - buffer, max_time + buffer)
    }

    /// Get total power range for chart y-axis
    pub fn get_total_power_range(&self) -> (f64, f64) {
        if self.history.is_empty() {
            return (0.0, 100.0);
        }

        let mut min_power = f64::MAX;
        let mut max_power = f64::MIN;

        for point in &self.history {
            if point.total_power_watts < min_power {
                min_power = point.total_power_watts;
            }
            if point.total_power_watts > max_power {
                max_power = point.total_power_watts;
            }
        }

        // Add 10% buffer
        let range = max_power - min_power;
        let buffer = range * 0.1;
        ((min_power - buffer).max(0.0), max_power + buffer)
    }

    /// Get average power per core range for chart y-axis
    pub fn get_avg_power_range(&self) -> (f64, f64) {
        if self.history.is_empty() {
            return (0.0, 10.0);
        }

        let mut min_power = f64::MAX;
        let mut max_power = f64::MIN;

        for point in &self.history {
            if point.avg_power_per_core < min_power {
                min_power = point.avg_power_per_core;
            }
            if point.avg_power_per_core > max_power {
                max_power = point.avg_power_per_core;
            }
        }

        // Add 10% buffer
        let range = max_power - min_power;
        let buffer = range * 0.1;
        ((min_power - buffer).max(0.0), max_power + buffer)
    }

    /// Update min/max values for dynamic thresholds
    fn update_min_max_values(&mut self, new_data: &SystemPowerData) {
        if !self.has_data {
            // Initialize with first data set
            self.power_min = new_data.total_power_watts;
            self.power_max = new_data.total_power_watts;

            if let Some(first_core) = new_data.cores.values().next() {
                self.temperature_min = first_core.temperature_celsius;
                self.temperature_max = first_core.temperature_celsius;
                self.frequency_min = first_core.frequency_mhz;
                self.frequency_max = first_core.frequency_mhz;
            }

            self.has_data = true;
        }

        // Update total power min/max
        self.power_min = self.power_min.min(new_data.total_power_watts);
        self.power_max = self.power_max.max(new_data.total_power_watts);

        // Update per-core min/max values
        for core_data in new_data.cores.values() {
            if core_data.temperature_celsius > 0.0 {
                self.temperature_min = self.temperature_min.min(core_data.temperature_celsius);
                self.temperature_max = self.temperature_max.max(core_data.temperature_celsius);
            }

            if core_data.frequency_mhz > 0.0 {
                self.frequency_min = self.frequency_min.min(core_data.frequency_mhz);
                self.frequency_max = self.frequency_max.max(core_data.frequency_mhz);
            }
        }
    }

    /// Get dynamic power thresholds based on observed values
    pub fn get_power_thresholds(&self) -> (f64, f64) {
        if !self.has_data || self.power_max <= self.power_min {
            return (5.0, 15.0); // Fallback to reasonable defaults
        }

        let range = self.power_max - self.power_min;
        let low_threshold = self.power_min + (range * 0.33); // 33rd percentile
        let high_threshold = self.power_min + (range * 0.67); // 67th percentile

        (low_threshold, high_threshold)
    }

    /// Get dynamic temperature thresholds based on observed values
    pub fn get_temperature_thresholds(&self) -> (f64, f64) {
        if !self.has_data || self.temperature_max <= self.temperature_min {
            return (60.0, 80.0); // Fallback to reasonable defaults
        }

        let range = self.temperature_max - self.temperature_min;

        // For temperature, we want to be more conservative
        // Low threshold at 40% of range, high threshold at 75% of range
        let low_threshold = self.temperature_min + (range * 0.4);
        let high_threshold = self.temperature_min + (range * 0.75);

        // Ensure reasonable bounds
        let low_threshold = low_threshold.clamp(40.0, 70.0);
        let high_threshold = high_threshold.clamp(60.0, 90.0);

        (low_threshold, high_threshold)
    }

    /// Get dynamic frequency thresholds based on observed values
    pub fn get_frequency_thresholds(&self) -> (f64, f64) {
        if !self.has_data || self.frequency_max <= self.frequency_min {
            return (1000.0, 3000.0); // Fallback to reasonable defaults
        }

        let range = self.frequency_max - self.frequency_min;

        // For frequency, lower is worse performance, higher is better
        let low_threshold = self.frequency_min + (range * 0.33); // 33rd percentile
        let high_threshold = self.frequency_min + (range * 0.67); // 67th percentile

        (low_threshold, high_threshold)
    }

    /// Get observed minimum and maximum values for informational display
    pub fn get_observed_ranges(
        &self,
    ) -> (
        (f64, f64), // power range
        (f64, f64), // temperature range
        (f64, f64), // frequency range
    ) {
        if !self.has_data {
            return ((0.0, 0.0), (0.0, 0.0), (0.0, 0.0));
        }

        (
            (self.power_min, self.power_max),
            (self.temperature_min, self.temperature_max),
            (self.frequency_min, self.frequency_max),
        )
    }
}

/// Power data collector that interfaces with the Linux power subsystem
pub struct PowerDataCollector {
    cpu_count: u32,
    sysfs_power_path: String,
    sysfs_cpufreq_path: String,
    sysfs_thermal_path: String,
    sysfs_cpuidle_path: String,
    rapl_monitor: Option<RaplPowerMonitor>,
}

impl PowerDataCollector {
    pub fn new() -> Result<Self> {
        let cpu_count = Self::detect_cpu_count()?;

        // Try to initialize RAPL monitor for MSR-based power readings
        let rapl_monitor = match RaplPowerMonitor::new() {
            Ok(monitor) => {
                if monitor.is_available() {
                    log::info!(
                        "MSR-based RAPL power monitoring enabled for {:?} CPU",
                        monitor.get_cpu_vendor()
                    );
                    Some(monitor)
                } else {
                    log::warn!("MSR-based RAPL not available, falling back to sysfs");
                    None
                }
            }
            Err(e) => {
                log::warn!("Failed to initialize RAPL monitor: {e}, falling back to sysfs");
                None
            }
        };

        Ok(Self {
            cpu_count,
            sysfs_power_path: "/sys/class/power_supply".to_string(),
            sysfs_cpufreq_path: "/sys/devices/system/cpu".to_string(),
            sysfs_thermal_path: "/sys/class/thermal".to_string(),
            sysfs_cpuidle_path: "/sys/devices/system/cpu".to_string(),
            rapl_monitor,
        })
    }

    fn detect_cpu_count() -> Result<u32> {
        let cpus_online = fs::read_to_string("/sys/devices/system/cpu/online")
            .map_err(|e| anyhow!("Failed to read CPU online info: {}", e))?;

        // Parse format like "0-7" or "0,2-7"
        let trimmed = cpus_online.trim();
        if let Some(dash_pos) = trimmed.rfind('-') {
            let max_cpu_str = &trimmed[dash_pos + 1..];
            let max_cpu: u32 = max_cpu_str
                .parse()
                .map_err(|e| anyhow!("Failed to parse max CPU number: {}", e))?;
            Ok(max_cpu + 1)
        } else {
            Err(anyhow!("Unexpected CPU online format: {}", trimmed))
        }
    }

    /// Collect current power data from the system
    pub fn collect(&mut self) -> Result<SystemPowerData> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut system_data = SystemPowerData {
            timestamp,
            ..Default::default()
        };

        // Collect per-core data
        for core_id in 0..self.cpu_count {
            if let Ok(core_data) = self.collect_core_data(core_id) {
                system_data.cores.insert(core_id, core_data);
            }
        }

        // Collect battery information
        if let Ok((battery_level, charging, remaining_time)) = self.collect_battery_info() {
            system_data.battery_level_percent = Some(battery_level);
            system_data.battery_charging = Some(charging);
            system_data.battery_remaining_time_minutes = remaining_time;
        }

        // Collect package power if available
        system_data.package_power = self.collect_package_power()?;

        // Calculate total power from package power (more accurate than core power sum)
        system_data.total_power_watts = if !system_data.package_power.is_empty() {
            system_data.package_power.values().sum()
        } else {
            // Fallback to core power sum if package power is not available
            system_data
                .cores
                .values()
                .map(|core| core.power_watts)
                .sum()
        };

        Ok(system_data)
    }

    fn collect_core_data(&self, core_id: u32) -> Result<CorePowerData> {
        let mut core_data = CorePowerData {
            core_id,
            ..Default::default()
        };

        // Get CPU frequency
        core_data.frequency_mhz = self.read_cpu_frequency(core_id)?;

        // Get CPU temperature
        core_data.temperature_celsius = self.read_cpu_temperature(core_id)?;

        // Only use actual RAPL power measurements, no estimates
        core_data.power_watts = 0.0;

        // Get C-state information
        core_data.c_states = self.read_c_states(core_id)?;

        // Get package ID
        core_data.package_id = self.get_package_id(core_id)?;

        // Enhance with comprehensive RAPL data if available
        if let Some(ref rapl_monitor) = self.rapl_monitor {
            if let Ok(rapl_reading) = rapl_monitor
                .msr_reader
                .read_rapl_energy(core_data.package_id)
            {
                // Populate TDP from RAPL power info
                core_data.tdp = rapl_reading.core_tdp.max(rapl_reading.package_tdp);

                // Populate power limits from RAPL
                core_data.power_limit = rapl_reading
                    .core_power_limit
                    .max(rapl_reading.package_power_limit);

                // Populate throttling information
                core_data.throttle_percent = rapl_reading
                    .core_throttled_pct
                    .max(rapl_reading.package_throttled_pct);

                // Store additional energy readings
                core_data.dram_energy_uj = rapl_reading.dram_energy_uj;
                core_data.gpu_energy_uj = rapl_reading.gpu_energy_uj;
                core_data.psys_energy_uj = rapl_reading.psys_energy_uj;
                core_data.l3_energy_uj = rapl_reading.l3_energy_uj;
            }
        }

        Ok(core_data)
    }

    fn read_cpu_frequency(&self, core_id: u32) -> Result<f64> {
        let freq_path = format!(
            "{}/cpu{core_id}/cpufreq/scaling_cur_freq",
            self.sysfs_cpufreq_path,
        );

        if !Path::new(&freq_path).exists() {
            // Fallback to cpuinfo_cur_freq
            let alt_path = format!(
                "{}/cpu{core_id}/cpufreq/cpuinfo_cur_freq",
                self.sysfs_cpufreq_path,
            );
            if Path::new(&alt_path).exists() {
                let freq_khz_str = fs::read_to_string(&alt_path)
                    .map_err(|e| anyhow!("Failed to read CPU frequency: {e}"))?;
                let freq_khz: f64 = freq_khz_str
                    .trim()
                    .parse()
                    .map_err(|e| anyhow!("Failed to parse CPU frequency: {e}"))?;
                return Ok(freq_khz / 1000.0); // Convert KHz to MHz
            }
            return Ok(0.0); // Default if frequency info not available
        }

        let freq_khz_str = fs::read_to_string(&freq_path)
            .map_err(|e| anyhow!("Failed to read CPU frequency: {e}"))?;
        let freq_khz: f64 = freq_khz_str
            .trim()
            .parse()
            .map_err(|e| anyhow!("Failed to parse CPU frequency: {e}"))?;

        Ok(freq_khz / 1000.0) // Convert KHz to MHz
    }

    fn read_cpu_temperature(&self, core_id: u32) -> Result<f64> {
        // Strategy 1: Try to find thermal zone for this specific CPU core
        for i in 0..20 {
            let thermal_path = format!("{}/thermal_zone{i}/type", self.sysfs_thermal_path);
            if let Ok(thermal_type) = fs::read_to_string(&thermal_path) {
                let thermal_type = thermal_type.trim().to_lowercase();
                if thermal_type.contains("cpu")
                    || thermal_type.contains(&format!("core {core_id}"))
                    || thermal_type.contains(&format!("core{core_id}"))
                    || thermal_type.contains("x86_pkg_temp")
                    || thermal_type.contains("coretemp")
                {
                    let temp_path = format!("{}/thermal_zone{i}/temp", self.sysfs_thermal_path);
                    if let Ok(temp_str) = fs::read_to_string(&temp_path) {
                        if let Ok(temp_millicelsius) = temp_str.trim().parse::<f64>() {
                            let temp_celsius = temp_millicelsius / 1000.0;
                            // Sanity check: reasonable CPU temperature range
                            if (0.0..=150.0).contains(&temp_celsius) {
                                return Ok(temp_celsius);
                            }
                        }
                    }
                }
            }
        }

        // Strategy 2: Try coretemp hwmon interface (multiple possible paths)
        let hwmon_paths = [
            format!(
                "/sys/devices/platform/coretemp.0/hwmon/hwmon0/temp{}_input",
                core_id + 2
            ),
            format!(
                "/sys/devices/platform/coretemp.0/hwmon/hwmon1/temp{}_input",
                core_id + 2
            ),
            format!(
                "/sys/devices/platform/coretemp.0/hwmon/hwmon2/temp{}_input",
                core_id + 2
            ),
            format!(
                "/sys/devices/platform/coretemp.0/hwmon/hwmon3/temp{}_input",
                core_id + 2
            ),
            format!("/sys/class/hwmon/hwmon0/temp{}_input", core_id + 2),
            format!("/sys/class/hwmon/hwmon1/temp{}_input", core_id + 2),
            format!("/sys/class/hwmon/hwmon2/temp{}_input", core_id + 2),
            format!("/sys/class/hwmon/hwmon3/temp{}_input", core_id + 2),
        ];

        for path in &hwmon_paths {
            if let Ok(temp_str) = fs::read_to_string(path) {
                if let Ok(temp_millicelsius) = temp_str.trim().parse::<f64>() {
                    let temp_celsius = temp_millicelsius / 1000.0;
                    if (0.0..=150.0).contains(&temp_celsius) {
                        return Ok(temp_celsius);
                    }
                }
            }
        }

        // Strategy 3: Try per-core temperature from coretemp with different numbering schemes
        let alt_core_paths = [
            format!("/sys/devices/platform/coretemp.0/temp{}_input", core_id + 1),
            format!("/sys/devices/platform/coretemp.0/temp{}_input", core_id + 2),
            format!("/sys/devices/platform/coretemp.0/temp{core_id}_input"),
        ];

        for path in &alt_core_paths {
            if let Ok(temp_str) = fs::read_to_string(path) {
                if let Ok(temp_millicelsius) = temp_str.trim().parse::<f64>() {
                    let temp_celsius = temp_millicelsius / 1000.0;
                    if (0.0..=150.0).contains(&temp_celsius) {
                        return Ok(temp_celsius);
                    }
                }
            }
        }

        // Strategy 4: Try CPU package temperature (shared across cores in package)
        let package_id = self.get_package_id(core_id).unwrap_or(0);
        let package_temp_paths = [
            format!("/sys/devices/platform/coretemp.{package_id}/temp1_input"),
            format!(
                "/sys/devices/platform/coretemp.{package_id}/hwmon/hwmon{package_id}/temp1_input"
            ),
            "/sys/devices/platform/coretemp.0/temp1_input".to_string(),
            "/sys/class/hwmon/hwmon0/temp1_input".to_string(),
            "/sys/class/hwmon/hwmon1/temp1_input".to_string(),
        ];

        for path in &package_temp_paths {
            if let Ok(temp_str) = fs::read_to_string(path) {
                if let Ok(temp_millicelsius) = temp_str.trim().parse::<f64>() {
                    let temp_celsius = temp_millicelsius / 1000.0;
                    if (0.0..=150.0).contains(&temp_celsius) {
                        return Ok(temp_celsius);
                    }
                }
            }
        }

        // Strategy 5: Try to auto-discover available hwmon devices
        if let Ok(hwmon_dir) = fs::read_dir("/sys/class/hwmon") {
            for entry in hwmon_dir.flatten() {
                let hwmon_path = entry.path();

                // Check if this hwmon device is for CPU temperature
                let name_path = hwmon_path.join("name");
                if let Ok(name) = fs::read_to_string(&name_path) {
                    let name = name.trim().to_lowercase();
                    if name.contains("coretemp") || name.contains("cpu") || name.contains("k10temp")
                    {
                        // Try various temp inputs for this hwmon device
                        for temp_input in 1..=10 {
                            let temp_path = hwmon_path.join(format!("temp{temp_input}_input"));
                            if let Ok(temp_str) = fs::read_to_string(&temp_path) {
                                if let Ok(temp_millicelsius) = temp_str.trim().parse::<f64>() {
                                    let temp_celsius = temp_millicelsius / 1000.0;
                                    if (0.0..=150.0).contains(&temp_celsius) {
                                        return Ok(temp_celsius);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If all strategies fail, return 0 (will be handled by the display logic)
        Ok(0.0)
    }

    fn read_c_states(&self, core_id: u32) -> Result<HashMap<String, CStateInfo>> {
        let mut c_states = HashMap::new();
        let cpuidle_path = format!("{}/cpu{core_id}/cpuidle", self.sysfs_cpuidle_path);

        if !Path::new(&cpuidle_path).exists() {
            return Ok(c_states);
        }

        // Read available C-states
        for i in 0..10 {
            // Check up to 10 C-states
            let state_path = format!("{cpuidle_path}/state{i}");
            if !Path::new(&state_path).exists() {
                break;
            }

            let name_path = format!("{state_path}/name");
            let latency_path = format!("{state_path}/latency");
            let usage_path = format!("{state_path}/usage");
            let time_path = format!("{state_path}/time");

            if let (Ok(name), Ok(latency_str), Ok(usage_str), Ok(time_str)) = (
                fs::read_to_string(&name_path),
                fs::read_to_string(&latency_path),
                fs::read_to_string(&usage_path),
                fs::read_to_string(&time_path),
            ) {
                let name = name.trim().to_string();
                let latency: u64 = latency_str.trim().parse().unwrap_or(0);
                let usage: u64 = usage_str.trim().parse().unwrap_or(0);
                let residency: u64 = time_str.trim().parse().unwrap_or(0);

                c_states.insert(
                    name.clone(),
                    CStateInfo {
                        name,
                        latency,
                        residency,
                        usage,
                    },
                );
            }
        }

        Ok(c_states)
    }

    fn get_package_id(&self, core_id: u32) -> Result<u32> {
        let topology_path =
            format!("/sys/devices/system/cpu/cpu{core_id}/topology/physical_package_id");
        if let Ok(package_str) = fs::read_to_string(&topology_path) {
            return Ok(package_str.trim().parse().unwrap_or(0));
        }
        Ok(0) // Default to package 0
    }

    fn collect_battery_info(&self) -> Result<(f64, bool, Option<u32>)> {
        let power_supply_dir = Path::new(&self.sysfs_power_path);
        if !power_supply_dir.exists() {
            return Err(anyhow!("Power supply directory not found"));
        }

        // Look for battery
        for entry in fs::read_dir(power_supply_dir)? {
            let entry = entry?;
            let supply_path = entry.path();

            // Check if this is a battery
            let type_path = supply_path.join("type");
            if let Ok(supply_type) = fs::read_to_string(&type_path) {
                if supply_type.trim() == "Battery" {
                    // Read battery information
                    let capacity_path = supply_path.join("capacity");
                    let status_path = supply_path.join("status");
                    let time_to_empty_path = supply_path.join("time_to_empty_now");

                    let capacity = if let Ok(cap_str) = fs::read_to_string(&capacity_path) {
                        cap_str.trim().parse::<f64>().unwrap_or(0.0)
                    } else {
                        0.0
                    };

                    let charging = if let Ok(status_str) = fs::read_to_string(&status_path) {
                        status_str.trim() == "Charging"
                    } else {
                        false
                    };

                    let remaining_time =
                        if let Ok(time_str) = fs::read_to_string(&time_to_empty_path) {
                            time_str.trim().parse::<u32>().ok().map(|s| s / 60) // Convert seconds to minutes
                        } else {
                            None
                        };

                    return Ok((capacity, charging, remaining_time));
                }
            }
        }

        Err(anyhow!("No battery found"))
    }

    fn collect_package_power(&mut self) -> Result<HashMap<u32, f64>> {
        // Priority 1: Try MSR-based RAPL if available
        if let Some(ref mut rapl_monitor) = self.rapl_monitor {
            if let Ok(msr_power_data) = rapl_monitor.collect_power_data() {
                if !msr_power_data.is_empty() {
                    return Ok(msr_power_data);
                }
            }
        }

        // Priority 2: Fallback to sysfs-based RAPL data
        let mut package_power = HashMap::new();

        let intel_rapl_path = "/sys/class/powercap/intel-rapl";
        if Path::new(intel_rapl_path).exists() {
            for entry in fs::read_dir(intel_rapl_path)? {
                let entry = entry?;
                let package_path = entry.path();
                let package_name = package_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");

                if package_name.starts_with("intel-rapl:") {
                    let energy_path = package_path.join("energy_uj");
                    let name_path = package_path.join("name");

                    if let (Ok(energy_str), Ok(name_str)) = (
                        fs::read_to_string(&energy_path),
                        fs::read_to_string(&name_path),
                    ) {
                        if name_str.trim().starts_with("package-") {
                            if let Ok(energy_uj) = energy_str.trim().parse::<u64>() {
                                // Extract package number from the path
                                let package_id = package_name
                                    .chars()
                                    .last()
                                    .and_then(|c| c.to_digit(10))
                                    .unwrap_or(0);

                                // Convert microjoules to watts (approximate based on sampling interval)
                                // This is a simplified calculation - real implementation would track
                                // energy changes over time
                                let power_watts = energy_uj as f64 / 1_000_000.0; // Convert to joules
                                package_power.insert(package_id, power_watts);
                            }
                        }
                    }
                }
            }
        }

        Ok(package_power)
    }
}

impl Default for PowerDataCollector {
    fn default() -> Self {
        Self::new().unwrap_or(Self {
            cpu_count: 1,
            sysfs_power_path: "/sys/class/power_supply".to_string(),
            sysfs_cpufreq_path: "/sys/devices/system/cpu".to_string(),
            sysfs_thermal_path: "/sys/class/thermal".to_string(),
            sysfs_cpuidle_path: "/sys/devices/system/cpu".to_string(),
            rapl_monitor: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_snapshot_update() {
        let mut snapshot = PowerSnapshot::new();
        let data = SystemPowerData {
            timestamp: 1000,
            total_power_watts: 50.0,
            ..Default::default()
        };

        snapshot.update(data.clone());
        assert_eq!(snapshot.current.timestamp, 1000);
        assert_eq!(snapshot.current.total_power_watts, 50.0);

        let data2 = SystemPowerData {
            timestamp: 2000,
            total_power_watts: 60.0,
            ..Default::default()
        };

        snapshot.update(data2);
        assert_eq!(snapshot.current.timestamp, 2000);
        assert_eq!(snapshot.current.total_power_watts, 60.0);
        assert!(snapshot.previous.is_some());
        assert_eq!(snapshot.previous.as_ref().unwrap().total_power_watts, 50.0);
    }

    #[test]
    fn test_c_state_info() {
        let c_state = CStateInfo {
            name: "C1".to_string(),
            latency: 10,
            residency: 1000,
            usage: 50,
        };

        assert_eq!(c_state.name, "C1");
        assert_eq!(c_state.latency, 10);
        assert_eq!(c_state.residency, 1000);
        assert_eq!(c_state.usage, 50);
    }
}
