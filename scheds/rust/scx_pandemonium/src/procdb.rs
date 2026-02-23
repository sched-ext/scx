// PANDEMONIUM PROCESS CLASSIFICATION DATABASE
// BPF OBSERVES MATURE TASK BEHAVIOR, RUST LEARNS PATTERNS, BPF APPLIES
//
// PROBLEM: EVERY NEW TASK ENTERS AS TIER_INTERACTIVE IN BPF enable().
// SHORT-LIVED PROCESSES (cc1, as, ld DURING COMPILATION) NEVER SURVIVE
// LONG ENOUGH TO GET RECLASSIFIED. HUNDREDS OF MISCLASSIFIED TASKS PER
// SECOND DURING make -j12, EACH FIRING PREEMPT KICKS AND GETTING SHORT
// INTERACTIVE SLICES.
//
// SOLUTION: BPF WRITES OBSERVATIONS TO AN LRU MAP WHEN A TASK'S EWMA
// MATURES (ewma_age == 8). RUST DRAINS OBSERVATIONS EVERY SECOND,
// MERGES INTO A HASHMAP WITH EWMA DECAY, AND WRITES CONFIDENT
// PREDICTIONS BACK TO A BPF HASH MAP. NEW TASKS WITH MATCHING comm
// START WITH THE CORRECT TIER AND avg_runtime FROM enable().

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use libbpf_rs::MapCore;

fn _timestamp() -> String {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!("[{:02}:{:02}:{:02}]", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

macro_rules! procdb_info {
    ($($arg:tt)*) => { println!("{} [INFO]   {}", _timestamp(), format!($($arg)*)) };
}
macro_rules! procdb_warn {
    ($($arg:tt)*) => { println!("{} [WARN]   {}", _timestamp(), format!($($arg)*)) };
}

const OBSERVE_PIN: &str = "/sys/fs/bpf/pandemonium/task_class_observe";
const INIT_PIN: &str = "/sys/fs/bpf/pandemonium/task_class_init";

pub const MIN_OBSERVATIONS: u32 = 3;
pub const MIN_CONFIDENCE: f64 = 0.6;
pub const MAX_PROFILES: usize = 512;
pub const STALE_TICKS: u64 = 60;

const PROCDB_MAGIC: &[u8; 4] = b"PDDB";
const PROCDB_VERSION: u32 = 2;
const PROCDB_PATH: &str = ".cache/pandemonium/procdb.bin";
const ENTRY_SIZE: usize = 64;
const V1_ENTRY_SIZE: usize = 40;

// MATCHES struct task_class_entry IN intf.h
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskClassEntry {
    pub tier: u8,
    pub _pad: [u8; 7],
    pub avg_runtime: u64,
    pub runtime_dev: u64,
    pub wakeup_freq: u64,
    pub csw_rate: u64,
}

// COMPILE-TIME ABI SAFETY: MUST MATCH struct task_class_entry IN intf.h
const _: () = assert!(std::mem::size_of::<TaskClassEntry>() == 40);

#[derive(Default)]
pub struct TaskProfile {
    pub tier_votes: [u32; 3], // COUNT PER TIER: [BATCH, INTERACTIVE, LAT_CRITICAL]
    pub avg_runtime_ns: u64,
    pub runtime_dev_ns: u64,
    pub wakeup_freq: u64,
    pub csw_rate: u64,
    pub observations: u32,
    pub last_seen_tick: u64,
}

impl TaskProfile {
    pub fn confidence(&self) -> f64 {
        let total: u32 = self.tier_votes.iter().sum();
        if total == 0 {
            return 0.0;
        }
        let max_count = *self.tier_votes.iter().max().unwrap_or(&0);
        max_count as f64 / total as f64
    }

    pub fn dominant_tier(&self) -> u8 {
        self.tier_votes
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| *c)
            .map(|(i, _)| i as u8)
            .unwrap_or(1) // INTERACTIVE DEFAULT
    }

    // MULTI-DIMENSIONAL CONFIDENCE: TIER AGREEMENT * BEHAVIORAL STABILITY
    // HIGH RUNTIME VARIANCE REDUCES CONFIDENCE EVEN WITH STRONG TIER AGREEMENT
    pub fn behavioral_confidence(&self) -> f64 {
        if self.observations < MIN_OBSERVATIONS {
            return 0.0;
        }
        let tier_conf = self.confidence();
        let dev_ratio = if self.avg_runtime_ns > 0 {
            self.runtime_dev_ns as f64 / self.avg_runtime_ns as f64
        } else {
            1.0
        };
        let stability = (1.0 - dev_ratio.min(1.0)).max(0.0);
        tier_conf * (0.5 + 0.5 * stability)
    }
}

pub struct ProcessDb {
    pub observe: Option<libbpf_rs::MapHandle>,
    pub init: Option<libbpf_rs::MapHandle>,
    pub profiles: HashMap<[u8; 16], TaskProfile>,
    pub tick: u64,
}

impl ProcessDb {
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        PathBuf::from(home).join(PROCDB_PATH)
    }

    pub fn new() -> Result<Self> {
        let observe = libbpf_rs::MapHandle::from_pinned_path(OBSERVE_PIN)?;
        let init = libbpf_rs::MapHandle::from_pinned_path(INIT_PIN)?;

        let db_path = Self::default_path();
        let profiles = match Self::load_from_disk(&db_path) {
            Ok(p) => {
                if !p.is_empty() {
                    procdb_info!(
                        "PROCDB: LOADED {} PROFILES FROM {}",
                        p.len(),
                        db_path.display()
                    );
                }
                p
            }
            Err(e) => {
                procdb_warn!("PROCDB LOAD: {}", e);
                HashMap::new()
            }
        };

        let db = Self {
            observe: Some(observe),
            init: Some(init),
            profiles,
            tick: 0,
        };

        db.flush_predictions();
        Ok(db)
    }

    // DRAIN OBSERVATIONS FROM BPF LRU MAP, MERGE INTO PROFILES
    pub fn ingest(&mut self) {
        let observe = match &self.observe {
            Some(m) => m,
            None => return,
        };
        let keys: Vec<Vec<u8>> = observe.keys().collect();
        for key in &keys {
            if let Ok(Some(val)) = observe.lookup(key, libbpf_rs::MapFlags::ANY) {
                if val.len() >= std::mem::size_of::<TaskClassEntry>() {
                    let entry: TaskClassEntry =
                        unsafe { std::ptr::read_unaligned(val.as_ptr() as *const TaskClassEntry) };

                    let mut comm = [0u8; 16];
                    let copy_len = key.len().min(16);
                    comm[..copy_len].copy_from_slice(&key[..copy_len]);

                    let profile = self.profiles.entry(comm).or_insert(TaskProfile {
                        ..Default::default()
                    });

                    let tier_idx = (entry.tier as usize).min(2);
                    profile.tier_votes[tier_idx] += 1;
                    if profile.observations == 0 {
                        profile.avg_runtime_ns = entry.avg_runtime;
                        profile.runtime_dev_ns = entry.runtime_dev;
                        profile.wakeup_freq = entry.wakeup_freq;
                        profile.csw_rate = entry.csw_rate;
                    } else {
                        // EWMA: 7/8 OLD + 1/8 NEW
                        profile.avg_runtime_ns =
                            (profile.avg_runtime_ns * 7 + entry.avg_runtime) / 8;
                        profile.runtime_dev_ns =
                            (profile.runtime_dev_ns * 7 + entry.runtime_dev) / 8;
                        profile.wakeup_freq = (profile.wakeup_freq * 7 + entry.wakeup_freq) / 8;
                        profile.csw_rate = (profile.csw_rate * 7 + entry.csw_rate) / 8;
                    }
                    profile.observations += 1;
                    profile.last_seen_tick = self.tick;
                }
            }
            let _ = observe.delete(key);
        }
    }

    // WRITE CONFIDENT PREDICTIONS TO BPF INIT MAP
    pub fn flush_predictions(&self) {
        let init = match &self.init {
            Some(m) => m,
            None => return,
        };
        for (comm, profile) in &self.profiles {
            if profile.behavioral_confidence() >= MIN_CONFIDENCE {
                let entry = TaskClassEntry {
                    tier: profile.dominant_tier(),
                    _pad: [0; 7],
                    avg_runtime: profile.avg_runtime_ns,
                    runtime_dev: profile.runtime_dev_ns,
                    wakeup_freq: profile.wakeup_freq,
                    csw_rate: profile.csw_rate,
                };

                let val = unsafe {
                    std::slice::from_raw_parts(
                        &entry as *const TaskClassEntry as *const u8,
                        std::mem::size_of::<TaskClassEntry>(),
                    )
                };
                let _ = init.update(comm.as_slice(), val, libbpf_rs::MapFlags::ANY);
            }
        }
    }

    // EVICT STALE PROFILES, CAP TOTAL ENTRIES
    pub fn tick(&mut self) {
        self.tick += 1;

        // REMOVE PROFILES NOT SEEN IN 60 SECONDS
        let tick = self.tick;
        let stale: Vec<[u8; 16]> = self
            .profiles
            .iter()
            .filter(|(_, p)| tick - p.last_seen_tick > STALE_TICKS)
            .map(|(k, _)| *k)
            .collect();
        for comm in &stale {
            self.profiles.remove(comm);
            if let Some(ref init) = self.init {
                let _ = init.delete(comm.as_slice());
            }
        }

        // CAP ENTRIES: EVICT OLDEST FIRST, TIE-BREAK BY OBSERVATIONS THEN COMM
        if self.profiles.len() > MAX_PROFILES {
            let mut entries: Vec<([u8; 16], u64, u32)> = self
                .profiles
                .iter()
                .map(|(k, v)| (*k, v.last_seen_tick, v.observations))
                .collect();
            entries.sort_by(|a, b| (a.1, a.2, a.0).cmp(&(b.1, b.2, b.0)));
            let to_remove = self.profiles.len() - MAX_PROFILES;
            for (k, _, _) in entries.into_iter().take(to_remove) {
                self.profiles.remove(&k);
                if let Some(ref init) = self.init {
                    let _ = init.delete(k.as_slice());
                }
            }
        }
    }

    // (TOTAL PROFILES, CONFIDENT PROFILES)
    pub fn summary(&self) -> (usize, usize) {
        let total = self.profiles.len();
        let confident = self
            .profiles
            .values()
            .filter(|p| p.behavioral_confidence() >= MIN_CONFIDENCE)
            .count();
        (total, confident)
    }

    // SERIALIZE CONFIDENT PROFILES TO DISK (ATOMIC WRITE)
    pub fn save(&self, path: &Path) -> Result<()> {
        let entries: Vec<_> = self
            .profiles
            .iter()
            .filter(|(_, p)| p.behavioral_confidence() >= MIN_CONFIDENCE)
            .collect();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("bin.tmp");
        let mut f = std::fs::File::create(&tmp_path)?;

        // HEADER: MAGIC + VERSION + COUNT
        f.write_all(PROCDB_MAGIC)?;
        f.write_all(&PROCDB_VERSION.to_le_bytes())?;
        f.write_all(&(entries.len() as u32).to_le_bytes())?;

        // ENTRIES: 64 BYTES EACH (V2)
        for (comm, profile) in &entries {
            let tier = profile.dominant_tier();
            let total_votes: u32 = profile.tier_votes.iter().sum();

            f.write_all(comm.as_slice())?; // 16 bytes
            f.write_all(&[tier])?; // 1 byte
            f.write_all(&[0u8; 7])?; // 7 bytes pad
            f.write_all(&profile.avg_runtime_ns.to_le_bytes())?; // 8 bytes
            f.write_all(&profile.runtime_dev_ns.to_le_bytes())?; // 8 bytes
            f.write_all(&profile.wakeup_freq.to_le_bytes())?; // 8 bytes
            f.write_all(&profile.csw_rate.to_le_bytes())?; // 8 bytes
            f.write_all(&profile.observations.to_le_bytes())?; // 4 bytes
            f.write_all(&total_votes.to_le_bytes())?; // 4 bytes
        }

        drop(f);
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    // DESERIALIZE PROFILES FROM DISK (RETURNS EMPTY ON CORRUPTION)
    pub fn load_from_disk(path: &Path) -> Result<HashMap<[u8; 16], TaskProfile>> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HashMap::new());
            }
            Err(e) => return Err(e.into()),
        };

        if data.len() < 12 {
            procdb_warn!("PROCDB: FILE TOO SHORT ({} BYTES)", data.len());
            return Ok(HashMap::new());
        }

        // VALIDATE MAGIC
        if &data[0..4] != PROCDB_MAGIC {
            procdb_warn!("PROCDB: BAD MAGIC {:?}", &data[0..4]);
            return Ok(HashMap::new());
        }

        // VALIDATE VERSION
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let entry_size = match version {
            1 => V1_ENTRY_SIZE,
            2 => ENTRY_SIZE,
            _ => {
                procdb_warn!("PROCDB: UNKNOWN VERSION {}", version);
                return Ok(HashMap::new());
            }
        };

        // VALIDATE COUNT VS FILE SIZE
        let count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let expected_size = 12 + count * entry_size;
        if data.len() < expected_size {
            procdb_warn!(
                "PROCDB: TRUNCATED (EXPECTED {} BYTES, GOT {})",
                expected_size,
                data.len()
            );
            return Ok(HashMap::new());
        }

        let mut profiles = HashMap::new();
        let mut offset = 12;

        for _ in 0..count {
            let mut comm = [0u8; 16];
            comm.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;

            let tier = data[offset] as usize;
            offset += 8; // tier + 7 pad

            let avg_runtime = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;

            // V2: READ EXTRA BEHAVIORAL FIELDS
            let (runtime_dev, wakeup_freq, csw_rate) = if version >= 2 {
                let rd = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let wf = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let cr = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                offset += 8;
                (rd, wf, cr)
            } else {
                (0, 0, 0)
            };

            let observations = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let total_votes = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;

            // RECONSTRUCT: ALL VOTES GO TO DOMINANT TIER (CONFIDENCE = 1.0)
            let mut tier_votes = [0u32; 3];
            tier_votes[tier.min(2)] = total_votes;

            profiles.insert(
                comm,
                TaskProfile {
                    tier_votes,
                    avg_runtime_ns: avg_runtime,
                    runtime_dev_ns: runtime_dev,
                    wakeup_freq,
                    csw_rate,
                    observations,
                    last_seen_tick: 0,
                },
            );
        }

        Ok(profiles)
    }
}
