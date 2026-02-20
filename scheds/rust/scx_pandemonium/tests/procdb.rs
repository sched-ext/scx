use std::collections::HashMap;

use pandemonium::procdb::{
    ProcessDb, TaskProfile, TaskClassEntry,
    MIN_CONFIDENCE, MIN_OBSERVATIONS, MAX_PROFILES, STALE_TICKS,
};

fn offline_db() -> ProcessDb {
    ProcessDb {
        observe: None,
        init: None,
        profiles: HashMap::new(),
        tick: 0,
    }
}

#[test]
fn profile_confidence_unanimous() {
    let p = TaskProfile {
        tier_votes: [5, 0, 0],
        avg_runtime_ns: 100000,
        observations: 5,
        ..Default::default()
    };
    assert_eq!(p.confidence(), 1.0);
    assert_eq!(p.dominant_tier(), 0); // BATCH
}

#[test]
fn profile_confidence_majority() {
    let p = TaskProfile {
        tier_votes: [3, 2, 0],
        avg_runtime_ns: 100000,
        observations: 5,
        ..Default::default()
    };
    assert_eq!(p.confidence(), 0.6);
    assert_eq!(p.dominant_tier(), 0); // BATCH WINS 3:2
}

#[test]
fn profile_confidence_below_threshold() {
    let p = TaskProfile {
        tier_votes: [2, 2, 1],
        avg_runtime_ns: 100000,
        observations: 5,
        ..Default::default()
    };
    // 2/5 = 0.4, BELOW MIN_CONFIDENCE OF 0.6
    assert!(p.confidence() < MIN_CONFIDENCE);
}

#[test]
fn profile_dominant_tier_lat_critical() {
    let p = TaskProfile {
        tier_votes: [1, 1, 5],
        avg_runtime_ns: 50000,
        observations: 7,
        ..Default::default()
    };
    assert_eq!(p.dominant_tier(), 2); // LAT_CRITICAL
}

#[test]
fn profile_confidence_zero_votes() {
    let p = TaskProfile {
        tier_votes: [0, 0, 0],
        avg_runtime_ns: 0,
        observations: 0,
        ..Default::default()
    };
    assert_eq!(p.confidence(), 0.0);
}

#[test]
fn task_class_entry_layout() {
    // VERIFY RUST STRUCT MATCHES BPF: 1 + 7 + 8 + 8 + 8 + 8 = 40 BYTES
    assert_eq!(std::mem::size_of::<TaskClassEntry>(), 40);
}

// PROCESSDB TESTS

fn make_comm(name: &[u8]) -> [u8; 16] {
    let mut comm = [0u8; 16];
    let len = name.len().min(16);
    comm[..len].copy_from_slice(&name[..len]);
    comm
}

fn confident_profile(last_seen_tick: u64) -> TaskProfile {
    TaskProfile {
        tier_votes: [5, 0, 0],
        avg_runtime_ns: 100000,
        observations: MIN_OBSERVATIONS,
        last_seen_tick,
        ..Default::default()
    }
}

#[test]
fn tick_evicts_stale_profiles() {
    let mut db = offline_db();
    let comm = make_comm(b"stale_task");
    db.profiles.insert(comm, confident_profile(0));

    for _ in 0..=STALE_TICKS {
        db.tick();
    }

    assert!(db.profiles.get(&comm).is_none());
}

#[test]
fn tick_preserves_fresh_profiles() {
    let mut db = offline_db();
    db.tick = 55;
    let comm = make_comm(b"fresh_task");
    db.profiles.insert(comm, confident_profile(55));

    db.tick();
    assert!(db.profiles.get(&comm).is_some());
}

#[test]
fn tick_caps_at_max_profiles() {
    let mut db = offline_db();
    let tick = 100000u64;
    db.tick = tick;

    // INSERT MAX_PROFILES ENTRIES, ALL AT CURRENT TICK (FRESH)
    for i in 1..=(MAX_PROFILES as u64) {
        let mut comm = [0u8; 16];
        comm[0..8].copy_from_slice(&i.to_le_bytes());
        db.profiles.insert(comm, TaskProfile {
            tier_votes: [5, 0, 0],
            avg_runtime_ns: 100000,
            observations: MIN_OBSERVATIONS,
            last_seen_tick: tick,
            ..Default::default()
        });
    }

    // INSERT ONE MORE ENTRY WITH SLIGHTLY OLDER TIMESTAMP (STILL FRESH)
    let oldest_comm = make_comm(b"oldest_entry");
    db.profiles.insert(oldest_comm, TaskProfile {
        tier_votes: [5, 0, 0],
        avg_runtime_ns: 100000,
        observations: MIN_OBSERVATIONS,
        last_seen_tick: tick - 10,
        ..Default::default()
    });

    assert_eq!(db.profiles.len(), MAX_PROFILES + 1);
    db.tick();
    assert!(db.profiles.len() <= MAX_PROFILES);

    // THE OLDEST ENTRY SHOULD BE EVICTED BY CAP ENFORCEMENT
    assert!(db.profiles.get(&oldest_comm).is_none());
}

#[test]
fn summary_counts_confident() {
    let mut db = offline_db();

    // TWO CONFIDENT PROFILES
    db.profiles.insert(make_comm(b"gcc"), confident_profile(0));
    db.profiles.insert(make_comm(b"ld"), confident_profile(0));

    // ONE NON-CONFIDENT: TOO FEW OBSERVATIONS
    db.profiles.insert(make_comm(b"new_task"), TaskProfile {
        tier_votes: [1, 0, 0],
        avg_runtime_ns: 50000,
        observations: 1,
        ..Default::default()
    });

    let (total, confident) = db.summary();
    assert_eq!(total, 3);
    assert_eq!(confident, 2);
}

#[test]
fn summary_empty_db() {
    let db = offline_db();
    assert_eq!(db.summary(), (0, 0));
}

// PERSISTENCE TESTS

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("pandemonium-test");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn save_load_round_trip() {
    let path = tmp_path("round_trip.bin");
    let _ = std::fs::remove_file(&path);

    let mut db = offline_db();
    db.profiles.insert(make_comm(b"gcc"), TaskProfile {
        tier_votes: [10, 0, 0],
        avg_runtime_ns: 2500000,
        runtime_dev_ns: 500000,
        wakeup_freq: 5,
        csw_rate: 10,
        observations: 10,
        last_seen_tick: 50,
    });
    db.profiles.insert(make_comm(b"kwin"), TaskProfile {
        tier_votes: [0, 0, 8],
        avg_runtime_ns: 50000,
        runtime_dev_ns: 5000,
        wakeup_freq: 40,
        csw_rate: 200,
        observations: 8,
        last_seen_tick: 50,
    });
    db.save(&path).unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert_eq!(loaded.len(), 2);

    let gcc = &loaded[&make_comm(b"gcc")];
    assert_eq!(gcc.dominant_tier(), 0); // BATCH
    assert_eq!(gcc.avg_runtime_ns, 2500000);
    assert_eq!(gcc.runtime_dev_ns, 500000);
    assert_eq!(gcc.wakeup_freq, 5);
    assert_eq!(gcc.csw_rate, 10);
    assert_eq!(gcc.observations, 10);
    assert_eq!(gcc.last_seen_tick, 0); // RESET ON LOAD

    let kwin = &loaded[&make_comm(b"kwin")];
    assert_eq!(kwin.dominant_tier(), 2); // LAT_CRITICAL
    assert_eq!(kwin.avg_runtime_ns, 50000);
    assert_eq!(kwin.runtime_dev_ns, 5000);
    assert_eq!(kwin.wakeup_freq, 40);
    assert_eq!(kwin.csw_rate, 200);
    assert_eq!(kwin.last_seen_tick, 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn save_load_empty() {
    let path = tmp_path("empty.bin");
    let _ = std::fs::remove_file(&path);

    let db = offline_db();
    db.save(&path).unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert!(loaded.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn save_skips_non_confident_profiles() {
    let path = tmp_path("skip_non_confident.bin");
    let _ = std::fs::remove_file(&path);

    let mut db = offline_db();
    // CONFIDENT
    db.profiles.insert(make_comm(b"gcc"), confident_profile(0));
    // NOT CONFIDENT: TOO FEW OBSERVATIONS
    db.profiles.insert(make_comm(b"new"), TaskProfile {
        tier_votes: [1, 0, 0],
        avg_runtime_ns: 50000,
        observations: 1,
        ..Default::default()
    });

    db.save(&path).unwrap();
    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.contains_key(&make_comm(b"gcc")));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_bad_magic() {
    let path = tmp_path("bad_magic.bin");
    std::fs::write(&path, b"BADMxxxxxx\x00\x00").unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert!(loaded.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_bad_version() {
    let path = tmp_path("bad_version.bin");
    let mut data = Vec::new();
    data.extend_from_slice(b"PDDB");
    data.extend_from_slice(&99u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    std::fs::write(&path, &data).unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert!(loaded.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_truncated() {
    let path = tmp_path("truncated.bin");
    let mut data = Vec::new();
    data.extend_from_slice(b"PDDB");
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes()); // CLAIMS 2 ENTRIES
    data.extend_from_slice(&[0u8; 20]); // ONLY HALF AN ENTRY
    std::fs::write(&path, &data).unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert!(loaded.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_file_not_found() {
    let path = tmp_path("nonexistent_file_xyz.bin");
    let _ = std::fs::remove_file(&path);

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn loaded_profiles_age_out() {
    let path = tmp_path("age_out.bin");
    let _ = std::fs::remove_file(&path);

    let mut db = offline_db();
    db.profiles.insert(make_comm(b"gcc"), confident_profile(0));
    db.save(&path).unwrap();

    // LOAD INTO FRESH DB -- PROFILES GET LAST_SEEN_TICK=0
    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    let mut db2 = ProcessDb {
        observe: None,
        init: None,
        profiles: loaded,
        tick: 0,
    };

    // TICK 61 TIMES -- PROFILE SHOULD BE EVICTED
    for _ in 0..=STALE_TICKS {
        db2.tick();
    }
    assert!(db2.profiles.get(&make_comm(b"gcc")).is_none());

    let _ = std::fs::remove_file(&path);
}

// DETERMINISTIC EVICTION TESTS

#[test]
fn eviction_oldest_first() {
    let mut db = offline_db();
    let tick = 100000u64;
    db.tick = tick;

    // FILL TO MAX_PROFILES WITH LAST_SEEN_TICK = TICK
    for i in 0..(MAX_PROFILES as u64) {
        let mut comm = [0u8; 16];
        comm[0..8].copy_from_slice(&(i + 1).to_le_bytes());
        db.profiles.insert(comm, TaskProfile {
            tier_votes: [5, 0, 0],
            avg_runtime_ns: 100000,
            observations: MIN_OBSERVATIONS,
            last_seen_tick: tick,
            ..Default::default()
        });
    }

    // INSERT ONE MORE WITH OLDER TIMESTAMP
    let victim = make_comm(b"victim");
    db.profiles.insert(victim, TaskProfile {
        tier_votes: [5, 0, 0],
        avg_runtime_ns: 100000,
        observations: MIN_OBSERVATIONS,
        last_seen_tick: tick - 5,
        ..Default::default()
    });

    assert_eq!(db.profiles.len(), MAX_PROFILES + 1);
    db.tick();
    assert_eq!(db.profiles.len(), MAX_PROFILES);
    assert!(db.profiles.get(&victim).is_none());
}

#[test]
fn eviction_tie_break_by_observations() {
    let mut db = offline_db();
    let tick = 100000u64;
    db.tick = tick;

    // FILL TO MAX_PROFILES WITH SAME TIMESTAMP, HIGH OBSERVATIONS
    for i in 0..(MAX_PROFILES as u64) {
        let mut comm = [0u8; 16];
        comm[0..8].copy_from_slice(&(i + 1).to_le_bytes());
        db.profiles.insert(comm, TaskProfile {
            tier_votes: [10, 0, 0],
            avg_runtime_ns: 100000,
            observations: 10,
            last_seen_tick: tick - 5,
            ..Default::default()
        });
    }

    // INSERT ONE MORE WITH SAME TIMESTAMP BUT FEWER OBSERVATIONS
    let victim = make_comm(b"low_obs");
    db.profiles.insert(victim, TaskProfile {
        tier_votes: [3, 0, 0],
        avg_runtime_ns: 100000,
        observations: 3,
        last_seen_tick: tick - 5,
        ..Default::default()
    });

    assert_eq!(db.profiles.len(), MAX_PROFILES + 1);
    db.tick();
    assert_eq!(db.profiles.len(), MAX_PROFILES);
    assert!(db.profiles.get(&victim).is_none());
}

#[test]
fn eviction_deterministic() {
    let tick = 100000u64;

    let build_db = || {
        let mut db = offline_db();
        db.tick = tick;

        for i in 0..=(MAX_PROFILES as u64) {
            let mut comm = [0u8; 16];
            comm[0..8].copy_from_slice(&i.to_le_bytes());
            db.profiles.insert(comm, TaskProfile {
                tier_votes: [5, 0, 0],
                avg_runtime_ns: 100000,
                observations: (i as u32) % 10 + 1,
                last_seen_tick: tick - (i % 20),
                ..Default::default()
            });
        }

        db.tick();
        db
    };

    let db1 = build_db();
    let db2 = build_db();

    assert_eq!(db1.profiles.len(), db2.profiles.len());

    // VERIFY SAME PROFILES SURVIVE IN BOTH
    for i in 0..=(MAX_PROFILES as u64) {
        let mut comm = [0u8; 16];
        comm[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(
            db1.profiles.get(&comm).is_some(),
            db2.profiles.get(&comm).is_some(),
            "MISMATCH AT i={}", i
        );
    }
}

// BEHAVIORAL CONFIDENCE (V4.0 PHASE 2)

#[test]
fn behavioral_confidence_high_stability() {
    // LOW RUNTIME VARIANCE = HIGH CONFIDENCE
    let p = TaskProfile {
        tier_votes: [9, 1, 0],
        avg_runtime_ns: 1_000_000,
        runtime_dev_ns: 100_000, // 10% DEV
        observations: 10,
        ..Default::default()
    };
    // TIER_CONF = 0.9, DEV_RATIO = 0.1, STABILITY = 0.9
    // BEHAVIORAL = 0.9 * (0.5 + 0.5 * 0.9) = 0.9 * 0.95 = 0.855
    let bc = p.behavioral_confidence();
    assert!(bc > 0.85 && bc < 0.86, "GOT {}", bc);
}

#[test]
fn behavioral_confidence_low_stability() {
    // HIGH RUNTIME VARIANCE = REDUCED CONFIDENCE
    let p = TaskProfile {
        tier_votes: [9, 1, 0],
        avg_runtime_ns: 1_000_000,
        runtime_dev_ns: 800_000, // 80% DEV
        observations: 10,
        ..Default::default()
    };
    // TIER_CONF = 0.9, DEV_RATIO = 0.8, STABILITY = 0.2
    // BEHAVIORAL = 0.9 * (0.5 + 0.5 * 0.2) = 0.9 * 0.6 = 0.54
    let bc = p.behavioral_confidence();
    assert!(bc > 0.53 && bc < 0.55, "GOT {}", bc);
}

#[test]
fn procdb_v1_load_compat() {
    // V1 FORMAT: 40-BYTE ENTRIES, NO BEHAVIORAL FIELDS
    let path = tmp_path("v1_compat.bin");
    let _ = std::fs::remove_file(&path);

    let mut data = Vec::new();
    data.extend_from_slice(b"PDDB");
    data.extend_from_slice(&1u32.to_le_bytes()); // VERSION 1
    data.extend_from_slice(&1u32.to_le_bytes()); // 1 ENTRY

    // V1 ENTRY: COMM(16) + TIER+PAD(8) + AVG_RUNTIME(8) + OBS(4) + VOTES(4) = 40
    let comm = make_comm(b"v1_task");
    data.extend_from_slice(&comm);
    data.push(0); // TIER = BATCH
    data.extend_from_slice(&[0u8; 7]); // PAD
    data.extend_from_slice(&2_000_000u64.to_le_bytes()); // AVG_RUNTIME
    data.extend_from_slice(&5u32.to_le_bytes()); // OBSERVATIONS
    data.extend_from_slice(&5u32.to_le_bytes()); // TOTAL_VOTES

    std::fs::write(&path, &data).unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    assert_eq!(loaded.len(), 1);
    let p = &loaded[&comm];
    assert_eq!(p.avg_runtime_ns, 2_000_000);
    assert_eq!(p.runtime_dev_ns, 0); // ZERO-FILLED
    assert_eq!(p.wakeup_freq, 0);    // ZERO-FILLED
    assert_eq!(p.csw_rate, 0);       // ZERO-FILLED
    assert_eq!(p.observations, 5);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn richer_observation_roundtrip() {
    // ALL 5 FIELDS SURVIVE SAVE -> LOAD
    let path = tmp_path("richer_roundtrip.bin");
    let _ = std::fs::remove_file(&path);

    let mut db = offline_db();
    db.profiles.insert(make_comm(b"firefox"), TaskProfile {
        tier_votes: [0, 0, 8],
        avg_runtime_ns: 75000,
        runtime_dev_ns: 12000,
        wakeup_freq: 45,
        csw_rate: 180,
        observations: 8,
        last_seen_tick: 100,
    });
    db.save(&path).unwrap();

    let loaded = ProcessDb::load_from_disk(&path).unwrap();
    let p = &loaded[&make_comm(b"firefox")];
    assert_eq!(p.avg_runtime_ns, 75000);
    assert_eq!(p.runtime_dev_ns, 12000);
    assert_eq!(p.wakeup_freq, 45);
    assert_eq!(p.csw_rate, 180);
    assert_eq!(p.observations, 8);

    let _ = std::fs::remove_file(&path);
}
