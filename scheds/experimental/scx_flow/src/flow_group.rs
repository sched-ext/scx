/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Group helpers for the flow scheduler.
 * Two groups split cores by half with extra
 * to hog. Odd counts give the extra core to hog in
 * both views. One LLC splits globally. Two plus N
 * LLCs split in each LLC. All singleton cores use
 * halves plus interleave exactly. Light holds short
 * waits. Hog holds burn.
 * The classifier uses burn with a 32ms window plus
 * wake hits. Demote needs 16ms burn or one burst at
 * 4ms quiet down to 1ms floor during flood. Promote
 * needs 4ms low for 64 wins near 2s or 8 short blocks
 * below 1ms with burn below 4ms. Cold tasks join
 * light. The 4x gap keeps flips rare. A per CPU table
 * holds live groups when ready, else halves applies.
 * Short slices clamp with no pad. Strict iff ready is
 * zero, best effort iff ready is one with dispatch on
 * halves and placement on live.
 */

/* Count of groups. Fixed at two with no knob. */
#[cfg(test)]
pub const NGROUPS: u64 = 2;
/* Light group id for short waits. */
pub const GROUP_LIGHT: u8 = 0;
/* Hog group id for burn. */
pub const GROUP_HOG: u8 = 1;
/* Park id of the light group. */
#[cfg(test)]
pub const PARK_LIGHT: u64 = 0x5000;
/* Park id of the hog group. */
#[cfg(test)]
pub const PARK_HOG: u64 = 0x5001;
/* Window length in nanos at 32ms. */
#[cfg(test)]
pub const WIN_NS: u64 = 32_000_000;
/* Window burn in nanos at 16ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURN_NS: u64 = 16_000_000;
/* Single burst in nanos at 4ms for demote. */
/* Quiet case of the adaptive check with depth 0. */
#[cfg(test)]
pub const DEMOTE_BURST_NS: u64 = 4_000_000;
/* Mild burst in nanos at 2ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURST_MID_NS: u64 = 2_000_000;
/* Floor burst in nanos at 1ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURST_FLOOR_NS: u64 = 1_000_000;
/* Window burn in nanos below 4ms for promote. */
#[cfg(test)]
pub const PROMOTE_BURN_NS: u64 = 4_000_000;
/* Low windows needed for one promote near 2s. */
#[cfg(test)]
pub const PROMOTE_WINS: u8 = 64;
/* Extra deadline in nanos at 8ms for pinned hog. */
#[cfg(test)]
pub const PINNED_INFLATE_NS: u64 = 8_000_000;
/* Short block in nanos below 1ms for wake. */
#[cfg(test)]
pub const WAKE_SHORT_NS: u64 = 1_000_000;
/* Short blocks needed for one fast promote. */
#[cfg(test)]
pub const PROMOTE_WAKE_HITS: u16 = 8;
/* Spread in percent above 10pct for hetero. */
pub const HETERO_SPREAD_PCT: u64 = 10;
/* Length of the per CPU group table. */
pub const GROUP_TABLE_LEN: usize = 1024;
/* Perf hint of light at max. */
#[cfg(test)]
pub const PERF_LIGHT: u32 = 1024;
/* Perf hint of hog at max. */
#[cfg(test)]
pub const PERF_HOG: u32 = 1024;
/* Cpu perf level at max for running. */
#[cfg(test)]
pub const CPUPERF_LEVEL: u32 = 1024;
/* Cpu perf idle at zero for blocked empty. */
#[cfg(test)]
pub const CPUPERF_IDLE: u32 = 0;
/* Cpu perf EMA budget in nanos at 1ms. */
#[cfg(test)]
pub const CPUPERF_BUDGET_NS: u64 = 1_000_000;
/* Cpu perf EMA half-life in nanos at 24ms. */
#[cfg(test)]
pub const CPUPERF_HALF_LIFE_NS: u64 = 24_000_000;
/* Cpu perf EMA climb alpha at 12x in FP8. */
#[cfg(test)]
pub const CPUPERF_ALPHA: u64 = 3072;
/* Cpu perf fixed point shift at 8. */
#[cfg(test)]
pub const CPUPERF_FP_SHIFT: u64 = 8;
/* Cpu perf fixed point one at 256. */
#[cfg(test)]
pub const CPUPERF_FP_ONE: u64 = 256;

/*
 * Group of one CPU by id halves with extra to hog.
 * Halves is the fallback when the table is not ready.
 * Dispatch keeps halves, so placement is best effort
 * iff ready is one with strict iff ready is zero. One
 * or no CPUs keeps all light. Otherwise the low half
 * is light and the high half is hog, so an odd count
 * gives the extra CPU to hog.
 */
pub fn group_of_cpu(cpu: u32, nr: usize) -> u8 {
    if nr <= 1 {
        return GROUP_LIGHT;
    }
    if (cpu as usize) < nr / 2 {
        return GROUP_LIGHT;
    }
    GROUP_HOG
}

/*
 * Live group of one CPU from table plus halves fallback.
 * Reads the table when ready holds groups, else halves.
 * Bad values fall back to halves with no trap. Mirrors
 * the BPF live helper for snapshot use. Placement uses
 * live, dispatch keeps halves, so strict iff ready is
 * zero, best effort iff ready is one.
 */
pub fn group_live(cpu: u32, nr: usize, table: &[u8], ready: u8) -> u8 {
    if ready != 0 && (cpu as usize) < nr && (cpu as usize) < table.len() {
        let g = table[cpu as usize];
        if g == GROUP_HOG {
            return GROUP_HOG;
        }
        if g == GROUP_LIGHT {
            return GROUP_LIGHT;
        }
    }
    group_of_cpu(cpu, nr)
}

/*
 * True when values spread past 10pct. Needs max past
 * min by more than 10pct of max, so uniform hosts stay
 * plain. Empty plus single plus zero max stays false.
 */
pub fn spread_exceeds(vals: &[u64]) -> bool {
    if vals.len() < 2 {
        return false;
    }
    let mut min = u64::MAX;
    let mut max = 0u64;
    for &v in vals {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    if max == 0 {
        return false;
    }
    (max - min) as u128 * 100 > max as u128 * HETERO_SPREAD_PCT as u128
}

/*
 * True when capacity or frequency spreads past 10pct.
 * Either signal marks hetero, so one-sided skew still
 * seeds the table. Short slices clamp to live CPUs.
 */
pub fn hetero_needed(caps: &[u64], freqs: &[u64]) -> bool {
    spread_exceeds(caps) || spread_exceeds(freqs)
}

/*
 * Assign groups by sorted interleave. Sorts live CPUs
 * by capacity plus frequency plus id, then assigns even
 * slots to light and odd slots to hog. Odd counts give
 * the extra CPU to hog, so counts match halves with no
 * knob. The order spreads fast CPUs across both groups.
 * Halves is the fallback when the table is not ready.
 * Single CPU keeps all light.
 */
pub fn assign_sorted_interleave(caps: &[u64], freqs: &[u64], nr: usize) -> Vec<u8> {
    let mut idx: Vec<usize> = (0..nr).collect();
    idx.sort_by(|&a, &b| {
        let ca = caps.get(a).copied().unwrap_or(0);
        let cb = caps.get(b).copied().unwrap_or(0);
        cb.cmp(&ca)
            .then_with(|| {
                let fa = freqs.get(a).copied().unwrap_or(0);
                let fb = freqs.get(b).copied().unwrap_or(0);
                fb.cmp(&fa)
            })
            .then_with(|| a.cmp(&b))
    });
    let mut out = vec![GROUP_LIGHT; nr];
    for (pos, cpu) in idx.iter().enumerate() {
        if nr > 1 && (pos % 2 == 1 || (nr % 2 == 1 && pos + 1 == nr)) {
            out[*cpu] = GROUP_HOG;
        } else {
            out[*cpu] = GROUP_LIGHT;
        }
    }
    out
}

/*
 * Seed the per CPU group table plus ready flag. Returns
 * interleaved groups with ready set when hetero holds.
 * Returns halves with ready cleared when hosts look
 * uniform, so the BPF side plus snapshot stay on halves.
 * Short slices clamp to available entries with no pad,
 * so missing entries never fake hetero.
 */
pub fn seed_groups(caps: &[u64], freqs: &[u64], nr: usize) -> ([u8; GROUP_TABLE_LEN], u8) {
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    if nr <= 1 {
        return (table, 0);
    }
    let avail = caps.len().min(freqs.len());
    let n = nr.min(GROUP_TABLE_LEN).min(avail);
    if n <= 1 {
        return (table, 0);
    }
    let live_caps: Vec<u64> = caps[..n].to_vec();
    let live_freqs: Vec<u64> = freqs[..n].to_vec();
    if !hetero_needed(&live_caps, &live_freqs) {
        return (table, 0);
    }
    let assign = assign_sorted_interleave(&live_caps, &live_freqs, n);
    for (cpu, g) in assign.iter().enumerate() {
        table[cpu] = *g;
    }
    (table, 1)
}

/* Empty marker for the sibling partner table. */
pub const SIBLING_EMPTY: u16 = 0xffff;

/*
 * Parse one sibling list from sysfs. Accepts comma
 * separated ids plus ranges with dash, such as 0-1
 * plus 0,1 plus 0-1,4. Trims space plus newline.
 * Bad tokens stay out with no trap. Ids at or past
 * 1024 stay out, so the cap holds with no extra use.
 */
pub fn parse_siblings_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((a, b)) = t.split_once('-') {
            let lo = a.trim().parse::<u32>().ok();
            let hi = b.trim().parse::<u32>().ok();
            if let (Some(l), Some(h)) = (lo, hi) {
                if l > h {
                    continue;
                }
                if h >= 1024 && l >= 1024 {
                    continue;
                }
                let mut v = l;
                loop {
                    if v < 1024 && !out.contains(&v) {
                        out.push(v);
                    }
                    if v >= h || v >= 1023 {
                        break;
                    }
                    v += 1;
                    if out.len() >= 1024 {
                        break;
                    }
                }
            }
            continue;
        }
        if let Ok(v) = t.parse::<u32>()
            && v < 1024
            && !out.contains(&v)
        {
            out.push(v);
        }
    }
    out.sort_unstable();
    out
}

/*
 * Build cores from sibling lists with union find.
 * Each list holds the sibling ids of one CPU. Only
 * ids below nr join, so offline ids stay out. Missing
 * lists mean singleton cores with no trap. Cores sort
 * by member plus by least id, so order stays stable.
 * No division, so no zero risk.
 */
pub fn build_cores(nr: usize, lists: &[Vec<u32>]) -> Vec<Vec<u32>> {
    let n = nr.min(GROUP_TABLE_LEN);
    if n == 0 {
        return Vec::new();
    }
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], mut x: usize) -> usize {
        let mut r = x;
        while p[r] != r {
            r = p[r];
        }
        while p[x] != x {
            let nxt = p[x];
            p[x] = r;
            x = nxt;
        }
        r
    }
    for cpu in 0..n {
        let sibs = lists.get(cpu);
        let empty: Vec<u32> = Vec::new();
        let vals = sibs.unwrap_or(&empty);
        for &s in vals {
            let v = s as usize;
            if v >= n {
                continue;
            }
            if v == cpu {
                continue;
            }
            let a = find(&mut parent, cpu);
            let b = find(&mut parent, v);
            if a != b {
                if a < b {
                    parent[b] = a;
                } else {
                    parent[a] = b;
                }
            }
        }
    }
    use std::collections::BTreeMap;
    let mut map: BTreeMap<usize, Vec<u32>> = BTreeMap::new();
    for cpu in 0..n {
        let r = find(&mut parent, cpu);
        map.entry(r).or_default().push(cpu as u32);
    }
    let mut cores: Vec<Vec<u32>> = map.into_values().collect();
    for c in cores.iter_mut() {
        c.sort_unstable();
    }
    cores.sort_by_key(|c| c[0]);
    cores
}

/*
 * True when all cores hold one CPU. Hosts with SMT
 * off land here. Callers bypass LLC rules then, so
 * the split reduces to halves plus interleave with
 * state equivalence to the prior release.
 */
pub fn cores_are_singletons(cores: &[Vec<u32>]) -> bool {
    for c in cores {
        if c.len() != 1 {
            return false;
        }
    }
    true
}

/*
 * Max value in one core. Missing entries read as
 * zero, so short slices stay quiet with no trap.
 */
pub fn core_max(vals: &[u64], core: &[u32]) -> u64 {
    let mut m = 0u64;
    for &cpu in core {
        let v = vals.get(cpu as usize).copied().unwrap_or(0);
        if v > m {
            m = v;
        }
    }
    m
}

/*
 * Assign groups by core split. Keeps siblings in one
 * group. First half of cores is light, rest is hog,
 * so an odd core count gives the extra core to hog.
 * Single CPU keeps all light. Single core with more
 * than one CPU falls back to halves, so no group
 * stays empty with no trap. Missing CPUs keep halves.
 */
pub fn assign_cores_split(cores: &[Vec<u32>], nr: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(nr);
    for cpu in 0..nr {
        out.push(group_of_cpu(cpu as u32, nr));
    }
    if nr <= 1 {
        return out;
    }
    let live: Vec<&Vec<u32>> = cores.iter().filter(|c| !c.is_empty()).collect();
    if live.len() <= 1 {
        return out;
    }
    let half = live.len() / 2;
    for (pos, core) in live.iter().enumerate() {
        let g = if pos < half { GROUP_LIGHT } else { GROUP_HOG };
        for &cpu in core.iter() {
            if (cpu as usize) < nr {
                out[cpu as usize] = g;
            }
        }
    }
    out
}

/*
 * Assign groups by hetero core interleave. Sorts cores
 * by max capacity plus max frequency plus least id,
 * then assigns even slots to light and odd slots to
 * hog. Odd core counts give the extra core to hog, so
 * counts match the split bias with no knob. Spreads
 * fast cores across both groups. Single CPU keeps all
 * light. Single core falls back to CPU interleave, so
 * no group stays empty with no trap.
 */
pub fn assign_cores_interleave(
    cores: &[Vec<u32>],
    caps: &[u64],
    freqs: &[u64],
    nr: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(nr);
    for cpu in 0..nr {
        out.push(group_of_cpu(cpu as u32, nr));
    }
    if nr <= 1 {
        return out;
    }
    let live: Vec<&Vec<u32>> = cores.iter().filter(|c| !c.is_empty()).collect();
    if live.len() <= 1 {
        let n = nr.min(caps.len().min(freqs.len()));
        if n <= 1 {
            return out;
        }
        let live_caps: Vec<u64> = caps[..n].to_vec();
        let live_freqs: Vec<u64> = freqs[..n].to_vec();
        let flat = assign_sorted_interleave(&live_caps, &live_freqs, n);
        for (cpu, g) in flat.iter().enumerate() {
            if cpu < nr {
                out[cpu] = *g;
            }
        }
        return out;
    }
    let mut order: Vec<usize> = (0..live.len()).collect();
    order.sort_by(|&a, &b| {
        let ca = core_max(caps, live[a]);
        let cb = core_max(caps, live[b]);
        cb.cmp(&ca)
            .then_with(|| {
                let fa = core_max(freqs, live[a]);
                let fb = core_max(freqs, live[b]);
                fb.cmp(&fa)
            })
            .then_with(|| live[a][0].cmp(&live[b][0]))
    });
    for (pos, &ci) in order.iter().enumerate() {
        let g = if pos % 2 == 1 || (live.len() % 2 == 1 && pos + 1 == live.len()) {
            GROUP_HOG
        } else {
            GROUP_LIGHT
        };
        for &cpu in live[ci].iter() {
            if (cpu as usize) < nr {
                out[cpu as usize] = g;
            }
        }
    }
    out
}

/*
 * Assign groups with LLC rules. One LLC splits cores
 * globally. Two plus N LLCs split cores in each LLC,
 * so each cache domain stays balanced. Cores take the
 * LLC of the least id. Missing LLC folds to one domain
 * with no pad. One core in one LLC keeps LIGHT as the
 * default with no split, so a single core LLC never
 * forces hog. Each LLC with an odd core count gives
 * the extra core to hog, so per LLC bias matches the
 * global bias with no knob. All singleton cores bypass
 * LLC and use the prior halves plus interleave exactly,
 * so SMT off keeps state equivalence. Empty group falls
 * back to global, so no group stays empty with no trap.
 * Strict iff ready is zero, best effort iff ready is
 * one with the same core view in both cases.
 */
pub fn assign_by_llc(
    cores: &[Vec<u32>],
    llc: &[u32],
    caps: &[u64],
    freqs: &[u64],
    nr: usize,
    hetero: bool,
) -> Vec<u8> {
    if nr <= 1 {
        return vec![GROUP_LIGHT; nr];
    }
    if cores_are_singletons(cores) {
        if hetero {
            let n = nr.min(caps.len().min(freqs.len()));
            if n <= 1 {
                let mut out = vec![GROUP_LIGHT; nr];
                for (cpu, slot) in out.iter_mut().enumerate() {
                    *slot = group_of_cpu(cpu as u32, nr);
                }
                return out;
            }
            let live_caps: Vec<u64> = caps[..n].to_vec();
            let live_freqs: Vec<u64> = freqs[..n].to_vec();
            let flat = assign_sorted_interleave(&live_caps, &live_freqs, n);
            let mut out = vec![GROUP_LIGHT; nr];
            for (cpu, g) in flat.iter().enumerate() {
                if cpu < nr {
                    out[cpu] = *g;
                }
            }
            for (cpu, slot) in out.iter_mut().enumerate().skip(n) {
                *slot = group_of_cpu(cpu as u32, nr);
            }
            return out;
        }
        let mut out = vec![GROUP_LIGHT; nr];
        for (cpu, slot) in out.iter_mut().enumerate() {
            *slot = group_of_cpu(cpu as u32, nr);
        }
        return out;
    }
    use std::collections::BTreeMap;
    let live_cores: Vec<Vec<u32>> = cores.iter().filter(|c| !c.is_empty()).cloned().collect();
    if live_cores.is_empty() {
        let mut out = vec![GROUP_LIGHT; nr];
        for (cpu, slot) in out.iter_mut().enumerate() {
            *slot = group_of_cpu(cpu as u32, nr);
        }
        return out;
    }
    let mut llc_of_core: Vec<u32> = Vec::with_capacity(live_cores.len());
    for core in &live_cores {
        let first = core[0] as usize;
        let id = llc.get(first).copied().unwrap_or(0);
        llc_of_core.push(id);
    }
    let mut distinct: Vec<u32> = llc_of_core.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if llc.len() < nr && distinct.len() > 1 {
        distinct = vec![0];
    }
    if distinct.len() <= 1 {
        if hetero {
            return assign_cores_interleave(&live_cores, caps, freqs, nr);
        }
        return assign_cores_split(&live_cores, nr);
    }
    let mut by_llc: BTreeMap<u32, Vec<Vec<u32>>> = BTreeMap::new();
    for (i, core) in live_cores.iter().enumerate() {
        let id = llc_of_core[i];
        by_llc.entry(id).or_default().push(core.clone());
    }
    let mut out = vec![GROUP_LIGHT; nr];
    for subset in by_llc.values() {
        let mut ordered: Vec<Vec<u32>> = subset.clone();
        ordered.sort_by_key(|c| c[0]);
        if hetero {
            ordered.sort_by(|a, b| {
                let ca = core_max(caps, a);
                let cb = core_max(caps, b);
                cb.cmp(&ca)
                    .then_with(|| {
                        let fa = core_max(freqs, a);
                        let fb = core_max(freqs, b);
                        fb.cmp(&fa)
                    })
                    .then_with(|| a[0].cmp(&b[0]))
            });
            if ordered.len() <= 1 {
                continue;
            }
            for (pos, core) in ordered.iter().enumerate() {
                let g = if pos % 2 == 1 || (ordered.len() % 2 == 1 && pos + 1 == ordered.len()) {
                    GROUP_HOG
                } else {
                    GROUP_LIGHT
                };
                for &cpu in core {
                    if (cpu as usize) < nr {
                        out[cpu as usize] = g;
                    }
                }
            }
        } else {
            if ordered.len() <= 1 {
                continue;
            }
            let half = ordered.len() / 2;
            for (pos, core) in ordered.iter().enumerate() {
                let g = if pos < half { GROUP_LIGHT } else { GROUP_HOG };
                for &cpu in core {
                    if (cpu as usize) < nr {
                        out[cpu as usize] = g;
                    }
                }
            }
        }
    }
    let light_n = out.iter().filter(|&&g| g == GROUP_LIGHT).count();
    let hog_n = out.iter().filter(|&&g| g == GROUP_HOG).count();
    if light_n == 0 || hog_n == 0 {
        if hetero {
            return assign_cores_interleave(&live_cores, caps, freqs, nr);
        }
        return assign_cores_split(&live_cores, nr);
    }
    out
}

/*
 * Seed the per CPU group table with topology. Builds
 * cores from sibling lists with union find, then
 * assigns with LLC rules plus hetero interleave. All
 * singleton cores use the prior halves plus interleave
 * exactly. Ready stays cleared when the core view
 * matches halves, else ready set. Strict iff ready is
 * zero, best effort iff ready is one. Short slices
 * clamp with no pad. Single CPU keeps ready cleared
 * with all light. One core in one LLC keeps LIGHT with
 * no split. Each odd LLC gives the extra core to hog.
 */
pub fn seed_groups_topology(
    caps: &[u64],
    freqs: &[u64],
    nr: usize,
    lists: &[Vec<u32>],
    llc: &[u32],
) -> ([u8; GROUP_TABLE_LEN], u8) {
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    if nr <= 1 {
        return (table, 0);
    }
    let n = nr.min(GROUP_TABLE_LEN);
    let cores = build_cores(n, lists);
    if cores_are_singletons(&cores) {
        return seed_groups(caps, freqs, n);
    }
    let avail = caps.len().min(freqs.len());
    let m = n.min(avail);
    if m <= 1 {
        return (table, 0);
    }
    let live_caps: Vec<u64> = caps[..m].to_vec();
    let live_freqs: Vec<u64> = freqs[..m].to_vec();
    let hetero = hetero_needed(&live_caps, &live_freqs);
    let assign = assign_by_llc(&cores, llc, caps, freqs, n, hetero);
    if !hetero {
        let mut same = true;
        for (cpu, g) in assign.iter().enumerate().take(n) {
            if *g != group_of_cpu(cpu as u32, n) {
                same = false;
                break;
            }
        }
        if same {
            return (table, 0);
        }
    }
    for (cpu, g) in assign.iter().enumerate() {
        if cpu < GROUP_TABLE_LEN {
            table[cpu] = *g;
        }
    }
    (table, 1)
}

/*
 * True when online ids form dense 0 plus 1 plus 2
 * with no gaps. Empty counts as dense with no trap.
 * The caller passes sorted ids with no sort here.
 */
pub fn online_is_dense(online: &[u32]) -> bool {
    for (rank, &id) in online.iter().enumerate() {
        if id as usize != rank {
            return false;
        }
    }
    true
}

/*
 * True when the online set skews from possible.
 * Needs len past possible or gaps or dense short,
 * so SMT off plus isolated plus hotplug all force
 * the live table with no halves fallback. Empty
 * stays false with no trap. Dense full stays false,
 * so prior state holds with no change.
 */
pub fn online_skewed(online: &[u32], possible_nr: usize) -> bool {
    if online.is_empty() {
        return false;
    }
    let want = possible_nr.min(GROUP_TABLE_LEN);
    if online.len().min(GROUP_TABLE_LEN) != want {
        return true;
    }
    !online_is_dense(online)
}

/*
 * Build cores from online ids with union find.
 * Each rank holds the sibling ids of one online CPU.
 * Only ids in the online set join, so offline ids
 * stay out with no trap. Missing lists mean singleton
 * cores with no trap. Cores hold ids sorted plus cores
 * sorted by least id, so order stays stable. No
 * division, so no zero risk. Mirrors build cores for
 * dense with rank mapping for sparse.
 */
pub fn build_cores_online(online: &[u32], lists: &[Vec<u32>]) -> Vec<Vec<u32>> {
    use std::collections::HashMap;
    let n = online.len().min(GROUP_TABLE_LEN);
    if n == 0 {
        return Vec::new();
    }
    let ids: Vec<u32> = online[..n].to_vec();
    let mut id_to_rank: HashMap<u32, usize> = HashMap::with_capacity(n);
    for (rank, &id) in ids.iter().enumerate() {
        id_to_rank.insert(id, rank);
    }
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], mut x: usize) -> usize {
        let mut r = x;
        while p[r] != r {
            r = p[r];
        }
        while p[x] != x {
            let nxt = p[x];
            p[x] = r;
            x = nxt;
        }
        r
    }
    for (rank, sibs) in lists.iter().enumerate().take(n) {
        for &s in sibs {
            let Some(&other) = id_to_rank.get(&s) else {
                continue;
            };
            if other == rank {
                continue;
            }
            let a = find(&mut parent, rank);
            let b = find(&mut parent, other);
            if a != b {
                if a < b {
                    parent[b] = a;
                } else {
                    parent[a] = b;
                }
            }
        }
    }
    use std::collections::BTreeMap;
    let mut map: BTreeMap<usize, Vec<u32>> = BTreeMap::new();
    for (rank, &id) in ids.iter().enumerate() {
        let r = find(&mut parent, rank);
        map.entry(r).or_default().push(id);
    }
    let mut cores: Vec<Vec<u32>> = map.into_values().collect();
    for c in cores.iter_mut() {
        c.sort_unstable();
    }
    cores.sort_by_key(|c| c[0]);
    cores
}

/*
 * Seed the per CPU group table by online rank plus
 * write by id. Sorts live ranks by capacity plus
 * frequency plus rank, then assigns even slots to
 * light and odd slots to hog. Odd counts give the
 * extra rank to hog, so counts match halves with no
 * knob. Offline ids stay light inert with no trap.
 * Dense full keeps prior ready plus table exactly.
 * Skewed plus hetero both force ready one, so SMT off
 * holds 4 plus 4 over online only with no stall.
 * Strict iff ready is zero, best effort iff ready is
 * one with dispatch on halves and placement on live.
 */
pub fn seed_groups_online(
    caps_rank: &[u64],
    freqs_rank: &[u64],
    online: &[u32],
    possible_nr: usize,
) -> ([u8; GROUP_TABLE_LEN], u8) {
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let n = online
        .len()
        .min(GROUP_TABLE_LEN)
        .min(caps_rank.len().min(freqs_rank.len()));
    if n <= 1 {
        return (table, 0);
    }
    let ids: Vec<u32> = online[..online.len().min(GROUP_TABLE_LEN)]
        .iter()
        .copied()
        .take(n)
        .collect();
    if ids.len() <= 1 {
        return (table, 0);
    }
    let live_caps: Vec<u64> = caps_rank[..n].to_vec();
    let live_freqs: Vec<u64> = freqs_rank[..n].to_vec();
    let hetero = hetero_needed(&live_caps, &live_freqs);
    let skewed = online_skewed(&online[..online.len().min(GROUP_TABLE_LEN)], possible_nr);
    if !hetero && !skewed {
        return (table, 0);
    }
    // Uniform skewed keeps rank halves, hetero keeps
    // interleave, so the table holds 4 plus 4 over online
    // only with offline inert.
    let assign: Vec<u8> = if hetero {
        assign_sorted_interleave(&live_caps, &live_freqs, n)
    } else {
        (0..n).map(|rank| group_of_cpu(rank as u32, n)).collect()
    };
    for (rank, &id) in ids.iter().enumerate() {
        if (id as usize) < GROUP_TABLE_LEN && rank < assign.len() {
            table[id as usize] = assign[rank];
        }
    }
    (table, 1)
}

/*
 * Seed the per CPU group table by online rank with
 * topology. Builds online cores from sibling lists,
 * then assigns with LLC rules plus hetero interleave
 * in rank order. All singleton online cores use the
 * rank halves plus interleave exactly. Offline ids
 * stay light inert with no trap. Dense full keeps
 * prior table plus ready exactly. Skewed forces ready
 * one even when uniform, so SMT off holds groups over
 * online only with no halves drift. Strict iff ready
 * is zero, best effort iff ready is one. Short slices
 * clamp with no pad. Single online keeps ready cleared
 * with all light.
 */
pub fn seed_groups_topology_online(
    caps_rank: &[u64],
    freqs_rank: &[u64],
    online: &[u32],
    lists_rank: &[Vec<u32>],
    llc_rank: &[u32],
    possible_nr: usize,
) -> ([u8; GROUP_TABLE_LEN], u8) {
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let n = online
        .len()
        .min(GROUP_TABLE_LEN)
        .min(caps_rank.len().min(freqs_rank.len()));
    if n <= 1 {
        return (table, 0);
    }
    let ids: Vec<u32> = online[..online.len().min(GROUP_TABLE_LEN)]
        .iter()
        .copied()
        .take(n)
        .collect();
    if ids.len() <= 1 {
        return (table, 0);
    }
    let live_caps: Vec<u64> = caps_rank[..n].to_vec();
    let live_freqs: Vec<u64> = freqs_rank[..n].to_vec();
    let mut live_lists: Vec<Vec<u32>> = Vec::with_capacity(n);
    for rank in 0..n {
        live_lists.push(lists_rank.get(rank).cloned().unwrap_or_default());
    }
    let mut live_llc: Vec<u32> = Vec::with_capacity(n);
    for rank in 0..n {
        live_llc.push(llc_rank.get(rank).copied().unwrap_or(0));
    }
    let hetero = hetero_needed(&live_caps, &live_freqs);
    let online_trimmed: Vec<u32> = online[..online.len().min(GROUP_TABLE_LEN)]
        .iter()
        .copied()
        .take(n)
        .collect();
    let skewed = online_skewed(&online[..online.len().min(GROUP_TABLE_LEN)], possible_nr);
    let cores_id = build_cores_online(&online_trimmed, &live_lists);
    if cores_are_singletons(&cores_id) {
        return seed_groups_online(&live_caps, &live_freqs, &online_trimmed, possible_nr);
    }
    // Map id cores to rank cores for the dense assign.
    use std::collections::HashMap;
    let mut id_to_rank: HashMap<u32, usize> = HashMap::with_capacity(n);
    for (rank, &id) in online_trimmed.iter().enumerate() {
        id_to_rank.insert(id, rank);
    }
    let mut cores_rank: Vec<Vec<u32>> = Vec::with_capacity(cores_id.len());
    for core in &cores_id {
        let mut ranks: Vec<u32> = Vec::with_capacity(core.len());
        for &id in core {
            if let Some(&r) = id_to_rank.get(&id) {
                ranks.push(r as u32);
            }
        }
        ranks.sort_unstable();
        if !ranks.is_empty() {
            cores_rank.push(ranks);
        }
    }
    cores_rank.sort_by_key(|c| c[0]);
    let assign = assign_by_llc(&cores_rank, &live_llc, &live_caps, &live_freqs, n, hetero);
    if !hetero && !skewed {
        let mut same = true;
        for (rank, g) in assign.iter().enumerate().take(n) {
            if *g != group_of_cpu(rank as u32, n) {
                same = false;
                break;
            }
        }
        if same {
            return (table, 0);
        }
    }
    for (rank, &id) in online_trimmed.iter().enumerate() {
        if (id as usize) < GROUP_TABLE_LEN && rank < assign.len() {
            table[id as usize] = assign[rank];
        }
    }
    (table, 1)
}

/*
 * Sibling partner table for BPF placement. Each CPU
 * holds the next CPU in the same core in id order.
 * Singletons hold 0xffff, so the free check is a
 * no-op. Capped at 1024 with no trap. Mirrors the
 * BPF walk of up to 8 steps with no division. Strict
 * iff ready is zero, best effort iff ready is one
 * with the same core view in both cases.
 */
pub fn sibling_table(cores: &[Vec<u32>], nr: usize) -> [u16; GROUP_TABLE_LEN] {
    let mut out = [SIBLING_EMPTY; GROUP_TABLE_LEN];
    let n = nr.min(GROUP_TABLE_LEN);
    for core in cores {
        if core.len() <= 1 {
            continue;
        }
        let mut sorted = core.clone();
        sorted.sort_unstable();
        for (i, &cpu) in sorted.iter().enumerate() {
            if (cpu as usize) >= n {
                continue;
            }
            let nxt = sorted[(i + 1) % sorted.len()];
            if (nxt as usize) >= n {
                continue;
            }
            out[cpu as usize] = nxt as u16;
        }
    }
    out
}

/*
 * Sibling partner table by online id for BPF placement.
 * Each online CPU holds the next online CPU in the same
 * core in id order. Singletons plus offline hold 0xffff,
 * so the free check is a no-op with no trap. Offline
 * stays inert with no write. Capped at 1024 with no
 * trap. Mirrors the BPF walk with the same bounds.
 * Dense full matches the prior table exactly.
 */
pub fn sibling_table_online(cores_id: &[Vec<u32>], online: &[u32]) -> [u16; GROUP_TABLE_LEN] {
    let mut out = [SIBLING_EMPTY; GROUP_TABLE_LEN];
    use std::collections::HashSet;
    let set: HashSet<u32> = online
        .iter()
        .copied()
        .filter(|&id| (id as usize) < GROUP_TABLE_LEN)
        .collect();
    for core in cores_id {
        if core.len() <= 1 {
            continue;
        }
        let mut sorted = core.clone();
        sorted.sort_unstable();
        sorted.retain(|id| set.contains(id));
        if sorted.len() <= 1 {
            continue;
        }
        for (i, &cpu) in sorted.iter().enumerate() {
            if (cpu as usize) >= GROUP_TABLE_LEN {
                continue;
            }
            let nxt = sorted[(i + 1) % sorted.len()];
            if (nxt as usize) >= GROUP_TABLE_LEN {
                continue;
            }
            if !set.contains(&nxt) {
                continue;
            }
            out[cpu as usize] = nxt as u16;
        }
    }
    out
}

/*
 * Park id of one group with light as default. Hog
 * uses 0x5001. Any other value uses 0x5000.
 */
#[cfg(test)]
pub fn park_for_group(group: u8) -> u64 {
    if group == GROUP_HOG {
        PARK_HOG
    } else {
        PARK_LIGHT
    }
}

/*
 * Perf hint of one group with single policy at max.
 * Light plus hog use max. Any other value uses max.
 */
#[cfg(test)]
pub fn perf_for_group(group: u8) -> u32 {
    if group == GROUP_HOG {
        PERF_HOG
    } else {
        PERF_LIGHT
    }
}

/*
 * True when a stopping task should restore the idle hint.
 * Bang-bang edge at M1 with no EMA plus no state growth.
 * M2 keeps the predicate but maps the value through the
 * EMA with from_ema, so long idle still decays to zero.
 * Needs blocked plus per CPU queue empty plus local empty,
 * so runnable never restores with any queued work held high.
 * Mirrors the BPF helper for stopping use.
 */
#[cfg(test)]
pub fn should_restore_hint(runnable: bool, dsq_nr: u64, local_nr: u64) -> bool {
    !runnable && dsq_nr == 0 && local_nr == 0
}

/*
 * Climb the EMA toward the 1ms budget with a gap step.
 * Pure-EMA proportional at M2 with uniform both groups.
 * Delta clamps to the budget first with u64 order, so a
 * long burst never overshoots in one step. Step is gap
 * times delta times alpha over budget times FP_ONE at
 * 12x in FP8, so a full slice saturates at once with a
 * fast attack. Adds min step gap, so max stays capped.
 * Mirrors the BPF helper with the same op order.
 */
#[cfg(test)]
pub fn ema_climb(ema: u64, delta: u64) -> u64 {
    if ema >= CPUPERF_BUDGET_NS {
        return CPUPERF_BUDGET_NS;
    }
    let gap = CPUPERF_BUDGET_NS - ema;
    let d = delta.min(CPUPERF_BUDGET_NS);
    if d == 0 || gap == 0 {
        return ema;
    }
    let denom = CPUPERF_BUDGET_NS * CPUPERF_FP_ONE;
    if denom == 0 {
        return ema;
    }
    let step = gap * d * CPUPERF_ALPHA / denom;
    let step = step.min(gap);
    ema + step
}

/*
 * Decay the EMA by sleep with half-life halves plus Taylor.
 * Shifts whole half-lives then scales the residual below one
 * half with a 2nd-order Taylor of 0.5 to the r power at r is
 * rem over half. Fixed point at FP_ONE 256 holds ln2 times
 * 256 at 177 plus quad times 256 at 61, so t is rem times
 * 256 over half in 0 to 255 with dec1 plus inc2 in u64 order
 * with no float plus no loop. Zero sleep keeps identity.
 * Zero half keeps identity with no divide. At or past 64
 * periods returns zero, so long idle still maps to zero.
 * Mirrors the BPF helper with the same op order.
 */
#[cfg(test)]
pub fn ema_decay(ema: u64, sleep: u64, half: u64) -> u64 {
    if ema == 0 {
        return 0;
    }
    if sleep == 0 {
        return ema;
    }
    if half == 0 {
        return ema;
    }
    let periods = sleep / half;
    let rem = sleep % half;
    if periods >= 64 {
        return 0;
    }
    let mut e = ema;
    if periods > 0 {
        e >>= periods;
        if e == 0 {
            return 0;
        }
    }
    if rem == 0 {
        return e;
    }
    let one = CPUPERF_FP_ONE;
    let t = rem * one / half;
    let dec1 = e * 177 * t / (one * one);
    let inc2 = e * 61 * t * t / (one * one * one);
    let out = e + inc2;
    if out < dec1 {
        return 0;
    }
    let out = out - dec1;
    if out > e { e } else { out }
}

/*
 * Map the EMA budget to a 0 to 1024 cpuperf hint.
 * Zero maps to zero, budget maps to 1024, over maps to
 * 1024 with clamp, so uniform both groups with no tier.
 * Mirrors the BPF helper with the same clamp.
 */
#[cfg(test)]
pub fn cpuperf_from_ema(ema: u64) -> u32 {
    if ema == 0 {
        return 0;
    }
    if ema >= CPUPERF_BUDGET_NS {
        return 1024;
    }
    let v = ema * 1024 / CPUPERF_BUDGET_NS;
    if v > 1024 { 1024 } else { v as u32 }
}

/*
 * Elapsed since the last EMA stamp with wrap safety.
 * Zero at stays zero with no under. A now before at
 * stays zero via the signed before check, so wrap holds
 * with no extra branch. Mirrors the BPF stopping use.
 */
#[cfg(test)]
pub fn cpuperf_elapsed(at: u64, now: u64) -> u64 {
    if at == 0 {
        return 0;
    }
    if crate::flow_edf::time_before(now, at) {
        return 0;
    }
    now.wrapping_sub(at)
}

/*
 * True when one window of 32ms has passed. Zero
 * start means no window yet, so the check fails
 * closed and the caller starts a fresh window.
 */
#[cfg(test)]
pub fn win_ready(now: u64, win_start: u64) -> bool {
    if win_start == 0 {
        return false;
    }
    now.wrapping_sub(win_start) >= WIN_NS
}

/*
 * True when window burn reaches 16ms for demote.
 * The 4x gap above the 4ms promote line keeps
 * flips rare with no extra state.
 */
#[cfg(test)]
pub fn burn_hot(burn: u32) -> bool {
    (burn as u64) >= DEMOTE_BURN_NS
}

/*
 * True when one burst reaches 4ms for demote. A
 * single long burst moves to hog at once with no
 * wait for the window end. Quiet case with depth 0.
 */
#[cfg(test)]
pub fn burst_hot(delta: u64) -> bool {
    delta >= DEMOTE_BURST_NS
}

/*
 * Allowance from light depth with flood backpressure.
 * Depth sums queued tasks in light per CPU queues
 * capped at 4. Table is depth 0 to 1 to 4ms, depth 2
 * to 3 to 2ms, depth 4 plus to 1ms. Quiet keeps 4ms
 * so solo bursts still move fast alone. Mild pressure
 * steps down to 2ms so rising flood reacts sooner yet
 * stays clear of one slice chatter. Deep flood pins at
 * 1ms, so per task worst case is one slice during
 * flood. Recomputed per stop with no new task field,
 * so task stays at 48B. Halves matches dispatch view
 * with no table cost in the stop path. Strict iff
 * ready is zero, best effort iff ready is one with
 * placement on the live table.
 */
#[cfg(test)]
pub fn burst_allowance(depth: u64) -> u64 {
    if depth >= 4 {
        DEMOTE_BURST_FLOOR_NS
    } else if depth >= 2 {
        DEMOTE_BURST_MID_NS
    } else {
        DEMOTE_BURST_NS
    }
}

/*
 * True when one burst reaches the allowance for
 * demote. The caller passes the allowance for the
 * current light depth, so flood lowers the line to
 * the floor with no extra state.
 */
#[cfg(test)]
pub fn burst_hot_at(delta: u64, allow: u64) -> bool {
    delta >= allow
}

/*
 * Light depth from per CPU queued counts capped at 4.
 * Sums queued tasks over light CPUs in halves order
 * with early stop at 4. Halves matches the BPF depth
 * with no table use. Strict iff ready is zero, best
 * effort iff ready is one with placement on live.
 * Missing entries count as zero, so short slices stay
 * quiet with no trap.
 */
#[cfg(test)]
pub fn light_depth(queued: &[u64], nr: usize) -> u64 {
    let mut depth = 0u64;
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != GROUP_LIGHT {
            continue;
        }
        depth = depth.saturating_add(queued.get(cpu).copied().unwrap_or(0));
        if depth >= 4 {
            depth = 4;
            break;
        }
    }
    depth
}

/*
 * Hog depth from per CPU queued counts capped at 4.
 * Sums queued tasks over hog CPUs in halves order
 * with early stop at 4. Halves matches the BPF view
 * with no table use. Strict iff ready is zero, best
 * effort iff ready is one with placement on live.
 * Missing entries count as zero, so short slices stay
 * quiet with no trap. Display only with no burst use.
 */
#[cfg(test)]
pub fn hog_depth(queued: &[u64], nr: usize) -> u64 {
    let mut depth = 0u64;
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != GROUP_HOG {
            continue;
        }
        depth = depth.saturating_add(queued.get(cpu).copied().unwrap_or(0));
        if depth >= 4 {
            depth = 4;
            break;
        }
    }
    depth
}

/*
 * Both depths from per CPU queued counts capped at 4.
 * Single pass over halves order with early stop when
 * both hit 4. Mirrors the BPF refresh with one pass
 * and bounded cost. Strict iff ready is zero, best
 * effort iff ready is one with placement on live.
 * Missing entries count as zero.
 */
#[cfg(test)]
pub fn group_depths(queued: &[u64], nr: usize) -> (u64, u64) {
    let mut light = 0u64;
    let mut hog = 0u64;
    for cpu in 0..nr {
        let n = queued.get(cpu).copied().unwrap_or(0);
        if group_of_cpu(cpu as u32, nr) == GROUP_LIGHT {
            light = light.saturating_add(n);
            if light >= 4 {
                light = 4;
            }
        } else {
            hog = hog.saturating_add(n);
            if hog >= 4 {
                hog = 4;
            }
        }
        if light >= 4 && hog >= 4 {
            break;
        }
    }
    (light, hog)
}

/*
 * True when window burn stays below 4ms for
 * promote. Only low windows move the streak
 * forward toward 64 wins near 2s.
 */
#[cfg(test)]
pub fn burn_low(burn: u32) -> bool {
    (burn as u64) < PROMOTE_BURN_NS
}

/*
 * True when one block is short below 1ms for wake.
 * Short blocks count toward fast promote with low
 * burn, so brief waits return to light quickly.
 */
#[cfg(test)]
pub fn wake_short(delta: u64) -> bool {
    delta < WAKE_SHORT_NS
}

/*
 * True when wake hits reach 8 for fast promote.
 * Eight qualifying short blocks move hog to light
 * at once with no wait for 64 wins.
 */
#[cfg(test)]
pub fn wake_ready(hits: u16) -> bool {
    (hits as u64) >= PROMOTE_WAKE_HITS as u64
}

/*
 * Deadline with pinned hog extra of 8ms. The sum
 * wraps with the clock, so order stays correct
 * across wrap with no extra check.
 */
#[cfg(test)]
pub fn inflate_deadline(dl: u64) -> u64 {
    dl.wrapping_add(PINNED_INFLATE_NS)
}

/*
 * Task window state for tests. Mirrors the BPF
 * task fields used by the classifier. Group holds
 * 0 for light and 1 for hog. Low runs counts low
 * windows toward 64. Burn holds window burn. Wake
 * hits counts short blocks toward 8 at off 46.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupState {
    /* Group id. 0 is light. 1 is hog. */
    pub group: u8,
    /* Window start in nanos. Zero means none. */
    pub win_start: u64,
    /* Window burn in nanos. */
    pub burn: u32,
    /* Low windows in a row toward promote. */
    pub low_runs: u8,
    /* Short blocks in a row toward fast promote. */
    pub wake_hits: u16,
}

#[cfg(test)]
impl GroupState {
    /*
     * Cold state with light plus no window. Fresh
     * tasks join light so short waits stay quick.
     */
    pub fn cold() -> Self {
        Self {
            group: GROUP_LIGHT,
            win_start: 0,
            burn: 0,
            low_runs: 0,
            wake_hits: 0,
        }
    }

    /*
     * True when the group id is hog. Any other
     * value reads as light with no trap.
     */
    pub fn is_hog(&self) -> bool {
        self.group == GROUP_HOG
    }
}

/*
 * Add one burst to window burn with cap. The sum
 * caps at max, so long runs stay hot with no wrap
 * to low and no extra branch in callers.
 */
#[cfg(test)]
pub fn burn_add(burn: u32, delta: u64) -> u32 {
    let sum = (burn as u64).saturating_add(delta);
    if sum > u32::MAX as u64 {
        u32::MAX
    } else {
        sum as u32
    }
}

/*
 * One classifier step for tests. Mirrors the BPF
 * stopping path with burn plus wake at quiet depth.
 * Quiet wrapper around the depth step with depth 0,
 * so lone bursts keep the 4ms line with no pressure.
 * See the depth step for the full move table.
 */
#[cfg(test)]
pub fn classify_step(st: &mut GroupState, now: u64, delta: u64) -> (bool, bool) {
    classify_step_depth(st, now, delta, 0)
}

/*
 * One classifier step with light depth for tests.
 * Mirrors the BPF stopping path with burn plus wake.
 * Adds the burst to burn, then checks the allowance
 * for the depth, then wake fast promote, then window
 * end. Allowance is 4ms at depth 0 to 1, 2ms at depth
 * 2 to 3, 1ms at depth 4 plus. Eight short blocks
 * below 1ms with burn below 4ms move hog to light at
 * once. A burst at the allowance clears wake hits. A
 * short with burn at or past 4ms clears wake hits. A
 * 16ms window moves light to hog at the window end. A
 * hot window at or past 16ms clears wake hits. A low
 * window below 4ms moves the streak forward and keeps
 * wake hits. A middle window at the end clears wake
 * hits with low runs and no move. A window in progress
 * keeps wake hits. A hog needs 64 low wins near 2s or
 * 8 short hits to return to light. Allowance is
 * recomputed per stop with no new task field, so task
 * stays at 48B. Returns true for demote plus true for
 * promote when each move runs.
 */
#[cfg(test)]
pub fn classify_step_depth(st: &mut GroupState, now: u64, delta: u64, depth: u64) -> (bool, bool) {
    if st.group != GROUP_LIGHT && st.group != GROUP_HOG {
        st.group = GROUP_LIGHT;
    }
    st.burn = burn_add(st.burn, delta);
    let mut demoted = false;
    let mut promoted = false;
    if burst_hot_at(delta, burst_allowance(depth)) {
        st.wake_hits = 0;
        if st.group == GROUP_LIGHT {
            st.group = GROUP_HOG;
            st.low_runs = 0;
            st.win_start = now;
            st.burn = 0;
            demoted = true;
            return (demoted, promoted);
        }
        st.low_runs = 0;
        return (demoted, promoted);
    }
    if wake_short(delta) {
        if st.group == GROUP_HOG {
            if burn_low(st.burn) {
                let next = st.wake_hits.saturating_add(1);
                st.wake_hits = next;
                if wake_ready(next) {
                    st.group = GROUP_LIGHT;
                    st.low_runs = 0;
                    st.wake_hits = 0;
                    st.win_start = now;
                    st.burn = 0;
                    promoted = true;
                    return (demoted, promoted);
                }
            } else {
                st.wake_hits = 0;
            }
        } else {
            st.wake_hits = 0;
        }
    }
    if st.win_start == 0 {
        st.win_start = now;
        return (demoted, promoted);
    }
    if !win_ready(now, st.win_start) {
        return (demoted, promoted);
    }
    if burn_hot(st.burn) {
        st.wake_hits = 0;
        if st.group == GROUP_LIGHT {
            st.group = GROUP_HOG;
            st.low_runs = 0;
            demoted = true;
        } else {
            st.low_runs = 0;
        }
        st.win_start = now;
        st.burn = 0;
        return (demoted, promoted);
    }
    if burn_low(st.burn) {
        if st.group == GROUP_HOG {
            let next = st.low_runs.saturating_add(1);
            st.low_runs = next;
            if next >= PROMOTE_WINS {
                st.group = GROUP_LIGHT;
                st.low_runs = 0;
                st.wake_hits = 0;
                promoted = true;
            }
        } else if st.low_runs < PROMOTE_WINS {
            st.low_runs = st.low_runs.saturating_add(1);
        }
        st.win_start = now;
        st.burn = 0;
        return (demoted, promoted);
    }
    st.low_runs = 0;
    st.wake_hits = 0;
    st.win_start = now;
    st.burn = 0;
    (demoted, promoted)
}

/*
 * Group task for dispatch models. The mask names
 * allowed CPUs. The live flag marks a trusted pid
 * lookup. The fail flag models a failed move. Group
 * holds 0 for light and 1 for hog.
 */
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTask {
    /* Allowed CPUs. Index is the CPU. */
    pub allowed: Vec<bool>,
    /* False models a NULL pid lookup. */
    pub live: bool,
    /* True models a failed queue move. */
    pub fail: bool,
    /* Group id. 0 is light. 1 is hog. */
    pub group: u8,
}

/*
 * True when one group task may move to the thief.
 * Needs a live task with no move failure plus the
 * CPU in the mask plus the same group. Tier 0 model
 * only. BPF ships Tier 3 park only by construction
 * with no task recheck due to verifier jump at 1000001
 * on donor check, so a stale cross entry may move iff
 * ready is one with strict park iff ready is zero and
 * best effort peer across groups. Pinned single tasks
 * with one allowed CPU may cross with an inflated
 * deadline, so the caller checks that path before this
 * strict check. Exiting tasks use the same rule with no
 * extra path.
 */
#[cfg(test)]
pub fn group_task_ok(thief: i32, thief_group: u8, task: &GroupTask) -> bool {
    if !task.live || task.fail {
        return false;
    }
    let g = if task.group == GROUP_HOG {
        GROUP_HOG
    } else {
        GROUP_LIGHT
    };
    if g != thief_group {
        return false;
    }
    crate::flow_select::may_run_on(thief, &task.allowed)
}

/*
 * Drain up to budget group tasks for one CPU. Tier 0
 * model only. BPF ships Tier 3 park only by
 * construction with no task recheck due to verifier jump
 * at 1000001 on donor check, so a stale cross entry may
 * move iff ready is one with strict park iff ready is
 * zero and best effort peer across groups. The scan
 * keeps order and moves each task that passes the
 * strict group check. Dead, foreign, failed, and cross
 * group heads stay, so one head never blocks later
 * work. Returns moved plus skipped where skipped counts
 * cross group heads on mask pass. The model keeps both
 * drains plus merged skip. BPF Tier 3 uses park only by
 * construction with halves due to verifier jump at
 * 1000001 with peer mask only.
 */
#[cfg(test)]
pub fn group_drain_model(
    queue: &mut std::collections::VecDeque<GroupTask>,
    cpu: i32,
    thief_group: u8,
    budget: u32,
) -> (u32, u32) {
    let mut moved = 0;
    let mut skipped = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let g = if task.group == GROUP_HOG {
            GROUP_HOG
        } else {
            GROUP_LIGHT
        };
        let same = g == thief_group;
        let ok = moved < budget
            && task.live
            && !task.fail
            && same
            && crate::flow_select::may_run_on(cpu, &task.allowed);
        if ok {
            moved += 1;
        } else {
            if task.live
                && !task.fail
                && !same
                && crate::flow_select::may_run_on(cpu, &task.allowed)
            {
                skipped += 1;
            }
            kept.push_back(task);
        }
    }
    *queue = kept;
    (moved, skipped)
}

/*
 * First allowed CPU in one group for tests. Scans
 * in id order and returns the first live CPU that
 * allows the task. Halves is the fallback. Returns
 * none when no allowed CPU lives in the group.
 */
#[cfg(test)]
pub fn first_in_group(allowed: &[bool], group: u8, nr: usize) -> Option<u32> {
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != group {
            continue;
        }
        if let Some(true) = allowed.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * First allowed CPU in one live group for tests.
 * Scans in id order with the table when ready, else
 * halves. Returns none when no allowed CPU lives in
 * the group.
 */
#[cfg(test)]
pub fn first_in_group_live(
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
) -> Option<u32> {
    for cpu in 0..nr {
        if group_live(cpu as u32, nr, table, ready) != group {
            continue;
        }
        if let Some(true) = allowed.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * Least queued allowed CPU in one group for tests.
 * Scans 0 to nr in id order with halves, so the
 * bound matches the BPF first helper. Needs group
 * plus mask plus queued depth. Picks the smallest
 * queued depth with lowest id on ties by strict
 * less only, so equal depths keep the first id.
 * Missing queued entries read as zero, so short
 * slices stay quiet with no trap. Returns none
 * when no allowed CPU lives in the group. Mirrors
 * the BPF least scan with halves view and frozen
 * constants.
 */
#[cfg(test)]
pub fn least_in_group(allowed: &[bool], group: u8, nr: usize, queued: &[u64]) -> Option<u32> {
    let mut best: Option<u32> = None;
    let mut best_q: u64 = 0;
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != group {
            continue;
        }
        if allowed.get(cpu).copied().unwrap_or(false) != true {
            continue;
        }
        let q = queued.get(cpu).copied().unwrap_or(0);
        match best {
            None => {
                best = Some(cpu as u32);
                best_q = q;
            }
            Some(_) if q < best_q => {
                best = Some(cpu as u32);
                best_q = q;
            }
            _ => {}
        }
    }
    best
}

/*
 * Least queued allowed CPU in one live group for
 * tests. Scans 0 to nr in id order with the table
 * when ready, else halves, so the bound matches the
 * BPF first helper used by select plus enqueue.
 * Needs live group plus mask plus queued depth.
 * Picks the smallest queued depth with lowest id
 * on ties by strict less only. Missing queued
 * entries read as zero with no trap. Returns none
 * when no allowed CPU lives in the group. Placement
 * keeps live, dispatch keeps halves, constants
 * frozen. Mirrors the BPF least scan.
 */
#[cfg(test)]
pub fn least_in_group_live(
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
    queued: &[u64],
) -> Option<u32> {
    let mut best: Option<u32> = None;
    let mut best_q: u64 = 0;
    for cpu in 0..nr {
        if group_live(cpu as u32, nr, table, ready) != group {
            continue;
        }
        if allowed.get(cpu).copied().unwrap_or(false) != true {
            continue;
        }
        let q = queued.get(cpu).copied().unwrap_or(0);
        match best {
            None => {
                best = Some(cpu as u32);
                best_q = q;
            }
            Some(_) if q < best_q => {
                best = Some(cpu as u32);
                best_q = q;
            }
            _ => {}
        }
    }
    best
}
