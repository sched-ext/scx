// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// scx_panda CPU TOPOLOGY
// READS SYSFS ONCE AT STARTUP AND ON HOTPLUG, COMPUTES THE R_eff TABLES, THE
// DOMAIN TREE AND tau, AND FILLS THE BPF MAPS. THIS IS THE CONTENT OF THE
// ALLOCATION THE LOADER MAKES; NOTHING HERE RUNS WHILE THE SCHEDULER RUNS.

use anyhow::Result;

use crate::scheduler::Scheduler;

// FIEDLER-VALUE / TOPOLOGY TIME CONSTANT
// lambda_2 IS THE SECOND-SMALLEST EIGENVALUE OF THE WEIGHTED GRAPH LAPLACIAN
// (THE "ALGEBRAIC CONNECTIVITY" OR "SPECTRAL GAP"). 1/lambda_2 IS THE MIXING
// TIME OF A RANDOM WALK ACROSS THE CPU GRAPH -- A CANONICAL "TIME CONSTANT"
// FOR HOW FAST WORK PROPAGATES ACROSS THE TOPOLOGY. EVERY TIMING/THRESHOLD
// FORMULA IN THE SCHEDULER DERIVES FROM tau VIA scale_tau() (BPF) OR
// scale_tau_u64() (RUST); ad-hoc nr_cpus FORMULAS ARE CRUDE APPROXIMATIONS
// OF THIS AND ARE EXPLICITLY MIGRATED OUT.
//
// CARVE-OUT: ONLY ABSOLUTE-COUNT QUANTITIES KEEP nr_cpu_ids. GRAPH-SHAPE
// QUANTITIES, SEARCH BUDGETS INCLUDED, GO THROUGH tau VIA
// lambda_2 = TAU_SCALE_NS / tau. TWO SITES IN main.bpf.c KEEP nr_cpu_ids:
//   select_cpu()'s wake_wide THRESHOLD, WHICH MATCHES A KERNEL CONVENTION
//   tick()'s ROTATING-SCAN BUDGET, WHICH IS COVERAGE, NOT GRAPH SHAPE
//
// EXTRACTION IS O(n log n) ON TOP OF THE EXISTING O(n^3) JACOBI.
// REFERENCE: CHEEGER'S INEQUALITY BOUNDS lambda_2 AGAINST GRAPH BOTTLENECK.
pub const LAMBDA_ZERO_EPS: f64 = 1e-8;
const TAU_SCALE_NS: f64 = 1.6e8; // 160MS. CAPACITY-AWARE ANCHOR: AT THE
// 12C REFERENCE (lambda_2=12, N=12)
// tau = 160ms / sqrt(144) = 13.3MS.
pub const TAU_FLOOR_NS: u64 = 1_000_000; //  1MS
pub const TAU_CEIL_NS: u64 = 40_000_000; // 40MS

// THE OSCILLATOR'S WORKING BAND, MIRRORING K_CODEL_FLOOR AND K_CODEL_MAX IN
// main.bpf.c. c_eq IS A POSITION INSIDE THIS BAND, SO IT NEEDS NO CLAMP OF ITS
// OWN -- SEE compute_codel_eq_ns.
const K_CODEL_FLOOR_Q16: f64 = 1147.0; // 0.0175 * tau
const K_CODEL_MAX_Q16: f64 = 3277.0; // 0.05   * tau
const Q16: f64 = 65536.0;

// THE BAND AS apply_tau_scaling() DERIVES IT, (FLOOR, SPAN) IN NS: THE FLOOR
// IS K_CODEL_FLOOR * tau AND NEVER UNDER CODEL_FLOOR_MIN_NS, AND WHERE THAT
// RAIL BINDS THE SPAN IS THE RAIL'S AT THE BAND'S OWN RATIO, K_CODEL_MAX OVER
// K_CODEL_FLOOR. tau FALLS AS THE CPU COUNT RISES, AND ON A LARGE PART THE
// RAIL IS THE FLOOR: AN EQUILIBRIUM PLACED IN THE UNRAILED BAND LAY UNDER IT
// AND WAS CLAMPED ONTO THE FLOOR, WHERE THE SPRING PUSHES ONE WAY ONLY.
fn codel_window(tau_ns: u64) -> (f64, f64) {
    let floor_ns = (K_CODEL_FLOOR_Q16 / Q16) * tau_ns as f64;
    let rail_ns = crate::bpf_intf::CODEL_FLOOR_MIN_NS as f64;
    if floor_ns < rail_ns {
        (
            rail_ns,
            rail_ns * (K_CODEL_MAX_Q16 / K_CODEL_FLOOR_Q16 - 1.0),
        )
    } else {
        (
            floor_ns,
            ((K_CODEL_MAX_Q16 - K_CODEL_FLOOR_Q16) / Q16) * tau_ns as f64,
        )
    }
}

// THE L2, L3, SOCKET AND DOMAIN ID OF AN OFFLINE CPU: ONE NO ONLINE CPU HAS.
// THE GRAPH IS BUILT OVER THE ONLINE CPUs, SO NOTHING READS IT AS A GROUP.
pub const OFFLINE_ID: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
pub struct TopologySpectrum {
    pub fiedler: f64,     // lambda_2
    pub tau_ns: u64,      // clamped TAU_SCALE_NS / sqrt(fiedler * N)
    pub codel_eq_ns: u64, // A POSITION IN THE BAND codel_window() GIVES,
    // SET BY THE SPECTRAL-GAP DEFICIT. NO CLAMP.
    // Phi migration-potential distance->wait scale (Q16). The extra head-wait a
    // steal must clear before crossing to a peer = (reff * this) >> 16 ns. Always
    // computed now (T1): the continuous metric prices distance on every part, no
    // binary topology gate -- on a monolithic part it calibrates to the L2 seam.
    pub phi_dist_scale_q16: u64,
}

// T2: the emergent domain tree. Leaves are tightly-coupled CPU sets (an L2 group
// / core -- nothing meaningful to partition below); internal nodes are a
// min-conductance cut carrying its phi, the price to cross that seam. T3's
// bounded-local steal climbs this tree: drain your leaf, then your subtree,
// crossing a cut only when its phi says the imbalance pays. The discrete cache domain
// enum is gone -- this structure emerges from the cache graph, per machine.
#[derive(Debug, Clone)]
pub enum DomainNode {
    Leaf(Vec<usize>),
    Cut {
        phi: f64,
        left: Box<DomainNode>,
        right: Box<DomainNode>,
    },
}

impl DomainNode {
    // Flatten to the leaf CPU sets -- each an emergent atomic domain.
    pub fn leaves(&self) -> Vec<Vec<usize>> {
        match self {
            DomainNode::Leaf(cpus) => vec![cpus.clone()],
            DomainNode::Cut { left, right, .. } => {
                let mut v = left.leaves();
                v.extend(right.leaves());
                v
            }
        }
    }

    // Every cut's phi -- the crossing-price ladder (coarser seams cost less, so
    // phi rises with depth as the steal climbs toward more tightly-coupled work).
    pub fn cut_phis(&self) -> Vec<f64> {
        match self {
            DomainNode::Leaf(_) => Vec::new(),
            DomainNode::Cut { phi, left, right } => {
                let mut v = vec![*phi];
                v.extend(left.cut_phis());
                v.extend(right.cut_phis());
                v
            }
        }
    }
}

pub fn extract_fiedler(eigenvalues: &[f64]) -> f64 {
    // Jacobi RETURNS EIGENVALUES UNSORTED. FOR A CONNECTED LAPLACIAN THE
    // SMALLEST EIGENVALUE IS 0 (SKIPPED VIA LAMBDA_ZERO_EPS). FOR A
    // DISCONNECTED GRAPH (HOTPLUG PARTITION) SEVERAL EIGENVALUES ARE ~0;
    // lambda_2 IS THE SMALLEST STRICTLY POSITIVE ONE.
    let mut v: Vec<f64> = eigenvalues.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v.into_iter()
        .find(|&x| x > LAMBDA_ZERO_EPS)
        .unwrap_or(LAMBDA_ZERO_EPS)
}

fn compute_tau_ns(fiedler: f64, n: usize) -> u64 {
    // CAPACITY-AWARE: tau = TAU_SCALE_NS / sqrt(lambda_2 * N) -- the geometric
    // mean of connectivity (1/lambda_2) and capacity (1/sqrt(N)). The old
    // pure-connectivity law gave a well-connected but capacity-starved
    // topology (a 2-core L2 pair, lambda_2=20) a tiny tau (8ms) and thus tight
    // tolerances exactly where scarce CPUs need loose ones -- which the
    // apply_tau_scaling floors then patched back up. sqrt(N) penalizes small N,
    // so 2C loosens to ~25ms with no floor needed. The 12C reference is
    // preserved: lambda_2=12, N=12 -> sqrt(144)=12 -> 160ms/12 = 13.3ms.
    let denom = (fiedler.max(LAMBDA_ZERO_EPS) * (n.max(1) as f64)).sqrt();
    let raw = TAU_SCALE_NS / denom.max(LAMBDA_ZERO_EPS);
    (raw as u64).clamp(TAU_FLOOR_NS, TAU_CEIL_NS)
}

// CoDel TARGET EQUILIBRIUM FROM THE LAPLACIAN SPECTRUM.
//   s    = 1 - lambda_2 * Tr(L+) / (N - 1)
//   c_eq = (K_CODEL_FLOOR + (K_CODEL_MAX - K_CODEL_FLOOR) * s) * tau
//
// s IS THE NORMALISED SPECTRAL-GAP DEFICIT. lambda_2 * Tr(L+) / (N-1) is
// lambda_2 over the HARMONIC MEAN of the positive eigenvalues: 1 on a flat
// spectrum, where no cut is worse than any other, falling toward 1/(N-1) when
// lambda_2 sits far below every other cut. So s measures HOW MUCH WORSE THE
// BOTTLENECK IS THAN THE GRAPH'S TYPICAL CONNECTIVITY, which is the quantity
// "how long should work be tolerated not moving" keys on. Cheeger already ties
// lambda_2 to that bottleneck, so this reads the same object the tau law uses.
//
// IT IS A POSITION IN THE BAND, NOT A QUANTITY CLAMPED INTO ONE. Tr(L+) >=
// 1/lambda_2 bounds s at 0 and Tr(L+) <= (N-1)/lambda_2 bounds it at
// 1 - 1/(N-1), so c_eq lands inside the band codel_window() gives, which is
// the window main.bpf.c derives, and its re-clamp into that window never fires.
// THAT IS THE POINT: an equilibrium equal to the band's ceiling gives the
// oscillator a spring that can only push one way.
//
// THE ENDS. A 2-CPU graph has exactly one positive eigenvalue, so s is 0 and
// the target sits at the floor -- two CPUs have no far tier and stalls should
// be caught as hard as the band allows. An SMT part, where a stiff sibling edge
// sits beside a weak cross-domain cut, reads s ~0.72 and tolerates longer.
fn compute_codel_eq_ns(eigenvalues: &[f64], n: usize, tau_ns: u64) -> u64 {
    let (floor_ns, _) = codel_window(tau_ns);
    if n < 2 {
        return floor_ns as u64;
    }
    let mut sum_inv_lambda = 0.0f64;
    let mut n_pos = 0usize;
    let mut lambda_2 = f64::MAX;
    for &lambda in eigenvalues {
        if lambda > LAMBDA_ZERO_EPS {
            sum_inv_lambda += 1.0 / lambda;
            n_pos += 1;
            if lambda < lambda_2 {
                lambda_2 = lambda;
            }
        }
    }
    // A DISCONNECTED OR DEGENERATE GRAPH HAS NO GAP TO READ. Fall to the floor,
    // which is the tightest the band allows and the safe direction for a
    // topology this cannot describe.
    if n_pos == 0 || lambda_2 == f64::MAX || sum_inv_lambda <= 0.0 {
        return floor_ns as u64;
    }
    codel_eq_at(lambda_2, sum_inv_lambda, n, tau_ns)
}

// THE SAME POSITION FROM lambda_2 AND Tr(L+) DIRECTLY, FOR THE SOLVER THAT HAS
// THEM WITHOUT THE REST OF THE SPECTRUM.
fn codel_eq_at(lambda_2: f64, sum_inv_lambda: f64, n: usize, tau_ns: u64) -> u64 {
    let (floor_ns, span_ns) = codel_window(tau_ns);
    if n < 2 || lambda_2 <= 0.0 || sum_inv_lambda <= 0.0 {
        return floor_ns as u64;
    }
    let s = (1.0 - lambda_2 * sum_inv_lambda / (n - 1) as f64).clamp(0.0, 1.0);
    (floor_ns + span_ns * s) as u64
}

// THE FOUR PER-SLOT TABLES, AS THE MAPS HOLD THEM. SEE affinity_tables.
pub struct AffinityTables {
    pub rank: Vec<u32>,
    pub value: Vec<u32>,
    pub frac: Vec<u32>,
    pub phi: Vec<u32>,
}

pub struct CpuTopology {
    pub nr_cpus: usize,      // POSSIBLE CPUs; EVERY PER-CPU TABLE IS INDEXED BY CPU ID
    pub online: Vec<usize>,  // ONLINE CPU IDS, ASCENDING. THE GRAPH'S VERTICES
    pub l2_domain: Vec<u32>, // l2_domain[cpu] = group_id
    pub l2_groups: Vec<Vec<u32>>, // l2_groups[group_id] = [cpu, ...]
    pub socket_domain: Vec<u32>, // socket_domain[cpu] = socket_id
    pub llc_domain: Vec<u32>, // llc_domain[cpu] = L3 GROUP (== socket WHEN MONOLITHIC)
    pub nr_sockets: u32,
}

impl CpuTopology {
    pub fn detect(nr_cpus: usize) -> Result<Self> {
        // TWO-PASS L2 DETECTION: A SINGLE PASS HAS TWO DEFECT CLASSES ON THE
        // SYSFS-FAILURE PATH (THE NORMAL CASE FOR OFFLINE CPUs AND UNDER
        // QEMU/KVM):
        //   1. CPU-0 ALIASING: A FAILED READ THAT ASSIGNS l2_domain[cpu] = cpu
        //      AS A SYNTHETIC ID NEVER REGISTERED IN l2_groups CAN COLLIDE
        //      WITH A REAL GROUP ID, AND cache_domain THEN FILES THAT CPU IN
        //      ANOTHER GROUP'S L2.
        //   2. ORDER DEPENDENCE: IF cpu A's READ TRANSIENTLY FAILS BUT cpu B's
        //      SUCCEEDS AND LISTS A AS A GENUINE SIBLING ("A,B"), THE TWO ARE
        //      NEVER UNIFIED -- AN ARTIFACT OF PROCESSING ORDER ALONE.
        // PASS 1 BUILDS THE REAL GROUPS FROM EVERY SUCCESSFUL READ; PASS 2
        // PLACES THE FAILURES -- JOINING A GROUP THAT ALREADY LISTS THEM, ELSE
        // A REGISTERED SINGLETON GROUP WITH A COLLISION-FREE SEQUENTIAL ID.
        //
        // ONLY THE ONLINE CPUs ARE READ. AN OFFLINE CPU HAS NO cache OR
        // topology DIRECTORY IN SYSFS, AND A WIDTH MADE BY TAKING CPUs OFFLINE
        // (OR SMT DISABLED BY THE KERNEL) LEAVES HALF OF THE POSSIBLE CPUs THAT
        // WAY: READ FOR EVERY POSSIBLE CPU, THE FIRST MISSING index3 DROPPED
        // THE L3 SPLIT FOR THE WHOLE MACHINE.
        let online = Self::online_cpus(nr_cpus);
        let mut l2_domain = vec![OFFLINE_ID; nr_cpus];
        let mut seen_groups: Vec<Vec<u32>> = Vec::new();

        for &cpu in &online {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index2/shared_cpu_list",
                cpu
            );
            let content = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue, // placed in pass 2
            };

            let members = parse_cpu_list(content.trim());

            // CHECK IF THIS GROUP ALREADY EXISTS
            let group_id = match seen_groups.iter().position(|g| *g == members) {
                Some(id) => id as u32,
                None => {
                    let id = seen_groups.len() as u32;
                    seen_groups.push(members.clone());
                    id
                }
            };

            l2_domain[cpu] = group_id;
        }
        for &cpu in &online {
            if l2_domain[cpu] != OFFLINE_ID {
                continue;
            }
            if let Some(id) = seen_groups.iter().position(|g| g.contains(&(cpu as u32))) {
                l2_domain[cpu] = id as u32;
            } else {
                let id = seen_groups.len() as u32;
                seen_groups.push(vec![cpu as u32]);
                l2_domain[cpu] = id;
            }
        }

        // DETECT SOCKET (PHYSICAL PACKAGE)
        let mut socket_domain = vec![OFFLINE_ID; nr_cpus];
        let mut seen_sockets: Vec<u32> = Vec::new();

        for &cpu in &online {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/topology/physical_package_id",
                cpu
            );
            let pkg_id = match std::fs::read_to_string(&path) {
                Ok(s) => s.trim().parse::<u32>().unwrap_or(0),
                Err(_) => 0,
            };
            if !seen_sockets.contains(&pkg_id) {
                seen_sockets.push(pkg_id);
            }
            let socket_idx = seen_sockets.iter().position(|&s| s == pkg_id).unwrap() as u32;
            socket_domain[cpu] = socket_idx;
        }

        let nr_sockets = seen_sockets.len() as u32;

        // DETECT L3 / cache domain / cache domain DOMAIN (index3). ON AMD multi-domain PARTS index3
        // SUBDIVIDES THE SOCKET INTO cache domain GROUPS; ON MONOLITHIC-L3 PARTS IT
        // SPANS THE WHOLE SOCKET. USE THE TIER ONLY WHEN IT GENUINELY
        // SUBDIVIDES A SOCKET (MORE L3 GROUPS THAN SOCKETS) AND index3 WAS
        // PRESENT FOR EVERY ONLINE CPU; OTHERWISE llc_domain == socket_domain
        // SO THE CROSS-DOMAIN RUNG IN build_laplacian NEVER FIRES (EXACT NO-OP).
        let mut llc_domain = vec![OFFLINE_ID; nr_cpus];
        let mut seen_llc: Vec<Vec<u32>> = Vec::new();
        let mut llc_ok = true;
        for &cpu in &online {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index3/shared_cpu_list",
                cpu
            );
            let content = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => {
                    llc_ok = false;
                    break;
                }
            };
            let members = parse_cpu_list(content.trim());
            let group_id = match seen_llc.iter().position(|g| *g == members) {
                Some(id) => id as u32,
                None => {
                    let id = seen_llc.len() as u32;
                    seen_llc.push(members);
                    id
                }
            };
            llc_domain[cpu] = group_id;
        }
        // THE L3 SPLITS THE SOCKET ONLY WHEN THERE ARE MORE L3 GROUPS THAN
        // SOCKETS; OTHERWISE THE SOCKET IS THE DOMAIN.
        let llc_subdivides = llc_ok && seen_llc.len() > nr_sockets as usize;
        if !llc_subdivides {
            llc_domain = socket_domain.clone();
        }

        Ok(Self {
            nr_cpus,
            online,
            l2_domain,
            l2_groups: seen_groups,
            socket_domain,
            llc_domain,
            nr_sockets,
        })
    }

    // THE ONLINE CPUs UNDER nr_cpus, ASCENDING, UNPRIVILEGED READ. None WHEN
    // THE LIST CANNOT BE READ OR IS EMPTY. THE HOTPLUG POLL'S CHANGE SIGNAL.
    pub fn read_online(nr_cpus: usize) -> Option<Vec<usize>> {
        let text = std::fs::read_to_string("/sys/devices/system/cpu/online").ok()?;
        let list: Vec<usize> = parse_cpu_list(text.trim())
            .into_iter()
            .map(|c| c as usize)
            .filter(|&c| c < nr_cpus)
            .collect();
        if list.is_empty() { None } else { Some(list) }
    }

    // THE GRAPH'S VERTICES. AN UNREADABLE LIST FALLS BACK TO EVERY POSSIBLE CPU.
    pub fn online_cpus(nr_cpus: usize) -> Vec<usize> {
        Self::read_online(nr_cpus).unwrap_or_else(|| (0..nr_cpus).collect())
    }

    // DETECT-AND-POPULATE, THE ONE STARTUP/HOTPLUG SEQUENCE. ALL RUST-SIDE
    // COMPUTATION RUNS BEFORE ANY OF THE MAP WRITES: THERE IS NO CROSS-MAP
    // TRANSACTION PRIMITIVE IN eBPF, SO THE EXPOSURE WHILE MAPS DISAGREE IS
    // BOUNDED BY WRITE TIME ALONE. WRITE ORDER: cache_domain, THE AFFINITY-RANK
    // FAMILY, cpu_domain, AND topo LAST, ITS GENERATION LAST OF ALL -- THE "GO"
    // SIGNAL THAT TRIGGERS BPF'S OWN RE-DERIVATION OF EVERYTHING topo FEEDS.
    pub fn detect_and_populate(sched: &mut Scheduler, nr_cpus: usize) -> Result<TopologySpectrum> {
        let topo = Self::detect(nr_cpus)?;
        topo.log_summary();
        let (reff, rank, spectrum) = topo.compute_resistance_affinity();
        topo.log_resistance_affinity(&reff, &rank, spectrum);
        let domains = topo.compute_domain_tree();
        topo.log_domains(&domains);
        let domain_phi = topo.domain_cross_phi_matrix(&domains);
        let nr_domains = topo.domain_count();
        let cpu_dom = topo.domain_partition(&domains, nr_domains);
        let dom_peers = topo.min_in_domain_peers(&rank, &cpu_dom);

        let tables = topo.affinity_tables(
            &reff,
            &rank,
            spectrum.phi_dist_scale_q16,
            spectrum.codel_eq_ns,
            &domain_phi,
        );

        if let Err(e) = sched.write_cache_domains(&topo.l2_domain) {
            log_warn!("CACHE TOPOLOGY MAP WRITE FAILED: {}", e);
        }
        if let Err(e) = sched.write_affinity_tables(&tables) {
            log_warn!("AFFINITY RANK MAP WRITE FAILED: {}", e);
        }
        if let Err(e) = sched.write_cpu_domains(&cpu_dom) {
            log_warn!("CPU DOMAIN MAP WRITE FAILED: {}", e);
        }
        log_info!("DOMAINS: {} (emergent, cpu_domain populated)", nr_domains);
        log_info!(
            "AFFINITY DOMAIN PEERS: {} (min over CPUs; bounds the \
                   idle-search floor)",
            dom_peers
        );
        if let Err(e) = sched.write_topo(
            spectrum.tau_ns,
            spectrum.codel_eq_ns,
            nr_domains as u32,
            dom_peers,
        ) {
            log_warn!("TOPOLOGY WRITE FAILED: {}", e);
        }
        Ok(spectrum)
    }

    // HOTPLUG POLL: COMPARE THE ONLINE CPU LIST AGAINST THE LAST ONE SEEN, AND
    // ON A CHANGE RE-RUN THE WHOLE DETECT-AND-POPULATE, SO EVERY R_eff, phi AND
    // DOMAIN TABLE TRACKS THE LIVE SET. THE LIST AND NOT ITS LENGTH: ONE CPU
    // GOING DOWN AS ANOTHER COMES UP INSIDE A POLL LEAVES THE COUNT WHERE IT WAS.
    // RETURNS TRUE WHEN IT FIRED.
    pub fn poll_hotplug(
        sched: &mut Scheduler,
        nr_cpus: usize,
        last_online: &mut Vec<usize>,
    ) -> bool {
        let Some(now) = Self::read_online(nr_cpus) else {
            return false;
        };
        if now == *last_online {
            return false;
        }
        log_info!(
            "HOTPLUG: online CPUs {} -> {} -- re-deriving topology",
            last_online.len(),
            now.len()
        );
        *last_online = now;
        if let Err(e) = Self::detect_and_populate(sched, nr_cpus) {
            log_warn!("HOTPLUG TOPOLOGY RE-DETECT FAILED: {}", e);
        }
        true
    }

    // RESISTANCE AFFINITY. EFFECTIVE RESISTANCE R_eff(u,v) IS THE MIGRATION COST
    // BETWEEN TWO CPUs THROUGH ALL TOPOLOGY PATHS, FROM THE LAPLACIAN
    // PSEUDOINVERSE OF THE CPU GRAPH:
    //   L  = D - W          DEGREE MINUS WEIGHTED ADJACENCY
    //   L+ = sum_{lambda_i > 0} (1/lambda_i) * v_i * v_i^T
    //   R_eff(i,j) = L+[i,i] + L+[j,j] - 2*L+[i,j]
    //
    // EDGE CONDUCTANCES, THE INVERSE OF RESISTANCE:
    //   L2 SIBLINGS          10.0   SHARED L2, NEAR-ZERO MIGRATION COST
    //   SAME L3              3.0    SHARED LLC
    //   CROSS-DOMAIN SOCKET  1.0    INTERCONNECT HOP, ~8x CORE-TO-CORE LATENCY
    //   CROSS-SOCKET         0.3    NUMA HOP
    // THE SAME-DOMAIN RUNG IS RAISED RATHER THAN THE CROSS-DOMAIN CUT LOWERED, SO
    // SAME-L3 PEERS RANK AHEAD OF CROSS-L3 ONES WITHOUT MOVING lambda_2 -- THE
    // CROSS-L3 CUT STAYS 1.0 AND tau AND codel_eq ARE UNCHANGED. ON A MONOLITHIC
    // PART THE L3 RUNG COINCIDES WITH THE SOCKET RUNG.
    //
    // THE EIGENSOLVE SERVES UP TO WALK_CUT_THRESHOLD CPUs AND ONE CHOLESKY
    // FACTOR, O(n^3), THE PARTS PAST IT.
    // REFERENCE: RESISTANCE DISTANCE IS KLEIN AND RANDIC (J. MATH. CHEM.
    //            1993); ALGEBRAIC CONNECTIVITY AND ITS EIGENVECTOR ARE
    //            FIEDLER (CZECH. MATH. J. 1973); THE SOLVERS FOLLOW
    //            Christiano-Kelner-Madry-Spielman-Teng (STOC 2011) AND
    //            Chen-Kyng-Liu-Peng-Gutenberg-Sachdeva (FOCS 2022)

    // STIFF L2 RUNG: SMT siblings SHARE L2, so a move between them costs ~0 cache.
    // Make the edge very stiff -> R_eff(SMT-sib) ~ 0, which lands the Phi migration
    // barrier exactly at the physical-core / L2 boundary (a real cold-L2 refill)
    // instead of penalizing free intra-core moves. lambda_2 is the cross-domain Fiedler
    // cut (independent of L2 stiffness) so tau is unchanged, and codel_eq is already
    // clamped at its ceiling, so the oscillator timescales are invariant.
    const CONDUCTANCE_L2: f64 = 1000.0; // L2 / SMT SIBLINGS
    const CONDUCTANCE_LLC: f64 = 3.0; // SAME L3 (ABOVE SOCKET; always-on rung)
    const CONDUCTANCE_SOCKET: f64 = 1.0; // SAME SOCKET, CROSS-DOMAIN (IF HOP) -- OR MONOLITHIC SAME-SOCKET
    const CONDUCTANCE_CROSS: f64 = 0.3; // CROSS-SOCKET NUMA HOP

    // INTEGER MIRROR OF THE RUNGS ABOVE, x10 SO THE 0.3 CROSS-SOCKET CUT CLEARS
    // TO AN INTEGER (SPILL-Phi). SAME RATIOS AS THE f64 TABLE --
    // INCLUDING THE STIFF L2 RUNG -- SO THE EXACT AND FLOAT PATHS PRICE THE
    // SAME GRAPH. THE STIFF L2 RUNG (10000) GROWS BAREISS INTERMEDIATES FAST:
    // i128 HOLDS THE DETERMINANTS TO ROUGHLY 8 CPUs ON AN SMT PART AND THE
    // checked_mul GUARD FALLS BACK TO THE FLOAT PSEUDOINVERSE ABOVE THAT --
    // EXACT WHERE INTEGERS HOLD, FLOAT WHERE THEY DON'T, BY CONSTRUCTION.
    const ICOND_L2: i128 = 10000;
    const ICOND_LLC: i128 = 30;
    const ICOND_SOCKET: i128 = 10;
    const ICOND_CROSS: i128 = 3;
    const ICOND_RECOVER: f64 = 10.0; // undo the x10 conductance scale
    const REFF_EXACT_MAX_CPUS: usize = 24;

    // SPILL-Phi PLACEMENT DEPTH THRESHOLDS. RUST FOLDS R_eff INTO A PER-PEER
    // DSQ-DEPTH CAP THE BPF SPILL HELPER APPLIES: NEAR PEERS (R_eff~0) ACCEPT
    // SPILLS UP TO SPILL_NEAR_DEPTH, THE MOST DISTANT ONLY WHEN NEAR-EMPTY
    // (SPILL_FAR_DEPTH). MONOLITHIC (NO DISTANCE STRUCTURE TO PRICE) -> FLAT
    // SPILL_MONO_DEPTH.
    // FAR_DEPTH=1 IS THE SHIPPED SETTING: THE STRICT FORM -- A FAR PEER TAKES
    // A SPILL ONLY WHEN EMPTY. MEASURED ON IT: LOCALITY 77.9% CACHE-LOCAL AT
    // 86k MIGRATIONS/s, LONGRUN p99 0.58x VS THE ARCHIVED PEAK, ipc NEUTRAL;
    // AN UNPROVEN BURST/MIXED DRIFT (~1.2x, p >= 0.67 AT N=2) IS TRACKED,
    // WITH A FAR_DEPTH=2 A/B QUEUED IN ROADMAP.md. CHANGE THIS VALUE ONLY
    // WITH THAT A/B IN HAND.

    // BUILD WEIGHTED GRAPH LAPLACIAN FROM CPU TOPOLOGY
    // Conductance edge weight between two CPUs, derived from the cache hierarchy.
    // The single source of truth for BOTH the Laplacian (R_eff / tau) and the
    // domain cut below, so the emergent locality boundary and the placement metric
    // price the exact same graph -- the continuous metric drives everything.
    fn conductance(&self, i: usize, j: usize) -> f64 {
        if self.l2_domain[i] == self.l2_domain[j] {
            Self::CONDUCTANCE_L2
        } else if self.llc_domain[i] == self.llc_domain[j] {
            Self::CONDUCTANCE_LLC
        } else if self.socket_domain[i] == self.socket_domain[j] {
            Self::CONDUCTANCE_SOCKET
        } else {
            Self::CONDUCTANCE_CROSS
        }
    }

    // m x m OVER THE ONLINE CPUs: ROW AND COLUMN k ARE CPU online[k].
    // THE CACHE RUNG TWO CPUs SHARE, NEAREST FIRST: 0 AN L2, 1 AN L3, 2 A
    // SOCKET, 3 NOTHING. THE SAME LADDER conductance() PRICES.
    fn rung(&self, i: usize, j: usize) -> u8 {
        if self.l2_domain[i] == self.l2_domain[j] {
            0
        } else if self.llc_domain[i] == self.llc_domain[j] {
            1
        } else if self.socket_domain[i] == self.socket_domain[j] {
            2
        } else {
            3
        }
    }

    pub fn build_laplacian(&self) -> Vec<f64> {
        let n = self.online.len();
        let mut l = vec![0.0f64; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let w = self.conductance(self.online[i], self.online[j]);
                l[i * n + j] = -w;
                l[j * n + i] = -w;
                l[i * n + i] += w;
                l[j * n + j] += w;
            }
        }
        l
    }

    // ---- T2: emergent domain cut (SOSA min-conductance) --------------------
    // The discrete cache domain layer is replaced by domains that EMERGE from the
    // cache graph. The boundary is the min-conductance cut: phi = cut_weight /
    // min(vol_a, vol_b). Low phi = a loosely-coupled seam = a real domain edge;
    // the phi of the cut IS the cross-domain crossing price (THE FLAG: the price
    // draws the boundary, no gate). Balance-free -- the seam falls where the
    // silicon divides (asymmetric X3D / P+E included), not where volume balances.

    // Conductance phi of a bipartition of `members` (in_side[c] = c is on side A).
    // O(|members|^2); boot-time only. The random-walk variant (next) avoids the
    // full scan for large N -- this exact form is the ground-truth + the price.
    fn cut_conductance(&self, members: &[usize], in_side: &[bool]) -> f64 {
        let mut cut = 0.0f64;
        let (mut vol_a, mut vol_b) = (0.0f64, 0.0f64);
        for &a in members {
            for &b in members {
                if a == b {
                    continue;
                }
                let w = self.conductance(a, b);
                if in_side[a] {
                    vol_a += w;
                } else {
                    vol_b += w;
                }
                if in_side[a] != in_side[b] {
                    cut += w; // each crossing edge counted twice (a,b and b,a)
                }
            }
        }
        cut /= 2.0;
        let denom = vol_a.min(vol_b);
        if denom <= 0.0 {
            f64::INFINITY
        } else {
            cut / denom
        }
    }

    // Fiedler vector (eigenvector of lambda_2) of the full graph -- the ground
    // truth the scalable random-walk cut is cross-checked against. eigenvectors
    // are column-major: component i of eigenvector k is eigenvectors[i*n + k].
    fn fiedler_vector(eigenvalues: &[f64], eigenvectors: &[f64], n: usize) -> Vec<f64> {
        let mut idx: Vec<usize> = (0..n).collect();
        idx.sort_by(|&a, &b| {
            eigenvalues[a]
                .partial_cmp(&eigenvalues[b])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let k = if n >= 2 { idx[1] } else { idx[0] }; // 2nd smallest = lambda_2
        (0..n).map(|i| eigenvectors[i * n + k]).collect()
    }

    // True when every member shares one L2 group -- the atomic leaf. L2 siblings
    // are maximally coupled; there is no meaningful seam to find below them.
    fn all_same_l2(&self, members: &[usize]) -> bool {
        members
            .windows(2)
            .all(|w| self.l2_domain[w[0]] == self.l2_domain[w[1]])
    }

    // Min-conductance cut of an ARBITRARY CPU subset (recursion-safe). The global
    // Fiedler degrades inside a subtree, so this builds the INDUCED Laplacian on
    // `members`, eigendecomposes it, and sweeps by the SUBSET's own Fiedler. (2d
    // replaces these internals with a local random walk -- no eigensolve, so it
    // scales; the tree-builder is agnostic to which produces the cut.) Returns
    // global CPU ids.
    fn domain_cut(&self, members: &[usize]) -> Option<(Vec<usize>, Vec<usize>, f64)> {
        let k = members.len();
        if k < 2 {
            return None;
        }
        let mut lap = vec![0.0f64; k * k]; // induced Laplacian, local-indexed 0..k
        for ia in 0..k {
            for ib in (ia + 1)..k {
                let w = self.conductance(members[ia], members[ib]);
                lap[ia * k + ib] = -w;
                lap[ib * k + ia] = -w;
                lap[ia * k + ia] += w;
                lap[ib * k + ib] += w;
            }
        }
        let (ev, evec) = Self::symmetric_eigen(&lap, k);
        let fsub = Self::fiedler_vector(&ev, &evec, k); // local-indexed
        let mut order: Vec<usize> = (0..k).collect();
        order.sort_by(|&a, &b| {
            fsub[a]
                .partial_cmp(&fsub[b])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut in_side = vec![false; self.nr_cpus]; // global-indexed for cut_conductance
        let (mut best_phi, mut best_k) = (f64::INFINITY, 1usize);
        for s in 1..k {
            in_side[members[order[s - 1]]] = true; // grow the prefix (global id)
            let phi = self.cut_conductance(members, &in_side);
            if phi < best_phi {
                best_phi = phi;
                best_k = s;
            }
        }
        let side_a: Vec<usize> = order[..best_k].iter().map(|&li| members[li]).collect();
        let side_b: Vec<usize> = order[best_k..].iter().map(|&li| members[li]).collect();
        Some((side_a, side_b, best_phi))
    }

    // Up to this many CPUs the Jacobi eigensolve is cheap, so the exact eigen
    // cut and the eigen pseudoinverse use it; above it classical Jacobi, about
    // O(n^4) with its pivot search, is the wall, and the random-walk cut and the
    // factored pseudoinverse take over. This is an implementation dispatch on
    // cost, not a placement gate (THE FLAG untouched).
    const WALK_CUT_THRESHOLD: usize = 64;

    // SCALABLE min-conductance cut: the SAME sweep as domain_cut, but the vertex
    // ordering comes from a RANDOM WALK instead of an eigendecomposition -- no
    // O(n^3) eigensolve, so it scales. Power iteration on the NORMALIZED operator
    // M = 2I - L_sym, where L_sym = I - D^{-1/2} A D^{-1/2} is the symmetric
    // normalized Laplacian (eigenvalues in [0,2] regardless of edge-weight scale,
    // so stiff L2 edges don't dominate the shift the way a raw cI - L would). Its
    // null eigenvector is D^{1/2}*1 (the walk's stationary distribution, deflated
    // out each step); the next is the normalized Fiedler -- the iterate converges
    // to it with a gap set by the CONDUCTANCE structure, not the weight magnitude.
    // The sweep order is f[i] = y[i] / sqrt(deg[i]) (un-normalizing back to the
    // walk eigenvector). Deterministic hash start (not a ramp -- ramps can align
    // with a non-Fiedler mode) so a topology yields the same domains every boot.
    // Cross-checked against domain_cut as ground truth (the T2 gate).
    fn walk_cut(&self, members: &[usize]) -> Option<(Vec<usize>, Vec<usize>, f64)> {
        let k = members.len();
        if k < 2 {
            return None;
        }
        let mut adj = vec![0.0f64; k * k];
        let mut deg = vec![0.0f64; k];
        for ia in 0..k {
            for ib in 0..k {
                if ia == ib {
                    continue;
                }
                let w = self.conductance(members[ia], members[ib]);
                adj[ia * k + ib] = w;
                deg[ia] += w;
            }
        }
        // D^{-1/2} and the stationary direction D^{1/2}*1 (L_sym's null vector).
        let dis: Vec<f64> = deg
            .iter()
            .map(|&d| if d > 0.0 { 1.0 / d.sqrt() } else { 0.0 })
            .collect();
        let dsq: Vec<f64> = deg.iter().map(|&d| d.sqrt()).collect();
        let dsq_sq: f64 = dsq.iter().map(|x| x * x).sum::<f64>().max(1e-30);
        // Deflate out the stationary (null) component each step.
        let deflate = |v: &mut [f64]| {
            let dot: f64 = v.iter().zip(&dsq).map(|(a, b)| a * b).sum();
            let coef = dot / dsq_sq;
            for i in 0..k {
                v[i] -= coef * dsq[i];
            }
        };
        let mut y: Vec<f64> = (0..k)
            .map(|i| {
                let h = (i as u64).wrapping_mul(2654435761) & 0xffff;
                h as f64 / 65535.0 - 0.5
            })
            .collect();
        deflate(&mut y);
        // A weak cut has a tiny normalized eigenvalue gap, so the per-iteration
        // rate is near 1 and convergence can take thousands of steps -- iterate to
        // CONVERGENCE (the direction stops moving), not a fixed count, capped high.
        // Each step is O(k^2); a one-time boot cost, well under a millisecond.
        const MAX_ITERS: usize = 20_000;
        const TOL: f64 = 1e-10;
        let mut w = vec![0.0f64; k];
        for _ in 0..MAX_ITERS {
            // (M y)[i] = y[i] + D^{-1/2}_i * sum_j A_ij * D^{-1/2}_j * y[j]
            for i in 0..k {
                let row = &adj[i * k..i * k + k];
                let mut s = 0.0;
                for j in 0..k {
                    s += row[j] * dis[j] * y[j];
                }
                w[i] = y[i] + dis[i] * s;
            }
            deflate(&mut w);
            let norm = w.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm < 1e-12 {
                break;
            }
            // cos angle between the new direction and the old unit vector y.
            let dot: f64 = w.iter().zip(&y).map(|(a, b)| a * b).sum::<f64>() / norm;
            for i in 0..k {
                y[i] = w[i] / norm;
            }
            if 1.0 - dot.abs() < TOL {
                break;
            }
        }
        // Sweep order by the un-normalized walk eigenvector f[i] = y[i]/sqrt(deg).
        let f: Vec<f64> = (0..k).map(|i| y[i] * dis[i]).collect();
        let mut order: Vec<usize> = (0..k).collect();
        order.sort_by(|&a, &b| f[a].partial_cmp(&f[b]).unwrap_or(std::cmp::Ordering::Equal));
        // THE SAME phi AS cut_conductance, CARRIED FROM ONE PREFIX TO THE NEXT:
        // MOVING v ACROSS ADDS ITS EDGES INTO THE FAR SIDE TO THE CUT, TAKES ITS
        // EDGES INTO THE NEAR SIDE OUT, AND MOVES ITS DEGREE BETWEEN THE VOLUMES.
        // O(k) A PREFIX WHERE THE FULL RECOUNT IS O(k^2), WHICH AT 1,024 CPUs IS
        // A BILLION EDGE READS FOR THE FIRST CUT ALONE.
        let mut near = vec![false; k];
        let (mut cut, mut vol_a) = (0.0f64, 0.0f64);
        let mut vol_b: f64 = deg.iter().sum();
        let (mut best_phi, mut best_k) = (f64::INFINITY, 1usize);
        for s in 1..k {
            let v = order[s - 1];
            let row = &adj[v * k..v * k + k];
            for u in 0..k {
                if u != v {
                    if near[u] {
                        cut -= row[u]
                    } else {
                        cut += row[u]
                    }
                }
            }
            near[v] = true;
            vol_a += deg[v];
            vol_b -= deg[v];
            let denom = vol_a.min(vol_b);
            let phi = if denom <= 0.0 {
                f64::INFINITY
            } else {
                cut / denom
            };
            if phi < best_phi {
                best_phi = phi;
                best_k = s;
            }
        }
        Some((
            order[..best_k].iter().map(|&li| members[li]).collect(),
            order[best_k..].iter().map(|&li| members[li]).collect(),
            best_phi,
        ))
    }

    // Dispatch: exact eigen cut below the threshold, scalable random-walk cut
    // above. Both produce the same boundary on real cache graphs (gate-tested).
    fn best_cut(&self, members: &[usize]) -> Option<(Vec<usize>, Vec<usize>, f64)> {
        if members.len() <= Self::WALK_CUT_THRESHOLD {
            self.domain_cut(members)
        } else {
            self.walk_cut(members)
        }
    }

    // Recurse the cut into the emergent domain tree. Leaf when the members are a
    // single L2 group (or one CPU) -- maximally coupled, no seam. Each Cut carries
    // its phi (the crossing price). This IS de-facto NUMA: the boundary is drawn
    // by the conductance landscape, not a hardcoded topology table.
    pub fn build_domain_tree(&self, members: &[usize]) -> DomainNode {
        if members.len() <= 1 || self.all_same_l2(members) {
            return DomainNode::Leaf(members.to_vec());
        }
        match self.best_cut(members) {
            Some((a, b, phi)) if !a.is_empty() && !b.is_empty() => DomainNode::Cut {
                phi,
                left: Box::new(self.build_domain_tree(&a)),
                right: Box::new(self.build_domain_tree(&b)),
            },
            _ => DomainNode::Leaf(members.to_vec()),
        }
    }

    // Compute the emergent domain tree over all online CPUs -- the de-facto-NUMA
    // hierarchy from which T3's bounded-local steal reads its locality clusters
    // and per-cut crossing prices. Public: the T2 -> T3 hand-off point.
    pub fn compute_domain_tree(&self) -> DomainNode {
        self.build_domain_tree(&self.online)
    }

    // Log the emergent domains at boot -- observability that the tree the steal
    // will climb matches the silicon: atomic-domain count, cut depth, the
    // crossing-price (phi) range, and the first leaves.
    pub fn log_domains(&self, tree: &DomainNode) {
        let leaves = tree.leaves();
        let phis = tree.cut_phis();
        let (pmin, pmax) = phis.iter().fold((f64::INFINITY, 0.0f64), |(lo, hi), &p| {
            (lo.min(p), hi.max(p))
        });
        log_info!(
            "EMERGENT DOMAINS: {} atomic, {} cuts, crossing phi {:.4}..{:.4}",
            leaves.len(),
            phis.len(),
            if phis.is_empty() { 0.0 } else { pmin },
            pmax
        );
        let preview: Vec<String> = leaves.iter().take(8).map(|l| format!("{:?}", l)).collect();
        log_info!("EMERGENT DOMAINS: leaves {}", preview.join(" "));
    }

    // T3b.1: the per-CPU-pair crossing-price matrix the bounded steal reads.
    // m[i*n + j] = (phi * 1e6) of the LCA cut separating CPU i and CPU j -- the
    // price to steal across that emergent domain boundary. A LOW phi is a loose
    // seam (a major boundary -- socket / cross-L3 -- far, needs more imbalance to
    // cross); a HIGH phi is a tight seam (near). Same-leaf pairs share NO cut:
    // sentinel u32::MAX = maximally local, the steal never has to "cross" for them.
    // Replaces the discrete domain map's discrete same/different-cache domain test with a continuous,
    // emergent boundary price (THE FLAG: priced, not gated).
    pub fn domain_cross_phi_matrix(&self, tree: &DomainNode) -> Vec<u32> {
        let n = self.nr_cpus;
        let mut m = vec![u32::MAX; n * n]; // default: no boundary (same leaf)
        Self::fill_cross_phi(tree, n, &mut m);
        m
    }

    fn fill_cross_phi(node: &DomainNode, n: usize, m: &mut [u32]) {
        if let DomainNode::Cut { phi, left, right } = node {
            let lc: Vec<usize> = left.leaves().concat();
            let rc: Vec<usize> = right.leaves().concat();
            let p = (phi * 1_000_000.0).round().clamp(0.0, u32::MAX as f64) as u32;
            for &a in &lc {
                for &b in &rc {
                    m[a * n + b] = p; // pairs whose lowest common ancestor IS this cut
                    m[b * n + a] = p;
                }
            }
            Self::fill_cross_phi(left, n, m);
            Self::fill_cross_phi(right, n, m);
        }
    }

    // Number of emergent DOMAINS to target = distinct L3 groups over the online
    // CPUs, so the partition keeps the L3 granularity.
    pub fn domain_count(&self) -> usize {
        let mut v: Vec<u32> = self.online.iter().map(|&c| self.llc_domain[c]).collect();
        v.sort_unstable();
        v.dedup();
        v.len().max(1)
    }

    // T3b.2: partition CPUs into emergent DOMAINS -- the discrete domain map
    // replacement. Descend the tree from the root, repeatedly splitting the
    // frontier subtree whose cut has the LOWEST phi (the coarsest, most-separable
    // seam) until `target` domains exist or no cut remains. Each resulting subtree
    // is one domain; dom[cpu] is its id. The granularity is the L3
    // count; the boundary is drawn by the emergent tree, not the discrete domain map.
    // An offline CPU is in no leaf and keeps OFFLINE_ID: every BPF use of a
    // domain id is an equality test, so it matches no online CPU's.
    pub fn domain_partition(&self, tree: &DomainNode, target: usize) -> Vec<u32> {
        let mut frontier: Vec<&DomainNode> = vec![tree];
        while frontier.len() < target.max(1) {
            let mut best: Option<(usize, f64)> = None;
            for (i, node) in frontier.iter().enumerate() {
                if let DomainNode::Cut { phi, .. } = node
                    && best.is_none_or(|(_, bp)| *phi < bp)
                {
                    best = Some((i, *phi));
                }
            }
            let Some((idx, _)) = best else { break }; // no cuts left to split
            let node = frontier[idx];
            if let DomainNode::Cut { left, right, .. } = node {
                frontier.swap_remove(idx);
                frontier.push(left.as_ref());
                frontier.push(right.as_ref());
            }
        }
        let n = self.nr_cpus;
        let mut dom = vec![OFFLINE_ID; n];
        for (id, node) in frontier.iter().enumerate() {
            for leaf in node.leaves() {
                for c in leaf {
                    if c < n {
                        dom[c] = id as u32;
                    }
                }
            }
        }
        // THE CUT'S DOMAINS ARE THE L3 GROUPS WHEREVER THE CUT CAN SEE THEM, AND
        // IT CANNOT SEE AN UNBALANCED ONE: phi DIVIDES BY THE SMALLER SIDE'S
        // VOLUME, SO AN L3 WITH ONE CPU ONLINE CUTS AT phi 1.0, THE WORST A CUT
        // CAN READ, AND THE TREE SPLITS A WHOLE L3 INSTEAD (4 OF THE REFERENCE
        // BOX'S 12: {0,2} AND {1,3} AT 0.8 FOR THE L3s {0,1,2} AND {3}). THE
        // RANK ORDERS BY THE CACHE RUNG AND THE SPILL IS BOUNDED BY THE DOMAIN,
        // SO A PARTITION THAT LEAVES THE L3 SEAM IS REPLACED BY THE L3 GROUPS.
        let follows_seam = self.online.iter().all(|&a| {
            self.online
                .iter()
                .all(|&b| (dom[a] == dom[b]) == (self.llc_domain[a] == self.llc_domain[b]))
        });
        if !follows_seam && target > 1 {
            let mut seen: Vec<u32> = Vec::new();
            for &c in &self.online {
                let llc = self.llc_domain[c];
                let id = match seen.iter().position(|&g| g == llc) {
                    Some(id) => id,
                    None => {
                        seen.push(llc);
                        seen.len() - 1
                    }
                };
                dom[c] = id as u32;
            }
        }
        dom
    }

    // HOW MANY affinity_rank SLOTS STAY INSIDE A CPU'S OWN DOMAIN, MINIMUM OVER
    // CPUs. COUNTED OFF THE SAME rank THE BPF WALK READS AND THE SAME cpu_dom THE
    // SPILL BOUND READS, SO THE BOUND CANNOT DISAGREE WITH THE WALK.
    //
    // THE PREFIX IS WHAT MATTERS. build_affinity_rank SORTS BY R_eff ASCENDING AND
    // THE CACHE RUNGS ARE ORDERED, SO A CPU'S SAME-DOMAIN PEERS OCCUPY AN UNBROKEN
    // PREFIX -- THE COUNT IS THEREFORE THE INDEX OF THE FIRST CROSS-DOMAIN SLOT,
    // WHICH IS THE BUDGET AT WHICH THE WALK LEAVES THE DOMAIN. THE LOOP STOPS AT
    // THE FIRST NON-MEMBER RATHER THAN COUNTING MEMBERSHIP ANYWHERE IN THE ROW.
    //
    // MINIMUM, NOT AVERAGE. THE BOUND KEEPS THE WALK INSIDE EVERY CPU'S DOMAIN,
    // SO THE TIGHTEST CPU SETS IT.
    //
    // A SINGLETON DOMAIN IS EXCLUDED RATHER THAN ALLOWED TO SET THE BOUND. A CPU
    // WITH NO IN-DOMAIN PEER HAS NO BUDGET THAT COULD KEEP IT LOCAL, SO ITS ZERO
    // WOULD DRAG EVERY OTHER CPU'S FLOOR TO 1 TO EXPRESS A CONSTRAINT THAT CANNOT
    // HELP IT. THE SINGLETON FALLS THROUGH TO THE dfl PICK INSTEAD.
    // RETURNS 1 ONLY WHEN NO CPU HAS A PEER.
    //
    // THE ROW AS STORED: THE TABLE KEEPS MAX_AFFINITY_CANDIDATES SLOTS A CPU,
    // AND A DOMAIN WIDER THAN THAT IS COUNTED TO THE TABLE'S EDGE, NOT PAST IT.
    pub fn min_in_domain_peers(&self, rank: &[u32], cpu_dom: &[u32]) -> u32 {
        let n = self.nr_cpus;
        if n < 2 || rank.len() < n * n || cpu_dom.len() < n {
            return 1;
        }
        let stored = (n - 1).min(crate::bpf_intf::MAX_AFFINITY_CANDIDATES as usize);
        let mut min_peers = u32::MAX;
        for &cpu in &self.online {
            let home = cpu_dom[cpu];
            let mut peers = 0u32;
            for slot in 0..stored {
                let target = rank[cpu * n + slot] as usize;
                if target >= n || cpu_dom[target] != home {
                    break;
                }
                peers += 1;
            }
            if peers > 0 && peers < min_peers {
                min_peers = peers;
            }
        }
        if min_peers == u32::MAX { 1 } else { min_peers }
    }

    // SYMMETRIC EIGENDECOMPOSITION VIA JACOBI ROTATIONS
    // RETURNS (eigenvalues, eigenvectors_column_major)
    // CALLED FOR n <= WALK_CUT_THRESHOLD. NO EXTERNAL DEPENDENCIES.
    pub fn symmetric_eigen(mat: &[f64], n: usize) -> (Vec<f64>, Vec<f64>) {
        let mut a = mat.to_vec();
        // EIGENVECTORS START AS IDENTITY
        let mut v = vec![0.0f64; n * n];
        for i in 0..n {
            v[i * n + i] = 1.0;
        }

        let max_iter = 100 * n * n;
        for _ in 0..max_iter {
            // FIND LARGEST OFF-DIAGONAL ELEMENT
            let mut max_val = 0.0f64;
            let mut p = 0;
            let mut q = 1;
            for i in 0..n {
                for j in (i + 1)..n {
                    let val = a[i * n + j].abs();
                    if val > max_val {
                        max_val = val;
                        p = i;
                        q = j;
                    }
                }
            }
            if max_val < 1e-12 {
                break;
            }

            // COMPUTE ROTATION
            let app = a[p * n + p];
            let aqq = a[q * n + q];
            let apq = a[p * n + q];
            let theta = if (app - aqq).abs() < 1e-15 {
                std::f64::consts::FRAC_PI_4
            } else {
                0.5 * (2.0 * apq / (app - aqq)).atan()
            };
            let c = theta.cos();
            let s = theta.sin();

            // APPLY ROTATION TO A
            for i in 0..n {
                if i == p || i == q {
                    continue;
                }
                let aip = a[i * n + p];
                let aiq = a[i * n + q];
                a[i * n + p] = c * aip + s * aiq;
                a[p * n + i] = a[i * n + p];
                a[i * n + q] = -s * aip + c * aiq;
                a[q * n + i] = a[i * n + q];
            }
            let new_pp = c * c * app + 2.0 * s * c * apq + s * s * aqq;
            let new_qq = s * s * app - 2.0 * s * c * apq + c * c * aqq;
            a[p * n + p] = new_pp;
            a[q * n + q] = new_qq;
            a[p * n + q] = 0.0;
            a[q * n + p] = 0.0;

            // ACCUMULATE EIGENVECTORS
            for i in 0..n {
                let vip = v[i * n + p];
                let viq = v[i * n + q];
                v[i * n + p] = c * vip + s * viq;
                v[i * n + q] = -s * vip + c * viq;
            }
        }

        let eigenvalues: Vec<f64> = (0..n).map(|i| a[i * n + i]).collect();
        (eigenvalues, v)
    }

    // COMPUTE LAPLACIAN PSEUDOINVERSE FROM EIGENDECOMPOSITION
    pub fn compute_pseudoinverse(eigenvalues: &[f64], eigenvectors: &[f64], n: usize) -> Vec<f64> {
        let mut l_pinv = vec![0.0f64; n * n];
        for k in 0..n {
            if eigenvalues[k].abs() < 1e-8 {
                continue; // SKIP NULL EIGENVALUE (CONNECTED GRAPH HAS ONE)
            }
            let inv_lambda = 1.0 / eigenvalues[k];
            for i in 0..n {
                for j in 0..n {
                    l_pinv[i * n + j] +=
                        inv_lambda * eigenvectors[i * n + k] * eigenvectors[j * n + k];
                }
            }
        }
        l_pinv
    }

    // COMPUTE ALL-PAIRS EFFECTIVE RESISTANCE FROM PSEUDOINVERSE
    // R_eff(i,j) = L+[i,i] + L+[j,j] - 2*L+[i,j]
    pub fn extract_reff(l_pinv: &[f64], n: usize) -> Vec<f64> {
        let mut r = vec![0.0f64; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let val = l_pinv[i * n + i] + l_pinv[j * n + j] - 2.0 * l_pinv[i * n + j];
                r[i * n + j] = val.max(0.0);
                r[j * n + i] = r[i * n + j];
            }
        }
        r
    }

    // BUILD PER-CPU AFFINITY RANK: FOR EACH ONLINE CPU, EVERY OTHER ONLINE CPU
    // SORTED BY THE CACHE RUNG THE PAIR SHARES AND, INSIDE A RUNG, BY R_EFF,
    // THE ROW COMPACTED: ITS PEERS FIRST, THEN THE SENTINEL. AN OFFLINE CPU IS
    // IN NO ROW AND ITS OWN ROW IS ALL SENTINEL, SO A WALK SPENDS NO SLOT AND
    // NO BUDGET ON A CPU THAT CANNOT RUN ANYTHING.
    //
    // THE RUNG LEADS BECAUSE R_eff ALONE ORDERS BY IT ONLY ON A SYMMETRIC
    // GRAPH. R_eff(i, j) LEANS ON 1/deg(i) + 1/deg(j), AND THE STIFF L2 EDGE
    // GIVES A CPU WITH AN ONLINE SIBLING SEVENTY TO NINETY TIMES THE DEGREE OF
    // ONE WITHOUT: AT 8 OF THE REFERENCE BOX'S 12 CPUs, CPU 3 READS THE OTHER L3'S
    // FOUR SIBLING-BEARING CPUs AT 0.1312 AND ITS OWN L3'S TWO AT 0.1429, AND
    // SORTED BY R_eff ALONE ITS OWN CACHE CAME LAST BUT ONE. WHERE EVERY CORE
    // HAS THE SAME THREADS ONLINE THE TWO ORDERS ARE THE SAME ORDER.
    // Returns flat array: affinity_rank[cpu * nr_cpus + slot] = target_cpu
    fn build_affinity_rank(&self, reff: &[f64]) -> Vec<u32> {
        let n = self.nr_cpus;
        let mut rank = vec![u32::MAX; n * n];
        for &cpu in &self.online {
            let mut others: Vec<(u8, u64, u32)> = self
                .online
                .iter()
                .filter(|&&c| c != cpu)
                .map(|&c| {
                    // SORT KEY: R_EFF AS FIXED-POINT TO AVOID FLOAT COMPARISON ISSUES
                    let key = (reff[cpu * n + c] * 1_000_000.0) as u64;
                    (self.rung(cpu, c), key, c as u32)
                })
                .collect();
            others.sort();
            for (slot, &(_, _, target)) in others.iter().enumerate() {
                rank[cpu * n + slot] = target;
            }
        }
        rank
    }

    // INTEGER LAPLACIAN FROM THE ICOND_* RUNG TABLE (SPILL-Phi). SAME EDGE
    // STRUCTURE AS build_laplacian, INTEGER WEIGHTS.
    fn build_laplacian_int(&self) -> Vec<i128> {
        let n = self.online.len();
        let mut l = vec![0i128; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let (a, b) = (self.online[i], self.online[j]);
                let w = if self.l2_domain[a] == self.l2_domain[b] {
                    Self::ICOND_L2
                } else if self.llc_domain[a] == self.llc_domain[b] {
                    Self::ICOND_LLC
                } else if self.socket_domain[a] == self.socket_domain[b] {
                    Self::ICOND_SOCKET
                } else {
                    Self::ICOND_CROSS
                };
                l[i * n + j] = -w;
                l[j * n + i] = -w;
                l[i * n + i] += w;
                l[j * n + j] += w;
            }
        }
        l
    }

    // BAREISS FRACTION-FREE DETERMINANT of an integer matrix (row-major, m x m).
    // Every division is exact by the Bareiss invariant. None on i128 overflow or a
    // zero pivot -- a connected reduced Laplacian is positive-definite, so a zero
    // pivot only ever means fall-back-to-float here, never a real singular case.
    pub fn bareiss_det(mut a: Vec<i128>, m: usize) -> Option<i128> {
        let mut prev: i128 = 1;
        for k in 0..m.saturating_sub(1) {
            let pivot = a[k * m + k];
            if pivot == 0 {
                return None;
            }
            for i in (k + 1)..m {
                for j in (k + 1)..m {
                    let t1 = a[i * m + j].checked_mul(pivot)?;
                    let t2 = a[i * m + k].checked_mul(a[k * m + j])?;
                    a[i * m + j] = t1.checked_sub(t2)? / prev;
                }
            }
            prev = pivot;
        }
        if m == 0 {
            Some(1)
        } else {
            Some(a[(m - 1) * m + (m - 1)])
        }
    }

    // det of the integer Laplacian with the given index set's rows AND columns gone.
    fn minor_det(l_int: &[i128], n: usize, remove: &[usize]) -> Option<i128> {
        let keep: Vec<usize> = (0..n).filter(|x| !remove.contains(x)).collect();
        let m = keep.len();
        let mut sub = vec![0i128; m * m];
        for (a, &ri) in keep.iter().enumerate() {
            for (b, &cj) in keep.iter().enumerate() {
                sub[a * m + b] = l_int[ri * n + cj];
            }
        }
        Self::bareiss_det(sub, m)
    }

    // EXACT R_eff(i,j) = det(L minus rows/cols i,j) / det(L minus row/col 0), the
    // spanning-2-forest / spanning-tree ratio (Barrett et al., Spanning 2-Forests
    // and Resistance Distance), in the integer Laplacian's units. None on overflow
    // so the caller falls back to the float path.
    pub fn reff_from_int_laplacian(l_int: &[i128], n: usize) -> Option<Vec<f64>> {
        if n < 2 {
            return Some(vec![0.0; n * n]);
        }
        let tau = Self::minor_det(l_int, n, &[0])?;
        if tau == 0 {
            return None;
        }
        let tau_f = tau as f64;
        let mut r = vec![0.0f64; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let f = Self::minor_det(l_int, n, &[i, j])?;
                let v = ((f as f64) / tau_f).max(0.0);
                r[i * n + j] = v;
                r[j * n + i] = v;
            }
        }
        Some(r)
    }

    // THE LAPLACIAN PSEUDOINVERSE WITHOUT AN EIGENSOLVE. ON A CONNECTED GRAPH
    // L + J/n IS POSITIVE DEFINITE (J THE ALL-ONES MATRIX: IT FILLS THE ONE
    // DIRECTION L HAS NO STIFFNESS IN) AND ITS INVERSE IS L+ + J/n, SO ONE
    // CHOLESKY FACTOR AND ITS INVERSE GIVE L+ IN O(n^3) WHERE JACOBI'S
    // ROTATIONS, EACH BEHIND A FULL PIVOT SEARCH, RUN TO ABOUT O(n^4). EVERY
    // INNER PRODUCT WALKS TWO ROWS, NEVER A COLUMN. None WHEN A PIVOT IS NOT
    // POSITIVE, WHICH A CONNECTED LAPLACIAN CANNOT GIVE; THE CALLER FALLS BACK
    // TO THE EIGENSOLVE.
    pub fn pseudoinverse_by_factor(lap: &[f64], n: usize) -> Option<Vec<f64>> {
        let shift = 1.0 / n as f64;
        // CHOLESKY: l LOWER TRIANGULAR, l * l^T = L + J/n.
        let mut l = vec![0.0f64; n * n];
        for i in 0..n {
            for j in 0..=i {
                let mut sum = lap[i * n + j] + shift;
                for k in 0..j {
                    sum -= l[i * n + k] * l[j * n + k];
                }
                if i == j {
                    if sum <= 0.0 || !sum.is_finite() {
                        return None;
                    }
                    l[i * n + i] = sum.sqrt();
                } else {
                    l[i * n + j] = sum / l[j * n + j];
                }
            }
        }
        // u = (l^-1)^T, UPPER TRIANGULAR, ROW BY ROW.
        let mut u = vec![0.0f64; n * n];
        for j in 0..n {
            u[j * n + j] = 1.0 / l[j * n + j];
            for i in (j + 1)..n {
                let mut sum = 0.0;
                for k in j..i {
                    sum -= l[i * n + k] * u[j * n + k];
                }
                u[j * n + i] = sum / l[i * n + i];
            }
        }
        // (L + J/n)^-1 = u * u^T, AND L+ IS THAT LESS J/n.
        let mut pinv = vec![0.0f64; n * n];
        for i in 0..n {
            for j in 0..=i {
                let mut sum = 0.0;
                for k in i..n {
                    sum += u[i * n + k] * u[j * n + k];
                }
                pinv[i * n + j] = sum - shift;
                pinv[j * n + i] = sum - shift;
            }
        }
        Some(pinv)
    }

    // lambda_2 FROM L+: ITS LARGEST EIGENVALUE IS 1/lambda_2, AND POWER
    // ITERATION FINDS IT AT O(n^2) A STEP. THE CONSTANT VECTOR IS L+'S NULL
    // DIRECTION AND IS PROJECTED OUT EACH STEP AGAINST ROUNDING. A REPEATED
    // lambda_2, WHICH EVERY SYMMETRIC PART WITH MORE THAN TWO L3s HAS, STILL
    // CONVERGES: THE ITERATE SETTLES SOMEWHERE IN THE EIGENSPACE AND THE
    // RAYLEIGH QUOTIENT IS THE SAME EVERYWHERE IN IT. DETERMINISTIC START.
    pub fn fiedler_from_pseudoinverse(pinv: &[f64], n: usize) -> f64 {
        if n < 2 {
            return LAMBDA_ZERO_EPS;
        }
        let center = |v: &mut [f64]| {
            let mean = v.iter().sum::<f64>() / n as f64;
            for x in v.iter_mut() {
                *x -= mean;
            }
        };
        let mut y: Vec<f64> = (0..n)
            .map(|i| {
                let h = (i as u64).wrapping_mul(2654435761) & 0xffff;
                h as f64 / 65535.0 - 0.5
            })
            .collect();
        center(&mut y);
        let mut w = vec![0.0f64; n];
        let mut mu = 0.0f64;
        for _ in 0..10_000 {
            let norm = y.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm < 1e-300 {
                break;
            }
            for x in y.iter_mut() {
                *x /= norm;
            }
            for i in 0..n {
                let row = &pinv[i * n..i * n + n];
                w[i] = row.iter().zip(&y).map(|(a, b)| a * b).sum();
            }
            center(&mut w);
            let next: f64 = w.iter().zip(&y).map(|(a, b)| a * b).sum();
            let settled = (next - mu).abs() <= 1e-14 * next.abs();
            mu = next;
            std::mem::swap(&mut y, &mut w);
            if settled {
                break;
            }
        }
        if mu > 0.0 { 1.0 / mu } else { LAMBDA_ZERO_EPS }
    }

    // COMPUTE RESISTANCE AFFINITY: FULL PIPELINE
    // Returns (reff_matrix, affinity_rank, spectrum) for use by BPF and scheduler.
    // Spectrum carries lambda_2 (Fiedler value) and its derived tau_ns, used as
    // the universal topology time constant for every core-scaled knob.
    //
    // THE GRAPH IS THE ONLINE CPUs: m OF THEM, AND EVERY SPECTRAL QUANTITY
    // (lambda_2, tau, codel_eq, R_eff) IS THAT GRAPH'S. THE R_eff MATRIX AND THE
    // RANK COME BACK INDEXED BY CPU ID, nr_cpus x nr_cpus, AN OFFLINE CPU'S ROW
    // AND COLUMN ZERO IN THE ONE AND SENTINEL IN THE OTHER.
    pub fn compute_resistance_affinity(&self) -> (Vec<f64>, Vec<u32>, TopologySpectrum) {
        let n = self.nr_cpus;
        let m = self.online.len();
        let laplacian = self.build_laplacian();
        // PAST THE EIGENSOLVE'S REACH THE PSEUDOINVERSE COMES FROM ONE FACTOR,
        // AND lambda_2 AND Tr(L+), ALL THE SPECTRUM tau AND codel_eq READ, FROM
        // IT. A FACTOR THAT FAILS FALLS BACK TO THE EIGENSOLVE.
        let factored = (m > Self::WALK_CUT_THRESHOLD)
            .then(|| Self::pseudoinverse_by_factor(&laplacian, m))
            .flatten();
        let (fiedler, tau_ns, codel_eq_ns, graph_reff) = if let Some(l_pinv) = factored {
            let fiedler = Self::fiedler_from_pseudoinverse(&l_pinv, m);
            let tau_ns = compute_tau_ns(fiedler, m);
            let trace: f64 = (0..m).map(|i| l_pinv[i * m + i]).sum();
            let codel_eq_ns = codel_eq_at(fiedler, trace, m, tau_ns);
            (fiedler, tau_ns, codel_eq_ns, Self::extract_reff(&l_pinv, m))
        } else {
            let (eigenvalues, eigenvectors) = Self::symmetric_eigen(&laplacian, m);
            let fiedler = extract_fiedler(&eigenvalues);
            let tau_ns = compute_tau_ns(fiedler, m);
            // EXACT INTEGER R_eff (Bareiss spanning-2-forest / spanning-tree determinant
            // ratio) where i128 holds it; else the float pseudoinverse. Same rung
            // ratios both paths, so downstream is unchanged either way.
            let graph_reff: Vec<f64> = match (m <= Self::REFF_EXACT_MAX_CPUS)
                .then(|| Self::reff_from_int_laplacian(&self.build_laplacian_int(), m))
                .flatten()
            {
                Some(r) => r.into_iter().map(|x| x * Self::ICOND_RECOVER).collect(),
                None => {
                    let l_pinv = Self::compute_pseudoinverse(&eigenvalues, &eigenvectors, m);
                    Self::extract_reff(&l_pinv, m)
                }
            };
            let codel_eq_ns = compute_codel_eq_ns(&eigenvalues, m, tau_ns);
            (fiedler, tau_ns, codel_eq_ns, graph_reff)
        };
        let mut reff = vec![0.0f64; n * n];
        for (a, &i) in self.online.iter().enumerate() {
            for (b, &j) in self.online.iter().enumerate() {
                reff[i * n + j] = graph_reff[a * m + b];
            }
        }
        let rank = self.build_affinity_rank(&reff);
        // DISTANCE SCALE: calibrated so the most distant pair (max R_eff)
        // maps to ~tau of required steal-wait, an SMT sibling (R_eff ~ 0) to ~0. Only
        // sustained backlog (~tau) justifies a far move; a single queued slice does
        // not. reff_norm uses the same 1e6 scale the BPF reff_value map stores.
        // ALWAYS computed: on a single-L3 part the most distant pair is the cross-L2
        // (cross-core) max, so reff_norm auto-calibrates the brake to the L2 boundary
        // instead of vanishing -- the continuous metric drives placement on EVERY
        // processor, with no binary topology gate in front of it (THE FLAG).
        let max_reff = reff.iter().cloned().fold(0.0f64, f64::max);
        let reff_norm = ((max_reff * 1_000_000.0).round() as u64).max(1);
        let phi_dist_scale_q16 = tau_ns.saturating_mul(65536) / reff_norm;
        (
            reff,
            rank,
            TopologySpectrum {
                fiedler,
                tau_ns,
                codel_eq_ns,
                phi_dist_scale_q16,
            },
        )
    }

    // THE FOUR TABLES THE BPF WALKS READ, EACH nr_cpus * MAX_AFFINITY_CANDIDATES
    // AND PAIRED 1:1 ON cpu * MAX_AFFINITY_CANDIDATES + slot:
    //   rank   THE TARGET CPU, R_eff ASCENDING
    //   value  THE STEAL'S DISTANCE PENALTY TO IT, NS
    //   frac   R_eff TO IT AS A Q16 FRACTION OF THE MACHINE'S SPAN
    //   phi    THE EMERGENT-DOMAIN CROSSING PRICE TO IT
    // A ROW HOLDS ITS CPU'S ONLINE PEERS, CAPPED AT THE TABLE'S WIDTH, AND THEN
    // THE SENTINEL IN ALL FOUR, WRITTEN EXPLICITLY: A ZERO-FILLED SLOT WOULD
    // READ AS CPU 0. AN OFFLINE CPU'S ROW IS ALL SENTINEL.
    pub fn affinity_tables(
        &self,
        reff: &[f64],
        rank: &[u32],
        phi_dist_scale_q16: u64,
        codel_eq_ns: u64,
        domain_phi: &[u32],
    ) -> AffinityTables {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES as usize;
        let n = self.nr_cpus;
        let mut t = AffinityTables {
            rank: vec![u32::MAX; n * stride],
            value: vec![u32::MAX; n * stride],
            frac: vec![u32::MAX; n * stride],
            phi: vec![u32::MAX; n * stride],
        };
        // R_eff's SPAN ACROSS DISTINCT ONLINE PAIRS, FOR THE DIMENSIONLESS EMIT
        // BELOW. A distance prices only its excess over the nearest pair on the
        // machine: the nearest peer is free, the most distant pair is 65536, and
        // a topology whose pairs are all equidistant (2C on one L3) prices
        // nothing. The diagonal is excluded -- R_eff(i, i) is 0 and is no peer.
        let (mut rmin, mut rmax) = (f64::MAX, 0.0f64);
        for &i in &self.online {
            for &j in &self.online {
                if i != j {
                    let r = reff[i * n + j];
                    rmin = rmin.min(r);
                    rmax = rmax.max(r);
                }
            }
        }
        let to_scaled = |r: f64| (r * 1_000_000.0).round().clamp(0.0, u32::MAX as f64) as u64;
        let reff_floor = if rmin == f64::MAX { 0 } else { to_scaled(rmin) };
        let reff_span = to_scaled(rmax).saturating_sub(reff_floor);
        for &cpu in &self.online {
            for slot in 0..n.saturating_sub(1).min(stride) {
                let val = rank[cpu * n + slot];
                if val as usize >= n {
                    break;
                }
                let at = cpu * stride + slot;
                t.rank[at] = val;
                // T3b.1: the emergent-domain crossing price to this ranked peer,
                // 1:1 with the rank slot.
                // IF phi_dist_scale_q16 IS 0 (tau UNSET; ITS FLOOR PREVENTS IT) THE STEAL
                // DOES NO R_eff DISTANCE PRICING; MAKE THE CROSSING PRICE
                // SENTINEL TOO SO THE STEAL-SIDE PAIR-SPLIT HOLD IS A NO-OP,
                // MATCHING reff_value's FLAT codel_target BASELINE (THE STEAL
                // IS domain_phi's CONSUMER).
                if phi_dist_scale_q16 != 0 {
                    t.phi[at] = domain_phi[cpu * n + val as usize];
                }
                // FOLD THE PHI DISTANCE PENALTY AT INIT: reff_value stores the
                // final steal extra-wait in ns, (R_eff * phi_dist_scale_q16) >> 16,
                // so the BPF steal does one indexed read and no multiply. The 1e6
                // scale matches build_affinity_rank's sort key. phi_dist_scale_q16
                // is computed on every part, a single-L3 one included; 0 only with tau unset -> flat
                // codel_target (exact prior behavior).
                // CEILING-ONLY CLAMP (shipped with SPILL-Phi; deliberately no
                // floor): an unclamped toll scales toward tau itself (~40ms,
                // the magnitude behind three hard freezes in the postmortem
                // record); cap it at 2*codel_eq_ns. NO floor -- dist_extra is a
                // per-peer price that must reach ~0 for a genuinely near peer (an
                // SMT sibling stays freely relievable), and STEP 1's phi_thresh
                // already adds the uniform codel_target_ns base on top.
                let r_scaled = to_scaled(reff[cpu * n + val as usize]);
                let raw_extra = r_scaled.saturating_mul(phi_dist_scale_q16) >> 16;
                t.value[at] = if phi_dist_scale_q16 == 0 {
                    0
                } else {
                    raw_extra
                        .min(codel_eq_ns.saturating_mul(2))
                        .min(u32::MAX as u64) as u32
                };
                // THE SAME R_eff SHAPE, WITH NO TIME UNIT ON IT. reff_value folds
                // the distance against TAU because that is the steal's question:
                // only sustained backlog (~tau) justifies a far pull. The wake-path
                // placement sites ask a different question against a comparand two
                // orders smaller -- one codel_target (233-667us) -- so the tau fold
                // is 20-170x oversized there and settles those tests by itself.
                // Emit the fraction instead and let each consumer multiply by the
                // yardstick its own comparison uses. Q16, so 65536 == the most
                // distant pair on this machine; bounded at every topology, which is
                // what stops slot 0 changing rung from moving a threshold 42x. The
                // nearest pair is 0, so a distance only ever prices how much
                // farther a peer is than the nearest one could have been.
                t.frac[at] = if phi_dist_scale_q16 == 0 || reff_span == 0 {
                    0u32
                } else {
                    ((r_scaled.saturating_sub(reff_floor) << 16) / reff_span).min(65536) as u32
                };
            }
        }
        t
    }

    pub fn log_resistance_affinity(&self, reff: &[f64], rank: &[u32], spectrum: TopologySpectrum) {
        log_info!(
            "TOPOLOGY SPECTRUM: lambda2={:.4} tau={}ms codel_eq={}us",
            spectrum.fiedler,
            spectrum.tau_ns / 1_000_000,
            spectrum.codel_eq_ns / 1_000
        );
        let n = self.nr_cpus;
        let m = self.online.len();
        let Some(&c0) = self.online.first() else {
            return;
        };
        // LOG TOP 3 AFFINITIES FOR THE FIRST ONLINE CPU
        let mut parts = Vec::new();
        for slot in 0..3.min(m - 1) {
            let target = rank[c0 * n + slot] as usize;
            if target >= n {
                break;
            }
            let r = reff[c0 * n + target];
            parts.push(format!("CPU{}(R={:.3})", target, r));
        }
        log_info!("RESISTANCE AFFINITY: CPU {} rank: {}", c0, parts.join(", "));

        // LOG L2 VS NON-L2 R_EFF FOR THE FIRST ONLINE CPU
        if m >= 2 {
            let l2_sib = rank[c0 * n] as usize;
            let non_l2 = rank[c0 * n + 1.min(m - 2)] as usize;
            log_info!(
                "RESISTANCE AFFINITY: R_eff L2={:.4} non-L2={:.4} ratio={:.1}x",
                reff[c0 * n + l2_sib],
                reff[c0 * n + non_l2],
                if reff[c0 * n + l2_sib] > 0.0 {
                    reff[c0 * n + non_l2] / reff[c0 * n + l2_sib]
                } else {
                    0.0
                }
            );
        }
    }

    pub fn log_summary(&self) {
        for (gid, members) in self.l2_groups.iter().enumerate() {
            let cpus: Vec<String> = members.iter().map(|c| c.to_string()).collect();
            log_info!("L2 GROUP {}: [{}]", gid, cpus.join(","));
        }
        log_info!(
            "L2 GROUPS: {} across {} ONLINE CPUs OF {}, {} SOCKETS",
            self.l2_groups.len(),
            self.online.len(),
            self.nr_cpus,
            self.nr_sockets
        );
        let mut llc: Vec<u32> = self.online.iter().map(|&c| self.llc_domain[c]).collect();
        llc.sort_unstable();
        llc.dedup();
        log_info!(
            "LLC DOMAINS: {} (L3 rung always-on, continuous Phi)",
            llc.len()
        );
    }
}

// PARSE KERNEL CPU LIST FORMAT: "0,6" or "0-2,6-8" or "3"
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut result = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                for cpu in s..=e {
                    result.push(cpu);
                }
            }
        } else if let Ok(cpu) = part.parse::<u32>() {
            result.push(cpu);
        }
    }
    result.sort();
    result.dedup();
    result
}
