// PANDEMONIUM CPU CACHE TOPOLOGY
// PARSES SYSFS AT STARTUP, POPULATES BPF MAP FOR CACHE-AWARE DISPATCH
//
// BPF dispatch() USES THE CACHE DOMAIN MAP TO PREFER TASKS THAT LAST
// RAN ON THE SAME CPU OR AN L2 SIBLING. THIS PRESERVES CACHE WARMTH
// AND REDUCES THE THROUGHPUT GAP CAUSED BY BLIND NODE-DSQ CONSUMPTION.

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
// QUANTITIES (including search budgets sized by spectral connectivity) ARE
// EXPRESSED THROUGH tau VIA lambda_2 = TAU_SCALE_NS / tau. TWO SITES IN
// main.bpf.c INTENTIONALLY KEEP nr_cpu_ids:
//   - select_cpu()'s wake_wide() flips threshold (matches the kernel's
//     wake_wide() convention; an external interface).
//   - tick()'s rotating-scan budget switch (coverage over the active CPU
//     range, not a graph-shape decision).
// Everything else -- timing, oscillator dynamics, search budgets, depth
// gates -- derives from tau in apply_tau_scaling().
//
// EXTRACTION IS O(n log n) ON TOP OF THE EXISTING O(n^3) Jacobi; NEGLIGIBLE.
// REFERENCE: CHEEGER'S INEQUALITY BOUNDS lambda_2 AGAINST GRAPH BOTTLENECK.
const LAMBDA_ZERO_EPS: f64 = 1e-8;
const TAU_SCALE_NS: f64 = 1.6e8; // 160MS. CAPACITY-AWARE ANCHOR: AT THE
                                 // 12C REFERENCE (lambda_2=12, N=12)
                                 // tau = 160ms / sqrt(144) = 13.3MS.
const TAU_FLOOR_NS: u64 = 1_000_000; //  1MS
const TAU_CEIL_NS: u64 = 40_000_000; // 40MS

// CoDel TARGET EQUILIBRIUM CLAMP RANGE. THE CONTROLLER'S MEAN-REVERTING
// TARGET IN ABSENCE OF DISTURBANCE. SAME ORDER OF MAGNITUDE AS THE
// CoDel TARGET RANGE ITSELF (FLOOR ~200us, CEILING ~8MS).
const C_EQ_FLOOR_NS: u64 = 200_000; // 200us
const C_EQ_CEIL_NS: u64 = 8_000_000; // 8ms

#[derive(Clone, Copy, Debug)]
pub struct TopologySpectrum {
    pub fiedler: f64,     // lambda_2
    pub tau_ns: u64,      // clamped TAU_SCALE_NS / lambda_2
    pub codel_eq_ns: u64, // <R_eff> * 2m * tau, clamped
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

#[allow(dead_code)]
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

fn extract_fiedler(eigenvalues: &[f64]) -> f64 {
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
// FORMULA:  c_eq = <R_eff> * 2m * tau
// SPECTRAL FORM:
//   <R_eff>  =  Tr(L+) / N  =  (1/N) * sum_{lambda > 0} 1 / lambda
//   2m       =  Tr(L)      =  sum_{lambda} lambda
//   tau      =  TAU_SCALE_NS / lambda_2  (already computed, in ns)
//
// PHYSICAL INTERPRETATION: c_eq is the natural commute-time scale of
// the topology graph -- the average time it takes work to bounce
// between two CPUs along the topology's slowest paths. The CoDel
// target's mean-reverting equilibrium settles to this value in the
// absence of disturbance, so the stall detector tightens around the
// topology's intrinsic timescale instead of a hand-picked constant.
//
// CLAMPED TO [200us, 8ms] -- THE CoDel TARGET RANGE ITSELF.
fn compute_codel_eq_ns(eigenvalues: &[f64], n: usize, tau_ns: u64) -> u64 {
    if n == 0 {
        return TAU_FLOOR_NS;
    }
    let mut sum_inv_lambda = 0.0f64;
    let mut sum_lambda = 0.0f64;
    for &lambda in eigenvalues {
        sum_lambda += lambda;
        if lambda > LAMBDA_ZERO_EPS {
            sum_inv_lambda += 1.0 / lambda;
        }
    }
    let avg_reff = sum_inv_lambda / n as f64;
    let two_m = sum_lambda;
    let raw_ns = avg_reff * two_m * tau_ns as f64;
    (raw_ns as u64).clamp(C_EQ_FLOOR_NS, C_EQ_CEIL_NS)
}

#[allow(dead_code)]
pub struct CpuTopology {
    pub nr_cpus: usize,
    pub l2_domain: Vec<u32>,      // l2_domain[cpu] = group_id
    pub l2_groups: Vec<Vec<u32>>, // l2_groups[group_id] = [cpu, ...]
    pub socket_domain: Vec<u32>,  // socket_domain[cpu] = socket_id
    pub llc_domain: Vec<u32>,     // llc_domain[cpu] = L3 GROUP (== socket WHEN MONOLITHIC)
    pub nr_sockets: u32,
}

impl CpuTopology {
    pub fn detect(nr_cpus: usize) -> Result<Self> {
        let mut l2_domain = vec![0u32; nr_cpus];
        let mut seen_groups: Vec<Vec<u32>> = Vec::new();

        for cpu in 0..nr_cpus {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index2/shared_cpu_list",
                cpu
            );
            let content = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => {
                    // CPU MIGHT BE OFFLINE OR HAVE NO L2 INFO -- ASSIGN OWN GROUP
                    l2_domain[cpu] = cpu as u32;
                    continue;
                }
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

        // DETECT SOCKET (PHYSICAL PACKAGE)
        let mut socket_domain = vec![0u32; nr_cpus];
        let mut seen_sockets: Vec<u32> = Vec::new();

        for cpu in 0..nr_cpus {
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
        // PRESENT FOR EVERY CPU; OTHERWISE llc_domain == socket_domain SO THE
        // CROSS-DOMAIN RUNG IN build_laplacian NEVER FIRES (EXACT NO-OP).
        let mut llc_domain = vec![0u32; nr_cpus];
        let mut seen_llc: Vec<Vec<u32>> = Vec::new();
        let mut llc_ok = true;
        for cpu in 0..nr_cpus {
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
        // MAX_OVERFLOW_DOMAINS mirrors src/bpf/intf.h: the BPF side creates exactly
        // this many per-domain overflow DSQs. If a (multi-socket, high-cache domain) box has
        // more L3 groups than that, degrade to the socket domain rather than let
        // a cache domain id index an uncreated DSQ -> dispatch failure -> ejection.
        const MAX_OVERFLOW_DOMAINS: usize = 32;
        let llc_subdivides = llc_ok
            && seen_llc.len() > nr_sockets as usize
            && seen_llc.len() <= MAX_OVERFLOW_DOMAINS;
        if !llc_subdivides {
            llc_domain = socket_domain.clone();
        }

        Ok(Self {
            nr_cpus,
            l2_domain,
            l2_groups: seen_groups,
            socket_domain,
            llc_domain,
            nr_sockets,
        })
    }

    // WRITE L2 DOMAIN MAP TO BPF ARRAY VIA SCHEDULER
    pub fn populate_bpf_map(&self, sched: &mut Scheduler) -> Result<()> {
        for cpu in 0..self.nr_cpus {
            sched.write_cache_domain(cpu as u32, self.l2_domain[cpu])?;
        }
        // nr_overflow_domains = number of distinct llc_domain values (the overflow-domain count)
        let mut seen: Vec<u32> = Vec::new();
        for &g in &self.llc_domain {
            if !seen.contains(&g) {
                seen.push(g);
            }
        }
        sched.write_nr_overflow_domains(seen.len() as u32);
        Ok(())
    }

    // WRITE L2 SIBLINGS FLAT ARRAY TO BPF MAP
    // l2_siblings[group_id * 8 + slot] = cpu_id, SENTINEL u32::MAX MARKS END
    pub fn populate_l2_siblings_map(&self, sched: &Scheduler) -> Result<()> {
        const MAX_L2_SIBLINGS: usize = 8;
        for (gid, members) in self.l2_groups.iter().enumerate() {
            for (slot, &cpu) in members.iter().enumerate().take(MAX_L2_SIBLINGS) {
                sched.write_l2_sibling(gid as u32, slot as u32, cpu)?;
            }
            if members.len() < MAX_L2_SIBLINGS {
                sched.write_l2_sibling(gid as u32, members.len() as u32, u32::MAX)?;
            }
        }
        Ok(())
    }

    // RESISTANCE AFFINITY (KYNG-DINIC ELECTRICAL FLOW MODEL)
    //
    // EFFECTIVE RESISTANCE R_eff(u,v) BETWEEN TWO CPUs CAPTURES THE TRUE
    // MIGRATION COST THROUGH ALL TOPOLOGY PATHS. COMPUTED FROM THE LAPLACIAN
    // PSEUDOINVERSE OF THE CPU TOPOLOGY GRAPH:
    //   R_eff(i,j) = L+[i,i] + L+[j,j] - 2*L+[i,j]
    //
    // EDGE CONDUCTANCES (INVERSE RESISTANCE):
    //   L2 SIBLINGS:      10.0  (SHARED L2, NEAR-ZERO MIGRATION COST)
    //   SAME L3 / cache domain:     3.0  (SHARED LLC; ONLY WHEN A SOCKET HOLDS >1 cache domain)
    //   CROSS-DOMAIN SOCKET:  1.0  (CROSS-DOMAIN INTERCONNECT HOP, ~8x CORE-TO-CORE LATENCY)
    //   CROSS-SOCKET:      0.3  (NUMA HOP, HIGH COST)
    // RAISING THE same-domain RUNG (NOT LOWERING THE CROSS-DOMAIN CUT) RANKS
    // SAME-L3 PEERS AHEAD OF CROSS-L3 ONES WITHOUT MOVING lambda_2: THE CROSS-L3
    // CUT STAYS 1.0, SO tau AND codel_eq ARE UNCHANGED. THE L3 RUNG IS ALWAYS ON;
    // on a monolithic part llc_domain == socket_domain, so it coincides with the
    // socket rung and the continuous R_eff metric calibrates to the L2 boundary.
    //
    // THE LAPLACIAN L = D - W WHERE D IS DEGREE MATRIX, W IS WEIGHTED ADJACENCY.
    // L+ (MOORE-PENROSE PSEUDOINVERSE) COMPUTED VIA EIGENDECOMPOSITION:
    //   L+ = sum_{i: lambda_i > 0} (1/lambda_i) * v_i * v_i^T
    //
    // FOR n CPUs THIS IS O(n^3) -- TRIVIAL AT SCHEDULER STARTUP (n <= 256).
    //
    // REFERENCE: Christiano-Kelner-Madry-Spielman-Teng (STOC 2011),
    //            Chen-Kyng-Liu-Peng-Gutenberg-Sachdeva (FOCS 2022)

    // Phi FIX A: SMT siblings SHARE L2, so a move between them costs ~0 cache.
    // Make the edge very stiff -> R_eff(SMT-sib) ~ 0, which lands the Phi migration
    // barrier exactly at the physical-core / L2 boundary (a real cold-L2 refill)
    // instead of penalizing free intra-core moves. lambda_2 is the cross-domain Fiedler
    // cut (independent of L2 stiffness) so tau is unchanged, and codel_eq is already
    // clamped at its ceiling, so the oscillator timescales are invariant.
    const CONDUCTANCE_L2: f64 = 1000.0; // L2 / SMT SIBLINGS
    const CONDUCTANCE_LLC: f64 = 3.0; // SAME L3 (ABOVE SOCKET; always-on rung)
    const CONDUCTANCE_SOCKET: f64 = 1.0; // SAME SOCKET, CROSS-DOMAIN (IF HOP) -- OR MONOLITHIC SAME-SOCKET
    const CONDUCTANCE_CROSS: f64 = 0.3; // CROSS-SOCKET NUMA HOP

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

    fn build_laplacian(&self) -> Vec<f64> {
        let n = self.nr_cpus;
        let mut l = vec![0.0f64; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let w = self.conductance(i, j);
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

    // Single-level min-conductance cut of `members` via the Fiedler sweep: order
    // the members by their Fiedler component, sweep every prefix as side A, keep
    // the split with the lowest phi. Balance-free. Returns (side_a, side_b, phi),
    // or None for a singleton. fvec is indexed by global CPU id.
    #[allow(dead_code)]
    fn fiedler_sweep_cut(
        &self,
        members: &[usize],
        fvec: &[f64],
    ) -> Option<(Vec<usize>, Vec<usize>, f64)> {
        if members.len() < 2 {
            return None;
        }
        let mut ordered = members.to_vec();
        ordered.sort_by(|&a, &b| {
            fvec[a]
                .partial_cmp(&fvec[b])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut in_side = vec![false; self.nr_cpus];
        let (mut best_phi, mut best_k) = (f64::INFINITY, 1usize);
        for k in 1..ordered.len() {
            in_side[ordered[k - 1]] = true; // grow the prefix one vertex
            let phi = self.cut_conductance(members, &in_side);
            if phi < best_phi {
                best_phi = phi;
                best_k = k;
            }
        }
        Some((
            ordered[..best_k].to_vec(),
            ordered[best_k..].to_vec(),
            best_phi,
        ))
    }

    // True when every member shares one L2 group -- the atomic leaf. L2 siblings
    // are maximally coupled; there is no meaningful seam to find below them.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

    // Below this many CPUs the exact eigen cut is cheap, so use it; above it,
    // the O(n^3) Jacobi is the wall and the random-walk cut takes over. This is an
    // implementation dispatch on cost, not a placement gate (THE FLAG untouched).
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
    #[allow(dead_code)]
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
        let mut in_side = vec![false; self.nr_cpus];
        let (mut best_phi, mut best_k) = (f64::INFINITY, 1usize);
        for s in 1..k {
            in_side[members[order[s - 1]]] = true;
            let phi = self.cut_conductance(members, &in_side);
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
        self.build_domain_tree(&(0..self.nr_cpus).collect::<Vec<_>>())
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

    // Number of emergent OVERFLOW DOMAINS to target = distinct L3 groups (the old
    // per-domain count), so re-keying the overflow DSQs preserves granularity.
    pub fn overflow_domain_count(&self) -> usize {
        let mut v = self.llc_domain.clone();
        v.sort_unstable();
        v.dedup();
        v.len().max(1)
    }

    // T3b.2: partition CPUs into emergent OVERFLOW DOMAINS -- the the discrete domain map
    // replacement. Descend the tree from the root, repeatedly splitting the
    // frontier subtree whose cut has the LOWEST phi (the coarsest, most-separable
    // seam) until `target` domains exist or no cut remains. Each resulting subtree
    // is one overflow domain; dom[cpu] is its id. The granularity is the old L3
    // count, but the boundary is now drawn by the emergent tree, not the discrete domain map.
    pub fn domain_partition(&self, tree: &DomainNode, target: usize) -> Vec<u32> {
        let mut frontier: Vec<&DomainNode> = vec![tree];
        while frontier.len() < target.max(1) {
            let mut best: Option<(usize, f64)> = None;
            for (i, node) in frontier.iter().enumerate() {
                if let DomainNode::Cut { phi, .. } = node {
                    if best.map_or(true, |(_, bp)| *phi < bp) {
                        best = Some((i, *phi));
                    }
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
        let mut dom = vec![0u32; n];
        for (id, node) in frontier.iter().enumerate() {
            for leaf in node.leaves() {
                for c in leaf {
                    if c < n {
                        dom[c] = id as u32;
                    }
                }
            }
        }
        dom
    }

    // SYMMETRIC EIGENDECOMPOSITION VIA JACOBI ROTATIONS
    // RETURNS (eigenvalues, eigenvectors_column_major)
    // SUITABLE FOR n <= 256. NO EXTERNAL DEPENDENCIES.
    fn symmetric_eigen(mat: &[f64], n: usize) -> (Vec<f64>, Vec<f64>) {
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
    fn compute_pseudoinverse(eigenvalues: &[f64], eigenvectors: &[f64], n: usize) -> Vec<f64> {
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
    fn extract_reff(l_pinv: &[f64], n: usize) -> Vec<f64> {
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

    // BUILD PER-CPU AFFINITY RANK: FOR EACH CPU, ALL OTHERS SORTED BY R_EFF
    // Returns flat array: affinity_rank[cpu * nr_cpus + slot] = target_cpu
    fn build_affinity_rank(reff: &[f64], n: usize) -> Vec<u32> {
        let mut rank = vec![0u32; n * n];
        for cpu in 0..n {
            let mut others: Vec<(u64, u32)> = (0..n)
                .filter(|&c| c != cpu)
                .map(|c| {
                    // SORT KEY: R_EFF AS FIXED-POINT TO AVOID FLOAT COMPARISON ISSUES
                    let key = (reff[cpu * n + c] * 1_000_000.0) as u64;
                    (key, c as u32)
                })
                .collect();
            others.sort();
            for (slot, &(_, target)) in others.iter().enumerate() {
                rank[cpu * n + slot] = target;
            }
            // FILL REMAINING SLOTS WITH SENTINEL
            for slot in others.len()..n {
                rank[cpu * n + slot] = u32::MAX;
            }
        }
        rank
    }

    // COMPUTE RESISTANCE AFFINITY: FULL PIPELINE
    // Returns (reff_matrix, affinity_rank, spectrum) for use by BPF and scheduler.
    // Spectrum carries lambda_2 (Fiedler value) and its derived tau_ns, used as
    // the universal topology time constant for every core-scaled knob.
    pub fn compute_resistance_affinity(&self) -> (Vec<f64>, Vec<u32>, TopologySpectrum) {
        let n = self.nr_cpus;
        let laplacian = self.build_laplacian();
        let (eigenvalues, eigenvectors) = Self::symmetric_eigen(&laplacian, n);
        let fiedler = extract_fiedler(&eigenvalues);
        let tau_ns = compute_tau_ns(fiedler, n);
        let l_pinv = Self::compute_pseudoinverse(&eigenvalues, &eigenvectors, n);
        let reff = Self::extract_reff(&l_pinv, n);
        let rank = Self::build_affinity_rank(&reff, n);
        let codel_eq_ns = compute_codel_eq_ns(&eigenvalues, n, tau_ns);
        // Phi FIX B: distance scale calibrated so the most distant pair (max R_eff)
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

    // WRITE AFFINITY RANK TO BPF MAP
    // affinity_rank[cpu * MAX_AFFINITY_CANDIDATES + slot] = target_cpu
    //
    // Emit the full sorted R_eff peer list per CPU, capped at the BPF
    // table width (MAX_AFFINITY_CANDIDATES). Slots beyond the actual
    // topology end (nr_cpus - 1) are written as explicit u32::MAX
    // sentinels so the BPF early-exit fires correctly -- map zero-init
    // would otherwise alias to "CPU 0" and silently mis-route.
    pub fn populate_affinity_rank_map(
        &self,
        sched: &Scheduler,
        reff: &[f64],
        rank: &[u32],
        phi_dist_scale_q16: u64,
        domain_phi: &[u32],
    ) -> Result<()> {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES as usize;
        let valid = self.nr_cpus.saturating_sub(1).min(stride);
        for cpu in 0..self.nr_cpus {
            for slot in 0..valid {
                let val = rank[cpu * self.nr_cpus + slot];
                sched.write_affinity_rank(cpu as u32, slot as u32, val)?;
                // T3b.1: the emergent-domain crossing price to this ranked peer,
                // 1:1 with the rank slot (sentinel for an out-of-range peer id).
                let dphi = domain_phi
                    .get(cpu * self.nr_cpus + val as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                sched.write_domain_phi(cpu as u32, slot as u32, dphi)?;
                // FOLD THE PHI DISTANCE PENALTY AT INIT: reff_value stores the
                // final steal extra-wait in ns, (R_eff * phi_dist_scale_q16) >> 16,
                // so the BPF steal does one indexed read and no multiply. The 1e6
                // scale matches build_affinity_rank's sort key. phi_dist_scale_q16
                // is 0 on monolithic / --phi-scale 0 -> every penalty 0 -> flat
                // codel_target (exact prior behavior).
                let r_scaled = (reff[cpu * self.nr_cpus + val as usize] * 1_000_000.0)
                    .round()
                    .clamp(0.0, u32::MAX as f64) as u64;
                let dist_extra =
                    (r_scaled.saturating_mul(phi_dist_scale_q16) >> 16).min(u32::MAX as u64) as u32;
                sched.write_reff_value(cpu as u32, slot as u32, dist_extra)?;
            }
            for slot in valid..stride {
                sched.write_affinity_rank(cpu as u32, slot as u32, u32::MAX)?;
                sched.write_reff_value(cpu as u32, slot as u32, u32::MAX)?;
                sched.write_domain_phi(cpu as u32, slot as u32, u32::MAX)?;
            }
        }
        Ok(())
    }

    pub fn log_resistance_affinity(&self, reff: &[f64], rank: &[u32], spectrum: TopologySpectrum) {
        log_info!(
            "TOPOLOGY SPECTRUM: lambda2={:.4} tau={}ms codel_eq={}us",
            spectrum.fiedler,
            spectrum.tau_ns / 1_000_000,
            spectrum.codel_eq_ns / 1_000
        );
        let n = self.nr_cpus;
        // LOG TOP 3 AFFINITIES FOR CPU 0
        let mut parts = Vec::new();
        for slot in 0..3.min(n - 1) {
            let target = rank[slot] as usize;
            if target >= n {
                break;
            }
            let r = reff[target];
            parts.push(format!("CPU{}(R={:.3})", target, r));
        }
        log_info!("RESISTANCE AFFINITY: CPU 0 rank: {}", parts.join(", "));

        // LOG L2 VS NON-L2 R_EFF FOR FIRST CPU
        if n >= 2 {
            let l2_sib = rank[0] as usize;
            let non_l2 = rank[1.min(n - 2)] as usize;
            log_info!(
                "RESISTANCE AFFINITY: R_eff L2={:.4} non-L2={:.4} ratio={:.1}x",
                reff[l2_sib],
                reff[non_l2],
                if reff[l2_sib] > 0.0 {
                    reff[non_l2] / reff[l2_sib]
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
            "L2 GROUPS: {} across {} CPUs, {} SOCKETS",
            self.l2_groups.len(),
            self.nr_cpus,
            self.nr_sockets
        );
        let mut llc = self.llc_domain.clone();
        llc.sort_unstable();
        llc.dedup();
        log_info!(
            "LLC DOMAINS: {} (L3 rung always-on, continuous Phi)",
            llc.len()
        );
    }
}

// PARSE KERNEL CPU LIST FORMAT: "0,6" or "0-2,6-8" or "3"
fn parse_cpu_list(s: &str) -> Vec<u32> {
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

#[cfg(test)]
mod t2_cut_tests {
    use super::*;

    // 8 CPUs, no SMT (each its own L2), one socket, two L3 groups: {0..3},{4..7}.
    // Intra-L3 edges weigh CONDUCTANCE_LLC (3.0), inter-L3 same-socket weigh
    // CONDUCTANCE_SOCKET (1.0) -- two clusters joined by weak edges.
    fn synth_2domain() -> CpuTopology {
        CpuTopology {
            nr_cpus: 8,
            l2_domain: (0..8u32).collect(),
            l2_groups: Vec::new(),
            socket_domain: vec![0u32; 8],
            llc_domain: vec![0, 0, 0, 0, 1, 1, 1, 1],
            nr_sockets: 1,
        }
    }

    #[test]
    fn min_conductance_cut_splits_on_llc() {
        let t = synth_2domain();
        let lap = t.build_laplacian();
        let (ev, evec) = CpuTopology::symmetric_eigen(&lap, 8);
        let fvec = CpuTopology::fiedler_vector(&ev, &evec, 8);
        let members: Vec<usize> = (0..8).collect();
        let (a, b, phi) = t.fiedler_sweep_cut(&members, &fvec).expect("cut");
        let (mut sa, mut sb) = (a.clone(), b.clone());
        sa.sort();
        sb.sort();
        let (llc0, llc1) = (vec![0usize, 1, 2, 3], vec![4usize, 5, 6, 7]);
        assert!(
            (sa == llc0 && sb == llc1) || (sa == llc1 && sb == llc0),
            "expected the L3 boundary, got {:?} | {:?}",
            sa,
            sb
        );
        assert!(phi.is_finite() && phi > 0.0 && phi < 1.0, "phi = {}", phi);
    }

    #[test]
    fn cut_conductance_zero_weight_guard() {
        // A singleton member set has no valid bipartition -> None, not a panic.
        let t = synth_2domain();
        assert!(t.fiedler_sweep_cut(&[3usize], &vec![0.0; 8]).is_none());
    }

    // 8 CPUs WITH SMT: 4 L2 pairs {0,1}{2,3}{4,5}{6,7}, two L3 groups {0..3},
    // {4..7}, one socket. L2-sib 1000, same-L3 cross-L2 3.0, cross-L3 same-socket
    // 1.0 -- a clean two-level hierarchy whose tree should be L3 over L2 pairs.
    fn synth_smt_2domain() -> CpuTopology {
        CpuTopology {
            nr_cpus: 8,
            l2_domain: vec![0, 0, 1, 1, 2, 2, 3, 3],
            l2_groups: Vec::new(),
            socket_domain: vec![0u32; 8],
            llc_domain: vec![0, 0, 0, 0, 1, 1, 1, 1],
            nr_sockets: 1,
        }
    }

    #[test]
    fn top_cut_is_the_l3_seam() {
        let t = synth_smt_2domain();
        let (a, b, phi) = t.domain_cut(&(0..8).collect::<Vec<_>>()).expect("cut");
        let (mut sa, mut sb) = (a.clone(), b.clone());
        sa.sort();
        sb.sort();
        let (l3a, l3b) = (vec![0usize, 1, 2, 3], vec![4usize, 5, 6, 7]);
        assert!(
            (sa == l3a && sb == l3b) || (sa == l3b && sb == l3a),
            "top cut should be the L3 seam, got {:?} | {:?}",
            sa,
            sb
        );
        assert!(phi.is_finite() && phi > 0.0 && phi < 1.0, "phi = {}", phi);
    }

    #[test]
    fn domain_tree_leaves_are_l2_groups() {
        let t = synth_smt_2domain();
        let tree = t.build_domain_tree(&(0..8).collect::<Vec<_>>());
        let mut leaves: Vec<Vec<usize>> = tree
            .leaves()
            .into_iter()
            .map(|mut l| {
                l.sort();
                l
            })
            .collect();
        leaves.sort();
        assert_eq!(
            leaves,
            vec![vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7]],
            "leaves should be the 4 L2 groups"
        );
        // The root cut (L3 seam) is the cheapest crossing: coarser seam, lower phi.
        let phis = tree.cut_phis();
        assert!(!phis.is_empty(), "tree should have cuts");
        let root_phi = phis[0];
        assert!(
            phis.iter().all(|&p| root_phi <= p + 1e-9),
            "root cut should be the lowest phi, got {:?}",
            phis
        );
    }

    // Two cuts induce the same bipartition (ignoring which side is A vs B)?
    fn same_bipartition(
        a: &(Vec<usize>, Vec<usize>, f64),
        b: &(Vec<usize>, Vec<usize>, f64),
    ) -> bool {
        let norm = |c: &(Vec<usize>, Vec<usize>, f64)| {
            let (mut x, mut y) = (c.0.clone(), c.1.clone());
            x.sort();
            y.sort();
            if x < y {
                (x, y)
            } else {
                (y, x)
            }
        };
        norm(a) == norm(b)
    }

    #[test]
    fn walk_cut_matches_eigen_cut_smt() {
        let t = synth_smt_2domain();
        let m: Vec<usize> = (0..8).collect();
        let eigen = t.domain_cut(&m).expect("eigen");
        let walk = t.walk_cut(&m).expect("walk");
        assert!(
            same_bipartition(&eigen, &walk),
            "walk {:?}|{:?} != eigen {:?}|{:?}",
            walk.0,
            walk.1,
            eigen.0,
            eigen.1
        );
    }

    // 16 CPUs, 2 sockets {0..7}{8..15}, 4 L3 groups, 8 L2 pairs. The weakest seam
    // is cross-socket (CONDUCTANCE_CROSS 0.3) -- both cuts must land there,
    // exercising the random walk on a deeper graph than the 8-CPU case.
    fn synth_2socket() -> CpuTopology {
        CpuTopology {
            nr_cpus: 16,
            l2_domain: (0..16).map(|c| (c / 2) as u32).collect(),
            l2_groups: Vec::new(),
            socket_domain: (0..16).map(|c| (c / 8) as u32).collect(),
            llc_domain: (0..16).map(|c| (c / 4) as u32).collect(),
            nr_sockets: 2,
        }
    }

    #[test]
    fn walk_cut_matches_eigen_cut_2socket() {
        let t = synth_2socket();
        let m: Vec<usize> = (0..16).collect();
        let eigen = t.domain_cut(&m).expect("eigen");
        let walk = t.walk_cut(&m).expect("walk");
        let (mut wa, mut wb) = (walk.0.clone(), walk.1.clone());
        wa.sort();
        wb.sort();
        let (s0, s1): (Vec<usize>, Vec<usize>) = ((0..8).collect(), (8..16).collect());
        assert!(
            (wa == s0 && wb == s1) || (wa == s1 && wb == s0),
            "walk top cut should be the socket seam, got {:?}|{:?}",
            wa,
            wb
        );
        assert!(same_bipartition(&eigen, &walk), "walk != eigen on 2-socket");
    }

    #[test]
    fn compute_domain_tree_public_wrapper() {
        let t = synth_smt_2domain();
        let tree = t.compute_domain_tree();
        assert_eq!(tree.leaves().len(), 4, "smt 2-domain -> 4 L2-group leaves");
    }

    #[test]
    fn single_cpu_is_one_leaf() {
        let t = CpuTopology {
            nr_cpus: 1,
            l2_domain: vec![0],
            l2_groups: Vec::new(),
            socket_domain: vec![0],
            llc_domain: vec![0],
            nr_sockets: 1,
        };
        let tree = t.compute_domain_tree();
        assert_eq!(tree.leaves(), vec![vec![0usize]]);
        assert!(tree.cut_phis().is_empty(), "a single CPU has no cuts");
    }

    #[test]
    fn cross_phi_matrix_prices_the_boundaries() {
        let t = synth_smt_2domain();
        let tree = t.compute_domain_tree();
        let m = t.domain_cross_phi_matrix(&tree);
        let n = 8;
        // Same leaf {0,1}: no boundary -> sentinel.
        assert_eq!(m[0 * n + 1], u32::MAX, "same-leaf pair must be sentinel");
        // Cross-L2 same-L3 (0,2) and cross-L3 (0,4): real, priced boundaries.
        assert_ne!(m[0 * n + 2], u32::MAX);
        assert_ne!(m[0 * n + 4], u32::MAX);
        // Cross-L2 is the TIGHTER (nearer) seam -> higher phi than cross-L3.
        assert!(
            m[0 * n + 2] > m[0 * n + 4],
            "cross-L2 phi {} should exceed cross-L3 phi {}",
            m[0 * n + 2],
            m[0 * n + 4]
        );
        // CPUs 2 and 3 are the same sibling L2 pair: identical crossing price from 0.
        assert_eq!(m[0 * n + 2], m[0 * n + 3]);
        // Symmetric.
        assert_eq!(m[0 * n + 4], m[4 * n + 0]);
    }

    #[test]
    fn overflow_partition_matches_l3_groups() {
        let t = synth_smt_2domain();
        assert_eq!(t.overflow_domain_count(), 2, "two L3 groups");
        let tree = t.compute_domain_tree();
        let dom = t.domain_partition(&tree, 2);
        assert!(
            dom[0] == dom[1] && dom[1] == dom[2] && dom[2] == dom[3],
            "L3 group 0 is one overflow domain: {:?}",
            dom
        );
        assert!(
            dom[4] == dom[5] && dom[5] == dom[6] && dom[6] == dom[7],
            "L3 group 1 is one overflow domain: {:?}",
            dom
        );
        assert_ne!(dom[0], dom[4], "the two L3 groups are distinct domains");
        // target 1 -> a single overflow domain (monolithic re-key).
        let mono = t.domain_partition(&tree, 1);
        assert!(
            mono.iter().all(|&d| d == 0),
            "target 1 = one domain: {:?}",
            mono
        );
    }
}
