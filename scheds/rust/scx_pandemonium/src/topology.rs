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
const TAU_SCALE_NS: f64 = 1.6e8; // 160MS -- CALIBRATED SO FLAT K_4 WITH
                                 // EDGE WEIGHT 10 (ALL L2 SIBLINGS)
                                 // YIELDS tau = 4MS.
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

fn compute_tau_ns(fiedler: f64) -> u64 {
    let raw = TAU_SCALE_NS / fiedler.max(LAMBDA_ZERO_EPS);
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

        Ok(Self {
            nr_cpus,
            l2_domain,
            l2_groups: seen_groups,
            socket_domain,
            nr_sockets,
        })
    }

    // WRITE L2 DOMAIN MAP TO BPF ARRAY VIA SCHEDULER
    pub fn populate_bpf_map(&self, sched: &Scheduler) -> Result<()> {
        for cpu in 0..self.nr_cpus {
            sched.write_cache_domain(cpu as u32, self.l2_domain[cpu])?;
        }
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
    //   L2 SIBLINGS:     10.0  (SHARED CACHE, NEAR-ZERO MIGRATION COST)
    //   SAME SOCKET:      1.0  (SHARED LLC, MODERATE COST)
    //   CROSS-SOCKET:     0.3  (NUMA HOP, HIGH COST)
    //
    // THE LAPLACIAN L = D - W WHERE D IS DEGREE MATRIX, W IS WEIGHTED ADJACENCY.
    // L+ (MOORE-PENROSE PSEUDOINVERSE) COMPUTED VIA EIGENDECOMPOSITION:
    //   L+ = sum_{i: lambda_i > 0} (1/lambda_i) * v_i * v_i^T
    //
    // FOR n CPUs THIS IS O(n^3) -- TRIVIAL AT SCHEDULER STARTUP (n <= 256).
    //
    // REFERENCE: Christiano-Kelner-Madry-Spielman-Teng (STOC 2011),
    //            Chen-Kyng-Liu-Peng-Gutenberg-Sachdeva (FOCS 2022)

    const CONDUCTANCE_L2: f64 = 10.0;
    const CONDUCTANCE_SOCKET: f64 = 1.0;
    const CONDUCTANCE_CROSS: f64 = 0.3;

    // BUILD WEIGHTED GRAPH LAPLACIAN FROM CPU TOPOLOGY
    fn build_laplacian(&self) -> Vec<f64> {
        let n = self.nr_cpus;
        let mut l = vec![0.0f64; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let w = if self.l2_domain[i] == self.l2_domain[j] {
                    Self::CONDUCTANCE_L2
                } else if self.socket_domain[i] == self.socket_domain[j] {
                    Self::CONDUCTANCE_SOCKET
                } else {
                    Self::CONDUCTANCE_CROSS
                };
                l[i * n + j] = -w;
                l[j * n + i] = -w;
                l[i * n + i] += w;
                l[j * n + j] += w;
            }
        }
        l
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
        let tau_ns = compute_tau_ns(fiedler);
        let l_pinv = Self::compute_pseudoinverse(&eigenvalues, &eigenvectors, n);
        let reff = Self::extract_reff(&l_pinv, n);
        let rank = Self::build_affinity_rank(&reff, n);
        let codel_eq_ns = compute_codel_eq_ns(&eigenvalues, n, tau_ns);
        (
            reff,
            rank,
            TopologySpectrum {
                fiedler,
                tau_ns,
                codel_eq_ns,
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
    pub fn populate_affinity_rank_map(&self, sched: &Scheduler, rank: &[u32]) -> Result<()> {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES as usize;
        let valid = self.nr_cpus.saturating_sub(1).min(stride);
        for cpu in 0..self.nr_cpus {
            for slot in 0..valid {
                let val = rank[cpu * self.nr_cpus + slot];
                sched.write_affinity_rank(cpu as u32, slot as u32, val)?;
            }
            for slot in valid..stride {
                sched.write_affinity_rank(cpu as u32, slot as u32, u32::MAX)?;
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
mod tests {
    use super::*;

    #[test]
    fn parse_single() {
        assert_eq!(parse_cpu_list("3"), vec![3]);
    }

    #[test]
    fn parse_comma() {
        assert_eq!(parse_cpu_list("0,6"), vec![0, 6]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_cpu_list("0-2,6-8"), vec![0, 1, 2, 6, 7, 8]);
    }

    #[test]
    fn parse_mixed() {
        assert_eq!(parse_cpu_list("0-2,5,9-11"), vec![0, 1, 2, 5, 9, 10, 11]);
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
    }

    #[test]
    fn detect_topology() {
        // RUNS ON ANY MACHINE -- VERIFIES SANE OUTPUT
        let nr_cpus = std::fs::read_dir("/sys/devices/system/cpu")
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .map(|e| {
                        e.file_name().to_string_lossy().starts_with("cpu")
                            && e.file_name().to_string_lossy()[3..].parse::<u32>().is_ok()
                    })
                    .unwrap_or(false)
            })
            .count();

        if nr_cpus == 0 {
            return; // NO CPUS VISIBLE (CONTAINER?)
        }

        let topo = CpuTopology::detect(nr_cpus).unwrap();
        assert_eq!(topo.nr_cpus, nr_cpus);
        assert_eq!(topo.l2_domain.len(), nr_cpus);

        // EVERY CPU MUST HAVE A VALID GROUP ID
        let max_group = topo.l2_groups.len() as u32;
        for cpu in 0..nr_cpus {
            assert!(
                topo.l2_domain[cpu] < max_group || topo.l2_domain[cpu] == cpu as u32,
                "CPU {} has invalid l2 group {}",
                cpu,
                topo.l2_domain[cpu]
            );
        }

        // AT LEAST ONE GROUP MUST EXIST
        assert!(!topo.l2_groups.is_empty());

        // SOCKET DETECTION
        assert_eq!(topo.socket_domain.len(), nr_cpus);
        assert!(topo.nr_sockets >= 1);
        for cpu in 0..nr_cpus {
            assert!(
                topo.socket_domain[cpu] < topo.nr_sockets,
                "CPU {} socket {} >= nr_sockets {}",
                cpu,
                topo.socket_domain[cpu],
                topo.nr_sockets
            );
        }

        // RESISTANCE AFFINITY: LAPLACIAN R_EFF
        let (reff, rank, spectrum) = topo.compute_resistance_affinity();
        assert!(
            spectrum.fiedler > 0.0,
            "lambda_2 must be positive for connected graph"
        );
        assert!(spectrum.tau_ns >= 1_000_000, "tau must be >= 1ms floor");
        assert!(spectrum.tau_ns <= 40_000_000, "tau must be <= 40ms ceiling");
        // SAME CPU = 0 (diagonal of R_eff matrix)
        assert_eq!(reff[0], 0.0);
        // L2 SIBLING SHOULD BE CHEAPEST (RANK SLOT 0)
        if nr_cpus >= 2 {
            let best = rank[0] as usize;
            assert!(best < nr_cpus);
            let r_best = reff[best];
            assert!(r_best > 0.0);
            // EVERY OTHER CPU SHOULD COST >= THE BEST
            for c in 1..nr_cpus {
                let r_c = reff[c];
                assert!(
                    r_c >= r_best - 1e-9,
                    "CPU {} R_eff {:.6} < best {:.6}",
                    c,
                    r_c,
                    r_best
                );
            }
        }
    }
}
